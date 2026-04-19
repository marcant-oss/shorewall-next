"""nft-worker subprocess: one per managed netns, long-lived.

Lifecycle
---------

The parent shorewalld process forks one child per target network
namespace at startup. The child:

1. Enters the target netns via ``setns(2)`` on an fd into
   ``/run/netns/<name>``. Required capabilities: ``CAP_SYS_ADMIN``
   for setns, ``CAP_NET_ADMIN`` for nft writes.
2. Installs ``PR_SET_PDEATHSIG = SIGTERM`` so a parent crash
   tears the worker down automatically.
3. Constructs a :class:`NftInterface` **in the target netns** —
   libnftables' netlink socket binds to the *current* netns at
   connect time, which is exactly why we fork-and-setns in the
   first place.
4. Drops into :func:`worker_main_loop`, reading SEQPACKET
   datagrams from the inherited transport, applying each batch
   via libnftables, and replying with an ack.

Hot path: receive datagram → decode header → for each op, build a
minimal nft command string → accumulate into an atomic script →
submit via ``NftInterface.cmd()`` → reply OK / ERROR. No per-batch
heap allocations beyond the command string (unavoidable — libnftables
wants a Python ``str``).

Shutdown
--------

The parent sends a ``CTRL_SHUTDOWN`` control datagram; the worker
replies with ``REPLY_SHUTDOWN`` and exits with status 0. On
``EOF`` / transport error the worker exits with status 1 and the
parent respawns it, re-running the init sequence.

Sandboxing
----------

The worker runs with the same uid/gid as the parent (root). This
is acceptable because:

* The parent already needs ``CAP_NET_ADMIN`` to compile and load
  shorewall rulesets.
* The attack surface here is the SEQPACKET IPC from the parent —
  the worker trusts its parent implicitly, there is no external
  network I/O.
* A compromised parent already owns the firewall; privilege
  separation would be theatre.

Future hardening: seccomp-bpf filter narrowing the worker to
``recvmsg/sendmsg/setns/nftables``-related syscalls, at the cost
of a ~200-line filter table. Deferred.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import signal
import socket
import sys
from typing import TYPE_CHECKING

from .batch_codec import (
    BATCH_OP_ADD,
    BATCH_OP_DEL,
    CTRL_SHUTDOWN,
    CTRL_SNAPSHOT,
    MAGIC_REQUEST,
    REPLY_ERROR,
    REPLY_OK,
    REPLY_SHUTDOWN,
    BatchOp,
    WireError,
    decode_control,
    decode_header,
    encode_reply_into,
    iter_ops,
)
from .logsetup import get_logger
from .read_codec import (
    MAGIC_READ_REQ,
    MAX_FILE_BYTES,
    READ_KIND_COUNT_LINES,
    READ_KIND_FILE,
    READ_STATUS_ERROR,
    READ_STATUS_NOT_FOUND,
    READ_STATUS_OK,
    READ_STATUS_TOO_LARGE,
    ReadWireError,
    decode_read_request,
    encode_line_count,
    encode_read_response_into,
    peek_magic,
)
from .worker_transport import WorkerTransport

if TYPE_CHECKING:
    from shorewall_nft.nft.netlink import NftInterface


log = get_logger("worker")

# libc prototype for PR_SET_PDEATHSIG. Linux-specific.
# PR_SET_NAME is handled by ``proctitle.set_proc_name``.
_PR_SET_PDEATHSIG = 1

# Table / family the workers write to. Shorewall-nft ships one
# inet table called "shorewall"; the worker's job is to push DNS set
# elements into that table. Constants here so tests can override if
# a future layout changes.
NFT_FAMILY = "inet"
NFT_TABLE = "shorewall"

# Reply buffer per worker. Sized for the largest response we might
# emit: a read-RPC file payload (up to ``MAX_FILE_BYTES`` ≈ 60 KiB)
# plus its response header. Batch acks are <2 KiB and fit trivially.
# Allocated once and reused for every reply to stay zero-alloc in
# the steady state.
_REPLY_BUF_SIZE = 65536


def _set_proc_name(netns_name: str) -> None:
    """Label the forked nft-worker process for ps/top.

    Name format: ``shwd/<netns>`` (truncated to 15 chars by prctl).  The
    5-char ``shwd/`` prefix leaves 10 chars for the netns name — long
    enough for typical names like ``recursor-v6`` where the old
    ``shorewalld/`` prefix would have truncated to ``shorewalld/recu``.
    """
    from .proctitle import set_proc_name
    set_proc_name(f"shwd/{netns_name}" if netns_name else "shwd/nft")


def _install_pdeathsig(sig: int = signal.SIGTERM) -> None:
    """Tell the kernel to signal us when our parent exits.

    Matches simlab's nsstub pattern — bullet-proof parent-death
    cleanup. Uses ``prctl(PR_SET_PDEATHSIG, sig)`` via libc. Failing
    silently is OK; the worker is still a useful process without it,
    just not self-cleaning on parent crash.
    """
    try:
        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        libc = ctypes.CDLL(libc_name, use_errno=True)
        libc.prctl(_PR_SET_PDEATHSIG, sig, 0, 0, 0)
    except OSError:
        log.debug("prctl PR_SET_PDEATHSIG failed — continuing")


def _enter_netns(name: str) -> None:
    """Move the current process into the named network namespace.

    Uses ``setns(fd, CLONE_NEWNET)``. Raises ``OSError`` if the
    namespace doesn't exist or we lack ``CAP_SYS_ADMIN``; the router
    translates that into a respawn failure.

    Empty ``name`` means "stay in the current netns" — that's the
    path for the daemon's own netns, where no fork is needed but we
    still use the worker abstraction for code uniformity.
    """
    if not name:
        return
    ns_path = f"/run/netns/{name}"
    fd = os.open(ns_path, os.O_RDONLY)
    try:
        CLONE_NEWNET = 0x40000000
        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        libc = ctypes.CDLL(libc_name, use_errno=True)
        rc = libc.setns(fd, CLONE_NEWNET)
        if rc != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"setns({ns_path}) failed: {os.strerror(err)}")
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# nft command builder — one string per batch, zero allocations per op
# beyond the final ``"".join``
# ---------------------------------------------------------------------------


def _set_name_for(set_id: int, family: int) -> str:
    """Resolve a ``set_id`` to the nft set name.

    The worker maintains its own mini-registry installed at startup
    via the set-name table message (Phase 2b). For Phase 2a we keep
    things simple: every op carries the set *name* in a small
    extension header. This is a TODO pointer; for the initial
    ship we hard-code a single resolver from the DnsSetTracker
    state that the parent maps.

    See :class:`ParentWorker` below which owns the table lookup.
    """
    # Intentional placeholder — the parent passes batches whose
    # ``set_id`` has been pre-resolved to an index the worker can
    # look up via a side channel. Until that side channel ships
    # (Phase 2b), tests use ParentWorker.apply_batch_local which
    # translates in the parent's address space.
    raise NotImplementedError(
        "worker-local set_id resolver not wired yet — "
        "use ParentWorker.apply_batch_local in tests")


def build_nft_script(
    ops: list[BatchOp],
    set_name_of: "dict[tuple[int, int], str] | callable",
    *,
    family: str = NFT_FAMILY,
    table: str = NFT_TABLE,
) -> str:
    """Turn a list of decoded ops into one atomic nft script.

    The script is a sequence of ``add element`` / ``delete element``
    lines. libnftables applies them atomically when submitted as a
    single ``cmd()`` call; if any line fails, the whole transaction
    rolls back and returns an error.

    ``set_name_of`` is either a dict mapping ``(set_id, family)`` →
    set name, or a callable with the same signature. The callable
    form lets the Parent-worker integration hook the
    ``DnsSetTracker.name_for`` lookup directly without materialising
    a copy of the mapping.

    The emitted ``add element`` line carries both ``timeout`` AND
    ``expires`` set to the same TTL.  Without an explicit ``expires``
    the kernel does NOT reset the remaining countdown for an element
    that already exists with the same ``timeout`` — the second
    ``add`` is silently a no-op and the element ages out on its
    original deadline.  Specifying ``expires`` populates
    ``NFTA_SET_ELEM_EXPIRATION``, which the kernel always honours, so
    a refresh genuinely refreshes the kernel-side deadline.
    """
    if not ops:
        return ""
    lookup = set_name_of if callable(set_name_of) else set_name_of.get
    lines: list[str] = []
    for op in ops:
        name = lookup((op.set_id, op.family))
        if name is None:
            continue  # allowlist drift — silently skip
        if op.family == 4:
            elem = ".".join(str(b) for b in op.ip_bytes)
        else:
            # Compact IPv6 via socket.inet_ntop — still fine here;
            # this path is per-op but in nft-script building, not on
            # the 20k-fps decode path.
            elem = socket.inet_ntop(socket.AF_INET6, op.ip_bytes)
        if op.op_kind == BATCH_OP_ADD:
            if op.ttl:
                ttl_attrs = f" timeout {op.ttl}s expires {op.ttl}s"
            else:
                ttl_attrs = ""
            lines.append(
                f"add element {family} {table} {name} "
                f"{{ {elem}{ttl_attrs} }}")
        elif op.op_kind == BATCH_OP_DEL:
            lines.append(
                f"delete element {family} {table} {name} "
                f"{{ {elem} }}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main worker loop
# ---------------------------------------------------------------------------


def _handle_read(kind: int, path: str) -> tuple[int, bytes]:
    """Execute a read-RPC in the worker's current netns.

    Returns ``(status, data)`` where ``data`` is an opaque payload:

    * ``READ_KIND_FILE`` + OK → raw file bytes (capped at
      :data:`MAX_FILE_BYTES`).
    * ``READ_KIND_COUNT_LINES`` + OK → 8-byte big-endian line count.
    * non-OK → UTF-8 error string (optional).

    Pure function w.r.t. the worker — never raises, never touches
    libnftables, never allocates more than one read buffer's worth.
    """
    try:
        if kind == READ_KIND_FILE:
            with open(path, "rb") as f:
                data = f.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                return READ_STATUS_TOO_LARGE, (
                    f"file > {MAX_FILE_BYTES} bytes; use count_lines"
                    .encode("utf-8"))
            return READ_STATUS_OK, data
        elif kind == READ_KIND_COUNT_LINES:
            n = 0
            with open(path, "rb") as f:
                for _ in f:
                    n += 1
            return READ_STATUS_OK, encode_line_count(n)
        else:
            return READ_STATUS_ERROR, (
                f"unknown read kind: {kind}".encode("utf-8"))
    except FileNotFoundError:
        return READ_STATUS_NOT_FOUND, b""
    except PermissionError as e:
        return READ_STATUS_NOT_FOUND, str(e).encode("utf-8")
    except OSError as e:
        return READ_STATUS_ERROR, str(e).encode("utf-8")


def worker_main_loop(
    transport: WorkerTransport,
    nft: "NftInterface",
    set_name_lookup,
) -> int:
    """Serve batches and read-RPCs until shutdown or transport error.

    Dispatches on the first four bytes of each incoming datagram:

    * :data:`MAGIC_REQUEST` (``"SWNF"``) — batch op, applied via
      libnftables.
    * :data:`MAGIC_READ_REQ` (``"SWRR"``) — file read / line count
      request, served from the worker's current netns. See
      :mod:`shorewalld.read_codec`.

    Returns the process exit code: 0 on clean shutdown, non-zero on
    transport error. Designed to be called as the entire child-process
    body after the fork + setns + nft initialisation.
    """
    reply_buf = bytearray(_REPLY_BUF_SIZE)
    log.info("nft-worker ready: pid=%d", os.getpid())
    while True:
        try:
            view = transport.recv_into()
        except OSError as e:
            log.warning("worker recv failed: %s", e)
            return 1
        if not view:
            log.info("worker eof; exiting")
            return 0

        try:
            magic = peek_magic(view)
        except ReadWireError as e:
            log.warning("worker wire error: %s", e)
            continue

        if magic == MAGIC_READ_REQ:
            try:
                req = decode_read_request(view)
            except ReadWireError as e:
                log.warning("worker read-rpc decode error: %s", e)
                continue
            status, data = _handle_read(req.kind, req.path)
            try:
                transport.send(encode_read_response_into(
                    reply_buf, status=status,
                    req_id=req.req_id, data=data))
            except OSError:
                return 1
            continue

        if magic != MAGIC_REQUEST:
            log.warning("worker: unknown magic 0x%08x — dropping", magic)
            continue

        try:
            header = decode_header(view)
        except WireError as e:
            log.warning("worker wire error: %s", e)
            transport.send(encode_reply_into(
                reply_buf, status=REPLY_ERROR,
                batch_id=0, applied=0, error=str(e)))
            continue
        # Control datagrams live in batch_id's high word.
        control, inner_id = decode_control(header.batch_id)
        if control == CTRL_SHUTDOWN:
            # Parent is tearing down; best-effort ack but never let a
            # closed peer escalate into an unhandled thread exception.
            try:
                transport.send(encode_reply_into(
                    reply_buf, status=REPLY_SHUTDOWN,
                    batch_id=inner_id, applied=0))
            except OSError:
                pass
            log.info("worker shutdown requested")
            return 0
        if control == CTRL_SNAPSHOT:
            # Phase 7/9 hook — snapshot of current nft set state.
            # The worker is not a source-of-truth for state; the
            # parent DnsSetTracker is. So we just ack with applied=0.
            try:
                transport.send(encode_reply_into(
                    reply_buf, status=REPLY_OK,
                    batch_id=inner_id, applied=0))
            except OSError:
                return 1
            continue

        ops = list(iter_ops(view, header))
        try:
            script = build_nft_script(ops, set_name_lookup)
            if script:
                nft.cmd(script)
            elif ops:
                log.warning(
                    "nft-worker: batch %d: all %d op(s) had unknown set_ids"
                    " — tracker snapshot may be stale (worker needs respawn?)",
                    header.batch_id, len(ops),
                )
            transport.send(encode_reply_into(
                reply_buf, status=REPLY_OK,
                batch_id=header.batch_id, applied=len(ops)))
        except Exception as e:  # noqa: BLE001
            err = str(e)[:_REPLY_BUF_SIZE - 128]
            log.warning("worker apply failed: %s", err)
            try:
                transport.send(encode_reply_into(
                    reply_buf, status=REPLY_ERROR,
                    batch_id=header.batch_id, applied=0, error=err))
            except OSError:
                return 1


def nft_worker_entrypoint(
    netns_name: str,
    transport_fd: int,
    *,
    lookup=None,
) -> int:
    """Post-fork child body.

    Caller passes the inherited ``WorkerTransport`` fd (from the
    parent's ``socketpair()``). We re-build the transport object
    from that fd, enter the target netns, construct an
    ``NftInterface`` that is bound to this netns, install pdeathsig,
    and drop into the main loop.

    ``lookup`` is a callable ``(set_id, family) → set_name | None``
    used by :func:`build_nft_script`.  After ``os.fork()`` the child
    inherits the parent's ``DnsSetTracker`` copy-on-write, so the
    caller can pass a closure over the tracker directly — no IPC
    round-trip needed.  When omitted, ops are silently skipped
    (standalone debugging mode, see ``__main__`` below).

    Exit codes:
        0 — clean shutdown
        2 — netns entry failed (caller may retry on transient errors)
        3 — nft init failed
        1 — transport error at runtime
    """
    _install_pdeathsig()
    _set_proc_name(netns_name)
    try:
        _enter_netns(netns_name)
    except OSError as e:
        log.error("nft-worker: setns(%s) failed: %s", netns_name, e)
        return 2

    from shorewall_nft.nft.netlink import NftInterface
    try:
        nft = NftInterface()
    except Exception as e:  # noqa: BLE001
        log.error("nft-worker: NftInterface init failed: %s", e)
        return 3

    sock = socket.socket(
        fileno=transport_fd,
        family=socket.AF_UNIX,
        type=socket.SOCK_SEQPACKET,
    )
    transport = WorkerTransport(sock)

    if lookup is None:
        def lookup(_key: tuple[int, int]) -> str | None:  # type: ignore[misc]
            return None

    try:
        return worker_main_loop(transport, nft, lookup)
    finally:
        transport.close()


if __name__ == "__main__":
    # Allow running the worker as a standalone module for debugging:
    #   python -m shorewalld.nft_worker fw 3
    if len(sys.argv) != 3:
        print("usage: nft_worker <netns> <transport_fd>", file=sys.stderr)
        sys.exit(64)
    rc = nft_worker_entrypoint(sys.argv[1], int(sys.argv[2]))
    logging.shutdown()
    sys.exit(rc)
