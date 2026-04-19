"""SEQPACKET transport between the shorewalld parent and an nft-worker.

The transport owns a single ``AF_UNIX``/``SOCK_SEQPACKET`` socket
and a preallocated receive ``bytearray``. Send buffers belong to
the caller — typically the :class:`BatchBuilder`'s internal view,
which we pass straight to ``sendmsg`` so there is **never** a copy
of the batch payload between encode and kernel.

Why SEQPACKET:

* Atomic datagrams: one send = one receive, no length framing.
* Reliable: kernel buffer absorbs bursts, no silent drops like UDP.
* ``socketpair()`` creates a pre-connected pair in one syscall —
  perfect for fork-inheriting into the worker's stdin/stdout slots.
* Message boundaries survive fork, so the worker doesn't need a
  read-loop with length prefixes.

Usage pattern::

    parent_sock, worker_sock = WorkerTransport.pair(recv_buf_size=4096)

    pid = os.fork()
    if pid == 0:
        parent_sock.close_parent_side()
        worker_transport = worker_sock
        # worker_transport.recv_into(buf) / .send(view)
        ...

    worker_sock.close_worker_side()
    # parent: parent_sock.send(batch_view); parent_sock.recv_into(ack_buf)

The class is intentionally thin. All policy — when to send, when to
retry, what a failed send means — lives in the caller
(:class:`WorkerRouter` in phase 2, step 5). This keeps the transport
unit-testable without a real worker process.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

# Tune to cover the largest datagram we ship over this transport.
# Batch replies fit in a few dozen bytes, but the read-RPC channel
# (:mod:`shorewalld.read_codec`) carries /proc file contents up to
# ``MAX_FILE_BYTES`` ≈ 60 KiB. 64 KiB leaves 4 KiB of margin for the
# response header and future growth. Memory cost is still pocket
# change per worker (two SEQPACKET fds × one buffer each).
DEFAULT_RECV_BUF = 65536

# Send timeout for the parent → worker direction. A worker that can't
# drain within this window is considered stuck; the router kills and
# respawns it. Must be long enough that a slow nft commit doesn't
# trip it — libnftables cmd() typically completes in <50 ms per
# batch, so 2 s leaves three orders of magnitude headroom.
#
# Applied via SO_SNDTIMEO only (not socket.settimeout which would also
# set SO_RCVTIMEO). Workers must block on recv indefinitely — the first
# batch may arrive tens of seconds after fork, e.g. on a slow pull-
# resolver startup. Only the send direction needs a bounded timeout.
DEFAULT_SEND_TIMEOUT = 2.0


def _set_sndtimeo(sock: socket.socket, timeout: float) -> None:
    """Apply SO_SNDTIMEO without touching SO_RCVTIMEO."""
    secs = int(timeout)
    usecs = int((timeout - secs) * 1_000_000)
    tv = struct.pack("@ll", secs, usecs)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, tv)


@dataclass
class TransportStats:
    """Lightweight counters for a single transport instance.

    The router reads these in snapshot() and pushes them into
    Prometheus. Integer adds only in the hot path, no Gauge()
    indirection — cheaper and easier to reason about.
    """
    sends_total: int = 0
    send_bytes_total: int = 0
    recvs_total: int = 0
    recv_bytes_total: int = 0
    send_errors_total: int = 0
    recv_errors_total: int = 0


class WorkerTransport:
    """Thin SEQPACKET wrapper.

    One instance per direction end — the parent holds one, the worker
    holds one, both were created by :meth:`pair`. The transport does
    not dup or inherit file descriptors itself; callers wire that up
    during fork.
    """

    __slots__ = ("_sock", "_recv_buf", "_recv_view", "stats")

    def __init__(
        self,
        sock: socket.socket,
        *,
        recv_buf_size: int = DEFAULT_RECV_BUF,
        send_timeout: float | None = DEFAULT_SEND_TIMEOUT,
    ) -> None:
        self._sock = sock
        if send_timeout is not None:
            _set_sndtimeo(self._sock, send_timeout)
        self._recv_buf = bytearray(recv_buf_size)
        self._recv_view = memoryview(self._recv_buf)
        self.stats = TransportStats()

    # ── Construction ──────────────────────────────────────────────────

    @classmethod
    def pair(
        cls,
        *,
        recv_buf_size: int = DEFAULT_RECV_BUF,
        send_timeout: float | None = DEFAULT_SEND_TIMEOUT,
    ) -> tuple["WorkerTransport", "WorkerTransport"]:
        """Create a connected ``(parent, worker)`` transport pair.

        Uses ``socketpair(AF_UNIX, SOCK_SEQPACKET, 0)``. Both ends
        are inheritable so a subsequent ``fork()`` can hand one end
        to the child and close the other in the parent.
        """
        a, b = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET, 0)
        # Mark both inheritable so fork can duplicate them.
        os.set_inheritable(a.fileno(), True)
        os.set_inheritable(b.fileno(), True)
        parent = cls(
            a,
            recv_buf_size=recv_buf_size,
            send_timeout=send_timeout,
        )
        worker = cls(
            b,
            recv_buf_size=recv_buf_size,
            send_timeout=send_timeout,
        )
        return parent, worker

    # ── Raw access ────────────────────────────────────────────────────

    @property
    def fileno(self) -> int:
        return self._sock.fileno()

    @property
    def sock(self) -> socket.socket:
        """Underlying socket — escape hatch for asyncio wiring."""
        return self._sock

    # ── Send / recv ───────────────────────────────────────────────────

    def send(self, view: memoryview | bytes) -> int:
        """Send one datagram, return the byte count written.

        ``view`` can be a ``memoryview`` aliasing the encoder's
        preallocated buffer — ``sendmsg`` copies the payload into the
        kernel's skbuff so there is no need for a second application
        copy. On error updates the error counter and re-raises.
        """
        try:
            n = self._sock.send(view)
        except OSError:
            self.stats.send_errors_total += 1
            raise
        self.stats.sends_total += 1
        self.stats.send_bytes_total += n
        return n

    def recv_into(
        self, buf: bytearray | memoryview | None = None
    ) -> memoryview:
        """Block until one datagram is available, return a slice of it.

        If ``buf`` is ``None``, fills the transport's preallocated
        receive buffer. The returned ``memoryview`` aliases that
        buffer — callers MUST consume it before the next ``recv_into``
        call, which reuses the same backing store.

        Short datagrams are returned with their actual length — the
        SEQPACKET kernel guarantees one recv = one send, so truncation
        on oversize is the only "weird" outcome. We detect that via
        ``MSG_TRUNC`` and raise.
        """
        target = self._recv_buf if buf is None else buf
        target_view = memoryview(target)
        try:
            n, _ancdata, msg_flags, _addr = self._sock.recvmsg_into(
                [target_view])
        except OSError:
            self.stats.recv_errors_total += 1
            raise
        if msg_flags & socket.MSG_TRUNC:
            self.stats.recv_errors_total += 1
            raise OSError(
                "SEQPACKET datagram truncated — "
                "bump recv_buf_size above the worker's max reply")
        if n == 0:
            self.stats.recv_errors_total += 1
            raise OSError("worker connection closed (EOF on SEQPACKET)")
        self.stats.recvs_total += 1
        self.stats.recv_bytes_total += n
        if buf is None:
            return self._recv_view[:n]
        return target_view[:n]

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Convenience for the in-process tests — a one-shot "echo worker"
# that the router tests use before we have a real nft_worker child
# process to talk to.
# ---------------------------------------------------------------------------


def echo_worker_loop(
    transport: WorkerTransport,
    max_iterations: int | None = None,
) -> int:
    """Echo every received datagram straight back.

    Used by :func:`tests.test_daemon_worker_transport` to verify the
    pair plumbing without bringing up a real nft_worker process.
    Returns the number of round-trips served.
    """
    iterations = 0
    while True:
        if max_iterations is not None and iterations >= max_iterations:
            return iterations
        try:
            view = transport.recv_into()
        except OSError:
            return iterations
        if not view:
            return iterations
        try:
            transport.send(view)
        except OSError:
            return iterations
        iterations += 1
