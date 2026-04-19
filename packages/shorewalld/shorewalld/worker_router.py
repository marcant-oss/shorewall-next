"""Parent-side orchestration for the nft-worker pool.

One :class:`ParentWorker` per target netns. The router owns:

* the fork() that creates the child and hands it one end of a
  socketpair,
* the inbound reply pump (asyncio reader) that consumes worker
  acks and resolves the corresponding batch futures,
* the crash-detection loop (SIGCHLD reaper + respawn with backoff),
* the ``DnsSetTracker.name_for`` bridge so worker-side ops can
  resolve set names without shipping a separate table message.

Non-goals:

* **Not** the batching logic. That lives in :class:`SetWriter`
  (next file). The router only knows "send this opaque datagram,
  await the ack".
* **Not** state ownership. The DnsSetTracker is the single source
  of truth for what the daemon *thinks* is in a set; the workers
  reflect what the kernel actually holds. The router bridges the
  two directions without owning either.

Single-netns fast path
----------------------

For the daemon's own netns (empty string), no fork is necessary —
we can call libnftables directly from the parent process. The
router still creates a ``ParentWorker`` object for uniformity, but
it skips the subprocess and dispatches through an in-process
:class:`LocalWorker` shim that uses the same API.

This keeps the SetWriter code identical regardless of deployment
shape (standalone vs. multi-netns) and lets the tests exercise the
whole pipeline without needing real fork()/setns()/CAP_SYS_ADMIN.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import signal
import time
from dataclasses import dataclass, field
from typing import Callable

from .batch_codec import (
    CTRL_SHUTDOWN,
    MAGIC_REPLY,
    REPLY_OK,
    REPLY_SHUTDOWN,
    BatchBuilder,
    decode_reply,
    encode_control,
)
from .dns_set_tracker import DnsSetTracker
from .exporter import CollectorBase, _MetricFamily
from .logsetup import get_logger
from .nft_worker import (
    NFT_FAMILY,
    NFT_TABLE,
    build_nft_script,
    nft_worker_entrypoint,
    worker_main_loop,
)
from .read_codec import (
    MAGIC_READ_RESP,
    READ_KIND_COUNT_LINES,
    READ_KIND_FILE,
    READ_STATUS_NOT_FOUND,
    READ_STATUS_OK,
    READ_STATUS_TOO_LARGE,
    ReadResponse,
    ReadWireError,
    decode_line_count,
    decode_read_response,
    encode_read_request,
    peek_magic,
)
from .worker_transport import WorkerTransport

log = get_logger("worker")

# Respawn backoff: each failure doubles the delay up to this cap.
RESPAWN_BACKOFF_MIN = 0.5
RESPAWN_BACKOFF_MAX = 30.0

# Auto-respawn after transport loss (worker crash / netns vanished):
# if the new child survives this long we treat it as healthy and reset
# the backoff so the next failure starts from zero again.
_RESPAWN_BACKOFF_MAX = RESPAWN_BACKOFF_MAX
_RESPAWN_HEALTHY_AFTER = 30.0

# Worker ack timeout — if the worker hasn't replied to a dispatched
# batch in this window, the router marks it stuck and respawns.
# libnftables commits on the reference 1600-rule ruleset take <50 ms;
# a 5 s cap is three orders of magnitude of slack.
WORKER_ACK_TIMEOUT = 5.0


@dataclass
class WorkerMetrics:
    """Per-netns counters read by the exporter."""
    spawned_total: int = 0
    restarts_total: int = 0
    alive: int = 0
    batches_sent_total: int = 0
    batches_applied_total: int = 0
    batches_failed_total: int = 0
    ipc_errors_total: int = 0
    ack_timeout_total: int = 0
    last_spawn_mono: float = 0.0


@dataclass
class _PendingBatch:
    """Bookkeeping for a batch awaiting a worker ack."""
    batch_id: int
    sent_at: float
    future: asyncio.Future
    op_count: int


class ParentWorker:
    """One nft-worker subprocess, seen from the parent's side.

    Owns the parent half of the SEQPACKET pair, the child pid (if
    any), and the pending-batch futures keyed on ``batch_id``.
    Callers use :meth:`dispatch` to send a prepared batch view and
    await the ack.

    Not an asyncio primitive itself — it uses ``loop.add_reader`` to
    drive the reply pump from the event loop. Most methods are
    async-friendly but the actual send/recv calls happen via the
    blocking :class:`WorkerTransport`, because SEQPACKET is trivially
    non-blocking when the parent socket has been set so.
    """

    def __init__(
        self,
        *,
        netns: str,
        tracker: DnsSetTracker | None,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self.netns = netns
        self._tracker = tracker
        self._loop = loop
        self._transport: WorkerTransport | None = None
        self._child_pid: int | None = None
        self._pending: dict[int, _PendingBatch] = {}
        self._pending_reads: dict[int, asyncio.Future[ReadResponse]] = {}
        self._next_batch_id = 1
        self._next_read_id = 1
        self.metrics = WorkerMetrics()
        # Ack-timeout enforcement task; lazy-started on first
        # dispatch so idle workers don't burn a task slot.
        self._timeout_task: asyncio.Task[None] | None = None
        self._stopped = False
        # Auto-respawn state: backoff grows on rapid child deaths
        # (e.g., the target netns vanished briefly), resets to 0 when a
        # spawn lives long enough to look healthy.
        self._respawn_task: asyncio.Task[None] | None = None
        self._respawn_backoff: float = 0.0

    # ── Spawn / respawn ───────────────────────────────────────────────

    async def start(self) -> None:
        """Create the transport pair, fork, and attach the reply pump.

        For an empty ``netns`` (the daemon's own namespace), uses the
        in-process :class:`LocalWorker` path — no fork. Callers can't
        tell the difference.
        """
        if not self.netns:
            await self._start_local()
        else:
            await self._start_forked()
        self.metrics.spawned_total += 1
        self.metrics.alive = 1
        self.metrics.last_spawn_mono = time.monotonic()
        log.info(
            "nft-worker started",
            extra={"netns": self.netns or "(own)"},
        )

    async def _start_local(self) -> None:
        """No fork — run the worker inline via a shim.

        Used when the daemon only manages its own netns. The
        :class:`LocalWorker` implements the same dispatch signature
        as a real ParentWorker but talks to libnftables directly
        from the asyncio executor, serialising writes.
        """
        # Swap our dispatch implementation pointer out — clean and
        # self-contained, no shared state.
        self._local = LocalWorker(
            tracker=self._tracker, loop=self._loop)
        await self._local.start()

    async def _start_forked(self) -> None:
        parent_t, worker_t = WorkerTransport.pair()
        tracker = self._tracker
        pid = os.fork()
        if pid == 0:
            # Child: close parent's end, run the worker entrypoint.
            # The tracker is inherited copy-on-write; build the lookup
            # closure here so the worker can resolve set_id → name
            # without any IPC round-trip. ``tracker`` may be ``None``
            # when the router was created before the DNS-set pipeline
            # bootstrapped (read-only scrape workers); the closure
            # returns ``None`` in that case and the worker silently
            # skips set ops — the parent respawns workers once a real
            # tracker attaches.
            parent_t.close()
            from shorewall_nft.nft.dns_sets import qname_to_set_name

            def _lookup(key: tuple[int, int]) -> str | None:
                if tracker is None:
                    return None
                entry = tracker.name_for(key[0])
                if entry is None:
                    return None
                qname, family = entry
                return qname_to_set_name(
                    qname, "v4" if family == 4 else "v6")

            rc = nft_worker_entrypoint(
                self.netns, worker_t.fileno, lookup=_lookup)
            os._exit(rc)
        worker_t.close()
        self._transport = parent_t
        self._child_pid = pid
        # Hook the SEQPACKET fd into asyncio so replies wake the loop.
        self._loop.add_reader(
            self._transport.fileno, self._drain_replies)
        self._timeout_task = self._loop.create_task(
            self._ack_timeout_loop(),
            name=f"shorewalld.nft.ack:{self.netns or '(own)'}")

    # ── Dispatch ──────────────────────────────────────────────────────

    def _alloc_batch_id(self) -> int:
        bid = self._next_batch_id
        self._next_batch_id = (self._next_batch_id + 1) & 0xFFFF_FFFF_FFFF
        if self._next_batch_id == 0:
            self._next_batch_id = 1
        return bid

    async def dispatch(self, builder: BatchBuilder) -> int:
        """Send a batch and wait for the worker's ack.

        Stamps the batch_id, allocates a future, sends the datagram,
        and returns the number of ops the worker reports as applied.
        Raises on error or timeout.
        """
        if hasattr(self, "_local"):
            return await self._local.dispatch(builder)

        if self._stopped:
            raise RuntimeError("ParentWorker stopped")
        if self._transport is None:
            # Worker died (or netns is briefly gone); kick the
            # auto-respawn task so the next batch has a fresh worker
            # to talk to and surface the cause to the caller now.
            self._schedule_respawn()
            raise RuntimeError(
                "ParentWorker transport lost; respawn scheduled")

        batch_id = self._alloc_batch_id()
        view = builder.finish(batch_id)
        op_count = builder.count
        fut: asyncio.Future[int] = self._loop.create_future()
        self._pending[batch_id] = _PendingBatch(
            batch_id=batch_id,
            sent_at=time.monotonic(),
            future=fut,
            op_count=op_count,
        )
        try:
            self._transport.send(view)
        except OSError as e:
            self._pending.pop(batch_id, None)
            self.metrics.ipc_errors_total += 1
            if not fut.done():
                fut.set_exception(e)
            raise
        self.metrics.batches_sent_total += 1
        return await fut

    def _drain_replies(self) -> None:
        """Called from the event loop whenever the SEQPACKET fd is readable.

        Dispatches on the reply datagram's magic: ``MAGIC_REPLY``
        → batch ack (existing code path), ``MAGIC_READ_RESP`` → read-RPC
        response (resolves a ``_pending_reads`` future).
        """
        if self._transport is None:
            return
        try:
            view = self._transport.recv_into()
        except OSError as e:
            self.metrics.ipc_errors_total += 1
            log.warning(
                "worker recv failed: %s", e,
                extra={"netns": self.netns or "(own)"},
            )
            self._tear_down_transport()
            self._fail_all_pending(e)
            self._schedule_respawn()
            return

        try:
            magic = peek_magic(view)
        except ReadWireError as e:
            self.metrics.ipc_errors_total += 1
            log.warning(
                "worker reply wire error: %s", e,
                extra={"netns": self.netns or "(own)"})
            return

        if magic == MAGIC_READ_RESP:
            try:
                resp = decode_read_response(view)
            except ReadWireError as e:
                self.metrics.ipc_errors_total += 1
                log.warning(
                    "worker read-resp decode failed: %s", e,
                    extra={"netns": self.netns or "(own)"})
                return
            fut = self._pending_reads.pop(resp.req_id, None)
            if fut is None:
                log.debug(
                    "worker read-resp for unknown req_id=%d",
                    resp.req_id,
                )
                return
            if not fut.done():
                fut.set_result(resp)
            return

        if magic != MAGIC_REPLY:
            self.metrics.ipc_errors_total += 1
            log.warning(
                "worker: unknown reply magic 0x%08x — dropping", magic,
                extra={"netns": self.netns or "(own)"})
            return

        try:
            reply = decode_reply(view)
        except Exception as e:  # noqa: BLE001
            self.metrics.ipc_errors_total += 1
            log.warning(
                "worker reply decode failed: %s", e,
                extra={"netns": self.netns or "(own)"},
            )
            return
        pending = self._pending.pop(reply.batch_id, None)
        if pending is None:
            log.debug(
                "worker reply for unknown batch_id=%d",
                reply.batch_id,
            )
            return
        if reply.status == REPLY_OK:
            self.metrics.batches_applied_total += 1
            if not pending.future.done():
                pending.future.set_result(reply.applied)
        elif reply.status == REPLY_SHUTDOWN:
            if not pending.future.done():
                pending.future.set_result(0)
        else:
            self.metrics.batches_failed_total += 1
            if not pending.future.done():
                pending.future.set_exception(
                    WorkerBatchError(reply.error or "worker reported error"))

    def _fail_all_pending(self, exc: BaseException) -> None:
        """Resolve every outstanding batch/read with an error — used on
        transport loss before respawn takes over."""
        for pending in self._pending.values():
            if not pending.future.done():
                pending.future.set_exception(exc)
        self._pending.clear()
        for fut in self._pending_reads.values():
            if not fut.done():
                fut.set_exception(exc)
        self._pending_reads.clear()

    # ── Read-RPC dispatch ─────────────────────────────────────────────

    def _alloc_read_id(self) -> int:
        rid = self._next_read_id
        self._next_read_id = (self._next_read_id + 1) & 0xFFFFFFFFFFFF
        if self._next_read_id == 0:
            self._next_read_id = 1
        return rid

    async def _dispatch_read(self, kind: int, path: str) -> ReadResponse:
        """Send a read-RPC and await the reply.

        Called from the event loop only. For scrape-thread callers,
        :class:`WorkerRouter` wraps this via ``run_coroutine_threadsafe``.
        """
        if hasattr(self, "_local"):
            return await self._local._dispatch_read(kind, path)
        if self._stopped:
            raise RuntimeError("ParentWorker stopped")
        if self._transport is None:
            self._schedule_respawn()
            raise RuntimeError(
                "ParentWorker transport lost; respawn scheduled")

        req_id = self._alloc_read_id()
        fut: asyncio.Future[ReadResponse] = self._loop.create_future()
        self._pending_reads[req_id] = fut
        try:
            payload = encode_read_request(
                kind=kind, req_id=req_id, path=path)
            self._transport.send(payload)
        except OSError as e:
            self._pending_reads.pop(req_id, None)
            self.metrics.ipc_errors_total += 1
            if not fut.done():
                fut.set_exception(e)
            raise
        return await fut

    async def read_file(self, path: str) -> bytes | None:
        """Read a file in the worker's netns. ``None`` when missing."""
        resp = await self._dispatch_read(READ_KIND_FILE, path)
        if resp.status == READ_STATUS_OK:
            return resp.data
        if resp.status == READ_STATUS_NOT_FOUND:
            return None
        if resp.status == READ_STATUS_TOO_LARGE:
            log.warning(
                "worker read_file(%s): file exceeds payload cap, "
                "returning None; use count_lines instead", path,
                extra={"netns": self.netns or "(own)"})
            return None
        log.warning(
            "worker read_file(%s) error: %s", path,
            resp.data.decode("utf-8", errors="replace"),
            extra={"netns": self.netns or "(own)"})
        return None

    async def count_lines(self, path: str) -> int | None:
        """Count lines in a file in the worker's netns. ``None`` on error."""
        resp = await self._dispatch_read(READ_KIND_COUNT_LINES, path)
        if resp.status == READ_STATUS_OK:
            return decode_line_count(resp.data)
        if resp.status == READ_STATUS_NOT_FOUND:
            return None
        log.warning(
            "worker count_lines(%s) error: %s", path,
            resp.data.decode("utf-8", errors="replace"),
            extra={"netns": self.netns or "(own)"})
        return None

    def _tear_down_transport(self) -> None:
        """Close the parent-side socket and reap the dead child.

        Idempotent. Always safe to call after a failed recv or before
        starting a fresh fork. Reaping the child prevents a zombie pile
        when the worker process exits but the parent never waitpid()s.
        """
        if self._transport is not None:
            try:
                self._loop.remove_reader(self._transport.fileno)
            except (ValueError, OSError):
                pass
            self._transport.close()
            self._transport = None
        if self._child_pid is not None:
            try:
                os.waitpid(self._child_pid, os.WNOHANG)
            except ChildProcessError:
                pass
            except OSError as e:
                log.debug(
                    "worker waitpid failed: %s", e,
                    extra={"netns": self.netns or "(own)"})
            self._child_pid = None
        if self._timeout_task is not None:
            self._timeout_task.cancel()
            self._timeout_task = None
        self.metrics.alive = 0

    def _schedule_respawn(self) -> None:
        """Trigger an asynchronous auto-respawn.

        Idempotent — a new task is only created if no respawn is
        already in flight.  The delay is governed by
        ``self._respawn_backoff`` which grows on rapid child deaths
        (typical when the target netns is briefly absent during a
        ``ip netns del/add`` cycle) and resets once the new child
        survives long enough to look stable.
        """
        if self._stopped:
            return
        if self._respawn_task is not None and not self._respawn_task.done():
            return
        self._respawn_task = self._loop.create_task(
            self._auto_respawn(),
            name=f"shorewalld.nft.respawn:{self.netns or '(own)'}")

    async def _auto_respawn(self) -> None:
        """Re-fork the worker child after a transport loss.

        Backoff schedule (seconds): 0, 1, 2, 4, 8, 16, 30, 30, …
        — capped so a wedged netns doesn't peg a CPU.  After a
        successful spawn that survives ``_RESPAWN_HEALTHY_AFTER``
        seconds we reset the backoff so the next failure starts
        from zero again.
        """
        delay = self._respawn_backoff
        self._respawn_backoff = min(
            max(self._respawn_backoff * 2.0, 1.0),
            _RESPAWN_BACKOFF_MAX,
        )
        if delay > 0:
            log.info(
                "nft-worker auto-respawn in %.1fs", delay,
                extra={"netns": self.netns or "(own)"})
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                return
        if self._stopped:
            return
        try:
            await self._start_forked()
        except Exception as e:  # noqa: BLE001
            log.error(
                "nft-worker auto-respawn failed: %s; will retry", e,
                extra={"netns": self.netns or "(own)"})
            # Re-schedule ourselves through the normal path so the
            # backoff continues to grow.
            self._respawn_task = None
            self._schedule_respawn()
            return
        self.metrics.spawned_total += 1
        self.metrics.restarts_total += 1
        self.metrics.alive = 1
        self.metrics.last_spawn_mono = time.monotonic()
        log.info(
            "nft-worker auto-respawned",
            extra={"netns": self.netns or "(own)"})
        # Schedule a backoff reset if the new child survives long
        # enough — done on the loop so we don't pin a coroutine.
        self._loop.call_later(
            _RESPAWN_HEALTHY_AFTER, self._reset_backoff_if_healthy)

    def _reset_backoff_if_healthy(self) -> None:
        if self._transport is not None and not self._stopped:
            self._respawn_backoff = 0.0

    # ── Shutdown + reaping ────────────────────────────────────────────

    async def shutdown(self) -> None:
        """Request a clean shutdown, wait briefly, then reap.

        If the worker is stuck (doesn't ack the shutdown control
        within 2 s), the router falls through to SIGTERM then
        SIGKILL so the parent can exit without blocking.
        """
        if hasattr(self, "_local"):
            await self._local.shutdown()
            self.metrics.alive = 0
            return
        self._stopped = True
        # Cancel any pending auto-respawn so it doesn't race with us
        # tearing the transport down.
        if self._respawn_task is not None and not self._respawn_task.done():
            self._respawn_task.cancel()
        if self._transport is None:
            return
        builder = BatchBuilder()
        try:
            view = encode_control(builder, CTRL_SHUTDOWN, batch_id=0)
            self._transport.send(view)
        except OSError:
            pass
        pid = self._child_pid
        if pid:
            for sig in (0, signal.SIGTERM, signal.SIGKILL):
                if sig:
                    try:
                        os.kill(pid, sig)
                    except ProcessLookupError:
                        break
                try:
                    finished_pid, _status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    break
                if finished_pid == pid:
                    break
                await asyncio.sleep(0.5)
        if self._timeout_task is not None:
            self._timeout_task.cancel()
        if self._transport is not None:
            try:
                self._loop.remove_reader(self._transport.fileno)
            except (ValueError, OSError):
                pass
            self._transport.close()
            self._transport = None
        self.metrics.alive = 0

    async def _ack_timeout_loop(self) -> None:
        """Poll for pending batches whose ack is overdue.

        The router doesn't need sub-second precision here — it runs
        at 1 Hz and counts stuck batches into
        ``shorewalld_nft_worker_ack_timeout_total``. A stuck worker
        triggers respawn at the next SetWriter.dispatch() attempt;
        this loop just makes the metric visible.
        """
        while not self._stopped:
            now = time.monotonic()
            for batch_id, pending in list(self._pending.items()):
                if now - pending.sent_at > WORKER_ACK_TIMEOUT:
                    self.metrics.ack_timeout_total += 1
                    if not pending.future.done():
                        pending.future.set_exception(
                            WorkerAckTimeout(
                                f"worker ack timeout for batch_id={batch_id}"))
                    self._pending.pop(batch_id, None)
            await asyncio.sleep(1.0)


# ---------------------------------------------------------------------------
# LocalWorker — in-process bypass for the single-netns case
# ---------------------------------------------------------------------------


class LocalWorker:
    """In-process stand-in for a ParentWorker.

    Calls libnftables directly on the asyncio executor using a
    dedicated single-threaded ``ThreadPoolExecutor`` so the
    non-thread-safe libnftables sees a single, serialised caller.

    Behaviourally equivalent to a forked ParentWorker from the
    SetWriter's perspective — it accepts :class:`BatchBuilder`
    instances and returns ``applied`` counts.
    """

    def __init__(
        self,
        *,
        tracker: DnsSetTracker | None,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._tracker = tracker
        self._loop = loop
        self._nft = None
        self._executor = None

    async def start(self) -> None:
        from concurrent.futures import ThreadPoolExecutor

        from shorewall_nft.nft.netlink import NftInterface
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="shwd-nft",
        )
        self._nft = NftInterface()

    async def dispatch(self, builder: BatchBuilder) -> int:
        if self._nft is None or self._executor is None:
            raise RuntimeError("LocalWorker not started")
        from .batch_codec import decode_header, iter_ops
        view = builder.finish(self._next_batch_id())
        header = decode_header(view)
        ops = list(iter_ops(view, header))
        if not ops:
            return 0
        tracker = self._tracker

        def lookup(key: tuple[int, int]) -> str | None:
            if tracker is None:
                return None
            entry = tracker.name_for(key[0])
            if entry is None:
                return None
            from shorewall_nft.nft.dns_sets import qname_to_set_name
            qname, family = entry
            return qname_to_set_name(
                qname, "v4" if family == 4 else "v6")

        script = build_nft_script(
            ops, lookup, family=NFT_FAMILY, table=NFT_TABLE)
        if not script:
            return len(ops)

        def apply():
            # All libnftables calls run on this dedicated thread
            # so we don't race any other caller.
            self._nft.cmd(script)
            return len(ops)

        return await self._loop.run_in_executor(self._executor, apply)

    _batch_id_counter = 0

    def _next_batch_id(self) -> int:
        LocalWorker._batch_id_counter += 1
        return LocalWorker._batch_id_counter

    # ── Read-RPC (in-process, default netns) ───────────────────────────

    async def _dispatch_read(self, kind: int, path: str) -> ReadResponse:
        """Serve a read-RPC without any IPC hop.

        LocalWorker is always the daemon's own netns, so a direct
        ``open()`` already sees the right ``/proc``. Runs on the
        default thread pool to keep the event loop unblocked during
        a large file read (e.g. ``/proc/net/ipv6_route`` on a BGP
        full-table box).
        """
        def _do() -> ReadResponse:
            from .nft_worker import _handle_read
            status, data = _handle_read(kind, path)
            return ReadResponse(
                magic=MAGIC_READ_RESP, version=1,
                status=status, req_id=0, data=data,
            )
        return await self._loop.run_in_executor(None, _do)

    async def shutdown(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None
        self._nft = None


# ---------------------------------------------------------------------------
# Router — top-level facade
# ---------------------------------------------------------------------------


@dataclass
class WorkerRouter:
    """One :class:`ParentWorker` per managed netns.

    Created by the :class:`Daemon` at startup. The router is live
    before the DNS-set pipeline bootstraps so that the Prometheus
    exporter can route ``/proc`` reads through netns-pinned workers
    even when the daemon is managing no set-writing pipeline at all.

    ``tracker`` is ``None`` until the DNS-set pipeline calls
    :meth:`attach_tracker` (typically during ``_start_dns_pipeline``).
    Workers forked before that point cannot resolve set-name lookups
    and will silently skip set-mutating batches until a respawn; read
    RPCs work regardless of tracker state.
    """

    loop: asyncio.AbstractEventLoop
    tracker: DnsSetTracker | None = None
    _workers: dict[str, ParentWorker] = field(default_factory=dict)

    def attach_tracker(self, tracker: DnsSetTracker) -> None:
        """Point the router at a freshly-created ``DnsSetTracker``.

        Existing forked workers captured the previous tracker
        (probably ``None``) at fork time; those must be respawned
        (``respawn_netns``) to pick up the new lookup closure.
        """
        self.tracker = tracker

    async def add_netns(self, netns: str) -> ParentWorker:
        """Spawn a worker for ``netns`` (idempotent)."""
        if netns in self._workers:
            return self._workers[netns]
        worker = ParentWorker(
            netns=netns, tracker=self.tracker, loop=self.loop)
        try:
            await worker.start()
        except Exception:
            raise
        self._workers[netns] = worker
        return worker

    async def respawn_netns(self, netns: str) -> None:
        """Shut down and re-fork the worker for ``netns``.

        Called when new qnames are added to the tracker after the worker
        was already running.  Forked workers snapshot the tracker at fork
        time (copy-on-write), so they cannot see set_ids allocated after
        the fork.  Respawning re-forks with the current tracker state.

        No-op if no worker for ``netns`` is running (it will be spawned
        fresh on first dispatch, which already has the full tracker).
        Only meaningful for forked (non-empty netns) workers; the
        LocalWorker reads the tracker live on every dispatch.
        """
        worker = self._workers.pop(netns, None)
        if worker is None:
            return
        try:
            await worker.shutdown()
        except Exception as e:  # noqa: BLE001
            log.warning(
                "worker respawn: shutdown error for netns %r: %s", netns, e)
        worker.metrics.restarts_total += 1
        new_worker = ParentWorker(
            netns=netns, tracker=self.tracker, loop=self.loop)
        new_worker.metrics.spawned_total = worker.metrics.spawned_total
        new_worker.metrics.restarts_total = worker.metrics.restarts_total
        try:
            await new_worker.start()
        except Exception:
            raise
        self._workers[netns] = new_worker
        log.info(
            "nft-worker respawned (tracker registry update)",
            extra={"netns": netns},
        )

    async def dispatch(
        self, netns: str, builder: BatchBuilder
    ) -> int:
        worker = self._workers.get(netns)
        if worker is None:
            worker = await self.add_netns(netns)
        return await worker.dispatch(builder)

    # ── Read-RPC surface (async + scrape-thread sync wrappers) ────────

    async def read_file(self, netns: str, path: str) -> bytes | None:
        """Read a file inside ``netns``. Spawns a worker if needed.

        For ``netns=""`` the :class:`LocalWorker` serves the read from
        the daemon's own netns (no fork, no IPC). For named netns the
        request goes through a forked worker already pinned there via
        ``setns(2)`` at fork time.
        """
        worker = self._workers.get(netns)
        if worker is None:
            worker = await self.add_netns(netns)
        return await worker.read_file(path)

    async def count_lines(self, netns: str, path: str) -> int | None:
        """Line-count a file inside ``netns`` (cheap for huge files)."""
        worker = self._workers.get(netns)
        if worker is None:
            worker = await self.add_netns(netns)
        return await worker.count_lines(path)

    def read_file_sync(
        self, netns: str, path: str, *, timeout: float = 5.0,
    ) -> bytes | None:
        """Blocking variant callable from a non-loop thread.

        The Prometheus scrape handler runs on a thread that is not the
        asyncio event loop; this wrapper schedules the async
        :meth:`read_file` on the daemon's loop via
        :func:`asyncio.run_coroutine_threadsafe` and waits for the
        reply. ``timeout`` elapses → return ``None`` so the collector
        simply skips the sample rather than stalling the whole scrape.
        """
        fut = asyncio.run_coroutine_threadsafe(
            self.read_file(netns, path), self.loop)
        try:
            return fut.result(timeout=timeout)
        except (concurrent.futures.TimeoutError,
                concurrent.futures.CancelledError):
            fut.cancel()
            return None
        except Exception as e:  # noqa: BLE001
            log.debug(
                "read_file_sync(%r, %r) failed: %s", netns, path, e)
            return None

    def count_lines_sync(
        self, netns: str, path: str, *, timeout: float = 5.0,
    ) -> int | None:
        """Blocking variant of :meth:`count_lines` for scrape threads."""
        fut = asyncio.run_coroutine_threadsafe(
            self.count_lines(netns, path), self.loop)
        try:
            return fut.result(timeout=timeout)
        except (concurrent.futures.TimeoutError,
                concurrent.futures.CancelledError):
            fut.cancel()
            return None
        except Exception as e:  # noqa: BLE001
            log.debug(
                "count_lines_sync(%r, %r) failed: %s", netns, path, e)
            return None

    async def shutdown(self) -> None:
        for worker in list(self._workers.values()):
            try:
                await worker.shutdown()
            except Exception as e:  # noqa: BLE001
                log.warning("worker shutdown error: %s", e)
        self._workers.clear()

    def iter_workers(self) -> list[ParentWorker]:
        return list(self._workers.values())


class WorkerBatchError(RuntimeError):
    """Worker returned REPLY_ERROR for a dispatched batch."""


class WorkerAckTimeout(RuntimeError):
    """Worker didn't ack a dispatched batch within ``WORKER_ACK_TIMEOUT``."""


# ---------------------------------------------------------------------------
# Test helper — in-process ParentWorker where the "worker side" runs
# an arbitrary callback from a thread, no fork.
# ---------------------------------------------------------------------------


def inproc_worker_pair(
    tracker: DnsSetTracker | None,
    loop: asyncio.AbstractEventLoop,
    set_name_lookup: Callable[[tuple[int, int]], str | None],
    apply_cb: Callable[[str], None] | None = None,
) -> tuple[ParentWorker, WorkerTransport]:
    """Wire a real SEQPACKET pair between a ParentWorker and a
    background thread running :func:`worker_main_loop`.

    Used by the router tests to exercise the full ack pipeline
    without forking. ``apply_cb`` receives the nft script each
    batch would run — default is a no-op so tests can assert on
    commands without actually touching libnftables.
    """
    import threading

    parent_t, worker_t = WorkerTransport.pair()

    class _FakeNft:
        def __init__(self, cb):
            self._cb = cb

        def cmd(self, script):
            if self._cb:
                self._cb(script)

    fake_nft = _FakeNft(apply_cb)

    def run():
        worker_main_loop(worker_t, fake_nft, set_name_lookup)

    t = threading.Thread(
        target=run, name="shwd-nft-inproc", daemon=True)
    t.start()

    pw = ParentWorker(netns="inproc", tracker=tracker, loop=loop)
    pw._transport = parent_t
    pw._child_pid = None
    loop.add_reader(parent_t.fileno, pw._drain_replies)
    pw._timeout_task = loop.create_task(
        pw._ack_timeout_loop(),
        name="shorewalld.nft.ack:inproc")
    pw.metrics.spawned_total = 1
    pw.metrics.alive = 1
    pw.metrics.last_spawn_mono = time.monotonic()
    return pw, worker_t


class WorkerRouterMetricsCollector(CollectorBase):
    """Prometheus collector for per-netns nft worker pool metrics."""

    def __init__(self, router: WorkerRouter) -> None:
        super().__init__(netns="")
        self._router = router

    def collect(self) -> list[_MetricFamily]:
        spawned   = _MetricFamily("shorewalld_worker_spawned_total",
                                  "nft worker forks since daemon start",
                                  ["netns"], mtype="counter")
        restarts  = _MetricFamily("shorewalld_worker_restarts_total",
                                  "nft worker crash-respawns",
                                  ["netns"], mtype="counter")
        alive     = _MetricFamily("shorewalld_worker_alive",
                                  "1 if the nft worker process is running",
                                  ["netns"])
        sent      = _MetricFamily("shorewalld_worker_batches_sent_total",
                                  "Batches dispatched to worker",
                                  ["netns"], mtype="counter")
        applied   = _MetricFamily("shorewalld_worker_batches_applied_total",
                                  "Batches acknowledged OK by worker",
                                  ["netns"], mtype="counter")
        failed    = _MetricFamily("shorewalld_worker_batches_failed_total",
                                  "Batches that returned a worker error",
                                  ["netns"], mtype="counter")
        ipc_err   = _MetricFamily("shorewalld_worker_ipc_errors_total",
                                  "IPC transport errors (SEQPACKET)",
                                  ["netns"], mtype="counter")
        ack_to    = _MetricFamily("shorewalld_worker_ack_timeout_total",
                                  "Batches that timed out waiting for worker ack",
                                  ["netns"], mtype="counter")

        for w in self._router.iter_workers():
            ns = w.netns or "(own)"
            m = w.metrics
            spawned.add([ns],  float(m.spawned_total))
            restarts.add([ns], float(m.restarts_total))
            alive.add([ns],    float(m.alive))
            sent.add([ns],     float(m.batches_sent_total))
            applied.add([ns],  float(m.batches_applied_total))
            failed.add([ns],   float(m.batches_failed_total))
            ipc_err.add([ns],  float(m.ipc_errors_total))
            ack_to.add([ns],   float(m.ack_timeout_total))

        return [spawned, restarts, alive, sent, applied, failed, ipc_err, ack_to]
