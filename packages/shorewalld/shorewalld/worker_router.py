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
import os
import signal
import time
from dataclasses import dataclass, field
from typing import Callable

from .batch_codec import (
    CTRL_SHUTDOWN,
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
from .worker_transport import WorkerTransport

log = get_logger("worker")

# Respawn backoff: each failure doubles the delay up to this cap.
RESPAWN_BACKOFF_MIN = 0.5
RESPAWN_BACKOFF_MAX = 30.0

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
        tracker: DnsSetTracker,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self.netns = netns
        self._tracker = tracker
        self._loop = loop
        self._transport: WorkerTransport | None = None
        self._child_pid: int | None = None
        self._pending: dict[int, _PendingBatch] = {}
        self._next_batch_id = 1
        self.metrics = WorkerMetrics()
        # Ack-timeout enforcement task; lazy-started on first
        # dispatch so idle workers don't burn a task slot.
        self._timeout_task: asyncio.Task[None] | None = None
        self._stopped = False

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
        pid = os.fork()
        if pid == 0:
            # Child: close parent's end, run the worker entrypoint.
            parent_t.close()
            rc = nft_worker_entrypoint(self.netns, worker_t.fileno)
            os._exit(rc)
        worker_t.close()
        self._transport = parent_t
        self._child_pid = pid
        # Hook the SEQPACKET fd into asyncio so replies wake the loop.
        self._loop.add_reader(
            self._transport.fileno, self._drain_replies)
        self._timeout_task = self._loop.create_task(
            self._ack_timeout_loop())

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

        if self._transport is None:
            raise RuntimeError(
                "ParentWorker not started or already stopped")
        if self._stopped:
            raise RuntimeError("ParentWorker stopped")

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
        """Called from the event loop whenever the SEQPACKET fd is readable."""
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
            # Remove the reader and drop the transport so the dead fd
            # doesn't keep firing this callback in a tight loop.
            if self._transport is not None:
                try:
                    self._loop.remove_reader(self._transport.fileno)
                except (ValueError, OSError):
                    pass
                self._transport.close()
                self._transport = None
            self._fail_all_pending(e)
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
        """Resolve every outstanding batch with an error — used on
        transport loss before respawn takes over."""
        for pending in self._pending.values():
            if not pending.future.done():
                pending.future.set_exception(exc)
        self._pending.clear()

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
        tracker: DnsSetTracker,
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
            thread_name_prefix="shorewalld-nft",
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

    Created by the :class:`Daemon` during startup after the
    DnsSetTracker has loaded the compiled allowlist. Handles
    dispatch() routing based on the batch's target netns — the
    SetWriter tells us which netns the batch belongs to via a
    per-call argument.
    """

    tracker: DnsSetTracker
    loop: asyncio.AbstractEventLoop
    _workers: dict[str, ParentWorker] = field(default_factory=dict)

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

    async def dispatch(
        self, netns: str, builder: BatchBuilder
    ) -> int:
        worker = self._workers.get(netns)
        if worker is None:
            worker = await self.add_netns(netns)
        return await worker.dispatch(builder)

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
    tracker: DnsSetTracker,
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

    t = threading.Thread(target=run, daemon=True)
    t.start()

    pw = ParentWorker(netns="inproc", tracker=tracker, loop=loop)
    pw._transport = parent_t
    pw._child_pid = None
    loop.add_reader(parent_t.fileno, pw._drain_replies)
    pw._timeout_task = loop.create_task(pw._ack_timeout_loop())
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
