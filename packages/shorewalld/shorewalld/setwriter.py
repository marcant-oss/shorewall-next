"""SetWriter — the glue coroutine between decoders and nft workers.

Data flow::

    decoder pool (threads)        setwriter (asyncio)           router → workers
    ─────────────────────         ───────────────────           ────────────────
    protobuf frame                                              nft add element
    └─ qname/ip/ttl ──► submit() ─► queue                        ▲
                                    │                            │
                                    ▼  drain_loop                │
                            tracker.propose()                    │
                            (ADD / REFRESH / DEDUP)              │
                                    │                            │
                                    ▼  per-netns BatchBuilder    │
                            accumulate up to window/max_ops  ───┘
                                    │
                                    ▼  dispatch + await ack
                            tracker.commit(verdicts)

Thread-safety model:

* :meth:`submit` is the only *thread-safe* entry point. Decoder
  worker threads call it from outside the event loop.
* All batch-building, dispatch, and tracker commit happens on the
  asyncio loop's thread. That is the single-writer discipline the
  performance doctrine demands — libnftables is not thread-safe,
  the nft worker pool dispatch funnels through one coroutine.

Batch assembly:

* One :class:`BatchBuilder` per ``(netns, family)`` so v4 and v6
  ops stay on separate batches (simpler worker-side script).
* Flush on any of three conditions: builder full, window elapsed,
  shutdown requested.
* BATCH_WINDOW_MS defaults to 10 ms, tunable via shorewall.conf.

Metrics are updated at commit time from the tracker's own counters,
so the exporter doesn't need a separate code path. The SetWriter
adds a few of its own bookkeeping counters (queue depth, flush
reason breakdown) that belong to the coroutine itself.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from .batch_codec import BATCH_OP_ADD, BatchBuilder
from .dns_set_tracker import DnsSetTracker, Proposal, Verdict
from .exporter import CollectorBase, _MetricFamily
from .logsetup import get_logger
from .worker_router import WorkerRouter

log = get_logger("setwriter")

DEFAULT_BATCH_WINDOW_SEC = 0.010       # 10 ms
DEFAULT_BATCH_MAX_OPS = 40              # matches BatchBuilder default
DEFAULT_QUEUE_SIZE = 16384


@dataclass
class SetWriterMetrics:
    queue_depth: int = 0
    queue_high_water: int = 0
    submits_total: int = 0
    dropped_queue_full_total: int = 0
    batches_flushed_total: int = 0
    flush_reason_window_total: int = 0
    flush_reason_full_total: int = 0
    flush_reason_shutdown_total: int = 0
    commits_total: int = 0
    commit_errors_total: int = 0


@dataclass
class _PendingOp:
    """One decoder-proposed update awaiting batch assembly."""
    proposal: Proposal
    netns: str
    family: int
    verdict: Verdict


@dataclass
class _BatchState:
    """Per-(netns, family) build buffer, reset between flushes."""
    builder: BatchBuilder
    proposals: list[Proposal] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)
    opened_at: float = 0.0


class SetWriter:
    """The lone coroutine that commits DNS set writes.

    Usage::

        writer = SetWriter(tracker, router)
        await writer.start()
        # decoder threads call:
        writer.submit(
            netns="fw", family=4, proposal=prop)
        ...
        await writer.shutdown()
    """

    def __init__(
        self,
        tracker: DnsSetTracker,
        router: WorkerRouter,
        *,
        batch_window_sec: float = DEFAULT_BATCH_WINDOW_SEC,
        batch_max_ops: int = DEFAULT_BATCH_MAX_OPS,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self._tracker = tracker
        self._router = router
        self._batch_window = batch_window_sec
        self._batch_max_ops = batch_max_ops
        self._queue: asyncio.Queue[_PendingOp] = asyncio.Queue(
            maxsize=queue_size)
        self._loop = loop
        self._drain_task: asyncio.Task[None] | None = None
        self._stopping = False
        self._batches: dict[tuple[str, int], _BatchState] = {}
        self.metrics = SetWriterMetrics()

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._drain_task is not None:
            return
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        self._drain_task = self._loop.create_task(self._drain_loop())

    async def shutdown(self) -> None:
        self._stopping = True
        if self._drain_task is not None:
            # Nudge the loop so the drain task wakes up even if the
            # queue is empty and the window timer hasn't elapsed yet.
            try:
                self._queue.put_nowait(_SENTINEL)
            except asyncio.QueueFull:
                pass
            try:
                await asyncio.wait_for(
                    self._drain_task, timeout=self._batch_window + 2.0)
            except asyncio.TimeoutError:
                self._drain_task.cancel()
            self._drain_task = None
        # Flush anything still in batch state even if drain couldn't.
        await self._flush_all(reason="shutdown")

    # ── Thread-safe submit — called from decoder pool ─────────────────

    def submit(
        self,
        *,
        netns: str,
        family: int,
        proposal: Proposal,
    ) -> bool:
        """Enqueue a proposal for batch assembly.

        Returns ``True`` if queued, ``False`` if the queue is full
        (caller increments its own drop counter). Thread-safe —
        ``asyncio.Queue.put_nowait`` is safe to call from non-loop
        threads because it only calls loop-bound code if the put
        succeeds.

        Per asyncio docs, cross-thread enqueue requires
        ``loop.call_soon_threadsafe`` around ``put_nowait``. We use
        that explicitly so the decoder thread never touches the
        loop's internal futures directly.
        """
        if self._loop is None:
            return False
        verdict = self._tracker.propose(proposal)
        if verdict == Verdict.DEDUP:
            return True   # accepted-and-handled, no batch needed
        op = _PendingOp(
            proposal=proposal,
            netns=netns,
            family=family,
            verdict=verdict,
        )
        try:
            self._loop.call_soon_threadsafe(self._enqueue_nothrow, op)
        except RuntimeError:
            # Loop closed — drop silently.
            return False
        return True

    def _enqueue_nothrow(self, op: _PendingOp) -> None:
        """Loop-thread enqueue helper used by :meth:`submit`."""
        try:
            self._queue.put_nowait(op)
            self.metrics.submits_total += 1
            depth = self._queue.qsize()
            self.metrics.queue_depth = depth
            if depth > self.metrics.queue_high_water:
                self.metrics.queue_high_water = depth
        except asyncio.QueueFull:
            self.metrics.dropped_queue_full_total += 1

    # ── Drain loop ────────────────────────────────────────────────────

    async def _drain_loop(self) -> None:
        """Consume the queue, accumulate batches, flush on schedule.

        Flush triggers (in priority order):

        1. ``_stopping`` is set — flush everything and exit.
        2. A per-batch BatchBuilder fills up to ``batch_max_ops``.
        3. The oldest open batch is older than ``batch_window_sec``.
        4. The queue is idle and the window has elapsed anyway.

        The loop uses ``asyncio.wait_for`` with the remaining window
        time as the timeout so it doesn't spin when there's no work.
        """
        while not self._stopping:
            op = await self._next_op()
            if op is None:
                await self._flush_due(reason="window")
                continue
            if op is _SENTINEL:
                break
            self.metrics.queue_depth = self._queue.qsize()
            await self._accumulate(op)
        await self._flush_all(reason="shutdown")

    async def _next_op(self) -> "_PendingOp | object | None":
        """Return the next pending op, or ``None`` on window timeout."""
        timeout = self._deadline_until_flush()
        if timeout is None:
            op = await self._queue.get()
            return op
        if timeout <= 0:
            return None
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def _deadline_until_flush(self) -> float | None:
        """Compute the seconds until the oldest open batch must flush.

        Returns ``None`` if there are no open batches (we can wait
        indefinitely for queue activity).
        """
        if not self._batches:
            return None
        now = time.monotonic()
        oldest = min(b.opened_at for b in self._batches.values() if b.proposals)
        return max(0.0, (oldest + self._batch_window) - now)

    async def _accumulate(self, op: _PendingOp) -> None:
        key = (op.netns, op.family)
        state = self._batches.get(key)
        if state is None:
            state = _BatchState(
                builder=BatchBuilder(max_ops=self._batch_max_ops),
                opened_at=time.monotonic(),
            )
            state.builder.reset()
            self._batches[key] = state

        ip = op.proposal.ip_bytes
        try:
            state.builder.append(
                set_id=op.proposal.set_id,
                family=op.family,
                op_kind=BATCH_OP_ADD,
                ttl=op.proposal.ttl,
                ip_bytes=ip,
            )
        except OverflowError:
            await self._flush_one(key, reason="full")
            # Fresh builder, re-open this op's batch.
            state = _BatchState(
                builder=BatchBuilder(max_ops=self._batch_max_ops),
                opened_at=time.monotonic(),
            )
            self._batches[key] = state
            state.builder.append(
                set_id=op.proposal.set_id,
                family=op.family,
                op_kind=BATCH_OP_ADD,
                ttl=op.proposal.ttl,
                ip_bytes=ip,
            )
        state.proposals.append(op.proposal)
        state.verdicts.append(op.verdict)

        if state.builder.full:
            await self._flush_one(key, reason="full")

    async def _flush_due(self, *, reason: str) -> None:
        now = time.monotonic()
        ready = [
            key for key, state in self._batches.items()
            if state.proposals
            and now - state.opened_at >= self._batch_window
        ]
        for key in ready:
            await self._flush_one(key, reason=reason)

    async def _flush_all(self, *, reason: str) -> None:
        for key in list(self._batches):
            if self._batches[key].proposals:
                await self._flush_one(key, reason=reason)

    async def _flush_one(
        self, key: tuple[str, int], *, reason: str
    ) -> None:
        state = self._batches.get(key)
        if state is None or not state.proposals:
            return
        netns, _family = key
        try:
            applied = await self._router.dispatch(netns, state.builder)
        except Exception as e:  # noqa: BLE001
            self.metrics.commit_errors_total += 1
            log.warning(
                "batch dispatch failed: %s", e,
                extra={"netns": netns, "reason": reason})
            # The tracker never saw these as committed, so the
            # decoder is free to resubmit them — do NOT call commit().
            # Just forget the pending state to keep the builder fresh.
            self._batches.pop(key, None)
            return

        # On success, commit to tracker so metrics reflect reality.
        self._tracker.commit(state.proposals, state.verdicts)
        self.metrics.commits_total += 1
        self.metrics.batches_flushed_total += 1
        if reason == "window":
            self.metrics.flush_reason_window_total += 1
        elif reason == "full":
            self.metrics.flush_reason_full_total += 1
        elif reason == "shutdown":
            self.metrics.flush_reason_shutdown_total += 1
        log.debug(
            "flushed batch netns=%s family=%d ops=%d reason=%s applied=%d",
            netns, key[1], len(state.proposals), reason, applied,
        )
        self._batches.pop(key, None)


# Sentinel to wake the drain loop during shutdown. Using an object
# rather than None distinguishes "window elapsed" from "stop requested"
# without an extra flag check on the hot path.
_SENTINEL: object = object()


class SetWriterMetricsCollector(CollectorBase):
    """Prometheus collector for the SetWriter batch pipeline."""

    def __init__(self, writer: "SetWriter") -> None:
        super().__init__(netns="")
        self._writer = writer

    def collect(self) -> list[_MetricFamily]:
        m = self._writer.metrics
        fams: list[_MetricFamily] = []

        def gauge(name: str, help_text: str, value: float) -> None:
            fam = _MetricFamily(name, help_text, [])
            fam.add([], value)
            fams.append(fam)

        def counter(name: str, help_text: str, value: int) -> None:
            fam = _MetricFamily(name, help_text, [], mtype="counter")
            fam.add([], float(value))
            fams.append(fam)

        gauge("shorewalld_setwriter_queue_depth",
              "Current DNS-update proposal queue depth", m.queue_depth)
        gauge("shorewalld_setwriter_queue_high_water",
              "Peak queue depth since daemon start", m.queue_high_water)
        counter("shorewalld_setwriter_submits_total",
                "Total proposals submitted from decoder threads", m.submits_total)
        counter("shorewalld_setwriter_dropped_queue_full_total",
                "Proposals dropped because the queue was saturated",
                m.dropped_queue_full_total)
        counter("shorewalld_setwriter_batches_flushed_total",
                "Batches dispatched to nft workers", m.batches_flushed_total)
        fam = _MetricFamily(
            "shorewalld_setwriter_flush_reason_total",
            "Batch flushes broken down by trigger reason",
            ["reason"], mtype="counter")
        fam.add(["window"], float(m.flush_reason_window_total))
        fam.add(["full"],   float(m.flush_reason_full_total))
        fam.add(["shutdown"], float(m.flush_reason_shutdown_total))
        fams.append(fam)
        counter("shorewalld_setwriter_commits_total",
                "Batches acknowledged OK by nft workers", m.commits_total)
        counter("shorewalld_setwriter_commit_errors_total",
                "Batches that returned a worker error", m.commit_errors_total)
        return fams
