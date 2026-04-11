"""Ruleset-reload detection + DNS set repopulation.

When the shorewall-nft compiler reloads the ``inet shorewall``
table (``shorewall-nft start`` / ``restart`` / ``reload``), the
kernel replaces the table atomically. Any DNS-managed set in the
old table is wiped — its elements were associated with the old
set instance and don't survive the swap.

Without this module, the next TTL-worth of traffic to a
DNS-managed hostname would be denied until the recursor happens
to re-answer for each name. With this module, the reload is
detected within ``RELOAD_POLL_INTERVAL`` (default 2 s) and every
live entry from the :class:`DnsSetTracker` is pushed back into
the new table in one batched write per ``(netns, set)``.

Reload detection
----------------

Phase 7 ships with a **poll-based** detector: every
``RELOAD_POLL_INTERVAL`` seconds the monitor asks libnftables
for the table's current state and compares a small fingerprint
against the last observed value. Any transition counts as a
potential reload and kicks off repopulation:

* **absent → present**: fresh table just got loaded, populate.
* **present → absent**: table was dropped (``shorewall-nft stop``),
  nothing to repopulate — the shadow in the tracker survives
  untouched, so the next ``start`` re-hydrates from it.
* **present with different fingerprint**: in-place ``nft -f`` swap;
  same repopulation path as absent→present.

A future phase can replace the poll loop with a real
``NFNLGRP_NFTABLES`` multicast listener if profiling shows the
2-second detection gap matters. The current interface deliberately
hides whether detection is poll-based or event-based so the swap
is a local change to this module.

Repopulation path
-----------------

Repopulation does **not** go through :class:`SetWriter.submit` —
that path runs through ``tracker.propose`` which would return
``DEDUP`` for every entry the tracker already thinks it has.
Instead, the monitor asks the tracker for its current
``export_state()`` list, groups by ``(netns, set_id)``, builds
:class:`BatchBuilder` batches directly, and dispatches them via
the :class:`WorkerRouter`.

This is the correct abstraction split: the tracker is the truth,
SetWriter is the incremental diff mechanism, reload_monitor is
the reconciliation mechanism. Each has a single job.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .batch_codec import BATCH_OP_ADD, MAX_OPS_PER_BATCH, BatchBuilder
from .dns_set_tracker import DnsSetTracker
from .logsetup import get_logger
from .worker_router import WorkerRouter

log = get_logger("reload")


RELOAD_POLL_INTERVAL = 2.0          # seconds between fingerprint checks

# Reason codes for reload events — make it easy to distinguish why
# the monitor fired in metrics.
REASON_INITIAL = "initial"          # first-ever populate at startup
REASON_ABSENT_TO_PRESENT = "table_appeared"
REASON_FINGERPRINT_CHANGE = "table_replaced"
REASON_MANUAL = "manual"            # operator triggered via API/signal


@dataclass
class ReloadMetrics:
    """Counters the exporter publishes as ``shorewalld_reload_*``.

    Split by reason so operators can tell a boot-time populate from
    a production reload blip from a maintenance restart.
    """
    events_total: int = 0
    events_by_reason_total: dict[str, int] = field(
        default_factory=lambda: {
            REASON_INITIAL: 0,
            REASON_ABSENT_TO_PRESENT: 0,
            REASON_FINGERPRINT_CHANGE: 0,
            REASON_MANUAL: 0,
        })
    repopulate_batches_total: int = 0
    repopulate_entries_total: int = 0
    repopulate_errors_total: int = 0
    last_event_mono: float = 0.0
    last_repopulate_seconds: float = 0.0

    def bump_reason(self, reason: str) -> None:
        self.events_total += 1
        self.events_by_reason_total[reason] = (
            self.events_by_reason_total.get(reason, 0) + 1)
        self.last_event_mono = time.monotonic()


# ---------------------------------------------------------------------------
# Fingerprint probe — abstraction over "does the table exist, and has it
# changed since last time".
# ---------------------------------------------------------------------------


class TableFingerprintProbe:
    """Callable that returns a per-netns fingerprint of the inet table.

    Default implementation shells through :class:`NftInterface` to
    ``list table inet shorewall`` and returns a tuple keyed on the
    rendered JSON length + rule-count + set-count — small enough
    to be cheap, specific enough that an in-place ``nft -f`` swap
    produces a different value.

    Tests inject a stub that returns pre-canned fingerprints from a
    list so the poll loop can be driven deterministically.
    """

    def __init__(self, nft_interface, netns: str = "") -> None:
        self._nft = nft_interface
        self._netns = netns

    def __call__(self) -> tuple | None:
        """Return a fingerprint, or ``None`` if the table is absent.

        The shape is intentionally opaque — callers compare for
        equality only, never interpret the contents.
        """
        try:
            data = self._nft.list_table(
                family="inet", table="shorewall",
                netns=self._netns or None,
            )
        except Exception:
            return None
        if not data:
            return None
        rule_count = 0
        set_count = 0
        # libnftables returns a ``{'nftables': [...]}`` top-level.
        items = data.get("nftables") if isinstance(data, dict) else data
        if not items:
            return None
        for item in items:
            if not isinstance(item, dict):
                continue
            if "rule" in item:
                rule_count += 1
            elif "set" in item:
                set_count += 1
        return (rule_count, set_count, len(items))


# ---------------------------------------------------------------------------
# Monitor — lifecycle owner + repopulate driver
# ---------------------------------------------------------------------------


class ReloadMonitor:
    """Background loop that reacts to ruleset changes.

    Typical wiring inside :class:`Daemon`::

        probes = {"fw": TableFingerprintProbe(nft, "fw"),
                  "rns1": TableFingerprintProbe(nft, "rns1")}
        monitor = ReloadMonitor(
            tracker=tracker,
            router=router,
            probes=probes,
            poll_interval=2.0,
        )
        await monitor.start(loop)
        ...
        await monitor.stop()
    """

    def __init__(
        self,
        *,
        tracker: DnsSetTracker,
        router: WorkerRouter,
        probes: dict[str, Callable[[], tuple | None]],
        poll_interval: float = RELOAD_POLL_INTERVAL,
    ) -> None:
        self._tracker = tracker
        self._router = router
        self._probes = probes
        self._poll_interval = poll_interval
        self._fingerprints: dict[str, tuple | None] = {}
        self._task: asyncio.Task[None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stopping = False
        self.metrics = ReloadMetrics()

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(
        self, loop: asyncio.AbstractEventLoop | None = None
    ) -> None:
        if self._task is not None:
            return
        self._loop = loop or asyncio.get_running_loop()
        self._task = self._loop.create_task(self._poll_loop())
        # Repopulate at startup so state loaded from
        # ``StateStore.load()`` reaches the live table immediately.
        await self.repopulate_all(reason=REASON_INITIAL)

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _poll_loop(self) -> None:
        while not self._stopping:
            try:
                await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                return
            await self._tick()

    async def _tick(self) -> None:
        for netns, probe in self._probes.items():
            try:
                new_fp = probe()
            except Exception as e:  # noqa: BLE001
                log.debug(
                    "probe failed",
                    extra={"netns": netns, "error": str(e)})
                continue
            old_fp = self._fingerprints.get(netns)
            self._fingerprints[netns] = new_fp
            if new_fp is None:
                # Table absent. Only interesting on transition
                # present→absent, but there's nothing to do about
                # it on our side — the tracker's shadow copy
                # survives untouched for the next repopulate.
                continue
            if old_fp is None:
                await self._repopulate_netns(
                    netns, reason=REASON_ABSENT_TO_PRESENT)
            elif old_fp != new_fp:
                await self._repopulate_netns(
                    netns, reason=REASON_FINGERPRINT_CHANGE)

    # ── Repopulation ──────────────────────────────────────────────────

    async def request_repopulate(
        self, netns: str | None = None
    ) -> None:
        """Force a repopulation, skipping the fingerprint check.

        Exposed for operator-driven refresh (eventually via a unix
        socket or SIGHUP handler). Repopulates a specific netns if
        provided, otherwise all of them.
        """
        if netns is None:
            await self.repopulate_all(reason=REASON_MANUAL)
        else:
            await self._repopulate_netns(netns, reason=REASON_MANUAL)

    async def repopulate_all(self, *, reason: str) -> None:
        """Push every live tracker entry back into all managed netns."""
        for netns in self._probes:
            await self._repopulate_netns(netns, reason=reason)

    async def _repopulate_netns(
        self, netns: str, *, reason: str
    ) -> None:
        entries = self._tracker.export_state()
        if not entries:
            self.metrics.bump_reason(reason)
            return
        started = time.monotonic()
        batches_sent = 0
        entries_sent = 0
        builder = BatchBuilder(max_ops=MAX_OPS_PER_BATCH)
        builder.reset()
        try:
            for qname, family, ip_bytes, deadline in entries:
                set_id = self._tracker.set_id_for(qname, family)
                if set_id is None:
                    continue
                ttl = max(1, int(deadline - time.monotonic()))
                builder.append(
                    set_id=set_id,
                    family=family,
                    op_kind=BATCH_OP_ADD,
                    ttl=ttl,
                    ip_bytes=ip_bytes,
                )
                entries_sent += 1
                if builder.full:
                    await self._router.dispatch(netns, builder)
                    batches_sent += 1
                    builder = BatchBuilder(max_ops=MAX_OPS_PER_BATCH)
                    builder.reset()
            if not builder.empty:
                await self._router.dispatch(netns, builder)
                batches_sent += 1
        except Exception as e:  # noqa: BLE001
            self.metrics.repopulate_errors_total += 1
            log.warning(
                "repopulate failed",
                extra={"netns": netns, "error": str(e)})
            return
        elapsed = time.monotonic() - started
        self.metrics.bump_reason(reason)
        self.metrics.repopulate_batches_total += batches_sent
        self.metrics.repopulate_entries_total += entries_sent
        self.metrics.last_repopulate_seconds = elapsed
        log.info(
            "repopulated netns after reload",
            extra={
                "netns": netns or "(own)",
                "reason": reason,
                "batches": batches_sent,
                "entries": entries_sent,
                "elapsed_ms": round(elapsed * 1000, 1),
            },
        )


# ---------------------------------------------------------------------------
# Test helper: a scripted probe that returns pre-canned values.
# ---------------------------------------------------------------------------


class ScriptedProbe:
    """Deterministic probe for unit tests.

    Drives the monitor through a sequence of fingerprints so tests
    can verify the absent→present and fingerprint-change branches
    without standing up a real nft table.
    """

    def __init__(self, sequence: Iterable[tuple | None]):
        self._sequence = list(sequence)
        self._index = 0

    def __call__(self) -> tuple | None:
        if self._index >= len(self._sequence):
            return self._sequence[-1] if self._sequence else None
        value = self._sequence[self._index]
        self._index += 1
        return value
