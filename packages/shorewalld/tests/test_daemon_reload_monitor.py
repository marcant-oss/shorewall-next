"""Tests for reload detection and repopulation."""

from __future__ import annotations

import asyncio

import pytest

from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    DnsSetTracker,
    Proposal,
    Verdict,
)
from shorewalld.reload_monitor import (
    REASON_ABSENT_TO_PRESENT,
    REASON_FINGERPRINT_CHANGE,
    REASON_INITIAL,
    REASON_MANUAL,
    ReloadMonitor,
    ScriptedProbe,
)
from shorewalld.worker_router import (
    WorkerRouter,
    inproc_worker_pair,
)
from shorewall_nft.nft.dns_sets import (
    DnsSetRegistry,
    DnsSetSpec,
    qname_to_set_name,
)


@pytest.fixture
def tracker_with_entries():
    reg = DnsSetRegistry()
    reg.add_spec(DnsSetSpec(
        qname="github.com", ttl_floor=60, ttl_ceil=3600, size=256))
    t = DnsSetTracker()
    t.load_registry(reg)
    sid_v4 = t.set_id_for("github.com", FAMILY_V4)
    t.commit([
        Proposal(set_id=sid_v4, ip_bytes=b"\x01\x02\x03\x04", ttl=600),
        Proposal(set_id=sid_v4, ip_bytes=b"\x05\x06\x07\x08", ttl=600),
    ], [Verdict.ADD, Verdict.ADD])
    return t


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def router_with_inproc(tracker_with_entries, event_loop):
    scripts: list[str] = []

    def lookup(key):
        entry = tracker_with_entries.name_for(key[0])
        if entry is None:
            return None
        qname, family = entry
        return qname_to_set_name(
            qname, "v4" if family == 4 else "v6")

    pw, _ = inproc_worker_pair(
        tracker_with_entries, event_loop, lookup,
        apply_cb=scripts.append)
    router = WorkerRouter(tracker=tracker_with_entries, loop=event_loop)
    router._workers["fw"] = pw
    yield router, scripts
    event_loop.run_until_complete(router.shutdown())


class TestReloadMonitorDetection:
    def test_initial_populate_at_start(
        self, tracker_with_entries, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        probe = ScriptedProbe([(1, 1, 2)])
        monitor = ReloadMonitor(
            tracker=tracker_with_entries,
            router=router,
            probes={"fw": probe},
            poll_interval=60.0,          # unreachable — only initial
        )
        event_loop.run_until_complete(monitor.start(event_loop))
        event_loop.run_until_complete(monitor.stop())
        assert monitor.metrics.events_by_reason_total[REASON_INITIAL] >= 1
        # At least one script executed (initial repopulate)
        assert any("dns_github_com_v4" in s for s in scripts)
        assert monitor.metrics.repopulate_entries_total == 2

    def test_absent_to_present_transition(
        self, tracker_with_entries, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        probe = ScriptedProbe([None, None, (1, 1, 2), (1, 1, 2)])
        monitor = ReloadMonitor(
            tracker=tracker_with_entries,
            router=router,
            probes={"fw": probe},
            poll_interval=0.01,
        )

        async def run():
            await monitor.start(event_loop)
            # Let the poll loop tick a few times.
            await asyncio.sleep(0.1)
            await monitor.stop()

        event_loop.run_until_complete(run())
        # We should see INITIAL + ABSENT_TO_PRESENT at least once.
        # The initial run observed None (nothing to do), then a
        # later tick saw the table appear.
        reason_counts = monitor.metrics.events_by_reason_total
        assert reason_counts[REASON_ABSENT_TO_PRESENT] >= 1

    def test_fingerprint_change_triggers_repopulate(
        self, tracker_with_entries, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        probe = ScriptedProbe([
            (1, 1, 2),   # initial
            (1, 1, 2),   # same → no-op
            (2, 1, 3),   # changed → reload!
            (2, 1, 3),   # same again
        ])
        monitor = ReloadMonitor(
            tracker=tracker_with_entries,
            router=router,
            probes={"fw": probe},
            poll_interval=0.02,
        )

        async def run():
            await monitor.start(event_loop)
            await asyncio.sleep(0.1)
            await monitor.stop()

        event_loop.run_until_complete(run())
        assert (monitor.metrics.events_by_reason_total[
            REASON_FINGERPRINT_CHANGE] >= 1)

    def test_manual_request_repopulate(
        self, tracker_with_entries, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        probe = ScriptedProbe([(1, 1, 2)])
        monitor = ReloadMonitor(
            tracker=tracker_with_entries,
            router=router,
            probes={"fw": probe},
            poll_interval=60.0,
        )

        async def run():
            await monitor.start(event_loop)
            await monitor.request_repopulate(netns="fw")
            await monitor.stop()

        event_loop.run_until_complete(run())
        assert monitor.metrics.events_by_reason_total[
            REASON_MANUAL] >= 1

    def test_manual_request_all(
        self, tracker_with_entries, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        probe = ScriptedProbe([(1, 1, 2)])
        monitor = ReloadMonitor(
            tracker=tracker_with_entries,
            router=router,
            probes={"fw": probe},
            poll_interval=60.0,
        )

        async def run():
            await monitor.start(event_loop)
            await monitor.request_repopulate()
            await monitor.stop()

        event_loop.run_until_complete(run())
        assert monitor.metrics.events_by_reason_total[
            REASON_MANUAL] >= 1


class TestRepopulateContents:
    def test_repopulate_scripts_contain_expected_ips(
        self, tracker_with_entries, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        probe = ScriptedProbe([(1, 1, 2)])
        monitor = ReloadMonitor(
            tracker=tracker_with_entries,
            router=router,
            probes={"fw": probe},
            poll_interval=60.0,
        )

        async def run():
            await monitor.start(event_loop)
            await monitor.stop()

        event_loop.run_until_complete(run())
        joined = "\n".join(scripts)
        assert "1.2.3.4" in joined
        assert "5.6.7.8" in joined
        assert "dns_github_com_v4" in joined

    def test_repopulate_batch_metrics(
        self, tracker_with_entries, event_loop, router_with_inproc
    ):
        router, _ = router_with_inproc
        probe = ScriptedProbe([(1, 1, 2)])
        monitor = ReloadMonitor(
            tracker=tracker_with_entries,
            router=router,
            probes={"fw": probe},
            poll_interval=60.0,
        )

        async def run():
            await monitor.start(event_loop)
            await monitor.stop()

        event_loop.run_until_complete(run())
        assert monitor.metrics.repopulate_batches_total >= 1
        assert monitor.metrics.repopulate_entries_total == 2


class TestScriptedProbe:
    def test_returns_values_in_order(self):
        probe = ScriptedProbe([None, (1, 1, 1), (2, 2, 2)])
        assert probe() is None
        assert probe() == (1, 1, 1)
        assert probe() == (2, 2, 2)

    def test_sticks_on_last_after_exhaustion(self):
        probe = ScriptedProbe([None, (9, 9, 9)])
        probe()
        probe()
        # After exhaustion, returns the final value forever.
        assert probe() == (9, 9, 9)
        assert probe() == (9, 9, 9)
