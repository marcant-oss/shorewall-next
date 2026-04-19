"""Unit tests for shorewalld.dns_set_tracker.

The tracker is the central state machine for DNS-backed nft sets:
allowlist management, propose/commit hot path, dedup decisions,
metric bookkeeping, state-file import/export. All tests use a
mocked monotonic clock so timing-dependent behaviour is
deterministic.
"""

from __future__ import annotations

import pytest

from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    FAMILY_V6,
    DnsSetMetricsCollector,
    DnsSetTracker,
    Proposal,
    Verdict,
)
from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsSetSpec


class FakeClock:
    """Monotonic clock with manual advancement."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, delta: float) -> None:
        self.now += delta


@pytest.fixture
def registry():
    reg = DnsSetRegistry()
    reg.add_spec(DnsSetSpec(
        qname="github.com", ttl_floor=300, ttl_ceil=3600, size=256))
    reg.add_spec(DnsSetSpec(
        qname="api.stripe.com", ttl_floor=60, ttl_ceil=3600, size=64))
    return reg


@pytest.fixture
def tracker(registry):
    clock = FakeClock()
    t = DnsSetTracker(clock=clock, refresh_threshold=0.5)
    t.load_registry(registry)
    # Stash clock so tests can advance it.
    t._test_clock = clock  # type: ignore[attr-defined]
    return t


def _ip4(s: str) -> bytes:
    return bytes(int(p) for p in s.split("."))


class TestAllowlistManagement:
    def test_loads_registry_assigns_ids(self, tracker):
        gh_v4 = tracker.set_id_for("github.com", FAMILY_V4)
        gh_v6 = tracker.set_id_for("github.com", FAMILY_V6)
        api_v4 = tracker.set_id_for("api.stripe.com", FAMILY_V4)
        assert gh_v4 is not None and gh_v6 is not None
        assert gh_v4 != gh_v6
        assert api_v4 != gh_v4
        # All four mappings distinct
        ids = {gh_v4, gh_v6, api_v4,
               tracker.set_id_for("api.stripe.com", FAMILY_V6)}
        assert len(ids) == 4

    def test_unknown_name_returns_none(self, tracker):
        assert tracker.set_id_for("unknown.example", FAMILY_V4) is None

    def test_reverse_lookup(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        assert tracker.name_for(sid) == ("github.com", FAMILY_V4)

    def test_reload_preserves_existing_state(self, tracker, registry):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        # Write an element
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])
        # Reload same registry — state should survive.
        tracker.load_registry(registry)
        assert tracker.set_id_for("github.com", FAMILY_V4) == sid
        snap = tracker.snapshot()
        assert snap.per_set[(sid, FAMILY_V4)].elements == 1

    def test_reload_drops_removed_names(self, tracker):
        sid = tracker.set_id_for("api.stripe.com", FAMILY_V4)
        assert sid is not None
        # Write something
        p = Proposal(set_id=sid, ip_bytes=_ip4("9.9.9.9"), ttl=300)
        tracker.commit([p], [Verdict.ADD])
        # Reload with only github.com
        reg2 = DnsSetRegistry()
        reg2.add_spec(DnsSetSpec(
            qname="github.com", ttl_floor=300, ttl_ceil=3600, size=256))
        tracker.load_registry(reg2)
        assert tracker.set_id_for("api.stripe.com", FAMILY_V4) is None

    def test_generation_counter_increments(self, tracker, registry):
        g0 = tracker.snapshot().allowlist_generation
        tracker.load_registry(registry)
        g1 = tracker.snapshot().allowlist_generation
        assert g1 == g0 + 1


class TestPropose:
    def test_unknown_set_returns_dedup(self, tracker):
        verdict = tracker.propose(
            Proposal(set_id=9999, ip_bytes=_ip4("1.2.3.4"), ttl=300))
        assert verdict == Verdict.DEDUP

    def test_first_entry_returns_add(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        verdict = tracker.propose(
            Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600))
        assert verdict == Verdict.ADD

    def test_recent_same_entry_returns_dedup(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])
        # Propose same entry immediately — cached deadline is full.
        assert tracker.propose(p) == Verdict.DEDUP

    def test_aging_entry_returns_refresh(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])
        # Age past 50% of TTL (600s × 0.5 = 300s).
        tracker._test_clock.advance(350)
        assert tracker.propose(p) == Verdict.REFRESH

    def test_ttl_floor_applied(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        # github.com has ttl_floor=300 — propose with ttl=10 clamps to
        # 300s, so the entry lives much longer than its nominal TTL.
        # Repeating the same low-TTL proposal 50s later should dedup:
        # clamped threshold = 0.5*300 = 150s, remaining = 300-50 = 250s.
        p_low = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=10)
        tracker.commit([p_low], [Verdict.ADD])
        tracker._test_clock.advance(50)
        assert tracker.propose(p_low) == Verdict.DEDUP

    def test_ttl_ceil_applied(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        # github.com ttl_ceil=3600 — propose with ttl=100000 clamps
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=100000)
        tracker.commit([p], [Verdict.ADD])
        tracker._test_clock.advance(3500)  # past ceil-threshold
        # Still within 50% of 3600? 3500 > 0.5*3600 = 1800 → so <=50% remain
        # 3600-3500 = 100 remaining, less than 1800 → REFRESH
        assert tracker.propose(
            Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=100000)
        ) == Verdict.REFRESH

    def test_dedup_hits_counted(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])
        for _ in range(5):
            tracker.propose(p)
        snap = tracker.snapshot()
        assert snap.per_set[(sid, FAMILY_V4)].dedup_hits_total == 5


class TestCommit:
    def test_add_populates_state(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])
        snap = tracker.snapshot()
        m = snap.per_set[(sid, FAMILY_V4)]
        assert m.elements == 1
        assert m.adds_total == 1
        assert m.dedup_misses_total == 1

    def test_refresh_does_not_grow_elements(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])
        tracker.commit([p], [Verdict.REFRESH])
        snap = tracker.snapshot()
        m = snap.per_set[(sid, FAMILY_V4)]
        assert m.elements == 1
        assert m.adds_total == 1
        assert m.refreshes_total == 1

    def test_unknown_set_commit_is_ignored(self, tracker):
        # Drop-through safety: a late commit for an evicted set_id
        # must not crash the tracker.
        p = Proposal(set_id=9999, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])  # no exception

    def test_multiple_entries_per_set(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        ips = [_ip4("1.1.1.1"), _ip4("2.2.2.2"), _ip4("3.3.3.3")]
        props = [Proposal(set_id=sid, ip_bytes=ip, ttl=600) for ip in ips]
        tracker.commit(props, [Verdict.ADD] * 3)
        snap = tracker.snapshot()
        assert snap.per_set[(sid, FAMILY_V4)].elements == 3


class TestPruneExpired:
    def test_removes_past_deadline_entries(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])
        tracker._test_clock.advance(700)  # past deadline
        removed = tracker.prune_expired()
        assert removed == 1
        snap = tracker.snapshot()
        m = snap.per_set[(sid, FAMILY_V4)]
        assert m.elements == 0
        assert m.expiries_total == 1

    def test_keeps_live_entries(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        live = Proposal(
            set_id=sid, ip_bytes=_ip4("1.1.1.1"), ttl=3600)
        dead = Proposal(
            set_id=sid, ip_bytes=_ip4("2.2.2.2"), ttl=300)
        tracker.commit([live, dead], [Verdict.ADD, Verdict.ADD])
        tracker._test_clock.advance(500)  # dead expired, live survives
        tracker.prune_expired()
        snap = tracker.snapshot()
        assert snap.per_set[(sid, FAMILY_V4)].elements == 1


class TestSnapshot:
    def test_totals_sum_across_sets(self, tracker):
        sid1 = tracker.set_id_for("github.com", FAMILY_V4)
        sid2 = tracker.set_id_for("api.stripe.com", FAMILY_V4)
        tracker.commit([
            Proposal(set_id=sid1, ip_bytes=_ip4("1.1.1.1"), ttl=600),
            Proposal(set_id=sid2, ip_bytes=_ip4("2.2.2.2"), ttl=600),
        ], [Verdict.ADD, Verdict.ADD])
        snap = tracker.snapshot()
        assert snap.totals.elements == 2
        assert snap.totals.adds_total == 2

    def test_per_set_is_deep_copy(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])
        snap = tracker.snapshot()
        # Mutating the snapshot must not bleed back.
        snap.per_set[(sid, FAMILY_V4)].elements = 999
        snap2 = tracker.snapshot()
        assert snap2.per_set[(sid, FAMILY_V4)].elements == 1

    def test_unknown_qname_counter(self, tracker):
        for _ in range(10):
            tracker.note_unknown_qname()
        snap = tracker.snapshot()
        assert snap.unknown_qname_total == 10


class TestStateExportImport:
    def test_round_trip(self, tracker, registry):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        props = [
            Proposal(set_id=sid, ip_bytes=_ip4("1.1.1.1"), ttl=600),
            Proposal(set_id=sid, ip_bytes=_ip4("2.2.2.2"), ttl=600),
        ]
        tracker.commit(props, [Verdict.ADD, Verdict.ADD])
        exported = tracker.export_state()
        assert len(exported) == 2

        # Fresh tracker with same registry — import should restore state.
        clock = FakeClock(start=1000.0)
        t2 = DnsSetTracker(clock=clock)
        t2.load_registry(registry)
        installed = t2.import_state(exported, now=1000.0)
        assert installed == 2
        assert t2.snapshot().per_set[
            (t2.set_id_for("github.com", FAMILY_V4), FAMILY_V4)
        ].elements == 2

    def test_import_drops_expired(self, tracker, registry):
        # Build a synthetic export with a past deadline.
        clock = FakeClock(start=2000.0)
        t2 = DnsSetTracker(clock=clock)
        t2.load_registry(registry)
        entries = [("github.com", FAMILY_V4, _ip4("1.2.3.4"), 1500.0)]
        installed = t2.import_state(entries, now=2000.0)
        assert installed == 0

    def test_import_drops_removed_name(self, tracker):
        # The exported state has github.com, but we reload with api only.
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        tracker.commit(
            [Proposal(set_id=sid, ip_bytes=_ip4("1.1.1.1"), ttl=600)],
            [Verdict.ADD])
        exported = tracker.export_state()

        reg2 = DnsSetRegistry()
        reg2.add_spec(DnsSetSpec(
            qname="api.stripe.com", ttl_floor=60, ttl_ceil=3600, size=64))
        clock = FakeClock()
        t2 = DnsSetTracker(clock=clock)
        t2.load_registry(reg2)
        installed = t2.import_state(exported, now=1000.0)
        assert installed == 0


class TestDnsSetMetricsCollector:
    """Exporter view of the tracker's per-set metrics."""

    @staticmethod
    def _family(families, name):
        for f in families:
            if f.name == name:
                return f
        raise AssertionError(f"no metric family {name!r}")

    def test_emits_per_set_elements_gauge(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        tracker.commit(
            [Proposal(set_id=sid, ip_bytes=_ip4("1.1.1.1"), ttl=600),
             Proposal(set_id=sid, ip_bytes=_ip4("2.2.2.2"), ttl=600)],
            [Verdict.ADD, Verdict.ADD])

        families = DnsSetMetricsCollector(tracker).collect()
        elements = self._family(families, "shorewalld_dns_set_elements")
        sample = [s for s in elements.samples
                  if s[0] == ["github.com", "ipv4"]]
        assert len(sample) == 1
        assert sample[0][1] == 2.0

    def test_dedup_split_counters(self, tracker):
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        p = Proposal(set_id=sid, ip_bytes=_ip4("1.2.3.4"), ttl=600)
        tracker.commit([p], [Verdict.ADD])
        # 3 dedup hits
        for _ in range(3):
            tracker.propose(p)

        families = DnsSetMetricsCollector(tracker).collect()
        hits = self._family(families, "shorewalld_dns_set_dedup_hits_total")
        miss = self._family(families, "shorewalld_dns_set_dedup_misses_total")
        hit_by_set = {tuple(lv): v for lv, v in hits.samples}
        miss_by_set = {tuple(lv): v for lv, v in miss.samples}
        assert hit_by_set[("github.com", "ipv4")] == 3.0
        # 1 ADD = 1 dedup_miss
        assert miss_by_set[("github.com", "ipv4")] == 1.0

    def test_last_update_age_omitted_when_never_written(self, tracker):
        # github.com has entries below; api.stripe.com is declared but
        # never touched → should NOT appear in the age gauge.
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        tracker.commit(
            [Proposal(set_id=sid, ip_bytes=_ip4("1.1.1.1"), ttl=600)],
            [Verdict.ADD])
        tracker._test_clock.advance(42.0)

        families = DnsSetMetricsCollector(tracker).collect()
        age = self._family(
            families, "shorewalld_dns_set_last_update_age_seconds")
        by_set = {tuple(lv): v for lv, v in age.samples}
        # github.com v4 observed; api.stripe.com entries missing.
        assert by_set[("github.com", "ipv4")] == pytest.approx(42.0)
        assert ("api.stripe.com", "ipv4") not in by_set
        assert ("api.stripe.com", "ipv6") not in by_set

    def test_emits_both_families_per_qname(self, tracker):
        sid_v4 = tracker.set_id_for("github.com", FAMILY_V4)
        sid_v6 = tracker.set_id_for("github.com", FAMILY_V6)
        tracker.commit(
            [Proposal(set_id=sid_v4, ip_bytes=_ip4("1.1.1.1"), ttl=600),
             Proposal(set_id=sid_v6, ip_bytes=b"\x20\x01" + b"\x00"*14,
                      ttl=600)],
            [Verdict.ADD, Verdict.ADD])

        families = DnsSetMetricsCollector(tracker).collect()
        adds = self._family(families, "shorewalld_dns_set_adds_total")
        by_labels = {tuple(lv): v for lv, v in adds.samples}
        assert by_labels[("github.com", "ipv4")] == 1.0
        assert by_labels[("github.com", "ipv6")] == 1.0


class TestThreadSafety:
    """Loose smoke tests — not a proper concurrency audit, just
    ensures the lock discipline doesn't deadlock under mixed ops."""

    def test_concurrent_propose_and_snapshot(self, tracker):
        import threading
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        stop = threading.Event()
        errors: list[BaseException] = []

        def writer():
            try:
                for i in range(100):
                    tracker.propose(Proposal(
                        set_id=sid,
                        ip_bytes=bytes([1, 1, 1, i % 256]),
                        ttl=600))
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        def reader():
            try:
                while not stop.is_set():
                    tracker.snapshot()
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        threads[0].join()
        threads[1].join()
        stop.set()
        threads[2].join(timeout=1.0)
        assert not errors
