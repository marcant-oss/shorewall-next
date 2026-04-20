"""Wave 6 — unit tests for nfsets Prometheus metrics.

Covers:
* NfsetsCollector: manager entry/host/payload gauges
* NfsetsCollector: DnsSetTracker N→1 shared-qname gauge
* NfsetsCollector: PlainListTracker refresh counters, entries, staleness,
  inotify flag, errors
* NfsetsManager.entries_by_backend / hosts_by_backend / payload_bytes
* PlainListTracker.metrics_snapshot()
* Label cardinality sanity
* Regression: existing metric names unchanged

Smoke test: instantiate NfsetsCollector, call collect(), verify
generate_latest() works (requires prometheus_client).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from unittest.mock import MagicMock

import pytest

from shorewalld.exporter import NfsetsCollector, _MetricFamily, ShorewalldRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_family(
    families: list[_MetricFamily], name: str
) -> _MetricFamily:
    for f in families:
        if f.name == name:
            return f
    raise AssertionError(f"no metric family {name!r}")


def _samples_dict(fam: _MetricFamily) -> dict[tuple, float]:
    """Return {tuple(label_values): value} for easy assertions."""
    return {tuple(lv): v for lv, v in fam.samples}


# ---------------------------------------------------------------------------
# NfSetsManager stub
# ---------------------------------------------------------------------------

class _FakeNfSetsManager:
    """Minimal stub matching the Wave 6 API additions to NfSetsManager."""

    def __init__(
        self,
        entries_by_backend: dict[str, int] | None = None,
        hosts_by_backend: dict[str, int] | None = None,
        payload_bytes: int = 0,
    ) -> None:
        self._entries = entries_by_backend or {}
        self._hosts = hosts_by_backend or {}
        self._payload = payload_bytes

    def entries_by_backend(self) -> dict[str, int]:
        return self._entries

    def hosts_by_backend(self) -> dict[str, int]:
        return self._hosts

    def payload_bytes(self) -> int:
        return self._payload


# ---------------------------------------------------------------------------
# DnsSetTracker stub (minimal)
# ---------------------------------------------------------------------------

class _FakeLock:
    """Trivial context-manager stub for DnsSetTracker._lock."""
    def __enter__(self): return self
    def __exit__(self, *_): return False


class _FakeDnsSetTracker:
    """Minimal stub exposing _lock, _by_name, _by_id, and the
    shared_qname_counts() public API added in W7."""

    def __init__(
        self,
        by_name: dict[tuple[str, int], int] | None = None,
        by_id: dict[int, tuple[str, int]] | None = None,
    ) -> None:
        self._lock = _FakeLock()
        self._by_name = by_name or {}
        self._by_id = by_id or {}

    def shared_qname_counts(self) -> dict[tuple[str, str], int]:
        counts_by_sid: dict[tuple[int, str], int] = {}
        for (_, family), sid in self._by_name.items():
            fam_str = "ipv4" if family == 4 else "ipv6"
            key = (sid, fam_str)
            counts_by_sid[key] = counts_by_sid.get(key, 0) + 1
        result: dict[tuple[str, str], int] = {}
        for (sid, fam_str), count in counts_by_sid.items():
            canonical = self._by_id.get(sid)
            if canonical is None:
                continue
            result[(canonical[0], fam_str)] = count
        return result


# ---------------------------------------------------------------------------
# PlainListTracker stub
# ---------------------------------------------------------------------------

@dataclass
class _FakePlainListSnapshot:
    name: str
    refresh_total: int = 0
    refresh_success_total: int = 0
    refresh_failure_total: int = 0
    refresh_error_counts: dict = field(default_factory=dict)
    last_success_ts: float = 0.0
    refresh_duration_sum: float = 0.0
    refresh_duration_count: int = 0
    v4_entries: int = 0
    v6_entries: int = 0
    inotify_active: int = 0
    source_type: str = "file"


class _FakePlainListTracker:
    def __init__(self, snapshots: list[_FakePlainListSnapshot]) -> None:
        self._snapshots = snapshots

    def metrics_snapshot(self):
        return self._snapshots


# ---------------------------------------------------------------------------
# NfSetsManager helper method tests
# ---------------------------------------------------------------------------

def test_nfsets_manager_entries_by_backend_from_payload():
    """NfSetsManager.entries_by_backend() counts entries per backend."""
    from shorewalld.nfsets_manager import NfSetsManager

    # Use an empty payload — entries_by_backend() returns {}
    mgr = NfSetsManager({})
    assert mgr.entries_by_backend() == {}
    assert mgr.hosts_by_backend() == {}
    assert mgr.payload_bytes() == 0


def test_nfsets_manager_stub_returns_counts():
    """Fake manager returns expected counts for collector test."""
    mgr = _FakeNfSetsManager(
        entries_by_backend={"dnstap": 2, "ip-list-plain": 1},
        hosts_by_backend={"dnstap": 4, "ip-list-plain": 1},
        payload_bytes=512,
    )
    assert mgr.entries_by_backend() == {"dnstap": 2, "ip-list-plain": 1}
    assert mgr.hosts_by_backend() == {"dnstap": 4, "ip-list-plain": 1}
    assert mgr.payload_bytes() == 512


# ---------------------------------------------------------------------------
# NfsetsCollector — manager metrics
# ---------------------------------------------------------------------------

class TestNfsetsCollectorManager:
    def _make(self, manager=None, tracker=None, plain=None):
        return NfsetsCollector("fw", manager=manager, tracker=tracker,
                               plain_tracker=plain)

    def test_entries_gauge_populated(self):
        mgr = _FakeNfSetsManager(
            {"dnstap": 3, "resolver": 1},
            {"dnstap": 6, "resolver": 2},
            payload_bytes=200,
        )
        col = self._make(manager=mgr)
        fams = col.collect()

        entries = _get_family(fams, "shorewalld_nfsets_entries")
        sd = _samples_dict(entries)
        assert sd[("fw", "dnstap")] == 3.0
        assert sd[("fw", "resolver")] == 1.0

    def test_hosts_gauge_populated(self):
        mgr = _FakeNfSetsManager(
            {"ip-list-plain": 2},
            {"ip-list-plain": 5},
        )
        col = self._make(manager=mgr)
        fams = col.collect()

        hosts = _get_family(fams, "shorewalld_nfsets_hosts")
        sd = _samples_dict(hosts)
        assert sd[("fw", "ip-list-plain")] == 5.0

    def test_payload_bytes_gauge(self):
        mgr = _FakeNfSetsManager(payload_bytes=1024)
        col = self._make(manager=mgr)
        fams = col.collect()

        payload = _get_family(fams, "shorewalld_nfsets_payload_bytes")
        assert payload.samples == [(["fw"], 1024.0)]

    def test_empty_when_no_manager(self):
        col = self._make(manager=None)
        fams = col.collect()

        entries = _get_family(fams, "shorewalld_nfsets_entries")
        hosts = _get_family(fams, "shorewalld_nfsets_hosts")
        payload = _get_family(fams, "shorewalld_nfsets_payload_bytes")
        assert entries.samples == []
        assert hosts.samples == []
        assert payload.samples == []

    def test_metric_types(self):
        mgr = _FakeNfSetsManager({"dnstap": 1}, {"dnstap": 2}, 100)
        col = self._make(manager=mgr)
        fams = col.collect()

        for name in ("shorewalld_nfsets_entries", "shorewalld_nfsets_hosts",
                     "shorewalld_nfsets_payload_bytes"):
            fam = _get_family(fams, name)
            assert fam.mtype == "gauge", f"{name} should be gauge"

    def test_labels_instance_and_backend(self):
        mgr = _FakeNfSetsManager({"dnstap": 1}, {"dnstap": 2}, 0)
        col = self._make(manager=mgr)
        fams = col.collect()
        entries = _get_family(fams, "shorewalld_nfsets_entries")
        assert entries.labels == ["instance", "backend"]

    def test_all_four_backends_can_appear(self):
        mgr = _FakeNfSetsManager(
            {"dnstap": 1, "resolver": 1, "ip-list": 1, "ip-list-plain": 1},
            {"dnstap": 1, "resolver": 1, "ip-list": 1, "ip-list-plain": 1},
        )
        col = self._make(manager=mgr)
        fams = col.collect()
        entries = _get_family(fams, "shorewalld_nfsets_entries")
        backends = {lv[1] for lv, _ in entries.samples}
        assert backends == {"dnstap", "resolver", "ip-list", "ip-list-plain"}


# ---------------------------------------------------------------------------
# NfsetsCollector — DNS shared-qname metrics
# ---------------------------------------------------------------------------

class TestNfsetsCollectorDnsShared:
    def _make(self, tracker=None):
        return NfsetsCollector("", tracker=tracker)

    def test_no_tracker_returns_empty_family(self):
        col = self._make(tracker=None)
        fams = col.collect()
        shared = _get_family(fams, "shorewalld_dns_set_shared_qnames")
        assert shared.samples == []

    def test_single_qname_set_shows_one(self):
        tracker = _FakeDnsSetTracker(
            by_name={("example.com", 4): 1, ("example.com", 6): 2},
            by_id={1: ("example.com", 4), 2: ("example.com", 6)},
        )
        col = self._make(tracker=tracker)
        fams = col.collect()
        shared = _get_family(fams, "shorewalld_dns_set_shared_qnames")
        sd = _samples_dict(shared)
        assert sd[("example.com", "ipv4")] == 1.0
        assert sd[("example.com", "ipv6")] == 1.0

    def test_n_to_1_grouping_shows_count(self):
        # Two qnames → same set_id (N→1)
        tracker = _FakeDnsSetTracker(
            by_name={
                ("example.com", 4): 1,
                ("www.example.com", 4): 1,  # same set_id → shared
                ("example.com", 6): 2,
                ("www.example.com", 6): 2,
            },
            by_id={1: ("example.com", 4), 2: ("example.com", 6)},
        )
        col = self._make(tracker=tracker)
        fams = col.collect()
        shared = _get_family(fams, "shorewalld_dns_set_shared_qnames")
        sd = _samples_dict(shared)
        assert sd[("example.com", "ipv4")] == 2.0  # two qnames share set_id=1
        assert sd[("example.com", "ipv6")] == 2.0

    def test_labels_are_set_name_and_family(self):
        tracker = _FakeDnsSetTracker(
            by_name={("host.example.com", 4): 1},
            by_id={1: ("host.example.com", 4)},
        )
        col = self._make(tracker=tracker)
        fams = col.collect()
        shared = _get_family(fams, "shorewalld_dns_set_shared_qnames")
        assert shared.labels == ["set_name", "family"]


# ---------------------------------------------------------------------------
# NfsetsCollector — PlainListTracker metrics
# ---------------------------------------------------------------------------

class TestNfsetsCollectorPlain:
    def _make(self, plain=None):
        return NfsetsCollector("", plain_tracker=plain)

    def test_empty_when_no_plain_tracker(self):
        col = self._make(plain=None)
        fams = col.collect()
        for name in (
            "shorewalld_plainlist_refresh_total",
            "shorewalld_plainlist_entries",
            "shorewalld_plainlist_last_success_timestamp_seconds",
            "shorewalld_plainlist_inotify_active",
            "shorewalld_plainlist_errors_total",
        ):
            fam = _get_family(fams, name)
            assert fam.samples == [], f"{name} should be empty without tracker"

    def test_refresh_success_and_failure_counters(self):
        snap = _FakePlainListSnapshot(
            name="nfset_block",
            source_type="http",
            refresh_total=10,
            refresh_success_total=8,
            refresh_failure_total=2,
        )
        col = self._make(plain=_FakePlainListTracker([snap]))
        fams = col.collect()

        rt = _get_family(fams, "shorewalld_plainlist_refresh_total")
        sd = _samples_dict(rt)
        assert sd[("nfset_block", "http", "success")] == 8.0
        assert sd[("nfset_block", "http", "failure")] == 2.0

    def test_no_refresh_total_when_both_zero(self):
        snap = _FakePlainListSnapshot(name="new_list", source_type="file")
        col = self._make(plain=_FakePlainListTracker([snap]))
        fams = col.collect()
        rt = _get_family(fams, "shorewalld_plainlist_refresh_total")
        # No samples emitted when both success and failure are 0.
        assert rt.samples == []

    def test_entries_gauge_v4_and_v6(self):
        snap = _FakePlainListSnapshot(
            name="nfset_bogons",
            source_type="http",
            v4_entries=1024,
            v6_entries=512,
        )
        col = self._make(plain=_FakePlainListTracker([snap]))
        fams = col.collect()

        ent = _get_family(fams, "shorewalld_plainlist_entries")
        sd = _samples_dict(ent)
        assert sd[("nfset_bogons", "ipv4")] == 1024.0
        assert sd[("nfset_bogons", "ipv6")] == 512.0

    def test_last_success_timestamp(self):
        ts = time.time() - 600.0  # 10 minutes ago
        snap = _FakePlainListSnapshot(
            name="nfset_x", source_type="file", last_success_ts=ts
        )
        col = self._make(plain=_FakePlainListTracker([snap]))
        fams = col.collect()

        lsf = _get_family(fams, "shorewalld_plainlist_last_success_timestamp_seconds")
        assert lsf.samples == [(["nfset_x"], ts)]

    def test_inotify_active_gauge(self):
        active = _FakePlainListSnapshot("f1", source_type="file", inotify_active=1)
        polling = _FakePlainListSnapshot("f2", source_type="file", inotify_active=0)
        col = self._make(plain=_FakePlainListTracker([active, polling]))
        fams = col.collect()

        ino = _get_family(fams, "shorewalld_plainlist_inotify_active")
        sd = _samples_dict(ino)
        assert sd[("f1",)] == 1.0
        assert sd[("f2",)] == 0.0

    def test_errors_total_by_error_type(self):
        snap = _FakePlainListSnapshot(
            name="nfset_err",
            source_type="http",
            refresh_error_counts={"http_status": 3, "timeout": 1},
        )
        col = self._make(plain=_FakePlainListTracker([snap]))
        fams = col.collect()

        errs = _get_family(fams, "shorewalld_plainlist_errors_total")
        sd = _samples_dict(errs)
        assert sd[("nfset_err", "http", "http_status")] == 3.0
        assert sd[("nfset_err", "http", "timeout")] == 1.0

    def test_errors_total_is_counter(self):
        snap = _FakePlainListSnapshot(
            "e", source_type="exec",
            refresh_error_counts={"exec_exit": 1},
        )
        col = self._make(plain=_FakePlainListTracker([snap]))
        fams = col.collect()
        errs = _get_family(fams, "shorewalld_plainlist_errors_total")
        assert errs.mtype == "counter"

    def test_refresh_total_is_counter(self):
        snap = _FakePlainListSnapshot(
            "z", source_type="file",
            refresh_success_total=5, refresh_failure_total=1,
        )
        col = self._make(plain=_FakePlainListTracker([snap]))
        fams = col.collect()
        rt = _get_family(fams, "shorewalld_plainlist_refresh_total")
        assert rt.mtype == "counter"

    def test_duration_sum_and_count_are_counters(self):
        snap = _FakePlainListSnapshot(
            "dur", source_type="http",
            refresh_duration_sum=12.5, refresh_duration_count=3,
        )
        col = self._make(plain=_FakePlainListTracker([snap]))
        fams = col.collect()

        s_fam = _get_family(fams, "shorewalld_plainlist_refresh_duration_seconds_sum")
        c_fam = _get_family(fams, "shorewalld_plainlist_refresh_duration_seconds_count")
        assert s_fam.mtype == "counter"
        assert c_fam.mtype == "counter"
        sd_s = _samples_dict(s_fam)
        sd_c = _samples_dict(c_fam)
        assert sd_s[("dur", "http")] == pytest.approx(12.5)
        assert sd_c[("dur", "http")] == 3.0

    def test_all_source_types_accepted(self):
        snaps = [
            _FakePlainListSnapshot("a", source_type="http",
                                   refresh_success_total=1),
            _FakePlainListSnapshot("b", source_type="file",
                                   refresh_success_total=1),
            _FakePlainListSnapshot("c", source_type="exec",
                                   refresh_success_total=1),
        ]
        col = self._make(plain=_FakePlainListTracker(snaps))
        fams = col.collect()
        rt = _get_family(fams, "shorewalld_plainlist_refresh_total")
        src_types = {lv[1] for lv, _ in rt.samples}
        assert src_types == {"http", "file", "exec"}


# ---------------------------------------------------------------------------
# PlainListTracker.metrics_snapshot() integration
# ---------------------------------------------------------------------------

class TestPlainListTrackerMetricsSnapshot:
    def _make_tracker(self, source: str):
        from shorewalld.iplist.plain import PlainListConfig, PlainListTracker
        cfg = PlainListConfig(
            name="nfset_test",
            source=source,
            refresh=3600,
        )
        nft = MagicMock()
        profiles: dict = {}
        return PlainListTracker([cfg], nft, profiles)

    def test_snapshot_returns_one_entry_per_config(self):
        tracker = self._make_tracker("/tmp/blocklist.txt")
        snapshots = tracker.metrics_snapshot()
        assert len(snapshots) == 1
        assert snapshots[0].name == "nfset_test"

    def test_source_type_http(self):
        tracker = self._make_tracker("https://example.com/list.txt")
        snaps = tracker.metrics_snapshot()
        assert snaps[0].source_type == "http"

    def test_source_type_file(self):
        tracker = self._make_tracker("/etc/shorewall/blocklist.txt")
        snaps = tracker.metrics_snapshot()
        assert snaps[0].source_type == "file"

    def test_source_type_exec(self):
        tracker = self._make_tracker("exec:/usr/local/bin/gen-list.sh")
        snaps = tracker.metrics_snapshot()
        assert snaps[0].source_type == "exec"

    def test_initial_counters_are_zero(self):
        tracker = self._make_tracker("/tmp/x")
        snap = tracker.metrics_snapshot()[0]
        assert snap.refresh_total == 0
        assert snap.refresh_success_total == 0
        assert snap.refresh_failure_total == 0
        assert snap.refresh_error_counts == {}
        assert snap.last_success_ts == 0.0
        assert snap.inotify_active == 0


# ---------------------------------------------------------------------------
# NfSetsManager.entries_by_backend / hosts_by_backend / payload_bytes
# ---------------------------------------------------------------------------

def test_nfsets_manager_with_real_payload():
    """Parse a real-looking nfsets payload and verify helper methods."""
    from shorewalld.nfsets_manager import NfSetsManager

    # Build a payload with two dnstap entries and one ip-list-plain entry.
    payload = {
        "entries": [
            {
                "name": "cloudflare",
                "backend": "dnstap",
                "hosts": ["cloudflare.com", "www.cloudflare.com"],
                "options": {},
                "refresh": None,
                "dns_servers": [],
                "inotify": False,
                "size": None,
                "dnstype": None,
            },
            {
                "name": "blocklist",
                "backend": "ip-list-plain",
                "hosts": ["https://example.com/blocklist.txt"],
                "options": {},
                "refresh": 3600,
                "dns_servers": [],
                "inotify": False,
                "size": None,
                "dnstype": None,
            },
        ]
    }

    mgr = NfSetsManager(payload)
    by_backend = mgr.entries_by_backend()
    assert by_backend.get("dnstap") == 1
    assert by_backend.get("ip-list-plain") == 1

    by_hosts = mgr.hosts_by_backend()
    assert by_hosts.get("dnstap") == 2   # two qnames
    assert by_hosts.get("ip-list-plain") == 1

    pb = mgr.payload_bytes()
    assert pb > 0


# ---------------------------------------------------------------------------
# Cardinality sanity
# ---------------------------------------------------------------------------

def test_cardinality_no_per_ip_labels():
    """No metric uses qname, IP, or source URL as a label value."""
    snap = _FakePlainListSnapshot(
        name="nfset_blocklist",
        source_type="http",
        refresh_success_total=5,
        refresh_failure_total=1,
        v4_entries=10000,
        v6_entries=500,
        refresh_error_counts={"timeout": 1},
    )
    col = NfsetsCollector("", plain_tracker=_FakePlainListTracker([snap]))
    fams = col.collect()

    for fam in fams:
        for label_name in fam.labels:
            # No label should be a high-cardinality source URL or IP.
            assert label_name not in ("ip", "prefix", "url", "host")
        for label_values, _ in fam.samples:
            for lv in label_values:
                # No sample value should be a full HTTP(S) URL.
                assert not lv.startswith("http://") and not lv.startswith("https://"), (
                    f"Full URL in label value: {lv}"
                )
                # "http" / "file" / "exec" are valid source_type enum values.


def test_backend_label_bounded():
    """The backend label has at most 4 distinct values."""
    valid_backends = {"dnstap", "resolver", "ip-list", "ip-list-plain"}
    mgr = _FakeNfSetsManager(
        {b: 1 for b in valid_backends},
        {b: 1 for b in valid_backends},
    )
    col = NfsetsCollector("fw", manager=mgr)
    fams = col.collect()
    entries = _get_family(fams, "shorewalld_nfsets_entries")
    backends = {lv[1] for lv, _ in entries.samples}
    assert backends <= valid_backends


# ---------------------------------------------------------------------------
# Regression: existing metric names unchanged
# ---------------------------------------------------------------------------

def test_existing_dns_set_metric_names_unchanged():
    """DnsSetMetricsCollector names must not be altered by Wave 6."""
    from shorewalld.dns_set_tracker import DnsSetTracker, DnsSetMetricsCollector
    tracker = DnsSetTracker()
    col = DnsSetMetricsCollector(tracker)
    fams = col.collect()
    names = {f.name for f in fams}
    expected = {
        "shorewalld_dns_set_elements",
        "shorewalld_dns_set_adds_total",
        "shorewalld_dns_set_refreshes_total",
        "shorewalld_dns_set_dedup_hits_total",
        "shorewalld_dns_set_dedup_misses_total",
        "shorewalld_dns_set_expiries_total",
        "shorewalld_dns_set_last_update_age_seconds",
    }
    assert expected <= names, f"Missing expected DNS metrics: {expected - names}"


def test_existing_iplist_metric_names_unchanged():
    """IpListMetrics names must not be altered by Wave 6."""
    from shorewalld.iplist.tracker import IpListMetrics
    m = IpListMetrics()
    fams = m.collect()
    names = {f.name for f in fams}
    expected = {
        "shorewalld_iplist_prefixes_total",
        "shorewalld_iplist_last_refresh_timestamp",
        "shorewalld_iplist_fetch_errors_total",
        "shorewalld_iplist_updates_total",
        "shorewalld_iplist_apply_duration_seconds_sum",
        "shorewalld_iplist_apply_duration_seconds_count",
        "shorewalld_iplist_apply_path_total",
        "shorewalld_iplist_set_capacity",
        "shorewalld_iplist_set_headroom_ratio",
    }
    assert expected <= names


# ---------------------------------------------------------------------------
# Smoke test: generate_latest() works end-to-end
# ---------------------------------------------------------------------------

def test_generate_latest_smoke():
    """NfsetsCollector can be registered and scraped via prometheus_client."""
    prometheus_client = pytest.importorskip("prometheus_client")
    from prometheus_client import CollectorRegistry
    from prometheus_client.exposition import generate_latest

    # Fake manager with all four backends.
    mgr = _FakeNfSetsManager(
        {"dnstap": 2, "resolver": 1, "ip-list": 1, "ip-list-plain": 3},
        {"dnstap": 4, "resolver": 2, "ip-list": 5, "ip-list-plain": 3},
        payload_bytes=1024,
    )

    # Fake plain tracker with one successful refresh.
    snap = _FakePlainListSnapshot(
        name="nfset_blocklist",
        source_type="http",
        refresh_success_total=10,
        refresh_failure_total=2,
        last_success_ts=time.time() - 120.0,
        v4_entries=50000,
        v6_entries=1000,
        inotify_active=0,
        refresh_error_counts={"timeout": 2},
        refresh_duration_sum=5.5,
        refresh_duration_count=10,
    )
    plain = _FakePlainListTracker([snap])

    # Fake tracker for N→1 gauge.
    tracker = _FakeDnsSetTracker(
        by_name={("example.com", 4): 1, ("alt.example.com", 4): 1},
        by_id={1: ("example.com", 4)},
    )

    class _WrappedCollector:
        """Adapter to bridge ShorewalldRegistry → prometheus_client REGISTRY."""
        def describe(self):
            return []

        def collect(self):
            reg = ShorewalldRegistry()
            nfc = NfsetsCollector(
                "fw",
                manager=mgr,
                tracker=tracker,
                plain_tracker=plain,
            )
            reg.add(nfc)
            return reg.to_prom_families()

    prom_reg = CollectorRegistry()
    prom_reg.register(_WrappedCollector())
    output = generate_latest(prom_reg).decode()

    # Spot-check key metric names in the output.
    assert "shorewalld_nfsets_entries" in output
    assert "shorewalld_nfsets_hosts" in output
    assert "shorewalld_nfsets_payload_bytes" in output
    assert "shorewalld_dns_set_shared_qnames" in output
    assert "shorewalld_plainlist_refresh_total" in output
    assert "shorewalld_plainlist_entries" in output
    assert "shorewalld_plainlist_last_success_timestamp_seconds" in output
    assert "shorewalld_plainlist_inotify_active" in output
    assert "shorewalld_plainlist_errors_total" in output
