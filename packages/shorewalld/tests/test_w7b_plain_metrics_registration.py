"""W7b regression: PlainListTracker metrics appear on the scrape endpoint.

Item A — shorewalld_iplist_apply_duration_seconds_sum (nft apply-path metrics
from IpListMetrics) and shorewalld_plainlist_refresh_total (fetch/parse metrics
from NfsetsCollector) must both be reachable via ShorewalldRegistry after a
PlainListTracker performs at least one successful refresh cycle.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from shorewalld.exporter import NfsetsCollector, ShorewalldRegistry
from shorewalld.iplist.plain import PlainListConfig, PlainListTracker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tracker(source: str) -> PlainListTracker:
    cfg = PlainListConfig(
        name="nfset_plain_test",
        source=source,
        set_v4="nfset_plain_test_v4",
        set_v6="nfset_plain_test_v6",
    )
    nft = MagicMock()
    # Return fake capacity probe so record_apply_capacity is populated.
    nft.cmd.return_value = {
        "nftables": [{"set": {"type": "ipv4_addr", "flags": [], "size": 65536}}]
    }
    return PlainListTracker([cfg], nft, {})


# ---------------------------------------------------------------------------
# Item A — registration path
# ---------------------------------------------------------------------------


class TestPlainListMetricsRegistration:
    """PlainListTracker._metrics (IpListMetrics) must be reachable from
    ShorewalldRegistry after _start_plain_tracker would register it."""

    def _register(self, tracker: PlainListTracker) -> ShorewalldRegistry:
        """Simulate what core._start_plain_tracker does."""
        registry = ShorewalldRegistry()
        registry.add(tracker._metrics)  # type: ignore[arg-type]
        registry.add(NfsetsCollector("", plain_tracker=tracker))
        return registry

    def test_iplist_apply_duration_in_scrape_after_successful_refresh(self):
        """After one successful refresh the nft apply-duration counter must
        appear in generate_latest() output with label matching the list name."""
        prometheus_client = pytest.importorskip("prometheus_client")
        from prometheus_client import CollectorRegistry
        from prometheus_client.exposition import generate_latest

        text = "198.51.100.0/24\n"
        tracker = _make_tracker("https://example.org/bl.txt")

        from unittest.mock import patch
        with patch("shorewalld.iplist.plain._fetch_url", return_value=text):
            asyncio.run(tracker._do_refresh(tracker._states["nfset_plain_test"]))

        # Manually call record_apply_duration so IpListMetrics has something
        # to emit (the diff path does this but profiles={} skips nft writes).
        tracker._metrics.record_apply_duration("nfset_plain_test", "v4", 0.01)

        registry = self._register(tracker)

        # Wrap in prometheus_client adapter.
        class _Adapter:
            def describe(self): return []
            def collect(self): return registry.to_prom_families()

        prom_reg = CollectorRegistry()
        prom_reg.register(_Adapter())
        output = generate_latest(prom_reg).decode()

        assert "shorewalld_iplist_apply_duration_seconds_sum" in output
        assert "nfset_plain_test" in output

    def test_plainlist_refresh_total_in_scrape_after_successful_refresh(self):
        """After one successful refresh the plainlist refresh counter must
        appear in generate_latest() output."""
        prometheus_client = pytest.importorskip("prometheus_client")
        from prometheus_client import CollectorRegistry
        from prometheus_client.exposition import generate_latest

        text = "198.51.100.1\n"
        tracker = _make_tracker("/fake/path.txt")

        from unittest.mock import patch
        with patch("shorewalld.iplist.plain._read_file", return_value=text):
            asyncio.run(tracker._do_refresh(tracker._states["nfset_plain_test"]))

        registry = self._register(tracker)

        class _Adapter:
            def describe(self): return []
            def collect(self): return registry.to_prom_families()

        prom_reg = CollectorRegistry()
        prom_reg.register(_Adapter())
        output = generate_latest(prom_reg).decode()

        assert "shorewalld_plainlist_refresh_total" in output
        # outcome=success label should appear after at least one success.
        assert "nfset_plain_test" in output

    def test_both_metric_groups_reachable_from_registry(self):
        """ShorewalldRegistry.to_prom_families() must include both IpListMetrics
        and NfsetsCollector families when both are registered."""
        tracker = _make_tracker("/tmp/list.txt")
        registry = self._register(tracker)
        families = registry.to_prom_families()
        names = {f.name for f in families}

        # IpListMetrics families
        assert "shorewalld_iplist_apply_duration_seconds_sum" in names
        assert "shorewalld_iplist_apply_duration_seconds_count" in names
        assert "shorewalld_iplist_set_capacity" in names

        # NfsetsCollector families.
        # Note: CounterMetricFamily strips the trailing _total suffix from its
        # .name attribute, so we check the base name here.
        assert "shorewalld_plainlist_refresh" in names
        assert "shorewalld_plainlist_entries" in names
        assert "shorewalld_plainlist_inotify_active" in names
