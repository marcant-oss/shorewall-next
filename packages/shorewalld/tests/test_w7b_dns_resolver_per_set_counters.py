"""W7b regression: PullResolver per-set success/failure counters + duration.

Item B — shorewalld_dns_resolver_refresh_total{set_name, outcome} and
shorewalld_dns_resolver_refresh_duration_seconds_{sum,count}{set_name}
must be emitted by PullResolverMetricsCollector.

Tests:
* successful refresh increments outcome=success
* resolver exception increments outcome=failure
* duration sum is monotonic non-decreasing after multiple refreshes
* qname label is absent (cardinality guard)
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import dns.resolver
import pytest

from shorewalld.dns_pull_resolver import (
    PullResolver,
    PullResolverMetricsCollector,
)
from shorewalld.dns_set_tracker import DnsSetTracker, Proposal
from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsSetSpec, DnsrRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dns_registry(*qnames: str) -> DnsSetRegistry:
    reg = DnsSetRegistry()
    for qn in qnames:
        reg.add_spec(DnsSetSpec(qn, 300, 86400, 512))
    return reg


def _loaded_tracker(*qnames: str) -> DnsSetTracker:
    tracker = DnsSetTracker()
    tracker.load_registry(_make_dns_registry(*qnames))
    return tracker


def _make_dnsr_registry(primary: str, qnames: list[str]) -> DnsrRegistry:
    reg = DnsrRegistry()
    reg.add_from_rule(primary, qnames)
    return reg


class FakeWriter:
    def __init__(self) -> None:
        self.submitted: list = []

    def submit(self, *, netns: str, family: int, proposal: Proposal) -> bool:
        self.submitted.append((netns, family, proposal))
        return True


def _dns_answer(addresses: list[str], ttl: int = 300):
    """Return a minimal fake dns.asyncresolver answer object."""
    _ttl = ttl
    _addresses = addresses

    class _Rdata:
        def __init__(self, addr):
            self.address = addr

    class _RRset:
        def __init__(self):
            self.ttl = _ttl
            self._rdatas = [_Rdata(a) for a in _addresses]

        def __iter__(self):
            return iter(self._rdatas)

    class _Answer:
        def __init__(self):
            self.rrset = _RRset()

        def __iter__(self):
            return iter(self.rrset)

    return _Answer()


def _resolve_side_effect(addresses_v4: list[str], ttl: int = 300):
    """Return an AsyncMock side_effect that answers A queries with addresses_v4
    and raises NoAnswer for AAAA queries, avoiding IPv6 parse errors."""
    v4_answer = _dns_answer(addresses_v4, ttl)

    async def _side_effect(qname, rdtype):
        if rdtype == "AAAA":
            raise dns.resolver.NoAnswer()
        return v4_answer

    return _side_effect


def _make_resolver(primary: str = "example.com") -> PullResolver:
    tracker = _loaded_tracker(primary)
    writer = FakeWriter()
    dnsr_reg = _make_dnsr_registry(primary, [primary])
    return PullResolver(
        dnsr_reg, tracker, writer, default_netns="", min_retry=1
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPerSetCounters:
    def test_success_increments_success_counter(self):
        """A successful resolve increments per_set_refresh_total[set][success]."""
        resolver = _make_resolver("example.com")
        group = resolver._primaries["example.com"]

        with patch.object(
            resolver._resolver, "resolve",
            new=AsyncMock(side_effect=_resolve_side_effect(["198.51.100.1"])),
        ):
            asyncio.run(resolver._resolve_group(group))

        assert resolver.metrics.per_set_refresh_total["example.com"]["success"] == 1
        assert resolver.metrics.per_set_refresh_total["example.com"].get("failure", 0) == 0

    def test_failure_increments_failure_counter(self):
        """A resolve that returns no A/AAAA records increments outcome=failure."""
        resolver = _make_resolver("noanswer.example.com")
        group = resolver._primaries["noanswer.example.com"]

        with patch.object(
            resolver._resolver, "resolve",
            new=AsyncMock(side_effect=dns.resolver.NXDOMAIN()),
        ):
            asyncio.run(resolver._resolve_group(group))

        counts = resolver.metrics.per_set_refresh_total["noanswer.example.com"]
        assert counts.get("failure", 0) == 1
        assert counts.get("success", 0) == 0

    def test_duration_sum_non_decreasing(self):
        """Duration sum grows monotonically after multiple successful refreshes."""
        resolver = _make_resolver("timing.example.com")
        group = resolver._primaries["timing.example.com"]

        with patch.object(
            resolver._resolver, "resolve",
            new=AsyncMock(side_effect=_resolve_side_effect(["198.51.100.1"])),
        ):
            asyncio.run(resolver._resolve_group(group))
            first_sum = resolver.metrics.per_set_duration_sum["timing.example.com"]
            first_count = resolver.metrics.per_set_duration_count["timing.example.com"]

            asyncio.run(resolver._resolve_group(group))
            second_sum = resolver.metrics.per_set_duration_sum["timing.example.com"]
            second_count = resolver.metrics.per_set_duration_count["timing.example.com"]

        assert first_count == 1
        assert second_count == 2
        assert second_sum >= first_sum

    def test_duration_not_recorded_on_failure(self):
        """Duration should not be incremented when the resolve fails."""
        resolver = _make_resolver("fail.example.com")
        group = resolver._primaries["fail.example.com"]

        with patch.object(
            resolver._resolver, "resolve",
            new=AsyncMock(side_effect=dns.resolver.NXDOMAIN()),
        ):
            asyncio.run(resolver._resolve_group(group))

        # Either key absent or zero.
        assert resolver.metrics.per_set_duration_count.get("fail.example.com", 0) == 0

    def test_metrics_collector_emits_refresh_total_family(self):
        """PullResolverMetricsCollector emits shorewalld_dns_resolver_refresh_total."""
        resolver = _make_resolver("emit.example.com")
        group = resolver._primaries["emit.example.com"]

        with patch.object(
            resolver._resolver, "resolve",
            new=AsyncMock(side_effect=_resolve_side_effect(["198.51.100.1"])),
        ):
            asyncio.run(resolver._resolve_group(group))

        col = PullResolverMetricsCollector(resolver)
        fams = col.collect()
        names = {f.name for f in fams}
        assert "shorewalld_dns_resolver_refresh_total" in names
        assert "shorewalld_dns_resolver_refresh_duration_seconds_sum" in names
        assert "shorewalld_dns_resolver_refresh_duration_seconds_count" in names

    def test_no_qname_label_in_new_metrics(self):
        """shorewalld_dns_resolver_refresh_total must not carry a qname label."""
        resolver = _make_resolver("noqname.example.com")
        group = resolver._primaries["noqname.example.com"]

        with patch.object(
            resolver._resolver, "resolve",
            new=AsyncMock(side_effect=_resolve_side_effect(["198.51.100.1"])),
        ):
            asyncio.run(resolver._resolve_group(group))

        col = PullResolverMetricsCollector(resolver)
        fams = col.collect()
        for fam in fams:
            if fam.name == "shorewalld_dns_resolver_refresh_total":
                assert "qname" not in fam.labels, (
                    "qname label must be absent to avoid cardinality explosion"
                )

    def test_generate_latest_includes_per_set_metrics(self):
        """Full prometheus_client scrape includes the new per-set metric names."""
        prometheus_client = pytest.importorskip("prometheus_client")
        from prometheus_client import CollectorRegistry
        from prometheus_client.exposition import generate_latest
        from shorewalld.exporter import ShorewalldRegistry

        resolver = _make_resolver("scrape.example.com")
        group = resolver._primaries["scrape.example.com"]

        with patch.object(
            resolver._resolver, "resolve",
            new=AsyncMock(side_effect=_resolve_side_effect(["198.51.100.1"])),
        ):
            asyncio.run(resolver._resolve_group(group))

        inner = ShorewalldRegistry()
        inner.add(PullResolverMetricsCollector(resolver))

        class _Adapter:
            def describe(self): return []
            def collect(self): return inner.to_prom_families()

        prom_reg = CollectorRegistry()
        prom_reg.register(_Adapter())
        output = generate_latest(prom_reg).decode()

        assert "shorewalld_dns_resolver_refresh_total" in output
        assert "scrape.example.com" in output
        assert 'outcome="success"' in output
