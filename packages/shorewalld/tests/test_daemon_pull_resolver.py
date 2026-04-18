"""Unit tests for shorewalld.dns_pull_resolver.PullResolver.

Tests are fully asyncio-based with mocked DNS resolver and a fake
SetWriter so no network or nft access is needed.

Coverage:
* Startup: all groups scheduled for immediate resolve
* TTL scheduling: next_at derived from min(resolved TTL) * 0.8
* min_retry floor when all qnames fail / NXDOMAIN
* max_ttl cap on next_at
* Multi-host group: all qnames resolved; IPs go into primary's set
* NXDOMAIN → log.info, not exception; retry after min_retry
* refresh() reschedules one or all groups immediately
* shutdown() cancels the run loop cleanly
* Tracker add_qname_alias: secondary routes to primary's set_id
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from unittest.mock import AsyncMock, patch

import dns.resolver
import pytest

from shorewalld.dns_pull_resolver import (
    DEFAULT_RESOLVE_FRACTION,
    PullResolver,
)
from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    FAMILY_V6,
    DnsSetTracker,
    Proposal,
)
from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsSetSpec, DnsrRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_dns_registry(*qnames: str) -> DnsSetRegistry:
    reg = DnsSetRegistry()
    for qn in qnames:
        reg.add_spec(DnsSetSpec(qn, 300, 86400, 512))
    return reg


def _make_dnsr_registry(groups: list[tuple[str, list[str]]]) -> DnsrRegistry:
    reg = DnsrRegistry()
    for primary, qnames in groups:
        reg.add_from_rule(primary, qnames)
    return reg


def _loaded_tracker(*qnames: str) -> DnsSetTracker:
    tracker = DnsSetTracker()
    tracker.load_registry(_make_dns_registry(*qnames))
    return tracker


class FakeWriter:
    """Collects submit() calls so tests can assert on them."""

    def __init__(self) -> None:
        self.submitted: list[tuple[str, int, Proposal]] = []

    def submit(self, *, netns: str, family: int, proposal: Proposal) -> bool:
        self.submitted.append((netns, family, proposal))
        return True


def _dns_answer(addresses: list[str], ttl: int = 300):
    """Return a minimal fake dns.asyncresolver answer object."""
    class _Rdata:
        def __init__(self, addr):
            self.address = addr

    class _RRset:
        def __init__(self):
            self.ttl = ttl

        def __iter__(self):
            return iter([_Rdata(a) for a in addresses])

    class _Answer:
        def __init__(self):
            self.rrset = _RRset()

        def __iter__(self):
            return iter(self.rrset)

    return _Answer()


def _raise(exc):
    raise exc


# ---------------------------------------------------------------------------
# Tracker alias support
# ---------------------------------------------------------------------------

class TestTrackerAlias:
    def test_alias_routes_to_primary_set_id(self):
        tracker = _loaded_tracker("github.com")
        primary_id_v4 = tracker.set_id_for("github.com", FAMILY_V4)
        assert primary_id_v4 is not None

        ok = tracker.add_qname_alias("mail.github.com", "github.com", FAMILY_V4)
        assert ok is True
        assert tracker.set_id_for("mail.github.com", FAMILY_V4) == primary_id_v4

    def test_alias_returns_false_for_unknown_primary(self):
        tracker = _loaded_tracker("github.com")
        ok = tracker.add_qname_alias("mail.github.com", "nonexistent.com", FAMILY_V4)
        assert ok is False
        assert tracker.set_id_for("mail.github.com", FAMILY_V4) is None

    def test_alias_independent_per_family(self):
        tracker = _loaded_tracker("github.com")
        tracker.add_qname_alias("mail.github.com", "github.com", FAMILY_V4)
        assert tracker.set_id_for("mail.github.com", FAMILY_V6) is None
        tracker.add_qname_alias("mail.github.com", "github.com", FAMILY_V6)
        assert tracker.set_id_for("mail.github.com", FAMILY_V6) is not None


# ---------------------------------------------------------------------------
# PullResolver — init
# ---------------------------------------------------------------------------

class TestPullResolverInit:
    def test_heap_has_entry_per_group(self):
        tracker = _loaded_tracker("github.com", "api.stripe.com")
        writer = FakeWriter()
        reg = _make_dnsr_registry([
            ("github.com", ["github.com"]),
            ("api.stripe.com", ["api.stripe.com"]),
        ])
        resolver = PullResolver(reg, tracker, writer)
        assert resolver.group_count == 2

    def test_all_entries_due_immediately(self):
        tracker = _loaded_tracker("github.com")
        writer = FakeWriter()
        reg = _make_dnsr_registry([("github.com", ["github.com"])])
        resolver = PullResolver(reg, tracker, writer)
        assert resolver._heap[0].next_at <= time.monotonic() + 0.5


# ---------------------------------------------------------------------------
# PullResolver — _resolve_group
# ---------------------------------------------------------------------------

class TestResolveGroup:
    def _make_resolver(self, qnames=("github.com",), max_ttl=None, min_retry=None):
        tracker = _loaded_tracker(*qnames)
        writer = FakeWriter()
        primary = qnames[0]
        reg = _make_dnsr_registry([(primary, list(qnames))])
        kwargs = {}
        if max_ttl is not None:
            kwargs["max_ttl"] = max_ttl
        if min_retry is not None:
            kwargs["min_retry"] = min_retry
        resolver = PullResolver(reg, tracker, writer, **kwargs)
        return resolver, tracker, writer, reg.groups[primary]

    def test_v4_ip_submitted_to_writer(self):
        resolver, tracker, writer, group = self._make_resolver()

        async def _run():
            with patch.object(
                resolver._resolver, "resolve", new_callable=AsyncMock
            ) as mock_resolve:
                mock_resolve.side_effect = lambda qname, rdtype: (
                    _dns_answer(["1.2.3.4"], ttl=600) if rdtype == "A"
                    else _raise(dns.resolver.NoAnswer())
                )
                await resolver._resolve_group(group)

        asyncio.run(_run())
        assert len(writer.submitted) == 1
        _, family, prop = writer.submitted[0]
        assert family == FAMILY_V4
        assert prop.ip_bytes == ipaddress.IPv4Address("1.2.3.4").packed

    def test_v6_ip_submitted(self):
        resolver, tracker, writer, group = self._make_resolver()

        async def _run():
            with patch.object(
                resolver._resolver, "resolve", new_callable=AsyncMock
            ) as mock_resolve:
                mock_resolve.side_effect = lambda qname, rdtype: (
                    _dns_answer(["2606:50c0::1"], ttl=300) if rdtype == "AAAA"
                    else _raise(dns.resolver.NoAnswer())
                )
                await resolver._resolve_group(group)

        asyncio.run(_run())
        v6 = [(f, p) for _, f, p in writer.submitted if f == FAMILY_V6]
        assert len(v6) == 1
        assert v6[0][1].ip_bytes == ipaddress.IPv6Address("2606:50c0::1").packed

    def test_next_at_uses_resolve_fraction(self):
        resolver, _, _, group = self._make_resolver()
        ttl = 1000

        async def _run():
            with patch.object(
                resolver._resolver, "resolve", new_callable=AsyncMock
            ) as mock_resolve:
                mock_resolve.side_effect = lambda qname, rdtype: (
                    _dns_answer(["1.2.3.4"], ttl=ttl) if rdtype == "A"
                    else _raise(dns.resolver.NoAnswer())
                )
                before = time.monotonic()
                return await resolver._resolve_group(group), before

        next_at, before = asyncio.run(_run())
        expected_wait = int(ttl * DEFAULT_RESOLVE_FRACTION)
        assert abs((next_at - before) - expected_wait) < 2.0

    def test_next_at_capped_by_max_ttl(self):
        resolver, _, _, group = self._make_resolver(max_ttl=100)

        async def _run():
            with patch.object(
                resolver._resolver, "resolve", new_callable=AsyncMock
            ) as mock_resolve:
                mock_resolve.side_effect = lambda qname, rdtype: (
                    _dns_answer(["1.2.3.4"], ttl=9999) if rdtype == "A"
                    else _raise(dns.resolver.NoAnswer())
                )
                before = time.monotonic()
                return await resolver._resolve_group(group), before

        next_at, before = asyncio.run(_run())
        assert next_at - before <= 101

    def test_nxdomain_retries_after_min_retry(self):
        resolver, _, writer, group = self._make_resolver(min_retry=30)

        async def _run():
            with patch.object(
                resolver._resolver, "resolve", new_callable=AsyncMock
            ) as mock_resolve:
                mock_resolve.side_effect = dns.resolver.NXDOMAIN()
                before = time.monotonic()
                return await resolver._resolve_group(group), before

        next_at, before = asyncio.run(_run())
        assert abs((next_at - before) - 30) < 1.0
        assert len(writer.submitted) == 0

    def test_multi_host_all_ips_go_to_primary_set(self):
        tracker = _loaded_tracker("github.com")
        tracker.add_qname_alias("mail.github.com", "github.com", FAMILY_V4)
        writer = FakeWriter()
        reg = _make_dnsr_registry([
            ("github.com", ["github.com", "mail.github.com"])])
        group = reg.groups["github.com"]
        resolver = PullResolver(reg, tracker, writer)
        primary_set_id = tracker.set_id_for("github.com", FAMILY_V4)

        async def _run():
            async def _side(qname, rdtype):
                if rdtype != "A":
                    raise dns.resolver.NoAnswer()
                return _dns_answer(["1.2.3.4"] if qname == "github.com" else ["5.6.7.8"])
            with patch.object(resolver._resolver, "resolve", side_effect=_side):
                await resolver._resolve_group(group)

        asyncio.run(_run())
        set_ids = {p.set_id for _, _, p in writer.submitted}
        assert set_ids == {primary_set_id}
        ips = {p.ip_bytes for _, _, p in writer.submitted}
        assert ipaddress.IPv4Address("1.2.3.4").packed in ips
        assert ipaddress.IPv4Address("5.6.7.8").packed in ips


# ---------------------------------------------------------------------------
# PullResolver — refresh()
# ---------------------------------------------------------------------------

class TestRefresh:
    def test_refresh_all_sets_next_at_to_now(self):
        tracker = _loaded_tracker("github.com", "api.stripe.com")
        writer = FakeWriter()
        reg = _make_dnsr_registry([
            ("github.com", ["github.com"]),
            ("api.stripe.com", ["api.stripe.com"]),
        ])
        resolver = PullResolver(reg, tracker, writer)
        import heapq
        far = time.monotonic() + 9999
        for entry in resolver._heap:
            entry.next_at = far
        heapq.heapify(resolver._heap)

        count = asyncio.run(resolver.refresh())

        assert count == 2
        now = time.monotonic()
        for entry in resolver._heap:
            assert entry.next_at <= now + 0.5

    def test_refresh_single_hostname(self):
        tracker = _loaded_tracker("github.com", "api.stripe.com")
        writer = FakeWriter()
        reg = _make_dnsr_registry([
            ("github.com", ["github.com"]),
            ("api.stripe.com", ["api.stripe.com"]),
        ])
        resolver = PullResolver(reg, tracker, writer)
        import heapq
        far = time.monotonic() + 9999
        for entry in resolver._heap:
            entry.next_at = far
        heapq.heapify(resolver._heap)

        count = asyncio.run(resolver.refresh("github.com"))

        assert count == 1
        now = time.monotonic()
        for entry in resolver._heap:
            if entry.primary_qname == "github.com":
                assert entry.next_at <= now + 0.5
            else:
                assert entry.next_at > now + 1000


# ---------------------------------------------------------------------------
# PullResolver — shutdown
# ---------------------------------------------------------------------------

class TestShutdown:
    def test_shutdown_stops_run_loop(self):
        tracker = _loaded_tracker("github.com")
        writer = FakeWriter()
        reg = _make_dnsr_registry([("github.com", ["github.com"])])
        resolver = PullResolver(reg, tracker, writer)

        async def _run():
            with patch.object(
                resolver._resolver, "resolve", new_callable=AsyncMock
            ) as mock_resolve:
                mock_resolve.side_effect = dns.resolver.NXDOMAIN()
                await resolver.start()
                await asyncio.sleep(0.05)
                await resolver.shutdown()

        asyncio.run(_run())
        assert resolver._task is None
