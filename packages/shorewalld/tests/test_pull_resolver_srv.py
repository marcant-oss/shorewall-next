"""Tests for PullResolver SRV record support (Wave 12).

Mock dns.asyncresolver.Resolver so no network or nft access is needed.

All hostnames use example.com / example.org (RFC 2606).
All IP addresses use RFC 5737 (198.51.100.0/24, 203.0.113.0/24) and
RFC 3849 (2001:db8::/32).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from unittest.mock import AsyncMock, patch

import dns.resolver

from shorewalld.dns_pull_resolver import MAX_SRV_TARGETS, PullResolver
from shorewalld.dns_set_tracker import FAMILY_V4, FAMILY_V6, DnsSetTracker, Proposal
from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsSetSpec, DnsrGroup, DnsrRegistry


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


class FakeWriter:
    """Collects submit() calls for assertion."""

    def __init__(self) -> None:
        self.submitted: list[tuple[str, int, Proposal]] = []

    def submit(self, *, netns: str, family: int, proposal: Proposal) -> bool:
        self.submitted.append((netns, family, proposal))
        return True


def _a_answer(addresses: list[str], ttl: int = 300):
    """Fake A/AAAA answer."""
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


def _srv_answer(targets: list[str], ttl: int = 600):
    """Fake SRV answer. Each target is a dotted hostname string."""
    class _SRVRdata:
        def __init__(self, t):
            # dns.name.Name-like — provide to_text()
            self.target = _FakeDnsName(t)

    class _FakeDnsName:
        def __init__(self, s: str):
            self._s = s

        def to_text(self, omit_final_dot: bool = False) -> str:
            return self._s

    class _SRVRRset:
        def __init__(self):
            self.ttl = ttl

        def __iter__(self):
            return iter([_SRVRdata(t) for t in targets])

    class _SRVAnswer:
        def __init__(self):
            self.rrset = _SRVRRset()

        def __iter__(self):
            return iter(self.rrset)

    return _SRVAnswer()


def _make_resolver_with_group(
    primary: str,
    qnames: list[str],
    dnstype: str | None,
) -> tuple[PullResolver, DnsSetTracker, FakeWriter, DnsrGroup]:
    tracker = _loaded_tracker(primary)
    writer = FakeWriter()
    reg = DnsrRegistry()
    reg.add_with_target(
        primary=primary,
        qnames=qnames,
        set_name="nfset_test",
        dnstype=dnstype,
    )
    resolver = PullResolver(reg, tracker, writer, jitter=0.0)
    group = reg.groups[primary]
    return resolver, tracker, writer, group


# ---------------------------------------------------------------------------
# SRV: basic two-target resolution
# ---------------------------------------------------------------------------

class TestSrvBasicResolution:
    def test_two_targets_four_ips_submitted(self):
        """SRV with 2 targets × 2 families → 4 IPs submitted."""
        resolver, tracker, writer, group = _make_resolver_with_group(
            primary="_sip._udp.example.org",
            qnames=["_sip._udp.example.org"],
            dnstype="srv",
        )

        async def _run():
            def _side(qname, rdtype):
                if rdtype == "SRV":
                    return _srv_answer(
                        ["target-a.example.com", "target-b.example.com"],
                        ttl=600,
                    )
                if rdtype == "A":
                    if qname == "target-a.example.com":
                        return _a_answer(["198.51.100.10"], ttl=300)
                    if qname == "target-b.example.com":
                        return _a_answer(["203.0.113.20"], ttl=300)
                if rdtype == "AAAA":
                    if qname == "target-a.example.com":
                        return _a_answer(["2001:db8::a"], ttl=300)
                    if qname == "target-b.example.com":
                        return _a_answer(["2001:db8::b"], ttl=300)
                raise dns.resolver.NoAnswer()

            with patch.object(resolver._resolver, "resolve", side_effect=_side):
                await resolver._resolve_group(group)

        asyncio.run(_run())

        ips = {p.ip for _, _, p in writer.submitted}
        assert int.from_bytes(ipaddress.IPv4Address("198.51.100.10").packed, "big") in ips
        assert int.from_bytes(ipaddress.IPv4Address("203.0.113.20").packed, "big") in ips
        assert int.from_bytes(ipaddress.IPv6Address("2001:db8::a").packed, "big") in ips
        assert int.from_bytes(ipaddress.IPv6Address("2001:db8::b").packed, "big") in ips
        assert len(writer.submitted) == 4

    def test_correct_set_id_used(self):
        """All SRV-derived IPs go to the primary's set_id."""
        resolver, tracker, writer, group = _make_resolver_with_group(
            primary="_sip._udp.example.org",
            qnames=["_sip._udp.example.org"],
            dnstype="srv",
        )
        primary_set_id_v4 = tracker.set_id_for("_sip._udp.example.org", FAMILY_V4)
        primary_set_id_v6 = tracker.set_id_for("_sip._udp.example.org", FAMILY_V6)

        async def _run():
            def _side(qname, rdtype):
                if rdtype == "SRV":
                    return _srv_answer(["target-a.example.com"], ttl=600)
                if rdtype == "A" and qname == "target-a.example.com":
                    return _a_answer(["198.51.100.10"], ttl=300)
                if rdtype == "AAAA" and qname == "target-a.example.com":
                    return _a_answer(["2001:db8::a"], ttl=300)
                raise dns.resolver.NoAnswer()

            with patch.object(resolver._resolver, "resolve", side_effect=_side):
                await resolver._resolve_group(group)

        asyncio.run(_run())
        for _, family, prop in writer.submitted:
            if family == FAMILY_V4:
                assert prop.set_id == primary_set_id_v4
            else:
                assert prop.set_id == primary_set_id_v6

    def test_ttl_is_min_of_srv_and_child(self):
        """Result TTL = min(srv_ttl=600, child_ttl=300) = 300, clamped to floor."""
        resolver, tracker, writer, group = _make_resolver_with_group(
            primary="_sip._udp.example.org",
            qnames=["_sip._udp.example.org"],
            dnstype="srv",
        )

        async def _run():
            def _side(qname, rdtype):
                if rdtype == "SRV":
                    return _srv_answer(["target-a.example.com"], ttl=600)
                if rdtype == "A" and qname == "target-a.example.com":
                    return _a_answer(["198.51.100.10"], ttl=300)
                raise dns.resolver.NoAnswer()

            with patch.object(resolver._resolver, "resolve", side_effect=_side):
                await resolver._resolve_group(group)

        asyncio.run(_run())
        ttls = {p.ttl for _, _, p in writer.submitted}
        assert ttls == {300}


# ---------------------------------------------------------------------------
# SRV: per-target failure isolation
# ---------------------------------------------------------------------------

class TestSrvTargetFailureIsolation:
    def test_one_target_fails_other_succeeds(self):
        """Timeout/DNSException on one target → other target's IPs still arrive."""
        resolver, tracker, writer, group = _make_resolver_with_group(
            primary="_sip._udp.example.org",
            qnames=["_sip._udp.example.org"],
            dnstype="srv",
        )

        async def _run():
            def _side(qname, rdtype):
                if rdtype == "SRV":
                    return _srv_answer(
                        ["target-a.example.com", "target-b.example.com"],
                        ttl=600,
                    )
                # target-a fails with a DNS exception
                if qname == "target-a.example.com":
                    raise dns.exception.Timeout()
                # target-b succeeds
                if rdtype == "A" and qname == "target-b.example.com":
                    return _a_answer(["203.0.113.20"], ttl=300)
                raise dns.resolver.NoAnswer()

            with patch.object(resolver._resolver, "resolve", side_effect=_side):
                await resolver._resolve_group(group)

        asyncio.run(_run())
        ips = {p.ip for _, _, p in writer.submitted}
        # target-b IP present
        assert int.from_bytes(ipaddress.IPv4Address("203.0.113.20").packed, "big") in ips
        # target-a produced nothing — not in results
        assert int.from_bytes(ipaddress.IPv4Address("198.51.100.10").packed, "big") not in ips

    def test_srv_nxdomain_returns_empty(self):
        """NXDOMAIN on the SRV query itself returns empty result + increments metric."""
        resolver, tracker, writer, group = _make_resolver_with_group(
            primary="_sip._udp.example.org",
            qnames=["_sip._udp.example.org"],
            dnstype="srv",
        )
        before = resolver.metrics.nxdomain_total

        async def _run():
            with patch.object(
                resolver._resolver, "resolve", new_callable=AsyncMock
            ) as mock_resolve:
                mock_resolve.side_effect = dns.resolver.NXDOMAIN()
                await resolver._resolve_group(group)

        asyncio.run(_run())
        assert len(writer.submitted) == 0
        assert resolver.metrics.nxdomain_total == before + 1


# ---------------------------------------------------------------------------
# SRV: MAX_SRV_TARGETS cap
# ---------------------------------------------------------------------------

class TestSrvMaxTargets:
    def test_50_targets_capped_to_max(self, caplog):
        """Feed 50 SRV targets; assert exactly MAX_SRV_TARGETS processed
        and a rate-limited warning is emitted."""
        resolver, tracker, writer, group = _make_resolver_with_group(
            primary="_sip._udp.example.org",
            qnames=["_sip._udp.example.org"],
            dnstype="srv",
        )

        # Build 50 unique target names.
        n_targets = 50
        all_targets = [f"target-{i}.example.com" for i in range(n_targets)]

        async def _run():
            def _side(qname, rdtype):
                if rdtype == "SRV":
                    return _srv_answer(all_targets, ttl=300)
                if rdtype == "A":
                    idx = int(qname.split("-")[1].split(".")[0])
                    return _a_answer([f"198.51.100.{idx % 256}"], ttl=120)
                raise dns.resolver.NoAnswer()

            with patch.object(resolver._resolver, "resolve", side_effect=_side):
                with caplog.at_level(logging.WARNING):
                    await resolver._resolve_group(group)

        asyncio.run(_run())

        # Only MAX_SRV_TARGETS A results (no AAAA since those raise NoAnswer).
        v4_submissions = [p for _, f, p in writer.submitted if f == FAMILY_V4]
        assert len(v4_submissions) == MAX_SRV_TARGETS

        # Warning must mention the cap.
        assert any(
            "MAX_SRV_TARGETS" in msg or str(MAX_SRV_TARGETS) in msg
            for msg in caplog.messages
        ), f"Expected cap warning; got: {caplog.messages}"

    def test_max_srv_targets_constant_is_32(self):
        assert MAX_SRV_TARGETS == 32


# ---------------------------------------------------------------------------
# Regression: dnstype=None still produces A+AAAA
# ---------------------------------------------------------------------------

class TestDnstypeNoneRegression:
    def test_none_dnstype_resolves_both_families(self):
        """dnstype=None group resolves A and AAAA directly (no SRV)."""
        resolver, tracker, writer, group = _make_resolver_with_group(
            primary="api.example.com",
            qnames=["api.example.com"],
            dnstype=None,
        )

        async def _run():
            def _side(qname, rdtype):
                if rdtype == "A":
                    return _a_answer(["198.51.100.1"], ttl=300)
                if rdtype == "AAAA":
                    return _a_answer(["2001:db8::1"], ttl=300)
                raise dns.resolver.NoAnswer()

            with patch.object(resolver._resolver, "resolve", side_effect=_side):
                await resolver._resolve_group(group)

        asyncio.run(_run())
        families = {f for _, f, _ in writer.submitted}
        assert FAMILY_V4 in families
        assert FAMILY_V6 in families
        assert len(writer.submitted) == 2

    def test_dnstype_a_only_resolves_v4(self):
        """dnstype='a' → only A query issued."""
        resolver, tracker, writer, group = _make_resolver_with_group(
            primary="api.example.com",
            qnames=["api.example.com"],
            dnstype="a",
        )

        async def _run():
            def _side(qname, rdtype):
                if rdtype == "A":
                    return _a_answer(["198.51.100.1"], ttl=300)
                raise AssertionError(f"Unexpected rdtype {rdtype!r}")

            with patch.object(resolver._resolver, "resolve", side_effect=_side):
                await resolver._resolve_group(group)

        asyncio.run(_run())
        families = {f for _, f, _ in writer.submitted}
        assert families == {FAMILY_V4}

    def test_dnstype_aaaa_only_resolves_v6(self):
        """dnstype='aaaa' → only AAAA query issued."""
        resolver, tracker, writer, group = _make_resolver_with_group(
            primary="api.example.com",
            qnames=["api.example.com"],
            dnstype="aaaa",
        )

        async def _run():
            def _side(qname, rdtype):
                if rdtype == "AAAA":
                    return _a_answer(["2001:db8::1"], ttl=300)
                raise AssertionError(f"Unexpected rdtype {rdtype!r}")

            with patch.object(resolver._resolver, "resolve", side_effect=_side):
                await resolver._resolve_group(group)

        asyncio.run(_run())
        families = {f for _, f, _ in writer.submitted}
        assert families == {FAMILY_V6}
