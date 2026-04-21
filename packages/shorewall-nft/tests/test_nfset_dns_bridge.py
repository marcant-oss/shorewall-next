"""Unit tests for the nfset ↔ DNS registry bridge in dns_sets.py.

Tests cover:
- DnsSetSpec with set_name field
- DnsSetRegistry.add_with_target
- DnsrRegistry.add_with_target
- DnsrGroup.dnstype (Wave 12)
- nfset_registry_to_dns_registries (including dnstype propagation)

All hostnames use example.com / example.org (RFC 2606).
All IP addresses use RFC 5737 (198.51.100.x, 203.0.113.x) or RFC 1918.
"""

from __future__ import annotations

import pytest

from shorewall_nft.nft.dns_sets import (
    DnsSetRegistry,
    DnsSetSpec,
    DnsrRegistry,
    nfset_registry_to_dns_registries,
)
from shorewall_nft.nft.nfsets import NfSetEntry, NfSetRegistry, nfset_to_set_name


# ---------------------------------------------------------------------------
# DnsSetSpec.set_name
# ---------------------------------------------------------------------------

class TestDnsSetSpecSetName:
    def test_default_is_none(self):
        spec = DnsSetSpec(qname="cdn.example.com")
        assert spec.set_name is None

    def test_explicit_set_name(self):
        spec = DnsSetSpec(qname="cdn.example.com", set_name="nfset_mycdn_v4")
        assert spec.set_name == "nfset_mycdn_v4"

    def test_frozen_dataclass_immutable(self):
        spec = DnsSetSpec(qname="cdn.example.com", set_name="nfset_mycdn_v4")
        with pytest.raises((AttributeError, TypeError)):
            spec.set_name = "other"  # type: ignore[misc]

    def test_round_trip_via_replace(self):
        import dataclasses
        spec = DnsSetSpec(qname="cdn.example.com")
        spec2 = dataclasses.replace(spec, set_name="nfset_mycdn_v4")
        assert spec2.set_name == "nfset_mycdn_v4"
        assert spec.set_name is None  # original unchanged


# ---------------------------------------------------------------------------
# DnsSetRegistry.add_with_target
# ---------------------------------------------------------------------------

class TestDnsSetRegistryAddWithTarget:
    def test_basic(self):
        reg = DnsSetRegistry()
        spec = reg.add_with_target("cdn.example.com", "nfset_mycdn_v4")
        assert spec.qname == "cdn.example.com"
        assert spec.set_name == "nfset_mycdn_v4"
        assert spec.declare_set is False  # nfset emitter declares the set

    def test_stored_in_specs(self):
        reg = DnsSetRegistry()
        reg.add_with_target("cdn.example.com", "nfset_mycdn_v4")
        assert "cdn.example.com" in reg.specs
        assert reg.specs["cdn.example.com"].set_name == "nfset_mycdn_v4"

    def test_canonicalises_qname(self):
        reg = DnsSetRegistry()
        spec = reg.add_with_target("CDN.Example.COM.", "nfset_mycdn_v4")
        assert spec.qname == "cdn.example.com"
        assert "cdn.example.com" in reg.specs

    def test_uses_registry_defaults(self):
        reg = DnsSetRegistry(
            default_ttl_floor=60,
            default_ttl_ceil=3600,
            default_size=256,
        )
        spec = reg.add_with_target("cdn.example.com", "nfset_mycdn_v4")
        assert spec.ttl_floor == 60
        assert spec.ttl_ceil == 3600
        assert spec.size == 256

    def test_overrides_defaults(self):
        reg = DnsSetRegistry()
        spec = reg.add_with_target(
            "cdn.example.com", "nfset_mycdn_v4",
            ttl_floor=30, ttl_ceil=900, size=128,
        )
        assert spec.ttl_floor == 30
        assert spec.ttl_ceil == 900
        assert spec.size == 128

    def test_comment_stored(self):
        reg = DnsSetRegistry()
        spec = reg.add_with_target(
            "cdn.example.com", "nfset_mycdn_v4",
            comment="nfset:mycdn",
        )
        assert spec.comment == "nfset:mycdn"


# ---------------------------------------------------------------------------
# DnsrRegistry.add_with_target
# ---------------------------------------------------------------------------

class TestDnsrRegistryAddWithTarget:
    def test_basic(self):
        reg = DnsrRegistry()
        group = reg.add_with_target(
            primary="a.example.org",
            qnames=["a.example.org", "b.example.org"],
            set_name="nfset_myset_v4",
        )
        assert group.primary_qname == "a.example.org"
        assert "a.example.org" in group.qnames
        assert "b.example.org" in group.qnames
        assert "nfset_target=nfset_myset_v4" in group.comment

    def test_pull_enabled_default(self):
        reg = DnsrRegistry()
        group = reg.add_with_target(
            primary="a.example.org",
            qnames=["a.example.org"],
            set_name="nfset_myset_v4",
        )
        assert group.pull_enabled is True

    def test_pull_disabled(self):
        reg = DnsrRegistry()
        group = reg.add_with_target(
            primary="a.example.org",
            qnames=["a.example.org"],
            set_name="nfset_myset_v4",
            pull_enabled=False,
        )
        assert group.pull_enabled is False

    def test_stored_keyed_by_primary(self):
        reg = DnsrRegistry()
        reg.add_with_target(
            primary="a.example.org",
            qnames=["a.example.org"],
            set_name="nfset_myset_v4",
        )
        assert "a.example.org" in reg.groups


# ---------------------------------------------------------------------------
# nfset_registry_to_dns_registries
# ---------------------------------------------------------------------------

def _make_nfsets(*entries: NfSetEntry) -> NfSetRegistry:
    reg = NfSetRegistry()
    for e in entries:
        reg.entries.append(e)
        reg.set_names.add(e.name)
    return reg


class TestNfsetRegistryToDnsRegistries:
    def test_empty_registry(self):
        nfsets = NfSetRegistry()
        dns_reg, dnsr_reg = nfset_registry_to_dns_registries(nfsets)
        assert dns_reg.specs == {}
        assert dnsr_reg.groups == {}

    def test_dnstap_entry_populates_dns_registry(self):
        entry = NfSetEntry(
            name="mycdn",
            hosts=["cdn.example.com", "static.example.org"],
            backend="dnstap",
        )
        nfsets = _make_nfsets(entry)
        dns_reg, dnsr_reg = nfset_registry_to_dns_registries(nfsets)

        # Both hosts must appear in the dns registry
        assert "cdn.example.com" in dns_reg.specs
        assert "static.example.org" in dns_reg.specs
        # And the dnsr registry must be empty (dnstap does not need pull)
        assert dnsr_reg.groups == {}

    def test_dnstap_set_name_is_base_name(self):
        """set_name stores the base name (no _v4/_v6 suffix) — A2 fix."""
        entry = NfSetEntry(
            name="mycdn",
            hosts=["cdn.example.com"],
            backend="dnstap",
        )
        nfsets = _make_nfsets(entry)
        dns_reg, _ = nfset_registry_to_dns_registries(nfsets)

        spec = dns_reg.specs["cdn.example.com"]
        # Base name: nfset_to_set_name("mycdn", "v4") with "_v4" stripped
        v4_name = nfset_to_set_name("mycdn", "v4")
        expected_base = v4_name[:-3]  # strip "_v4"
        assert spec.set_name == expected_base, (
            f"set_name should be base name {expected_base!r}, got {spec.set_name!r}")
        # Must NOT carry a family suffix
        assert not spec.set_name.endswith("_v4"), "base name must not have _v4 suffix"
        assert not spec.set_name.endswith("_v6"), "base name must not have _v6 suffix"

    def test_dnstap_single_registration_covers_both_families(self):
        """One qname registration suffices for both families when set_name override used."""
        entry = NfSetEntry(
            name="mycdn",
            hosts=["cdn.example.com"],
            backend="dnstap",
        )
        nfsets = _make_nfsets(entry)
        dns_reg, _ = nfset_registry_to_dns_registries(nfsets)

        # Single spec entry — both families derived at write time from base name.
        assert "cdn.example.com" in dns_reg.specs
        spec = dns_reg.specs["cdn.example.com"]
        assert spec.set_name is not None, "set_name must be set for nfset bridge"

    def test_resolver_entry_populates_dnsr_registry(self):
        entry = NfSetEntry(
            name="resolver-set",
            hosts=["a.example.com", "b.example.com"],
            backend="resolver",
        )
        nfsets = _make_nfsets(entry)
        dns_reg, dnsr_reg = nfset_registry_to_dns_registries(nfsets)

        # Resolver entries go to dnsr registry
        assert dnsr_reg.groups != {}
        # Primary is the first host
        assert "a.example.com" in dnsr_reg.groups

    def test_iplist_entry_skipped(self):
        entry = NfSetEntry(
            name="blocklist",
            hosts=["https://example.org/list.txt"],
            backend="ip-list",
        )
        nfsets = _make_nfsets(entry)
        dns_reg, dnsr_reg = nfset_registry_to_dns_registries(nfsets)

        # ip-list entries are handled by NfSetsManager (Wave 3)
        assert dns_reg.specs == {}
        assert dnsr_reg.groups == {}

    def test_iplist_plain_entry_skipped(self):
        entry = NfSetEntry(
            name="local-list",
            hosts=["/var/lib/lists/block.txt"],
            backend="ip-list-plain",
        )
        nfsets = _make_nfsets(entry)
        dns_reg, dnsr_reg = nfset_registry_to_dns_registries(nfsets)

        assert dns_reg.specs == {}
        assert dnsr_reg.groups == {}

    def test_mixed_registry_only_dns_extracted(self):
        """Mixed registry: only dnstap/resolver entries are extracted."""
        entries = [
            NfSetEntry(name="cdn", hosts=["cdn.example.com"], backend="dnstap"),
            NfSetEntry(name="blocklist", hosts=["https://example.org/l.txt"],
                       backend="ip-list"),
            NfSetEntry(name="resolver-cdn", hosts=["r.example.com"],
                       backend="resolver"),
        ]
        nfsets = _make_nfsets(*entries)
        dns_reg, dnsr_reg = nfset_registry_to_dns_registries(nfsets)

        # Only the dnstap entry lands in dns_reg
        assert "cdn.example.com" in dns_reg.specs
        # The ip-list entry is not in either registry
        assert not any("example.org" in k for k in dns_reg.specs)
        # The resolver entry lands in dnsr_reg
        assert "r.example.com" in dnsr_reg.groups

    def test_set_name_annotation_in_resolver_group(self):
        entry = NfSetEntry(
            name="api-resolver",
            hosts=["api.example.com"],
            backend="resolver",
        )
        nfsets = _make_nfsets(entry)
        _, dnsr_reg = nfset_registry_to_dns_registries(nfsets)

        group = dnsr_reg.groups.get("api.example.com")
        assert group is not None
        # The comment must contain the nfset_target annotation with the base name.
        assert "nfset_target=" in group.comment
        # Base name: v4 variant with "_v4" stripped.
        v4_name = nfset_to_set_name("api-resolver", "v4")
        expected_base = v4_name[:-3]
        assert expected_base in group.comment, (
            f"base name {expected_base!r} not found in comment {group.comment!r}")

    def test_resolver_single_registration_covers_both_families(self):
        """One resolver group registration suffices; family suffix appended at write time."""
        entry = NfSetEntry(
            name="api-resolver",
            hosts=["api.example.com"],
            backend="resolver",
        )
        nfsets = _make_nfsets(entry)
        _, dnsr_reg = nfset_registry_to_dns_registries(nfsets)

        # Only one group for the primary — not two (one per family)
        assert len(dnsr_reg.groups) == 1
        group = dnsr_reg.groups["api.example.com"]
        assert "nfset_target=" in group.comment


# ---------------------------------------------------------------------------
# Wave 12: DnsrGroup.dnstype field
# ---------------------------------------------------------------------------

class TestDnsrGroupDnstype:
    def test_default_is_none(self):
        """DnsrGroup.dnstype defaults to None (A+AAAA behaviour)."""
        from shorewall_nft.nft.dns_sets import DnsrGroup
        g = DnsrGroup(primary_qname="api.example.com", qnames=["api.example.com"])
        assert g.dnstype is None

    def test_add_with_target_dnstype_srv_stored(self):
        """add_with_target(..., dnstype='srv') stores the value correctly."""
        reg = DnsrRegistry()
        group = reg.add_with_target(
            primary="_sip._udp.example.org",
            qnames=["_sip._udp.example.org"],
            set_name="nfset_sip",
            dnstype="srv",
        )
        assert group.dnstype == "srv"
        # Also verify it's stored in the registry
        stored = reg.groups["_sip._udp.example.org"]
        assert stored.dnstype == "srv"

    def test_add_with_target_dnstype_a(self):
        reg = DnsrRegistry()
        group = reg.add_with_target(
            primary="api.example.com",
            qnames=["api.example.com"],
            set_name="nfset_api",
            dnstype="a",
        )
        assert group.dnstype == "a"

    def test_add_with_target_dnstype_aaaa(self):
        reg = DnsrRegistry()
        group = reg.add_with_target(
            primary="api.example.com",
            qnames=["api.example.com"],
            set_name="nfset_api",
            dnstype="aaaa",
        )
        assert group.dnstype == "aaaa"

    def test_add_with_target_dnstype_default_none(self):
        """Omitting dnstype kwarg keeps None — backward compat."""
        reg = DnsrRegistry()
        group = reg.add_with_target(
            primary="api.example.com",
            qnames=["api.example.com"],
            set_name="nfset_api",
        )
        assert group.dnstype is None


class TestNfsetRegistryToDnsRegistriesDnstype:
    def test_dnstype_srv_propagated(self):
        """nfset_registry_to_dns_registries propagates entry.dnstype='srv'."""
        entry = NfSetEntry(
            name="sip",
            hosts=["_sip._udp.example.org"],
            backend="resolver",
            dnstype="srv",
        )
        nfsets = _make_nfsets(entry)
        _, dnsr_reg = nfset_registry_to_dns_registries(nfsets)

        group = dnsr_reg.groups.get("_sip._udp.example.org")
        assert group is not None, "group must be registered"
        assert group.dnstype == "srv", (
            f"expected dnstype='srv', got {group.dnstype!r}")

    def test_dnstype_none_propagated(self):
        """Entries with no dnstype produce groups with dnstype=None."""
        entry = NfSetEntry(
            name="api",
            hosts=["api.example.com"],
            backend="resolver",
        )
        nfsets = _make_nfsets(entry)
        _, dnsr_reg = nfset_registry_to_dns_registries(nfsets)

        group = dnsr_reg.groups.get("api.example.com")
        assert group is not None
        assert group.dnstype is None

    def test_dnstype_a_propagated(self):
        """dnstype='a' propagates through the bridge."""
        entry = NfSetEntry(
            name="v4only",
            hosts=["api.example.com"],
            backend="resolver",
            dnstype="a",
        )
        nfsets = _make_nfsets(entry)
        _, dnsr_reg = nfset_registry_to_dns_registries(nfsets)
        group = dnsr_reg.groups["api.example.com"]
        assert group.dnstype == "a"
