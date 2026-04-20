"""Unit tests for shorewall_nft.nft.nfsets — parser, emitter, and payload
round-trip.

All hostnames use example.com / example.org (RFC 2606).
All IP addresses use RFC 5737 (198.51.100.x, 203.0.113.x) or RFC 1918.
"""

from __future__ import annotations

import pytest

from shorewall_nft.nft.nfsets import (
    NfSetEntry,
    NfSetRegistry,
    _parse_size,
    build_nfset_registry,
    emit_nfset_declarations,
    nfset_registry_to_payload,
    nfset_to_set_name,
    payload_to_nfset_registry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeLine:
    """Minimal stand-in for a ConfigLine: just exposes .columns."""

    def __init__(self, *cols: str):
        self.columns = list(cols)


def _lines(*rows: tuple) -> list[_FakeLine]:
    return [_FakeLine(*r) for r in rows]


# ---------------------------------------------------------------------------
# nfset_to_set_name
# ---------------------------------------------------------------------------

class TestNfsetToSetName:
    def test_basic_v4(self):
        name = nfset_to_set_name("mycdn", "v4")
        assert name == "nfset_mycdn_v4"
        assert len(name) <= 31

    def test_basic_v6(self):
        name = nfset_to_set_name("mycdn", "v6")
        assert name == "nfset_mycdn_v6"

    def test_sanitises_non_alnum(self):
        name = nfset_to_set_name("my-cdn.set", "v4")
        assert "nfset_" in name
        assert name.endswith("_v4")
        # Hyphens and dots become underscores; consecutive collapsed.
        assert "__" not in name

    def test_max_length(self):
        long_name = "a" * 100
        name = nfset_to_set_name(long_name, "v4")
        assert len(name) <= 31

    def test_collision_avoidance(self):
        # Two long names that would truncate to the same prefix must stay
        # distinct (SHA-1 tail).
        n1 = nfset_to_set_name("a" * 30 + "x", "v4")
        n2 = nfset_to_set_name("a" * 30 + "y", "v4")
        assert n1 != n2

    def test_lowercases(self):
        assert nfset_to_set_name("MySet", "v4") == nfset_to_set_name("myset", "v4")


# ---------------------------------------------------------------------------
# build_nfset_registry — backend types
# ---------------------------------------------------------------------------

class TestBuildNfsetRegistryBackends:
    def test_dnstap_backend(self):
        rows = _lines(("mycdn", "cdn.example.org", "dnstap"))
        reg = build_nfset_registry(rows)
        assert len(reg.entries) == 1
        e = reg.entries[0]
        assert e.name == "mycdn"
        assert e.backend == "dnstap"
        assert "cdn.example.org" in e.hosts

    def test_resolver_backend(self):
        rows = _lines(("svc", "api.example.com", "resolver"))
        reg = build_nfset_registry(rows)
        assert reg.entries[0].backend == "resolver"

    def test_iplist_backend(self):
        rows = _lines(("blocklist", "https://example.org/ips.txt", "ip-list"))
        reg = build_nfset_registry(rows)
        assert reg.entries[0].backend == "ip-list"

    def test_iplist_plain_backend(self):
        rows = _lines(("allowlist", "/var/lib/lists/allow.txt", "ip-list-plain"))
        reg = build_nfset_registry(rows)
        assert reg.entries[0].backend == "ip-list-plain"

    def test_all_names_registered(self):
        rows = _lines(
            ("a", "a.example.com", "dnstap"),
            ("b", "b.example.com", "resolver"),
        )
        reg = build_nfset_registry(rows)
        assert reg.set_names == {"a", "b"}


# ---------------------------------------------------------------------------
# build_nfset_registry — options parsing
# ---------------------------------------------------------------------------

class TestOptionsParsingDns(object):
    def test_dns_servers(self):
        rows = _lines(("r", "api.example.com", "resolver,dns=198.51.100.1"))
        e = build_nfset_registry(rows).entries[0]
        assert "198.51.100.1" in e.dns_servers

    def test_multiple_dns_servers(self):
        rows = _lines(
            ("r", "api.example.com",
             "resolver,dns=198.51.100.1,dns=203.0.113.53"))
        e = build_nfset_registry(rows).entries[0]
        assert e.dns_servers == ["198.51.100.1", "203.0.113.53"]

    def test_filter_option(self):
        rows = _lines(
            ("bl", "198.51.100.0/24", "ip-list,filter=region=us-east-1"))
        e = build_nfset_registry(rows).entries[0]
        assert e.options.get("filter") == ["region=us-east-1"]

    def test_refresh_seconds(self):
        rows = _lines(("r", "api.example.com", "resolver,refresh=3600"))
        e = build_nfset_registry(rows).entries[0]
        assert e.refresh == 3600

    def test_refresh_minutes(self):
        rows = _lines(("r", "api.example.com", "resolver,refresh=5m"))
        e = build_nfset_registry(rows).entries[0]
        assert e.refresh == 300

    def test_refresh_hours(self):
        rows = _lines(("r", "api.example.com", "resolver,refresh=1h"))
        e = build_nfset_registry(rows).entries[0]
        assert e.refresh == 3600

    def test_inotify_flag(self):
        rows = _lines(("wl", "/var/lib/lists/ok.txt", "ip-list-plain,inotify"))
        e = build_nfset_registry(rows).entries[0]
        assert e.inotify is True

    def test_inotify_defaults_false(self):
        rows = _lines(("wl", "/var/lib/lists/ok.txt", "ip-list-plain"))
        e = build_nfset_registry(rows).entries[0]
        assert e.inotify is False

    def test_dnstype_a(self):
        rows = _lines(("r", "api.example.com", "resolver,dnstype=a"))
        e = build_nfset_registry(rows).entries[0]
        assert e.dnstype == "a"

    def test_dnstype_aaaa(self):
        rows = _lines(("r", "api.example.com", "resolver,dnstype=aaaa"))
        e = build_nfset_registry(rows).entries[0]
        assert e.dnstype == "aaaa"

    def test_dnstype_srv(self):
        rows = _lines(("r", "api.example.com", "resolver,dnstype=srv"))
        e = build_nfset_registry(rows).entries[0]
        assert e.dnstype == "srv"

    def test_dnstype_defaults_none(self):
        rows = _lines(("r", "api.example.com", "resolver"))
        e = build_nfset_registry(rows).entries[0]
        assert e.dnstype is None


# ---------------------------------------------------------------------------
# build_nfset_registry — merging same-name rows
# ---------------------------------------------------------------------------

class TestMergingSameNameRows:
    def test_hosts_accumulate(self):
        rows = _lines(
            ("mycdn", "a.example.org", "dnstap"),
            ("mycdn", "b.example.org", "dnstap"),
        )
        reg = build_nfset_registry(rows)
        assert len(reg.entries) == 1
        e = reg.entries[0]
        assert "a.example.org" in e.hosts
        assert "b.example.org" in e.hosts

    def test_conflicting_backends_raises(self):
        rows = _lines(
            ("mycdn", "a.example.org", "dnstap"),
            ("mycdn", "b.example.org", "resolver"),
        )
        with pytest.raises(ValueError, match="conflicting backends"):
            build_nfset_registry(rows)

    def test_dns_servers_accumulate_across_rows(self):
        rows = _lines(
            ("r", "a.example.com", "resolver,dns=198.51.100.1"),
            ("r", "b.example.com", "resolver,dns=203.0.113.53"),
        )
        e = build_nfset_registry(rows).entries[0]
        assert "198.51.100.1" in e.dns_servers
        assert "203.0.113.53" in e.dns_servers


# ---------------------------------------------------------------------------
# build_nfset_registry — brace expansion
# ---------------------------------------------------------------------------

class TestBraceExpansionAtParseTime:
    def test_brace_in_hosts(self):
        rows = _lines(("s", "{ns1,ns2}.example.org", "dnstap"))
        e = build_nfset_registry(rows).entries[0]
        assert "ns1.example.org" in e.hosts
        assert "ns2.example.org" in e.hosts
        assert len(e.hosts) == 2

    def test_no_brace_unchanged(self):
        rows = _lines(("s", "api.example.com", "dnstap"))
        e = build_nfset_registry(rows).entries[0]
        assert e.hosts == ["api.example.com"]


# ---------------------------------------------------------------------------
# build_nfset_registry — error handling
# ---------------------------------------------------------------------------

class TestUnknownOptionRaises:
    def test_unknown_option_token(self):
        rows = _lines(("s", "api.example.com", "resolver,bogus=yes"))
        with pytest.raises(ValueError, match="unknown nfsets option"):
            build_nfset_registry(rows)

    def test_unknown_bare_token(self):
        rows = _lines(("s", "api.example.com", "resolver,notanoption"))
        with pytest.raises(ValueError, match="unknown nfsets option"):
            build_nfset_registry(rows)

    def test_missing_backend_raises(self):
        rows = _lines(("s", "api.example.com", "dns=198.51.100.1"))
        with pytest.raises(ValueError, match="no backend"):
            build_nfset_registry(rows)

    def test_invalid_dnstype_raises(self):
        rows = _lines(("s", "api.example.com", "resolver,dnstype=cname"))
        with pytest.raises(ValueError, match="unknown dnstype"):
            build_nfset_registry(rows)


# ---------------------------------------------------------------------------
# emit_nfset_declarations — flags and size
# ---------------------------------------------------------------------------

class TestEmitNfsetDeclarations:
    def _make_entry(self, name, backend) -> NfSetEntry:
        return NfSetEntry(name=name, hosts=["h.example.org"], backend=backend)

    def _reg(self, *entries: NfSetEntry) -> NfSetRegistry:
        reg = NfSetRegistry(entries=list(entries),
                            set_names={e.name for e in entries})
        return reg

    def test_dns_only_flags_timeout(self):
        reg = self._reg(self._make_entry("a", "dnstap"),
                        self._make_entry("b", "resolver"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "flags timeout;" in out
        assert "flags interval" not in out

    def test_iplist_only_flags_interval(self):
        reg = self._reg(self._make_entry("a", "ip-list"),
                        self._make_entry("b", "ip-list-plain"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "flags interval;" in out
        assert "flags timeout" not in out

    def test_mixed_flags_timeout_interval(self):
        reg = self._reg(self._make_entry("a", "dnstap"),
                        self._make_entry("b", "ip-list"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "flags timeout, interval;" in out

    def test_dns_only_size_4096(self):
        reg = self._reg(self._make_entry("a", "dnstap"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "size 4096;" in out

    def test_iplist_size_262144(self):
        reg = self._reg(self._make_entry("a", "ip-list"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "size 262144;" in out

    def test_mixed_dns_gets_4096_iplist_gets_262144(self):
        # In a mixed registry, each entry uses its own backend default.
        reg = self._reg(self._make_entry("a", "dnstap"),
                        self._make_entry("b", "ip-list"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "size 4096;" in out
        assert "size 262144;" in out

    def test_both_v4_and_v6_emitted(self):
        reg = self._reg(self._make_entry("myset", "dnstap"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "nfset_myset_v4" in out
        assert "nfset_myset_v6" in out

    def test_empty_registry_returns_empty(self):
        reg = NfSetRegistry()
        assert emit_nfset_declarations(reg) == []

    def test_ipv4_addr_and_ipv6_addr_types(self):
        reg = self._reg(self._make_entry("s", "resolver"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "type ipv4_addr;" in out
        assert "type ipv6_addr;" in out


# ---------------------------------------------------------------------------
# Payload round-trip
# ---------------------------------------------------------------------------

class TestPayloadRoundTrip:
    def _build_registry(self) -> NfSetRegistry:
        rows = _lines(
            ("cdn", "{a,b}.example.org", "dnstap"),
            ("resolv", "api.example.com", "resolver,dns=198.51.100.1,refresh=5m"),
            ("blocklist", "/var/lib/bl.txt",
             "ip-list-plain,inotify,filter=region=eu-west-1"),
        )
        return build_nfset_registry(rows)

    def test_round_trip_preserves_names(self):
        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)
        assert {e.name for e in reg2.entries} == {e.name for e in reg.entries}

    def test_round_trip_preserves_backends(self):
        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)
        for orig, restored in zip(reg.entries, reg2.entries):
            assert orig.backend == restored.backend

    def test_round_trip_preserves_hosts(self):
        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)
        for orig, restored in zip(reg.entries, reg2.entries):
            assert orig.hosts == restored.hosts

    def test_round_trip_preserves_dns_servers(self):
        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)
        resolv = next(e for e in reg2.entries if e.name == "resolv")
        assert "198.51.100.1" in resolv.dns_servers

    def test_round_trip_preserves_refresh(self):
        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)
        resolv = next(e for e in reg2.entries if e.name == "resolv")
        assert resolv.refresh == 300  # 5m

    def test_round_trip_preserves_inotify(self):
        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)
        bl = next(e for e in reg2.entries if e.name == "blocklist")
        assert bl.inotify is True

    def test_round_trip_preserves_filter_option(self):
        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)
        bl = next(e for e in reg2.entries if e.name == "blocklist")
        assert "region=eu-west-1" in bl.options.get("filter", [])

    def test_empty_registry_round_trips(self):
        reg = NfSetRegistry()
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)
        assert reg2.entries == []
        assert reg2.set_names == set()

    def test_payload_is_json_safe(self):
        """The payload must contain only JSON-serialisable types."""
        import json
        reg = self._build_registry()
        payload = nfset_registry_to_payload(reg)
        # Should not raise.
        serialised = json.dumps(payload)
        assert isinstance(serialised, str)

    def test_round_trip_preserves_size(self):
        rows = _lines(("bl", "/var/lib/bl.txt", "ip-list-plain,size=1M"))
        reg = build_nfset_registry(rows)
        payload = nfset_registry_to_payload(reg)
        reg2 = payload_to_nfset_registry(payload)
        assert reg2.entries[0].size == 1048576


# ---------------------------------------------------------------------------
# _parse_size — unit tests
# ---------------------------------------------------------------------------

class TestParseSize:
    def test_plain_integer(self):
        assert _parse_size("262144") == 262144

    def test_k_suffix(self):
        assert _parse_size("5k") == 5120

    def test_M_suffix_10M(self):
        assert _parse_size("10M") == 10 * 1024 * 1024

    def test_M_suffix_1M(self):
        assert _parse_size("1M") == 1048576

    def test_256k(self):
        assert _parse_size("256k") == 262144

    def test_invalid_alpha_raises(self):
        with pytest.raises(ValueError, match="unrecognised size format"):
            _parse_size("abc")

    def test_zero_raises(self):
        with pytest.raises(ValueError, match="out of range"):
            _parse_size("0")

    def test_too_large_raises(self):
        # 200M = 209715200 > 64M cap
        with pytest.raises(ValueError, match="out of range"):
            _parse_size("200M")

    def test_boundary_min(self):
        assert _parse_size("1") == 1

    def test_boundary_max(self):
        # 64M exactly should be accepted.
        assert _parse_size("64M") == 64 * 1024 * 1024

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty size value"):
            _parse_size("")

    def test_entry_name_in_error(self):
        with pytest.raises(ValueError, match="myblocklist"):
            _parse_size("0", entry_name="myblocklist")


# ---------------------------------------------------------------------------
# emit_nfset_declarations — explicit size override
# ---------------------------------------------------------------------------

class TestEmitNfsetDeclarationsExplicitSize:
    def _make_entry(self, name, backend, size=None) -> NfSetEntry:
        return NfSetEntry(
            name=name, hosts=["h.example.org"], backend=backend, size=size
        )

    def _reg(self, *entries: NfSetEntry) -> NfSetRegistry:
        return NfSetRegistry(entries=list(entries),
                             set_names={e.name for e in entries})

    def test_explicit_size_overrides_default(self):
        reg = self._reg(self._make_entry("bl", "ip-list", size=1_000_000))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "size 1000000;" in out
        # Must NOT fall back to default.
        assert "size 262144;" not in out

    def test_explicit_size_on_dns_entry(self):
        reg = self._reg(self._make_entry("dns", "dnstap", size=8192))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "size 8192;" in out
        assert "size 4096;" not in out

    def test_no_override_iplist_uses_262144(self):
        reg = self._reg(self._make_entry("bl", "ip-list-plain"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "size 262144;" in out

    def test_no_override_dns_uses_4096(self):
        reg = self._reg(self._make_entry("dns", "resolver"))
        out = "\n".join(emit_nfset_declarations(reg))
        assert "size 4096;" in out

    def test_mixed_registry_global_flags_unchanged(self):
        # Flags must remain registry-wide (not per-set) — global logic unchanged.
        reg = self._reg(
            self._make_entry("a", "dnstap"),
            self._make_entry("b", "ip-list"),
        )
        out = "\n".join(emit_nfset_declarations(reg))
        assert "flags timeout, interval;" in out


# ---------------------------------------------------------------------------
# size= option via build_nfset_registry
# ---------------------------------------------------------------------------

class TestSizeOptionParsedByRegistry:
    def test_size_plain_integer(self):
        rows = _lines(("bl", "/var/lib/bl.txt", "ip-list-plain,size=262144"))
        e = build_nfset_registry(rows).entries[0]
        assert e.size == 262144

    def test_size_M_suffix(self):
        rows = _lines(("bl", "/var/lib/bl.txt", "ip-list,size=10M"))
        e = build_nfset_registry(rows).entries[0]
        assert e.size == 10 * 1024 * 1024

    def test_size_k_suffix(self):
        rows = _lines(("bl", "/var/lib/bl.txt", "ip-list,size=5k"))
        e = build_nfset_registry(rows).entries[0]
        assert e.size == 5120

    def test_size_zero_raises(self):
        rows = _lines(("bl", "/var/lib/bl.txt", "ip-list,size=0"))
        with pytest.raises(ValueError, match="out of range"):
            build_nfset_registry(rows)

    def test_size_too_large_raises(self):
        rows = _lines(("bl", "/var/lib/bl.txt", "ip-list,size=200M"))
        with pytest.raises(ValueError, match="out of range"):
            build_nfset_registry(rows)

    def test_size_invalid_value_raises(self):
        rows = _lines(("bl", "/var/lib/bl.txt", "ip-list,size=abc"))
        with pytest.raises(ValueError, match="unrecognised size format"):
            build_nfset_registry(rows)

    def test_no_size_option_defaults_to_none(self):
        rows = _lines(("bl", "/var/lib/bl.txt", "ip-list-plain"))
        e = build_nfset_registry(rows).entries[0]
        assert e.size is None

    def test_size_emitted_in_declaration(self):
        rows = _lines(("bl", "/var/lib/bl.txt", "ip-list,size=1M"))
        reg = build_nfset_registry(rows)
        out = "\n".join(emit_nfset_declarations(reg))
        assert "size 1048576;" in out
