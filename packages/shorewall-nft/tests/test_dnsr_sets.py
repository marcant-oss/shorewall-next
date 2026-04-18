"""Tests for ``dnsr:`` pull-resolver token support.

Covers:
* DnsrGroup / DnsrRegistry data model
* is_dnsr_token predicate
* _spec_contains_dnsr_token / _rewrite_dnsr_spec in the compiler IR
* Compiled allowlist round-trip: write + read_compiled_dnsr_allowlist
* Full compile: dnsr: token in rules → same dns_ set as dns: token
* Secondary qnames registered in dns_registry for tap pipeline
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shorewall_nft.compiler.ir import (
    _rewrite_dnsr_spec,
    _spec_contains_dnsr_token,
    build_ir,
)
from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewall_nft.nft.dns_sets import (
    DnsSetRegistry,
    DnsrRegistry,
    is_dnsr_token,
    read_compiled_allowlist,
    read_compiled_dnsr_allowlist,
    write_compiled_allowlist,
)
from shorewall_nft.nft.emitter import emit_nft


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def minimal_config():
    cfg = ShorewalConfig(config_dir=Path("/tmp"))
    cfg.zones = [
        ConfigLine(columns=["fw", "firewall"], file="zones", lineno=1),
        ConfigLine(columns=["net", "ipv4"], file="zones", lineno=2),
    ]
    cfg.interfaces = [
        ConfigLine(columns=["net", "eth0", "-"], file="interfaces", lineno=1),
    ]
    return cfg


# ---------------------------------------------------------------------------
# is_dnsr_token
# ---------------------------------------------------------------------------

class TestIsDnsrToken:
    def test_detects_dnsr_prefix(self):
        assert is_dnsr_token("dnsr:github.com")

    def test_multi_host(self):
        assert is_dnsr_token("dnsr:github.com,mail.github.com")

    def test_rejects_bare_dnsr(self):
        assert not is_dnsr_token("dnsr:")

    def test_does_not_match_dns_token(self):
        assert not is_dnsr_token("dns:github.com")

    def test_does_not_match_plain(self):
        assert not is_dnsr_token("github.com")


# ---------------------------------------------------------------------------
# DnsrRegistry
# ---------------------------------------------------------------------------

class TestDnsrRegistry:
    def test_add_single_host(self):
        reg = DnsrRegistry()
        group = reg.add_from_rule("github.com", ["github.com"])
        assert group.primary_qname == "github.com"
        assert group.qnames == ["github.com"]
        assert "github.com" in reg.groups

    def test_add_multi_host(self):
        reg = DnsrRegistry()
        group = reg.add_from_rule(
            "github.com", ["github.com", "mail.github.com"])
        assert group.qnames == ["github.com", "mail.github.com"]

    def test_merge_secondary_qnames(self):
        reg = DnsrRegistry()
        reg.add_from_rule("github.com", ["github.com"])
        reg.add_from_rule("github.com", ["github.com", "api.github.com"])
        group = reg.groups["github.com"]
        assert "api.github.com" in group.qnames
        assert group.qnames.count("github.com") == 1  # no duplicates

    def test_canonicalises_qnames(self):
        reg = DnsrRegistry()
        group = reg.add_from_rule("Github.Com.", ["Github.Com.", "API.GitHub.COM"])
        assert group.primary_qname == "github.com"
        assert "api.github.com" in group.qnames

    def test_iter_sorted(self):
        reg = DnsrRegistry()
        reg.add_from_rule("zzz.example.com", ["zzz.example.com"])
        reg.add_from_rule("aaa.example.com", ["aaa.example.com"])
        names = [g.primary_qname for g in reg.iter_sorted()]
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# _spec_contains_dnsr_token
# ---------------------------------------------------------------------------

class TestSpecContainsDnsrToken:
    def test_bare(self):
        assert _spec_contains_dnsr_token("dnsr:github.com")

    def test_negated(self):
        assert _spec_contains_dnsr_token("!dnsr:bad.example.org")

    def test_zone_prefixed(self):
        assert _spec_contains_dnsr_token("net:dnsr:github.com")

    def test_zone_negated(self):
        assert _spec_contains_dnsr_token("net:!dnsr:github.com")

    def test_multi_host(self):
        assert _spec_contains_dnsr_token("dnsr:github.com,mail.github.com")

    def test_does_not_match_dns(self):
        assert not _spec_contains_dnsr_token("dns:github.com")

    def test_does_not_match_plain(self):
        assert not _spec_contains_dnsr_token("net")
        assert not _spec_contains_dnsr_token("1.2.3.4")


# ---------------------------------------------------------------------------
# _rewrite_dnsr_spec
# ---------------------------------------------------------------------------

class TestRewriteDnsrSpec:
    def test_single_host_v4(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        out = _rewrite_dnsr_spec("dnsr:github.com", dns_reg, dnsr_reg, "v4")
        assert out == "+dns_github_com_v4"

    def test_single_host_v6(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        out = _rewrite_dnsr_spec("dnsr:github.com", dns_reg, dnsr_reg, "v6")
        assert out == "+dns_github_com_v6"

    def test_multi_host_uses_primary_set(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        out = _rewrite_dnsr_spec(
            "dnsr:github.com,mail.github.com", dns_reg, dnsr_reg, "v4")
        assert out == "+dns_github_com_v4"

    def test_registers_primary_in_dns_registry(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        _rewrite_dnsr_spec("dnsr:github.com,mail.github.com", dns_reg, dnsr_reg, "v4")
        assert "github.com" in dns_reg.specs

    def test_registers_secondaries_in_dns_registry_for_tap(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        _rewrite_dnsr_spec("dnsr:github.com,mail.github.com", dns_reg, dnsr_reg, "v4")
        # secondary also in dns_registry so tap pipeline can route it
        assert "mail.github.com" in dns_reg.specs

    def test_primary_declares_set_secondary_does_not(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        _rewrite_dnsr_spec(
            "dnsr:github.com,mail.github.com", dns_reg, dnsr_reg, "v4")
        assert dns_reg.specs["github.com"].declare_set is True
        assert dns_reg.specs["mail.github.com"].declare_set is False

    def test_secondary_promoted_to_primary_by_dns_rule(self):
        from shorewall_nft.compiler.ir import _rewrite_dns_spec
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        _rewrite_dnsr_spec(
            "dnsr:github.com,mail.github.com", dns_reg, dnsr_reg, "v4")
        # mail.github.com starts as secondary (declare_set=False)
        assert dns_reg.specs["mail.github.com"].declare_set is False
        # A direct dns: reference should promote it.
        _rewrite_dns_spec("dns:mail.github.com", dns_reg, "v4")
        assert dns_reg.specs["mail.github.com"].declare_set is True

    def test_registers_group_in_dnsr_registry(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        _rewrite_dnsr_spec(
            "dnsr:github.com,mail.github.com", dns_reg, dnsr_reg, "v4")
        assert "github.com" in dnsr_reg.groups
        group = dnsr_reg.groups["github.com"]
        assert "mail.github.com" in group.qnames

    def test_zone_prefix_preserved(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        out = _rewrite_dnsr_spec("net:dnsr:github.com", dns_reg, dnsr_reg, "v4")
        assert out == "net:+dns_github_com_v4"

    def test_negation_preserved(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        out = _rewrite_dnsr_spec("!dnsr:github.com", dns_reg, dnsr_reg, "v4")
        assert out == "!+dns_github_com_v4"

    def test_zone_and_negation(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        out = _rewrite_dnsr_spec(
            "net:!dnsr:github.com", dns_reg, dnsr_reg, "v4")
        assert out == "net:!+dns_github_com_v4"

    def test_returns_unchanged_on_invalid_host(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        # ip literals are not valid hostnames
        out = _rewrite_dnsr_spec("dnsr:1.2.3.4", dns_reg, dnsr_reg, "v4")
        assert out == "dnsr:1.2.3.4"
        assert not dns_reg.specs

    def test_no_op_on_plain_spec(self):
        dns_reg = DnsSetRegistry()
        dnsr_reg = DnsrRegistry()
        out = _rewrite_dnsr_spec("net", dns_reg, dnsr_reg, "v4")
        assert out == "net"


# ---------------------------------------------------------------------------
# Compiled allowlist round-trip
# ---------------------------------------------------------------------------

class TestAllowlistRoundTrip:
    def test_write_and_read_back_dns_section(self, tmp_path):
        from shorewall_nft.nft.dns_sets import DnsSetSpec
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec("github.com", 300, 86400, 256))

        dnsr_reg = DnsrRegistry()
        dnsr_reg.add_from_rule("github.com", ["github.com", "mail.github.com"])

        path = tmp_path / "dnsnames.compiled"
        write_compiled_allowlist(reg, path, dnsr_registry=dnsr_reg)

        # dns section still readable by existing reader
        dns_out = read_compiled_allowlist(path)
        assert "github.com" in dns_out.specs
        assert dns_out.specs["github.com"].size == 256

    def test_write_and_read_back_dnsr_section(self, tmp_path):
        from shorewall_nft.nft.dns_sets import DnsSetSpec
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec("github.com", 300, 86400, 256))

        dnsr_reg = DnsrRegistry()
        dnsr_reg.add_from_rule(
            "github.com", ["github.com", "mail.github.com"])
        dnsr_reg.add_from_rule(
            "api.stripe.com", ["api.stripe.com"])

        path = tmp_path / "dnsnames.compiled"
        write_compiled_allowlist(reg, path, dnsr_registry=dnsr_reg)

        out = read_compiled_dnsr_allowlist(path)
        assert "github.com" in out.groups
        assert "api.stripe.com" in out.groups
        gh = out.groups["github.com"]
        assert gh.qnames == ["github.com", "mail.github.com"]

    def test_no_dnsr_section_when_registry_empty(self, tmp_path):
        from shorewall_nft.nft.dns_sets import DnsSetSpec
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec("github.com", 300, 86400, 256))
        path = tmp_path / "dnsnames.compiled"
        write_compiled_allowlist(reg, path)
        content = path.read_text()
        assert "[dnsr]" not in content
        # existing reader still works
        dns_out = read_compiled_allowlist(path)
        assert "github.com" in dns_out.specs

    def test_read_dnsr_returns_empty_when_no_section(self, tmp_path):
        from shorewall_nft.nft.dns_sets import DnsSetSpec
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec("github.com", 300, 86400, 256))
        path = tmp_path / "dnsnames.compiled"
        write_compiled_allowlist(reg, path)
        out = read_compiled_dnsr_allowlist(path)
        assert not out.groups

    def test_ttl_and_size_preserved(self, tmp_path):
        dnsr_reg = DnsrRegistry()
        dnsr_reg.add_from_rule("example.com", ["example.com"])
        dnsr_reg.groups["example.com"].ttl_floor = 60
        dnsr_reg.groups["example.com"].ttl_ceil = 3600
        dnsr_reg.groups["example.com"].size = 64

        path = tmp_path / "dnsnames.compiled"
        write_compiled_allowlist(DnsSetRegistry(), path, dnsr_registry=dnsr_reg)
        out = read_compiled_dnsr_allowlist(path)
        g = out.groups["example.com"]
        assert g.ttl_floor == 60
        assert g.ttl_ceil == 3600
        assert g.size == 64


# ---------------------------------------------------------------------------
# Full compile integration
# ---------------------------------------------------------------------------

class TestFullCompileDnsr:
    def test_dnsr_dest_produces_dns_set(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(
                columns=["ACCEPT", "fw", "net:dnsr:github.com", "tcp", "443"],
                file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        # Primary qname registered in dns_registry → set declared
        assert "github.com" in ir.dns_registry.specs
        # Pull-resolver group recorded
        assert "github.com" in ir.dnsr_registry.groups

    def test_dnsr_multi_host_dest(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(
                columns=["ACCEPT", "fw",
                         "net:dnsr:github.com,mail.github.com", "tcp", "443"],
                file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        # Both qnames in dns_registry (secondary for tap pipeline)
        assert "github.com" in ir.dns_registry.specs
        assert "mail.github.com" in ir.dns_registry.specs
        # Pull-resolver group has both
        group = ir.dnsr_registry.groups["github.com"]
        assert "mail.github.com" in group.qnames

    def test_dnsr_emits_same_set_as_dns(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(
                columns=["ACCEPT", "fw", "net:dnsr:github.com", "tcp", "443"],
                file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        script = emit_nft(ir)
        # Same dns_github_com_v4/v6 sets as produced by dns: token
        assert "dns_github_com_v4" in script
        assert "dns_github_com_v6" in script

    def test_dnsr_and_dns_same_hostname_share_set(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(
                columns=["ACCEPT", "fw", "net:dns:github.com", "tcp", "443"],
                file="rules", lineno=1),
            ConfigLine(
                columns=["ACCEPT", "fw", "net:dnsr:github.com", "tcp", "80"],
                file="rules", lineno=2),
        ]
        ir = build_ir(minimal_config)
        script = emit_nft(ir)
        # Only one declaration of each set (no duplicates)
        assert script.count("set dns_github_com_v4") == 1
        assert script.count("set dns_github_com_v6") == 1

    def test_dnsr_rule_matches_nft_set_ref(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(
                columns=["ACCEPT", "fw", "net:dnsr:github.com", "tcp", "443"],
                file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        script = emit_nft(ir)
        assert "@dns_github_com_v4" in script or "@dns_github_com_v6" in script

    def test_dns_multi_host_primary_declares_only(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(
                columns=["ACCEPT", "fw",
                         "net:dns:github.com,microsoft.com", "tcp", "443"],
                file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        script = emit_nft(ir)
        # Primary declared, secondary absorbed via tap alias only.
        assert "set dns_github_com_v4" in script
        assert "set dns_microsoft_com_v4" not in script
        # Tap alias group recorded but pull_enabled is False.
        assert "github.com" in ir.dnsr_registry.groups
        assert ir.dnsr_registry.groups["github.com"].pull_enabled is False

    def test_dns_multi_host_allowlist_roundtrip(self, tmp_path, minimal_config):
        minimal_config.rules = [
            ConfigLine(
                columns=["ACCEPT", "fw",
                         "net:dns:github.com,microsoft.com", "tcp", "443"],
                file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        path = tmp_path / "dnsnames.compiled"
        write_compiled_allowlist(
            ir.dns_registry, path, dnsr_registry=ir.dnsr_registry)

        dnsr_out = read_compiled_dnsr_allowlist(path)
        assert "github.com" in dnsr_out.groups
        group = dnsr_out.groups["github.com"]
        assert group.pull_enabled is False
        assert group.qnames == ["github.com", "microsoft.com"]

    def test_dnsr_secondary_does_not_declare_nft_set(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(
                columns=["ACCEPT", "fw",
                         "net:dnsr:github.com,mail.github.com", "tcp", "443"],
                file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        script = emit_nft(ir)
        # Primary's set declared; secondary's set must not be, since
        # dnsr sends all IPs to the primary's set.
        assert "set dns_github_com_v4" in script
        assert "set dns_mail_github_com_v4" not in script
        assert "set dns_mail_github_com_v6" not in script

    def test_dnsr_allowlist_roundtrip_via_write(self, tmp_path, minimal_config):
        minimal_config.rules = [
            ConfigLine(
                columns=["ACCEPT", "fw",
                         "net:dnsr:github.com,mail.github.com", "tcp", "443"],
                file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        path = tmp_path / "dnsnames.compiled"
        write_compiled_allowlist(
            ir.dns_registry, path, dnsr_registry=ir.dnsr_registry)

        dns_out = read_compiled_allowlist(path)
        dnsr_out = read_compiled_dnsr_allowlist(path)

        assert "github.com" in dns_out.specs
        assert "mail.github.com" in dns_out.specs
        assert "github.com" in dnsr_out.groups
        assert "mail.github.com" in dnsr_out.groups["github.com"].qnames
