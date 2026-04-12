"""Compiler-level tests for ``dns:`` token handling.

Exercises the full path: ``rules`` column containing
``dns:hostname`` → IR pre-pass → emitter → nft script that declares
the DNS-backed sets and rewrites the rule to match on them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shorewall_nft.compiler.ir import (
    _rewrite_dns_spec,
    _spec_contains_dns_token,
    build_ir,
)
from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewall_nft.nft.dns_sets import DnsSetRegistry, qname_to_set_name
from shorewall_nft.nft.emitter import emit_nft


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


class TestSpecContainsDnsToken:
    def test_bare_dns_token(self):
        assert _spec_contains_dns_token("dns:github.com")

    def test_zone_prefixed(self):
        assert _spec_contains_dns_token("net:dns:github.com")

    def test_negated(self):
        assert _spec_contains_dns_token("!dns:bad.com")

    def test_plain_zone(self):
        assert not _spec_contains_dns_token("net")
        assert not _spec_contains_dns_token("net:1.2.3.4")

    def test_false_positive_guard(self):
        assert not _spec_contains_dns_token("dnsdomain.com")


class TestRewriteDnsSpec:
    def test_bare_token_v4(self):
        reg = DnsSetRegistry()
        out = _rewrite_dns_spec("dns:github.com", reg, "v4")
        assert out == "+dns_github_com_v4"
        assert "github.com" in reg.specs

    def test_zone_prefix_preserved(self):
        reg = DnsSetRegistry()
        out = _rewrite_dns_spec("net:dns:github.com", reg, "v6")
        assert out == "net:+dns_github_com_v6"

    def test_negation_preserved(self):
        reg = DnsSetRegistry()
        out = _rewrite_dns_spec("!dns:bad.example.org", reg, "v4")
        assert out == "!+dns_bad_example_org_v4"

    def test_invalid_host_passes_through(self):
        reg = DnsSetRegistry()
        out = _rewrite_dns_spec("dns:not-a-host", reg, "v4")
        # Single-label, bogus form — caller's parser rejects later.
        assert out == "dns:not-a-host"
        assert not reg.specs

    def test_canonicalisation_applied(self):
        reg = DnsSetRegistry()
        _rewrite_dns_spec("dns:GitHub.Com.", reg, "v4")
        assert "github.com" in reg.specs
        assert "GitHub.Com" not in reg.specs


class TestBuildIrDnsRules:
    def test_single_rule_becomes_two_family_rules(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(columns=["ACCEPT", "fw", "net:dns:github.com"],
                       file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        assert "github.com" in ir.dns_registry.specs

        # Find the rules in the fw→net chain.
        chain = None
        for name, c in ir.chains.items():
            if "fw" in name and "net" in name:
                chain = c
                break
        assert chain is not None

        # Should have two rules with ACCEPT + DNS set matches.
        daddr_matches = []
        for r in chain.rules:
            for m in r.matches:
                if "daddr" in m.field and m.value.startswith("+dns_"):
                    daddr_matches.append((m.field, m.value))

        assert ("ip daddr", "+dns_github_com_v4") in daddr_matches
        assert ("ip6 daddr", "+dns_github_com_v6") in daddr_matches

    def test_dns_set_size_override_from_shorewall_conf(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(columns=["ACCEPT", "fw", "net:dns:example.com"],
                       file="rules", lineno=1),
        ]
        minimal_config.settings = {
            "DNS_SET_SIZE": "128",
            "DNS_SET_TTL_FLOOR": "600",
        }
        ir = build_ir(minimal_config)
        spec = ir.dns_registry.specs["example.com"]
        assert spec.size == 128
        assert spec.ttl_floor == 600

    def test_dnsnames_file_overrides_defaults(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(columns=["ACCEPT", "fw", "net:dns:api.stripe.com"],
                       file="rules", lineno=1),
        ]
        minimal_config.dnsnames = [
            ConfigLine(
                columns=["api.stripe.com", "60", "3600", "32",
                         "Payment", "webhooks"],
                file="dnsnames", lineno=1),
        ]
        ir = build_ir(minimal_config)
        spec = ir.dns_registry.specs["api.stripe.com"]
        assert spec.ttl_floor == 60
        assert spec.size == 32
        assert "Payment webhooks" in spec.comment

    def test_hostname_only_in_dnsnames_without_rule(self, minimal_config):
        """dnsnames entries stand alone — the daemon can pre-populate
        sets that no rule explicitly references yet."""
        minimal_config.dnsnames = [
            ConfigLine(columns=["example.com", "-", "-", "-", "placeholder"],
                       file="dnsnames", lineno=1),
        ]
        ir = build_ir(minimal_config)
        assert "example.com" in ir.dns_registry.specs

    def test_negated_dns_destination(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(columns=["DROP", "fw", "net:!dns:bad.example.org"],
                       file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        assert "bad.example.org" in ir.dns_registry.specs
        chain = None
        for name, c in ir.chains.items():
            if "fw" in name and "net" in name:
                chain = c
                break
        assert chain is not None
        negated_seen = False
        for r in chain.rules:
            for m in r.matches:
                if m.value.startswith("+dns_") and m.negate:
                    negated_seen = True
        assert negated_seen


class TestEmitterDnsSets:
    def test_sets_declared_with_timeout_flag(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(columns=["ACCEPT", "fw", "net:dns:github.com",
                                "tcp", "443"],
                       file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        script = emit_nft(ir)
        assert "set dns_github_com_v4 {" in script
        assert "set dns_github_com_v6 {" in script
        assert "flags timeout;" in script
        # Size line should appear — default is 512 unless overridden
        assert "size 512;" in script

    def test_rule_references_use_at_prefix(self, minimal_config):
        minimal_config.rules = [
            ConfigLine(columns=["ACCEPT", "fw", "net:dns:github.com",
                                "tcp", "443"],
                       file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        script = emit_nft(ir)
        assert "@dns_github_com_v4" in script
        assert "@dns_github_com_v6" in script
        # Per-family split — v4 rule uses ``ip daddr``, v6 rule ``ip6 daddr``
        assert "ip daddr @dns_github_com_v4" in script
        assert "ip6 daddr @dns_github_com_v6" in script

    def test_missing_sets_fallback_not_invoked_for_dns(self, minimal_config):
        """``_declare_missing_sets`` creates empty ipv4_addr sets as
        a safety net. For DNS sets we claim the name upfront so the
        fallback never emits a conflicting declaration."""
        minimal_config.rules = [
            ConfigLine(columns=["ACCEPT", "fw", "net:dns:example.org"],
                       file="rules", lineno=1),
        ]
        ir = build_ir(minimal_config)
        script = emit_nft(ir)
        # Only ONE declaration of each DNS set.
        assert script.count("set dns_example_org_v4 {") == 1
        assert script.count("set dns_example_org_v6 {") == 1

    def test_deterministic_set_names_across_calls(self):
        # Regression: compiler and daemon must agree on the exact
        # name chosen for any given qname.
        a = qname_to_set_name("api.stripe.com", "v4")
        b = qname_to_set_name("api.stripe.com", "v4")
        assert a == b == "dns_api_stripe_com_v4"
