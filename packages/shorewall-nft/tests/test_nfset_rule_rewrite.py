"""Unit tests for nfset token detection, spec rewriting, and rule cloning.

All hostnames use example.com / example.org (RFC 2606).
All IP addresses use RFC 5737 (198.51.100.x, 203.0.113.x) or RFC 1918.
"""

from __future__ import annotations

import pytest

from shorewall_nft.compiler.ir import (
    _spec_contains_nfset_token,
    _rewrite_nfset_spec,
)
from shorewall_nft.nft.nfsets import NfSetRegistry, NfSetEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _registry(*names: str, backend: str = "dnstap") -> NfSetRegistry:
    """Build a minimal NfSetRegistry with the given logical set names."""
    reg = NfSetRegistry()
    for name in names:
        entry = NfSetEntry(
            name=name,
            hosts=["cdn.example.com"],
            backend=backend,
        )
        reg.entries.append(entry)
        reg.set_names.add(name)
    return reg


# ---------------------------------------------------------------------------
# _spec_contains_nfset_token
# ---------------------------------------------------------------------------

class TestSpecContainsNfsetToken:
    def test_bare(self):
        assert _spec_contains_nfset_token("nfset:mycdn") is True

    def test_negated(self):
        assert _spec_contains_nfset_token("!nfset:mycdn") is True

    def test_zone_prefixed(self):
        assert _spec_contains_nfset_token("net:nfset:mycdn") is True

    def test_zone_prefixed_negated(self):
        assert _spec_contains_nfset_token("net:!nfset:mycdn") is True

    def test_no_match_dns(self):
        assert _spec_contains_nfset_token("dns:cdn.example.com") is False

    def test_no_match_plain_zone(self):
        assert _spec_contains_nfset_token("net:1.2.3.4") is False

    def test_no_match_nfset_word_alone(self):
        assert _spec_contains_nfset_token("nfset") is False

    def test_no_match_existing_set_ref(self):
        # A pre-existing +set_name sentinel must not be re-detected
        assert _spec_contains_nfset_token("+nfset_mycdn_v4") is False

    def test_no_match_empty(self):
        assert _spec_contains_nfset_token("") is False

    def test_no_match_all(self):
        assert _spec_contains_nfset_token("all") is False

    def test_multiname(self):
        assert _spec_contains_nfset_token("nfset:a,b") is True


# ---------------------------------------------------------------------------
# _rewrite_nfset_spec
# ---------------------------------------------------------------------------

class TestRewriteNfsetSpec:
    def test_bare_v4(self):
        reg = _registry("mycdn")
        result = _rewrite_nfset_spec("nfset:mycdn", reg, "v4")
        assert result == "+nfset_mycdn_v4"

    def test_bare_v6(self):
        reg = _registry("mycdn")
        result = _rewrite_nfset_spec("nfset:mycdn", reg, "v6")
        assert result == "+nfset_mycdn_v6"

    def test_negated(self):
        reg = _registry("mycdn")
        result = _rewrite_nfset_spec("!nfset:mycdn", reg, "v4")
        assert result == "!+nfset_mycdn_v4"

    def test_zone_prefixed_v4(self):
        reg = _registry("mycdn")
        result = _rewrite_nfset_spec("net:nfset:mycdn", reg, "v4")
        assert result == "net:+nfset_mycdn_v4"

    def test_zone_prefixed_v6(self):
        reg = _registry("mycdn")
        result = _rewrite_nfset_spec("net:nfset:mycdn", reg, "v6")
        assert result == "net:+nfset_mycdn_v6"

    def test_zone_prefixed_negated(self):
        reg = _registry("mycdn")
        result = _rewrite_nfset_spec("net:!nfset:mycdn", reg, "v4")
        assert result == "net:!+nfset_mycdn_v4"

    def test_unknown_name_raises(self):
        reg = _registry("known")
        with pytest.raises(ValueError, match="nfset:.*not declared"):
            _rewrite_nfset_spec("nfset:unknown", reg, "v4")

    def test_passthrough_non_nfset(self):
        reg = _registry("mycdn")
        spec = "net:1.2.3.4"
        result = _rewrite_nfset_spec(spec, reg, "v4")
        assert result == spec

    def test_passthrough_dns_token(self):
        reg = _registry("mycdn")
        spec = "dns:cdn.example.com"
        result = _rewrite_nfset_spec(spec, reg, "v4")
        assert result == spec

    def test_sanitised_name_with_hyphen(self):
        # Hyphens in logical names become underscores in the nft set name
        reg = _registry("my-cdn")
        result = _rewrite_nfset_spec("nfset:my-cdn", reg, "v4")
        assert result == "+nfset_my_cdn_v4"


# ---------------------------------------------------------------------------
# Multi-set expansion (via _process_rules round-trip)
# ---------------------------------------------------------------------------

class TestMultiSetExpansion:
    """Verify that nfset:a,b in DEST produces two IR zone-pair chains, one per set."""

    def test_multiset_dest_yields_four_chains(self):
        """nfset:a,b in DEST → IR has one zone-pair chain per set×family."""
        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.config.parser import ShorewalConfig, ConfigLine
        from pathlib import Path

        cfg = ShorewalConfig(config_dir=Path("/tmp"))
        cfg.settings["FASTACCEPT"] = "Yes"

        def _cl(*cols: str) -> ConfigLine:
            return ConfigLine(columns=list(cols), file="", lineno=0,
                              comment_tag=None, section="", raw="",
                              format_version=1)

        cfg.zones = [_cl("fw", "firewall"), _cl("net", "ipv4")]
        cfg.interfaces = [_cl("net", "eth0", "-", "-")]
        cfg.policy = [_cl("fw", "net", "ACCEPT"), _cl("net", "fw", "DROP")]
        # Rule: from fw to nfset:alpha,beta — should produce 4 chains
        cfg.rules = [_cl("ACCEPT", "fw", "nfset:alpha,beta")]
        cfg.nfsets = [
            _cl("alpha", "a.example.com", "dnstap"),
            _cl("beta", "b.example.com", "dnstap"),
        ]

        ir = build_ir(cfg)

        # The sentinel +nfset_X_vY appears as the zone-pair chain name suffix.
        # The IR uses chain names like "fw-+nfset_alpha_v4" for each clone.
        chain_names = set(ir.chains.keys())
        assert "fw-+nfset_alpha_v4" in chain_names, f"chains={chain_names}"
        assert "fw-+nfset_alpha_v6" in chain_names, f"chains={chain_names}"
        assert "fw-+nfset_beta_v4" in chain_names, f"chains={chain_names}"
        assert "fw-+nfset_beta_v6" in chain_names, f"chains={chain_names}"

    def test_emitter_produces_set_match_rules(self):
        """Emitted nft script contains ip daddr @nfset_alpha_v4 match rules."""
        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.config.parser import ShorewalConfig, ConfigLine
        from shorewall_nft.nft.emitter import emit_nft
        from pathlib import Path

        cfg = ShorewalConfig(config_dir=Path("/tmp"))
        cfg.settings["FASTACCEPT"] = "Yes"

        def _cl(*cols: str) -> ConfigLine:
            return ConfigLine(columns=list(cols), file="", lineno=0,
                              comment_tag=None, section="", raw="",
                              format_version=1)

        cfg.zones = [_cl("fw", "firewall"), _cl("net", "ipv4")]
        cfg.interfaces = [_cl("net", "eth0", "-", "-")]
        cfg.policy = [_cl("fw", "net", "ACCEPT"), _cl("net", "fw", "DROP")]
        cfg.rules = [_cl("ACCEPT", "fw", "nfset:alpha,beta")]
        cfg.nfsets = [
            _cl("alpha", "a.example.com", "dnstap"),
            _cl("beta", "b.example.com", "dnstap"),
        ]

        ir = build_ir(cfg)
        script = emit_nft(ir)

        # Declarations must be present
        assert "set nfset_alpha_v4" in script
        assert "set nfset_alpha_v6" in script
        assert "set nfset_beta_v4" in script
        assert "set nfset_beta_v6" in script


# ---------------------------------------------------------------------------
# Pre-pass ordering: nfset pass must not disturb dns: tokens
# ---------------------------------------------------------------------------

class TestPrePassOrdering:
    """The nfset pre-pass must leave dns: tokens untouched."""

    def test_nfset_pass_leaves_dns_token_intact(self):
        """A spec with only a dns: token is NOT touched by the nfset rewriter."""
        from shorewall_nft.nft.nfsets import NfSetRegistry
        reg = NfSetRegistry()  # empty — no nfsets declared

        spec = "dns:cdn.example.com"
        # The nfset detector should not fire on this spec.
        assert not _spec_contains_nfset_token(spec)
        # And the rewriter leaves it unchanged.
        result = _rewrite_nfset_spec(spec, reg, "v4")
        assert result == spec

    def test_nfset_rewrite_does_not_touch_dns_prefix(self):
        """A spec rewritten by the nfset pass contains no dns: token."""
        reg = _registry("mycdn")
        result = _rewrite_nfset_spec("nfset:mycdn", reg, "v4")
        assert "dns:" not in result
        assert result.startswith("+nfset_")
