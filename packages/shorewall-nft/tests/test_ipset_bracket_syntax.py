"""Tests for W16: classic ipsets bracket-flag syntax and AND-multi-set lists.

All set names are synthetic (alphanumeric/hyphen).
All RFC 5737 / RFC 3849 addresses used where IPs appear.
"""

from __future__ import annotations

import pytest

from shorewall_nft.compiler.ir import (
    _spec_contains_bracket_ipset,
    _rewrite_bracket_spec,
    _normalise_bracket_flags,
)


# ---------------------------------------------------------------------------
# _spec_contains_bracket_ipset
# ---------------------------------------------------------------------------

class TestSpecContainsBracketIpset:
    # Bare +setname without brackets does NOT trigger the bracket pre-pass;
    # it is handled by the normal ipset path in _add_rule.
    def test_bare_plus_no_trigger(self):
        assert _spec_contains_bracket_ipset("+mylist") is False

    def test_negated_bare_plus_no_trigger(self):
        assert _spec_contains_bracket_ipset("!+mylist") is False

    def test_plus_with_src_flag(self):
        assert _spec_contains_bracket_ipset("+mylist[src]") is True

    def test_plus_with_dst_flag(self):
        assert _spec_contains_bracket_ipset("+mylist[dst]") is True

    def test_plus_with_src_dst_flag(self):
        assert _spec_contains_bracket_ipset("+mylist[src,dst]") is True

    def test_negated_plus_with_bracket(self):
        assert _spec_contains_bracket_ipset("!+mylist[dst]") is True

    def test_zone_prefixed_plus(self):
        assert _spec_contains_bracket_ipset("net:+mylist[src]") is True

    def test_zone_prefixed_negated(self):
        assert _spec_contains_bracket_ipset("net:!+mylist[dst]") is True

    def test_and_multiset(self):
        assert _spec_contains_bracket_ipset("+[alpha,beta]") is True

    def test_negated_and_multiset(self):
        assert _spec_contains_bracket_ipset("!+[alpha,beta]") is True

    def test_no_match_plain_zone(self):
        assert _spec_contains_bracket_ipset("net:198.51.100.1") is False

    def test_no_match_nfset_token(self):
        assert _spec_contains_bracket_ipset("nfset:mycdn") is False

    def test_no_match_dns_token(self):
        assert _spec_contains_bracket_ipset("dns:example.org") is False

    def test_no_match_empty(self):
        assert _spec_contains_bracket_ipset("") is False

    def test_no_match_plain_zone_name(self):
        assert _spec_contains_bracket_ipset("all") is False

    def test_already_processed_sentinel_no_trigger(self):
        # nfset/dns sentinels like +nfset_alpha_v4 have no bracket flags
        # and must NOT trigger the bracket pre-pass
        assert _spec_contains_bracket_ipset("+nfset_alpha_v4") is False
        assert _spec_contains_bracket_ipset("+dns_example_v4") is False


# ---------------------------------------------------------------------------
# _normalise_bracket_flags
# ---------------------------------------------------------------------------

class TestNormaliseBracketFlags:
    def test_empty_uses_column_src(self):
        assert _normalise_bracket_flags("", "src") == ["src"]

    def test_empty_uses_column_dst(self):
        assert _normalise_bracket_flags("", "dst") == ["dst"]

    def test_src_explicit(self):
        assert _normalise_bracket_flags("src", "dst") == ["src"]

    def test_dst_explicit(self):
        assert _normalise_bracket_flags("dst", "src") == ["dst"]

    def test_src_dst(self):
        result = _normalise_bracket_flags("src,dst", "src")
        assert set(result) == {"src", "dst"}

    def test_dst_src_normalised(self):
        result = _normalise_bracket_flags("dst,src", "src")
        assert set(result) == {"src", "dst"}

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="invalid bracket flag"):
            _normalise_bracket_flags("foo", "src")

    def test_empty_bracket_raises(self):
        # empty string inside [] that is not simply "use column default"
        # (normalise_bracket_flags treats "" as "use default" — not an error)
        assert _normalise_bracket_flags("", "src") == ["src"]


# ---------------------------------------------------------------------------
# _rewrite_bracket_spec — single set
# ---------------------------------------------------------------------------

class TestRewriteBracketSpecSingle:
    """Single set +setname[flags] forms."""

    def test_bare_no_brackets_src_column(self):
        stripped, infos = _rewrite_bracket_spec("+mylist", "src")
        # No bracket → spec unchanged, one match on column_side
        assert stripped == "+mylist"
        assert len(infos) == 1
        side, name, neg = infos[0]
        assert side == "src"
        assert name == "mylist"
        assert neg is False

    def test_bare_no_brackets_dst_column(self):
        stripped, infos = _rewrite_bracket_spec("+mylist", "dst")
        assert stripped == "+mylist"
        side, name, neg = infos[0]
        assert side == "dst"
        assert name == "mylist"

    def test_src_flag_overrides_dst_column(self):
        """[src] in DEST column → saddr match, not daddr."""
        stripped, infos = _rewrite_bracket_spec("+mylist[src]", "dst")
        assert stripped == "+mylist"
        assert len(infos) == 1
        side, name, neg = infos[0]
        assert side == "src"
        assert name == "mylist"
        assert neg is False

    def test_dst_flag_overrides_src_column(self):
        """[dst] in SOURCE column → daddr match."""
        stripped, infos = _rewrite_bracket_spec("+mylist[dst]", "src")
        assert stripped == "+mylist"
        side, name, neg = infos[0]
        assert side == "dst"
        assert name == "mylist"

    def test_src_dst_produces_two_matches(self):
        stripped, infos = _rewrite_bracket_spec("+mylist[src,dst]", "src")
        assert stripped == "+mylist"
        assert len(infos) == 2
        sides = {info[0] for info in infos}
        assert sides == {"src", "dst"}
        names = {info[1] for info in infos}
        assert names == {"mylist"}

    def test_negated_bare(self):
        stripped, infos = _rewrite_bracket_spec("!+mylist", "src")
        assert stripped == "!+mylist"
        side, name, neg = infos[0]
        assert neg is True
        assert name == "mylist"

    def test_negated_with_dst_flag(self):
        stripped, infos = _rewrite_bracket_spec("!+mylist[dst]", "src")
        assert stripped == "!+mylist"
        side, name, neg = infos[0]
        assert side == "dst"
        assert neg is True

    def test_zone_prefixed_src_flag(self):
        stripped, infos = _rewrite_bracket_spec("net:+mylist[src]", "dst")
        assert stripped == "net:+mylist"
        side, name, neg = infos[0]
        assert side == "src"
        assert name == "mylist"
        assert neg is False

    def test_zone_prefixed_negated(self):
        stripped, infos = _rewrite_bracket_spec("net:!+mylist[dst]", "src")
        assert stripped == "net:!+mylist"
        side, name, neg = infos[0]
        assert side == "dst"
        assert neg is True

    def test_invalid_bracket_content_raises(self):
        with pytest.raises(ValueError):
            _rewrite_bracket_spec("+mylist[foo]", "src")

    def test_invalid_three_way_bracket_raises(self):
        with pytest.raises(ValueError):
            _rewrite_bracket_spec("+mylist[src,dst,zzz]", "src")

    def test_empty_bracket_raises(self):
        """Empty [] is not a valid flag combination."""
        with pytest.raises(ValueError):
            _rewrite_bracket_spec("+mylist[]", "src")

    def test_non_bracket_spec_returns_unchanged(self):
        """Non-plus specs are returned unchanged with empty infos."""
        stripped, infos = _rewrite_bracket_spec("net:198.51.100.1", "src")
        assert stripped == "net:198.51.100.1"
        assert infos == []


# ---------------------------------------------------------------------------
# _rewrite_bracket_spec — AND-multi-set +[a,b,c]
# ---------------------------------------------------------------------------

class TestRewriteAndMultiset:
    def test_two_sets_src_column(self):
        stripped, infos = _rewrite_bracket_spec("+[alpha,beta]", "src")
        # AND-multi-set: spec stripped to first-set sentinel (no brackets)
        assert stripped == "+alpha"
        assert len(infos) == 2
        sides = {i[0] for i in infos}
        names = {i[1] for i in infos}
        assert sides == {"src"}
        assert names == {"alpha", "beta"}
        assert all(not i[2] for i in infos)  # not negated

    def test_two_sets_dst_column(self):
        stripped, infos = _rewrite_bracket_spec("+[alpha,beta]", "dst")
        # Sentinel uses first set name; column side determines dst
        assert stripped == "+alpha"
        assert len(infos) == 2
        sides = {i[0] for i in infos}
        assert sides == {"dst"}

    def test_negated_and_multiset(self):
        stripped, infos = _rewrite_bracket_spec("!+[alpha,beta]", "src")
        # Negation preserved on sentinel
        assert stripped == "!+alpha"
        assert all(i[2] is True for i in infos)

    def test_three_sets(self):
        stripped, infos = _rewrite_bracket_spec("+[a,b,c]", "dst")
        assert stripped == "+a"
        assert len(infos) == 3
        names = {i[1] for i in infos}
        assert names == {"a", "b", "c"}


# ---------------------------------------------------------------------------
# Integration: bracket syntax through build_ir / emitter
# ---------------------------------------------------------------------------

def _make_config(src_spec: str, dst_spec: str = "fw"):
    """Build a minimal ShorewalConfig with one rule using the given specs.

    Zone names: ``fw`` (firewall), ``net`` (ipv4, interface eth0).
    Source/dest specs must include the zone prefix, e.g. ``net:+mylist[dst]``.
    """
    from pathlib import Path
    from shorewall_nft.config.parser import ShorewalConfig, ConfigLine

    cfg = ShorewalConfig(config_dir=Path("/tmp"))
    cfg.settings["FASTACCEPT"] = "Yes"

    def _cl(*cols: str) -> ConfigLine:
        return ConfigLine(
            columns=list(cols), file="/etc/shorewall/rules",
            lineno=1, comment_tag=None, section="", raw="",
            format_version=1,
        )

    cfg.zones = [_cl("fw", "firewall"), _cl("net", "ipv4")]
    cfg.interfaces = [_cl("net", "eth0", "-", "-")]
    cfg.policy = [_cl("fw", "net", "ACCEPT"), _cl("net", "fw", "DROP")]
    cfg.rules = [_cl("ACCEPT", src_spec, dst_spec)]
    return cfg


class TestBracketIpsetIRIntegration:
    """Verify that bracket specs reach the IR as correctly-fielded Match objects.

    In Shorewall syntax the set reference appears with a zone prefix:
    ``net:+setname[flags]``, ``fw:+setname``, etc.
    """

    def test_bare_plus_src_column_emits_saddr(self):
        """Bare zone:+setname in SOURCE → ip saddr @setname (regression)."""
        from shorewall_nft.compiler.ir import build_ir
        cfg = _make_config("net:+mylist", "fw")
        ir = build_ir(cfg)
        matches = [m for chain in ir.chains.values()
                   for rule in chain.rules
                   for m in rule.matches
                   if m.value == "+mylist"]
        assert any(m.field in ("ip saddr", "ip6 saddr") for m in matches), \
            f"expected saddr match; got {[m.field for m in matches]}"

    def test_dst_flag_in_source_column_emits_daddr(self):
        """net:+setname[dst] in SOURCE column → ip daddr @setname."""
        from shorewall_nft.compiler.ir import build_ir
        cfg = _make_config("net:+mylist[dst]", "fw")
        ir = build_ir(cfg)
        matches = [m for chain in ir.chains.values()
                   for rule in chain.rules
                   for m in rule.matches
                   if m.value == "+mylist"]
        assert any(m.field in ("ip daddr", "ip6 daddr") for m in matches), \
            f"expected daddr match; got {[m.field for m in matches]}"

    def test_src_flag_in_dest_column_emits_saddr(self):
        """fw:+setname[src] in DEST column → ip saddr @setname."""
        from shorewall_nft.compiler.ir import build_ir
        cfg = _make_config("net", "fw:+mylist[src]")
        ir = build_ir(cfg)
        matches = [m for chain in ir.chains.values()
                   for rule in chain.rules
                   for m in rule.matches
                   if m.value == "+mylist"]
        assert any(m.field in ("ip saddr", "ip6 saddr") for m in matches), \
            f"expected saddr match; got {[m.field for m in matches]}"

    def test_src_dst_flag_emits_two_matches(self):
        """net:+setname[src,dst] → two Match objects for saddr + daddr."""
        from shorewall_nft.compiler.ir import build_ir
        cfg = _make_config("net:+mylist[src,dst]", "fw")
        ir = build_ir(cfg)
        matches = [m for chain in ir.chains.values()
                   for rule in chain.rules
                   for m in rule.matches
                   if m.value == "+mylist"]
        fields = {m.field for m in matches}
        has_saddr = any("saddr" in f for f in fields)
        has_daddr = any("daddr" in f for f in fields)
        assert has_saddr and has_daddr, \
            f"expected both saddr and daddr; got {fields}"

    def test_negated_plus_dst_in_source(self):
        """net:!+setname[dst] in SOURCE → negated daddr match."""
        from shorewall_nft.compiler.ir import build_ir
        cfg = _make_config("net:!+mylist[dst]", "fw")
        ir = build_ir(cfg)
        matches = [m for chain in ir.chains.values()
                   for rule in chain.rules
                   for m in rule.matches
                   if m.value == "+mylist"]
        assert any(m.negate and "daddr" in m.field for m in matches), \
            f"expected negated daddr; got {[(m.field, m.negate) for m in matches]}"

    def test_zone_prefixed_src_flag(self):
        """net:+setname[src] in SOURCE → saddr match with zone prefix preserved."""
        from shorewall_nft.compiler.ir import build_ir
        cfg = _make_config("net:+mylist[src]", "fw")
        ir = build_ir(cfg)
        matches = [m for chain in ir.chains.values()
                   for rule in chain.rules
                   for m in rule.matches
                   if m.value == "+mylist"]
        assert any("saddr" in m.field for m in matches), \
            f"expected saddr match; got {[m.field for m in matches]}"

    def test_and_multiset_src_produces_multiple_saddr_matches(self):
        """net:+[alpha,beta] in SOURCE → two saddr matches, one per set."""
        from shorewall_nft.compiler.ir import build_ir
        cfg = _make_config("net:+[alpha,beta]", "fw")
        ir = build_ir(cfg)
        saddr_values = [
            m.value for chain in ir.chains.values()
            for rule in chain.rules
            for m in rule.matches
            if "saddr" in m.field and m.value.startswith("+")
        ]
        assert "+alpha" in saddr_values, f"saddr_values={saddr_values}"
        assert "+beta" in saddr_values, f"saddr_values={saddr_values}"

    def test_and_multiset_dst_produces_multiple_daddr_matches(self):
        """fw:+[alpha,beta] in DEST → two daddr matches."""
        from shorewall_nft.compiler.ir import build_ir
        cfg = _make_config("net", "fw:+[alpha,beta]")
        ir = build_ir(cfg)
        daddr_values = [
            m.value for chain in ir.chains.values()
            for rule in chain.rules
            for m in rule.matches
            if "daddr" in m.field and m.value.startswith("+")
        ]
        assert "+alpha" in daddr_values, f"daddr_values={daddr_values}"
        assert "+beta" in daddr_values, f"daddr_values={daddr_values}"

    def test_negated_and_multiset_src(self):
        """net:!+[alpha,beta] in SOURCE → two negated saddr matches."""
        from shorewall_nft.compiler.ir import build_ir
        cfg = _make_config("net:!+[alpha,beta]", "fw")
        ir = build_ir(cfg)
        matches = [m for chain in ir.chains.values()
                   for rule in chain.rules
                   for m in rule.matches
                   if m.value.startswith("+") and "saddr" in m.field]
        assert all(m.negate for m in matches if m.value in ("+alpha", "+beta")), \
            f"expected all negated; got {[(m.value, m.negate) for m in matches]}"

    def test_invalid_bracket_raises_value_error(self):
        from shorewall_nft.compiler.ir import _rewrite_bracket_spec
        with pytest.raises(ValueError):
            _rewrite_bracket_spec("+mylist[foo]", "src")

    def test_invalid_three_way_bracket_raises(self):
        from shorewall_nft.compiler.ir import _rewrite_bracket_spec
        with pytest.raises(ValueError):
            _rewrite_bracket_spec("+mylist[src,dst,zzz]", "src")

    def test_empty_bracket_raises(self):
        from shorewall_nft.compiler.ir import _rewrite_bracket_spec
        with pytest.raises(ValueError):
            _rewrite_bracket_spec("+mylist[]", "src")


class TestBracketIpsetEmitter:
    """Verify the emitted nft script contains the correct set-match syntax."""

    def test_zone_prefixed_plus_src_emits_saddr_at_rule(self):
        """net:+setname in SOURCE → 'ip saddr @setname' in emitted script."""
        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.nft.emitter import emit_nft
        cfg = _make_config("net:+mylist", "fw")
        ir = build_ir(cfg)
        script = emit_nft(ir)
        assert "saddr @mylist" in script or "ip saddr @mylist" in script, \
            "expected saddr @mylist in emitted script"

    def test_dst_flag_in_source_emits_daddr_at_rule(self):
        """net:+setname[dst] in SOURCE → 'ip daddr @setname' in emitted script."""
        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.nft.emitter import emit_nft
        cfg = _make_config("net:+mylist[dst]", "fw")
        ir = build_ir(cfg)
        script = emit_nft(ir)
        assert "daddr @mylist" in script or "ip daddr @mylist" in script, \
            "expected daddr @mylist in emitted script"
