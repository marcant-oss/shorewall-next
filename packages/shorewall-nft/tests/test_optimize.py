"""Tests for the IR post-compile optimizer."""

from __future__ import annotations

from shorewall_nft.compiler.ir import Chain, FirewallIR, Match, Rule, Verdict
from shorewall_nft.compiler.optimize import (
    _combine_values,
    _find_combinable_field,
    _is_set_reference,
    optimize_chain_merge,
    optimize_combine_matches,
    optimize_duplicates,
    optimize_empty_chains,
    run_optimizations,
)

# ── helpers ──

def _ir_with_chains(**chains):
    ir = FirewallIR()
    for name, chain in chains.items():
        chain.name = name
        ir.chains[name] = chain
    return ir


def _rule(verdict=Verdict.ACCEPT, **matches):
    return Rule(
        verdict=verdict,
        matches=[Match(field=k.replace("_", " "), value=v)
                 for k, v in matches.items()],
    )


# ── _is_set_reference ──

class TestSetReference:
    def test_ipset(self):
        assert _is_set_reference("+BY-ipv4")
        assert _is_set_reference("@geoip")

    def test_plain(self):
        assert not _is_set_reference("1.1.1.1")
        assert not _is_set_reference("1.1.1.1, 2.2.2.2")
        assert not _is_set_reference("80-443")

    def test_list_with_set_ref(self):
        assert _is_set_reference("1.1.1.1, +ipset")


# ── _find_combinable_field ──

class TestCombinableField:
    def test_same_rule(self):
        r1 = _rule(ip_saddr="1.1.1.1", tcp_dport="80")
        r2 = _rule(ip_saddr="1.1.1.1", tcp_dport="80")
        # No difference — nothing to combine
        assert _find_combinable_field(r1, r2) is None

    def test_differ_in_saddr(self):
        r1 = _rule(ip_saddr="1.1.1.1", tcp_dport="80")
        r2 = _rule(ip_saddr="1.1.1.2", tcp_dport="80")
        assert _find_combinable_field(r1, r2) == "ip saddr"

    def test_differ_in_dport(self):
        r1 = _rule(ip_saddr="1.1.1.1", tcp_dport="80")
        r2 = _rule(ip_saddr="1.1.1.1", tcp_dport="443")
        assert _find_combinable_field(r1, r2) == "tcp dport"

    def test_differ_in_two_fields(self):
        r1 = _rule(ip_saddr="1.1.1.1", tcp_dport="80")
        r2 = _rule(ip_saddr="1.1.1.2", tcp_dport="443")
        assert _find_combinable_field(r1, r2) is None

    def test_different_verdict(self):
        r1 = _rule(Verdict.ACCEPT, ip_saddr="1.1.1.1")
        r2 = _rule(Verdict.DROP, ip_saddr="1.1.1.2")
        assert _find_combinable_field(r1, r2) is None

    def test_ipset_rejected(self):
        r1 = _rule(ip_saddr="+BY-ipv4")
        r2 = _rule(ip_saddr="+RU-ipv4")
        assert _find_combinable_field(r1, r2) is None

    def test_different_match_set(self):
        r1 = _rule(ip_saddr="1.1.1.1", tcp_dport="80")
        r2 = _rule(ip_saddr="1.1.1.1")  # missing tcp_dport
        assert _find_combinable_field(r1, r2) is None

    def test_non_combinable_field(self):
        # ct state is not in the combinable set
        r1 = _rule()
        r1.matches.append(Match(field="ct state", value="new"))
        r2 = _rule()
        r2.matches.append(Match(field="ct state", value="established"))
        assert _find_combinable_field(r1, r2) is None


# ── _combine_values ──

class TestCombineValues:
    def test_simple(self):
        assert _combine_values(["1.1.1.1", "2.2.2.2"]) == "1.1.1.1, 2.2.2.2"

    def test_dedup(self):
        assert _combine_values(["1.1.1.1", "1.1.1.1"]) == "1.1.1.1"

    def test_strip_braces(self):
        assert _combine_values(["{1.1.1.1, 2.2.2.2}", "3.3.3.3"]) == (
            "1.1.1.1, 2.2.2.2, 3.3.3.3")

    def test_ports(self):
        assert _combine_values(["80", "443", "8080"]) == "80, 443, 8080"


# ── optimize_duplicates ──

class TestDuplicates:
    def test_remove_exact_duplicates(self):
        chain = Chain(name="test", policy=Verdict.DROP)
        chain.rules = [
            _rule(ip_saddr="1.1.1.1"),
            _rule(ip_saddr="1.1.1.1"),
            _rule(ip_saddr="2.2.2.2"),
        ]
        ir = _ir_with_chains(test=chain)
        removed = optimize_duplicates(ir)
        assert removed == 1
        assert len(chain.rules) == 2

    def test_different_verdicts_not_duplicate(self):
        chain = Chain(name="test")
        chain.rules = [
            _rule(Verdict.ACCEPT, ip_saddr="1.1.1.1"),
            _rule(Verdict.DROP, ip_saddr="1.1.1.1"),
        ]
        ir = _ir_with_chains(test=chain)
        removed = optimize_duplicates(ir)
        assert removed == 0


# ── optimize_empty_chains ──

class TestEmptyChains:
    def test_remove_accept_policy_empty(self):
        chain = Chain(name="loc-dmz", policy=Verdict.ACCEPT)
        ir = _ir_with_chains(loc_dmz=chain)
        removed = optimize_empty_chains(ir)
        assert removed == 1
        assert "loc-dmz" not in ir.chains

    def test_keep_drop_policy_empty(self):
        """DROP-policy empty chains must NOT be removed — they still drop."""
        ir = FirewallIR()
        chain = Chain(name="net-loc", policy=Verdict.DROP)
        chain.rules = [Rule(verdict=Verdict.JUMP, verdict_args="sw_Drop")]
        ir.chains["net-loc"] = chain
        removed = optimize_empty_chains(ir)
        assert removed == 0
        assert "net-loc" in ir.chains

    def test_keep_chain_with_user_rules(self):
        chain = Chain(name="loc-dmz", policy=Verdict.ACCEPT)
        chain.rules = [_rule(Verdict.ACCEPT, ip_saddr="1.1.1.1")]
        ir = _ir_with_chains(loc_dmz=chain)
        removed = optimize_empty_chains(ir)
        assert removed == 0


# ── optimize_combine_matches ──

class TestCombineMatches:
    def test_combine_adjacent_saddr(self):
        chain = Chain(name="test")
        chain.rules = [
            _rule(ip_saddr="1.1.1.1", tcp_dport="80"),
            _rule(ip_saddr="2.2.2.2", tcp_dport="80"),
            _rule(ip_saddr="3.3.3.3", tcp_dport="80"),
        ]
        ir = _ir_with_chains(test=chain)
        removed = optimize_combine_matches(ir)
        assert removed == 2
        assert len(chain.rules) == 1
        combined = chain.rules[0]
        # Find the combined saddr match
        saddr = next(m for m in combined.matches if m.field == "ip saddr")
        assert "1.1.1.1" in saddr.value
        assert "2.2.2.2" in saddr.value
        assert "3.3.3.3" in saddr.value

    def test_combine_preserves_order_across_uncombinable(self):
        chain = Chain(name="test")
        chain.rules = [
            _rule(Verdict.ACCEPT, ip_saddr="1.1.1.1"),
            _rule(Verdict.ACCEPT, ip_saddr="2.2.2.2"),
            _rule(Verdict.DROP, ip_saddr="3.3.3.3"),
            _rule(Verdict.ACCEPT, ip_saddr="4.4.4.4"),
        ]
        ir = _ir_with_chains(test=chain)
        removed = optimize_combine_matches(ir)
        assert removed == 1
        # Order: [combined(1,2), drop(3), accept(4)]
        assert len(chain.rules) == 3
        assert chain.rules[0].verdict == Verdict.ACCEPT
        assert chain.rules[1].verdict == Verdict.DROP
        assert chain.rules[2].verdict == Verdict.ACCEPT

    def test_no_combine_two_diffs(self):
        chain = Chain(name="test")
        chain.rules = [
            _rule(ip_saddr="1.1.1.1", tcp_dport="80"),
            _rule(ip_saddr="2.2.2.2", tcp_dport="443"),
        ]
        ir = _ir_with_chains(test=chain)
        removed = optimize_combine_matches(ir)
        assert removed == 0

    def test_no_combine_ipset(self):
        chain = Chain(name="test")
        chain.rules = [
            _rule(Verdict.DROP, ip_saddr="+BY-ipv4"),
            _rule(Verdict.DROP, ip_saddr="+RU-ipv4"),
        ]
        ir = _ir_with_chains(test=chain)
        removed = optimize_combine_matches(ir)
        assert removed == 0


# ── optimize_chain_merge ──

class TestChainMerge:
    def test_merge_identical_chains(self):
        def make_chain(name):
            c = Chain(name=name, policy=Verdict.DROP)
            c.rules = [
                _rule(Verdict.ACCEPT, ip_saddr="1.1.1.1"),
                _rule(Verdict.ACCEPT, ip_saddr="2.2.2.2"),
            ]
            return c

        ir = FirewallIR()
        ir.chains["a-b"] = make_chain("a-b")
        ir.chains["a-c"] = make_chain("a-c")
        ir.chains["a-d"] = make_chain("a-d")

        merged = optimize_chain_merge(ir)
        # 2 of 3 redirected to canonical (a-b alphabetically first)
        assert merged == 2
        # Canonical keeps its rules
        assert len(ir.chains["a-b"].rules) == 2
        # Duplicates become a single jump to canonical
        assert len(ir.chains["a-c"].rules) == 1
        assert ir.chains["a-c"].rules[0].verdict == Verdict.JUMP
        assert ir.chains["a-c"].rules[0].verdict_args == "a-b"
        assert len(ir.chains["a-d"].rules) == 1
        assert ir.chains["a-d"].rules[0].verdict_args == "a-b"

    def test_different_chains_not_merged(self):
        ir = FirewallIR()
        a = Chain(name="a-b")
        a.rules = [_rule(ip_saddr="1.1.1.1")]
        b = Chain(name="a-c")
        b.rules = [_rule(ip_saddr="2.2.2.2")]
        ir.chains["a-b"] = a
        ir.chains["a-c"] = b

        merged = optimize_chain_merge(ir)
        assert merged == 0


# ── run_optimizations ──

class TestRunOptimizations:
    def test_level_0(self):
        ir = FirewallIR()
        results = run_optimizations(ir, 0)
        assert results == {}

    def test_level_2_runs_1_and_2(self):
        ir = FirewallIR()
        results = run_optimizations(ir, 2)
        assert "routefilter" in results
        assert "duplicates" in results
        assert "combine_matches" not in results

    def test_level_4_runs_up_to_4(self):
        ir = FirewallIR()
        results = run_optimizations(ir, 4)
        assert "combine_matches" in results
        assert "chain_merge" not in results

    def test_level_8_runs_everything(self):
        ir = FirewallIR()
        results = run_optimizations(ir, 8)
        assert "chain_merge" in results
