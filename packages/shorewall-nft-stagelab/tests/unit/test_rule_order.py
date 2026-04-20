"""Unit tests for rule_order.py — exactly 6 tests."""

from __future__ import annotations

from pathlib import Path

import yaml

from shorewall_nft_stagelab.rule_order import (
    RuleRef,
    build_groups,
    parse_nft_ruleset_with_counters,
    suggest_order,
    write_hint_yaml,
)

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "nft_ruleset_sample.txt"


# ---------------------------------------------------------------------------
# 1. Parse fixture yields expected counters
# ---------------------------------------------------------------------------


def test_parse_fixture_yields_expected_counters():
    body = FIXTURE_PATH.read_text()
    counters = parse_nft_ruleset_with_counters(body)

    # input: 5 rules, forward: 8 rules, postrouting: 1 rule = 14 total
    assert len(counters) == 14

    # All in expected chains
    chains = {rc.rule.chain for rc in counters}
    assert chains == {"input", "forward", "postrouting"}

    # Spot-check handles and packets
    by_handle = {rc.rule.handle: rc for rc in counters}
    assert by_handle[12].packets == 20000
    assert by_handle[13].packets == 5000
    assert by_handle[14].packets == 300
    assert by_handle[50].packets == 0   # masquerade rule has no inline counter
    assert by_handle[1].rule.table == "inet filter"
    assert by_handle[50].rule.table == "ip nat"


# ---------------------------------------------------------------------------
# 2. ct state rules become singleton groups
# ---------------------------------------------------------------------------


def test_groups_singleton_for_ct_state():
    rules = [
        RuleRef("inet filter", "forward", 10, "ct state established,related accept"),
        RuleRef("inet filter", "forward", 11, "ct state invalid drop"),
        RuleRef("inet filter", "forward", 12, "tcp dport 443 accept"),
    ]
    groups = build_groups(rules)

    # handles 10 and 11 each in their own singleton group
    singleton_handles = {grp.rules[0].handle for grp in groups if len(grp.rules) == 1}
    assert 10 in singleton_handles
    assert 11 in singleton_handles

    # handle 12 forms its own group (only one rule left)
    all_handles = [h for grp in groups for r in grp.rules for h in [r.handle]]
    assert all_handles.count(12) == 1


# ---------------------------------------------------------------------------
# 3. Distinct-dport accept rules merge into one commutative group
# ---------------------------------------------------------------------------


def test_groups_merge_port_based_accepts():
    rules = [
        RuleRef("inet filter", "forward", 12, "tcp dport 443 accept"),
        RuleRef("inet filter", "forward", 13, "tcp dport 80 accept"),
        RuleRef("inet filter", "forward", 14, "tcp dport 53 accept"),
    ]
    groups = build_groups(rules)

    # All three should form a single commutative group
    assert len(groups) == 1
    assert len(groups[0].rules) == 3
    handles = {r.handle for r in groups[0].rules}
    assert handles == {12, 13, 14}


# ---------------------------------------------------------------------------
# 4. suggest_order sorts within commutative group by packets desc
# ---------------------------------------------------------------------------


def test_suggest_order_sorts_within_group_desc():
    # Extract only forward chain from the fixture for clarity
    body = FIXTURE_PATH.read_text()
    all_counters = parse_nft_ruleset_with_counters(body)
    fwd = [rc for rc in all_counters if rc.rule.chain == "forward"]

    hints = suggest_order(fwd)
    assert hints, "Expected at least one hint for forward chain"

    hint = hints[0]
    # The tcp/udp dport rules (handles 12,13,14,15,16) form a commutative group.
    # Within that group the order should be descending by packets:
    # 12 (20000) > 13 (5000) > 15 (800) > 14 (300) > 16 (50)
    expected_group_order = [12, 13, 15, 14, 16]
    # Find the slice in suggested_order corresponding to these handles
    sugg = list(hint.suggested_order)
    group_positions = [sugg.index(h) for h in expected_group_order]
    # They must appear in strictly increasing index order
    assert group_positions == sorted(group_positions), (
        f"Expected {expected_group_order} in order within {sugg}"
    )


# ---------------------------------------------------------------------------
# 5. ct state established,related stays at chain head (singleton)
# ---------------------------------------------------------------------------


def test_suggest_order_preserves_singletons():
    body = FIXTURE_PATH.read_text()
    all_counters = parse_nft_ruleset_with_counters(body)
    fwd = [rc for rc in all_counters if rc.rule.chain == "forward"]

    hints = suggest_order(fwd)
    assert hints
    hint = hints[0]

    # handle 10 (ct state established,related) must be first
    assert hint.suggested_order[0] == 10, (
        f"ct state rule (handle 10) must stay first, got {hint.suggested_order}"
    )
    # handle 11 (ct state invalid) must be second
    assert hint.suggested_order[1] == 11


# ---------------------------------------------------------------------------
# 6. write_hint_yaml roundtrip
# ---------------------------------------------------------------------------


def test_write_hint_yaml_roundtrip(tmp_path: Path):
    body = FIXTURE_PATH.read_text()
    counters = parse_nft_ruleset_with_counters(body)
    hints = suggest_order(counters)
    assert hints, "Fixture must produce at least one hint"

    out = tmp_path / "rule-order-hint.yaml"
    write_hint_yaml(hints, out)

    loaded = yaml.safe_load(out.read_text())
    assert "rule_order_hints" in loaded
    entries = loaded["rule_order_hints"]
    assert isinstance(entries, list)
    assert len(entries) == len(hints)

    for entry in entries:
        assert "chain" in entry
        assert "table" in entry
        assert "group_count" in entry
        assert "original_order" in entry
        assert "suggested_order" in entry
        assert "rationale" in entry
        assert isinstance(entry["original_order"], list)
        assert isinstance(entry["suggested_order"], list)
        assert len(entry["original_order"]) == len(entry["suggested_order"])
