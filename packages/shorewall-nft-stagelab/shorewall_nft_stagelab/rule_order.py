"""Rule ordering analyser for nft rulesets.

Parses ``nft -a list ruleset`` output, groups commutative rules per chain,
sorts within each commutative group by counter.packets descending, and emits
a ``rule-order-hint.yaml`` artifact for a future compiler optimisation pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class RuleRef:
    """Identifies a single rule in the ruleset."""

    table: str        # e.g. "inet filter"
    chain: str        # e.g. "forward"
    handle: int       # nft rule handle number
    expression: str   # verbatim rule body, e.g. "tcp dport 443 accept"


@dataclass(frozen=True)
class RuleCounter:
    rule: RuleRef
    packets: int
    bytes: int


@dataclass(frozen=True)
class RuleGroup:
    """Consecutive commutative rules within a single chain.

    Rules are commutative iff the sole verdict is accept/drop (no NAT, mark,
    ct zone/set, goto, return, jump, masquerade), no ``ct state`` match, and
    their match expressions do not share a key+value token for the tracked
    fields (tcp/udp dport, ip/ip6 saddr/daddr).  Anything else → singleton.
    """

    chain: str
    rules: tuple[RuleRef, ...]


@dataclass(frozen=True)
class RuleOrderHint:
    """Per-chain reordered rule-handle sequence."""

    chain: str
    table: str
    original_order: tuple[int, ...]
    suggested_order: tuple[int, ...]
    group_count: int
    rationale: str


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_INLINE_CTR = re.compile(r"\bcounter\s+packets\s+(\d+)\s+bytes\s+(\d+)\b")
_HANDLE = re.compile(r"#\s+handle\s+(\d+)\s*$")
_TABLE = re.compile(r"^\s*table\s+(\S+\s+\S+)\s*\{?\s*$")
_CHAIN = re.compile(r"^\s*chain\s+(\S+)\s*\{?\s*$")
_TYPE_LINE = re.compile(r"^\s*type\s+")
_NON_COMMUTATIVE = re.compile(
    r"\b(goto|return|jump|masquerade|dnat|snat|redirect|mark\s+set"
    r"|ct\s+zone\s+set|ct\s+mark\s+set|tproxy|queue)\b",
    re.IGNORECASE,
)
_CT_STATE = re.compile(r"\bct\s+state\b", re.IGNORECASE)
_MATCH_KV = re.compile(
    r"\b(tcp\s+dport|udp\s+dport|ip\s+saddr|ip\s+daddr|ip6\s+saddr|ip6\s+daddr)"
    r"\s+(\S+)"
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_nft_ruleset_with_counters(body: str) -> list[RuleCounter]:
    """Parse ``nft -a list ruleset`` output; return one RuleCounter per rule.

    Supports inline counters (``counter packets N bytes M``).
    Rules without an inline counter get packets=0, bytes=0.
    Lines without a ``# handle N`` suffix are silently ignored.
    """
    counters: list[RuleCounter] = []
    current_table = ""
    current_chain = ""

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line == "}":
            continue

        t_match = _TABLE.match(raw_line)
        if t_match:
            current_table = t_match.group(1).strip()
            current_chain = ""
            continue

        c_match = _CHAIN.match(raw_line)
        if c_match:
            current_chain = c_match.group(1)
            continue

        if _TYPE_LINE.match(raw_line):
            continue

        h_match = _HANDLE.search(line)
        if not h_match:
            continue

        handle = int(h_match.group(1))
        expr = line[: h_match.start()].rstrip()

        ctr_match = _INLINE_CTR.search(expr)
        if ctr_match:
            pkts = int(ctr_match.group(1))
            byts = int(ctr_match.group(2))
            expr = (expr[: ctr_match.start()] + expr[ctr_match.end():]).strip()
        else:
            pkts = 0
            byts = 0

        ref = RuleRef(table=current_table, chain=current_chain,
                      handle=handle, expression=expr)
        counters.append(RuleCounter(rule=ref, packets=pkts, bytes=byts))

    return counters


# ---------------------------------------------------------------------------
# Commutativity helpers
# ---------------------------------------------------------------------------


def _is_singleton(expr: str) -> bool:
    return bool(_CT_STATE.search(expr) or _NON_COMMUTATIVE.search(expr))


def _match_kvs(expr: str) -> set[str]:
    return {f"{m.group(1)} {m.group(2)}" for m in _MATCH_KV.finditer(expr)}


def _rules_overlap(a: RuleRef, b: RuleRef) -> bool:
    return bool(_match_kvs(a.expression) & _match_kvs(b.expression))


def build_groups(rules: list[RuleRef]) -> list[RuleGroup]:
    """Group consecutive commutative rules per chain.

    Non-commutative rules (ct state, NAT, goto, return, …) become singletons.
    Commutative rules merge iff no key+value overlap with current accumulator.
    """
    if not rules:
        return []

    groups: list[RuleGroup] = []
    current_group: list[RuleRef] = []

    def _flush() -> None:
        if current_group:
            groups.append(RuleGroup(chain=current_group[0].chain,
                                    rules=tuple(current_group)))
            current_group.clear()

    for rule in rules:
        if _is_singleton(rule.expression):
            _flush()
            groups.append(RuleGroup(chain=rule.chain, rules=(rule,)))
            continue
        if any(_rules_overlap(rule, e) for e in current_group):
            _flush()
        current_group.append(rule)

    _flush()
    return groups


# ---------------------------------------------------------------------------
# Suggestion engine
# ---------------------------------------------------------------------------


def suggest_order(counters: list[RuleCounter]) -> list[RuleOrderHint]:
    """For each chain: sort within commutative groups by packets desc.

    Returns one RuleOrderHint per chain where suggested_order != original_order.
    """
    chain_rules: dict[tuple[str, str], list[RuleCounter]] = {}
    for rc in counters:
        chain_rules.setdefault((rc.rule.table, rc.rule.chain), []).append(rc)

    hints: list[RuleOrderHint] = []
    for (table, chain), chain_counters in chain_rules.items():
        refs = [rc.rule for rc in chain_counters]
        cmap: dict[int, int] = {rc.rule.handle: rc.packets for rc in chain_counters}
        groups = build_groups(refs)
        original_order = tuple(r.handle for r in refs)

        suggested: list[int] = []
        for grp in groups:
            if len(grp.rules) <= 1:
                suggested.extend(r.handle for r in grp.rules)
            else:
                suggested.extend(
                    sorted((r.handle for r in grp.rules),
                           key=lambda h: cmap.get(h, 0), reverse=True)
                )

        suggested_order = tuple(suggested)
        if suggested_order == original_order:
            continue

        reordered = sum(
            1 for grp in groups if len(grp.rules) > 1
            and tuple(sorted((r.handle for r in grp.rules),
                              key=lambda h: cmap.get(h, 0), reverse=True))
            != tuple(r.handle for r in grp.rules)
        )
        rationale = (
            f"reordered {reordered} group{'s' if reordered != 1 else ''}"
            " by counter packets desc"
        )
        hints.append(RuleOrderHint(
            chain=chain, table=table,
            original_order=original_order, suggested_order=suggested_order,
            group_count=len(groups), rationale=rationale,
        ))

    return hints


# ---------------------------------------------------------------------------
# YAML writer
# ---------------------------------------------------------------------------


def write_hint_yaml(hints: list[RuleOrderHint], path: Path) -> None:
    """Emit rule-order-hint.yaml.

    Shape::

        rule_order_hints:
          - chain: forward
            table: inet filter
            group_count: 3
            original_order: [10, 20, 30]
            suggested_order: [10, 30, 20]
            rationale: "reordered 1 group by counter packets desc"
    """
    payload = {
        "rule_order_hints": [
            {
                "chain": h.chain,
                "table": h.table,
                "group_count": h.group_count,
                "original_order": list(h.original_order),
                "suggested_order": list(h.suggested_order),
                "rationale": h.rationale,
            }
            for h in hints
        ]
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True))
