"""Post-compile optimization of the firewall IR.

Implements Shorewall-style OPTIMIZE levels:

- Level 1: Remove rules with unreachable source addresses (routefilter heuristic)
- Level 2: Eliminate exact-duplicate rules within chains
- Level 3: Remove truly no-op chains (ACCEPT-policy chains without user rules)
- Level 4: Combine adjacent rules differing only in source/dest/port into
           a single rule with an anonymous set
- Level 8: Merge chains with identical content, redirecting jumps to the
           canonical copy (cross-chain dedup)

Higher levels imply all lower levels. Dispatch jumps are regenerated on
every emit pass by the emitter iterating over ir.chains, so removing a
chain from the IR automatically removes its dispatch jump — no cleanup
needed for that mechanism.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from shorewall_nft.compiler.ir import FirewallIR, Match, Rule, Verdict

# ── Level 1: Routefilter heuristic ─────────────────────────────────────

def optimize_unreachable_sources(ir: FirewallIR) -> int:
    """Remove rules where the source address is unreachable via the source zone.

    When source=all:ADDR expands, it creates rules in ALL zone-pair chains.
    For zones with routefilter, addresses not belonging to the zone's address
    space would be dropped by the kernel's rp_filter anyway — we can drop them
    at compile time.

    We infer each zone's address space from source addresses that are actually
    used in rules coming OUT of that zone.
    """
    zone_prefixes: dict[str, set[str]] = defaultdict(set)

    for chain_name, chain in ir.chains.items():
        if chain.is_base_chain or chain_name.startswith("sw_"):
            continue
        parts = chain_name.split("-", 1)
        if len(parts) != 2:
            continue
        src_zone = parts[0]

        for rule in chain.rules:
            for match in rule.matches:
                if match.field == "ip saddr" and match.value:
                    for addr in match.value.split(","):
                        addr = addr.strip()
                        if addr and not addr.startswith("+") and "/" in addr:
                            try:
                                net = ipaddress.ip_network(addr, strict=False)
                                zone_prefixes[src_zone].add(str(net))
                            except ValueError:
                                pass

    routefilter_zones: set[str] = set()
    for zone_name, zone in ir.zones.zones.items():
        for iface in zone.interfaces:
            if any("routefilter" in opt for opt in iface.options):
                routefilter_zones.add(zone_name)
                break

    removed = 0
    for chain_name, chain in list(ir.chains.items()):
        if chain.is_base_chain or chain_name.startswith("sw_"):
            continue
        parts = chain_name.split("-", 1)
        if len(parts) != 2:
            continue
        src_zone = parts[0]

        if src_zone not in routefilter_zones:
            continue
        if src_zone == ir.zones.firewall_zone:
            continue

        src_known = zone_prefixes.get(src_zone, set())
        if not src_known:
            continue

        new_rules = []
        for rule in chain.rules:
            keep = True
            for match in rule.matches:
                if match.field == "ip saddr" and match.value:
                    addrs = [a.strip() for a in match.value.split(",")]
                    all_unreachable = True
                    for addr in addrs:
                        if addr.startswith("+") or "/" not in addr:
                            all_unreachable = False
                            break
                        try:
                            src_net = ipaddress.ip_network(addr, strict=False)
                            reachable = False
                            for known_str in src_known:
                                try:
                                    known_net = ipaddress.ip_network(
                                        known_str, strict=False)
                                    if src_net.overlaps(known_net):
                                        reachable = True
                                        break
                                except ValueError:
                                    continue
                            if reachable:
                                all_unreachable = False
                                break
                        except ValueError:
                            all_unreachable = False
                            break
                    if all_unreachable and addrs:
                        keep = False
                        break

            if keep:
                new_rules.append(rule)
            else:
                removed += 1

        chain.rules = new_rules

    return removed


# ── Level 2: Exact-duplicate elimination ───────────────────────────────

def _rule_key(rule: Rule) -> tuple:
    """Return a hashable key uniquely identifying a rule for duplicate detection."""
    return (
        tuple((m.field, m.value, m.negate) for m in rule.matches),
        rule.verdict,
        rule.verdict_args,
        rule.log_prefix,
        rule.rate_limit,
        rule.connlimit,
        rule.time_match,
        rule.user_match,
        rule.mark_match,
        rule.counter,
    )


def optimize_duplicates(ir: FirewallIR) -> int:
    """Remove exact-duplicate rules within each chain (order preserved)."""
    removed = 0
    for chain in ir.chains.values():
        if chain.is_base_chain:
            continue
        seen: set[tuple] = set()
        new_rules = []
        for rule in chain.rules:
            key = _rule_key(rule)
            if key in seen:
                removed += 1
                continue
            seen.add(key)
            new_rules.append(rule)
        chain.rules = new_rules
    return removed


# ── Level 3: Remove no-op chains ───────────────────────────────────────

def optimize_empty_chains(ir: FirewallIR) -> int:
    """Remove zone-pair chains that are effectively no-ops.

    A chain is a no-op if:
    - It has no user rules AND
    - Its policy is ACCEPT (or no policy → ACCEPT by default)

    DROP/REJECT chains with no user rules are KEPT because removing them
    would let traffic fall through to the base chain's default (ACCEPT),
    which silently opens the firewall.

    When a chain is removed from ir.chains, the emitter will automatically
    skip its dispatch rule on the next emit pass — no jump cleanup needed.
    """
    removed = 0
    sw_action_prefixes = ("sw_Drop", "sw_Reject", "sw_Broadcast")

    for name, chain in list(ir.chains.items()):
        if chain.is_base_chain or name.startswith("sw_"):
            continue

        # Count rules that are NOT the default-action jump
        user_rules = [
            r for r in chain.rules
            if not (r.verdict == Verdict.JUMP
                    and r.verdict_args
                    and any(r.verdict_args.startswith(p)
                            for p in sw_action_prefixes))
        ]
        if user_rules:
            continue

        # Only remove ACCEPT-policy chains — removing DROP chains would
        # silently open the firewall.
        policy = chain.policy or Verdict.ACCEPT
        if policy != Verdict.ACCEPT:
            continue

        del ir.chains[name]
        removed += 1

    return removed


# ── Level 4: Combine adjacent rules with anonymous sets ────────────────

_COMBINABLE_FIELDS = frozenset({
    "ip saddr", "ip daddr",
    "ip6 saddr", "ip6 daddr",
    "tcp dport", "tcp sport",
    "udp dport", "udp sport",
    "iifname", "oifname",
})


def _rule_meta_key(rule: Rule) -> tuple:
    """Signature of a rule's non-match attributes."""
    return (
        rule.verdict,
        rule.verdict_args,
        rule.log_prefix,
        rule.rate_limit,
        rule.connlimit,
        rule.time_match,
        rule.user_match,
        rule.mark_match,
        rule.counter,
    )


def _rule_matches_except(rule: Rule, exclude_field: str) -> tuple:
    """All matches of a rule except for one field (for grouping)."""
    return tuple(
        (m.field, m.value, m.negate)
        for m in rule.matches
        if m.field != exclude_field
    )


def _is_set_reference(value: str) -> bool:
    """Check if a match value contains a set reference.

    Shorewall ipset references start with '+' (e.g. '+BY-ipv4').
    nft set references start with '@'.
    Anonymous sets wrapped in '{}' are also not directly combinable
    because their contents may include set references.
    """
    v = value.strip()
    if not v:
        return False
    # Single set reference
    if v.startswith("+") or v.startswith("@"):
        return True
    # Comma-separated list containing any set reference
    for item in v.split(","):
        item = item.strip()
        if item.startswith("+") or item.startswith("@"):
            return True
    return False


def _find_combinable_field(r1: Rule, r2: Rule) -> str | None:
    """Return the single field name if r1 and r2 differ in exactly one combinable match.

    Returns None if they differ in more than one field, in non-combinable
    fields, in negation state, in non-match attributes, or if either value
    contains an ipset/named-set reference.
    """
    if _rule_meta_key(r1) != _rule_meta_key(r2):
        return None

    def matches_map(rule: Rule) -> dict[str, tuple[str, bool]]:
        return {m.field: (m.value, m.negate) for m in rule.matches}

    m1 = matches_map(r1)
    m2 = matches_map(r2)

    if set(m1.keys()) != set(m2.keys()):
        return None

    diff_fields = [f for f in m1 if m1[f] != m2[f]]
    if len(diff_fields) != 1:
        return None

    f = diff_fields[0]
    if f not in _COMBINABLE_FIELDS:
        return None

    if m1[f][1] != m2[f][1]:
        return None

    # Reject set-reference values — nft anonymous sets cannot contain
    # named-set references like @set1 or +ipset.
    if _is_set_reference(m1[f][0]) or _is_set_reference(m2[f][0]):
        return None

    return f


def _combine_values(values: list[str]) -> str:
    """Merge a list of match values into a single anonymous set expression.

    Each input value may itself be a comma-separated list or set.
    The result is a flat comma-separated list suitable for `{ ... }`.
    """
    parts: list[str] = []
    seen: set[str] = set()
    for val in values:
        # Strip any existing braces
        v = val.strip()
        if v.startswith("{") and v.endswith("}"):
            v = v[1:-1]
        for item in v.split(","):
            item = item.strip()
            if item and item not in seen:
                seen.add(item)
                parts.append(item)
    return ", ".join(parts)


def _make_combined_rule(group: list[Rule], field: str) -> Rule:
    """Build a single rule that combines a group of adjacent rules.

    `group` is a list of rules that all differ only in `field`.
    The combined rule uses an anonymous set for that field.
    """
    base = group[0]
    values = []
    for r in group:
        for m in r.matches:
            if m.field == field:
                values.append(m.value)
                break

    combined_value = _combine_values(values)

    new_matches = []
    for m in base.matches:
        if m.field == field:
            new_matches.append(Match(
                field=field,
                value=f"{{ {combined_value} }}",
                negate=m.negate,
            ))
        else:
            new_matches.append(Match(field=m.field, value=m.value, negate=m.negate))

    return Rule(
        matches=new_matches,
        verdict=base.verdict,
        verdict_args=base.verdict_args,
        comment=base.comment,
        counter=base.counter,
        log_prefix=base.log_prefix,
        rate_limit=base.rate_limit,
        connlimit=base.connlimit,
        time_match=base.time_match,
        user_match=base.user_match,
        mark_match=base.mark_match,
        source_file=base.source_file,
        source_line=base.source_line,
    )


def optimize_combine_matches(ir: FirewallIR) -> int:
    """Combine adjacent rules that differ only in one combinable match field.

    Example: three separate rules:
        ip saddr 1.1.1.1 tcp dport 80 accept
        ip saddr 1.1.1.2 tcp dport 80 accept
        ip saddr 1.1.1.3 tcp dport 80 accept
    become:
        ip saddr { 1.1.1.1, 1.1.1.2, 1.1.1.3 } tcp dport 80 accept

    Only adjacent rules are considered (no reordering) to preserve semantics.
    """
    removed = 0

    for chain in ir.chains.values():
        if chain.is_base_chain:
            continue
        if not chain.rules:
            continue

        new_rules: list[Rule] = []
        i = 0
        while i < len(chain.rules):
            cur = chain.rules[i]
            group = [cur]
            combine_field: str | None = None

            j = i + 1
            while j < len(chain.rules):
                candidate = chain.rules[j]
                # Probe the field from the first pair; subsequent rules must
                # match the same field.
                if combine_field is None:
                    field = _find_combinable_field(cur, candidate)
                    if field is None:
                        break
                    combine_field = field
                    group.append(candidate)
                else:
                    # Check candidate against the group's first rule on the
                    # SAME field only
                    field = _find_combinable_field(cur, candidate)
                    if field != combine_field:
                        break
                    group.append(candidate)
                j += 1

            if len(group) > 1 and combine_field is not None:
                combined = _make_combined_rule(group, combine_field)
                new_rules.append(combined)
                removed += len(group) - 1
                i = j
            else:
                new_rules.append(cur)
                i += 1

        chain.rules = new_rules

    return removed


# ── Level 8: Merge identical chains ────────────────────────────────────

def _chain_fingerprint(chain) -> tuple:
    """Structural fingerprint of a chain's rules for identity matching."""
    return (
        chain.policy,
        tuple(_rule_key(r) for r in chain.rules),
    )


def optimize_chain_merge(ir: FirewallIR) -> int:
    """Merge non-base chains with identical content.

    When two or more zone-pair chains have exactly the same rules and policy,
    keep only one (the alphabetically first) and redirect jumps from the
    others to the canonical copy. The dropped chains are removed from the IR;
    the emitter will still dispatch for their zone pairs by using the
    alphabetical-first chain name.

    Note: this optimization changes the dispatch target for some zone pairs.
    Because the base chain's dispatch emitter iterates chains by name and
    emits a jump per zone pair, removing a chain would skip its dispatch.
    We work around this by NOT removing the duplicate chains — instead, we
    replace their rule list with a single `jump canonical` rule.
    """
    by_fp: dict[tuple, list[str]] = defaultdict(list)
    for name, chain in ir.chains.items():
        if chain.is_base_chain or name.startswith("sw_"):
            continue
        # Ignore empty chains (handled by level 3)
        if not chain.rules and chain.policy is None:
            continue
        fp = _chain_fingerprint(chain)
        by_fp[fp].append(name)

    merged = 0
    for names in by_fp.values():
        if len(names) < 2:
            continue
        # Pick the canonical (alphabetically first)
        canonical = sorted(names)[0]
        for dup in names:
            if dup == canonical:
                continue
            chain = ir.chains[dup]
            # Replace with a single jump → canonical
            chain.rules = [Rule(
                verdict=Verdict.JUMP,
                verdict_args=canonical,
                comment=f"merged: identical to {canonical}",
            )]
            # Drop the policy since the jump handles it
            chain.policy = None
            merged += 1
    return merged


# ── Orchestration ──────────────────────────────────────────────────────

def run_optimizations(ir: FirewallIR, level: int) -> dict[str, int]:
    """Run all optimizations up to the given level.

    Returns a dict of optimization name → count of changes.
    """
    results: dict[str, int] = {}

    if level >= 1:
        results["routefilter"] = optimize_unreachable_sources(ir)

    if level >= 2:
        results["duplicates"] = optimize_duplicates(ir)

    if level >= 3:
        results["empty_chains"] = optimize_empty_chains(ir)

    if level >= 4:
        results["combine_matches"] = optimize_combine_matches(ir)

    if level >= 8:
        results["chain_merge"] = optimize_chain_merge(ir)

    return results
