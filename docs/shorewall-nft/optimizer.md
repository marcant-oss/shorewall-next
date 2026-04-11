---
title: Optimizer
description: Post-compile IR optimization passes that shrink the emitted nftables ruleset.
---

# Optimizer

shorewall-nft applies post-compile optimization passes to the
intermediate representation (IR) before emitting the nft script. Set
`OPTIMIZE=N` in `shorewall.conf` to enable them.

## Levels

Higher levels imply all lower levels.

| Level | Name | Description |
|-------|------|-------------|
| 0 | (none) | No optimization (default) |
| 1 | Routefilter | Drop rules unreachable via kernel `rp_filter` (heuristic: if a zone has `routefilter` and a source address doesn't overlap with any other addr used in that zone, the kernel would drop it anyway) |
| 2 | Duplicates | Remove exact-duplicate rules within a chain (match set, verdict, flags) |
| 3 | Empty chains | Remove ACCEPT-policy zone-pair chains that have no user rules — their dispatch is regenerated from the IR, so removing the chain automatically removes the jump. DROP-policy empties are kept because removing them would silently open the firewall. |
| 4 | Combine matches | Merge adjacent rules that differ in exactly one match field (saddr/daddr/sport/dport/iifname/oifname) into a single rule with an anonymous set |
| 8 | Chain merge | Detect chains with identical content, keep the alphabetically first as canonical, replace the others with a single `jump canonical` stub |

Levels 5-7 and 9+ are not implemented — they correspond to Shorewall
upstream's iptables-specific optimizations that have no nft analog.

## Real-world reduction

Measured on production configs (lines of emitted nft script):

| Config | OPTIMIZE=0 | OPTIMIZE=8 | Reduction |
|--------|------------|------------|-----------|
| fw-large | 18366 | 12806 | **30%** |
| fw-medium | 12075 | 7598 | **37%** |
| fw-small | 625 | 546 | **12%** |

## Example: Level 4 (combine matches)

Before:
```
ip saddr 1.1.1.1 tcp dport 80 accept
ip saddr 1.1.1.2 tcp dport 80 accept
ip saddr 1.1.1.3 tcp dport 80 accept
```

After:
```
ip saddr { 1.1.1.1, 1.1.1.2, 1.1.1.3 } tcp dport 80 accept
```

Only adjacent rules with identical non-match attributes (verdict,
log_prefix, rate_limit, connlimit, time_match, user_match, mark_match,
counter) are combined. Reordering is never applied.

## Example: Level 8 (chain merge)

When two zone-pair chains have byte-identical content (same rules, same
policy), shorewall-nft keeps one canonical copy and replaces the others
with a jump stub:

```
chain brs-alpha {        # canonical
    # ... 9 rules ...
}
chain mgmt-alpha {
    jump brs-alpha       # merged: identical to brs-alpha
}
```

Dispatch jumps from base chains still work because the stub chain
remains valid; the stub just defers to the canonical implementation.

## Excluded from combine

Level 4 does not combine match values that contain:

- Shorewall ipset references (`+BY-ipv4`)
- nft named set references (`@geoip`)
- Values with mismatched negation (`ip saddr 1.1.1.1` vs `! ip saddr 2.2.2.2`)

These would produce invalid nft syntax when placed inside an anonymous
set `{ ... }`.

## Semantic safety

All optimizations preserve semantics by construction:

- **Level 2** removes only byte-identical rules
- **Level 3** only removes ACCEPT-policy empties (base chain default is
  accept, so falling through is equivalent)
- **Level 4** combines with anonymous sets, which match the union of
  their elements — same as sequential rules with different values
- **Level 8** redirects jumps to a byte-identical canonical chain

No rule reordering is ever applied.

## Interaction with debug mode

Optimizer and debug mode are independent. Running with `OPTIMIZE=8`
and `shorewall-nft debug` emits a debug-annotated **optimized** ruleset
— the named counters and source comments are attached to the combined
rules, so a single debug counter may cover multiple original source
lines. The comment references the first source line in the combined
group.
