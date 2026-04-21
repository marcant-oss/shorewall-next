# Classic ipsets syntax in shorewall-nft

shorewall-nft does **not** use the legacy `ipset` kernel module. Named sets
are nft-native, declared either via the `nfsets` config file (preferred,
declarative) or loaded externally via `shorewall-nft load-sets` (for
ip-list providers). This page documents the classic `+setname` syntax that
shorewall-nft accepts for compatibility with existing configurations.

---

## Syntax reference

All forms below are accepted in any rule-file column that holds a host or
network address (SOURCE, DEST, and address-list columns in `rules`,
`blrules`, `stoppedrules`, `masq`, `notrack`, `tcrules`, etc.).

| Syntax | Semantics |
|--------|-----------|
| `+setname` | Match packets whose address is in the nft set `setname`. Match side (src/dst) inferred from column context. |
| `!+setname` | Negative match — address is NOT in `setname`. |
| `+setname[src]` | Force source-address match regardless of column. |
| `+setname[dst]` | Force destination-address match regardless of column. |
| `+setname[src,dst]` | Match both source and destination addresses against `setname`. |
| `+[set1,set2]` | AND-multi-set: packet must match **all** listed sets. (Different from nfsets comma syntax, which is OR-clone.) |

Bracket flags and negation compose: `!+setname[dst]`, `net:+setname[src]`,
`zone:!+setname[src,dst]` are all valid.

Set name rules (inherited from upstream Shorewall):
- Must begin with a letter (after the `+`).
- Composed of letters, digits, dashes (`-`), or underscores (`_`).

---

## How shorewall-nft resolves `+setname`

shorewall-nft maps `+setname` to the nft set `setname` in the compiled
`table inet shorewall`. No `ipset` kernel module is involved. The set must
exist at apply time — shorewall-nft emits a set reference, not a set
declaration. Use `nfsets` to declare sets declaratively, or
`shorewall-nft load-sets` to populate sets from external sources.
When libnftables' native JSON API is available, bulk element loads skip the
nft text parser entirely, making large set population (tens of thousands of
prefixes) significantly faster.

---

## Migration

| Classic pattern | shorewall-nft equivalent | Notes |
|-----------------|--------------------------|-------|
| `+Mirrors[src]` | `+Mirrors[src]` | Works unchanged. shorewall-nft emits `ip saddr @Mirrors`. |
| `+DYNAMIC_BLACKLIST` | `shorewall-nft blacklist add <ip>` | Use the blacklist command; the set is managed internally. |
| `+[trust,vpn]` | `+[trust,vpn]` | AND-multi-set works unchanged. |
| Large static set via `ipset create` | Declare in `nfsets` with `ip-list-plain` backend | Preferred for URL/file-sourced lists. |
| DNS-driven ipset | Declare in `nfsets` with `resolver` or `dnstap` backend | Replace with `dnst:hostname` inline or named nfset. |
| `SAVE_IPSETS=Yes` in `shorewall.conf` | Not applicable | shorewall-nft manages nft-native sets; no ipset save/restore. |

### Transition from inline `dns:` to `dnst:`

If your rules use `dns:hostname` inline syntax, migrate to `dnst:hostname`.
Both are accepted; `dns:` emits a deprecation warning at compile time:

```
# old (deprecated — emits WARNING)
ACCEPT   fw   net:dns:updates.example.org   tcp   443

# new (preferred)
ACCEPT   fw   net:dnst:updates.example.org  tcp   443
```

For sets with multiple hostnames or non-DNS backends, switch to a named
`nfsets` entry and reference it with `nfset:name`.

---

## Cross-links

- [`docs/features/nfsets.md`](nfsets.md) — declarative named set configuration
- `shorewall-nft-nfsets(5)` — man page for the `nfsets` config file
- `shorewall-nft-rules(5)` — bracket syntax reference and `dnst:` token documentation
- [Dynamic zones](Dynamic.md) — ipset-backed dynamic zones (legacy Shorewall feature)
