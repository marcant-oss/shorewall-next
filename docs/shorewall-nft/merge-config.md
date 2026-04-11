---
title: merge-config
description: Smart dual-stack merge of /etc/shorewall and /etc/shorewall6 into a unified /etc/shorewall46 config.
---

# merge-config

`shorewall-nft merge-config` combines a `shorewall` (IPv4) and a
`shorewall6` (IPv6) directory into a single unified config at
`/etc/shorewall46`. This becomes the **authoritative dual-stack
source** — shorewall-nft commands automatically prefer it over
`/etc/shorewall`.

## Usage

```bash
# Basic: merges /etc/shorewall + /etc/shorewall6 → /etc/shorewall46
shorewall-nft merge-config /etc/shorewall /etc/shorewall6

# Custom output directory
shorewall-nft merge-config /etc/shorewall /etc/shorewall6 -o /srv/firewall

# Guided mode: interactively resolve collisions
shorewall-nft merge-config /etc/shorewall /etc/shorewall6 --guided

# Disable plugin enrichment for this run
shorewall-nft merge-config /etc/shorewall /etc/shorewall6 --no-plugins
```

## What gets merged

| File | Strategy |
|------|----------|
| `zones` | All v4 zones kept; v6-only zones appended with type converted from `ipv6` to `-` (inet handles both) |
| `interfaces` | All v4 interfaces kept; v6-only interfaces appended |
| `policy` | v4 kept; v6-only (src, dst) pairs appended |
| `rules` | Smart merge by `?COMMENT` block — see below |
| `params` | v4 kept; v6 collisions renamed with `_V6` suffix (or grouped by plugin-detected pairs); transitive rewrites applied |
| `shorewall.conf` | v4 as base; v6-only settings appended |
| `masq`, `conntrack`, `notrack`, `blrules` | v4 + v6 merged by `?COMMENT` tag if present, otherwise appended |
| `macros/` | v4 + v6 macros combined; v6 entries appended to same-named macros |

## `?COMMENT` block merging

The `rules` file is merged **block by block**. Blocks with the same
`?COMMENT` tag (e.g. `?COMMENT mandant-b`) are combined — v4 rules
first, then v6 rules inserted before the closing `?COMMENT`:

Before (`/etc/shorewall/rules`):
```
?COMMENT mandant-b
ACCEPT    host:203.0.113.121    net
Web(ACCEPT)    all    host:203.0.113.121
?COMMENT
```

Before (`/etc/shorewall6/rules`):
```
?COMMENT mandant-b
ACCEPT    host:<2001:db8:0:100:217:14:168:121>    net
?COMMENT
```

After merge (`/etc/shorewall46/rules`):
```
?COMMENT mandant-b
ACCEPT    host:203.0.113.121    net
Web(ACCEPT)    all    host:203.0.113.121
?FAMILY ipv6
ACCEPT    host:<2001:db8:0:100:217:14:168:121>    net
?FAMILY any
?COMMENT
```

The `?FAMILY ipv6` / `?FAMILY any` wrap tells the shorewall-nft parser
to treat the enclosed rules as IPv6-origin, so the compiler emits
`meta nfproto ipv6` matches.

Blocks with the same tag in v4 and v6 are **merged**. Blocks only in
v4 stay as-is. Blocks only in v6 are appended at the end, under an
"IPv6-only mandants" heading, also wrapped in `?FAMILY ipv6`.

## v4↔v6 variable rewriting

When the same variable name is defined in both `params` files with
different values (e.g. `EXAMPLE_PFX=203.0.113.0/24` in v4 and
`EXAMPLE_PFX=2001:db8::/32` in v6), the merged params file keeps v4
as-is and renames v6 with a `_V6` suffix:

```
# merged params
EXAMPLE_PFX=203.0.113.0/24,198.51.100.0/21,198.51.100.128/24
...
# v4: EXAMPLE_PFX=203.0.113.0/24,198.51.100.0/21,198.51.100.128/24
EXAMPLE_PFX_V6=2001:db8::/32
```

All v6-originated rules that referenced `$EXAMPLE_PFX` are automatically
rewritten to `$EXAMPLE_PFX_V6`.

**Transitive rewrites**: if a third variable derives from a renamed
one, it is also renamed. Example:

```
# v4 and v6 both have (literally identical):
ALL_DC=$DC1,$DC2

# but DC1, DC2 differ between families:
# v4:  DC1=192.168.195.3, DC2=192.168.195.4
# v6:  DC1=2001:db8:0:400::3, DC2=2001:db8:0:400::6

# merged output:
DC1=192.168.195.3
DC2=192.168.195.4
ALL_DC=$DC1,$DC2
# --- DC1 (v4/v6 pair) ---
DC1_V6=2001:db8:0:400::3
# --- DC2 (v4/v6 pair) ---
DC2_V6=2001:db8:0:400::6
# --- ALL_DC (v6-transitive) ---
ALL_DC_V6=$DC1_V6,$DC2_V6
```

Any v6 rule referencing `$ALL_DC` in the source shorewall6/rules is
rewritten to `$ALL_DC_V6` in the merged output.

## Guided mode

With `--guided`, shorewall-nft prompts interactively at each collision:

```
╔══ Collision: Param $EXAMPLE_PFX
║ v4: EXAMPLE_PFX=203.0.113.0/24,198.51.100.0/21,198.51.100.128/24
║ v6: EXAMPLE_PFX=2001:db8::/32
║
║ Merge proposal:
║   # v4: EXAMPLE_PFX=203.0.113.0/24,...
║   EXAMPLE_PFX_V6=2001:db8::/32
╚══

    [1] Keep v4 only
    [2] Keep v6 only
    [3] Use merge proposal
    [4] Enter custom value
  Choice [3]:
```

Applies to params, zones, policies, shorewall.conf settings, and
`?COMMENT` blocks. Default (Enter) is always `[3]` (the auto-merge
proposal).

## Plugin enrichment

If `plugins.conf` exists in the v4 source directory, loaded plugins
add metadata during the merge:

- **ip-info**: detects v4/v6 pairs via subnet pattern, adds comments
  listing pattern-derived mappings inside each mandant block
- **netbox**: detects pairs via shared `dns_name`, groups customer
  info, adds annotated pair comments

See [plugins](plugins.md) for details. Disable with `--no-plugins`.

## `/etc/shorewall46` precedence

Once `/etc/shorewall46` exists, **all shorewall-nft commands default
to it** instead of `/etc/shorewall`. Override with an explicit directory
argument:

```bash
# Uses /etc/shorewall46 automatically
shorewall-nft start

# Force the legacy layout
shorewall-nft start /etc/shorewall

# Or set a completely different path
shorewall-nft start /srv/firewall
```

Inside a loaded `/etc/shorewall46`, the parser **does not** auto-detect
a sibling `/etc/shorewall466`. The merged config is self-contained.

## Why this matters

Upstream Shorewall keeps v4 and v6 as separate installations
(`shorewall`, `shorewall6`) and compiles them to separate iptables and
ip6tables rulesets. shorewall-nft emits a single `inet` table for both
families, so merging at config time saves a redundant parse+compile
cycle and gives you one place to manage dual-stack rules.

The result: **identical semantic output** compared to compiling
`/etc/shorewall` with auto-detected `/etc/shorewall6`, but:

- No duplicated zone/interface/policy definitions
- Mandant `?COMMENT` blocks show v4 and v6 side-by-side
- Paired params are explicitly grouped
- Plugin metadata is embedded inline
