---
title: Config directory resolution
description: How shorewall-nft picks its configuration source, and all the ways you can override it from the CLI.
---

# Config directory resolution

`shorewall-nft` supports **six distinct modes** for locating its
configuration source. All 13 commands that take a config directory
(`start`, `restart`, `reload`, `check`, `compile`, `verify`, `debug`,
`migrate`, `simulate`, `load-sets`, `generate-set-loader`,
`generate-sysctl`, `generate-tc`) accept the same override flags.

## The 6 modes at a glance

| # | Mode | CLI | Result |
|---|------|-----|--------|
| 1 | Default auto | `shorewall-nft start` | `/etc/shorewall46` if present, else `/etc/shorewall` + sibling |
| 2 | Explicit merged | `shorewall-nft start -c /srv/merged` | Single merged dir, no sibling merge |
| 3 | Legacy dual (sibling auto) | `shorewall-nft start /srv/v4` <br> `shorewall-nft start --config-dir4 /srv/v4` | v4 + auto-detected `/srv/v46` sibling |
| 4 | Legacy dual (explicit) | `shorewall-nft start --config-dir4 /srv/v4 --config6-dir /srv/other/v6` | Both dirs set; no auto-detect |
| 5 | v4-only | `shorewall-nft start --config-dir4 /srv/v4 --no-auto-v6` | v4 loaded, no v6 merge |
| 6 | v6-only | `shorewall-nft start --config6-dir /srv/v6 --no-auto-v4` | v6 loaded, no v4 merge |

## Default resolution order

With no flags and no positional argument:

1. **`/etc/shorewall46`** is used if it exists. This is the dual-stack
   output of `merge-config` and is treated as the authoritative source.
2. **`/etc/shorewall`** is used as fallback. The parser then
   auto-detects a sibling `/etc/shorewall6` and merges it in.

## Flag reference

### `-c`, `--config-dir <path>`

Override the merged dir. This is the "single dir contains everything"
mode, usually pointing to a `merge-config` output. The parser treats
this as a pre-merged dual-stack config and does **not** look for a
sibling.

```bash
shorewall-nft start -c /srv/firewall/merged
```

**Mutually exclusive** with `--config-dir4`, `--config6-dir`, and the
positional directory argument.

### `--config-dir4 <path>`

Explicit IPv4 config directory. By itself, the parser will still
auto-detect a sibling v6 directory (`<path>6`) and merge it — which is
the legacy Shorewall behavior.

```bash
# Auto-detect /srv/firewall/v46 if it exists
shorewall-nft start --config-dir4 /srv/firewall/v4

# v4-only, skip sibling detection
shorewall-nft start --config-dir4 /srv/firewall/v4 --no-auto-v6
```

### `--config6-dir <path>`

Explicit IPv6 config directory. Symmetric to `--config-dir4`: if given
alone, the CLI tries to find a v4 sibling by stripping the trailing
`6` (e.g. `/etc/shorewall6` → `/etc/shorewall`).

```bash
# Auto-detects /srv/firewall/v4 if it exists
shorewall-nft start --config6-dir /srv/firewall/v46

# v6-only, no v4 merge
shorewall-nft start --config6-dir /srv/firewall/v46 --no-auto-v4

# Full control: v4 from one path, v6 from another
shorewall-nft start --config-dir4 /etc/shorewall-test \
                    --config6-dir /etc/shorewall6-other
```

### `--no-auto-v4`

Disable auto-detection of a v4 sibling when only `--config6-dir` is
given. Use for **v6-only** deployments.

### `--no-auto-v6`

Disable auto-detection of a v6 sibling when only `--config-dir4` (or a
positional argument) is given. Use for **v4-only** deployments, or
when you want to keep v6 handling external.

## Positional argument (backward compatible)

The classic `shorewall-nft start /etc/shorewall` still works and is
equivalent to `--config-dir4 /etc/shorewall`. The positional argument
**cannot** be combined with any of the new flags — pick one style.

```bash
# All equivalent:
shorewall-nft start /etc/shorewall
shorewall-nft start --config-dir4 /etc/shorewall
```

## Errors

Conflicting flags produce a `UsageError`:

```
$ shorewall-nft start -c /a --config-dir4 /b
Usage: shorewall-nft start [OPTIONS] [DIRECTORY]
Error: --config-dir is mutually exclusive with --config-dir4/--config6-dir

$ shorewall-nft start /a --config-dir4 /b
Usage: shorewall-nft start [OPTIONS] [DIRECTORY]
Error: Positional directory cannot be combined with --config-dir, --config-dir4 or --config6-dir
```

## Internals

The resolution is centralized in `_resolve_config_paths()` in
`shorewall_nft/runtime/cli.py`. It returns a triple
`(primary, secondary, skip_sibling_merge)` that feeds into
`load_config()`:

- `primary` is always the first arg to `load_config()`
- `secondary` is passed as `config6_dir=` kwarg (only set for explicit
  dual mode)
- `skip_sibling_merge` disables the parser's automatic sibling lookup

Tests for all 6 modes and every conflict case are in
`tests/test_cli_config_flags.py`.
