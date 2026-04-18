---
title: CLI command reference
description: All `shorewall-nft` subcommands with their options and arguments.
---

# CLI command reference

`shorewall-nft` v1.4.0 has 36 top-level subcommands.
Auto-generated from the CLI definition — a machine-readable
version is in [`reference/commands.json`](../reference/commands.json).

## Lifecycle

### `start`

Compile and apply firewall rules (like shorewall start).

```
shorewall-nft start [directory] [--netns <value>] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Apply in network namespace.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

#### Progress output

`start` reports each phase. On a TTY the current step is overwritten
in-place with ANSI colour; piped or under systemd the same text is
emitted as plain lines suitable for journald:

```
[1/5] Parsing and compiling config …        ✓
[2/5] Probing kernel capabilities …         ⚠  (warnings logged; never aborts)
[3/5] Applying ruleset …                    ✓
[4/5] Configuring proxy-ARP / NDP …         ✓
[5/5] Cleaning up stopped-firewall table …  ✓
Firewall started.
```

Capability warnings in step 2 are **non-fatal** — they are collected
and shown, but `start` continues. Step 3 (`apply_nft`) is the
authoritative gate: if the kernel rejects a rule, that step fails with
a ✗ and the command exits non-zero. This means capability probing never
aborts a `start` that would otherwise succeed on the running kernel.

### `stop`

Stop the firewall (remove all rules).

```
shorewall-nft stop [--netns <value>]
```

- **`--netns`** — Target network namespace.

### `restart`

Recompile and atomically replace the ruleset.

```
shorewall-nft restart [directory] [--netns <value>] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Target network namespace.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `reload`

Reload rules (same as restart for nft — atomic replace).

```
shorewall-nft reload [directory] [--netns <value>] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Target network namespace.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `status`

Show firewall status.

```
shorewall-nft status [--netns <value>]
```

- **`--netns`** — Target network namespace.

### `clear`

Clear all firewall rules (accept all traffic).

```
shorewall-nft clear [--netns <value>]
```

- **`--netns`** — Target network namespace.

### `save`

Save current ruleset (like shorewall save).

```
shorewall-nft save [filename] [-C] [--netns <value>]
```

- **`-C`** — Include counters.
- **`--netns`** — Target network namespace.

### `restore`

Restore a saved ruleset (like shorewall restore).

```
shorewall-nft restore <filename> [--netns <value>]
```

- **`--netns`** — Target network namespace.

### `check`

Validate config without applying (like shorewall check).

```
shorewall-nft check [directory] [--skip-caps] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--skip-caps`** — Skip capability check.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `compile`

Compile config to nft script (like shorewall compile).

```
shorewall-nft compile [directory] [-o <value>] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`-o, --output`** — Output file.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

## Inspection

### `show`

Show firewall info (like shorewall show). Subcommands: zones, policies, config, connections.

```
shorewall-nft show [what] [-x] [--netns <value>]
```

- **`-x`** — Show exact counters.
- **`--netns`** — Target network namespace.

### `counters`

List all counter values (packets/bytes).

```
shorewall-nft counters [--netns <value>]
```

- **`--netns`**

### `reset`

Reset counters (like shorewall reset).

```
shorewall-nft reset [chains] [--netns <value>]
```

- **`--netns`** — Target network namespace.

## Dynamic blacklist

### `drop`

Dynamically drop traffic from addresses (like shorewall drop).

```
shorewall-nft drop <addresses> [--netns <value>]
```

- **`--netns`**

### `blacklist`

Add address to dynamic blacklist with timeout (like shorewall blacklist).

```
shorewall-nft blacklist <address> [-t <value>] [--netns <value>]
```

- **`-t, --timeout`** — Timeout (e.g. 1h, 30m, 1d).
- **`--netns`**

### `reject`

Dynamically reject traffic from addresses (like shorewall reject).

```
shorewall-nft reject <addresses> [--netns <value>]
```

- **`--netns`**

### `allow`

Remove addresses from the blacklist (like shorewall allow).

```
shorewall-nft allow <addresses> [--netns <value>]
```

- **`--netns`**

## Capabilities & features

### `capabilities`

Detect nftables capabilities of the running kernel.

```
shorewall-nft capabilities [--netns <value>] [--json]
```

- **`--netns`** — Probe in network namespace.
- **`--json`** — Output as JSON.

### `explain-nft-features`

Show nft features with syntax examples and availability.

```
shorewall-nft explain-nft-features [--probe] [--category <value>] [--json]
```

- **`--probe`** — Probe kernel for feature availability.
- **`--category, -c`** — Filter by category (e.g. 'Sets', 'NAT', 'IPv6').
- **`--json`** — Output as JSON.

## Verification

### `verify`

Verify compiled output against iptables baseline.

```
shorewall-nft verify [directory] [--iptables <value>] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--iptables`** — Path to iptables-save dump (ground truth).
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `simulate`

Run packet-level simulation in 3 network namespaces.

```
shorewall-nft simulate [directory] [--iptables <value>] [--target <value>] [--max-tests <value>] [--seed <value>] [-V] [--parallel <value>] [--no-trace] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--iptables`** — iptables-save dump (ground truth).
- **`--target`** — Target IP for tests.
- **`--max-tests, -n`** — Max test cases.
- **`--seed`** — Random seed for sampling.
- **`-V, --sim-verbose`** — Show all test results.
- **`--parallel, -j`** — Parallel test threads.
- **`--no-trace`** — Disable nft trace logging.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `migrate`

Verify migration from Shorewall to shorewall-nft.

```
shorewall-nft migrate [directory] [--iptables <value>] [-o <value>] [--dry-run] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--iptables`** — iptables-save dump for verification.
- **`-o, --output`**
- **`--dry-run`** — Validate with nft -c.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `trace`

Start live packet tracing (nft monitor trace).

```
shorewall-nft trace [--netns <value>]
```

- **`--netns`** — Trace in network namespace.

## Generators

### `generate-sysctl`

Generate sysctl configuration script.

```
shorewall-nft generate-sysctl [directory] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `generate-systemd`

Generate systemd service files.

```
shorewall-nft generate-systemd [--netns] [-o <value>]
```

- **`--netns`** — Generate template for network namespaces.
- **`-o, --output-dir`**

### `generate-tc`

Generate tc (traffic control) commands.

```
shorewall-nft generate-tc [directory] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `generate-set-loader`

Generate a shell script that loads external sets.

```
shorewall-nft generate-set-loader [directory] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `load-sets`

Load external sets (ipsets, GeoIP) into nft after apply.

```
shorewall-nft load-sets [directory] [--netns <value>] [--geoip-dir <value>] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Target network namespace.
- **`--geoip-dir`** — GeoIP prefix directory.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

## Dual-stack merge

### `merge-config`

Merge Shorewall + Shorewall6 configs into unified directory.

```
shorewall-nft merge-config <shorewall_dir> [shorewall6_dir] [-o <value>] [--guided] [--no-plugins]
```

- **`-o, --output`** — Output directory (default: <parent>/shorewall46)
- **`--guided`** — Interactive mode: ask on each collision
- **`--no-plugins`** — Disable plugin enrichment even if plugins.conf exists

## Plugins

### `plugins`

Manage shorewall-nft plugins.

```
shorewall-nft plugins [subcommand] [--config-dir <value>]
```

- **`--config-dir, -c`**

### `lookup`

Lookup an IP address across all configured plugins.

```
shorewall-nft lookup <ip> [--config-dir <value>] [--json]
```

- **`--config-dir, -c`** — Config dir with plugins.conf
- **`--json`** — Output raw JSON (machine-readable).

### `enrich`

Run plugin enrichment in-place on a config directory.

```
shorewall-nft enrich [directory] [--no-backup] [--dry-run]
```

- **`--no-backup`** — Skip .bak file creation (dangerous)
- **`--dry-run`** — Preview changes without touching disk (shows a unified diff).

## Debug

### `debug`

Temporarily load a debug-annotated ruleset.

```
shorewall-nft debug [directory] [--netns <value>] [--no-restore] [--trace <value>] [-c <value>] [--config-dir4 <value>] [--config6-dir <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Target network namespace.
- **`--no-restore`** — Do not restore the original ruleset on exit.
- **`--trace`** — Auto-install a `meta nftrace set 1` rule in the input chain for the given nft match (e.g. 'ip saddr 1.2.3.4' or 'meta l4proto icmp'). Removed on exit.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir4`** — Explicit IPv4 config directory.
- **`--config6-dir`** — Explicit IPv6 config directory (use with --config-dir4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

## ip-info plugin

## netbox plugin

