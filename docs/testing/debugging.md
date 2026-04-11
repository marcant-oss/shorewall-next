---
title: Debugging firewall rules
description: Live packet tracing, counter inspection, bisecting rule behavior in a loaded ruleset.
---

# Debugging firewall rules

When a rule fires unexpectedly — or doesn't fire when it should —
this is the canonical workflow for tracing the exact Shorewall source
rule responsible. It works on production configs with 10000+ rules
and completes in seconds.

## Prerequisites

- Test tooling installed (see [Setup](setup.md))
- A netns you can dedicate to the investigation (will be created)
- The problematic Shorewall config on disk

## Step-by-step: trace a single packet

### 1. Enter debug mode with an auto-trace filter

```bash
shorewall-nft debug /etc/shorewall \
    --netns shorewall-next-sim-bug \
    --trace 'ip saddr 192.168.1.100'
```

What happens:

1. **Saves** the current ruleset in the netns to a tempfile
2. **Compiles** your config with per-rule counters + source comments
3. **Loads** the debug-annotated ruleset
4. **Inserts** `ip saddr 192.168.1.100 meta nftrace set 1` at the
   top of the `input` chain
5. Waits for `Ctrl+C` (restore hook installed on SIGINT)

The filter expression is any valid nft match. Common patterns:

| Filter | Matches |
|--------|---------|
| `ip saddr 1.2.3.4` | Single source IP |
| `ip daddr 10.0.0.0/24` | Destination subnet |
| `meta l4proto icmp` | All ICMP |
| `tcp dport 443` | HTTPS traffic |
| `meta nfproto ipv6 ip6 saddr 2001:db8::1` | Single v6 source |

### 2. Watch the trace

In a second terminal:

```bash
sudo /usr/local/bin/run-netns exec shorewall-next-sim-bug \
    nft monitor trace
```

### 3. Generate the traffic

From wherever makes sense: ping, curl, or replay from a pcap. The
trace will show every rule the packet visits:

```
trace id 5f2c81ab inet shorewall input packet: iif "eth0"
    ip saddr 192.168.1.100 ip daddr 10.0.0.1 ip protocol tcp ...
trace id 5f2c81ab inet shorewall input rule ip saddr 192.168.1.100 meta nftrace set 1 (verdict continue)
trace id 5f2c81ab inet shorewall input rule jump loc-fw (verdict jump loc-fw)
trace id 5f2c81ab inet shorewall loc-fw rule meta nfproto ipv4
    tcp dport 22 counter name "r_loc_fw_0014" accept
    comment "rules:87: SSH(ACCEPT) loc $FW" (verdict accept)
```

The last line gives you:

- **`rules:87`** — exact source file and line
- **`SSH(ACCEPT) loc $FW`** — the original Shorewall rule
- **`r_loc_fw_0014`** — the named counter for this rule
- **`verdict accept`** — the final verdict

### 4. Cross-reference counters

Which rules in this chain are hot?

```bash
sudo /usr/local/bin/run-netns exec shorewall-next-sim-bug \
    nft list counters table inet shorewall | grep -B1 'packets [1-9]'
```

Shows only counters with non-zero hits. Useful for answering "has
this rule ever matched" at a glance.

### 5. Inspect the IR

If the compiled rule looks wrong, bypass runtime and compare the
input/output directly:

```bash
# What does the compiler produce for this config?
shorewall-nft compile /etc/shorewall -o /tmp/check.nft
grep -B2 -A2 'comment "rules:87' /tmp/check.nft
```

### 6. Fix and re-test

Edit the source. Hit `Ctrl+C` in the debug terminal to restore the
original ruleset. Re-enter debug mode — the config hash drift check
will confirm the source changed:

```bash
shorewall-nft status --netns shorewall-next-sim-bug
#   Config hash: <old> (loaded)
#                <new> (on-disk) — DRIFT!

shorewall-nft debug /etc/shorewall --netns shorewall-next-sim-bug \
    --trace 'ip saddr 192.168.1.100'
```

Generate the packet again. If the trace shows the expected verdict,
you're done.

## Debug comment format

Every rule in a debug-compiled ruleset has a comment like:

```
comment "rules:87: SSH(ACCEPT) loc $FW [mandant-tag] {rate=3/min}"
          │       │                      │             │
          │       │                      │             └── meta annotations
          │       │                      │                 (rate, connlimit, time, user, mark)
          │       │                      └── ?COMMENT tag (if inside a block)
          │       └── trimmed original Shorewall rule (up to 120 chars)
          └── source file basename and line number
```

Limitations:

- nft comments cap at 128 bytes — longer rules are truncated with `…`
- Macros that expand to multiple rules all reference the **calling**
  source line, not the macro definition line
- Auto-generated rules (e.g. NDP, DHCP helpers) have no source line
  and get an empty file prefix

## Counter name format

```
r_<sanitized_chain_name>_<rule_index>
```

Examples:

| Counter | Chain | Index |
|---------|-------|-------|
| `r_input_0000` | `input` (base chain) | 0 |
| `r_ACCEPT_fw_0014` | `ACCEPT-fw` | 14 |
| `r_net_loc_0123` | `net-loc` | 123 |
| `r_sw_Drop_0003` | `sw_Drop` (action chain) | 3 |

Index is zero-based and matches the rule's position in the chain as
emitted (after optimization passes). If OPTIMIZE=8 merges chains,
the index references the **canonical** chain's rule list.

## Without `--trace`

If you prefer to control the nftrace rule manually — e.g. to match a
more complex pattern — just skip `--trace` and insert the rule
yourself:

```bash
shorewall-nft debug /etc/shorewall --netns shorewall-next-sim-bug

# In another terminal:
sudo /usr/local/bin/run-netns exec shorewall-next-sim-bug nft insert rule \
    inet shorewall input \
    ip saddr 192.168.1.100 tcp dport 22 \
    meta nftrace set 1
```

The trace rule persists until the next `flush chain` or until the
ruleset is restored (which happens on `debug` exit).

## Debugging in production

**Don't.** Debug mode is designed for isolated netns analysis. If
the bug only reproduces with real traffic from the production host,
one option is to take an `iptables-save` snapshot, run the `simulate`
command with it, and bisect there instead. See
[Verification tools](verification.md).

If you absolutely must add trace instrumentation to a production
ruleset, insert a tightly-scoped `meta nftrace set 1` rule (NOT
`shorewall-nft debug`, which would replace the whole ruleset) and
remove it immediately after the capture.

## Agent-friendly variants

For automated / scripted debugging from LLMs or CI:

```bash
# Get the hash without running anything
shorewall-nft status --netns shorewall-next-sim-bug | grep 'Config hash'

# Compile + extract the comment for a specific source line
shorewall-nft compile /etc/shorewall -o - | \
    awk '/comment "rules:87:/{print; exit}'

# Machine-readable feature catalog
cat docs/reference/features.json | jq '.features[].name'

# Machine-readable CLI reference
cat docs/reference/commands.json | \
    jq '.subcommands[] | select(.name=="debug") | .params'
```

All these invocations are stable and their output is deterministic
(modulo timestamps), so they can be parsed by agents.

## See also

- [Testing index — bugfix workflow](index.md#bugfix-workflow) — the
  short-form version of this page
- [Debug mode docs](../shorewall-nft/debug.md) — emitter internals
- [Config hash & drift detection](../shorewall-nft/config-hash.md)
