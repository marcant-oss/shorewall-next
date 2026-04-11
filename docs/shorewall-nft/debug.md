---
title: Debug mode
description: Temporarily load a debug-annotated ruleset with per-rule counters and source comments for live tracing.
---

# Debug mode

`shorewall-nft debug` temporarily replaces the running firewall with a
debug-instrumented version of the same config. Every rule gets:

- A **named counter** (`r_<chain>_<idx>`) queryable via
  `nft list counter inet shorewall <name>`
- A **source comment** visible in `nft monitor trace` output, showing
  file, line number, trimmed original Shorewall rule, mandant tag, and
  relevant meta info (rate limits, connlimit, time, user, mark)

When you exit with `Ctrl+C`, the original ruleset is restored.

## Usage

```bash
# Debug the default config in the host's main netns
shorewall-nft debug

# Debug a specific config in a netns
shorewall-nft debug /etc/shorewall --netns fw

# Don't restore on exit (leave debug ruleset loaded)
shorewall-nft debug --no-restore
```

## What the trace shows

A ping through a debug-instrumented ruleset produces trace events like:

```
trace id be38cfa4 inet shorewall input packet: iif "lo" ip saddr 127.0.0.1 ...
trace id be38cfa4 inet shorewall input rule meta l4proto icmp meta nftrace set 1 (verdict continue)
trace id be38cfa4 inet shorewall input rule jump ACCEPT-fw (verdict jump ACCEPT-fw)
trace id be38cfa4 inet shorewall ACCEPT-fw rule
  meta nfproto ipv4 counter name "r_ACCEPT_fw_0000" accept
  comment "rules:38: OrgAdmin/ACCEPT net $FW"
  (verdict accept)
```

The `comment "rules:38: OrgAdmin/ACCEPT net $FW"` string identifies
the exact Shorewall source rule that accepted this packet:

- **`rules`** — filename (`rules`, `policy`, `blrules`, `params`, etc.)
- **`38`** — line number
- **`OrgAdmin/ACCEPT net $FW`** — the trimmed original Shorewall
  rule, with tabs collapsed to single spaces

For rules inside `?COMMENT` blocks, the mandant tag is appended:

```
comment "rules:387: ACCEPT host:203.0.113.121 net [mandant-b]"
```

Rules with rate limits, connlimits, or other meta matches show them
at the end:

```
comment "rules:91: ACCEPT all dmz:$WEB {rate=3/min}"
comment "rules:102: Ping(ACCEPT) net $FW {connlimit=s:5}"
```

## Enabling nftrace for a flow

The trace itself is silent by default — you need to mark specific
packets with `meta nftrace set 1` for the kernel to emit trace events:

```bash
# Trace all ICMP (ping) traffic
sudo nft insert rule inet shorewall input meta l4proto icmp meta nftrace set 1

# Trace all traffic from one source IP
sudo nft insert rule inet shorewall input ip saddr 192.168.1.100 meta nftrace set 1

# Trace in a netns
sudo /usr/local/bin/run-netns exec fw \
    nft insert rule inet shorewall input ip saddr 1.2.3.4 meta nftrace set 1
```

Then run `nft monitor trace` (or `shorewall-nft trace --netns fw`) in
another terminal and generate the traffic. Cleanup by flushing the
input chain or stopping debug mode.

## Querying per-rule counters

Every rule in debug mode has a named counter. Counter names follow the
pattern `r_<sanitized_chain>_<index>`, e.g. `r_ACCEPT_fw_0000`,
`r_net_fw_0123`, `r_loc_dmz_0007`.

```bash
# List all counters with non-zero hits
sudo nft list counters table inet shorewall | grep -B1 "packets [1-9]"

# Query a specific counter
sudo nft list counter inet shorewall r_ACCEPT_fw_0000

# Reset all counters in the debug table
sudo nft reset counters table inet shorewall
```

## Config hash drift check

Before entering debug mode, shorewall-nft compares the hash of the
on-disk config with the hash of the currently-loaded ruleset. If they
don't match, **explicit confirmation is required** because entering
debug mode would reload the firewall with the current config, changing
production behavior:

```
── WARNING: Config drift detected ──
  Loaded ruleset hash:  c5cde3358773069a
  On-disk config hash:  7f9d50edc93fd1ea

The currently loaded ruleset was compiled from a DIFFERENT
config than the one on disk. Entering debug mode will
RELOAD the firewall with the current on-disk config, which
may change production behavior until you exit debug mode.

Do you want to proceed and reload with debug annotations? [y/N]:
```

See [config-hash](config-hash.md) for how drift detection works.

## Typical debugging workflow

```bash
# 1. Start debug mode (saves current ruleset, loads annotated version)
shorewall-nft debug /etc/shorewall --netns fw

# (In another terminal)

# 2. Mark the flow you want to trace
sudo /usr/local/bin/run-netns exec fw \
    nft insert rule inet shorewall input ip saddr 192.168.1.100 meta nftrace set 1

# 3. Start the trace viewer
sudo /usr/local/bin/run-netns exec fw nft monitor trace

# 4. Generate the traffic from 192.168.1.100

# 5. Read the trace output to see which Shorewall rule handled the packet
#    → comment "rules:38: OrgAdmin/ACCEPT net $FW"

# 6. (Optional) query counters to see how often each rule fired
sudo /usr/local/bin/run-netns exec fw \
    nft list counter inet shorewall r_ACCEPT_fw_0000

# 7. Exit debug mode (Ctrl+C in the debug terminal)
#    → original ruleset is restored
```

## Overhead

Per-rule counters and comments add a small amount of memory per rule
(counter object + comment string). A typical production ruleset with
~11000 rules gains ~2MB of kernel memory and adds a few microseconds
per packet due to counter increments. This is fine for debugging but
the user is not required to run this in production.

## Safety

- The **original ruleset is saved** to a tempfile before loading debug,
  and restored on `SIGINT`/`SIGTERM` via a signal handler.
- If the debug load fails, the original is **not** replaced.
- `--no-restore` skips the restore on exit — useful if you need the
  debug ruleset to persist across shell sessions.
- The saved ruleset path is printed; if the restore fails for any
  reason, you can manually reload it with
  `nft -f /tmp/shorewall-next-sim-debug-saved-<id>.nft`.
