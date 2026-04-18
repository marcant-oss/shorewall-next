---
title: Testing
description: How to run the test suite, debug firewall rules, and contribute fixes to shorewall-nft.
---

# Testing

shorewall-nft ships with a complete test tooling stack. This chapter
documents every piece of it and walks you through the workflows for
reproducing bugs and verifying fixes. **Everyone should be able to
run these tests and debug production rules on their own machine** —
that's the goal, and the setup is designed for it.

## Quick path for new contributors

```bash
# 1. Clone and enter the project
git clone <repo> shorewall-nft && cd shorewall-nft

# 2. Create a virtualenv and install shorewall-nft + dev deps
python3 -m venv .venv
source .venv/bin/activate
pip install -e "packages/shorewall-nft[dev,simulate]" \
            -e "packages/shorewalld[dev]" \
            -e "packages/shorewall-nft-simlab[dev]"

# 3. Run the full test suite (must run as root on a dedicated host)
sudo tools/run-tests.sh packages/shorewall-nft/tests/ \
                        packages/shorewalld/tests/ \
                        packages/shorewall-nft-simlab/tests/ -v
```

`tools/run-tests.sh` creates a private network + mount namespace via
`unshare --mount --net` before invoking pytest. No sudoers rules,
helper binaries, or group membership needed beyond root access.

If everything is green, you're ready to hack.

## Chapters in this section

- [Setup](setup.md) — tool inventory, installation, distro packages
- [Test suite](test-suite.md) — pytest layout, running, fixtures
- [Debugging firewall rules](debugging.md) — how to trace a packet through a loaded ruleset
- [Verification tools](verification.md) — triangle verifier, simulator, connstate
- [Fuzz testing](fuzz.md) — random config generator
- [Troubleshooting](troubleshooting.md) — common failures and fixes

## Tool inventory

| Tool | Purpose | Shipped in | Required? |
|------|---------|------------|-----------|
| `pytest` | Unit + integration tests | pip dep (`[dev]`) | always |
| `run-tests.sh` | Isolated test runner (`unshare --mount --net`) | [`tools/run-tests.sh`](../../tools/run-tests.sh) | for netns tests |
| `nft` | kernel nftables binary | system (`nftables` package) | always |
| `ip` | iproute2 for netns + interface setup | system (`iproute2`) | for netns tests |
| `unshare` | private namespace for tests | system (`util-linux`) | for netns tests |
| `scapy` | Packet crafting for connection-state tests | pip dep (`[simulate]`) | optional |
| `pandoc` | DocBook → Markdown conversion | system (`pandoc`) | doc build only |
| `mkdocs-material` | Docs site generator | pip dep (optional) | doc preview only |

Everything under `tools/` is in-project — you don't need to fetch
anything from external repos. See [Setup](setup.md) for distro
package names and version requirements.

## What gets tested at each level

```
                   ┌─────────────────────────────┐
                   │  Unit tests (no netns)      │
                   │  ~220 tests, <10s           │
                   │  — parser, compiler,        │
                   │    plugins, optimizer,      │
                   │    hash, emitter            │
                   └─────────────────────────────┘
                                 │
                                 ▼
                   ┌─────────────────────────────┐
                   │  CLI integration tests      │
                   │  (netns-scoped)             │
                   │  ~40 tests, ~1 min          │
                   │  — start/stop/save/restore, │
                   │    debug, load-sets, trace  │
                   └─────────────────────────────┘
                                 │
                                 ▼
                   ┌─────────────────────────────┐
                   │  Triangle verifier          │
                   │  — compares compiled nft    │
                   │    against iptables dump    │
                   │  → 100% coverage target     │
                   └─────────────────────────────┘
                                 │
                                 ▼
                   ┌─────────────────────────────┐
                   │  Packet simulator (3-netns) │
                   │  — sends real TCP/UDP/ICMP  │
                   │    through a loaded ruleset │
                   │  → verdict vs iptables      │
                   └─────────────────────────────┘
```

- **Unit tests** run on any machine — no kernel features required.
- **CLI integration tests** need the netns tooling.
- **Verification** needs a production Shorewall config + its
  `iptables-save` dump to compare against.
- **Simulation** needs the netns tooling + scapy.

Each level catches different bug classes. A bug report ideally
includes the smallest level at which the bug reproduces.

## Bugfix workflow

When you hit a bug in a compiled ruleset — a rule that fires when it
shouldn't, or doesn't fire when it should — here's the canonical
sequence to reproduce, locate, and fix it.

### 1. Reproduce in a netns

```bash
# Compile with debug annotations
shorewall-nft debug /etc/shorewall --netns shorewall-next-sim-bug \
    --trace "ip saddr 192.168.1.100"
```

This:

- Saves the host's current ruleset (restored on Ctrl+C)
- Compiles your config with per-rule named counters and source-location
  comments
- Auto-inserts a `meta nftrace set 1` rule for the specified filter
- Prints instructions and waits

### 2. Send the offending packet

In a second terminal:

```bash
# Send a test packet from the trace-matched source
ip netns exec shorewall-next-sim-bug \
    nft monitor trace
# (separate terminal) generate traffic with ping, curl, etc.
```

The `nft monitor trace` output shows **the exact Shorewall source
file and line** that made the verdict, because the debug-compiled
rules carry `comment "rules:38: OrgAdmin/ACCEPT net $FW"` annotations.

### 3. Check the counter

```bash
# Which rule(s) matched?
ip netns exec shorewall-next-sim-bug \
    nft list counters table inet shorewall | grep -B1 'packets [1-9]'
```

Counter names are `r_<chain>_<idx>` — the chain tells you the zone
pair, the index tells you the position. Cross-reference with the
`comment` field in `nft list ruleset`.

### 4. Locate the source

Each counter comment pinpoints the Shorewall rule:

```
comment "rules:387: ACCEPT host:203.0.113.121 net [mandant-b]"
```

Open `/etc/shorewall/rules` at line 387. The `[mandant-b]` tag is the
`?COMMENT` tag of the enclosing mandant block.

### 5. Fix and test

After editing the source config, the **config hash drifts** — the
loaded (debug) ruleset no longer matches the on-disk source:

```bash
shorewall-nft status --netns shorewall-next-sim-bug
# Shorewall-nft is running.
#   Config hash: c5cde3358773069a (loaded)
#                6acbd4dc58cfe76b (on-disk) — DRIFT!
```

Re-enter debug mode to reload with the fix:

```bash
# Press Ctrl+C in the original debug terminal to restore host ruleset
# Then restart debug with the fixed config:
shorewall-nft debug /etc/shorewall --netns shorewall-next-sim-bug \
    --trace "ip saddr 192.168.1.100"
```

Generate the same packet. If the trace now shows the correct verdict,
your fix works. Commit.

### 6. Add a regression test

Before you ship the fix, add a unit test that would have caught the
bug. See [Test suite](test-suite.md) for patterns.

## Test isolation

`tools/run-tests.sh` uses `unshare --mount --net` to create a
**private network + mount namespace** before pytest starts:

- All nft rules, sysctl changes, and `ip netns add` bind-mounts are
  invisible to the host kernel.
- Individual tests spin up their own nested network namespaces via
  `ip netns add/exec/delete` — these are also fully isolated.
- Loopback (`lo`) is brought up automatically so UDP-based tests work.

Tests run as **root** — no sudoers rules, helper binaries, or group
membership required.

## Security note

Tests must run as root on a **dedicated test host**, not on a
production firewall. The private namespace completely isolates test
nft rules and namespace state from the host, but root access on a
firewall node is itself a risk. See [Setup](setup.md) and
[`tools/setup-remote-test-host.sh`](../../tools/setup-remote-test-host.sh)
for the recommended remote-host workflow.
