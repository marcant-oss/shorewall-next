---
title: shorewall-nft
description: nftables-native firewall compiler with Shorewall-compatible configuration
---

# shorewall-nft

nftables-native firewall compiler with Shorewall-compatible configuration.
Four installable packages — pick what you need:

| Package | What it does |
|---------|-------------|
| **shorewall-nft** | Compiler + CLI: turns Shorewall config into nft rulesets |
| **shorewalld** | Prometheus exporter + DNS-driven nft set daemon |
| **shorewall-nft-simlab** | Packet-level firewall validation lab (netns + scapy) |
| **shorewall-nft-stagelab** | Distributed bridge-lab: performance, DPDK, advisor, readiness review |

`shorewall-nft-netkit` is a shared-primitives package (TUN/TAP, netns stub,
packet builders) used by both simlab and stagelab; install it first when
bootstrapping.

→ **[Quick Start](quick-start.md)** — get running in minutes, beginner and pro paths

---

## shorewall-nft

The compiler reads `/etc/shorewall` (and `/etc/shorewall6` / `/etc/shorewall46`)
and emits an atomic nftables script. Config format is identical to upstream
Shorewall — existing configs load unchanged.

**Extensions beyond Shorewall:**

| Feature | Doc |
|---------|-----|
| Unified `inet` dual-stack table from Shorewall + Shorewall6 | [merge-config](shorewall-nft/merge-config.md) |
| Plugin system — Netbox, IP-INFO, custom | [plugins](shorewall-nft/plugins.md) — [write a plugin](shorewall-nft/plugin-development.md) |
| Post-compile optimizer (OPTIMIZE 1–8, 30–37% rule reduction) | [optimizer](shorewall-nft/optimizer.md) |
| Debug mode: per-rule named counters + source refs in traces | [debug mode](shorewall-nft/debug.md) |
| Config hash drift detection | [config-hash](shorewall-nft/config-hash.md) |
| Six config-dir modes (merged, dual, v4-only, v6-only, …) | [config-dirs](shorewall-nft/config-dirs.md) |
| Native network-namespace support | [CLI reference](cli/commands.md) |
| DNS-driven nft set population (`dns:` rule syntax) | [shorewalld](shorewalld/index.md) |

**Config concepts** (shared with upstream Shorewall):

- [Introduction](concepts/Introduction.md) — zones, interfaces, policies, rules
- [Macros](concepts/Macros.md) — macro expansion and reversal
- [Marks and connmarks](concepts/marks-and-connmark.md) — traffic control
- [Dynamic routing / multi-ISP](concepts/dynamic-routing.md)
- [NAT](features/NAT.md) · [IPv6](features/IPv6Support.md) · [Logging](features/shorewall_logging.md)
- [All concepts →](concepts/Introduction.md) · [All features →](features/NAT.md)

**Setup guides:**

- [Standalone (single interface)](reference/standalone.md)
- [Two-interface (LAN + internet)](reference/two-interface.md)
- [Three-interface (LAN + DMZ + internet)](reference/three-interface.md)
- [Starting and stopping](reference/starting_and_stopping_shorewall.md)
- [Configuration file format](reference/configuration_file_basics.md)
- [CLI reference](cli/commands.md) · [Dependencies](reference/dependencies.md)

---

## shorewalld

Long-running companion daemon with two jobs:

1. **Prometheus exporter** — per-rule packet/byte counters from every
   `inet shorewall` table across all network namespaces
2. **DNS-set API** — feeds nft sets named `dns_<qname>_v4/v6` from
   `pdns_recursor` so rules can match on hostname

→ [shorewalld reference](shorewalld/index.md)

---

## shorewall-nft-simlab

Packet-level validation lab: builds a multi-namespace topology, injects
real packets via TUN/TAP, and compares firewall verdicts against an
iptables baseline.

→ [Testing overview](testing/index.md) · [Simlab reference](testing/simlab.md)

---

## shorewall-nft-stagelab

Distributed bridge-lab for performance and readiness testing against real
firewall hardware. Drives iperf3, nmap, scapy, or TRex traffic through a
VLAN-trunked interface, collects Prometheus/SNMP metrics, and runs a
rule-based advisor that emits tiered tuning recommendations.

Three endpoint modes:

- **probe** — scapy frames via TAP, ~1 Gbps, correctness smoke without
  a line-rate NIC
- **native** — physical NIC VLAN sub-interface, iperf3/nmap, 10–25 Gbps
- **dpdk** — NIC bound to vfio-pci, TRex STL/ASTF, 40–100 Gbps / 10 M+
  concurrent sessions

→ [Stagelab reference](testing/stagelab.md)

---

## Reference

- [CLI commands](cli/commands.md)
- [CLI override schema](cli/override-json.md)
- [Dependencies by distro](reference/dependencies.md)
- [Machine-readable: commands.json](reference/commands.json)
- [Machine-readable: features.json](reference/features.json)
- [Troubleshooting](reference/troubleshoot.md)
- [FAQ](reference/FAQ.md)
- [License (GPL-2.0)](reference/GnuCopyright.md)

---

## Testing

- [Testing overview](testing/index.md) — test pyramid, levels, tools
- [Test environment setup](testing/setup.md)
- [Test suite reference](testing/test-suite.md)
- [Debugging a packet](testing/debugging.md)
- [Verification tools](testing/verification.md)
- [Simlab](testing/simlab.md)
- [Stagelab](testing/stagelab.md)
- [Point of truth](testing/point-of-truth.md)

---

> The `concepts/` and `features/` sections document the Shorewall configuration
> language that shorewall-nft compiles. They were adapted from the original
> Shorewall documentation by Tom Eastep (GPL-2.0). Pages describing the Perl
> compiler, iptables internals, or platform-specific installers have been
> removed — they do not apply to shorewall-nft.
