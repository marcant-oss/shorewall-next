---
title: shorewall-nft
description: nftables-native firewall compiler with Shorewall-compatible configuration
---

# shorewall-nft

A Python implementation of the Shorewall firewall compiler that emits
native **nftables** rulesets instead of iptables. Drop-in compatible
with existing Shorewall configurations, with additional dual-stack,
plugin, optimizer, and debug features.

## Quick links

- [Getting started](reference/shorewall_quickstart_guide.md)
- [Configuration basics](reference/configuration_file_basics.md)
- [CLI reference](cli/commands.md)
- [Feature index (machine-readable)](reference/features.json)

## What's different from upstream Shorewall

shorewall-nft reimplements the Shorewall configuration language in
Python and compiles it directly to nftables. The configuration format
is identical — existing `/etc/shorewall` and `/etc/shorewall6` trees
load unchanged — but the backend is modern nft instead of iptables.

Additions on top of Shorewall:

| Feature | Page |
|---------|------|
| Unified `inet` table for dual-stack IPv4+IPv6 | [merge-config](shorewall-nft/merge-config.md) |
| Plugin system with IP-INFO and Netbox plugins | [plugins](shorewall-nft/plugins.md) |
| Post-compile optimizer (OPTIMIZE levels 1-8) | [optimizer](shorewall-nft/optimizer.md) |
| Debug mode with named counters + source refs | [debug mode](shorewall-nft/debug.md) |
| Config hash drift detection | [config-hash](shorewall-nft/config-hash.md) |
| Native netns support | [CLI reference — netns flags](cli/commands.md) |
| Verification against iptables baseline | [verify tools](testing/verification.md) |
| DNS-driven nft-set population (`dns:` rules) | [shorewalld](reference/shorewalld.md) |
| Prometheus metrics exporter (beta) | [shorewalld — metrics](reference/shorewalld.md#metrics) |

## Documentation structure

- **`concepts/`** — Shorewall core concepts: anatomy, zones, macros, actions, rules, events. Applies to both upstream Shorewall and shorewall-nft.
- **`features/`** — Feature-level docs: NAT, traffic shaping, logging, VPN, accounting, IPv6, blacklisting, etc.
- **`shorewall-nft/`** — Extensions unique to shorewall-nft (plugins, optimizer, debug mode, merge-config, config hash, netns).
- **`cli/`** — Command reference for the `shorewall-nft` binary.
- **`reference/`** — Installation, quickstart guides, sample setups (2-interface, 3-interface, standalone), FAQ, troubleshooting, internals, licenses.
- **`legacy/`** — Upstream-only docs: old version-specific notes, Shorewall-Perl era, hypervisor-specific setups, language variants. Kept for historical reference.

Most concept and feature pages were imported from the original Shorewall documentation by Tom Eastep and converted from DocBook to Markdown. They describe the configuration semantics that shorewall-nft preserves. Pages specific to the Perl compiler, iptables output, sysvinit scripts, or platform-specific installers are in `legacy/` and do not apply to shorewall-nft.
