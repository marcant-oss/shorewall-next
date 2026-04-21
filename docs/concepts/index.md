# Concepts

**Audience**: operators, developers
**Scope**: Background and conceptual reference for Shorewall configuration — zones, policies, rules, and netfilter internals.

---

## Overview

This area covers the concepts you need to understand before writing Shorewall configuration.
For step-by-step guides, see `docs/reference/`. For feature-specific configuration, see `docs/features/`.

## Files in this area

| File | Description |
|------|-------------|
| [Actions.md](Actions.md) | Defining reusable action rule-sets |
| [dynamic-routing.md](dynamic-routing.md) | OSPF/BGP alongside Shorewall |
| [Events.md](Events.md) | Shorewall Events (supersede port-knocking) |
| [GettingStarted.md](GettingStarted.md) | First-run orientation guide |
| [Introduction.md](Introduction.md) | Zones, policies, rules, interfaces — core model |
| [Macros.md](Macros.md) | Reusable macro rule patterns |
| [ManualChains.md](ManualChains.md) | Custom netfilter chains from extension scripts |
| [marks-and-connmark.md](marks-and-connmark.md) | Packet/connection marks for QoS and routing |
| [multipath-and-ecmp.md](multipath-and-ecmp.md) | Equal-cost multipath routing |
| [Multiple_Zones.md](Multiple_Zones.md) | Nested and host-based zone definitions |
| [MyNetwork.md](MyNetwork.md) | Worked example: complex multi-zone configuration |
| [naming-and-layout.md](naming-and-layout.md) | Config file naming and directory layout |
| [NetfilterOverview.md](NetfilterOverview.md) | Netfilter tables, chains, and hooks |
| [security-defaults.md](security-defaults.md) | Hardened default policies for shorewall-nft |
| [Shorewall_Doesnt.md](Shorewall_Doesnt.md) | Scope limitations of Shorewall |
| [shorewall_features.md](shorewall_features.md) | High-level feature catalogue |
| [shorewall_prerequisites.md](shorewall_prerequisites.md) | Kernel modules and packages required |

## See also

- [docs/features/](../features/index.md) — per-feature configuration references
- [docs/reference/](../reference/index.md) — setup guides and detailed references
- [docs/index.md](../index.md) — documentation root
