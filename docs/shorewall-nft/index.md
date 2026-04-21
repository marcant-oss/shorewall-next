# shorewall-nft extensions

**Audience**: operators, developers
**Scope**: Features and behaviour unique to shorewall-nft (beyond the base Shorewall configuration surface).

---

## Overview

This area documents extensions that are specific to the `shorewall-nft` compiler and runtime.
For base Shorewall concepts, see `docs/concepts/`. For features shared with classic Shorewall, see `docs/features/`.

## Files in this area

| File | Description |
|------|-------------|
| [config-dirs.md](config-dirs.md) | Config directory resolution: six location modes and CLI overrides |
| [config-hash.md](config-hash.md) | Ruleset drift detection via sha256 hash in the nft comment |
| [debug.md](debug.md) | Debug mode: per-rule counters and source comments for live tracing |
| [flowtable.md](flowtable.md) | Software and hardware flow offloading via nft flowtables |
| [merge-config.md](merge-config.md) | Dual-stack merge of /etc/shorewall + /etc/shorewall6 |
| [optimizer.md](optimizer.md) | Post-compile IR optimization passes |
| [plugin-development.md](plugin-development.md) | Writing a custom plugin: hooks, priority, CLI integration |
| [plugins.md](plugins.md) | Built-in plugin system: IP lookups, v4/v6 mapping, enrichment |

## See also

- [docs/concepts/](../concepts/index.md) — foundational Shorewall concepts
- [docs/features/](../features/index.md) — per-feature configuration references
- [docs/roadmap/](../roadmap/index.md) — planned nftables features and offload roadmap
- [docs/index.md](../index.md) — documentation root
