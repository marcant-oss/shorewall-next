# CLAUDE.md — monorepo overview

`shorewall-nft` — nftables-native firewall compiler with a
Shorewall-compatible configuration surface.

## Repo layout

```
packages/
  shorewall-nft/          Core: compiler, emitter, config, runtime
  shorewalld/             Prometheus exporter + DNS-based dynamic sets
  shorewall-nft-simlab/   Packet-level simulation lab (netns + scapy)
docs/                     User-facing docs; docs/testing/ for simlab
tools/                    Operator scripts (setup-remote-test-host.sh …)
packaging/                .deb / .rpm / systemd units
```

Each package has its own `CLAUDE.md` — open it before touching that code.

## Bootstrap

```bash
# Install all three (editable, dev extras):
pip install -e 'packages/shorewall-nft[dev]' \
            -e 'packages/shorewalld[dev]' \
            -e 'packages/shorewall-nft-simlab[dev]'

# Run core tests:
cd packages/shorewall-nft && python -m pytest tests/ -q

# Run daemon tests:
cd packages/shorewalld && python -m pytest tests/ -q
```

## Release state

Branch `shorewall-nft-release`. Versions in sync across all three
`pyproject.toml` files and `packages/shorewall-nft/shorewall_nft/__init__.py`.
Current version: **1.2.3** (unreleased; 1.1.0 pending simlab sign-off).

## Sister projects

Located at `/home/avalentin/projects/marcant-fw/`:

- **shorewall2foomuuri** — Shorewall → foomuuri DSL → nft translator.
  Useful as nft syntax reference and iptables↔nft equivalence checker.
- **netns-routing** — production environment: 16 zones, ~3300 rules,
  HA with VRRP across two nodes / three namespaces, real flowtables.
  Best "what does the reference config really look like" reference.

## Key rules (all packages)

- Commit messages / CHANGELOG / release notes **never name the
  deployment** — say "the reference HA firewall" / "the reference config".
- Test reports must split **false-drop** vs **false-accept** and explain
  random-probe mismatches with the oracle reason.
- Point of truth for verification: `old/iptables.txt` +
  `old/ip6tables.txt` (2026-04-07). simlab is the weakest signal.
