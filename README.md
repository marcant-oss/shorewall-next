# shorewall-nft

nftables-native firewall compiler with Shorewall-compatible configuration.

Drop-in replacement for Shorewall that compiles the same config files
directly to `nft -f` scripts — no iptables, no iptables-restore.

**v1.4.0** · Python 3.11+ · Linux ≥ 5.8 · GPL-2.0

## Packages

| Package | Install | What it does |
|---------|---------|-------------|
| `shorewall-nft` | `pip install shorewall-nft` | Compiler, CLI, runtime |
| `shorewalld` | `pip install 'shorewall-nft[daemon]'` | Prometheus exporter + DNS-set daemon |
| `shorewall-nft-simlab` | `pip install shorewall-nft-simlab` | Packet-level validation lab |

```bash
# Install all three (editable, dev extras):
pip install -e 'packages/shorewall-nft[dev]' \
            -e 'packages/shorewalld[dev]' \
            -e 'packages/shorewall-nft-simlab[dev]'
```

## What it does

- **Compiles** Shorewall config (`/etc/shorewall`, `/etc/shorewall6`) to
  native nft scripts — every rule, chain, set, NAT, TC mark, and helper.
- **Dual-stack**: merges Shorewall + Shorewall6 into one `table inet`
  ruleset via `merge-config`, with guided collision resolution.
- **Plugin system**: Netbox and IP-INFO built-in, extensible via TOML.
- **Optimizer**: 5 passes, 30–37% rule reduction on production configs.
- **Debug mode**: per-rule named counters + source comments in `nft monitor
  trace` output. Restores original ruleset on Ctrl+C.
- **Config hash**: drift detection between on-disk config and loaded ruleset.
- **Network namespace support**: `--netns <name>` on every command.
- **DNS-driven nft sets**: `dns:github.com` in a rule → shorewalld keeps
  `dns_github_com_v4/v6` sets populated from pdns_recursor answers.
- **Prometheus metrics**: per-rule packet/byte counters, per-interface stats,
  conntrack fill level, across all namespaces.
- **12 000+ LOC Python, 236 tests, 36 CLI commands.**

## Quick start

```bash
# Check your config without loading anything:
shorewall-nft check /etc/shorewall

# Compile and apply:
sudo shorewall-nft start /etc/shorewall

# Verify against an iptables baseline:
shorewall-nft verify /etc/shorewall --iptables iptables-save.txt
```

→ **[Full Quick Start guide](docs/quick-start.md)** — beginner and migration paths

## Usage

```bash
# Shorewall-compatible lifecycle
shorewall-nft start [DIR]          # compile + apply
shorewall-nft stop                 # remove all rules
shorewall-nft restart [DIR]        # atomic re-apply
shorewall-nft check [DIR]          # validate config
shorewall-nft status               # loaded hash, zone summary
shorewall-nft compile [DIR]        # print nft script to stdout
shorewall-nft show [zones|sets|counters]

# Dynamic blacklist
shorewall-nft drop 1.2.3.4         # block
shorewall-nft allow 1.2.3.4        # unblock
shorewall-nft blacklist 1.2.3.4 -t 1h

# Dual-stack merge
shorewall-nft merge-config /etc/shorewall /etc/shorewall6 -o /etc/shorewall46
shorewall-nft merge-config ... --guided   # interactive collision resolution

# Plugins
shorewall-nft enrich [DIR]         # enrich config in-place (.bak backup)
shorewall-nft lookup 203.0.113.5   # query plugins for one IP
shorewall-nft plugins list

# Debug + trace
shorewall-nft debug [DIR] [--netns NAME]   # load debug ruleset, Ctrl+C restores
shorewall-nft counters [--netns NAME]      # counter values
shorewall-nft trace [--netns NAME]         # live nft monitor trace

# Verification
shorewall-nft verify [DIR] --iptables DUMP   # static rule coverage
shorewall-nft simulate [DIR] --iptables DUMP # packet-level test

# Generation
shorewall-nft generate-systemd [--netns]
shorewall-nft generate-sysctl [DIR]
shorewall-nft generate-tc [DIR]
shorewall-nft migrate [DIR] --iptables DUMP --dry-run
```

## shorewalld

```bash
# Start Prometheus exporter + DNS-set daemon:
shorewalld --listen-prom :9748 --netns auto

# Scrape:
curl -s http://localhost:9748/metrics | grep shorewall_nft

# Inspect dnstap stream live:
shorewalld tap --socket /run/shorewalld/dnstap.sock --format pretty
```

→ [shorewalld reference](docs/shorewalld/index.md)

## Testing

```bash
# Unit tests per package:
cd packages/shorewall-nft     && python -m pytest tests/ -q   # ~333 tests
cd packages/shorewalld        && python -m pytest tests/ -q   # ~292 tests
cd packages/shorewall-nft-simlab && python -m pytest tests/ -q

# Run tests (isolated, cannot crash host):
tools/run-tests.sh

# Packet-level simlab (requires netns + test host):
python -m shorewall_nft_simlab.smoketest full --random 50 --seed 42
```

→ [Testing docs](docs/testing/index.md)

## Documentation

Full docs in [`docs/`](docs/index.md), browsable with `mkdocs serve`.

- [Quick Start](docs/quick-start.md)
- [shorewall-nft extensions](docs/shorewall-nft/plugins.md)
- [shorewalld daemon](docs/shorewalld/index.md)
- [Testing + simlab](docs/testing/index.md)
- [CLI reference](docs/cli/commands.md)
- [Dependencies](docs/reference/dependencies.md)

Machine-readable references:
- [`docs/reference/commands.json`](docs/reference/commands.json)
- [`docs/reference/features.json`](docs/reference/features.json)

## Architecture

```
packages/
  shorewall-nft/
    shorewall_nft/
      config/      # Shorewall config parser (zones, interfaces, all file types)
      compiler/    # Config → IR (zone pairs → chains → rules)
      nft/         # IR → nft script (emitter, sets, objects, flowtable, DNS sets)
      runtime/     # CLI (36 commands), sysctl/TC/systemd generators
      verify/      # Triangle comparator + packet simulator
      plugins/     # Plugin loader + built-in plugins (ip-info, netbox)
      netns/       # Network namespace apply + systemd templates
      tools/       # merge_config, migrate
  shorewalld/
    shorewalld/
      core.py, cli.py, exporter.py, discover.py
      dnstap.py, pbdns.py, worker_router.py, setwriter.py
      dns_set_tracker.py, state.py, reload_monitor.py, peer.py
      tap.py
  shorewall-nft-simlab/
    shorewall_nft_simlab/
      smoketest.py, controller.py, topology.py, worker.py
      oracle.py, packets.py, report.py, nsstub.py
```

## License

GPL-2.0-only (same as Shorewall upstream)
