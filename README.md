# shorewall-nft

nftables-native firewall compiler with Shorewall-compatible configuration.

Drop-in replacement for Shorewall that compiles the same config files
directly to `nft -f` scripts — no iptables, no iptables-restore.

## Status

**v1.0.0** — verified against 3 production firewalls:

| Config    | Zones | IPv4 | IPv6 |
|-----------|-------|------|------|
| fw-large  | 16 | [PASS] 100.0% (8281/8281) | [PASS] 100.0% (3310/3310) |
| fw-medium | 27 | [PASS] 100.0% (2998/2998) | [PASS] 100.0% (252/252)   |
| fw-small  |  4 | [PASS] 100.0% (202/202)   | [PASS] 100.0% (60/60)     |
| **Combined** | | **15103/15103 = 100.0%** | |

- **Dual-stack**: merges Shorewall + Shorewall6 into one `table inet` ruleset
- **Six config modes**: auto, merged, dual auto-sibling, dual explicit, v4-only, v6-only — all via CLI flags
- **Kernel-verified**: loads successfully via `nft -f` in test namespace
- **Capability detection**: auto-probes kernel features, reports errors with context
- **Port/protocol resolution**: reads `/etc/services` and `/etc/protocols`
- **Plugin system**: IP-INFO + Netbox, extensible via TOML config
- **Optimizer**: 5 levels, 30–37% rule reduction on production configs
- **Debug mode**: per-rule named counters + source comments in trace output, auto `--trace` filter
- **Config hash**: drift detection between on-disk config and loaded ruleset
- 12000+ LOC Python, 236 tests, 36 CLI commands

## Documentation

Full docs are in [`docs/`](docs/index.md) as Markdown, compatible with
MkDocs Material:

- [**Testing chapter**](docs/testing/index.md) — setup, test suite, debugging workflow, verification tools
- [**shorewall-nft specifics**](docs/shorewall-nft/plugins.md) — plugins, optimizer, debug mode, merge-config, config hash
- [**Dependencies**](docs/reference/dependencies.md) — runtime and distro package reference

Machine-readable references (for agents and scripts):

- [`docs/reference/commands.json`](docs/reference/commands.json) — all CLI commands with params
- [`docs/reference/features.json`](docs/reference/features.json) — nft feature catalog

Run `mkdocs serve` to browse the docs locally.

## Testing

Install the test tooling in one step:

```bash
sudo tools/install-test-tooling.sh
pytest tests/ -v
```

See [`docs/testing/setup.md`](docs/testing/setup.md) for details,
distro package requirements, and troubleshooting.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Requires: Python 3.11+, `nft` binary, `pyroute2`.  
Optional: `python3-nftables` (system package) for libnftables bindings.

## Usage

### Shorewall-compatible commands

```bash
shorewall-nft start [/etc/shorewall]      # Compile and apply
shorewall-nft stop                         # Remove all rules
shorewall-nft restart [/etc/shorewall]     # Atomic re-apply
shorewall-nft reload [/etc/shorewall]      # Same as restart (nft is atomic)
shorewall-nft status                       # Show if running
shorewall-nft check [/etc/shorewall]       # Validate config
shorewall-nft compile [/etc/shorewall]     # Output nft script to stdout
shorewall-nft save [filename]              # Save current ruleset
shorewall-nft restore <filename>           # Restore saved ruleset
shorewall-nft show [zones|counters|sets]   # Show firewall info
shorewall-nft reset                        # Reset counters
shorewall-nft clear                        # Accept all traffic
```

### Dynamic blacklist

```bash
shorewall-nft drop 1.2.3.4                # Block address
shorewall-nft allow 1.2.3.4               # Unblock address
shorewall-nft blacklist 1.2.3.4 -t 1h     # Block with timeout
shorewall-nft reject 1.2.3.4              # Reject address
```

### Network namespace support

```bash
shorewall-nft start /etc/shorewall/fw --netns fw
shorewall-nft status --netns fw
shorewall-nft stop --netns fw
```

### nft-native extensions

```bash
shorewall-nft verify [dir] --iptables dump.txt     # Triangle comparison
shorewall-nft simulate [dir] --iptables dump.txt   # Packet-level test (3-netns)
shorewall-nft trace [--netns fw]                   # Live nft monitor trace
shorewall-nft debug [dir] [--netns fw]             # Temporary debug ruleset
shorewall-nft counters [--netns fw]                # Counter values
shorewall-nft load-sets [dir] [--geoip-dir DIR]    # Load external sets
shorewall-nft migrate [dir] --iptables dump.txt    # Migration check
shorewall-nft generate-systemd [--netns]           # systemd service files
shorewall-nft generate-sysctl [dir]                # Sysctl script
shorewall-nft generate-tc [dir]                    # Traffic control script
shorewall-nft generate-set-loader [dir]            # Set loader script

# Dual-stack merge + plugin enrichment
shorewall-nft merge-config /etc/shorewall /etc/shorewall6 [-o /etc/shorewall46]
shorewall-nft merge-config ... --guided            # Interactive collision resolution
shorewall-nft lookup <ip>                          # Query plugins for an IP
shorewall-nft enrich [dir]                         # Run plugins in-place (.bak backup)
shorewall-nft plugins list                         # Show loaded plugins
```

When `/etc/shorewall46` exists (from `merge-config`), it becomes the default
config source — the legacy `/etc/shorewall` and `/etc/shorewall6` directories
are ignored. Pass an explicit path to any command to override.

### Debug mode

`shorewall-nft debug` temporarily loads a debug-annotated ruleset where
every rule has:

- A **named counter** queryable via `nft list counter inet shorewall <name>`
- A **source comment** visible in `nft monitor trace`, showing the exact
  Shorewall source file, line number, and the original trimmed rule text:

```
trace id be38cfa4 inet shorewall ACCEPT-fw rule
  counter name "r_ACCEPT_fw_0000" accept
  comment "rules:38: ORG-ADM/ACCEPT net $FW"
  (verdict accept)
```

On `Ctrl+C` the original ruleset is automatically restored. If the
currently loaded ruleset's config hash differs from the on-disk config,
debug mode requires explicit confirmation before reloading.

### Config hash drift detection

Every emitted nft ruleset embeds a sha256 hash of its source config as a
table comment (`config-hash:<16-hex>`). `shorewall-nft status` compares
the loaded hash with the current on-disk source and warns if they differ:

```
  Config hash: c5cde3358773069a (loaded)
               6acbd4dc58cfe76b (on-disk) — DRIFT!
  WARNING: loaded ruleset differs from on-disk config. Run `shorewall-nft reload` to sync.
```

### OPTIMIZE levels

Set `OPTIMIZE=N` in `shorewall.conf`:

| Level | Optimization |
|-------|--------------|
| 1 | Remove rules unreachable via kernel `rp_filter` (routefilter heuristic) |
| 2 | Remove exact-duplicate rules within a chain |
| 3 | Remove ACCEPT-policy chains that have no user rules |
| 4 | Combine adjacent rules differing only in src/dst/port into anonymous sets |
| 8 | Merge chains with identical content (cross-chain dedup) |

Production reduction examples:
- fw-large: 18366 → 12806 nft lines (**30% smaller**)
- fw-medium: 12075 → 7598 nft lines (**37% smaller**)
- fw-small:     625 →  546 nft lines (**12% smaller**)

### Plugin system

Plugins extend shorewall-nft with IP lookups, v4↔v6 mappings, comment
block enrichment, and custom CLI commands. Configured via
`etc/shorewall/plugins.conf` (TOML) + `plugins/<name>.toml` per plugin.

Built-in plugins:

- **ip-info** — pattern-based v4↔v6 mapping per /24 subnet (fallback).
  Example: `203.0.113.65 → 2001:db8:0:100:203:0:113:65`.
- **netbox** — authoritative IPAM via Netbox API with local TTL cache.
  Links v4 and v6 addresses via shared `dns_name`. Extracts customer
  number from `tenant.name` format (`"12345 - Example Inc"`).

Plugins enhance `merge-config` by detecting paired v4/v6 params and
annotating mandant `?COMMENT` blocks with customer/host metadata.

## Architecture

```
shorewall_nft/
├── config/           # Shorewall config parser
│   ├── parser.py     # Column-based format, preprocessor (?IF, ?FORMAT, ?COMMENT)
│   ├── zones.py      # Zone/interface model
│   └── validate.py   # Config validation
├── compiler/         # Rule compiler
│   ├── ir.py         # Internal Representation (zone-pairs → chains → rules)
│   ├── nat.py        # SNAT/DNAT/Masquerade
│   ├── tc.py         # Traffic control / marks / DSCP
│   ├── actions.py    # Action chains (Drop, Reject, Broadcast, etc.)
│   ├── accounting.py # Accounting rules and counters
│   ├── providers.py  # Multi-ISP / policy routing
│   └── optimize.py   # Routefilter optimization
├── nft/              # nft backend
│   ├── emitter.py    # IR → nft -f script
│   ├── netlink.py    # libnftables / pyroute2 integration
│   ├── sets.py       # Named sets from ipset/init
│   ├── set_loader.py # External set loading (GeoIP, prefix files)
│   ├── objects.py    # Stateful objects (counters, ct helpers, synproxy)
│   ├── flowtable.py  # Hardware/software offloading
│   └── families.py   # Table families (inet, netdev, bridge)
├── netns/            # Network namespace support
│   ├── apply.py      # nft -f in target namespace
│   └── systemd.py    # systemd service templates
├── verify/           # Verification framework
│   ├── triangle.py   # Semantic comparison vs iptables baseline
│   ├── simulate.py   # 3-netns packet-level simulation
│   └── iptables_parser.py  # iptables-save parser
├── runtime/          # CLI and runtime
│   ├── cli.py        # Shorewall-compatible CLI (30 commands)
│   ├── sysctl.py     # Sysctl generation
│   └── monitor.py    # nft monitor trace
├── tools/
│   └── migrate.py    # Migration tool
└── main.py           # Entry point
```

## Supported Shorewall features

- **Config files**: params, shorewall.conf, zones, interfaces, hosts, policy, rules, masq, conntrack, notrack, blrules, routestopped, tcrules, tcdevices, tcinterfaces, tcclasses, tcfilters, tcpri, mangle, providers, routes, rtrules, tunnels, accounting, secmarks
- **Preprocessor**: ?FORMAT, ?SECTION, ?COMMENT, ?IF/?ELSIF/?ELSE/?ENDIF, ?SET, ?INCLUDE, ?REQUIRE, ?BEGIN PERL/?END PERL, DEFAULTS
- **Macros**: 149 standard macros + custom macros from macros/ directory, recursive expansion, SOURCE/DEST reversal
- **Actions**: Drop, Reject, Broadcast, Multicast, DropSmurfs, dropNotSyn, dropInvalid, AllowICMPs, DropDNSrep, Established, Invalid, BLACKLIST
- **NAT**: SNAT, DNAT, Masquerade, Redirect
- **Conntrack**: CT helpers (ftp, snmp, tftp, pptp), notrack, ct state
- **Interface options**: tcpflags, nosmurfs, routefilter, routeback, arp_filter, logmartians
- **Sets**: ipset → nft named sets, GeoIP sets, negated set lists, auto-dedup
- **Marks**: MARK, CONNMARK, RESTORE, SAVE, DSCP, CLASSIFY
- **Logging**: Shorewall-format log prefix, nft log levels
- **Default actions**: DROP_DEFAULT, REJECT_DEFAULT
- **Dynamic blacklist**: DYNAMIC_BLACKLIST with timeout support
- **AUDIT**: A_ACCEPT, A_DROP, A_REJECT

## Verification

### Static verification (triangle comparison)

```bash
shorewall-nft verify /etc/shorewall --iptables iptables-save.txt
# [PASS] 100.0% coverage (8281/8281) | 240/241 pairs | 0 order-conflicts
```

### Packet-level simulation

```bash
shorewall-nft simulate /etc/shorewall --iptables iptables-save.txt \
    --target 203.0.113.5 --max-tests 20 -V
```

Creates 3 network namespaces (shorewall-next-sim-src, shorewall-next-sim-fw, shorewall-next-sim-dst),
loads the compiled ruleset, and sends real TCP/UDP/ICMP packets
to validate firewall verdicts against the iptables baseline.

## systemd integration

```bash
# Generate service files
shorewall-nft generate-systemd              # shorewall-nft.service
shorewall-nft generate-systemd --netns      # shorewall-nft@.service (per-netns)

# Enable
systemctl enable shorewall-nft
systemctl enable shorewall-nft@fw           # For netns "fw"
```

## Migration from Shorewall

```bash
# Check migration readiness
shorewall-nft migrate /etc/shorewall --iptables iptables-save.txt --dry-run

# Steps:
# 1. Install shorewall-nft
# 2. Run migrate to verify
# 3. Generate systemd unit
# 4. shorewall-nft start
# 5. Disable shorewall, enable shorewall-nft
```

## License

GPL-2.0-only (same as Shorewall)
