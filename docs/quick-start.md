---
title: Quick Start
description: Get shorewall-nft running in minutes — beginner and experienced-admin paths
---

# Quick Start

Two paths depending on your starting point:

- **[Beginner](#beginner-path)** — first Shorewall-style firewall, learning the config language
- **[Experienced admin](#experienced-admin-path)** — existing Shorewall config, migration to nftables

---

## Beginner path

### What you are getting

`shorewall-nft` is a firewall compiler. You describe your network in plain
text config files (zones, interfaces, rules, NAT) and it generates a
correct, atomic nftables ruleset and loads it into the kernel. You never
write raw nft syntax.

### Requirements

- Linux kernel ≥ 5.8 with nftables (`nft` binary from `nftables` package)
- Python 3.11+
- `iproute2` (`ip` binary)
- Recommended: `python3-nftables` system package (libnftables bindings;
  falls back to subprocess otherwise)

### Install

```bash
# From a Git checkout (development):
python3 -m venv .venv && source .venv/bin/activate
pip install -e 'packages/shorewall-nft[dev]'

# From PyPI (release):
pip install shorewall-nft

# Debian/Ubuntu:
apt install shorewall-nft

# Fedora/RHEL:
dnf install shorewall-nft
```

### Your first config

The minimum working config for a single-host firewall lives in three files
under `/etc/shorewall/`:

**`/etc/shorewall/zones`**
```
#ZONE    TYPE
fw       firewall
net      ipv4
```

**`/etc/shorewall/interfaces`**
```
#ZONE    INTERFACE    OPTIONS
net      eth0         dhcp,tcpflags,nosmurfs
```

**`/etc/shorewall/policy`**
```
#SOURCE    DEST    POLICY    LOG
fw         net     ACCEPT
net        fw      DROP      info
net        all     DROP      info
all        all     REJECT    info
```

**`/etc/shorewall/rules`** (optional — add exceptions to the policy)
```
#ACTION    SOURCE    DEST    PROTO    DPORT
ACCEPT     net       fw      tcp      22    # allow inbound SSH
```

### Validate and start

```bash
# Check config without loading:
shorewall-nft check /etc/shorewall

# Compile and preview (no kernel changes):
shorewall-nft compile /etc/shorewall

# Load the ruleset:
sudo shorewall-nft start /etc/shorewall

# Verify it is running:
shorewall-nft status
```

The status output shows the loaded config hash, zone summary, and whether
the ruleset is loaded in the kernel.

### Next steps

- [Configuration file basics](reference/configuration_file_basics.md) —
  column format, variables, preprocessor directives
- [Concepts: Introduction](concepts/Introduction.md) — zones, policies,
  rules explained
- [Two-interface setup](reference/two-interface.md) — LAN + internet
  example
- [Three-interface setup](reference/three-interface.md) — LAN + DMZ +
  internet example
- [CLI reference](cli/commands.md) — all 36 commands
- [Named dynamic nft sets (nfsets)](features/nfsets.md) — hostname-based
  and IP-list rules without hardcoding addresses

---

## Experienced admin path

For admins with an existing Shorewall config who want to switch to the
nftables backend.

### Migration from Shorewall

Your existing `/etc/shorewall` loads unchanged. No config edits required
for basic operation. Check for surprises first:

```bash
# Dry-run: show what would differ from your running iptables
shorewall-nft migrate /etc/shorewall --iptables iptables-save.txt --dry-run

# Verify the compiled nft output matches your iptables baseline:
shorewall-nft verify /etc/shorewall --iptables iptables-save.txt
# [PASS] 100.0% coverage (8281/8281) | 240/241 pairs | 0 order-conflicts
```

If `verify` passes, you are done. Replace `shorewall` with `shorewall-nft`
in your systemd unit or cron job.

### Dual-stack merge (IPv4 + IPv6 in one config)

If you have separate `/etc/shorewall` and `/etc/shorewall6`, merge them
into a single `inet` table config:

```bash
# Interactive collision resolution:
shorewall-nft merge-config /etc/shorewall /etc/shorewall6 --guided \
    -o /etc/shorewall46

# When /etc/shorewall46 exists, it becomes the default automatically.
# The legacy directories are ignored.
shorewall-nft start   # picks up /etc/shorewall46 automatically
```

See [merge-config](shorewall-nft/merge-config.md) for details on the six
config-dir modes and collision types.

### systemd integration

```bash
# Generate and install the service unit:
shorewall-nft generate-systemd > /etc/systemd/system/shorewall-nft.service
systemctl daemon-reload
systemctl enable --now shorewall-nft

# Network-namespace variant (one unit per netns):
shorewall-nft generate-systemd --netns > \
    /etc/systemd/system/shorewall-nft@.service
systemctl enable --now shorewall-nft@fw
```

### Plugin enrichment (Netbox, IP-INFO)

Plugins annotate your config with IPAM data from Netbox or IP-INFO, turning
IP addresses into named customer blocks:

```bash
# Configure:
cat > /etc/shorewall46/plugins/netbox.toml <<'EOF'
url = "https://netbox.example.com/"
token_file = "/etc/shorewall46/plugins/netbox.token"
EOF

# Enrich in-place (creates .bak backup):
shorewall-nft enrich /etc/shorewall46

# Test a single IP:
shorewall-nft lookup 203.0.113.42
```

See [plugins](shorewall-nft/plugins.md) and [plugin development](shorewall-nft/plugin-development.md).

### DNS-based dynamic sets

Allow or deny traffic to hostnames — the firewall tracks A/AAAA records
and keeps nft sets in sync:

```
# /etc/shorewall46/rules
ACCEPT    fw    net:dnst:updates.example.org    tcp    443
```

Requires the `shorewalld` companion daemon. See [shorewalld](shorewalld/index.md).

> **See also**: [nfsets](features/nfsets.md) — named dynamic sets with multiple hostnames
> per set, non-DNS backends (URL blocklists, cloud prefix lists), and explicit naming
> for tooling/monitoring. Use `nfset:<name>` in rules instead of `dns:`/`dnsr:` when
> you need any of those features.

### Prometheus metrics

`shorewalld` also exports per-rule packet/byte counters to Prometheus:

```bash
# Install:
pip install 'shorewall-nft[daemon]'

# Start exporter (scrapes all netns automatically):
shorewalld --listen-prom :9748 --netns auto

# Or via systemd:
systemctl enable --now shorewalld
```

Metrics endpoint: `http://localhost:9748/metrics`

See [shorewalld](shorewalld/index.md#metrics).

### Optimizer

Set `OPTIMIZE=15` in `shorewall.conf` to enable all passes. Rule sets
typically shrink 30–37%:

```bash
echo "OPTIMIZE=15" >> /etc/shorewall46/shorewall.conf
shorewall-nft compile /etc/shorewall46 | wc -l    # before vs after
```

See [optimizer](shorewall-nft/optimizer.md).

### Debug mode

Temporarily load a counter-annotated ruleset and watch which rules fire:

```bash
sudo shorewall-nft debug /etc/shorewall46 --netns fw
# Keep running — hit Ctrl+C to restore the original ruleset
```

```bash
# In another terminal:
shorewall-nft counters --netns fw | grep -v ' 0 packets'
nft monitor trace   # every matched packet shows file:line:rule
```

See [debug mode](shorewall-nft/debug.md).

### Testing your ruleset

```bash
# Packet-level simulation against your iptables baseline:
shorewall-nft simulate /etc/shorewall46 --iptables iptables-save.txt \
    --target 203.0.113.5 --max-tests 50

# Full simlab run (network namespaces, real packet injection):
python -m shorewall_nft_simlab.smoketest full --random 50 --seed 42
```

See [testing overview](testing/index.md) and [simlab](testing/simlab.md).
