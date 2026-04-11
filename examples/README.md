# Example configurations

This directory contains ready-to-copy example files for shorewall-nft
features that don't come with a Shorewall upstream reference.

## Plugin configurations

- **`plugins.conf`** — master plugin registry (which plugins to enable)
- **`plugins/ip-info.toml`** — pattern-based v4↔v6 mapping (pattern-based)
- **`plugins/netbox.toml`** — Netbox IPAM integration (online + snapshot modes)

### Install

```bash
# Copy to your Shorewall config directory
sudo cp plugins.conf /etc/shorewall/
sudo mkdir -p /etc/shorewall/plugins
sudo cp plugins/ip-info.toml /etc/shorewall/plugins/
sudo cp plugins/netbox.toml /etc/shorewall/plugins/

# Edit the netbox config with your URL / token / subnets
sudo $EDITOR /etc/shorewall/plugins/netbox.toml

# Secure the config (API token is in there — or in a separate file)
sudo chmod 600 /etc/shorewall/plugins/netbox.toml

# Verify plugins load
shorewall-nft plugins list
```

### Test lookups

```bash
# Refresh the netbox cache
sudo shorewall-nft netbox refresh

# Aggregated lookup across plugins
shorewall-nft lookup 203.0.113.86

# Pattern-based IPv6 derivation
shorewall-nft ip-info v4-to-v6 203.0.113.65
```

## Merge-config

See [`docs/shorewall-nft/merge-config.md`](../docs/shorewall-nft/merge-config.md)
for the full workflow. Minimal example:

```bash
shorewall-nft merge-config /etc/shorewall /etc/shorewall6
# → writes /etc/shorewall46/
```

Subsequent `shorewall-nft start` / `status` / `reload` commands will
automatically use `/etc/shorewall46`.
