---
title: Plugin system
description: Extend shorewall-nft with IP lookups, v4↔v6 mapping, and metadata enrichment plugins.
---

# Plugin system

shorewall-nft ships with an extensible plugin mechanism. Plugins can:

- Look up metadata for IP addresses (hostname, tenant, tags)
- Map between IPv4 and IPv6 addresses for the same host
- Enrich `?COMMENT` mandant blocks during `merge-config`
- Detect paired v4/v6 parameters in the params file
- Register their own CLI subcommands

## Configuration

Plugins are configured via TOML in the Shorewall config directory.

### `plugins.conf`

```toml
[[plugins]]
name = "ip-info"
enabled = true

[[plugins]]
name = "netbox"
enabled = true
```

### Per-plugin configs

Each plugin reads its own `plugins/<name>.toml`:

```
/etc/shorewall/
├── plugins.conf
└── plugins/
    ├── ip-info.toml
    ├── netbox.toml
    └── netbox-cache.json      # auto-managed cache
```

## Built-in plugins

### `ip-info` (priority 10 — fallback)

Pattern-based IPv4↔IPv6 mapping. Each configured `/24` subnet is linked
to a corresponding `/64` IPv6 prefix. The last 64 bits of the IPv6
address encode the IPv4 address directly as hex-looking decimal digits.

Example: `203.0.113.65` → `2001:db8:0:100:217:14:168:65`

```toml
# plugins/ip-info.toml
embedding = "v4-in-host"

[[mappings]]
v4_subnet = "203.0.113.0/24"
v6_prefix = "2001:db8:0:100::/64"

[[mappings]]
v4_subnet = "198.51.100.0/24"
v6_prefix = "2001:db8:0:200::/64"
```

CLI subcommands:

```
shorewall-nft ip-info v4-to-v6 203.0.113.65
shorewall-nft ip-info v6-to-v4 2001:db8:0:100:217:14:168:65
shorewall-nft ip-info list-mappings
```

### `netbox` (priority 100 — authoritative)

Netbox IPAM client. Links v4 and v6 addresses via shared `dns_name`
(not via device assignments, because at OrgName IPs are registered
without interface bindings). Extracts customer numbers from the
`tenant.name` field in the format `"NNNNNN - Company Name"`.

Two modes:

- **Online**: live API with token, optional bulk_subnets for efficient refresh
- **Snapshot**: offline JSON file (same format as shorewall2foomuuri) — good for CI

```toml
# plugins/netbox.toml
url = "https://netbox.example.com"
token = "..."                        # or token_file = "/etc/.../netbox.token"
cache_ttl = 86400
priority = 100

# Bulk mode: these subnets are fully pre-fetched on refresh.
# IPs outside are fetched on-demand.
bulk_subnets = [
    "203.0.113.0/24",
    "2001:db8::/32",
]
```

Secure the token file:

```bash
chmod 600 /etc/shorewall/plugins/netbox.toml
```

Or use `token_file =` to reference a separately-owned file:

```toml
token_file = "/etc/shorewall/plugins/netbox.token"
```

CLI subcommands:

```
shorewall-nft netbox refresh
shorewall-nft netbox lookup 203.0.113.86
shorewall-nft netbox by-dns mail.example.com
shorewall-nft netbox stats
```

## Priority ordering

Plugins are queried in descending priority order for lookups
(`map_v4_to_v6`, `map_v6_to_v4`, `lookup_ip`). The first plugin to
return a non-None result wins.

- `netbox` (priority 100): authoritative — asked first
- `ip-info` (priority 10): fallback — asked only if netbox has no mapping

For enrichment (`enrich_comment_block`, `enrich_params`), results from
all plugins are combined.

## Integration with `merge-config`

When `/etc/shorewall/plugins.conf` exists, `merge-config` automatically
uses the configured plugins to:

1. **Detect paired params**: `MAIL5=203.0.113.86` (v4) and
   `MAIL5=2001:db8:0:100:217:14:168:86` (v6) referring to the same
   host are grouped with a comment:
   ```
   # netbox: mail.example.com / Kunde 12345
   MAIL5=203.0.113.86
   MAIL5_V6=2001:db8:0:100:217:14:168:86
   ```

2. **Enrich `?COMMENT` mandant blocks** with customer/host metadata:
   ```
   ?COMMENT mandant-b
   # netbox: 2 customer(s): 12345 (Example Inc), 67890 (Another Customer Inc)
   # netbox: 3 known host(s):
   #   203.0.113.121 → test.example.com (cust: 67890)
   # ip-info: 2 v4/v6 host pair(s) detected (pattern-based)
   ...
   ```

Disable plugins for a single `merge-config` run with `--no-plugins`.

## Standalone usage

Plugins can be queried outside of `merge-config`:

```bash
# Aggregate lookup across all plugins
shorewall-nft lookup 203.0.113.86

# Refresh enrichment in an existing config (.bak backup created)
shorewall-nft enrich /etc/shorewall

# List loaded plugins
shorewall-nft plugins list
```

## Writing custom plugins

*(Planned: full developer guide in a future release.)*

A plugin is a Python class inheriting from
`shorewall_nft.plugins.base.Plugin`. Override the hook methods you
implement, set `name`, `version`, and `priority` class attributes, and
add your module to the built-in registry in
`shorewall_nft.plugins.manager._BUILTIN_PLUGINS`.

Hook methods:

| Method | When called |
|--------|-------------|
| `load()` | On plugin manager init; load cache/static data |
| `refresh()` | `shorewall-nft <plugin> refresh`; refresh from external source |
| `lookup_ip(ip)` | General IP lookup — return dict of metadata or None |
| `map_v4_to_v6(ip)` | Return a v6 address or None |
| `map_v6_to_v4(ip)` | Return a v4 address or None |
| `enrich_comment_block(tag, v4, v6)` | Annotate a `?COMMENT` block |
| `enrich_params(v4, v6)` | Detect paired v4/v6 params |
| `register_cli(cli_group)` | Add plugin-specific commands |
