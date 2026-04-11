---
title: Plugin development guide
description: How to write a custom shorewall-nft plugin — hooks, priority, CLI integration, packaging.
---

# Plugin development guide

shorewall-nft plugins are Python classes that hook into the config
pipeline to provide IP lookups, v4↔v6 mapping, metadata enrichment,
and custom CLI commands. This page walks through writing one from
scratch.

## Skeleton

A minimal plugin is a subclass of `shorewall_nft.plugins.base.Plugin`:

```python
# shorewall_nft/plugins/builtin/myplugin.py
from pathlib import Path
from shorewall_nft.plugins.base import Plugin, EnrichResult


class MyPlugin(Plugin):
    name = "myplugin"
    version = "1.0.0"
    priority = 50  # 100 = authoritative, 10 = fallback

    def __init__(self, config: dict, config_dir: Path):
        super().__init__(config, config_dir)
        # Read plugin-specific settings from config
        self.my_option = config.get("my_option", "default")

    def load(self) -> None:
        """Called once by the manager after __init__. Load cache or
        static data here. No network access — use refresh() for that."""

    def refresh(self) -> None:
        """Called by `shorewall-nft myplugin refresh` or automatically
        when a TTL expires. Do expensive I/O here."""
```

Register the class in `shorewall_nft/plugins/manager.py`:

```python
_BUILTIN_PLUGINS = {
    "ip-info": "shorewall_nft.plugins.builtin.ip_info:IpInfoPlugin",
    "netbox":  "shorewall_nft.plugins.builtin.netbox:NetboxPlugin",
    "myplugin": "shorewall_nft.plugins.builtin.myplugin:MyPlugin",
}
```

And enable it in `plugins.conf`:

```toml
[[plugins]]
name = "myplugin"
enabled = true
```

Plugin-specific config is read from `plugins/myplugin.toml`:

```toml
my_option = "hello"
```

## Hook methods

Override only the hooks you need. Unimplemented hooks return `None` or
empty results and are skipped by the manager.

### `lookup_ip(ip: str) -> dict | None`

Return arbitrary metadata for an IP. Multiple plugins' results are
merged by the manager, with higher-priority plugins overriding lower
ones on key conflicts.

```python
def lookup_ip(self, ip: str) -> dict | None:
    if ip in self._cache:
        return {
            "hostname": self._cache[ip]["hostname"],
            "tenant":   self._cache[ip]["tenant"],
            "source":   "myplugin",
        }
    return None
```

### `map_v4_to_v6(ip: str) -> str | None`

Given a v4 address, return its v6 equivalent (or None if unknown).
Called in priority order — the first plugin to return a non-None wins.

```python
def map_v4_to_v6(self, ip: str) -> str | None:
    if ip.startswith("10."):
        return "fd00::" + ip.rsplit(".", 1)[-1]
    return None
```

### `map_v6_to_v4(ip: str) -> str | None`

Inverse of `map_v4_to_v6`.

### `enrich_comment_block(tag, v4_rules, v6_rules) -> EnrichResult`

Called during `merge-config` for each `?COMMENT`-tagged block. Return
an `EnrichResult` to annotate the block. Useful for adding customer
metadata, stale-IP warnings, or auto-generated rule comments.

```python
from shorewall_nft.plugins.base import EnrichResult

def enrich_comment_block(self, tag, v4_rules, v6_rules):
    comments = [f"# myplugin: block '{tag}' "
                f"has {len(v4_rules)} v4 rules, "
                f"{len(v6_rules)} v6 rules"]
    return EnrichResult(prepend_comments=comments)
```

`EnrichResult` fields:

- `tag`: if set, rename the `?COMMENT` tag (e.g. `"mandant-b (Kunde 12345)"`)
- `prepend_comments`: shell-style comments inserted after the opening tag
- `append_comments`: inserted before the closing tag
- `replace_rules`: replace the entire block body
- `drop`: if True, remove the block entirely

### `enrich_params(v4_params, v6_params) -> ParamEnrichResult`

Detect paired variables during `merge-config`. Pairs are variables
that refer to the same host in v4 and v6. Marking them as pairs causes
`merge-config` to emit both variants with a grouping comment instead
of silently renaming the v6 one.

```python
from shorewall_nft.plugins.base import ParamEnrichResult

def enrich_params(self, v4_params, v6_params):
    result = ParamEnrichResult()
    for varname, v4_line in v4_params.items():
        if varname in v6_params and varname.startswith("MAIL"):
            result.pairs[varname] = (v4_line, v6_params[varname])
            result.annotations[varname] = f"# myplugin: mail host pair"
    return result
```

### `register_cli(cli_group: click.Group)`

Add plugin-specific commands under a subgroup named after the plugin:

```python
def register_cli(self, cli_group):
    plugin_self = self

    @cli_group.group("myplugin")
    def myplugin_cmd():
        """My plugin: description here."""

    @myplugin_cmd.command("refresh")
    def refresh_cmd():
        plugin_self.refresh()
        click.echo("Done.")

    @myplugin_cmd.command("lookup")
    @click.argument("ip")
    def lookup_cmd(ip):
        info = plugin_self.lookup_ip(ip)
        click.echo(json.dumps(info, indent=2) if info else "Not found")
```

Plugin commands are available as `shorewall-nft myplugin refresh`,
`shorewall-nft myplugin lookup 1.2.3.4`, etc.

**Important**: CLI commands are only registered when `plugins.conf`
exists in the default config directory at module load time. Plugin
commands don't currently honor `--config-dir` because click needs them
registered before parsing the top-level options.

## Priority conventions

| Range | Meaning |
|-------|---------|
| 100+ | Authoritative source (e.g. IPAM system) |
| 50-99 | Derived / computed sources |
| 10-49 | Heuristic fallbacks |
| 0-9 | Last resort, debug |

The manager sorts plugins by `priority` descending. For
`map_v4_to_v6` and `lookup_ip`, the first plugin with a non-None
answer wins. For `enrich_comment_block` and `enrich_params`, all
plugins contribute and results are merged.

The user can override the priority via `plugins/myplugin.toml`:

```toml
priority = 95  # override the class default
```

## Lifecycle

```
shorewall-nft start
    ↓
PluginManager(__init__)
    ↓
  for each enabled plugin:
    plugin = PluginClass(config, config_dir)
    plugin.load()                # ← sync cache load
    ↓
shorewall-nft <plugin-cmd>
    ↓
  plugin.refresh()               # ← explicit refresh
    ↓
shorewall-nft merge-config
    ↓
  manager.enrich_comment_block(...)
  manager.enrich_params(...)
```

## Config conventions

- Plugin configs live in `<config_dir>/plugins/<name>.toml`
- Secrets go in separate files referenced via `token_file = "..."`
- Cache files go next to the config: `<config_dir>/plugins/<name>-cache.json`
- Never write outside `<config_dir>/plugins/`

## Testing

Write unit tests under `tests/test_<plugin>.py`. Use a fresh
`tmp_path` for `config_dir` in each test:

```python
import pytest
from pathlib import Path
from shorewall_nft.plugins.builtin.myplugin import MyPlugin

@pytest.fixture
def plugin(tmp_path):
    (tmp_path / "plugins").mkdir()
    p = MyPlugin(config={"my_option": "test"}, config_dir=tmp_path)
    p.load()
    return p

def test_lookup(plugin):
    assert plugin.lookup_ip("1.2.3.4") is None
```

For plugins with external APIs, mock `urllib.request.urlopen` rather
than hitting the network:

```python
from unittest.mock import patch

def test_api_lookup(plugin):
    with patch.object(plugin, "_fetch_on_demand",
                      return_value={"hostname": "test"}):
        assert plugin.lookup_ip("1.2.3.4")["hostname"] == "test"
```

## Example: a country-code plugin

Here's a minimal complete plugin that annotates rules with GeoIP
country codes:

```python
# shorewall_nft/plugins/builtin/geoip.py
import ipaddress
from pathlib import Path
from shorewall_nft.plugins.base import Plugin, EnrichResult
from shorewall_nft.plugins.utils import extract_ipv4, extract_ipv6


class GeoIpPlugin(Plugin):
    name = "geoip"
    version = "1.0.0"
    priority = 30

    def __init__(self, config, config_dir):
        super().__init__(config, config_dir)
        self.ranges: list[tuple[ipaddress.IPv4Network, str]] = []

    def load(self):
        """Load CIDR→country map from a simple CSV."""
        csv_path = self.config_dir / "plugins" / "geoip.csv"
        if not csv_path.exists():
            return
        for line in csv_path.read_text().splitlines():
            if line.startswith("#") or not line.strip():
                continue
            cidr, country = line.strip().split(",", 1)
            self.ranges.append(
                (ipaddress.ip_network(cidr.strip()), country.strip()))

    def lookup_ip(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, country in self.ranges:
            if addr in net:
                return {"country": country, "source": "geoip"}
        return None

    def enrich_comment_block(self, tag, v4_rules, v6_rules):
        countries = set()
        for rule in v4_rules + v6_rules:
            for ip in extract_ipv4(rule) + extract_ipv6(rule):
                info = self.lookup_ip(ip)
                if info:
                    countries.add(info["country"])
        if not countries:
            return EnrichResult()
        return EnrichResult(
            prepend_comments=[f"# geoip: countries: "
                              f"{', '.join(sorted(countries))}"])
```

Register in `manager.py`, enable in `plugins.conf`, drop a
`plugins/geoip.csv` like:

```
# CIDR,country
8.8.8.0/24,US
1.1.1.0/24,US
2001:db8::/32,DE
```

Run it:

```bash
shorewall-nft lookup 8.8.8.8
# { "country": "US", "source": "geoip", ... }

shorewall-nft merge-config /etc/shorewall /etc/shorewall6
# → mandant blocks gain "# geoip: countries: DE, US" annotations
```

## Packaging

Built-in plugins live under `shorewall_nft/plugins/builtin/`. Third-party
plugins can either:

1. **Vendor**: copy the class into `shorewall_nft/plugins/builtin/` and
   register in `manager.py` (requires a shorewall-nft fork or patch)
2. **Future**: pip entry-points (`[project.entry-points."shorewall_nft.plugins"]`
   in your own `pyproject.toml`) — **not yet implemented**, planned
   for a later release

For now, vendor-and-register is the supported path.

## Error handling

Plugin failures are caught by the manager and logged as warnings —
they never abort the compile or merge. If your plugin can't reach its
data source, return `None` gracefully:

```python
def lookup_ip(self, ip):
    try:
        return self._fetch(ip)
    except (ConnectionError, TimeoutError):
        return None  # manager will try the next plugin
```

## See also

- [Plugin system overview](plugins.md) — user-facing docs
- `shorewall_nft/plugins/base.py` — full `Plugin` and result classes
- `shorewall_nft/plugins/builtin/ip_info.py` — simple pattern-based plugin
- `shorewall_nft/plugins/builtin/netbox.py` — complex plugin with API + cache
