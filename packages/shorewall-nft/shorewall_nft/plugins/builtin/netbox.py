"""Netbox plugin: authoritative v4↔v6 mapping via dns_name.

Uses Netbox IPAM API to:
- Map v4 addresses to v6 addresses sharing the same dns_name
- Lookup tenant/hostname/status metadata
- Cache results locally with TTL-based refresh

Why dns_name linking and not device assignments?
In many real-world Netbox deployments, IP addresses are NOT assigned to
interfaces/devices (`assigned_object_type` is null). The only reliable
cross-family link
between a v4 and its v6 counterpart is a shared `dns_name`. Example:
    v4 203.0.113.86 + v6 2001:db8:0:100:203:0:113:86 → both dns_name mail.example.com
The v6 address is NOT always pattern-derived from the v4 — sometimes they
differ (e.g. v4 .183 ↔ v6 :46 for the same dns_name). This makes Netbox
authoritative and the ip-info pattern plugin a fallback.

Field mapping (derived from real Netbox 4.5+ schema):
- tenant.name       → "NNNNNN - Company GmbH" (customer number embedded)
- dns_name          → hostname (key for v4↔v6 linking)
- status.value      → active/reserved/deprecated/decommissioning
- assigned_object   → usually null at OrgName (not used for linking)
- tags[]            → usually empty at OrgName (but supported)
- role              → usually null at OrgName (but supported)

Two operating modes:
- Online: hits Netbox API with token
- Snapshot: reads a pre-generated JSON file (for CI/offline)

Configuration (plugins/netbox.toml):
    url = "https://netbox.example.com"
    token = "..."
    snapshot = "path/to/snapshot.json"  # alternative to url+token
    cache_ttl = 86400
    bulk_subnets = ["203.0.113.0/24", "2001:db8::/32"]

FUTURE (planned, not yet implemented): the plugin will also read the
same keys (NETBOX_URL, NETBOX_TOKEN, NETBOX_CACHE_TTL, ...) straight
out of ``/etc/shorewall46/shorewall.conf`` as shell-style
assignments, layered *below* ``plugins/netbox.toml`` (toml wins on
collision). That lets operators keep a single config file for
everything. The global CLI flag ``--override-json`` will then layer
dynamic JSON on top of shorewall.conf at runtime. Load order will
be:  defaults → shorewall.conf → plugins/netbox.toml → --override-json.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import click

from shorewall_nft.plugins.base import (
    EnrichResult,
    ParamEnrichResult,
    Plugin,
)
from shorewall_nft.plugins.utils import (
    extract_ipv4,
    extract_ipv6,
    ip_in_subnet,
    is_ipv4,
    is_ipv6,
)

# Netbox statuses — values from the API status.value field
ACTIVE_STATUSES = frozenset({"active", "reserved", "dhcp", "slaac"})
STALE_STATUSES = frozenset({"deprecated", "decommissioning"})

# Tenant-name format: "NNNNNN - Company Name"
_TENANT_CUSTOMER_RE = re.compile(r"^(\d+)\s*-\s*(.+)$")


def _parse_tenant(name: str) -> tuple[str | None, str]:
    """Extract customer number and name from tenant string.

    Returns (customer_number, display_name).
    For "12345 - Example Inc" → ("12345", "Example Inc")
    For "OrgName" → (None, "OrgName")
    """
    if not name:
        return None, ""
    m = _TENANT_CUSTOMER_RE.match(name)
    if m:
        return m.group(1), m.group(2).strip()
    return None, name


class NetboxPlugin(Plugin):
    """Netbox IPAM plugin — authoritative v4↔v6 mapping via device assignments."""

    name = "netbox"
    version = "1.0.0"
    priority = 100  # High — asked before ip-info

    def __init__(self, config: dict, config_dir: Path):
        super().__init__(config, config_dir)
        self.url = config.get("url", "").rstrip("/")
        self.token = self._load_token(config)
        self.snapshot_path = config.get("snapshot")
        self.cache_ttl = config.get("cache_ttl", 86400)
        self.timeout = config.get("timeout", 30)
        self.priority = config.get("priority", self.priority)
        self.bulk_subnets: list[str] = config.get("bulk_subnets", [])

        self.cache_file = config_dir / "plugins" / "netbox-cache.json"
        self._cache: dict = {
            "_meta": {"refreshed_at": 0, "bulk_subnets": []},
            "by_ip": {},
            "by_dns_name": {},  # dns_name → list of IPs sharing that name
        }
        # On-demand fetches mark the cache dirty; periodic flush keeps
        # disk I/O amortized across many lookups. Flushed at most every
        # _dirty_flush_interval on-demand fetches, or on explicit
        # flush_cache() calls (e.g. on shutdown).
        self._dirty_count: int = 0
        self._dirty_flush_interval: int = config.get(
            "dirty_flush_interval", 50)

    def _load_token(self, config: dict) -> str:
        """Load API token from direct config or from token_file."""
        token = config.get("token", "")
        token_file = config.get("token_file")
        if token_file and not token:
            try:
                token = Path(token_file).read_text().strip()
            except OSError:
                pass
        return token

    # ── Lifecycle ──

    def load(self) -> None:
        """Load cache from disk if present, or snapshot file in snapshot mode."""
        if self.snapshot_path:
            self._load_snapshot()
            return
        if self.cache_file.exists():
            try:
                self._cache = json.loads(self.cache_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass

    def _load_snapshot(self) -> None:
        """Load data from a pre-generated Netbox snapshot JSON file.

        Snapshot format (compatible with shorewall2foomuuri):
            {
              "ip_addresses": {
                "203.0.113.86": {
                  "address": "203.0.113.86/32",
                  "dns_name": "mail.example.com",
                  "tenant": "12345 - Example Inc",
                  "tags": ["production", "mail"],
                  "status": "active",
                  ...
                }
              }
            }
        """
        path = Path(self.snapshot_path)
        if not path.is_absolute():
            path = self.config_dir / path
        if not path.exists():
            return

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return

        by_ip: dict = {}
        by_dns_name: dict = {}

        for ip_raw, raw in data.get("ip_addresses", {}).items():
            try:
                ip = str(ipaddress.ip_address(ip_raw))
            except ValueError:
                ip = ip_raw
            tenant_raw = raw.get("tenant") or ""
            customer_number, tenant_name = _parse_tenant(tenant_raw)
            dns_name = (raw.get("dns_name") or "").strip().lower()
            entry = {
                "dns_name": dns_name,
                "description": raw.get("description", ""),
                "tags": list(raw.get("tags", [])),
                "tenant": tenant_name,
                "tenant_slug": None,
                "customer": customer_number,
                "role": raw.get("role"),
                "status": raw.get("status", "active"),
                "last_modified": raw.get("last_modified"),
            }
            by_ip[ip] = entry
            if dns_name:
                by_dns_name.setdefault(dns_name, []).append(ip)

        self._cache = {
            "_meta": {
                "refreshed_at": int(time.time()),
                "bulk_subnets": [],
                "snapshot": str(path),
            },
            "by_ip": by_ip,
            "by_dns_name": by_dns_name,
        }

    def refresh(self) -> None:
        """Refresh cache: from snapshot or by querying the API."""
        if self.snapshot_path:
            self._load_snapshot()
            return

        if not self.url or not self.token:
            return

        new_by_ip: dict = {}
        new_by_dns_name: dict = {}

        if self.bulk_subnets:
            for subnet in self.bulk_subnets:
                for ip_obj in self._fetch_ips(parent=subnet):
                    self._index_ip(ip_obj, new_by_ip, new_by_dns_name)
        else:
            for ip_obj in self._fetch_ips():
                self._index_ip(ip_obj, new_by_ip, new_by_dns_name)

        self._cache = {
            "_meta": {
                "refreshed_at": int(time.time()),
                "bulk_subnets": list(self.bulk_subnets),
            },
            "by_ip": new_by_ip,
            "by_dns_name": new_by_dns_name,
        }
        self._save_cache()

    def _save_cache(self) -> None:
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.cache_file.write_text(json.dumps(self._cache, indent=2))

    def _is_cache_stale(self) -> bool:
        refreshed = self._cache.get("_meta", {}).get("refreshed_at", 0)
        return (time.time() - refreshed) > self.cache_ttl

    def _auto_refresh_if_needed(self) -> None:
        """Refresh cache if stale and we have credentials or snapshot."""
        if not self._is_cache_stale():
            return
        if self.snapshot_path or (self.url and self.token):
            try:
                self.refresh()
            except Exception as e:
                print(f"Warning: netbox refresh failed: {e}", file=sys.stderr)

    # ── API helpers ──

    def _fetch_ips(self, parent: str | None = None,
                   address: str | None = None) -> list[dict]:
        """Fetch IP addresses from Netbox with cursor-based pagination."""
        results: list[dict] = []
        params: dict = {"limit": 1000}
        if parent:
            params["parent"] = parent
        if address:
            params["address"] = address

        url: str | None = (
            f"{self.url}/api/ipam/ip-addresses/?"
            + urllib.parse.urlencode(params)
        )
        max_pages = 50
        page = 0
        while url and page < max_pages:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Token {self.token}",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
            results.extend(data.get("results", []))
            url = data.get("next")
            page += 1
        return results

    def _index_ip(self, ip_obj: dict, by_ip: dict, by_dns_name: dict) -> None:
        """Insert a Netbox IP object into the cache indexes.

        Normalizes IPv6 addresses so lookups work regardless of notation.
        """
        address = ip_obj.get("address", "")
        if not address:
            return
        ip_raw = address.split("/")[0]
        # Normalize (especially for IPv6: "2001:db8:0:100:203:0:113:86"
        # stays as-is but ensures consistent format)
        try:
            ip = str(ipaddress.ip_address(ip_raw))
        except ValueError:
            ip = ip_raw

        # Tags: use slug (matches shorewall2foomuuri convention)
        tags = []
        for t in ip_obj.get("tags", []):
            if isinstance(t, dict):
                slug = t.get("slug") or t.get("name")
                if slug:
                    tags.append(slug)
            elif isinstance(t, str):
                tags.append(t)

        # Status: {"value": "active", "label": "Active"}
        status = ""
        status_obj = ip_obj.get("status")
        if isinstance(status_obj, dict):
            status = status_obj.get("value", "")
        elif isinstance(status_obj, str):
            status = status_obj

        # Tenant: {"id": 1, "name": "12345 - Example Inc", "slug": "..."}
        # Extract customer number and display name
        tenant_name = None
        tenant_slug = None
        customer_number = None
        tenant_obj = ip_obj.get("tenant")
        if isinstance(tenant_obj, dict):
            raw_name = tenant_obj.get("name") or ""
            tenant_slug = tenant_obj.get("slug")
            customer_number, tenant_name = _parse_tenant(raw_name)

        # Role: {"value": "host", "label": "Host"} — usually null at OrgName
        role = None
        role_obj = ip_obj.get("role")
        if isinstance(role_obj, dict):
            role = role_obj.get("label") or role_obj.get("value")

        dns_name = (ip_obj.get("dns_name") or "").strip().lower()

        entry = {
            "dns_name": dns_name,
            "description": ip_obj.get("description", "") or "",
            "tags": tags,
            "tenant": tenant_name,
            "tenant_slug": tenant_slug,
            "customer": customer_number,
            "role": role,
            "status": status,
            "last_modified": ip_obj.get("last_updated"),
        }

        by_ip[ip] = entry

        if dns_name:
            ips = by_dns_name.setdefault(dns_name, [])
            if ip not in ips:
                ips.append(ip)

    # ── Lookups ──

    def _lookup_cached(self, ip: str) -> dict | None:
        return self._cache.get("by_ip", {}).get(ip)

    def _is_in_bulk_subnets(self, ip: str) -> bool:
        return any(ip_in_subnet(ip, sn) for sn in self.bulk_subnets)

    def _fetch_on_demand(self, ip: str) -> dict | None:
        """Fetch a single IP from Netbox on-demand and cache it.

        Only works in API mode, not snapshot mode.
        """
        if self.snapshot_path or not self.url or not self.token:
            return None
        try:
            ips = self._fetch_ips(address=ip)
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return None
        if not ips:
            return None
        self._index_ip(ips[0], self._cache["by_ip"], self._cache["by_dns_name"])
        self._save_cache()
        return self._cache["by_ip"].get(ip)

    def lookup_ip(self, ip: str) -> dict | None:
        """Return metadata dict for an IP, or None."""
        self._auto_refresh_if_needed()

        entry = self._lookup_cached(ip)
        if entry is not None:
            return dict(entry)

        if not self._is_in_bulk_subnets(ip):
            entry = self._fetch_on_demand(ip)
            if entry is not None:
                return dict(entry)

        return None

    def map_v4_to_v6(self, ip: str) -> str | None:
        """Find v6 with the same dns_name as this v4.

        At OrgName, IPs are linked via dns_name (not device assignment).
        If multiple v6 addresses share the same dns_name, returns the first.
        """
        if not is_ipv4(ip):
            return None
        self._auto_refresh_if_needed()

        entry = self._lookup_cached(ip)
        if entry is None and not self._is_in_bulk_subnets(ip):
            entry = self._fetch_on_demand(ip)
        if entry is None:
            return None

        dns_name = entry.get("dns_name")
        if not dns_name:
            return None

        for other_ip in self._cache.get("by_dns_name", {}).get(dns_name, []):
            if is_ipv6(other_ip):
                return other_ip
        return None

    def map_v6_to_v4(self, ip: str) -> str | None:
        """Find v4 with the same dns_name as this v6."""
        if not is_ipv6(ip):
            return None
        self._auto_refresh_if_needed()

        try:
            normalized = str(ipaddress.IPv6Address(ip))
        except ValueError:
            return None

        entry = self._lookup_cached(normalized) or self._lookup_cached(ip)
        if entry is None and not self._is_in_bulk_subnets(normalized):
            entry = self._fetch_on_demand(normalized)
        if entry is None:
            return None

        dns_name = entry.get("dns_name")
        if not dns_name:
            return None

        for other_ip in self._cache.get("by_dns_name", {}).get(dns_name, []):
            if is_ipv4(other_ip):
                return other_ip
        return None

    # ── Enrichment hooks ──

    def enrich_comment_block(
        self, tag: str, v4_rules: list[str], v6_rules: list[str]
    ) -> EnrichResult:
        """Collect tenant/hostname info from all IPs in the block."""
        all_ips: set[str] = set()
        for rule in v4_rules:
            all_ips.update(extract_ipv4(rule))
        for rule in v6_rules:
            for v6 in extract_ipv6(rule):
                try:
                    all_ips.add(str(ipaddress.IPv6Address(v6)))
                except ValueError:
                    pass

        hosts: list[tuple[str, dict]] = []
        # Group by customer number (if available) or tenant name
        customers: dict[str, str] = {}  # {customer_id or tenant: tenant_name}
        stale_ips: list[str] = []

        for ip in sorted(all_ips):
            info = self._lookup_cached(ip)
            if info:
                hosts.append((ip, info))
                cust = info.get("customer")
                tenant = info.get("tenant") or ""
                if cust:
                    customers[cust] = tenant
                elif tenant:
                    customers[tenant] = tenant
                if info.get("status") in STALE_STATUSES:
                    stale_ips.append(ip)

        if not hosts:
            return EnrichResult()

        comments = []
        if customers:
            # Show customer number + name: "12345 (Example Inc)"
            parts = []
            for key, name in sorted(customers.items()):
                if key != name:
                    parts.append(f"{key} ({name})")
                else:
                    parts.append(key)
            comments.append(f"# netbox: {len(customers)} customer(s): "
                            f"{', '.join(parts)}")

        if stale_ips:
            comments.append(f"# netbox: WARNING {len(stale_ips)} stale IP(s):")
            for ip in stale_ips[:5]:
                comments.append(f"#   {ip}")

        comments.append(f"# netbox: {len(hosts)} known host(s):")
        for ip, info in hosts[:10]:
            dns_name = info.get("dns_name", "?")
            tags = info.get("tags") or []
            tag_str = f" [{','.join(tags)}]" if tags else ""
            cust = info.get("customer") or info.get("tenant") or ""
            cust_str = f" (cust {cust})" if cust else ""
            comments.append(f"#   {ip} → {dns_name}{tag_str}{cust_str}")
        if len(hosts) > 10:
            comments.append(f"#   ... and {len(hosts) - 10} more")

        # Optional: rename tag if single customer
        new_tag = None
        if len(customers) == 1:
            key = next(iter(customers))
            name = customers[key]
            if key != name:
                new_tag = f"{tag} (Kunde {key} {name})"
            else:
                new_tag = f"{tag} ({name})"

        return EnrichResult(tag=new_tag, prepend_comments=comments)

    def enrich_params(
        self, v4_params: dict[str, str], v6_params: dict[str, str]
    ) -> ParamEnrichResult:
        """Detect paired params via shared dns_name in Netbox."""
        result = ParamEnrichResult()
        for varname, v4_line in v4_params.items():
            if varname not in v6_params:
                continue
            v6_line = v6_params[varname]
            v4_ips = extract_ipv4(v4_line)
            v6_ips = extract_ipv6(v6_line)
            if not v4_ips or not v6_ips:
                continue

            v4_entry = self._lookup_cached(v4_ips[0])
            if v4_entry is None:
                continue
            try:
                v6_norm = str(ipaddress.IPv6Address(v6_ips[0]))
            except ValueError:
                continue
            v6_entry = self._lookup_cached(v6_norm)
            if v6_entry is None:
                continue

            v4_dns = v4_entry.get("dns_name")
            v6_dns = v6_entry.get("dns_name")
            if v4_dns and v4_dns == v6_dns:
                result.pairs[varname] = (v4_line, v6_line)
                cust = v4_entry.get("customer") or v4_entry.get("tenant") or ""
                parts = [p for p in [v4_dns,
                                     f"Kunde {cust}" if cust else ""] if p]
                if parts:
                    result.annotations[varname] = (
                        f"# netbox: {' / '.join(parts)}")
        return result

    # ── CLI ──

    def register_cli(self, cli_group: "click.Group") -> None:
        plugin_self = self

        @cli_group.group("netbox")
        def netbox_cmd():
            """Netbox plugin: IPAM lookups and cache management."""

        @netbox_cmd.command("refresh")
        def refresh_cmd():
            """Full refresh of the Netbox cache."""
            if plugin_self.snapshot_path:
                click.echo(f"Loading snapshot: {plugin_self.snapshot_path}")
                plugin_self.refresh()
            elif not plugin_self.url or not plugin_self.token:
                click.echo("Error: netbox url/token or snapshot not configured",
                           err=True)
                raise SystemExit(1)
            else:
                click.echo(f"Refreshing cache from {plugin_self.url}...")
                plugin_self.refresh()
            click.echo(f"Cached {len(plugin_self._cache['by_ip'])} IPs, "
                       f"{len(plugin_self._cache['by_device'])} devices")

        @netbox_cmd.command("lookup")
        @click.argument("ip")
        def lookup_cmd(ip: str):
            """Lookup an IP in the Netbox cache."""
            info = plugin_self.lookup_ip(ip)
            if info is None:
                click.echo(f"No info for {ip}", err=True)
                raise SystemExit(1)
            click.echo(json.dumps(info, indent=2))

        @netbox_cmd.command("by-dns")
        @click.argument("dns_name")
        def by_dns_cmd(dns_name: str):
            """Show all IPs sharing a dns_name."""
            ips = plugin_self._cache.get("by_dns_name", {}).get(
                dns_name.lower(), [])
            if not ips:
                click.echo(f"No IPs with dns_name {dns_name}", err=True)
                raise SystemExit(1)
            click.echo(f"dns_name: {dns_name}")
            for ip in ips:
                info = plugin_self._lookup_cached(ip) or {}
                cust = info.get("customer") or info.get("tenant") or ""
                status = info.get("status", "")
                click.echo(f"  {ip}  status={status}  cust={cust}")

        @netbox_cmd.command("stats")
        def stats_cmd():
            """Show cache statistics."""
            meta = plugin_self._cache.get("_meta", {})
            refreshed = meta.get("refreshed_at", 0)
            age = int(time.time() - refreshed) if refreshed else None
            age_str = f"{age}s ago" if age is not None else "never"
            click.echo(f"Mode:       {'snapshot' if plugin_self.snapshot_path else 'api'}")
            if plugin_self.snapshot_path:
                click.echo(f"Snapshot:   {plugin_self.snapshot_path}")
            click.echo(f"Cache file: {plugin_self.cache_file}")
            click.echo(f"Refreshed:  {age_str}")
            click.echo(f"TTL:        {plugin_self.cache_ttl}s")
            click.echo(f"Stale:      {plugin_self._is_cache_stale()}")
            click.echo(f"IPs:        {len(plugin_self._cache.get('by_ip', {}))}")
            click.echo(f"dns_names:  {len(plugin_self._cache.get('by_dns_name', {}))}")
            if meta.get("bulk_subnets"):
                click.echo(f"Bulk subnets: {meta['bulk_subnets']}")
