"""IP INFO plugin: pattern-based v4↔v6 mapping per /24 subnet.

This is a fallback source — netbox is preferred if available.
The mapping embeds the v4 address directly in the last 64 bits of the v6:
    203.0.113.65 → 2001:db8:0:100:203:0:113:65
                   └── prefix ──┘ └── v4 in hex ──┘
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
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


@dataclass
class _SubnetMapping:
    v4_subnet: str
    v6_prefix: str          # e.g. "2001:db8:0:100::/64"
    v6_prefix_base: str     # e.g. "2001:db8:0:100" (first 4 groups)


class IpInfoPlugin(Plugin):
    """Pattern-based v4→v6 mapping plugin."""

    name = "ip-info"
    version = "1.0.0"
    priority = 10  # Low — fallback only

    def __init__(self, config: dict, config_dir: Path):
        super().__init__(config, config_dir)
        self.embedding = config.get("embedding", "v4-in-host")
        self.mappings: list[_SubnetMapping] = []
        for m in config.get("mappings", []):
            v4 = m["v4_subnet"]
            v6 = m["v6_prefix"]
            # Extract the first 4 groups from "2001:db8:0:100::/64"
            v6_addr_part = v6.split("/")[0]
            # Normalize: expand :: and take first 4 groups
            v6_full = ipaddress.IPv6Address(
                int(ipaddress.IPv6Address(v6_addr_part)) & ~((1 << 64) - 1)
            ).exploded
            groups = v6_full.split(":")[:4]
            # Strip leading zeros for readable form
            base = ":".join(g.lstrip("0") or "0" for g in groups)
            self.mappings.append(_SubnetMapping(
                v4_subnet=v4, v6_prefix=v6, v6_prefix_base=base,
            ))

    # ── Mapping logic ──

    def map_v4_to_v6(self, ip: str) -> str | None:
        """Map v4 → v6 using configured /24 mappings.

        For `203.0.113.65` with mapping `203.0.113.0/24` → `2001:db8:0:100::/64`,
        returns `2001:db8:0:100:203:0:113:65`.
        """
        if not is_ipv4(ip):
            return None
        for mapping in self.mappings:
            if ip_in_subnet(ip, mapping.v4_subnet):
                octets = ip.split(".")
                host_part = f"{octets[0]}:{octets[1]}:{octets[2]}:{octets[3]}"
                v6 = f"{mapping.v6_prefix_base}:{host_part}"
                # Normalize via ipaddress
                try:
                    return str(ipaddress.IPv6Address(v6))
                except ValueError:
                    return None
        return None

    def map_v6_to_v4(self, ip: str) -> str | None:
        """Map v6 → v4 by matching prefix and extracting embedded v4."""
        if not is_ipv6(ip):
            return None
        try:
            v6_addr = ipaddress.IPv6Address(ip)
        except ValueError:
            return None

        for mapping in self.mappings:
            v6_net = ipaddress.IPv6Network(mapping.v6_prefix, strict=False)
            if v6_addr in v6_net:
                # Extract the last 64 bits. Each group is the decimal v4 octet
                # written as hex digits (e.g. group "0217" = decimal 217).
                exploded = v6_addr.exploded.split(":")
                host_groups = exploded[4:]  # last 4 groups
                try:
                    # Parse each group as decimal digits, not as hex value
                    octets = [int(g.lstrip("0") or "0", 10) for g in host_groups]
                    if all(0 <= o <= 255 for o in octets):
                        v4 = ".".join(str(o) for o in octets)
                        if ip_in_subnet(v4, mapping.v4_subnet):
                            return v4
                except ValueError:
                    continue
        return None

    def lookup_ip(self, ip: str) -> dict | None:
        """Return mapping info for an IP."""
        if is_ipv4(ip):
            v6 = self.map_v4_to_v6(ip)
            if v6:
                for m in self.mappings:
                    if ip_in_subnet(ip, m.v4_subnet):
                        return {
                            "v4": ip, "v6": v6,
                            "v4_subnet": m.v4_subnet,
                            "v6_prefix": m.v6_prefix,
                            "source": "ip-info (pattern)",
                        }
        elif is_ipv6(ip):
            v4 = self.map_v6_to_v4(ip)
            if v4:
                for m in self.mappings:
                    if ip_in_subnet(v4, m.v4_subnet):
                        return {
                            "v4": v4, "v6": ip,
                            "v4_subnet": m.v4_subnet,
                            "v6_prefix": m.v6_prefix,
                            "source": "ip-info (pattern)",
                        }
        return None

    # ── Enrichment hooks ──

    def enrich_comment_block(
        self, tag: str, v4_rules: list[str], v6_rules: list[str]
    ) -> EnrichResult:
        """Detect v4/v6 host pairs in a mandant block."""
        v4_ips = set()
        for rule in v4_rules:
            v4_ips.update(extract_ipv4(rule))

        v6_ips = set()
        for rule in v6_rules:
            v6_ips.update(extract_ipv6(rule))

        pairs = []
        v4_only = []
        for v4 in sorted(v4_ips):
            mapped_v6 = self.map_v4_to_v6(v4)
            if mapped_v6 is None:
                continue
            # Check if mapped v6 (or its normalized form) is in v6_ips
            normalized_v6_ips = {str(ipaddress.IPv6Address(v6)) for v6 in v6_ips
                                 if is_ipv6(v6)}
            if mapped_v6 in normalized_v6_ips:
                pairs.append((v4, mapped_v6))
            else:
                v4_only.append((v4, mapped_v6))

        if not pairs and not v4_only:
            return EnrichResult()

        comments = []
        if pairs:
            comments.append(f"# ip-info: {len(pairs)} v4/v6 host pair(s) "
                            f"detected (pattern-based)")
        if v4_only:
            comments.append(f"# ip-info: {len(v4_only)} v4-only host(s) "
                            f"(no matching v6 rule):")
            for v4, expected_v6 in v4_only[:5]:
                comments.append(f"#   {v4} → expected {expected_v6}")
            if len(v4_only) > 5:
                comments.append(f"#   ... and {len(v4_only) - 5} more")

        return EnrichResult(prepend_comments=comments)

    def enrich_params(
        self, v4_params: dict[str, str], v6_params: dict[str, str]
    ) -> ParamEnrichResult:
        """Detect paired v4/v6 params via pattern matching.

        A param like `MAIL5=203.0.113.86` (v4) is paired with
        `MAIL5=2001:db8:0:100:203:0:113:86` (v6) if the v4 address
        maps to the v6 address via our pattern.
        """
        result = ParamEnrichResult()
        for varname, v4_line in v4_params.items():
            if varname not in v6_params:
                continue
            v6_line = v6_params[varname]
            # Extract IPs from both lines
            v4_ips = extract_ipv4(v4_line)
            v6_ips = extract_ipv6(v6_line)
            if not v4_ips or not v6_ips:
                continue
            # Check if the first v4 IP maps to the first v6 IP
            expected_v6 = self.map_v4_to_v6(v4_ips[0])
            if expected_v6 is None:
                continue
            try:
                first_v6_norm = str(ipaddress.IPv6Address(v6_ips[0]))
                if first_v6_norm == expected_v6:
                    result.pairs[varname] = (v4_line, v6_line)
            except ValueError:
                continue
        return result

    # ── CLI ──

    def register_cli(self, cli_group: "click.Group") -> None:
        plugin_self = self

        @cli_group.group("ip-info")
        def ip_info_cmd():
            """IP INFO plugin: pattern-based v4↔v6 mapping."""

        @ip_info_cmd.command("v4-to-v6")
        @click.argument("ip")
        def v4_to_v6(ip: str):
            """Map an IPv4 address to its v6 equivalent via pattern."""
            result = plugin_self.map_v4_to_v6(ip)
            if result:
                click.echo(result)
            else:
                click.echo(f"No mapping for {ip}", err=True)
                raise SystemExit(1)

        @ip_info_cmd.command("v6-to-v4")
        @click.argument("ip")
        def v6_to_v4(ip: str):
            """Extract IPv4 address from a v6 using pattern."""
            result = plugin_self.map_v6_to_v4(ip)
            if result:
                click.echo(result)
            else:
                click.echo(f"No reverse mapping for {ip}", err=True)
                raise SystemExit(1)

        @ip_info_cmd.command("list-mappings")
        def list_mappings():
            """List all configured v4→v6 subnet mappings."""
            if not plugin_self.mappings:
                click.echo("No mappings configured")
                return
            for m in plugin_self.mappings:
                click.echo(f"  {m.v4_subnet:22s} → {m.v6_prefix}")
