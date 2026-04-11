"""Tunnel configuration processing.

Handles IPsec, GRE, OpenVPN, 6to4, PPTP tunnel definitions
from the Shorewall tunnels config file.

Format: TYPE ZONE GATEWAY GATEWAY_ZONE
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import (
    FirewallIR,
    Match,
    Rule,
    Verdict,
)
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.config.zones import ZoneModel

# Tunnel type → required protocols/ports
_TUNNEL_RULES: dict[str, list[tuple[str, str | None]]] = {
    "ipsec": [("50", None), ("51", None), ("udp", "500")],
    "ipsecnat": [("50", None), ("udp", "500"), ("udp", "4500")],
    "gre": [("47", None)],
    "ipip": [("4", None)],
    "6to4": [("41", None)],
    "6in4": [("41", None)],
    "pptpclient": [("tcp", "1723"), ("47", None)],
    "pptpserver": [("tcp", "1723"), ("47", None)],
    "openvpn": [("udp", "1194")],
    "openvpnclient": [("udp", "1194")],
    "openvpnserver": [("udp", "1194")],
    "l2tp": [("udp", "1701")],
    "tinc": [("tcp", "655"), ("udp", "655")],
    "wireguard": [("udp", "51820")],
}


def process_tunnels(ir: FirewallIR, tunnel_lines: list[ConfigLine],
                    zones: ZoneModel) -> None:
    """Process tunnel definitions into firewall rules.

    Format: TYPE[:option] ZONE GATEWAY GATEWAY_ZONE
    """
    if not tunnel_lines:
        return

    for line in tunnel_lines:
        cols = line.columns
        if len(cols) < 3:
            continue

        tunnel_type = cols[0].lower().split(":")[0]
        zone = cols[1]
        gateway = cols[2]
        gateway_zone = cols[3] if len(cols) > 3 and cols[3] != "-" else None

        rules = _TUNNEL_RULES.get(tunnel_type)
        if not rules:
            continue

        fw = zones.firewall_zone

        for proto, port in rules:
            # Allow tunnel traffic to/from the gateway
            # Inbound
            chain_in = ir.get_or_create_chain(f"{zone}-{fw}")
            rule_in = Rule(
                verdict=Verdict.ACCEPT,
                source_file=line.file,
                source_line=line.lineno,
                comment=f"tunnel:{tunnel_type}",
            )
            if gateway and gateway != "-" and gateway != "0.0.0.0/0":
                rule_in.matches.append(Match(field="ip saddr", value=gateway))
            rule_in.matches.append(Match(field="meta l4proto", value=proto))
            if port:
                rule_in.matches.append(Match(field=f"{proto} dport", value=port))
            chain_in.rules.append(rule_in)

            # Outbound
            chain_out = ir.get_or_create_chain(f"{fw}-{zone}")
            rule_out = Rule(
                verdict=Verdict.ACCEPT,
                source_file=line.file,
                source_line=line.lineno,
                comment=f"tunnel:{tunnel_type}",
            )
            if gateway and gateway != "-" and gateway != "0.0.0.0/0":
                rule_out.matches.append(Match(field="ip daddr", value=gateway))
            rule_out.matches.append(Match(field="meta l4proto", value=proto))
            if port:
                rule_out.matches.append(Match(field=f"{proto} sport", value=port))
            chain_out.rules.append(rule_out)
