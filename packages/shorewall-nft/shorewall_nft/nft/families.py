"""nft table family support.

Handles different nftables families:
- inet: Combined IPv4/IPv6 (default, used for filter/nat/raw)
- netdev: Ingress/egress hooks for DDoS mitigation
- bridge: Bridge filtering (replaces ebtables)
- arp: ARP filtering (replaces arptables)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NetdevChain:
    """A netdev chain for ingress/egress filtering."""
    name: str
    device: str
    hook: str = "ingress"  # ingress or egress
    priority: int = -500


def emit_netdev_table(table_name: str, chains: list[NetdevChain]) -> str:
    """Generate a netdev table with ingress/egress chains."""
    lines: list[str] = []
    lines.append(f"table netdev {table_name} {{")
    for chain in chains:
        lines.append(f"\tchain {chain.name} {{")
        lines.append(f"\t\ttype filter hook {chain.hook} device \"{chain.device}\" priority {chain.priority};")
        lines.append("\t}")
        lines.append("")
    lines.append("}")
    return "\n".join(lines)
