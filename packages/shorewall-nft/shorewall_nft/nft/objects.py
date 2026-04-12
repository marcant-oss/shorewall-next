"""Stateful nft objects: counters, quotas, limits, ct helpers, synproxys.

Generates nft object declarations for use in rules.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NamedCounter:
    """An nft named counter for Prometheus-style metrics."""
    name: str
    packets: int = 0
    bytes: int = 0


@dataclass
class CtHelperObj:
    """An nft ct helper object declaration."""
    name: str
    protocol: str  # tcp or udp
    l3proto: str = "inet"


def emit_ct_helper_objects(helpers: list[CtHelperObj]) -> str:
    """Generate nft ct helper object declarations."""
    lines: list[str] = []
    for h in helpers:
        lines.append(f"\tct helper {h.name} {{")
        lines.append(f'\t\ttype "{h.name}" protocol {h.protocol};')
        lines.append(f"\t\tl3proto {h.l3proto};")
        lines.append("\t}")
        lines.append("")
    return "\n".join(lines)


@dataclass
class SynproxyObj:
    """An nft synproxy object for DDoS protection."""
    name: str
    mss: int = 1460
    wscale: int = 7
    timestamp: bool = True
    sack_perm: bool = True


def emit_synproxy_objects(synproxys: list[SynproxyObj]) -> str:
    """Generate nft synproxy object declarations."""
    lines: list[str] = []
    for sp in synproxys:
        flags = []
        if sp.timestamp:
            flags.append("timestamp")
        if sp.sack_perm:
            flags.append("sack-perm")
        flags_str = f"\n\t\tflags {','.join(flags)};" if flags else ""
        lines.append(f"\tsynproxy {sp.name} {{")
        lines.append(f"\t\tmss {sp.mss};")
        lines.append(f"\t\twscale {sp.wscale};{flags_str}")
        lines.append("\t}")
        lines.append("")
    return "\n".join(lines)
