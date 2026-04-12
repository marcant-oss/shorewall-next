"""nft set generation from ipset definitions and prefix files.

Parses Shorewall init scripts for ipset create/add patterns
and generates nft named set declarations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NftSet:
    """An nft named set."""
    name: str
    set_type: str = "ipv4_addr"  # ipv4_addr, ipv6_addr, inet_service
    flags: list[str] = field(default_factory=list)
    elements: list[str] = field(default_factory=list)


def parse_init_for_sets(init_path: Path, config_dir: Path) -> list[NftSet]:
    """Parse a Shorewall init script for ipset definitions.

    Recognizes patterns like:
        ipset create NAME hash:net
        ipset add NAME PREFIX
        while read ...; do ipset add NAME "$pfx"; done < FILE
    """
    if not init_path.exists():
        return []

    text = init_path.read_text()
    sets: dict[str, NftSet] = {}

    # Find ipset create commands
    for m in re.finditer(r'ipset\s+create\s+(\S+)\s+hash:(\w+)', text):
        name = m.group(1)
        hash_type = m.group(2)
        nft_type = "ipv4_addr" if hash_type == "net" else "ipv4_addr"
        sets[name] = NftSet(name=name, set_type=nft_type, flags=["interval"])

    # Find "done < FILE" patterns to load elements from files
    for m in re.finditer(r'ipset\s+add\s+(\S+)\s+.*done\s*<\s*(\S+)', text, re.DOTALL):
        name = m.group(1)
        file_path = m.group(2)

        if name not in sets:
            sets[name] = NftSet(name=name, flags=["interval", "auto-merge"])

        # Resolve file path
        p = Path(file_path)
        if not p.is_absolute():
            p = config_dir / file_path
        # Also try substituting /etc/shorewall/ with config_dir
        if not p.exists() and "/etc/shorewall/" in file_path:
            p = config_dir / Path(file_path).name

        if p.exists():
            for line in p.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    sets[name].elements.append(line)

    # Find individual ipset add commands
    for m in re.finditer(r'ipset\s+add\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+\S*)\s', text):
        name = m.group(1)
        prefix = m.group(2)
        if name not in sets:
            sets[name] = NftSet(name=name, flags=["interval", "auto-merge"])
        if prefix not in sets[name].elements:
            sets[name].elements.append(prefix)

    # Deduplicate overlapping prefixes in each set
    for s in sets.values():
        if s.elements and s.flags and "interval" in s.flags:
            s.elements = _dedup_prefixes(s.elements)

    return list(sets.values())


def _dedup_prefixes(prefixes: list[str]) -> list[str]:
    """Remove prefixes that are subsets of other prefixes in the list.

    E.g. if we have 10.0.0.0/8 and 10.1.0.0/16, remove the /16.
    Also removes exact duplicates.
    """
    import ipaddress

    nets: list[ipaddress.IPv4Network] = []
    for p in prefixes:
        try:
            nets.append(ipaddress.ip_network(p.strip(), strict=False))
        except ValueError:
            continue

    if not nets:
        return prefixes

    # Sort by prefix length (broadest first) then address
    nets.sort(key=lambda n: (n.prefixlen, n.network_address))

    # Keep only nets not covered by a broader net
    result: list[ipaddress.IPv4Network] = []
    for net in nets:
        covered = False
        for existing in result:
            if net.subnet_of(existing):
                covered = True
                break
        if not covered:
            result.append(net)

    return [str(n) for n in result]


def emit_nft_sets(sets: list[NftSet]) -> str:
    """Generate nft set declarations."""
    if not sets:
        return ""

    lines: list[str] = []
    for s in sets:
        flags_str = f"\n\t\tflags {', '.join(s.flags)};" if s.flags else ""
        lines.append(f"\tset {s.name} {{")
        lines.append(f"\t\ttype {s.set_type};{flags_str}")
        if s.elements:
            # Emit elements in chunks to avoid overly long lines
            lines.append("\t\telements = {")
            chunk_size = 10
            for i in range(0, len(s.elements), chunk_size):
                chunk = s.elements[i:i + chunk_size]
                suffix = "," if i + chunk_size < len(s.elements) else ""
                lines.append(f"\t\t\t{', '.join(chunk)}{suffix}")
            lines.append("\t\t}")
        lines.append("\t}")
        lines.append("")

    return "\n".join(lines)
