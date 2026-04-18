"""External nft set loader.

Populates nft named sets from external sources:
- Prefix files (one prefix per line, like customer-a-prefixes-aggregated.txt)
- GeoIP prefix files (from a GeoIP set builder or similar)
- init script ipset definitions

Equivalent to Shorewall's init script but using native nft set operations.

Usage:
    loader = SetLoader(netns="fw")
    loader.load_from_file("customer-a-ipv4", "/etc/shorewall/customer-a-prefixes-aggregated.txt")
    loader.load_geoip_sets("/usr/share/geoipsets/nftset/")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from shorewall_nft.nft.netlink import NftError, NftInterface


@dataclass
class SetSource:
    """Definition of an external set to load."""
    name: str
    set_type: str = "ipv4_addr"
    flags: list[str] = field(default_factory=lambda: ["interval"])
    source_file: Path | None = None
    elements: list[str] = field(default_factory=list)


class SetLoader:
    """Load external data into nft named sets."""

    def __init__(self, table: str = "shorewall", family: str = "inet",
                 netns: str | None = None):
        self.table = table
        self.family = family
        self.netns = netns
        self.nft = NftInterface()

    def load_from_file(self, set_name: str, file_path: str | Path,
                       *, create: bool = True) -> int:
        """Load prefixes from a file into a named set.

        File format: one prefix per line (CIDR notation), # comments.
        Returns number of elements loaded.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Set file not found: {path}")

        elements = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            elements.append(line)

        if not elements:
            return 0

        if create:
            self._ensure_set(set_name, "ipv4_addr", ["interval"])

        self._add_elements(set_name, elements)
        return len(elements)

    def load_geoip_dir(self, geoip_dir: str | Path,
                       sets: list[str] | None = None) -> dict[str, int]:
        """Load GeoIP sets from a directory of prefix files.

        Expected structure: DIR/XX-ipv4.txt (or .nftset)
        Returns {set_name: element_count}.
        """
        geoip_path = Path(geoip_dir)
        if not geoip_path.is_dir():
            raise FileNotFoundError(f"GeoIP directory not found: {geoip_path}")

        results: dict[str, int] = {}
        for f in sorted(geoip_path.iterdir()):
            if not f.is_file():
                continue
            name = f.stem  # e.g. "DE-ipv4"
            if f.suffix not in (".txt", ".nftset", ""):
                continue
            if sets and name not in sets:
                continue

            count = self.load_from_file(name, f)
            if count > 0:
                results[name] = count

        return results

    def load_from_init(self, init_path: str | Path,
                       config_dir: str | Path) -> dict[str, int]:
        """Parse a Shorewall init script and load the sets it defines.

        Recognizes:
            ipset create NAME hash:net
            while read pfx; do ipset add NAME "$pfx"; done < FILE
        """
        init_path = Path(init_path)
        config_dir = Path(config_dir)

        if not init_path.exists():
            return {}

        from shorewall_nft.nft.sets import parse_init_for_sets
        nft_sets = parse_init_for_sets(init_path, config_dir)

        results: dict[str, int] = {}
        for s in nft_sets:
            if s.elements:
                self._ensure_set(s.name, s.set_type, s.flags)
                self._add_elements(s.name, s.elements)
                results[s.name] = len(s.elements)

        return results

    def flush_set(self, set_name: str) -> None:
        """Remove all elements from a set."""
        cmd = f"flush set {self.family} {self.table} {set_name}"
        try:
            self.nft.cmd(cmd, netns=self.netns)
        except (NftError, Exception):
            pass  # Set might not exist yet

    def _ensure_set(self, name: str, set_type: str, flags: list[str]) -> None:
        """Create the set if it doesn't exist."""
        flags_str = f"flags {', '.join(flags)}; " if flags else ""
        cmd = (f"add set {self.family} {self.table} {name} "
               f"{{ type {set_type}; {flags_str}}}")
        try:
            self.nft.cmd(cmd, netns=self.netns)
        except (NftError, Exception):
            pass  # Set might already exist

    def _add_elements(self, set_name: str, elements: list[str],
                      chunk_size: int = 500) -> None:
        """Add elements to a set in chunks."""
        for i in range(0, len(elements), chunk_size):
            chunk = elements[i:i + chunk_size]
            elem_str = ", ".join(chunk)
            cmd = f"add element {self.family} {self.table} {set_name} {{ {elem_str} }}"
            try:
                self.nft.cmd(cmd, netns=self.netns)
            except (NftError, Exception):
                # Log but don't fail — some elements might be duplicates
                pass


def generate_set_loader_script(config_dir: Path) -> str:
    """Generate a shell script that loads external sets after nft rules.

    This is the nft equivalent of Shorewall's init script.
    """
    from shorewall_nft.nft.sets import parse_init_for_sets

    lines: list[str] = []
    lines.append("#!/bin/sh")
    lines.append("# Generated by shorewall-nft — external set loader")
    lines.append("# Run after 'shorewall-nft apply' to populate sets")
    lines.append("")
    lines.append('NFT="${NFT:-/usr/sbin/nft}"')
    lines.append('TABLE="${TABLE:-inet shorewall}"')
    lines.append("")

    # Sets from init script
    nft_sets = parse_init_for_sets(config_dir / "init", config_dir)
    for s in nft_sets:
        if s.elements:
            lines.append(f"# Set: {s.name} ({len(s.elements)} elements)")
            lines.append(f'$NFT flush set $TABLE {s.name} 2>/dev/null')
            # Write elements in chunks
            chunk_size = 50
            for i in range(0, len(s.elements), chunk_size):
                chunk = s.elements[i:i + chunk_size]
                elem_str = ", ".join(chunk)
                lines.append(f'$NFT add element $TABLE {s.name} {{ {elem_str} }}')
            lines.append("")

    # GeoIP sets (look for common locations)
    geoip_dirs = [
        config_dir / "geoip",
        Path("/usr/share/geoipsets/nftset"),
        Path("/usr/share/xt_geoip/nftset"),
    ]
    for geoip_dir in geoip_dirs:
        if geoip_dir.is_dir():
            lines.append(f"# GeoIP sets from {geoip_dir}")
            for f in sorted(geoip_dir.iterdir()):
                if f.is_file() and f.suffix in (".txt", ".nftset"):
                    name = f.stem
                    lines.append(f'if [ -f "{f}" ]; then')
                    lines.append(f'    $NFT flush set $TABLE {name} 2>/dev/null')
                    lines.append('    while IFS= read -r prefix; do')
                    lines.append('        case "$prefix" in "#"*|"") continue ;; esac')
                    lines.append(f'        $NFT add element $TABLE {name} {{ "$prefix" }}')
                    lines.append(f'    done < "{f}"')
                    lines.append('fi')
            lines.append("")
            break

    return "\n".join(lines)
