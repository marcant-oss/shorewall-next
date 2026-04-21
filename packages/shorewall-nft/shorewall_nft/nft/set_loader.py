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

import logging
import math
from dataclasses import dataclass, field
from pathlib import Path

from shorewall_nft.nft.netlink import NftError, NftInterface

_LOG = logging.getLogger(__name__)

# JSON-API chunk size: large enough to minimise round-trips, small enough to
# keep individual libnftables payloads reasonable.  50 000 prefixes × ~20 B
# each ≈ 1 MB — well within kernel netlink limits.
_JSON_CHUNK_DEFAULT = 50_000

# Text-mode chunk size: limited by the nft parser's string buffer.
_TEXT_CHUNK_DEFAULT = 500


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

        self.bulk_add_elements(set_name, elements)
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
                self.bulk_add_elements(s.name, s.elements)
                results[s.name] = len(s.elements)

        return results

    def flush_set(self, set_name: str) -> None:
        """Remove all elements from a set."""
        cmd = f"flush set {self.family} {self.table} {set_name}"
        try:
            self.nft.cmd(cmd, netns=self.netns)
        except (NftError, Exception):
            pass  # Set might not exist yet

    def bulk_add_elements(
        self,
        set_name: str,
        elements: list[str],
        *,
        chunk_size: int | None = None,
        prefer_json: bool = True,
    ) -> None:
        """Add elements to a set, optionally via libnftables JSON API.

        When ``prefer_json=True`` (the default) and libnftables is available
        (``self.nft._use_lib`` is True), elements are sent via the native JSON
        API in chunks of ``chunk_size`` (default: 50 000).  This skips the nft
        text parser and is significantly faster for bulk loads (tens of
        thousands of elements).

        When libnftables is not available, or ``prefer_json=False``, falls back
        to the text-chunked path with a default chunk size of 500.

        ``chunk_size`` overrides the default for whichever path is chosen;
        passing ``chunk_size=500`` positionally is still supported for backward
        compatibility.
        """
        if not elements:
            return

        use_json = prefer_json and self.nft._use_lib

        if use_json:
            effective_chunk = chunk_size if chunk_size is not None else _JSON_CHUNK_DEFAULT
            n_chunks = math.ceil(len(elements) / effective_chunk)
            _LOG.debug(
                "SetLoader: JSON API, %d elements in %d chunk(s) for set %s",
                len(elements), n_chunks, set_name,
            )
            for i in range(0, len(elements), effective_chunk):
                chunk = elements[i:i + effective_chunk]
                payload: dict = {
                    "nftables": [
                        {
                            "add": {
                                "element": {
                                    "family": self.family,
                                    "table": self.table,
                                    "name": set_name,
                                    "elem": chunk,
                                }
                            }
                        }
                    ]
                }
                try:
                    self.nft.cmd_json(payload)
                except (NftError, Exception):
                    # Log but don't fail — some elements might be duplicates
                    _LOG.debug(
                        "SetLoader: JSON API chunk %d/%d for set %s failed (ignored)",
                        i // effective_chunk + 1, n_chunks, set_name,
                    )
        else:
            effective_chunk = chunk_size if chunk_size is not None else _TEXT_CHUNK_DEFAULT
            n_chunks = math.ceil(len(elements) / effective_chunk)
            _LOG.debug(
                "SetLoader: text mode, %d elements in %d chunk(s) for set %s",
                len(elements), n_chunks, set_name,
            )
            for i in range(0, len(elements), effective_chunk):
                chunk = elements[i:i + effective_chunk]
                elem_str = ", ".join(chunk)
                cmd = (f"add element {self.family} {self.table} "
                       f"{set_name} {{ {elem_str} }}")
                try:
                    self.nft.cmd(cmd, netns=self.netns)
                except (NftError, Exception):
                    # Log but don't fail — some elements might be duplicates
                    pass

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ensure_set(self, name: str, set_type: str, flags: list[str]) -> None:
        """Create the set if it doesn't exist, via JSON API when available."""
        if self.nft._use_lib:
            set_obj: dict = {
                "family": self.family,
                "table": self.table,
                "name": name,
                "type": set_type,
            }
            if flags:
                set_obj["flags"] = flags
            payload: dict = {"nftables": [{"add": {"set": set_obj}}]}
            try:
                self.nft.cmd_json(payload)
            except (NftError, Exception):
                pass  # Set might already exist
        else:
            flags_str = f"flags {', '.join(flags)}; " if flags else ""
            cmd = (f"add set {self.family} {self.table} {name} "
                   f"{{ type {set_type}; {flags_str}}}")
            try:
                self.nft.cmd(cmd, netns=self.netns)
            except (NftError, Exception):
                pass  # Set might already exist

    # Keep the old private name as an alias so any callers that happened to
    # call it directly continue to work.
    def _add_elements(self, set_name: str, elements: list[str],
                      chunk_size: int = _TEXT_CHUNK_DEFAULT) -> None:
        """Deprecated alias for bulk_add_elements (text path)."""
        self.bulk_add_elements(set_name, elements, chunk_size=chunk_size,
                               prefer_json=True)


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
