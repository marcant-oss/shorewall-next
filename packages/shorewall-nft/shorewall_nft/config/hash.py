"""Config directory hash computation for drift detection.

The hash is a short sha256 over the content of all Shorewall config files
in the directory. It's embedded in the emitted nft ruleset as a table
comment, and checked at start/reload/debug time to detect when the loaded
ruleset no longer matches the on-disk config.

Use cases:
  - Operator edits a config file but forgets to `shorewall-nft reload`
    → on next `status` check, we can warn "loaded ruleset is N minutes older"
  - Debug mode wants to reload with annotations → must verify the user
    is aware that this replaces the current production ruleset
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

# Files that contribute to the hash. Only Shorewall config files — not
# editor backups, .bak, .pyc, etc.
_HASHED_FILES = frozenset({
    "shorewall.conf", "shorewall6.conf",
    "zones", "interfaces", "hosts", "policy", "rules",
    "params", "masq", "conntrack", "notrack", "blrules",
    "tcrules", "tcinterfaces", "tcdevices", "tcpri",
    "providers", "snat", "init", "netmap",
    "accounting", "actions", "routes", "routestopped",
    "stoppedrules",
    # Files added in the structured-io coverage round.
    "blacklist", "helpers",
    "arprules", "proxyarp", "proxyndp", "ecn",
    "nfacct", "rawnat", "scfilter",
    # Perl extension hook + shell library — content changes
    # affect runtime behaviour even though shorewall-nft itself
    # doesn't execute them.
    "compile", "lib.private",
})

# Subdirectories whose contents contribute
_HASHED_DIRS = frozenset({"rules.d", "macros"})


def compute_config_hash(config_dir: Path) -> str:
    """Compute a short sha256 hash of the relevant config files.

    Returns a 16-char hex string (first 64 bits of sha256). Stable across
    runs as long as the content is identical.
    """
    h = hashlib.sha256()

    if not config_dir.is_dir():
        return "missing"

    # Collect files deterministically (sorted by relative path)
    to_hash: list[tuple[str, Path]] = []

    for name in sorted(_HASHED_FILES):
        p = config_dir / name
        if p.is_file():
            to_hash.append((name, p))

    for dirname in sorted(_HASHED_DIRS):
        d = config_dir / dirname
        if d.is_dir():
            for child in sorted(d.rglob("*")):
                if child.is_file() and not child.name.endswith((".bak", "~")):
                    rel = child.relative_to(config_dir).as_posix()
                    to_hash.append((rel, child))

    for name, path in to_hash:
        try:
            content = path.read_bytes()
        except OSError:
            continue
        # Include the filename so a renamed file changes the hash
        h.update(name.encode())
        h.update(b"\0")
        h.update(content)
        h.update(b"\0")

    return h.hexdigest()[:16]


# Marker format in the emitted nft file. Matches in table comments.
_HASH_MARKER_RE = re.compile(r'config-hash:([0-9a-f]{16}|missing)')


def format_hash_marker(config_hash: str) -> str:
    """Format the hash for embedding in an nft table comment."""
    return f"config-hash:{config_hash}"


def extract_hash_from_ruleset(ruleset_text: str) -> str | None:
    """Extract the config-hash marker from an nft list-ruleset output.

    Returns the hash string, or None if no marker was found.
    """
    m = _HASH_MARKER_RE.search(ruleset_text)
    if m:
        return m.group(1)
    return None
