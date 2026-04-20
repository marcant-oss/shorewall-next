"""Central column schema for Shorewall config files.

This module is the single source of truth for:

- Which columnar files exist.
- What the columns are called (for JSON export/import).
- Which files use ``?SECTION`` nesting (rules, blrules).
- Which files are line-based extension scripts (started, stopped,
  init, start, stop, findgw, ifup, isusable, refresh, refreshed,
  restored, savesets, initdone) — those stay opaque line lists in
  the structured blob.

**Authoritative source:** all columnar schemas were cross-checked
against the shorewall-nft parser + compiler code (the positions
that ``shorewall_nft.compiler.*`` actually reads), not the
Shorewall manpages, because the code is what actually consumes
the files at runtime. Where the code reads fewer columns than the
manpage documents, the schema follows the code — extra on-disk
columns still round-trip through the ``extra: [...]`` overflow
slot in the exporter.

Version bump of ``SCHEMA_VERSION`` is required whenever a column
is renamed or reordered (adds are backwards compatible because
readers use the position, not the name).
"""

from __future__ import annotations

SCHEMA_VERSION = 1


# ── columnar file column names ──────────────────────────────────────
#
# Keys are file basenames (relative to the config dir). Values are
# the positional column names, in order. When a file has more
# on-disk columns than the schema, they land in ``extra: [...]`` on
# the exported row.

_COLUMNS: dict[str, list[str]] = {
    # Zones and hosts
    "zones": [
        "zone", "type", "options", "in_options", "out_options",
    ],
    "interfaces": [
        "zone", "interface", "broadcast", "options",
    ],
    "hosts": [
        "zone", "hosts", "options",
    ],

    # Policy + filter rules (verified against compiler/ir.py)
    "policy": [
        "source", "dest", "policy", "log_level", "burst", "connlimit",
    ],
    "rules": [
        "action", "source", "dest", "proto", "dport", "sport",
        "orig_dest", "rate", "user", "mark", "connlimit", "time",
        "headers", "switch", "helper",
    ],
    "blrules": [
        "action", "source", "dest", "proto", "dport", "sport",
    ],
    "stoppedrules": [
        "target", "source", "dest", "proto", "dport", "sport",
    ],

    # NAT (verified against compiler/nat.py)
    "masq": [
        "interface", "source", "address", "proto", "port", "ipsec",
        "mark", "user", "switch", "orig_dest", "probability",
    ],
    "netmap": [
        "type", "net1", "interface", "net2", "proto", "dport",
    ],
    "rawnat": [
        "action", "source", "dest", "proto", "dport", "sport", "user",
    ],

    # Conntrack
    "conntrack": [
        "action", "source", "dest", "proto", "dport", "sport",
        "user", "switch",
    ],
    "notrack": [
        "source", "dest", "proto", "dport", "sport", "user",
    ],

    # Routing (verified against compiler/providers.py)
    "providers": [
        "name", "number", "mark", "interface", "gateway", "options",
    ],
    "routes": [
        "provider", "dest", "gateway", "device",
    ],
    "rtrules": [
        "source", "dest", "provider", "priority", "mark",
    ],
    "tunnels": [
        "type", "zone", "gateway", "gateway_zones",
    ],

    # routestopped (verified against compiler/ir.py _process_routestopped)
    "routestopped": [
        "interface", "hosts", "options", "proto", "dport", "sport",
    ],

    # tc (verified against compiler/tc.py)
    "tcdevices": [
        "interface", "in_bandwidth", "out_bandwidth", "options", "redirect",
    ],
    "tcclasses": [
        "interface", "mark", "rate", "ceil", "priority", "options",
    ],
    "tcfilters": [
        "class", "source", "dest", "proto", "dport", "sport",
    ],
    "tcinterfaces": [
        "interface", "type", "in_bandwidth", "out_bandwidth",
    ],
    "tcrules": [
        "mark", "source", "dest", "proto", "dport", "sport", "user",
        "test", "length", "tos", "connbytes", "helper", "headers",
    ],
    "tcpri": [
        "band", "proto", "port", "address", "interface", "helper",
    ],

    # Mangle (same shape as rules with an action column)
    "mangle": [
        "action", "source", "dest", "proto", "dport", "sport",
        "user", "test", "length", "tos", "connbytes", "helper",
        "headers", "probability", "dscp", "state", "time", "switch",
    ],

    # Accounting (verified against compiler/accounting.py)
    "accounting": [
        "action", "chain", "source", "dest", "proto", "dport", "sport",
        "user", "mark", "ipsec", "headers",
    ],

    # Security marks
    "secmarks": [
        "secmark", "chain", "source", "dest", "proto", "dport", "sport",
        "state",
    ],

    # MAC filtering
    "maclist": [
        "disposition", "interface", "mac", "ip", "assigned_interfaces",
    ],

    # Files added as part of the structured-io plan — the parser
    # gained support for these in the same commit that added this
    # schema.
    "arprules": [
        "action", "source", "dest", "interface", "mac",
    ],
    "proxyarp": [
        "address", "interface", "external", "haveroute", "persistent",
    ],
    "proxyndp": [
        "address", "interface", "external", "haveroute", "persistent",
    ],
    "ecn": [
        "interface", "host",
    ],
    "nfacct": [
        "name", "packets", "bytes",
    ],
    "scfilter": [
        "interface", "hosts", "options",
    ],
    # Static blacklist file: address-or-subnet plus optional
    # proto/port narrowing. Distinct from blrules (which has the
    # full rule grammar) — blacklist is the legacy "drop these
    # sources outright" list.
    "blacklist": [
        "address", "proto", "port",
    ],

    # Named dynamic nft sets — backend-agnostic set declaration.
    # Each row declares one named set; the options column carries
    # the backend type and per-backend parameters.
    "nfsets": [
        "name", "hosts", "options",
    ],
}


# ── files that use ?SECTION nesting ─────────────────────────────────
#
# policy is NOT in this set: the manpage mentions sections but
# real-world configs keep it flat. rules and blrules do use
# ?SECTION NEW / ESTABLISHED / RELATED / INVALID / UNTRACKED.

_SECTIONED_FILES: frozenset[str] = frozenset({
    "rules",
    "blrules",
})


# ── line-based extension scripts ────────────────────────────────────
#
# These are shell (or Perl in ``compile``) snippets invoked by
# shorewall at specific lifecycle points. Not columnar; the
# exporter emits them as ``{"lines": [...], "lang": "sh"}``.

_SCRIPT_FILES: frozenset[str] = frozenset({
    "start", "started", "stop", "stopped",
    "init", "initdone",
    "refresh", "refreshed", "restored",
    "findgw", "ifup", "isusable",
    "savesets",
    # Helpers file is the legacy `loadmodule …` list — shorewall
    # invokes it at startup to load the kernel conntrack helper
    # modules. Treat as a line-based script so the round-trip
    # preserves it byte-for-byte.
    "helpers",
    # Perl-format ``compile`` extension hook — shorewall (perl
    # backend) lets you inject custom rules at compile time.
    # shorewall-nft doesn't run it, but the file is part of the
    # config dir and shouldn't disappear on round-trip.
    "compile",
    # Shell library sourced by shorewall start/stop scripts.
    # Shorewall-nft doesn't source it either, but again it's
    # part of the config and operators rely on it surviving
    # the round-trip.
    "lib.private",
})


# ── public API ──────────────────────────────────────────────────────


def columns_for(file: str) -> list[str] | None:
    """Return the authoritative column list for ``file`` or None."""
    return _COLUMNS.get(file)


def is_sectioned(file: str) -> bool:
    """True if ``file`` uses ``?SECTION`` nesting."""
    return file in _SECTIONED_FILES


def is_script(file: str) -> bool:
    """True if ``file`` is a line-based extension script."""
    return file in _SCRIPT_FILES


def all_columnar_files() -> list[str]:
    """Return every file name that carries a column schema."""
    return sorted(_COLUMNS)


def all_script_files() -> list[str]:
    """Return every file name treated as a line-based script."""
    return sorted(_SCRIPT_FILES)
