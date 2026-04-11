"""Structured export of a parsed ShorewallConfig as a JSON/YAML blob.

First piece of the ``--override-json`` / ``config export`` plan
(see ``docs/cli/override-json.md``). Not a full round-trip implementation
yet — round-trip requires the matching importer to reconstruct the
positional column layout. For now the export is read-only and is used
by:

- ``shorewall-nft config export [DIR] --format=json|yaml``
- The structured overlay loader (future work)
- Integration tests that want to assert on config content

The export follows the shape documented in ``docs/cli/override-json.md``:
- Top-level keys are file names relative to the config dir.
- KEY=VALUE files (``shorewall.conf``, ``params``) → dict.
- Column-based files → list of row objects with column names as keys.
- ``rules`` / ``blrules`` / ``policy`` are nested by ``?SECTION`` when
  the parser recorded one.
"""

from __future__ import annotations

from typing import Any

from shorewall_nft.config.parser import ConfigLine, ShorewalConfig


# Column-name schemas for the files Shorewall manpages document.
# ``None`` entries mean "no fixed name — emit as col_N". Trailing
# columns beyond the named schema go into ``extra`` as a list to
# preserve forward compat with files that grow new columns.
_COLUMNS: dict[str, list[str]] = {
    "zones": [
        "zone", "type", "options", "in_options", "out_options",
    ],
    "interfaces": [
        "zone", "interface", "broadcast", "options",
    ],
    "hosts": [
        "zone", "hosts", "options",
    ],
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
        "orig_dest", "rate", "user", "mark",
    ],
    "masq": [
        "interface", "source", "address", "proto", "port", "ipsec",
        "mark", "user", "switch", "orig_dest", "probability",
    ],
    "mangle": [
        "action", "source", "dest", "proto", "dport", "sport",
        "user", "test", "length", "tos", "connbytes", "helper",
        "headers", "probability", "dscp", "state", "time", "switch",
    ],
    "conntrack": [
        "action", "source", "dest", "proto", "dport", "sport",
        "user", "switch",
    ],
    "notrack": [
        "source", "dest", "proto", "dport", "sport", "user",
    ],
    "providers": [
        "name", "number", "mark", "duplicate", "interface", "gateway",
        "options", "copy",
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
    "netmap": [
        "type", "net1", "interface", "net2", "net3", "proto",
        "dport", "sport",
    ],
    "maclist": [
        "disposition", "interface", "mac", "ip", "assigned_interfaces",
    ],
    "routestopped": [
        "interface", "hosts", "options", "proto", "dport", "sport",
    ],
    "tcdevices": [
        "interface", "in_bandwidth", "out_bandwidth", "options", "redirected",
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
    "accounting": [
        "action", "chain", "source", "dest", "proto", "dport", "sport",
        "user", "mark", "ipsec", "headers",
    ],
    "secmarks": [
        "secmark", "chain", "source", "dest", "proto", "dport", "sport",
        "state",
    ],
}

# Files whose rows nest under ``?SECTION`` names in Shorewall.
# ``policy`` does NOT use sections in practice even though the
# manpage mentions them — keep it flat.
_SECTIONED_FILES = {"rules", "blrules"}


def _row_to_dict(line: ConfigLine, schema: list[str] | None) -> dict[str, Any]:
    """Map a ConfigLine to a dict using the column-name schema.

    - ``-`` placeholders become ``None`` (Shorewall's "no value" marker).
    - Columns beyond the schema land in ``extra: [...]`` for forward
      compat with files that grew new columns.
    - Rows carry ``_lineno`` / ``_file`` for diagnostic trace, which the
      overlay applier strips on merge.
    """
    out: dict[str, Any] = {}
    cols = line.columns
    if schema:
        for i, name in enumerate(schema):
            if i < len(cols):
                val = cols[i]
                out[name] = None if val == "-" else val
        if len(cols) > len(schema):
            out["extra"] = cols[len(schema):]
    else:
        # No schema known — fall back to positional naming
        for i, val in enumerate(cols):
            out[f"col_{i}"] = None if val == "-" else val
    # Diagnostic trace — easy to strip on import
    if line.comment_tag:
        out["_comment"] = line.comment_tag
    if line.file:
        out["_file"] = line.file
    if line.lineno:
        out["_lineno"] = line.lineno
    return out


def _group_by_section(lines: list[ConfigLine],
                      schema: list[str] | None) -> dict[str, list[dict]]:
    """Group a list of ConfigLine rows by their ``?SECTION`` marker.

    Shorewall's default section when none has been seen is ``NEW``.
    """
    out: dict[str, list[dict]] = {}
    for ln in lines:
        section = ln.section or "NEW"
        out.setdefault(section, []).append(_row_to_dict(ln, schema))
    return out


def export_config(config: ShorewalConfig, *,
                  include_trace: bool = False) -> dict[str, Any]:
    """Turn a parsed ShorewallConfig into a structured JSON-ready dict.

    ``include_trace=False`` (the default) strips the ``_file`` /
    ``_lineno`` / ``_comment`` diagnostics so the output round-trips
    through json.dumps with no stable-output noise.
    """
    blob: dict[str, Any] = {
        "schema_version": 1,
        "config_dir": str(config.config_dir),
    }

    if config.settings:
        blob["shorewall.conf"] = dict(config.settings)
    if config.params:
        # Strip builtin variables — they're always defined and hide
        # the signal in the noise.
        user_params = {
            k: v for k, v in config.params.items()
            if not k.startswith("__")
        }
        if user_params:
            blob["params"] = user_params

    # Column-based files
    for attr, schema_name in [
        ("zones",        "zones"),
        ("interfaces",   "interfaces"),
        ("hosts",        "hosts"),
        ("policy",       "policy"),
        ("rules",        "rules"),
        ("masq",         "masq"),
        ("conntrack",    "conntrack"),
        ("notrack",      "notrack"),
        ("blrules",      "blrules"),
        ("mangle",       "mangle"),
        ("netmap",       "netmap"),
        ("maclist",      "maclist"),
        ("providers",    "providers"),
        ("routes",       "routes"),
        ("rtrules",      "rtrules"),
        ("tunnels",      "tunnels"),
        ("routestopped", "routestopped"),
        ("tcrules",      "tcrules"),
        ("tcdevices",    "tcdevices"),
        ("tcinterfaces", "tcinterfaces"),
        ("tcclasses",    "tcclasses"),
        ("tcfilters",    "tcfilters"),
        ("tcpri",        "tcpri"),
        ("accounting",   "accounting"),
        ("secmarks",     "secmarks"),
    ]:
        lines: list[ConfigLine] = getattr(config, attr, [])
        if not lines:
            continue
        schema = _COLUMNS.get(schema_name)
        if attr in _SECTIONED_FILES:
            blob[attr] = _group_by_section(lines, schema)
        else:
            blob[attr] = [_row_to_dict(ln, schema) for ln in lines]

    if config.macros:
        blob["macros"] = {
            name: [_row_to_dict(ln, _COLUMNS.get("rules"))
                   for ln in body]
            for name, body in config.macros.items()
        }

    if not include_trace:
        _strip_trace(blob)
    return blob


def _strip_trace(obj: Any) -> None:
    """Recursively remove ``_file`` / ``_lineno`` / ``_comment`` keys."""
    if isinstance(obj, dict):
        for k in ("_file", "_lineno", "_comment"):
            obj.pop(k, None)
        for v in obj.values():
            _strip_trace(v)
    elif isinstance(obj, list):
        for item in obj:
            _strip_trace(item)
