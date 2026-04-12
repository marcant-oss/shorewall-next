"""Structured export of a parsed ShorewallConfig as a JSON/YAML blob.

First piece of the ``--override-json`` / ``config export`` plan
(see ``docs/cli/override-json.md``). Not a full round-trip
implementation yet — round-trip requires the matching importer.

Shape (documented in ``docs/cli/override-json.md``):

- Top-level keys are file names relative to the config dir.
- KEY=VALUE files (``shorewall.conf``, ``params``) → dict.
- Column-based files → list of row objects with column names as
  keys from :mod:`shorewall_nft.config.schema`.
- ``rules`` / ``blrules`` are nested under their ``?SECTION`` labels.
- Extension scripts (start/started/stop/stopped/…) → ``{"lang":
  "sh", "lines": [...]}`` so they round-trip through JSON/YAML
  without pretending they have columns.

The column schema lives in :mod:`shorewall_nft.config.schema` —
the exporter never duplicates the list.
"""

from __future__ import annotations

from typing import Any

from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewall_nft.config.schema import (
    SCHEMA_VERSION,
    all_columnar_files,
    columns_for,
    is_sectioned,
)


def _row_to_dict(line: ConfigLine, schema: list[str] | None) -> dict[str, Any]:
    """Map a ConfigLine to a dict using the column-name schema.

    - ``-`` placeholders become ``None`` (Shorewall's "no value"
      marker).
    - Columns beyond the schema land in ``extra: [...]`` for forward
      compat with files that grew new columns.
    - Rows carry ``_file`` / ``_lineno`` / ``_comment`` trace fields
      when ``include_trace`` is on.
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
        for i, val in enumerate(cols):
            out[f"col_{i}"] = None if val == "-" else val
    if line.comment_tag:
        out["_comment"] = line.comment_tag
    if line.file:
        out["_file"] = line.file
    if line.lineno:
        out["_lineno"] = line.lineno
    return out


def _group_by_section(
    lines: list[ConfigLine], schema: list[str] | None,
) -> dict[str, list[dict]]:
    """Group rows by ``?SECTION``. Default section when none set: NEW."""
    out: dict[str, list[dict]] = {}
    for ln in lines:
        section = ln.section or "NEW"
        out.setdefault(section, []).append(_row_to_dict(ln, schema))
    return out


def export_config(
    config: ShorewalConfig, *, include_trace: bool = False,
) -> dict[str, Any]:
    """Turn a parsed ShorewallConfig into a structured JSON-ready dict.

    ``include_trace=False`` (the default) strips the ``_file`` /
    ``_lineno`` / ``_comment`` diagnostics so the output round-trips
    through json.dumps with stable byte-for-byte output.
    """
    blob: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "config_dir": str(config.config_dir),
    }

    if config.settings:
        blob["shorewall.conf"] = dict(config.settings)
    if config.params:
        # Strip builtin variables (``__``-prefixed) — they're always
        # defined by the parser and hide the signal in the noise.
        user_params = {
            k: v for k, v in config.params.items()
            if not k.startswith("__")
        }
        if user_params:
            blob["params"] = user_params

    # Column-based files: every file name the schema knows about that
    # has a matching attribute on the dataclass.
    for name in all_columnar_files():
        lines = getattr(config, name, None)
        if not lines:
            continue
        schema = columns_for(name)
        if is_sectioned(name):
            blob[name] = _group_by_section(lines, schema)
        else:
            blob[name] = [_row_to_dict(ln, schema) for ln in lines]

    if config.macros:
        rules_schema = columns_for("rules")
        blob["macros"] = {
            macro_name: [_row_to_dict(ln, rules_schema) for ln in body]
            for macro_name, body in config.macros.items()
        }

    # Line-based extension scripts. We emit them last in alphabetical
    # order so the blob is diff-friendly.
    if config.scripts:
        blob["scripts"] = {
            name: {"lang": "sh", "lines": lines}
            for name, lines in sorted(config.scripts.items())
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
