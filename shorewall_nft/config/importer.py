"""Structured import of a JSON/YAML blob into a ShorewalConfig.

The round-trip counterpart to :mod:`shorewall_nft.config.exporter`.
Takes the JSON shape documented in ``docs/cli/override-json.md`` and
builds a fresh :class:`ShorewalConfig` (for ``config import`` / the
overlay applier) or merges into an existing one (for
``--override-json`` applied on top of an on-disk parse).

Column order is reconstructed from the central
:mod:`shorewall_nft.config.schema` module. Rows expressed as
``{name: value}`` are walked in schema order and written back into
``ConfigLine.columns`` with ``None`` values rendered as ``-`` to
match the on-disk placeholder convention.

**No filesystem writes** — this module only builds the in-memory
object. The on-disk writer (``shorewall-nft config import FILE --to
DIR``) lives in the CLI layer and serialises a ShorewalConfig back
to the Shorewall column format via :func:`write_config_dir` (TODO).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewall_nft.config.schema import (
    SCHEMA_VERSION,
    all_columnar_files,
    all_script_files,
    columns_for,
    is_sectioned,
)


class ImportError(Exception):
    """Raised when a structured blob cannot be imported."""


def _row_to_configline(
    row: dict[str, Any], file: str, schema: list[str],
    section: str | None = None,
) -> ConfigLine:
    """Rebuild a ConfigLine from a dict row using the schema order.

    - ``None`` values render as ``"-"`` (Shorewall's "no value" marker).
    - Known schema columns are emitted in schema order. Trailing
      columns from ``extra: [...]`` are appended verbatim.
    - Diagnostic ``_file`` / ``_lineno`` / ``_comment`` fields round-trip
      back to the ConfigLine fields; absent → default values.
    """
    cols: list[str] = []
    for name in schema:
        val = row.get(name, "-")
        if val is None:
            val = "-"
        cols.append(str(val))
    extra = row.get("extra")
    if isinstance(extra, list):
        cols.extend(str(x) for x in extra)
    # Round-trip symmetry: the exporter only emits columns up to the
    # last non-empty one. If we leave trailing "-" placeholders here,
    # a second export would carry them as explicit null fields and
    # diverge from the first export. Trim them off.
    while cols and cols[-1] == "-":
        cols.pop()

    return ConfigLine(
        columns=cols,
        file=str(row.get("_file", file)),
        lineno=int(row.get("_lineno", 0) or 0),
        comment_tag=row.get("_comment"),
        section=section,
        raw=" ".join(cols),
    )


def _import_columnar(
    blob_value: Any, file: str,
) -> list[ConfigLine]:
    """Dispatch one file's blob value into a list of ConfigLines."""
    schema = columns_for(file) or []
    out: list[ConfigLine] = []

    if is_sectioned(file):
        # Expected shape: ``{"NEW": [...], "ESTABLISHED": [...], ...}``.
        # Also accept a flat list (treat as "NEW" section) for
        # convenience.
        if isinstance(blob_value, list):
            blob_value = {"NEW": blob_value}
        if not isinstance(blob_value, dict):
            raise ImportError(
                f"{file}: sectioned file expects dict of section → rows, "
                f"got {type(blob_value).__name__}")
        for section, rows in blob_value.items():
            if not isinstance(rows, list):
                raise ImportError(
                    f"{file}[{section}]: expected list of row dicts, "
                    f"got {type(rows).__name__}")
            for row in rows:
                if not isinstance(row, dict):
                    continue
                out.append(_row_to_configline(row, file, schema, section))
        return out

    # Flat columnar file
    if not isinstance(blob_value, list):
        raise ImportError(
            f"{file}: expected list of row dicts, got "
            f"{type(blob_value).__name__}")
    for row in blob_value:
        if not isinstance(row, dict):
            continue
        out.append(_row_to_configline(row, file, schema))
    return out


def _import_scripts(blob_value: Any) -> dict[str, list[str]]:
    """Unpack the ``scripts`` top-level key.

    Shape: ``{name: {"lang": "sh", "lines": [...]}}``. A plain string
    value is also accepted and split on newlines for convenience.
    """
    if not isinstance(blob_value, dict):
        raise ImportError(
            f"scripts: expected dict of name → body, got "
            f"{type(blob_value).__name__}")
    out: dict[str, list[str]] = {}
    for name, body in blob_value.items():
        if name not in all_script_files():
            # Unknown script name — keep it anyway so round-trip is
            # idempotent for future Shorewall versions that add new
            # extension points.
            pass
        if isinstance(body, str):
            out[name] = body.splitlines()
        elif isinstance(body, dict):
            lines = body.get("lines")
            if isinstance(lines, list):
                out[name] = [str(x) for x in lines]
            else:
                out[name] = []
        elif isinstance(body, list):
            out[name] = [str(x) for x in body]
        else:
            raise ImportError(
                f"scripts[{name}]: expected str / list / dict, got "
                f"{type(body).__name__}")
    return out


def blob_to_config(
    blob: dict[str, Any],
    *,
    config_dir: Path | None = None,
) -> ShorewalConfig:
    """Build a fresh :class:`ShorewalConfig` from a structured blob.

    ``config_dir`` is set on the returned object; it does **not** have
    to exist on disk. If absent, the ``config_dir`` key from the blob
    itself is used, falling back to ``/dev/null``.
    """
    if not isinstance(blob, dict):
        raise ImportError(
            f"blob must be a dict, got {type(blob).__name__}")

    version = blob.get("schema_version")
    if version is None:
        raise ImportError("blob missing required 'schema_version' field")
    if version > SCHEMA_VERSION:
        raise ImportError(
            f"blob schema_version={version} is newer than tool "
            f"supports ({SCHEMA_VERSION}); upgrade shorewall-nft")

    cdir_str = (config_dir and str(config_dir)) or blob.get(
        "config_dir", "/dev/null")
    config = ShorewalConfig(config_dir=Path(cdir_str))

    # KEY=VALUE sections
    sw_conf = blob.get("shorewall.conf")
    if isinstance(sw_conf, dict):
        config.settings = {k: str(v) for k, v in sw_conf.items()}
    params = blob.get("params")
    if isinstance(params, dict):
        config.params = {k: str(v) for k, v in params.items()}

    # Columnar files
    known_columnar = set(all_columnar_files())
    for key, value in blob.items():
        if key in ("schema_version", "config_dir", "shorewall.conf",
                   "params", "macros", "scripts"):
            continue
        # Plugin files (plugins.conf + plugins/*.toml + plugins/*.token)
        # land in config.plugin_files as-is so write_config_dir can
        # emit them as TOML / raw strings.
        if key == "plugins.conf" or key.startswith("plugins/"):
            config.plugin_files[key] = value
            continue
        if key not in known_columnar:
            # Unknown top-level key — forward-compat hint, not an
            # error. Real unknowns will be caught by a stricter
            # --strict mode on the CLI layer later.
            continue
        if not hasattr(config, key):
            continue
        setattr(config, key, _import_columnar(value, key))

    # Macros (dict-of-rules)
    macros = blob.get("macros")
    if isinstance(macros, dict):
        rules_schema = columns_for("rules") or []
        for macro_name, body in macros.items():
            if not isinstance(body, list):
                continue
            config.macros[macro_name] = [
                _row_to_configline(row, f"macro.{macro_name}", rules_schema)
                for row in body
                if isinstance(row, dict)
            ]

    # Extension scripts
    scripts = blob.get("scripts")
    if scripts is not None:
        config.scripts = _import_scripts(scripts)

    return config


def apply_overlay(
    config: ShorewalConfig, overlay: dict[str, Any],
) -> None:
    """Merge an overlay blob on top of an already-parsed ShorewalConfig.

    Used by ``--override-json`` and ``--override FILE=JSON``. Semantics
    match ``docs/cli/override-json.md``:

    - ``shorewall.conf`` / ``params`` dicts are merged (overlay keys
      win on collision).
    - Columnar file rows are **appended** by default. Pass a dict with
      ``"_replace": true`` and ``"rows": [...]`` to replace instead.
    - Sectioned files (``rules``, ``blrules``) accept either a full
      sectioned dict (section name → rows) merged per-section, or a
      flat list (appended to the ``NEW`` section).
    - ``scripts`` / ``macros`` overlays replace the matching name
      entirely — scripts are rarely partially edited in practice.
    """
    if not isinstance(overlay, dict):
        raise ImportError(
            f"overlay must be a dict, got {type(overlay).__name__}")

    if "shorewall.conf" in overlay and isinstance(
            overlay["shorewall.conf"], dict):
        for k, v in overlay["shorewall.conf"].items():
            config.settings[k] = str(v)

    if "params" in overlay and isinstance(overlay["params"], dict):
        for k, v in overlay["params"].items():
            config.params[k] = str(v)

    known_columnar = set(all_columnar_files())
    for key, value in overlay.items():
        if key in ("schema_version", "config_dir", "shorewall.conf",
                   "params", "macros", "scripts"):
            continue
        if key not in known_columnar:
            continue
        if not hasattr(config, key):
            continue

        # Parse the overlay shape for this file
        replace = False
        rows: Any = value
        if isinstance(value, dict) and not is_sectioned(key):
            if value.get("_replace") is True:
                replace = True
                rows = value.get("rows", [])

        new_rows = _import_columnar(rows, key)
        if replace:
            setattr(config, key, new_rows)
        else:
            existing = getattr(config, key)
            existing.extend(new_rows)

    if "scripts" in overlay:
        new_scripts = _import_scripts(overlay["scripts"])
        config.scripts.update(new_scripts)

    if "macros" in overlay and isinstance(overlay["macros"], dict):
        rules_schema = columns_for("rules") or []
        for macro_name, body in overlay["macros"].items():
            if isinstance(body, list):
                config.macros[macro_name] = [
                    _row_to_configline(row, f"macro.{macro_name}", rules_schema)
                    for row in body if isinstance(row, dict)
                ]


def _columns_to_line(cols: list[str]) -> str:
    """Render one ConfigLine back to a Shorewall column-format line."""
    # Shorewall uses whitespace separation. A single tab between each
    # column gives predictable output that editors align nicely and
    # the parser round-trips byte-identical through strip/split.
    return "\t".join(cols)


def _zone_pair_key(line: ConfigLine) -> tuple[str, str]:
    """Return a (src_zone, dst_zone) key for sorting rule blocks.

    Used by the rules pretty-printer to group ``foo→bar`` lines
    next to each other regardless of file order. Anything we can't
    parse falls back to ``("", "")`` so it sorts to the front and
    keeps relative order with its peers (Python's sort is stable).
    """
    cols = line.columns
    if len(cols) < 3:
        return ("", "")
    src = (cols[1] or "").split(":", 1)[0].split(",", 1)[0].strip()
    dst = (cols[2] or "").split(":", 1)[0].split(",", 1)[0].strip()
    return (src, dst)


_DROP_LIKE_ACTIONS = frozenset({
    "DROP", "REJECT", "DROP/LOG", "REJECT/LOG", "Drop", "Reject",
    "DROP_DEFAULT", "REJECT_DEFAULT",
})


def _is_catchall_drop(line: ConfigLine) -> bool:
    """True if a rule is a catch-all DROP/REJECT (no host/proto/port).

    These belong at the BOTTOM of each zone-pair group so the kind
    of mid-chain shadowing we just fixed in
    ``compiler/ir._add_rule`` (catch-all expansions getting placed
    before later more-specific rules) doesn't sneak back via a
    future hand-edit. The exporter is the second line of defence:
    even if the user re-orders the on-disk file, write_config_dir
    moves the catch-alls back to the tail.
    """
    cols = line.columns
    if not cols:
        return False
    action_raw = cols[0].split(":", 1)[0]
    action = action_raw.split("(", 1)[0].rstrip("+")
    if action not in _DROP_LIKE_ACTIONS:
        return False
    src = cols[1] if len(cols) > 1 else ""
    dst = cols[2] if len(cols) > 2 else ""
    proto = cols[3] if len(cols) > 3 else ""
    dport = cols[4] if len(cols) > 4 else ""
    sport = cols[5] if len(cols) > 5 else ""
    # Catch-all = no proto/port narrowing AND no host narrowing in
    # either zone spec.
    has_host = (":" in src or ":" in dst)
    has_proto = bool(proto and proto != "-")
    has_port = (
        (dport and dport != "-") or (sport and sport != "-"))
    return not (has_host or has_proto or has_port)


def _reorder_rules_block(rows: list[ConfigLine]) -> list[ConfigLine]:
    """Group rules by zone-pair affinity and push catch-all DROPs
    to the tail of each group.

    Stable sort by ``(src_zone, dst_zone)`` keeps the relative
    order of rules within a single zone-pair so a hand-curated
    sequence (DNS macro before HTTP macro before generic catch)
    survives the round-trip. The catch-all DROP/REJECT pass runs
    AFTER the group sort so the order inside each group becomes
    "specific accepts → catch-all drop" — same shape Shorewall's
    iptables backend produces.
    """
    grouped = sorted(rows, key=_zone_pair_key)
    final: list[ConfigLine] = []
    cur_key: tuple[str, str] | None = None
    cur_block: list[ConfigLine] = []

    def _flush() -> None:
        catchalls = [r for r in cur_block if _is_catchall_drop(r)]
        rest = [r for r in cur_block if not _is_catchall_drop(r)]
        final.extend(rest)
        final.extend(catchalls)

    for ln in grouped:
        k = _zone_pair_key(ln)
        if cur_key is None:
            cur_key = k
        if k != cur_key:
            _flush()
            cur_block = []
            cur_key = k
        cur_block.append(ln)
    if cur_block:
        _flush()
    return final


def _aligned_block(rows: list[list[str]], header_cols: list[str] | None,
                   *, min_pad: int = 2, max_col_width: int = 28) -> list[str]:
    """Render a block of rows with per-column space padding.

    Walks every row in the block to compute the maximum width of
    each column (capped at ``max_col_width``), then pads each
    cell to that width with at least ``min_pad`` trailing spaces.
    The header row (if present) is aligned the same way.

    The width cap matters: a single rule with a 200-character
    comma-separated SOURCE list would otherwise force every row
    in the file to use 200 characters of padding for the SOURCE
    column. With the cap, the over-wide cell breaks the grid
    for its own row only and the rest of the file stays
    scannable. Default 28 fits the common ``zone:host`` ::
    ``port`` shapes.

    The whitespace separation parses the same as the tab form
    (Shorewall's parser is whitespace-tolerant), so the round-
    trip test still passes byte-equivalent through ``split()``.
    """
    if not rows and not header_cols:
        return []

    # Pad rows to the longest row's length so column-width
    # computation doesn't go out of bounds for trailing-default
    # rows (Shorewall lets you drop trailing ``-`` columns).
    width = max(
        (len(r) for r in rows),
        default=0,
    )
    if header_cols and len(header_cols) > width:
        width = len(header_cols)
    norm_rows: list[list[str]] = [
        list(r) + [""] * (width - len(r)) for r in rows
    ]
    norm_header: list[str] | None = None
    if header_cols:
        norm_header = list(header_cols) + [""] * (width - len(header_cols))

    col_widths = [0] * width
    if norm_header:
        for i, cell in enumerate(norm_header):
            col_widths[i] = max(col_widths[i], min(len(cell), max_col_width))
    for r in norm_rows:
        for i, cell in enumerate(r):
            col_widths[i] = max(col_widths[i], min(len(cell), max_col_width))

    def _fmt(row: list[str]) -> str:
        parts: list[str] = []
        for i, cell in enumerate(row):
            if i == width - 1:
                parts.append(cell)  # last column — no trailing pad
            elif len(cell) >= col_widths[i]:
                # Over-wide cell → break the grid for this row only.
                parts.append(cell + " " * min_pad)
            else:
                parts.append(cell.ljust(col_widths[i] + min_pad))
        return "".join(parts).rstrip()

    out: list[str] = []
    if norm_header:
        out.append("#" + _fmt(norm_header))
    for r in norm_rows:
        out.append(_fmt(r))
    return out


def _render_toml_value(v: Any) -> str:
    """Minimal TOML value serialiser — strings, ints, bools, lists."""
    if v is None:
        return '""'
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        # Escape backslashes and quotes
        escaped = v.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(v, list):
        return "[" + ", ".join(_render_toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        # Inline table — rare, used only for simple nested settings
        items = ", ".join(f"{k} = {_render_toml_value(w)}"
                          for k, w in v.items())
        return "{ " + items + " }"
    return _render_toml_value(str(v))


def _render_toml(doc: dict) -> str:
    """Render a minimal-but-correct TOML document from a dict.

    Handles the shapes the shorewall-nft plugin files actually use:

    - Top-level scalar keys (strings, ints, bools, lists)
    - Arrays of tables via a nested ``list[dict]`` value:
      ``{"plugins": [{"name": "netbox", ...}]}`` → ``[[plugins]]``.
    - One level of nested sub-tables as ``[section]`` headers when a
      top-level value is a dict (also handles simple inline form
      through ``_render_toml_value``).

    Not a general-purpose TOML writer — deliberately minimal to stay
    dependency-free. The ``tomli_w`` package would do the same job
    more thoroughly but we don't want to add another runtime dep.
    """
    out: list[str] = []
    # 1. Top-level scalars + arrays first
    for k, v in doc.items():
        if isinstance(v, dict):
            continue  # emit as [section] below
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            continue  # emit as [[array]] below
        out.append(f"{k} = {_render_toml_value(v)}")
    # 2. [[array-of-tables]] sections
    for k, v in doc.items():
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            for entry in v:
                out.append("")
                out.append(f"[[{k}]]")
                for kk, vv in entry.items():
                    out.append(f"{kk} = {_render_toml_value(vv)}")
    # 3. [section] sub-tables
    for k, v in doc.items():
        if isinstance(v, dict):
            out.append("")
            out.append(f"[{k}]")
            for kk, vv in v.items():
                out.append(f"{kk} = {_render_toml_value(vv)}")
    return "\n".join(out) + "\n"


def write_config_dir(
    config: ShorewalConfig, target_dir: Path, *,
    force: bool = False,
    write_scripts: bool = True,
    pretty: bool = True,
    provenance: bool = False,
) -> list[Path]:
    """Serialise a :class:`ShorewalConfig` back to on-disk Shorewall files.

    Writes one file per populated section into ``target_dir``:

    - ``shorewall.conf`` / ``params`` as ``KEY=VALUE`` lines
    - columnar files as tab-separated rows
    - extension scripts as raw line lists (one file per name)
    - macros as ``macros/macro.NAME`` files

    Sectioned files (``rules``, ``blrules``) emit ``?SECTION NAME``
    headers before each section's rows, preserving the grouping.

    ``force=False`` refuses to write into a target that already
    exists and is non-empty; pass ``force=True`` to overwrite.

    Returns a list of the paths actually written.
    """
    target_dir = Path(target_dir)
    if target_dir.exists():
        if any(target_dir.iterdir()) and not force:
            raise ImportError(
                f"{target_dir} exists and is not empty — pass force=True "
                f"to overwrite")
    else:
        target_dir.mkdir(parents=True)

    written: list[Path] = []

    def _write(name: str, text: str) -> None:
        p = target_dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        written.append(p)

    # KEY=VALUE files
    if config.settings:
        lines = [f"{k}={v}" for k, v in config.settings.items()]
        _write("shorewall.conf", "\n".join(lines) + "\n")
    if config.params:
        # Skip the parser builtins (__-prefixed)
        user_params = [
            (k, v) for k, v in config.params.items()
            if not k.startswith("__")
        ]
        if user_params:
            lines = [f"{k}={v}" for k, v in user_params]
            _write("params", "\n".join(lines) + "\n")

    # Columnar files
    for name in all_columnar_files():
        rows: list[ConfigLine] = getattr(config, name, None) or []
        if not rows:
            continue
        schema = columns_for(name) or []
        lines_out: list[str] = []

        if pretty:
            header_cols = (
                [c.upper() for c in schema] if schema else None)
            # Rules-file reordering: group by zone-pair affinity,
            # push catch-all DROPs to the tail of each group. Only
            # applied to ``rules`` and ``blrules`` — other files
            # don't have a meaningful zone-pair semantic.
            should_reorder = name in ("rules", "blrules")

            def _emit_block(rows_block: list[ConfigLine],
                            hdr: list[str] | None) -> list[str]:
                """Render one block of rows with comment_tag + optional provenance.

                Always preserves ``?COMMENT`` directives — when
                consecutive rows share a ``comment_tag`` we emit
                one ``?COMMENT <tag>`` line before the run, and a
                bare ``?COMMENT`` (empty) when the tag clears or
                changes. This brings ``?COMMENT`` blocks back into
                the round-trip; they carry semantic grouping in
                production rules files (e.g. "Sophos UTM
                Administration") and the legacy snapshot uses
                hundreds of them.

                When ``provenance=True`` each rule additionally
                gets a shell comment ``# from <file>:<lineno>``
                immediately before its data line.
                """
                if not rows_block and not hdr:
                    return []
                aligned = _aligned_block(
                    [list(r.columns) for r in rows_block], hdr)
                out_lines: list[str] = []
                idx = 0
                if hdr:
                    out_lines.append(aligned[0])
                    idx = 1
                cur_tag: str | None = None
                for i, ln in enumerate(rows_block):
                    tag = ln.comment_tag or None
                    if tag != cur_tag:
                        if tag:
                            out_lines.append(f"?COMMENT {tag}")
                        else:
                            out_lines.append("?COMMENT")
                        cur_tag = tag
                    if provenance:
                        src_file = (ln.file or "").rsplit("/", 1)[-1]
                        if src_file and ln.lineno:
                            out_lines.append(
                                f"# from {src_file}:{ln.lineno}")
                    out_lines.append(aligned[idx + i])
                return out_lines

            if is_sectioned(name):
                by_section: dict[str, list[ConfigLine]] = {}
                for ln in rows:
                    by_section.setdefault(
                        ln.section or "NEW", []).append(ln)
                first = True
                for section, rows_in_section in by_section.items():
                    if not first or section != "NEW":
                        lines_out.append(f"?SECTION {section}")
                    first = False
                    if should_reorder:
                        rows_in_section = _reorder_rules_block(
                            rows_in_section)
                    lines_out.extend(
                        _emit_block(rows_in_section, header_cols))
                    header_cols = None  # only the first section gets one
            else:
                ordered = (
                    _reorder_rules_block(rows) if should_reorder else rows)
                lines_out.extend(_emit_block(ordered, header_cols))
        else:
            if schema:
                header = "#" + "\t".join(c.upper() for c in schema)
                lines_out.append(header)
            if is_sectioned(name):
                by_section = {}
                for ln in rows:
                    by_section.setdefault(
                        ln.section or "NEW", []).append(ln)
                first = True
                for section, rows_in_section in by_section.items():
                    if not first or section != "NEW":
                        lines_out.append(f"?SECTION {section}")
                    first = False
                    for ln in rows_in_section:
                        lines_out.append(_columns_to_line(ln.columns))
            else:
                for ln in rows:
                    lines_out.append(_columns_to_line(ln.columns))

        _write(name, "\n".join(lines_out) + "\n")

    # Macros
    if config.macros:
        for macro_name, body in config.macros.items():
            lines_out = [
                _columns_to_line(ln.columns)
                for ln in body
            ]
            _write(f"macros/macro.{macro_name}",
                   "\n".join(lines_out) + "\n")

    # Extension scripts
    if write_scripts and config.scripts:
        for script_name, script_lines in config.scripts.items():
            _write(script_name, "\n".join(script_lines) + "\n")

    # Plugin config files (plugins.conf + plugins/*.toml + plugins/*.token)
    import os as _os
    for path, value in config.plugin_files.items():
        full_path = target_dir / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        if path.endswith(".token") or isinstance(value, str):
            # Raw string file — usually a credential. 0600.
            full_path.write_text(str(value) + ("\n" if not str(value).endswith("\n") else ""))
            try:
                _os.chmod(full_path, 0o600)
            except OSError:
                pass
        elif isinstance(value, dict):
            full_path.write_text(_render_toml(value))
        else:
            # Unknown shape — emit as JSON so nothing is silently dropped
            import json as _json
            full_path.write_text(_json.dumps(value, indent=2) + "\n")
        written.append(full_path)

    return written


__all__ = [
    "ImportError",
    "apply_overlay",
    "blob_to_config",
    "write_config_dir",
]
