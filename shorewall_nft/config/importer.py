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
from typing import Any, Iterable

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


def write_config_dir(
    config: ShorewalConfig, target_dir: Path, *,
    force: bool = False,
    write_scripts: bool = True,
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

        if schema:
            header = "#" + "\t".join(c.upper() for c in schema)
            lines_out.append(header)

        if is_sectioned(name):
            # Group by section so we can re-emit ?SECTION headers
            by_section: dict[str, list[ConfigLine]] = {}
            for ln in rows:
                by_section.setdefault(ln.section or "NEW", []).append(ln)
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

    return written


__all__ = [
    "ImportError",
    "apply_overlay",
    "blob_to_config",
    "write_config_dir",
]
