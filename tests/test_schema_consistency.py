"""Consistency tests between the central schema module and the
JSON Schema file shipped to operators / editor tooling.

``shorewall_nft/config/schema.py`` is the single source of truth
for:

- per-file column names (``_COLUMNS``)
- sectioned files (``_SECTIONED_FILES``)
- line-based extension scripts (``_SCRIPT_FILES``)

``docs/cli/override-json.schema.json`` is a published artifact
that operators plug into their editors and CI tooling. It MUST
stay in sync with the central module — otherwise editor
completion lies about the available keys, and CI lint passes
on invalid configs that the real importer will reject.

These tests pin the two together: every file in the central
module has a matching property in the JSON schema, and the
JSON schema doesn't ship keys the module doesn't know. Drift
triggers a clear failure telling the operator *which* file
needs to be added / removed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
JSON_SCHEMA_PATH = REPO / "docs" / "cli" / "override-json.schema.json"


@pytest.fixture(scope="module")
def json_schema() -> dict:
    if not JSON_SCHEMA_PATH.exists():
        pytest.skip(f"no JSON schema at {JSON_SCHEMA_PATH}")
    return json.loads(JSON_SCHEMA_PATH.read_text())


@pytest.fixture(scope="module")
def central_schema_files() -> set[str]:
    from shorewall_nft.config.schema import all_columnar_files
    return set(all_columnar_files())


def test_json_schema_version_matches_central(json_schema):
    """schema_version in the JSON schema matches the central module."""
    from shorewall_nft.config.schema import SCHEMA_VERSION

    v_const = (
        json_schema.get("properties", {})
        .get("schema_version", {})
        .get("const")
    )
    assert v_const == SCHEMA_VERSION, (
        f"JSON schema advertises schema_version const={v_const}, "
        f"central module is at SCHEMA_VERSION={SCHEMA_VERSION}. "
        f"Bump one of them."
    )


def test_every_central_columnar_file_has_json_property(
    central_schema_files, json_schema,
):
    """Every columnar file known to the central module has a JSON-
    schema property (so editor completion + CI validation see it)."""
    properties = set(json_schema.get("properties", {}).keys())
    # The JSON schema carries a few non-file envelope keys too.
    envelope_keys = {
        "schema_version", "config_dir",
        "shorewall.conf", "params", "macros", "scripts",
    }
    file_properties = properties - envelope_keys

    missing = central_schema_files - file_properties
    extra = file_properties - central_schema_files
    assert not missing, (
        f"JSON schema is missing properties for columnar files: "
        f"{sorted(missing)}. Add them to "
        f"docs/cli/override-json.schema.json so editor completion "
        f"matches what the importer accepts."
    )
    assert not extra, (
        f"JSON schema carries unknown columnar file properties: "
        f"{sorted(extra)}. Either the central module is missing "
        f"them (add to shorewall_nft/config/schema.py::_COLUMNS) "
        f"or the JSON schema is stale (remove them)."
    )


def test_scripts_property_matches_central_script_files(json_schema):
    """The JSON schema's ``scripts`` key should describe the dict
    shape; the central module enumerates the known script names.

    We don't pin the full list into the JSON schema as an enum
    (the shape accepts unknown names for forward-compat), but we
    do require the scripts property to exist.
    """
    scripts = json_schema.get("properties", {}).get("scripts")
    assert scripts is not None, (
        "JSON schema missing a 'scripts' property — operators "
        "can't validate extension script blocks."
    )
    assert scripts.get("type") == "object", (
        f"JSON schema 'scripts' property must be an object, got "
        f"{scripts.get('type')}"
    )

    from shorewall_nft.config.schema import all_script_files
    assert len(all_script_files()) > 0, (
        "central module lists no script files — fix the "
        "_SCRIPT_FILES set in shorewall_nft/config/schema.py"
    )


def test_marcant_reference_export_validates(json_schema, tmp_path):
    """Export the reference config, parse with jsonschema, assert valid.

    Catches the inverse: a columnar file whose schema positions
    don't match the JSON schema's row property list.

    Skipped when jsonschema or the reference config tree aren't
    available — the test only runs when both are present.
    """
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("jsonschema package not installed")

    ref = Path("/home/avalentin/projects/marcant-fw/old/etc/shorewall")
    if not ref.is_dir():
        pytest.skip(f"no reference config at {ref}")

    from shorewall_nft.config.exporter import export_config
    from shorewall_nft.config.parser import load_config

    cfg = load_config(ref)
    blob = export_config(cfg)

    # Validate — this will raise jsonschema.ValidationError on drift.
    jsonschema.validate(blob, json_schema)


def test_minimal_fixture_export_validates(json_schema):
    """Same validation against the bundled minimal fixture so CI
    catches drift without needing the reference tree."""
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("jsonschema package not installed")

    fixture = Path(__file__).resolve().parent / "configs" / "minimal"
    if not fixture.is_dir():
        pytest.skip(f"no minimal fixture at {fixture}")

    from shorewall_nft.config.exporter import export_config
    from shorewall_nft.config.parser import load_config

    cfg = load_config(fixture)
    blob = export_config(cfg)

    jsonschema.validate(blob, json_schema)
