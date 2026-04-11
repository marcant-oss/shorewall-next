"""Round-trip tests for config export ↔ import.

These are the regression gate for the structured-io plan (see
``docs/cli/override-json.md``). A round-trip must be byte-identical:
parse → export → import → export and assert the two blobs are the
same JSON bytes. Any divergence means either the exporter drops
information that the schema knows about, or the importer rebuilds
rows in a way that doesn't match the exporter's output format.

Test corpus: the minimal fixture at ``tests/configs/minimal`` plus
(when present) the real marcant-fw reference at
``/home/avalentin/projects/marcant-fw/old/etc/shorewall``. The
latter is a best-effort absolute path: on CI hosts without the
reference tree, the test is skipped rather than failed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shorewall_nft.config.exporter import export_config
from shorewall_nft.config.importer import apply_overlay, blob_to_config
from shorewall_nft.config.parser import load_config


def _roundtrip(config_dir: Path) -> tuple[str, str]:
    """Parse → export → import → export; return the two JSON strings."""
    cfg1 = load_config(config_dir)
    blob1 = export_config(cfg1)
    cfg2 = blob_to_config(blob1)
    blob2 = export_config(cfg2)
    # Use sort_keys + default=str so dict key order doesn't make the
    # test flakey on different Python versions.
    s1 = json.dumps(blob1, sort_keys=True, default=str)
    s2 = json.dumps(blob2, sort_keys=True, default=str)
    return s1, s2


def test_roundtrip_minimal_fixture():
    """The shipped minimal fixture must round-trip byte-identical."""
    fixture = Path(__file__).resolve().parent / "configs" / "minimal"
    if not fixture.is_dir():
        pytest.skip(f"no minimal fixture at {fixture}")
    s1, s2 = _roundtrip(fixture)
    assert s1 == s2, (
        f"round-trip divergence: {len(s1)} vs {len(s2)} bytes\n"
        f"first 200 chars: {s1[:200]!r}\nvs: {s2[:200]!r}"
    )


def test_roundtrip_marcant_reference():
    """The real marcant-fw config must round-trip byte-identical."""
    ref = Path("/home/avalentin/projects/marcant-fw/old/etc/shorewall")
    if not ref.is_dir():
        pytest.skip(f"no marcant reference at {ref}")
    s1, s2 = _roundtrip(ref)
    assert s1 == s2, (
        f"round-trip divergence on marcant ref: "
        f"{len(s1)} vs {len(s2)} bytes"
    )


def test_schema_version_required():
    """``blob_to_config`` rejects blobs without schema_version."""
    from shorewall_nft.config.importer import ImportError as CfgImportError

    with pytest.raises(CfgImportError, match="schema_version"):
        blob_to_config({"zones": []})


def test_schema_version_newer_rejected():
    """Future schema versions are refused with a clear error."""
    from shorewall_nft.config.importer import ImportError as CfgImportError

    with pytest.raises(CfgImportError, match="newer than tool"):
        blob_to_config({"schema_version": 999})


def test_overlay_appends_rules_by_default():
    """``apply_overlay`` appends columnar rows, keeping the on-disk ones."""
    cfg = blob_to_config({
        "schema_version": 1,
        "rules": {
            "NEW": [
                {"action": "ACCEPT", "source": "net", "dest": "fw",
                 "proto": "tcp", "dport": "22"},
            ],
        },
    })
    before = len(cfg.rules)
    apply_overlay(cfg, {
        "rules": {
            "NEW": [
                {"action": "DROP", "source": "net", "dest": "fw",
                 "proto": "tcp", "dport": "23"},
            ],
        },
    })
    assert len(cfg.rules) == before + 1
    # The new row's columns must be ordered per schema
    new_row = cfg.rules[-1]
    assert new_row.columns[0] == "DROP"
    assert new_row.columns[3] == "tcp"
    assert new_row.columns[4] == "23"


def test_overlay_flat_zones_append():
    """Flat columnar overlay rows append to the existing list."""
    cfg = blob_to_config({
        "schema_version": 1,
        "zones": [{"zone": "fw", "type": "firewall"}],
    })
    apply_overlay(cfg, {
        "zones": [{"zone": "net", "type": "ipv4"}],
    })
    assert len(cfg.zones) == 2
    assert cfg.zones[-1].columns[0] == "net"


def test_overlay_replace_via_sentinel():
    """``_replace: true`` on a flat file wipes the existing rows first."""
    cfg = blob_to_config({
        "schema_version": 1,
        "zones": [
            {"zone": "fw", "type": "firewall"},
            {"zone": "net", "type": "ipv4"},
        ],
    })
    apply_overlay(cfg, {
        "zones": {
            "_replace": True,
            "rows": [{"zone": "only", "type": "ipv4"}],
        },
    })
    assert len(cfg.zones) == 1
    assert cfg.zones[0].columns[0] == "only"


def test_overlay_shorewall_conf_merges():
    """``shorewall.conf`` dict keys merge over existing settings."""
    cfg = blob_to_config({
        "schema_version": 1,
        "shorewall.conf": {"OPTIMIZE": "3", "FASTACCEPT": "Yes"},
    })
    apply_overlay(cfg, {
        "shorewall.conf": {"OPTIMIZE": "8"},
    })
    assert cfg.settings["OPTIMIZE"] == "8"
    assert cfg.settings["FASTACCEPT"] == "Yes"
