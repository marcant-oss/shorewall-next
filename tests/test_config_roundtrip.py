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


def test_roundtrip_through_disk_minimal(tmp_path):
    """parse → export → import → write_config_dir → parse → export.

    The full filesystem round-trip. Regression gate for
    ``write_config_dir``: whatever the writer emits must be parseable
    back into a ShorewalConfig that re-exports to the same blob.
    """
    fixture = Path(__file__).resolve().parent / "configs" / "minimal"
    if not fixture.is_dir():
        pytest.skip(f"no minimal fixture at {fixture}")

    from shorewall_nft.config.importer import write_config_dir

    cfg_a = load_config(fixture)
    blob_a = export_config(cfg_a)

    cfg_b = blob_to_config(blob_a)
    target = tmp_path / "written"
    # pretty=False — the round-trip contract is byte-identical
    # JSON. The pretty-printing path (default) reorders rules
    # by zone-pair affinity which is a perfectly valid emit but
    # not byte-identical input vs output.
    written = write_config_dir(cfg_b, target, pretty=False)
    assert len(written) > 0

    cfg_c = load_config(target)
    blob_c = export_config(cfg_c)

    # The config_dir key will legitimately differ (different paths).
    # Strip both before comparing content.
    blob_a_cmp = dict(blob_a)
    blob_a_cmp.pop("config_dir", None)
    blob_c_cmp = dict(blob_c)
    blob_c_cmp.pop("config_dir", None)
    s_a = json.dumps(blob_a_cmp, sort_keys=True, default=str)
    s_c = json.dumps(blob_c_cmp, sort_keys=True, default=str)
    assert s_a == s_c, (
        f"disk round-trip diverged: {len(s_a)} vs {len(s_c)} bytes")


def test_pretty_export_groups_by_zone_pair_and_pushes_drops_to_tail(tmp_path):
    """Pretty exporter groups by zone-pair and tail-sorts catch-all DROPs."""
    from shorewall_nft.config.importer import (
        blob_to_config,
        write_config_dir,
    )

    blob = {
        "schema_version": 1,
        "zones": [
            {"zone": "fw", "type": "firewall"},
            {"zone": "net", "type": "ipv4"},
            {"zone": "loc", "type": "ipv4"},
        ],
        "rules": {
            "rows": [
                {"action": "DROP", "source": "net", "dest": "loc"},
                {"action": "ACCEPT", "source": "loc",
                 "dest": "net", "proto": "tcp", "dport": "80"},
                {"action": "ACCEPT", "source": "net",
                 "dest": "loc:10.0.0.5", "proto": "tcp", "dport": "22"},
                {"action": "ACCEPT", "source": "loc",
                 "dest": "net", "proto": "tcp", "dport": "443"},
            ],
        },
    }
    cfg = blob_to_config(blob)
    target = tmp_path / "pretty"
    write_config_dir(cfg, target, force=True, pretty=True)
    rules_text = (target / "rules").read_text()
    lines = [l for l in rules_text.splitlines()
             if l and not l.startswith("#")]

    # All loc→net rules should appear before net→loc, and within
    # the net→loc group the catch-all DROP should land at the tail.
    loc_indexes = [i for i, l in enumerate(lines)
                   if l.split()[1].startswith("loc") if len(l.split()) > 1]
    net_indexes = [i for i, l in enumerate(lines)
                   if l.split()[1].startswith("net") if len(l.split()) > 1]
    assert max(loc_indexes) < min(net_indexes), (
        "loc→net rules should appear before net→loc:\n" + rules_text)
    # Within the net group, the DROP must be the last line.
    last_line = lines[-1].split()
    assert last_line[0] == "DROP" and last_line[1] == "net", (
        "catch-all DROP should be tail-sorted within its group:\n"
        + rules_text)


def test_pretty_export_provenance_markers(tmp_path):
    """provenance=True interleaves shell comments before each row."""
    from shorewall_nft.config.importer import (
        blob_to_config,
        write_config_dir,
    )
    blob = {
        "schema_version": 1,
        "zones": [
            {"zone": "fw", "type": "firewall"},
            {"zone": "net", "type": "ipv4"},
        ],
        "rules": {
            "rows": [
                {"action": "ACCEPT", "source": "net",
                 "dest": "fw", "proto": "tcp", "dport": "22"},
            ],
        },
    }
    cfg = blob_to_config(blob)
    target = tmp_path / "with-provenance"
    write_config_dir(cfg, target, force=True, pretty=True, provenance=True)
    rules_text = (target / "rules").read_text()
    # The blob_to_config path doesn't set file/lineno on the
    # synthesised ConfigLines, so the provenance pass should
    # silently skip rows without origin info instead of crashing.
    assert "ACCEPT" in rules_text


def test_write_refuses_non_empty_target_without_force(tmp_path):
    """write_config_dir refuses to overwrite a non-empty dir unless forced."""
    from shorewall_nft.config.importer import (
        ImportError as CfgImportError,
    )
    from shorewall_nft.config.importer import (
        write_config_dir,
    )

    cfg = blob_to_config({
        "schema_version": 1,
        "zones": [{"zone": "fw", "type": "firewall"}],
    })
    target = tmp_path / "taken"
    target.mkdir()
    (target / "junk").write_text("hands off")

    with pytest.raises(CfgImportError, match="force=True"):
        write_config_dir(cfg, target)

    # With force=True it proceeds
    written = write_config_dir(cfg, target, force=True)
    assert any(p.name == "zones" for p in written)
