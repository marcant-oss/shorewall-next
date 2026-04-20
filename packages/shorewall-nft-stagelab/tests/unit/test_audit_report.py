"""Unit tests for audit_report.py."""

from __future__ import annotations

import json
from pathlib import Path

from shorewall_nft_stagelab import audit_report as ar

# ---------------------------------------------------------------------------
# 1. Category mapping covers all known scenario kinds
# ---------------------------------------------------------------------------


def test_category_mapping_covers_all_kinds():
    """Every kind literal in the config discriminated union must appear in
    _CATEGORY_MAP or intentionally fall back to 'Other' via classify()."""
    from shorewall_nft_stagelab.config import (
        ConnStormAstfScenario,
        ConnStormScenario,
        DnsDosScenario,
        HalfOpenDosScenario,
        RuleCoverageMatrixScenario,
        RuleScanScenario,
        SynFloodDosScenario,
        ThroughputDpdkScenario,
        ThroughputScenario,
        TuningSweepScenario,
    )

    known_kinds = {
        ThroughputScenario.model_fields["kind"].default,
        ConnStormScenario.model_fields["kind"].default,
        RuleScanScenario.model_fields["kind"].default,
        TuningSweepScenario.model_fields["kind"].default,
        ThroughputDpdkScenario.model_fields["kind"].default,
        ConnStormAstfScenario.model_fields["kind"].default,
        SynFloodDosScenario.model_fields["kind"].default,
        DnsDosScenario.model_fields["kind"].default,
        HalfOpenDosScenario.model_fields["kind"].default,
        RuleCoverageMatrixScenario.model_fields["kind"].default,
    }

    for kind in known_kinds:
        # Must either be in the explicit map or classify() returns "Other"
        cat, _ = ar.classify({"kind": kind, "ok": False})
        assert cat in ar._CATEGORY_SEVERITY_WEIGHT, (
            f"kind={kind!r} mapped to category {cat!r} which is not in "
            "_CATEGORY_SEVERITY_WEIGHT — add it or update the map"
        )


# ---------------------------------------------------------------------------
# 2. Grade thresholds
# ---------------------------------------------------------------------------


def test_grade_thresholds():
    assert ar.grade(95.0) == "A+"
    assert ar.grade(100.0) == "A+"
    assert ar.grade(90.0) == "A"
    assert ar.grade(89.0) == "B"
    assert ar.grade(80.0) == "B"
    assert ar.grade(79.9) == "C"
    assert ar.grade(70.0) == "C"
    assert ar.grade(60.0) == "D"
    assert ar.grade(59.0) == "F"
    assert ar.grade(0.0) == "F"


# ---------------------------------------------------------------------------
# 3. Risk score weighted calculation
# ---------------------------------------------------------------------------


def _make_payload(scenarios: list[dict]) -> ar.AuditPayload:
    return ar.AuditPayload(
        run_id="test-run",
        operator="test",
        config_path="test.yaml",
        scenarios=tuple(scenarios),
        recommendations=(),
        sut_facts={},
        setup_facts={},
    )


def test_risk_score_weighted():
    # 1 failed Evasion (weight=10) + 2 failed Performance (weight=2 each) = 14
    payload = _make_payload([
        {"scenario_id": "ev1", "kind": "evasion_probes", "ok": False, "duration_s": 5.0, "raw": {}},
        {"scenario_id": "tp1", "kind": "throughput", "ok": False, "duration_s": 5.0, "raw": {}},
        {"scenario_id": "tp2", "kind": "throughput", "ok": False, "duration_s": 5.0, "raw": {}},
    ])
    assert ar.risk_score(payload) == 14


# ---------------------------------------------------------------------------
# 4. render_html produces bidirectional anchors
# ---------------------------------------------------------------------------


def test_render_html_has_both_anchors():
    payload = _make_payload([
        {
            "scenario_id": "smoke-tcp",
            "kind": "throughput",
            "ok": True,
            "duration_s": 10.0,
            "raw": {"gbps": 9.5},
            "note": "",
        }
    ])
    html = ar.render_html(payload)

    # Summary anchor
    assert 'id="summary-smoke-tcp"' in html
    # Detail anchor
    assert 'id="detail-smoke-tcp"' in html
    # Bidirectional link from summary to detail
    assert 'href="#detail-smoke-tcp"' in html
    # Bidirectional link from detail back to summary
    assert 'href="#summary-smoke-tcp"' in html


# ---------------------------------------------------------------------------
# 5. load_runs merges two run dirs
# ---------------------------------------------------------------------------


def test_load_runs_multi_dir_merges(tmp_path: Path):
    d1 = tmp_path / "2026-04-20T10:00:00Z"
    d1.mkdir()
    (d1 / "run.json").write_text(json.dumps({
        "run_id": "2026-04-20T10:00:00Z",
        "config_path": "a.yaml",
        "scenarios": [
            {"scenario_id": "s1", "kind": "throughput", "ok": True,
             "duration_s": 5.0, "raw": {}},
        ],
        "recommendations": [],
    }))

    d2 = tmp_path / "2026-04-20T11:00:00Z"
    d2.mkdir()
    (d2 / "run.json").write_text(json.dumps({
        "run_id": "2026-04-20T11:00:00Z",
        "config_path": "b.yaml",
        "scenarios": [
            {"scenario_id": "s2", "kind": "rule_scan", "ok": False,
             "duration_s": 3.0, "raw": {}},
        ],
        "recommendations": [],
    }))

    payload = ar.load_runs([d1, d2])

    scenario_ids = {s["scenario_id"] for s in payload.scenarios}
    assert "s1" in scenario_ids
    assert "s2" in scenario_ids
    assert len(payload.scenarios) == 2
    # run_id should be the most recent (last in sorted order)
    assert payload.run_id == "2026-04-20T11:00:00Z"
