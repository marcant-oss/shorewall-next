"""Unit tests for audit_report.py."""

from __future__ import annotations

import json
from pathlib import Path

from shorewall_nft_stagelab import audit_report as ar
from shorewall_nft_stagelab import standards as _standards

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


# ---------------------------------------------------------------------------
# 6. HTML renders Test-ID and Standard columns for known test_id
# ---------------------------------------------------------------------------


def test_render_html_test_id_and_standard_columns():
    """When a scenario has test_id known to standards.TEST_ID, HTML includes both columns."""
    test_id = "owasp-fw-3-default-deny"
    assert test_id in _standards.TEST_ID, "precondition: test_id must exist in TEST_ID"

    payload = _make_payload([
        {
            "scenario_id": "scan-wan",
            "kind": "rule_scan",
            "ok": True,
            "duration_s": 3.0,
            "raw": {},
            "test_id": test_id,
            "standard_refs": ["owasp/FW-3"],
            "criteria_results": {},
            "note": "",
        }
    ])
    html = ar.render_html(payload)
    assert "Test-ID" in html
    assert "Standard" in html
    assert test_id in html
    ref = _standards.lookup(test_id)
    assert ref.control in html


# ---------------------------------------------------------------------------
# 7. HTML gracefully handles test_id=None (empty cells, no exception)
# ---------------------------------------------------------------------------


def test_render_html_none_test_id_no_error():
    """When test_id is None, HTML renders without error and leaves cells empty."""
    payload = _make_payload([
        {
            "scenario_id": "anon-scan",
            "kind": "rule_scan",
            "ok": False,
            "duration_s": 1.0,
            "raw": {},
            "test_id": None,
            "standard_refs": [],
            "criteria_results": {},
            "note": "",
        }
    ])
    html = ar.render_html(payload)
    # No exception; Test-ID column still present in header
    assert "Test-ID" in html
    assert "Standard" in html
    # No stray text from a None test_id
    assert "None" not in html


# ---------------------------------------------------------------------------
# 8. render_json produces valid JSON with schema_version==1
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 9. render_html with simlab_report: "Correctness (simlab)" heading present
# ---------------------------------------------------------------------------


def _make_simlab_json(tmp_path: Path, fail_accept: int = 0, fail_drop: int = 0) -> Path:
    """Write a minimal simlab.json fixture and return the path."""
    simlab_path = tmp_path / "simlab.json"
    scenarios = [
        {
            "scenario_id": "simlab-fail-accept",
            "kind": "simlab_correctness",
            "ok": fail_accept == 0,
            "duration_s": 0.0,
            "test_id": "simlab-fail-accept",
            "standard_refs": ["cc-iso-15408-fdp-iff-1"],
            "criteria_results": {"fail_accept_is_zero": fail_accept == 0},
            "raw": {"count": fail_accept},
            "source": "simlab",
        },
        {
            "scenario_id": "simlab-fail-drop",
            "kind": "simlab_correctness",
            "ok": fail_drop <= 2,
            "duration_s": 0.0,
            "test_id": "simlab-fail-drop",
            "standard_refs": ["cc-iso-15408-fdp-iff-1"],
            "criteria_results": {"fail_drop_within_tolerance": fail_drop <= 2},
            "raw": {"count": fail_drop},
            "source": "simlab",
        },
    ]
    import json as _json
    simlab_path.write_text(_json.dumps({
        "schema_version": 1,
        "kind": "simlab-correctness",
        "run_name": "smoke",
        "run_ts": None,
        "summary": {
            "pass_accept": 10,
            "pass_drop": 5,
            "fail_accept": fail_accept,
            "fail_drop": fail_drop,
            "total": 10 + 5 + fail_accept + fail_drop,
            "mismatch_rate": 0.0,
        },
        "failures": [],
        "scenarios": scenarios,
    }, indent=2))
    return simlab_path


def test_render_html_simlab_section_present(tmp_path: Path) -> None:
    """render_html with simlab_report set includes 'Correctness (simlab)' heading."""
    simlab_path = _make_simlab_json(tmp_path)
    payload = ar.AuditPayload(
        run_id="test-run",
        operator="test",
        config_path="test.yaml",
        scenarios=tuple([
            {"scenario_id": "tp1", "kind": "throughput", "ok": True,
             "duration_s": 5.0, "raw": {}, "note": ""},
        ]),
        recommendations=(),
        sut_facts={},
        setup_facts={},
        simlab_report=simlab_path,
    )
    html = ar.render_html(payload)
    assert "Correctness (simlab)" in html
    assert "simlab-fail-accept" in html
    assert "simlab-fail-drop" in html


def test_render_html_no_simlab_no_section() -> None:
    """render_html without simlab_report must NOT contain 'Correctness (simlab)'."""
    payload = _make_payload([
        {"scenario_id": "tp1", "kind": "throughput", "ok": True,
         "duration_s": 5.0, "raw": {}, "note": ""},
    ])
    html = ar.render_html(payload)
    assert "Correctness (simlab)" not in html


# ---------------------------------------------------------------------------
# 10. render_json with simlab_report: source tags present on all scenarios
# ---------------------------------------------------------------------------


def test_render_json_with_simlab(tmp_path: Path) -> None:
    """render_json merges simlab scenarios tagged source='simlab'; stagelab ones
    get source='stagelab'."""
    simlab_path = _make_simlab_json(tmp_path)
    payload = ar.AuditPayload(
        run_id="test-run",
        operator="test",
        config_path="test.yaml",
        scenarios=tuple([
            {"scenario_id": "tp1", "kind": "throughput", "ok": True,
             "duration_s": 5.0, "raw": {}, "note": ""},
        ]),
        recommendations=(),
        sut_facts={},
        setup_facts={},
        simlab_report=simlab_path,
    )
    doc = json.loads(ar.render_json(payload))

    all_sc = doc["scenarios"]
    # Must have 1 stagelab + 2 simlab
    assert len(all_sc) == 3

    stagelab_sc = [s for s in all_sc if s["source"] == "stagelab"]
    simlab_sc = [s for s in all_sc if s["source"] == "simlab"]
    assert len(stagelab_sc) == 1
    assert len(simlab_sc) == 2

    simlab_ids = {s["scenario_id"] for s in simlab_sc}
    assert simlab_ids == {"simlab-fail-accept", "simlab-fail-drop"}


def test_render_json_without_simlab_no_source_tag() -> None:
    """render_json without simlab_report: stagelab scenarios tagged 'stagelab'."""
    payload = _make_payload([
        {"scenario_id": "tp1", "kind": "throughput", "ok": True,
         "duration_s": 5.0, "raw": {}},
    ])
    doc = json.loads(ar.render_json(payload))
    for s in doc["scenarios"]:
        assert s["source"] == "stagelab"


# ---------------------------------------------------------------------------
# 11. load_runs preserves test_id + standard_refs from run.json
# ---------------------------------------------------------------------------


def test_load_runs_preserves_test_id(tmp_path: Path) -> None:
    """load_runs carries test_id and standard_refs from run.json into AuditPayload."""
    d1 = tmp_path / "2026-04-20T12:00:00Z"
    d1.mkdir()
    (d1 / "run.json").write_text(json.dumps({
        "run_id": "2026-04-20T12:00:00Z",
        "config_path": "a.yaml",
        "scenarios": [
            {
                "scenario_id": "owasp-fw-1-config-review",
                "kind": "rule_coverage_matrix",
                "ok": True,
                "duration_s": 2.5,
                "raw": {},
                "test_id": "owasp-fw-1-config-review",
                "standard_refs": ["owasp-fw-1"],
            },
        ],
        "recommendations": [],
    }))
    payload = ar.load_runs([d1])
    assert len(payload.scenarios) == 1
    sc = payload.scenarios[0]
    assert sc["test_id"] == "owasp-fw-1-config-review"
    assert sc["standard_refs"] == ["owasp-fw-1"]


def test_load_runs_backcompat_missing_fields(tmp_path: Path) -> None:
    """Old run.json without test_id/standard_refs still loads (back-compat)."""
    d1 = tmp_path / "2026-04-20T13:00:00Z"
    d1.mkdir()
    (d1 / "run.json").write_text(json.dumps({
        "run_id": "2026-04-20T13:00:00Z",
        "config_path": "old.yaml",
        "scenarios": [
            {
                "scenario_id": "legacy-scan",
                "kind": "rule_scan",
                "ok": False,
                "duration_s": 1.0,
                "raw": {},
                # no test_id, no standard_refs
            },
        ],
        "recommendations": [],
    }))
    payload = ar.load_runs([d1])
    sc = payload.scenarios[0]
    assert sc["test_id"] is None
    assert sc["standard_refs"] == []


# ---------------------------------------------------------------------------
# 12. render_json emits test_id + standard_refs per scenario
# ---------------------------------------------------------------------------


def test_render_json_emits_test_id_and_standard_refs() -> None:
    """render_json must include test_id and standard_refs for each scenario."""
    payload = _make_payload([
        {
            "scenario_id": "owasp-fw-3-default-deny",
            "kind": "rule_scan",
            "ok": True,
            "duration_s": 3.0,
            "raw": {},
            "test_id": "owasp-fw-3-default-deny",
            "standard_refs": ["owasp-fw-3"],
        }
    ])
    d = json.loads(ar.render_json(payload))
    sc = d["scenarios"][0]
    assert sc["test_id"] == "owasp-fw-3-default-deny"
    assert sc["standard_refs"] == ["owasp-fw-3"]


# ---------------------------------------------------------------------------
# 13. render_html contains test_id for a scenario loaded via load_runs
# ---------------------------------------------------------------------------


def test_render_html_test_id_from_load_runs(tmp_path: Path) -> None:
    """End-to-end: run.json with test_id → load_runs → render_html contains test_id string."""
    d1 = tmp_path / "2026-04-20T14:00:00Z"
    d1.mkdir()
    (d1 / "run.json").write_text(json.dumps({
        "run_id": "2026-04-20T14:00:00Z",
        "config_path": "a.yaml",
        "scenarios": [
            {
                "scenario_id": "owasp-fw-1-config-review",
                "kind": "rule_coverage_matrix",
                "ok": True,
                "duration_s": 2.5,
                "raw": {},
                "test_id": "owasp-fw-1-config-review",
                "standard_refs": ["owasp-fw-1"],
                "note": "",
                "criteria_results": {},
            },
        ],
        "recommendations": [],
    }))
    payload = ar.load_runs([d1])
    html = ar.render_html(payload)
    assert "owasp-fw-1-config-review" in html


def test_render_json_valid():
    """render_json returns valid JSON; schema_version==1; scenarios have expected keys."""
    payload = _make_payload([
        {
            "scenario_id": "tp1",
            "kind": "throughput",
            "ok": True,
            "duration_s": 10.0,
            "raw": {"gbps": 9.5},
            "test_id": "owasp-fw-3-default-deny",
            "standard_refs": ["owasp-fw-3"],
            "criteria_results": {"min_gbps": True},
            "note": "",
        }
    ])
    j = ar.render_json(payload)
    d = json.loads(j)

    assert d["schema_version"] == 1
    assert d["run_id"] == "test-run"
    assert len(d["scenarios"]) == 1
    sc = d["scenarios"][0]
    assert sc["scenario_id"] == "tp1"
    assert sc["test_id"] == "owasp-fw-3-default-deny"
    assert sc["criteria_results"] == {"min_gbps": True}
    assert sc["standard"] == "owasp"
    assert sc["control"] == "FW-3"
