"""Stress test: 50 rule_scan scenarios in a single controller run.

Validates that controller state (scenario list, metric_rows, connections)
stays uncorrupted across many concurrent scenario dispatches. No root
required — send_probe / collect_oracle_verdict return error responses
from the agent (unknown handler), which is the intended outcome: we test
bookkeeping, not real packet traffic.
"""

from __future__ import annotations

import asyncio
import json
import textwrap

import pytest

from shorewall_nft_stagelab import report as report_mod
from shorewall_nft_stagelab.config import load
from shorewall_nft_stagelab.controller import StagelabController, spawn_local

# ---------------------------------------------------------------------------
# YAML builder: 2 hosts, 2 probe endpoints, 50 rule_scan scenarios.
# Scenarios alternate source between ep-0 and ep-1 (~25 each).
# ---------------------------------------------------------------------------

_SCENARIO_COUNT = 50


def _build_yaml(output_dir: str) -> str:
    scenario_entries = []
    for i in range(_SCENARIO_COUNT):
        scenario_entries.append(
            f"  - id: scen_{i:03d}\n"
            f"    kind: rule_scan\n"
            f"    source: ep-{i % 2}\n"
            f"    target_subnet: 10.0.{i % 256}.0/24\n"
            f"    random_count: 1"
        )
    scenarios_yaml = "\n".join(scenario_entries)
    header = textwrap.dedent("""\
        hosts:
          - name: host1
            address: "local:"
          - name: host2
            address: "local:"

        dut:
          kind: external

        endpoints:
          - name: ep-0
            host: host1
            mode: probe
            bridge: br-0
          - name: ep-1
            host: host2
            mode: probe
            bridge: br-1

        scenarios:
    """)
    footer = f"\nreport:\n  output_dir: {output_dir}\n"
    return header + scenarios_yaml + footer


# ---------------------------------------------------------------------------
# Shared async helper
# ---------------------------------------------------------------------------


async def _run_controller(cfg_path) -> "report_mod.RunReport":
    cfg = load(cfg_path)
    controller = StagelabController(cfg, transport_factory=spawn_local, config_path=str(cfg_path))
    try:
        await controller.connect()
        # Deliberately skip setup_endpoints — send_probe will return error,
        # which is what we want for a bookkeeping stress test.
        await controller.start_scraping()  # no-op (no sources defined)
        report = await controller.run_scenarios()
        await controller.stop_scraping()
    finally:
        await controller.close()
    return report


# ---------------------------------------------------------------------------
# Test 1: all 50 scenarios complete, IDs are unique and complete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.timeout(90)
async def test_run_50_scenarios_completes_cleanly(tmp_path):
    """50 rule_scan scenarios run without exception; every scen_000…049 present once."""
    cfg_file = tmp_path / "stress.yaml"
    cfg_file.write_text(_build_yaml(str(tmp_path / "reports")))

    report = await asyncio.wait_for(_run_controller(cfg_file), timeout=90.0)

    # ── Bookkeeping assertions ────────────────────────────────────────────────
    assert len(report.scenarios) == _SCENARIO_COUNT, (
        f"expected {_SCENARIO_COUNT} ScenarioResults, got {len(report.scenarios)}"
    )

    expected_ids = {f"scen_{i:03d}" for i in range(_SCENARIO_COUNT)}
    actual_ids = {s.scenario_id for s in report.scenarios}
    assert actual_ids == expected_ids, (
        f"scenario ID mismatch.\n  missing: {expected_ids - actual_ids}\n"
        f"  extra: {actual_ids - expected_ids}"
    )

    # Each ID appears exactly once (no duplicates despite concurrency).
    id_list = [s.scenario_id for s in report.scenarios]
    assert len(id_list) == len(set(id_list)), "duplicate scenario IDs in report"

    # run_id must be an ISO-8601 UTC timestamp (ends with 'Z').
    assert report.run_id.endswith("Z"), f"run_id not UTC ISO-8601: {report.run_id!r}"
    assert "T" in report.run_id, f"run_id missing 'T' separator: {report.run_id!r}"


# ---------------------------------------------------------------------------
# Test 2: write() produces correct run.json and summary.md
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.timeout(90)
async def test_report_write_atomic_for_50_scenarios(tmp_path):
    """write() produces run.json with 50 scenarios and summary.md with 50 ### headings."""
    reports_dir = tmp_path / "reports"
    cfg_file = tmp_path / "stress.yaml"
    cfg_file.write_text(_build_yaml(str(reports_dir)))

    report = await asyncio.wait_for(_run_controller(cfg_file), timeout=90.0)

    run_dir = report_mod.write(report, reports_dir)

    # ── run.json assertions ───────────────────────────────────────────────────
    run_json_path = run_dir / "run.json"
    assert run_json_path.exists(), "run.json not written"
    payload = json.loads(run_json_path.read_text())
    assert len(payload["scenarios"]) == _SCENARIO_COUNT, (
        f"run.json has {len(payload['scenarios'])} scenario entries, expected {_SCENARIO_COUNT}"
    )
    json_ids = {s["scenario_id"] for s in payload["scenarios"]}
    assert json_ids == {f"scen_{i:03d}" for i in range(_SCENARIO_COUNT)}, (
        "run.json scenario IDs do not match expected set"
    )

    # ── summary.md assertions ─────────────────────────────────────────────────
    summary_path = run_dir / "summary.md"
    assert summary_path.exists(), "summary.md not written"
    summary_text = summary_path.read_text()
    h3_lines = [ln for ln in summary_text.splitlines() if ln.startswith("### ")]
    assert len(h3_lines) == _SCENARIO_COUNT, (
        f"summary.md has {len(h3_lines)} '###' headings, expected {_SCENARIO_COUNT}"
    )
