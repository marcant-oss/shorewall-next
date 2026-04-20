"""Unit tests for shorewall_nft_stagelab.report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shorewall_nft_stagelab.report import (
    RunReport,
    ScenarioResult,
    _render_markdown,
    write,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _throughput_report() -> RunReport:
    return RunReport(
        run_id="2026-04-20T15:00:00Z",
        config_path="/etc/shorewall46/stagelab.yaml",
        scenarios=[
            ScenarioResult(
                scenario_id="tput-001",
                kind="throughput",
                ok=True,
                duration_s=30.0,
                raw={"gbps": 9.87, "retransmits": 3, "duration_s": 30.01},
            )
        ],
    )


def _rule_scan_report() -> RunReport:
    mismatches = [
        # Two false-drops (expected accept, got drop)
        {
            "probe_id": 101,
            "src_ip": "10.0.1.5",
            "dst_ip": "10.0.2.10",
            "proto": "tcp/443",
            "expected": "accept",
            "actual": "drop",
            "oracle_rule": "fw-in chain: drop tcp dport 443",
        },
        {
            "probe_id": 102,
            "src_ip": "10.0.1.6",
            "dst_ip": "10.0.2.11",
            "proto": "udp/53",
            "expected": "accept",
            "actual": "drop",
            "oracle_rule": "",
        },
        # One false-accept (expected drop, got accept)
        {
            "probe_id": 201,
            "src_ip": "192.168.99.1",
            "dst_ip": "10.0.2.1",
            "proto": "tcp/22",
            "expected": "drop",
            "actual": "accept",
            "oracle_rule": "fw-in chain: drop src 192.168.99.0/24",
        },
    ]
    return RunReport(
        run_id="2026-04-20T16:00:00Z",
        config_path="/etc/shorewall46/stagelab.yaml",
        scenarios=[
            ScenarioResult(
                scenario_id="scan-001",
                kind="rule_scan",
                ok=False,
                duration_s=5.2,
                raw={
                    "total_probes": 500,
                    "passed": 497,
                    "mismatches": mismatches,
                },
            )
        ],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_write_creates_dir_and_files(tmp_path: Path) -> None:
    run = _throughput_report()
    result_dir = write(run, tmp_path)

    assert result_dir == tmp_path / run.run_id
    assert result_dir.is_dir()
    assert (result_dir / "run.json").is_file()
    assert (result_dir / "summary.md").is_file()

    # Basic sanity: JSON is valid and contains run_id
    data = json.loads((result_dir / "run.json").read_text())
    assert data["run_id"] == run.run_id
    assert data["config_path"] == run.config_path
    assert len(data["scenarios"]) == 1


def test_write_refuses_overwrite(tmp_path: Path) -> None:
    run = _throughput_report()
    # Pre-create the run directory
    (tmp_path / run.run_id).mkdir()

    with pytest.raises(FileExistsError):
        write(run, tmp_path)


def test_markdown_rule_scan_splits_fd_fa() -> None:
    run = _rule_scan_report()
    md = _render_markdown(run)

    # Must contain false-drop header with count 2
    assert "False-drop (expected accept but dropped): 2" in md
    # Must contain false-accept header with count 1
    assert "False-accept (expected drop but accepted): 1" in md

    # The oracle_rule snippet for probe 101 must appear
    assert "fw-in chain: drop tcp dport 443" in md
    # The oracle_rule snippet for probe 201 must appear
    assert "fw-in chain: drop src 192.168.99.0/24" in md

    # Probe IDs must appear
    assert "probe 101" in md
    assert "probe 201" in md

    # Verify the counts are NOT swapped
    lines = md.splitlines()
    fd_line = next(l for l in lines if "False-drop" in l)
    fa_line = next(l for l in lines if "False-accept" in l)
    assert "2" in fd_line
    assert "1" in fa_line


def test_markdown_throughput_renders() -> None:
    run = _throughput_report()
    md = _render_markdown(run)

    # Must contain the Gbps value
    assert "9.870" in md or "9.87" in md
    # Scenario heading
    assert "tput-001" in md
    assert "throughput" in md
    assert "OK" in md
