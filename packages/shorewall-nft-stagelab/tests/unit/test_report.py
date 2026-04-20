"""Unit tests for shorewall_nft_stagelab.report."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
import yaml

from shorewall_nft_stagelab.advisor import Recommendation
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


# ---------------------------------------------------------------------------
# New tests: recommendations in report
# ---------------------------------------------------------------------------


def _two_recommendations() -> tuple[Recommendation, ...]:
    return (
        Recommendation(
            tier="A",
            signal="rx_no_buffer",
            action="ethtool -G eth0 rx 4096",
            rationale="rx_no_buffer_count=42 observed on thx1-eth0 under throughput",
            target="testhost",
            confidence="high",
        ),
        Recommendation(
            tier="B",
            signal="conntrack_headroom",
            action="sysctl -w net.netfilter.nf_conntrack_max=8388608",
            rationale="conntrack_count=900000 / conntrack_max=1000000 (90.0% — headroom below 20%)",
            target="fw",
            confidence="medium",
        ),
    )


def test_recommendations_yaml_written_when_nonempty(tmp_path: Path) -> None:
    run = RunReport(
        run_id="2026-04-20T17:00:00Z",
        config_path="/etc/stagelab.yaml",
        scenarios=[],
        recommendations=_two_recommendations(),
    )
    run_dir = write(run, tmp_path)

    yaml_path = run_dir / "recommendations.yaml"
    assert yaml_path.is_file(), "recommendations.yaml must be written when non-empty"

    data = yaml.safe_load(yaml_path.read_text())
    recs = data["recommendations"]
    assert len(recs) == 2

    # Verify key fields of first entry
    assert recs[0]["tier"] == "A"
    assert recs[0]["signal"] == "rx_no_buffer"
    assert recs[0]["target"] == "testhost"

    # Verify key fields of second entry
    assert recs[1]["tier"] == "B"
    assert recs[1]["signal"] == "conntrack_headroom"
    assert recs[1]["target"] == "fw"


def test_recommendations_section_in_markdown() -> None:
    rec = Recommendation(
        tier="A",
        signal="rx_no_buffer",
        action="ethtool -G eth0 rx 4096",
        rationale="rx_no_buffer_count=42 observed",
        target="testhost",
        confidence="medium",
    )
    run = RunReport(
        run_id="2026-04-20T18:00:00Z",
        config_path="/etc/stagelab.yaml",
        scenarios=[],
        recommendations=(rec,),
    )
    md = _render_markdown(run)

    assert "## Recommendations" in md
    assert "rx_no_buffer" in md
    assert "ethtool -G eth0 rx 4096" in md


# ---------------------------------------------------------------------------
# New tests: tuning_sweep report rendering
# ---------------------------------------------------------------------------


def _sweep_result(scenario_id: str = "sweep-1") -> ScenarioResult:
    points = [
        {"point": {"rss_queues": 1, "rmem_max": 1048576}, "throughput_gbps": 5.2, "ok": True},
        {"point": {"rss_queues": 8, "rmem_max": 16777216}, "throughput_gbps": 18.3, "ok": True},
    ]
    best = points[1]
    return ScenarioResult(
        scenario_id=scenario_id,
        kind="tuning_sweep",
        ok=True,
        duration_s=0.0,
        raw={"points": points, "optimum": best, "tool": "tuning_sweep"},
    )


def test_sweep_markdown_has_table() -> None:
    """_render_markdown for tuning_sweep emits a Markdown table with axis columns."""
    run = RunReport(
        run_id="2026-04-20T19:00:00Z",
        config_path="/etc/stagelab.yaml",
        scenarios=[_sweep_result()],
    )
    md = _render_markdown(run)

    assert "tuning_sweep" in md
    assert "sweep-1" in md
    # Table header row must be present
    assert "| rss_queues |" in md
    assert "| rmem_max |" in md
    assert "throughput_gbps" in md
    # Optimum line
    assert "18.3 Gbps" in md


def test_sweep_csv_written(tmp_path: Path) -> None:
    """write() emits sweep-<id>.csv with correct header and data rows."""
    run = RunReport(
        run_id="2026-04-20T20:00:00Z",
        config_path="/etc/stagelab.yaml",
        scenarios=[_sweep_result("my-sweep")],
    )
    run_dir = write(run, tmp_path)

    csv_path = run_dir / "sweep-my-sweep.csv"
    assert csv_path.is_file(), "sweep CSV file must be written"

    rows = list(csv.DictReader(io.StringIO(csv_path.read_text())))
    assert len(rows) == 2

    # Header must include the axes and metrics columns
    fieldnames = list(rows[0].keys())
    assert "rss_queues" in fieldnames
    assert "rmem_max" in fieldnames
    assert "throughput_gbps" in fieldnames
    assert "ok" in fieldnames

    # Verify values
    assert rows[0]["rss_queues"] == "1"
    assert rows[1]["throughput_gbps"] == "18.300"
    assert rows[1]["ok"] == "true"
