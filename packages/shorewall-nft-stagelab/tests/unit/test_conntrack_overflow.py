"""Unit tests for ConntrackOverflowScenario (config) and ConntrackOverflowRunner."""

from __future__ import annotations

import textwrap

import pytest
import yaml

from shorewall_nft_stagelab.config import StagelabConfig
from shorewall_nft_stagelab.controller import _compute_conntrack_window_delta
from shorewall_nft_stagelab.metrics import MetricRow
from shorewall_nft_stagelab.scenarios import (
    AgentCommand,
    ConntrackOverflowRunner,
    build_runner,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_YAML = textwrap.dedent("""\
    hosts:
      - name: tester
        address: root@192.168.4.73

    dut:
      kind: external

    endpoints:
      - name: src
        host: tester
        mode: native
        nic: eth0
        vlan: 10
        ipv4: 10.0.10.1/24
        ipv4_gw: 10.0.10.254
      - name: sink
        host: tester
        mode: native
        nic: eth0
        vlan: 20
        ipv4: 10.0.20.1/24
        ipv4_gw: 10.0.20.254

    scenarios:
      - id: cto1
        kind: conntrack_overflow
        source: src
        sink: sink
        fw_host: "root@fw-under-test"
        duration_s: 30
        rate_new_per_s: 20000
        test_id: nist-sc-5-dos-conntrack
        standard_refs: [nist-800-53-sc-5]
        acceptance_criteria:
          expect_table_fill_pct_min: 95
          expect_no_new_conntracks_when_full: true

    report:
      output_dir: /tmp/out
""")


def _load(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


# ---------------------------------------------------------------------------
# Test 1 — config parses and validates correctly
# ---------------------------------------------------------------------------


def test_conntrack_overflow_config_parse():
    cfg = _load(_BASE_YAML)
    assert len(cfg.scenarios) == 1
    sc = cfg.scenarios[0]
    assert sc.kind == "conntrack_overflow"
    assert sc.id == "cto1"
    assert sc.fw_host == "root@fw-under-test"
    assert sc.duration_s == 30
    assert sc.rate_new_per_s == 20000
    assert sc.test_id == "nist-sc-5-dos-conntrack"
    assert sc.standard_refs == ["nist-800-53-sc-5"]
    assert sc.acceptance_criteria["expect_table_fill_pct_min"] == 95


# ---------------------------------------------------------------------------
# Test 2 — plan() returns 3 AgentCommands with correct kinds
# ---------------------------------------------------------------------------


def test_conntrack_overflow_plan_three_commands():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)
    assert isinstance(runner, ConntrackOverflowRunner)

    commands = runner.plan(cfg)
    assert len(commands) == 3
    kinds = [c.kind for c in commands]
    assert kinds == [
        "conntrack_overflow_fill",
        "conntrack_overflow_probe",
        "conntrack_overflow_inspect",
    ]
    # fill command carries expected spec keys
    fill_cmd: AgentCommand = commands[0]
    assert fill_cmd.endpoint_name == "src"
    assert fill_cmd.spec["duration_s"] == 30
    assert fill_cmd.spec["rate_new_per_s"] == 20000
    assert fill_cmd.spec["sink_ip"] == "10.0.20.1"

    # inspect command carries fw_host
    inspect_cmd: AgentCommand = commands[2]
    assert inspect_cmd.spec["fw_host"] == "root@fw-under-test"


# ---------------------------------------------------------------------------
# Test 3 — summarize: all 3 criteria pass → ok=True
# ---------------------------------------------------------------------------


def test_conntrack_overflow_summarize_all_pass():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    results = [
        {
            "tool": "conntrack_overflow_fill",
            "ok": True,
            "duration_s": 30.0,
        },
        {
            "tool": "conntrack_overflow_probe",
            "ok": True,
            "accepted_count": 0,
            "dropped_count": 10,
        },
        {
            "tool": "conntrack_overflow_inspect",
            "ok": True,
            "count": 65000,
            "max": 65536,
            "dmesg_hits": 7,
        },
    ]
    result = runner.summarize(results)
    assert result.ok is True
    assert result.scenario_id == "cto1"
    assert result.kind == "conntrack_overflow"
    cr = result.raw["criteria_results"]
    assert cr["table_fill_reached"] is True
    assert cr["drops_reported"] is True
    assert cr["probe_after_fill_blocked"] is True
    assert result.raw["fill_pct"] == 99  # 100 * 65000 // 65536


# ---------------------------------------------------------------------------
# Test 4 — summarize: table_fill_reached FAIL → ok=False
# ---------------------------------------------------------------------------


def test_conntrack_overflow_summarize_fill_fail():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    results = [
        {"tool": "conntrack_overflow_fill", "ok": True, "duration_s": 30.0},
        {"tool": "conntrack_overflow_probe", "ok": True, "accepted_count": 0, "dropped_count": 10},
        {
            "tool": "conntrack_overflow_inspect",
            "ok": True,
            "count": 10000,   # only 15% fill — below 95% threshold
            "max": 65536,
            "dmesg_hits": 3,
        },
    ]
    result = runner.summarize(results)
    assert result.ok is False
    cr = result.raw["criteria_results"]
    assert cr["table_fill_reached"] is False
    assert cr["drops_reported"] is True
    assert cr["probe_after_fill_blocked"] is True


# ---------------------------------------------------------------------------
# Test 5 — summarize: drops_reported FAIL (no dmesg hits) → ok=False
# ---------------------------------------------------------------------------


def test_conntrack_overflow_summarize_no_dmesg_drops():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    results = [
        {"tool": "conntrack_overflow_fill", "ok": True, "duration_s": 30.0},
        {"tool": "conntrack_overflow_probe", "ok": True, "accepted_count": 0, "dropped_count": 10},
        {
            "tool": "conntrack_overflow_inspect",
            "ok": True,
            "count": 64000,  # 97% — fill OK
            "max": 65536,
            "dmesg_hits": 0,  # no table full messages in dmesg
        },
    ]
    result = runner.summarize(results)
    assert result.ok is False
    cr = result.raw["criteria_results"]
    assert cr["table_fill_reached"] is True
    assert cr["drops_reported"] is False


# ---------------------------------------------------------------------------
# Test 6 — config parses with new baseline_window_s / dos_window_s fields
# ---------------------------------------------------------------------------


_WINDOWED_YAML = textwrap.dedent("""\
    hosts:
      - name: tester
        address: root@192.168.4.73

    dut:
      kind: external

    endpoints:
      - name: src
        host: tester
        mode: native
        nic: eth0
        vlan: 10
        ipv4: 10.0.10.1/24
        ipv4_gw: 10.0.10.254
      - name: sink
        host: tester
        mode: native
        nic: eth0
        vlan: 20
        ipv4: 10.0.20.1/24
        ipv4_gw: 10.0.20.254

    scenarios:
      - id: cto-windowed
        kind: conntrack_overflow
        source: src
        sink: sink
        fw_host: "root@fw-under-test"
        duration_s: 30
        rate_new_per_s: 20000
        baseline_window_s: 5
        dos_window_s: 10
        acceptance_criteria:
          conntrack_count_increase_ratio_max: 10.0

    report:
      output_dir: /tmp/out
""")


def test_conntrack_overflow_windowed_config_parse():
    cfg = _load(_WINDOWED_YAML)
    sc = cfg.scenarios[0]
    assert sc.baseline_window_s == pytest.approx(5.0)
    assert sc.dos_window_s == pytest.approx(10.0)
    assert sc.acceptance_criteria["conntrack_count_increase_ratio_max"] == pytest.approx(10.0)


def test_conntrack_overflow_windowed_default_fields():
    """Without specifying window fields, defaults of 10.0 are used."""
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    assert sc.baseline_window_s == pytest.approx(10.0)
    assert sc.dos_window_s == pytest.approx(10.0)


# ---------------------------------------------------------------------------
# Test 7 — window_delta helper: 10x conntrack increase → criterion True
# ---------------------------------------------------------------------------


def test_window_delta_10x_increase_over_threshold():
    """With a 10x conntrack increase and threshold=10.0, criterion is True (>threshold)."""
    scenario_start = 100.0
    rows = [
        # baseline window [90, 100]: low counts
        MetricRow(source="fw", ts_unix=91.0, key="node_conntrack_count", value=1000.0),
        MetricRow(source="fw", ts_unix=95.0, key="node_conntrack_count", value=1100.0),
        # dos window [100, 110]: 10× increase
        MetricRow(source="fw", ts_unix=101.0, key="node_conntrack_count", value=9000.0),
        MetricRow(source="fw", ts_unix=105.0, key="node_conntrack_count", value=11000.0),
    ]
    result = _compute_conntrack_window_delta(
        rows,
        scenario_start=scenario_start,
        baseline_window_s=10.0,
        dos_window_s=10.0,
    )
    ratio = result["conntrack_count_increase_ratio"]
    # dos_max=11000, baseline_min=1000 → ratio=11.0 > 10.0
    assert ratio == pytest.approx(11.0)
    threshold = 10.0
    assert ratio > threshold  # over_threshold would be True


# ---------------------------------------------------------------------------
# Test 8 — window_delta helper: no increase → criterion False
# ---------------------------------------------------------------------------


def test_window_delta_no_increase_under_threshold():
    """With no conntrack increase, ratio ≤ threshold → criterion would be False."""
    scenario_start = 100.0
    rows = [
        MetricRow(source="fw", ts_unix=91.0, key="node_conntrack_count", value=5000.0),
        MetricRow(source="fw", ts_unix=95.0, key="node_conntrack_count", value=5100.0),
        MetricRow(source="fw", ts_unix=101.0, key="node_conntrack_count", value=5050.0),
        MetricRow(source="fw", ts_unix=105.0, key="node_conntrack_count", value=5200.0),
    ]
    result = _compute_conntrack_window_delta(
        rows,
        scenario_start=scenario_start,
        baseline_window_s=10.0,
        dos_window_s=10.0,
    )
    ratio = result["conntrack_count_increase_ratio"]
    # dos_max=5200, baseline_min=5000 → ratio≈1.04
    assert ratio == pytest.approx(5200.0 / 5000.0)
    threshold = 10.0
    assert ratio <= threshold  # over_threshold would be False
