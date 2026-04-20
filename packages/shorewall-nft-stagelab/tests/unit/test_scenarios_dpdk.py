"""Unit tests for ThroughputDpdkRunner and ConnStormAstfRunner."""

from __future__ import annotations

import textwrap

import yaml

from shorewall_nft_stagelab.config import StagelabConfig
from shorewall_nft_stagelab.scenarios import (
    AgentCommand,
    ConnStormAstfRunner,
    ThroughputDpdkRunner,
    build_runner,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DPDK_CFG_YAML = textwrap.dedent("""\
    hosts:
      - name: thx1
        address: root@192.168.4.73

    dut:
      kind: external

    endpoints:
      - name: dpdk-tx
        host: thx1
        mode: dpdk
        pci_addr: "0000:01:00.0"
        dpdk_cores: [2, 3]
        hugepages_gib: 4
        trex_role: client
      - name: dpdk-rx
        host: thx1
        mode: dpdk
        pci_addr: "0000:01:00.1"
        dpdk_cores: [4, 5]
        hugepages_gib: 4
        trex_role: server

    scenarios:
      - id: tput-dpdk-1
        kind: throughput_dpdk
        source: dpdk-tx
        sink: dpdk-rx
        duration_s: 10
        multiplier: "10gbps"

    report:
      output_dir: /tmp/out
""")

_ASTF_CFG_YAML = textwrap.dedent("""\
    hosts:
      - name: thx1
        address: root@192.168.4.73

    dut:
      kind: external

    endpoints:
      - name: dpdk-client
        host: thx1
        mode: dpdk
        pci_addr: "0000:01:00.0"
        dpdk_cores: [2, 3]
        hugepages_gib: 4
        trex_role: client
      - name: dpdk-server
        host: thx1
        mode: dpdk
        pci_addr: "0000:01:00.1"
        dpdk_cores: [4, 5]
        hugepages_gib: 4
        trex_role: server

    scenarios:
      - id: astf-storm-1
        kind: conn_storm_astf
        source: dpdk-client
        sink: dpdk-server
        profile_py: /opt/trex/profiles/http.py
        duration_s: 30
        multiplier: 2.0
        expect_min_concurrent: 100000

    report:
      output_dir: /tmp/out
""")


def _load_cfg(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


# ---------------------------------------------------------------------------
# ThroughputDpdkRunner tests
# ---------------------------------------------------------------------------


def test_throughput_dpdk_plan_one_command():
    """build_runner(ThroughputDpdkScenario).plan() returns exactly 1 AgentCommand
    with kind=run_trex_stateless on the source endpoint."""
    cfg = _load_cfg(_DPDK_CFG_YAML)
    sc = cfg.scenarios[0]
    assert sc.kind == "throughput_dpdk"
    runner = build_runner(sc)
    assert isinstance(runner, ThroughputDpdkRunner)

    commands = runner.plan(cfg)
    assert len(commands) == 1
    cmd = commands[0]
    assert isinstance(cmd, AgentCommand)
    assert cmd.kind == "run_trex_stateless"
    assert cmd.endpoint_name == "dpdk-tx"
    assert cmd.spec["_scenario_id"] == "tput-dpdk-1"


def test_throughput_dpdk_summarize_ok():
    """summarize() with ok=True result surfaces throughput_gbps into raw and returns ok=True."""
    cfg = _load_cfg(_DPDK_CFG_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    cmd_result = {
        "tool": "trex-stl",
        "ok": True,
        "throughput_gbps": 9.5,
        "pps": 1_000_000.0,
        "errors": 0,
        "duration_s": 10.0,
    }
    result = runner.summarize([cmd_result])
    assert result.ok is True
    assert result.scenario_id == "tput-dpdk-1"
    assert result.kind == "throughput_dpdk"
    assert result.raw["throughput_gbps"] == 9.5


def test_throughput_dpdk_summarize_on_error():
    """summarize() with ok=False result returns ScenarioResult with ok=False."""
    cfg = _load_cfg(_DPDK_CFG_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    cmd_result = {
        "tool": "trex-stl",
        "ok": False,
        "throughput_gbps": 0.0,
        "pps": 0.0,
        "errors": 42,
        "duration_s": 2.0,
    }
    result = runner.summarize([cmd_result])
    assert result.ok is False
    assert result.scenario_id == "tput-dpdk-1"


# ---------------------------------------------------------------------------
# ConnStormAstfRunner tests
# ---------------------------------------------------------------------------


def test_conn_storm_astf_plan_one_command():
    """build_runner(ConnStormAstfScenario).plan() returns exactly 1 run_trex_astf command."""
    cfg = _load_cfg(_ASTF_CFG_YAML)
    sc = cfg.scenarios[0]
    assert sc.kind == "conn_storm_astf"
    runner = build_runner(sc)
    assert isinstance(runner, ConnStormAstfRunner)

    commands = runner.plan(cfg)
    assert len(commands) == 1
    cmd = commands[0]
    assert isinstance(cmd, AgentCommand)
    assert cmd.kind == "run_trex_astf"
    assert cmd.endpoint_name == "dpdk-client"
    assert cmd.spec["profile_py"] == "/opt/trex/profiles/http.py"
    assert cmd.spec["_scenario_id"] == "astf-storm-1"


def test_conn_storm_astf_summarize_meets_threshold():
    """summarize() with concurrent_sessions >= threshold returns ok=True."""
    cfg = _load_cfg(_ASTF_CFG_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    cmd_result = {
        "tool": "trex-astf",
        "ok": True,
        "concurrent_sessions": 200_000,
        "new_sessions_per_s": 5_000.0,
        "errors": 0,
        "duration_s": 30.0,
    }
    result = runner.summarize([cmd_result])
    assert result.ok is True
    assert result.raw["concurrent_sessions"] == 200_000
    assert result.raw["expect_min_concurrent"] == 100_000


def test_conn_storm_astf_summarize_below_threshold():
    """summarize() with concurrent_sessions < threshold returns ok=False."""
    cfg = _load_cfg(_ASTF_CFG_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    cmd_result = {
        "tool": "trex-astf",
        "ok": True,
        "concurrent_sessions": 50_000,
        "new_sessions_per_s": 1_000.0,
        "errors": 0,
        "duration_s": 30.0,
    }
    result = runner.summarize([cmd_result])
    assert result.ok is False
    assert result.raw["concurrent_sessions"] == 50_000
