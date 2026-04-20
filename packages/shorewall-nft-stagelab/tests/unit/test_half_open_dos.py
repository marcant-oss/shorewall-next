"""Unit tests for HalfOpenDosScenario (config) and HalfOpenDosRunner (scenarios)."""

from __future__ import annotations

import textwrap

import yaml

from shorewall_nft_stagelab.config import StagelabConfig
from shorewall_nft_stagelab.scenarios import (
    AgentCommand,
    HalfOpenDosRunner,
    build_runner,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_YAML = textwrap.dedent("""\
    hosts:
      - name: tester
        address: root@192.0.2.73

    dut:
      kind: external

    endpoints:
      - name: dpdk-src
        host: tester
        mode: dpdk
        pci_addr: "0000:01:00.0"
        dpdk_cores: [2, 3]
        hugepages_gib: 4
        trex_role: client
        ipv4: 10.0.0.1/24
      - name: dpdk-sink
        host: tester
        mode: dpdk
        pci_addr: "0000:01:00.1"
        dpdk_cores: [4, 5]
        hugepages_gib: 4
        trex_role: server
        ipv4: 10.0.0.200/24

    dos_target_allowlist:
      - 10.0.0.0/24

    scenarios:
      - id: half-open-1
        kind: dos_half_open
        source: dpdk-src
        sink: dpdk-sink
        duration_s: 30
        target_conns: 5000
        open_rate_per_s: 200
        dst_port: 80

    report:
      output_dir: /tmp/out
""")


def _load(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


# ---------------------------------------------------------------------------
# Test 1 — plan() returns 1 AgentCommand with kind="run_trex_astf"
# ---------------------------------------------------------------------------


def test_half_open_plan_one_astf_command():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    assert sc.kind == "dos_half_open"
    runner = build_runner(sc)
    assert isinstance(runner, HalfOpenDosRunner)

    commands = runner.plan(cfg)
    assert len(commands) == 1
    cmd = commands[0]
    assert isinstance(cmd, AgentCommand)
    assert cmd.kind == "run_trex_astf"
    assert cmd.endpoint_name == "dpdk-src"
    assert cmd.spec["duration_s"] == 30
    assert "profile_text" in cmd.spec


# ---------------------------------------------------------------------------
# Test 2 — profile_text contains "connect" and the target_conns literal
# ---------------------------------------------------------------------------


def test_half_open_profile_text_contains_connect_and_idle():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    commands = runner.plan(cfg)
    profile_text = commands[0].spec["profile_text"]

    assert "connect" in profile_text
    assert str(sc.target_conns) in profile_text  # "5000" embedded in template


# ---------------------------------------------------------------------------
# Test 3 — summarize: observed_conns >= target_conns → ok=True
# ---------------------------------------------------------------------------


def test_half_open_summarize_pass():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    result = runner.summarize([{
        "ok": True,
        "concurrent_sessions": 10000,
        "duration_s": 30.0,
        "errors": 0,
    }])
    assert result.ok is True
    assert result.scenario_id == "half-open-1"
    assert result.kind == "dos_half_open"
    assert result.raw["observed_conns"] == 10000
    assert result.raw["conntrack_saturated"] is False


# ---------------------------------------------------------------------------
# Test 4 — summarize: observed_conns << target_conns → ok=False + saturated
# ---------------------------------------------------------------------------


def test_half_open_summarize_fail_conntrack_exhaustion():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    result = runner.summarize([{
        "ok": True,
        "concurrent_sessions": 100,
        "duration_s": 30.0,
        "errors": 0,
    }])
    assert result.ok is False
    assert result.raw["conntrack_saturated"] is True
    assert result.raw["observed_conns"] == 100
    assert result.raw["target_conns"] == 5000
