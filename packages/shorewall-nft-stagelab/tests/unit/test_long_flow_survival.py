"""Unit tests for LongFlowSurvivalScenario (config) and LongFlowSurvivalRunner (scenarios)."""

from __future__ import annotations

import textwrap

import pytest
import yaml
from pydantic import ValidationError

from shorewall_nft_stagelab.config import LongFlowSurvivalScenario, StagelabConfig
from shorewall_nft_stagelab.scenarios import (
    AgentCommand,
    LongFlowSurvivalRunner,
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
      - name: src-ep
        host: tester
        mode: native
        nic: eth0
        vlan: 10
        ipv4: 10.0.10.1/24
        ipv4_gw: 10.0.10.254
      - name: sink-ep
        host: tester
        mode: native
        nic: eth0
        vlan: 20
        ipv4: 10.0.20.1/24
        ipv4_gw: 10.0.20.254

    scenarios:
      - id: lf-test-1
        kind: long_flow_survival
        source: src-ep
        sink: sink-ep
        fw_host: root@192.168.4.1
        duration_s: 300
        sysctl_key: net.netfilter.nf_conntrack_tcp_timeout_established
        sysctl_value: 240
        expect_flow_dies: false

    report:
      output_dir: /tmp/out
""")


def _load(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


def _make_runner(yaml_text: str = _BASE_YAML) -> tuple[LongFlowSurvivalRunner, StagelabConfig]:
    cfg = _load(yaml_text)
    sc_cfg = cfg.scenarios[0]
    runner = LongFlowSurvivalRunner(sc_cfg)  # type: ignore[arg-type]
    return runner, cfg


# ---------------------------------------------------------------------------
# Test 1 — plan() returns 3 commands: set_fw_sysctl, run_iperf3_server, run_iperf3_client
# ---------------------------------------------------------------------------


def test_plan_emits_sysctl_server_client() -> None:
    """plan() must return exactly 3 AgentCommands in order: sysctl, server, client."""
    runner, cfg = _make_runner()
    cmds = runner.plan(cfg)

    assert len(cmds) == 3
    assert cmds[0].kind == "set_fw_sysctl"
    assert cmds[1].kind == "run_iperf3_server"
    assert cmds[2].kind == "run_iperf3_client"


# ---------------------------------------------------------------------------
# Test 2 — first command spec has sysctl_key + sysctl_value from the scenario
# ---------------------------------------------------------------------------


def test_plan_sysctl_spec_has_key_and_value() -> None:
    """First command spec must contain the sysctl_key and sysctl_value from the scenario."""
    runner, cfg = _make_runner()
    cmds = runner.plan(cfg)

    sysctl_cmd: AgentCommand = cmds[0]
    assert sysctl_cmd.spec["sysctl_key"] == "net.netfilter.nf_conntrack_tcp_timeout_established"
    assert sysctl_cmd.spec["sysctl_value"] == 240
    assert sysctl_cmd.spec["fw_host"] == "root@192.168.4.1"


# ---------------------------------------------------------------------------
# Test 3 — summarize: pass when flow survives and expect_flow_dies=False
# ---------------------------------------------------------------------------


def test_summarize_pass_flow_survives_as_expected() -> None:
    """ok=True when expect_flow_dies=False, flow ran full 300 s, sysctl applied."""
    runner, cfg = _make_runner()

    result = runner.summarize([
        {"tool": "fw_sysctl", "ok": True, "duration_s": 0.3},
        {"tool": "iperf3", "role": "server", "ok": True, "duration_s": 320.0},
        {"tool": "iperf3", "ok": True, "duration_s": 300.0},
    ])

    assert result.ok is True
    assert result.scenario_id == "lf-test-1"
    assert result.kind == "long_flow_survival"
    assert result.raw["observed_flow_survived"] is True
    assert result.raw["expected_flow_dies"] is False
    assert result.raw["sysctl_applied"] is True


# ---------------------------------------------------------------------------
# Test 4 — summarize: fail when flow dies early but expected to survive
# ---------------------------------------------------------------------------


def test_summarize_fail_flow_dies_but_expected_to_survive() -> None:
    """ok=False when expect_flow_dies=False but flow lasted only 120 s (< 95% of 300)."""
    runner, cfg = _make_runner()

    result = runner.summarize([
        {"tool": "fw_sysctl", "ok": True, "duration_s": 0.3},
        {"tool": "iperf3", "role": "server", "ok": True, "duration_s": 140.0},
        {"tool": "iperf3", "ok": True, "duration_s": 120.0},
    ])

    assert result.ok is False
    assert result.raw["observed_flow_survived"] is False
    assert result.raw["observed_duration_s"] == 120.0


# ---------------------------------------------------------------------------
# Test 5 — summarize: pass when flow dies and expect_flow_dies=True
# ---------------------------------------------------------------------------


def test_summarize_pass_flow_dies_as_expected() -> None:
    """ok=True when expect_flow_dies=True and flow lasted only 120 s (< 95% of 300)."""
    cfg_yaml = _BASE_YAML.replace("expect_flow_dies: false", "expect_flow_dies: true")
    cfg = _load(cfg_yaml)
    sc_cfg = cfg.scenarios[0]
    runner = LongFlowSurvivalRunner(sc_cfg)  # type: ignore[arg-type]

    result = runner.summarize([
        {"tool": "fw_sysctl", "ok": True, "duration_s": 0.3},
        {"tool": "iperf3", "role": "server", "ok": True, "duration_s": 140.0},
        {"tool": "iperf3", "ok": True, "duration_s": 120.0},
    ])

    assert result.ok is True
    assert result.raw["expected_flow_dies"] is True
    assert result.raw["observed_flow_survived"] is False


# ---------------------------------------------------------------------------
# Test 6 — sysctl_key validator rejects non-conntrack keys
# ---------------------------------------------------------------------------


def test_sysctl_key_must_be_conntrack() -> None:
    """sysctl_key that does not start with 'net.netfilter.nf_conntrack_' raises ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        LongFlowSurvivalScenario.model_validate({
            "id": "bad-key",
            "kind": "long_flow_survival",
            "source": "src",
            "sink": "sink",
            "fw_host": "root@fw",
            "sysctl_key": "net.ipv4.ip_forward",
        })

    assert "nf_conntrack" in str(exc_info.value)
