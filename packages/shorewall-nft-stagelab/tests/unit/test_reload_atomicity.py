"""Unit tests for ReloadAtomicityScenario (config) and ReloadAtomicityRunner (scenarios)."""

from __future__ import annotations

import textwrap

import pytest
import yaml
from pydantic import ValidationError

from shorewall_nft_stagelab.config import ReloadAtomicityScenario, StagelabConfig
from shorewall_nft_stagelab.scenarios import (
    AgentCommand,
    ReloadAtomicityRunner,
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
      - id: reload-test-1
        kind: reload_atomicity
        source: src-ep
        sink: sink-ep
        fw_host: root@192.168.4.1
        duration_s: 60
        reload_at_s: 20

    report:
      output_dir: /tmp/out
""")


def _load(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


def _make_runner(yaml_text: str = _BASE_YAML) -> tuple[ReloadAtomicityRunner, StagelabConfig]:
    cfg = _load(yaml_text)
    sc_cfg = cfg.scenarios[0]
    runner = ReloadAtomicityRunner(sc_cfg)  # type: ignore[arg-type]
    return runner, cfg


# ---------------------------------------------------------------------------
# Test 1 — plan() returns 3 commands in order: server, client, trigger
# ---------------------------------------------------------------------------


def test_plan_emits_server_client_trigger() -> None:
    """plan() must return exactly 3 AgentCommands in order: server, client, trigger."""
    runner, cfg = _make_runner()
    cmds = runner.plan(cfg)

    assert len(cmds) == 3
    assert cmds[0].kind == "run_iperf3_server"
    assert cmds[0].endpoint_name == "sink-ep"
    assert cmds[1].kind == "run_iperf3_client"
    assert cmds[1].endpoint_name == "src-ep"
    assert cmds[2].kind == "trigger_fw_reload"
    assert cmds[2].endpoint_name == "src-ep"


# ---------------------------------------------------------------------------
# Test 2 — trigger command carries fw_host and reload_command
# ---------------------------------------------------------------------------


def test_plan_trigger_carries_fw_host_and_command() -> None:
    """Third command spec must contain the fw_host and reload_command from the scenario."""
    runner, cfg = _make_runner()
    cmds = runner.plan(cfg)

    trigger: AgentCommand = cmds[2]
    assert trigger.spec["fw_host"] == "root@192.168.4.1"
    assert trigger.spec["reload_command"] == "shorewall-nft restart /etc/shorewall46"


# ---------------------------------------------------------------------------
# Test 3 — trigger spec delay_before_s equals reload_at_s
# ---------------------------------------------------------------------------


def test_plan_trigger_delay_matches_reload_at_s() -> None:
    """delay_before_s in the trigger command spec must equal scenario.reload_at_s."""
    runner, cfg = _make_runner()
    cmds = runner.plan(cfg)

    trigger: AgentCommand = cmds[2]
    assert trigger.spec["delay_before_s"] == 20  # matches reload_at_s in _BASE_YAML


# ---------------------------------------------------------------------------
# Test 4 — summarize: pass when retransmits under threshold
# ---------------------------------------------------------------------------


def test_summarize_pass_under_retrans_threshold() -> None:
    """ok=True when retransmits=10 (< 100) and both stream + reload succeeded."""
    runner, cfg = _make_runner()

    result = runner.summarize([
        {"tool": "iperf3", "ok": True, "retransmits": 10, "duration_s": 60.0},
        {"tool": "fw_reload", "ok": True, "duration_s": 2.1},
    ])

    assert result.ok is True
    assert result.scenario_id == "reload-test-1"
    assert result.kind == "reload_atomicity"
    assert result.raw["retransmits_observed"] == 10
    assert result.raw["stream_survived"] is True
    assert result.raw["reload_triggered_ok"] is True


# ---------------------------------------------------------------------------
# Test 5 — summarize: fail when retransmits exceed threshold
# ---------------------------------------------------------------------------


def test_summarize_fail_when_retrans_over_threshold() -> None:
    """ok=False and retransmits_observed=500 when 500 retransmits were seen."""
    runner, cfg = _make_runner()

    result = runner.summarize([
        {"tool": "iperf3", "ok": True, "retransmits": 500, "duration_s": 60.0},
        {"tool": "fw_reload", "ok": True, "duration_s": 1.8},
    ])

    assert result.ok is False
    assert result.raw["retransmits_observed"] == 500
    assert result.raw["max_retrans_allowed"] == 100


# ---------------------------------------------------------------------------
# Test 6 — reload_at_s bounds validation
# ---------------------------------------------------------------------------


def test_reload_at_s_bounds() -> None:
    """reload_at_s=0 and reload_at_s=58 (with duration_s=60) must raise ValidationError;
    reload_at_s=20 with duration_s=60 must be accepted."""
    base = {
        "id": "r1",
        "kind": "reload_atomicity",
        "source": "x",
        "sink": "y",
        "fw_host": "root@fw",
        "duration_s": 60,
    }

    # reload_at_s=0: below minimum (< 2)
    with pytest.raises(ValidationError):
        ReloadAtomicityScenario.model_validate({**base, "reload_at_s": 0})

    # reload_at_s=58: equal to duration_s - 2 = 58, which is NOT < dur-2 (i.e., 58 >= 58)
    with pytest.raises(ValidationError):
        ReloadAtomicityScenario.model_validate({**base, "reload_at_s": 58})

    # reload_at_s=20: valid (2 <= 20 < 58)
    sc = ReloadAtomicityScenario.model_validate({**base, "reload_at_s": 20})
    assert sc.reload_at_s == 20
