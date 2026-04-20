"""Unit tests for HaFailoverDrillScenario (config) and HaFailoverDrillRunner (scenarios)."""

from __future__ import annotations

import textwrap

import pytest
import yaml
from pydantic import ValidationError

from shorewall_nft_stagelab.config import HaFailoverDrillScenario, StagelabConfig
from shorewall_nft_stagelab.scenarios import (
    AgentCommand,
    HaFailoverDrillRunner,
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
      - id: ha-drill-1
        kind: ha_failover_drill
        source: src-ep
        sink: sink-ep
        primary_fw_host: root@192.0.2.1
        secondary_fw_host: root@192.0.2.2
        duration_s: 90
        stop_at_s: 20
        restart_at_s: 60
        service_name: keepalived

    report:
      output_dir: /tmp/out
""")


def _load(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


def _make_runner(
    yaml_text: str = _BASE_YAML,
) -> tuple[HaFailoverDrillRunner, StagelabConfig]:
    cfg = _load(yaml_text)
    sc_cfg = cfg.scenarios[0]
    runner = HaFailoverDrillRunner(sc_cfg)  # type: ignore[arg-type]
    return runner, cfg


# ---------------------------------------------------------------------------
# Test 1 — plan() returns 5 commands in order
# ---------------------------------------------------------------------------


def test_plan_emits_five_commands() -> None:
    """plan() must return exactly 5 AgentCommands in order:
    server, client, stop_fw_service, start_fw_service, query_conntrack_count."""
    runner, cfg = _make_runner()
    cmds = runner.plan(cfg)

    assert len(cmds) == 5
    assert cmds[0].kind == "run_iperf3_server"
    assert cmds[0].endpoint_name == "sink-ep"
    assert cmds[1].kind == "run_iperf3_client"
    assert cmds[1].endpoint_name == "src-ep"
    assert cmds[2].kind == "stop_fw_service"
    assert cmds[3].kind == "start_fw_service"
    assert cmds[4].kind == "query_conntrack_count"


# ---------------------------------------------------------------------------
# Test 2 — stop command carries correct delay and service name
# ---------------------------------------------------------------------------


def test_plan_stop_carries_delay_and_service() -> None:
    """Third command (stop_fw_service) must have delay_before_s=stop_at_s
    and service_name matching the scenario config."""
    runner, cfg = _make_runner()
    cmds = runner.plan(cfg)

    stop_cmd: AgentCommand = cmds[2]
    assert stop_cmd.spec["delay_before_s"] == 20   # stop_at_s from _BASE_YAML
    assert stop_cmd.spec["service_name"] == "keepalived"
    assert stop_cmd.spec["fw_host"] == "root@192.0.2.1"


# ---------------------------------------------------------------------------
# Test 3 — start command carries correct delay
# ---------------------------------------------------------------------------


def test_plan_restart_carries_delay() -> None:
    """Fourth command (start_fw_service) must have delay_before_s=restart_at_s."""
    runner, cfg = _make_runner()
    cmds = runner.plan(cfg)

    start_cmd: AgentCommand = cmds[3]
    assert start_cmd.spec["delay_before_s"] == 60  # restart_at_s from _BASE_YAML
    assert start_cmd.spec["service_name"] == "keepalived"
    assert start_cmd.spec["fw_host"] == "root@192.0.2.1"


# ---------------------------------------------------------------------------
# Test 4 — service_name validator rejects unknown services
# ---------------------------------------------------------------------------


def test_service_name_validator_rejects_unknown() -> None:
    """service_name='sshd' must raise ValidationError (not in allowed set)."""
    with pytest.raises(ValidationError):
        HaFailoverDrillScenario.model_validate({
            "id": "x",
            "kind": "ha_failover_drill",
            "source": "src",
            "sink": "sink",
            "primary_fw_host": "root@fw1",
            "secondary_fw_host": "root@fw2",
            "service_name": "sshd",
        })


# ---------------------------------------------------------------------------
# Test 5 — summarize: pass when stream survived and retransmits are low
# ---------------------------------------------------------------------------


def test_summarize_pass_stream_survived_low_retrans() -> None:
    """ok=True when stream_ok + stop_ok + start_ok + retrans=100 (plausible failover)."""
    runner, cfg = _make_runner()

    result = runner.summarize([
        {"tool": "iperf3", "ok": True, "retransmits": 100, "duration_s": 90.0},
        {"tool": "fw_service", "action": "stop", "ok": True, "duration_s": 0.3},
        {"tool": "fw_service", "action": "start", "ok": True, "duration_s": 0.2},
        {"tool": "conntrack_count", "ok": True, "count": 1234},
    ])

    assert result.ok is True
    assert result.scenario_id == "ha-drill-1"
    assert result.kind == "ha_failover_drill"
    assert result.raw["retransmits_observed"] == 100
    assert result.raw["stream_survived"] is True
    assert result.raw["service_stopped"] is True
    assert result.raw["service_started"] is True
    assert result.raw["secondary_conntrack_count"] == 1234


# ---------------------------------------------------------------------------
# Test 6 — summarize: fail when retransmit count is in storm territory
# ---------------------------------------------------------------------------


def test_summarize_fail_retrans_storm() -> None:
    """ok=False when retransmits=5000 (exceeds plausible VRRP failover burst)."""
    runner, cfg = _make_runner()

    result = runner.summarize([
        {"tool": "iperf3", "ok": True, "retransmits": 5000, "duration_s": 90.0},
        {"tool": "fw_service", "action": "stop", "ok": True, "duration_s": 0.3},
        {"tool": "fw_service", "action": "start", "ok": True, "duration_s": 0.2},
        {"tool": "conntrack_count", "ok": True, "count": 500},
    ])

    assert result.ok is False
    assert result.raw["retransmits_observed"] == 5000
