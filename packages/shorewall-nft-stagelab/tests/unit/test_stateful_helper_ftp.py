"""Unit tests for StatefulHelperFtpScenario (config) and StatefulHelperFtpRunner (scenarios)."""

from __future__ import annotations

import textwrap

import yaml

from shorewall_nft_stagelab.config import StagelabConfig
from shorewall_nft_stagelab.scenarios import (
    AgentCommand,
    StatefulHelperFtpRunner,
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
      - id: ftp-test-1
        kind: stateful_helper_ftp
        source: src-ep
        sink: sink-ep

    report:
      output_dir: /tmp/out
""")


def _load(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


# ---------------------------------------------------------------------------
# Test 1 — plan() emits exactly one AgentCommand with kind="run_ftp_helper_probe"
# ---------------------------------------------------------------------------


def test_plan_emits_one_command() -> None:
    """plan() must return exactly 1 AgentCommand of kind run_ftp_helper_probe."""
    cfg = _load(_BASE_YAML)
    sc_cfg = cfg.scenarios[0]
    runner = StatefulHelperFtpRunner(sc_cfg)  # type: ignore[arg-type]
    cmds = runner.plan(cfg)

    assert len(cmds) == 1
    cmd: AgentCommand = cmds[0]
    assert isinstance(cmd, AgentCommand)
    assert cmd.kind == "run_ftp_helper_probe"
    assert cmd.endpoint_name == "src-ep"
    assert cmd.spec["sink_ip"] == "10.0.20.1"
    assert cmd.spec["scenario_id"] == "ftp-test-1"


# ---------------------------------------------------------------------------
# Test 2 — mode and credentials are forwarded to the spec
# ---------------------------------------------------------------------------


def test_plan_passes_mode_and_credentials() -> None:
    """Active mode and custom credentials are forwarded into the emitted spec."""
    yaml_text = textwrap.dedent("""\
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
          - id: ftp-cred-test
            kind: stateful_helper_ftp
            source: src-ep
            sink: sink-ep
            mode: active
            user: alice
            password: bob123

        report:
          output_dir: /tmp/out
    """)
    cfg = _load(yaml_text)
    sc_cfg = cfg.scenarios[0]
    runner = StatefulHelperFtpRunner(sc_cfg)  # type: ignore[arg-type]
    cmds = runner.plan(cfg)

    assert len(cmds) == 1
    spec = cmds[0].spec
    assert spec["mode"] == "active"
    assert spec["user"] == "alice"
    assert spec["password"] == "bob123"


# ---------------------------------------------------------------------------
# Test 3 — summarize: ok=True when data transfer succeeds and is expected
# ---------------------------------------------------------------------------


def test_summarize_pass_when_data_ok_and_expected() -> None:
    """ScenarioResult ok=True when control_ok and data_transfer_ok are both True."""
    cfg = _load(_BASE_YAML)
    sc_cfg = cfg.scenarios[0]
    runner = StatefulHelperFtpRunner(sc_cfg)  # type: ignore[arg-type]

    result = runner.summarize([
        {"control_ok": True, "data_transfer_ok": True, "duration_s": 1.5},
    ])

    assert result.ok is True
    assert result.scenario_id == "ftp-test-1"
    assert result.kind == "stateful_helper_ftp"
    assert result.raw["control_ok"] is True
    assert result.raw["data_transfer_ok"] is True


# ---------------------------------------------------------------------------
# Test 4 — summarize: ok=False when data transfer fails (helper missing)
# ---------------------------------------------------------------------------


def test_summarize_fail_when_helper_missing_simulation() -> None:
    """ScenarioResult ok=False when control_ok=True but data_transfer_ok=False."""
    cfg = _load(_BASE_YAML)
    sc_cfg = cfg.scenarios[0]
    runner = StatefulHelperFtpRunner(sc_cfg)  # type: ignore[arg-type]

    result = runner.summarize([
        {"control_ok": True, "data_transfer_ok": False, "duration_s": 0.8},
    ])

    assert result.ok is False
    assert result.raw["control_ok"] is True
    assert result.raw["data_transfer_ok"] is False
    assert result.raw["expected_data_connection"] is True
