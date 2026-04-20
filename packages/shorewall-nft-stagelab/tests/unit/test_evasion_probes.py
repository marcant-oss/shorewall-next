"""Unit tests for EvasionProbesScenario (config) and EvasionProbesRunner (scenarios)."""

from __future__ import annotations

import textwrap

import yaml

from shorewall_nft_stagelab.config import StagelabConfig
from shorewall_nft_stagelab.scenarios import EvasionProbesRunner

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
      - name: probe-ep
        host: tester
        mode: probe
        bridge: br-probe
        ipv4: 10.0.10.1/24

    scenarios:
      - id: evasion-1
        kind: evasion_probes
        source: probe-ep
        target_ip: 10.0.20.1
        probe_types:
          - tcp_null
          - tcp_xmas
          - ip_spoof

    report:
      output_dir: /tmp/out
""")


def _load(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


# ---------------------------------------------------------------------------
# Test 1 — plan() emits one command per probe_type plus one oracle command
# ---------------------------------------------------------------------------


def test_plan_emits_one_command_per_probe_type_plus_oracle() -> None:
    """3 probe_types → plan returns 4 commands (3 send_probe + 1 collect_oracle_verdict)."""
    cfg = _load(_BASE_YAML)
    sc_cfg = cfg.scenarios[0]
    runner = EvasionProbesRunner(sc_cfg)  # type: ignore[arg-type]
    cmds = runner.plan(cfg)

    assert len(cmds) == 4
    probe_cmds = [c for c in cmds if c.kind == "send_probe"]
    oracle_cmds = [c for c in cmds if c.kind == "collect_oracle_verdict"]
    assert len(probe_cmds) == 3
    assert len(oracle_cmds) == 1


# ---------------------------------------------------------------------------
# Test 2 — tcp_null probe maps to tcp_flags=""
# ---------------------------------------------------------------------------


def test_plan_maps_tcp_null_to_no_flags() -> None:
    """The tcp_null command must carry tcp_flags='' (no flags at all)."""
    cfg = _load(_BASE_YAML)
    sc_cfg = cfg.scenarios[0]
    runner = EvasionProbesRunner(sc_cfg)  # type: ignore[arg-type]
    cmds = runner.plan(cfg)

    tcp_null_cmd = next(
        (c for c in cmds if c.kind == "send_probe" and c.spec.get("probe_type") == "tcp_null"),
        None,
    )
    assert tcp_null_cmd is not None, "tcp_null send_probe command not found"
    assert tcp_null_cmd.spec["tcp_flags"] == ""
    assert tcp_null_cmd.spec["proto"] == "tcp"
    assert tcp_null_cmd.spec["expected_verdict"] == "drop"


# ---------------------------------------------------------------------------
# Test 3 — ip_spoof probe uses spoof_src_ip
# ---------------------------------------------------------------------------


def test_plan_ip_spoof_uses_spoof_src_ip() -> None:
    """The ip_spoof command must carry src_ip equal to spoof_src_ip."""
    cfg = _load(_BASE_YAML)
    sc_cfg = cfg.scenarios[0]
    # Default spoof_src_ip is "10.255.255.255"
    runner = EvasionProbesRunner(sc_cfg)  # type: ignore[arg-type]
    cmds = runner.plan(cfg)

    spoof_cmd = next(
        (c for c in cmds if c.kind == "send_probe" and c.spec.get("probe_type") == "ip_spoof"),
        None,
    )
    assert spoof_cmd is not None, "ip_spoof send_probe command not found"
    assert spoof_cmd.spec["src_ip"] == sc_cfg.spoof_src_ip  # type: ignore[union-attr]
    assert spoof_cmd.spec["src_ip"] == "10.255.255.255"


# ---------------------------------------------------------------------------
# Test 4 — summarize: all dropped → ok=True
# ---------------------------------------------------------------------------


def test_summarize_all_dropped_passes() -> None:
    """When all probe results have observed_verdict='drop', ScenarioResult is ok=True."""
    cfg = _load(_BASE_YAML)
    sc_cfg = cfg.scenarios[0]
    runner = EvasionProbesRunner(sc_cfg)  # type: ignore[arg-type]

    probe_results = [
        {"probe_id": 1, "probe_type": "tcp_null", "observed_verdict": "drop"},
        {"probe_id": 2, "probe_type": "tcp_xmas", "observed_verdict": "drop"},
        {"probe_id": 3, "probe_type": "ip_spoof", "observed_verdict": "drop"},
    ]
    result = runner.summarize(probe_results)

    assert result.ok is True
    assert result.scenario_id == "evasion-1"
    assert result.kind == "evasion_probes"
    assert result.raw["leaked_through"] == 0
    assert result.raw["dropped_by_fw"] == 3
    assert result.raw["total_probes"] == 3


# ---------------------------------------------------------------------------
# Test 5 — summarize: any leaked → ok=False, leaked_probe_types reports it
# ---------------------------------------------------------------------------


def test_summarize_any_leaked_fails() -> None:
    """One probe with observed_verdict='accept' → ok=False, leaked_probe_types non-empty."""
    cfg = _load(_BASE_YAML)
    sc_cfg = cfg.scenarios[0]
    runner = EvasionProbesRunner(sc_cfg)  # type: ignore[arg-type]

    probe_results = [
        {"probe_id": 1, "probe_type": "tcp_null", "observed_verdict": "drop"},
        {"probe_id": 2, "probe_type": "tcp_xmas", "observed_verdict": "accept"},
        {"probe_id": 3, "probe_type": "ip_spoof", "observed_verdict": "drop"},
    ]
    result = runner.summarize(probe_results)

    assert result.ok is False
    assert result.raw["leaked_through"] == 1
    assert result.raw["dropped_by_fw"] == 2
    assert "tcp_xmas" in result.raw["leaked_probe_types"]
