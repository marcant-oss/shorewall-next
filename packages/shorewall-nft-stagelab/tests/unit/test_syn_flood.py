"""Unit tests for SynFloodDosScenario (config) and SynFloodDosRunner (scenarios)."""

from __future__ import annotations

import textwrap

import pytest
import yaml

from shorewall_nft_stagelab.config import StagelabConfig
from shorewall_nft_stagelab.scenarios import (
    AgentCommand,
    SynFloodDosRunner,
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
      - id: syn-flood-1
        kind: dos_syn_flood
        source: dpdk-src
        sink: dpdk-sink
        duration_s: 10
        rate_pps: 500000
        src_ip_range: 192.0.2.0/24
        dst_port_range: "80,443"

    report:
      output_dir: /tmp/out
""")


def _load(yaml_text: str) -> StagelabConfig:
    return StagelabConfig.model_validate(yaml.safe_load(yaml_text))


# ---------------------------------------------------------------------------
# Test 1 — plan() emits one run_trex_stateless command
# ---------------------------------------------------------------------------


def test_syn_flood_plan_emits_one_command():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    assert sc.kind == "dos_syn_flood"
    runner = build_runner(sc)
    assert isinstance(runner, SynFloodDosRunner)

    commands = runner.plan(cfg)
    assert len(commands) == 1
    cmd = commands[0]
    assert isinstance(cmd, AgentCommand)
    assert cmd.kind == "run_trex_stateless"
    assert cmd.endpoint_name == "dpdk-src"

    spec = cmd.spec
    # source endpoint dpdk-src is trex_port_id=0 (first DPDK ep on tester)
    assert spec["ports"] == (0,)
    assert spec["duration_s"] == 10
    assert spec["multiplier"] == "500000pps"
    assert "profile_text" in spec
    assert isinstance(spec["profile_text"], str)
    assert len(spec["profile_text"]) > 0


# ---------------------------------------------------------------------------
# Test 2 — allowlist rejects sink outside allowed range
# ---------------------------------------------------------------------------


def test_syn_flood_allowlist_rejects_outside_sink():
    yaml_text = textwrap.dedent("""\
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
          - name: dpdk-sink
            host: tester
            mode: dpdk
            pci_addr: "0000:01:00.1"
            dpdk_cores: [4, 5]
            hugepages_gib: 4
            trex_role: server
            ipv4: 10.0.1.5/32

        dos_target_allowlist:
          - 10.0.0.0/24

        scenarios:
          - id: syn-flood-outside
            kind: dos_syn_flood
            source: dpdk-src
            sink: dpdk-sink
            rate_pps: 100000
            src_ip_range: 192.0.2.0/24

        report:
          output_dir: /tmp/out
    """)
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        _load(yaml_text)
    assert "dos_target_allowlist" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 3 — rate_pps above cap raises ValidationError
# ---------------------------------------------------------------------------


def test_syn_flood_rate_cap_rejected():
    yaml_text = textwrap.dedent("""\
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
          - name: dpdk-sink
            host: tester
            mode: dpdk
            pci_addr: "0000:01:00.1"
            dpdk_cores: [4, 5]
            hugepages_gib: 4
            trex_role: server

        dos_target_allowlist:
          - 0.0.0.0/0

        scenarios:
          - id: syn-flood-overcap
            kind: dos_syn_flood
            source: dpdk-src
            sink: dpdk-sink
            rate_pps: 50000000
            src_ip_range: 192.0.2.0/24

        report:
          output_dir: /tmp/out
    """)
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        _load(yaml_text)
    assert "rate_pps" in str(exc_info.value) and "exceeds" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 4 — summarize: passed_ratio <= threshold → ok=True
# ---------------------------------------------------------------------------


def test_syn_flood_summarize_pass_under_threshold():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    result = runner.summarize([{
        "ok": True,
        "passed_ratio": 0.01,
        "pps": 500_000.0,
        "errors": 0,
        "duration_s": 10.0,
    }])
    assert result.ok is True
    assert result.scenario_id == "syn-flood-1"
    assert result.kind == "dos_syn_flood"
    assert result.raw["passed_ratio"] == pytest.approx(0.01)


# ---------------------------------------------------------------------------
# Test 5 — summarize: passed_ratio > threshold → ok=False
# ---------------------------------------------------------------------------


def test_syn_flood_summarize_fail_over_threshold():
    cfg = _load(_BASE_YAML)
    sc = cfg.scenarios[0]
    runner = build_runner(sc)

    result = runner.summarize([{
        "ok": True,
        "passed_ratio": 0.10,
        "pps": 500_000.0,
        "errors": 0,
        "duration_s": 10.0,
    }])
    assert result.ok is False
    assert result.raw["passed_ratio"] == pytest.approx(0.10)
