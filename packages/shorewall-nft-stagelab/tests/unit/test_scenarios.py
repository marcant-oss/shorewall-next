"""Unit tests for shorewall_nft_stagelab.scenarios."""

from __future__ import annotations

from shorewall_nft_stagelab.config import (
    ConnStormScenario,
    Dut,
    Endpoint,
    Host,
    MetricsSpec,
    ReportSpec,
    RuleScanScenario,
    StagelabConfig,
    ThroughputScenario,
)
from shorewall_nft_stagelab.scenarios import ThroughputRunner, build_runner

_VLAN_COUNTER = {"n": 10}


def _make_native_ep(name: str, host: str, ipv4: str, vlan: int = 10) -> Endpoint:
    return Endpoint(
        name=name,
        host=host,
        mode="native",
        nic="eth0",
        vlan=vlan,
        ipv4=ipv4,
    )


def _base_cfg(scenarios: list) -> StagelabConfig:
    return StagelabConfig(
        hosts=[Host(name="host1", address="10.0.0.1")],
        dut=Dut(kind="external"),
        endpoints=[
            _make_native_ep("src", "host1", "192.168.1.10/24", vlan=10),
            _make_native_ep("sink", "host1", "192.168.1.20/24", vlan=20),
        ],
        scenarios=scenarios,
        metrics=MetricsSpec(),
        report=ReportSpec(output_dir="/tmp/stagelab-test"),
    )


# ---------------------------------------------------------------------------
# Test 1: throughput plan emits server then client
# ---------------------------------------------------------------------------


def test_throughput_plan_emits_server_then_client():
    sc = ThroughputScenario(
        id="tp1",
        kind="throughput",
        source="src",
        sink="sink",
        proto="tcp",
        duration_s=10,
        parallel=4,
        expect_min_gbps=1.0,
    )
    cfg = _base_cfg([sc])
    runner = build_runner(sc)
    cmds = runner.plan(cfg)

    assert len(cmds) == 2
    server_cmd, client_cmd = cmds

    assert server_cmd.kind == "run_iperf3_server"
    assert server_cmd.endpoint_name == "sink"

    assert client_cmd.kind == "run_iperf3_client"
    assert client_cmd.endpoint_name == "src"

    # server_ip in client spec must match the sink's IPv4 (prefix stripped)
    assert client_cmd.spec["server_ip"] == "192.168.1.20"


# ---------------------------------------------------------------------------
# Test 2: conn_storm plan emits exactly one tcpkali command on source
# ---------------------------------------------------------------------------


def test_conn_storm_plan_one_command():
    sc = ConnStormScenario(
        id="cs1",
        kind="conn_storm",
        source="src",
        sink="sink",
        target_conns=1000,
        rate_per_s=200,
        hold_s=5,
    )
    cfg = _base_cfg([sc])
    runner = build_runner(sc)
    cmds = runner.plan(cfg)

    assert len(cmds) == 1
    cmd = cmds[0]
    assert cmd.kind == "run_tcpkali"
    assert cmd.endpoint_name == "src"


# ---------------------------------------------------------------------------
# Test 3: rule_scan plan count matches random_count
# ---------------------------------------------------------------------------


def test_rule_scan_plan_count_matches_random_count():
    sc = RuleScanScenario(
        id="rs1",
        kind="rule_scan",
        source="src",
        target_subnet="10.10.0.0/24",
        random_count=5,
    )
    cfg = _base_cfg([sc])
    runner = build_runner(sc)
    cmds = runner.plan(cfg)

    probe_cmds = [c for c in cmds if c.kind == "send_probe"]
    assert len(probe_cmds) == 5

    probe_ids = [c.spec["probe_id"] for c in probe_cmds]
    assert len(set(probe_ids)) == 5, "Each probe must have a unique probe_id"


# ---------------------------------------------------------------------------
# Test 4: rule_scan is deterministic with same seed
# ---------------------------------------------------------------------------


def test_rule_scan_is_deterministic_with_seed():
    sc = RuleScanScenario(
        id="rs2",
        kind="rule_scan",
        source="src",
        target_subnet="10.10.0.0/24",
        random_count=8,
    )
    cfg = _base_cfg([sc])

    runner1 = build_runner(sc)
    cmds1 = runner1.plan(cfg)

    runner2 = build_runner(sc)
    cmds2 = runner2.plan(cfg)

    assert len(cmds1) == len(cmds2)
    for c1, c2 in zip(cmds1, cmds2):
        assert c1 == c2, f"Commands differ: {c1!r} vs {c2!r}"


# ---------------------------------------------------------------------------
# Test 5: summarize throughput ok vs fail
# ---------------------------------------------------------------------------


def test_summarize_throughput_ok_vs_fail():
    sc = ThroughputScenario(
        id="tp2",
        kind="throughput",
        source="src",
        sink="sink",
        proto="tcp",
        duration_s=10,
        parallel=1,
        expect_min_gbps=5.0,
    )
    runner = ThroughputRunner(sc)

    # OK case: throughput above threshold
    ok_result = runner.summarize(
        [{"ok": True, "throughput_gbps": 7.5, "duration_s": 10.1}]
    )
    assert ok_result.ok is True
    assert ok_result.raw["throughput_gbps"] == 7.5

    # Fail case: throughput below threshold
    fail_result = runner.summarize(
        [{"ok": True, "throughput_gbps": 2.0, "duration_s": 10.0}]
    )
    assert fail_result.ok is False
    assert fail_result.raw["throughput_gbps"] == 2.0
