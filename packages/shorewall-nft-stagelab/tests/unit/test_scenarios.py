"""Unit tests for shorewall_nft_stagelab.scenarios."""

from __future__ import annotations

import pytest

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
# Test 2: conn_storm plan emits 3 commands: start_http_listener, run_tcpkali,
#          stop_http_listener
# ---------------------------------------------------------------------------


def test_conn_storm_plan_three_commands():
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

    assert len(cmds) == 3, f"expected 3 commands, got {len(cmds)}: {[c.kind for c in cmds]}"

    start_cmd, storm_cmd, stop_cmd = cmds

    # 1) HTTP listener start on sink
    assert start_cmd.kind == "start_http_listener"
    assert start_cmd.endpoint_name == "sink"
    assert start_cmd.spec["bind_ip"] == "192.168.1.20"
    assert start_cmd.spec["port"] == 80
    assert start_cmd.spec["_http_sidecar"] is True

    # 2) Connection storm on source — target is sink_ip:target_port (default 80)
    assert storm_cmd.kind == "run_tcpkali"
    assert storm_cmd.endpoint_name == "src"
    assert storm_cmd.spec["target"] == "192.168.1.20:80"
    assert storm_cmd.spec["connections"] == 1000
    assert storm_cmd.spec["connect_rate"] == 200
    assert storm_cmd.spec["duration_s"] == 5

    # 3) HTTP listener stop on sink
    assert stop_cmd.kind == "stop_http_listener"
    assert stop_cmd.endpoint_name == "sink"
    assert stop_cmd.spec["port"] == 80
    assert stop_cmd.spec["_http_sidecar"] is True


def test_conn_storm_plan_custom_target_port():
    """target_port=443 propagates into both the listener and the storm target."""
    sc = ConnStormScenario(
        id="cs2",
        kind="conn_storm",
        source="src",
        sink="sink",
        target_conns=500,
        rate_per_s=100,
        hold_s=10,
        target_port=443,
    )
    cfg = _base_cfg([sc])
    runner = build_runner(sc)
    cmds = runner.plan(cfg)

    assert len(cmds) == 3
    start_cmd, storm_cmd, stop_cmd = cmds
    assert start_cmd.spec["port"] == 443
    assert storm_cmd.spec["target"] == "192.168.1.20:443"
    assert stop_cmd.spec["port"] == 443


def test_conn_storm_summarize_ignores_http_sidecar():
    """summarize() must compute established from pyconn result, not sidecar dicts."""
    sc = ConnStormScenario(
        id="cs3",
        kind="conn_storm",
        source="src",
        sink="sink",
        target_conns=100,
        rate_per_s=50,
        hold_s=5,
    )
    runner = build_runner(sc)
    # Simulate 3 result dicts: start sidecar, pyconn, stop sidecar
    results = [
        {"tool": "http_listener", "ok": True, "pid": 1234, "port": 80, "_http_sidecar": True},
        {
            "tool": "pyconn", "ok": True,
            "connections_established": 100, "connections_failed": 0,
            "duration_s": 5.0, "traffic_bps": 0,
        },
        {"tool": "http_listener", "ok": True, "pid": 1234, "port": 80, "_http_sidecar": True},
    ]
    result = runner.summarize(results)
    assert result.ok is True
    assert result.raw["established"] == 100
    assert result.raw["failed"] == 0


def test_conn_storm_summarize_fails_when_established_below_target():
    """summarize() ok=False when established < target_conns."""
    sc = ConnStormScenario(
        id="cs4",
        kind="conn_storm",
        source="src",
        sink="sink",
        target_conns=1000,
        rate_per_s=100,
        hold_s=5,
    )
    runner = build_runner(sc)
    results = [
        {"tool": "http_listener", "ok": True, "pid": 9, "port": 80, "_http_sidecar": True},
        {
            "tool": "pyconn", "ok": True,
            "connections_established": 200, "connections_failed": 800,
            "duration_s": 5.0, "traffic_bps": 0,
        },
        {"tool": "http_listener", "ok": True, "pid": 9, "port": 80, "_http_sidecar": True},
    ]
    result = runner.summarize(results)
    assert result.ok is False
    assert result.raw["established"] == 200


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
# Test 5: summarize propagates test_id + standard_refs from scenario config
# ---------------------------------------------------------------------------


def test_rule_scan_summarize_propagates_test_id():
    sc = RuleScanScenario(
        id="test-scan-1",
        kind="rule_scan",
        source="src",
        target_subnet="10.10.0.0/24",
        random_count=2,
        test_id="test-scan-1",
        standard_refs=["std-x"],
    )
    runner = build_runner(sc)
    # Provide minimal results: two passing probes (no mismatches)
    results = [
        {"kind": "probe", "ok": True, "duration_s": 0.1},
        {"kind": "probe", "ok": True, "duration_s": 0.1},
    ]
    result = runner.summarize(results)
    assert result.test_id == "test-scan-1"
    assert result.standard_refs == ["std-x"]


def test_throughput_summarize_propagates_test_id():
    sc = ThroughputScenario(
        id="tput-tagged",
        kind="throughput",
        source="src",
        sink="sink",
        proto="tcp",
        duration_s=10,
        parallel=1,
        expect_min_gbps=1.0,
        test_id="owasp-fw-3-default-deny",
        standard_refs=["owasp-fw-3"],
    )
    runner = build_runner(sc)
    results = [{"role": "client", "throughput_gbps": 9.5, "duration_s": 10.0, "ok": True}]
    result = runner.summarize(results)
    assert result.test_id == "owasp-fw-3-default-deny"
    assert result.standard_refs == ["owasp-fw-3"]


def test_summarize_without_test_id_defaults_none():
    sc = RuleScanScenario(
        id="no-tag",
        kind="rule_scan",
        source="src",
        target_subnet="10.10.0.0/24",
        random_count=1,
        # no test_id, no standard_refs
    )
    runner = build_runner(sc)
    result = runner.summarize([{"kind": "probe", "ok": True, "duration_s": 0.1}])
    assert result.test_id is None
    assert result.standard_refs == []


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


# ---------------------------------------------------------------------------
# Test 6: build_runner unknown kind raises ValueError
# ---------------------------------------------------------------------------


def test_build_runner_unknown_kind_raises():
    """build_runner with an unknown kind string must raise ValueError."""

    class _FakeScenario:
        kind = "does_not_exist"

    with pytest.raises(ValueError, match="does_not_exist"):
        build_runner(_FakeScenario())  # type: ignore[arg-type]
