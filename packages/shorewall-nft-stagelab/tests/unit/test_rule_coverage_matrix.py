"""Unit tests for RuleCoverageMatrixScenario + RuleCoverageMatrixRunner."""

from __future__ import annotations

from shorewall_nft_stagelab.config import (
    Dut,
    Endpoint,
    Host,
    MetricsSpec,
    ReportSpec,
    RuleCoverageMatrixScenario,
    StagelabConfig,
)
from shorewall_nft_stagelab.scenarios import RuleCoverageMatrixRunner

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_ZONE_SUBNETS = {"dmz": "10.0.20.0/24", "lan": "10.0.10.0/24"}


def _make_scenario(**kwargs) -> RuleCoverageMatrixScenario:
    defaults = dict(
        id="rcm1",
        kind="rule_coverage_matrix",
        source="src",
        zone_subnets=_ZONE_SUBNETS,
        protos=["tcp", "udp"],
        tcp_ports=[80, 443],
        udp_ports=[53],
        probe_count_per_tuple=1,
    )
    defaults.update(kwargs)
    return RuleCoverageMatrixScenario(**defaults)


def _make_native_ep(name: str, host: str, ipv4: str, vlan: int) -> Endpoint:
    return Endpoint(
        name=name,
        host=host,
        mode="native",
        nic="eth0",
        vlan=vlan,
        ipv4=ipv4,
    )


def _base_cfg(scenario: RuleCoverageMatrixScenario) -> StagelabConfig:
    return StagelabConfig(
        hosts=[Host(name="host1", address="10.0.0.1")],
        dut=Dut(kind="external"),
        endpoints=[
            _make_native_ep("src", "host1", "10.0.10.1/24", vlan=10),
        ],
        scenarios=[scenario],
        metrics=MetricsSpec(),
        report=ReportSpec(output_dir="/tmp/stagelab-rcm-test"),
    )


# ---------------------------------------------------------------------------
# Test 1: plan emits one probe per (zone-pair, proto, port) + 1 oracle cmd
# ---------------------------------------------------------------------------


def test_plan_emits_tuple_per_zone_pair_proto_port():
    """2 zones × 1 ordered pair each direction × (2 tcp_ports + 1 udp_port) = 6 probes."""
    sc = _make_scenario()
    cfg = _base_cfg(sc)
    runner = RuleCoverageMatrixRunner(sc)
    cmds = runner.plan(cfg)

    # Expect: 2 zone-pairs (lan→dmz, dmz→lan) × 2 protos × ports-per-proto.
    # tcp: 2 ports, udp: 1 port → per direction: 2+1=3 probes.
    # 2 directions × 3 = 6 send_probe + 1 collect_oracle_verdict = 7 total.
    probe_cmds = [c for c in cmds if c.kind == "send_probe"]
    oracle_cmds = [c for c in cmds if c.kind == "collect_oracle_verdict"]

    assert len(probe_cmds) == 6
    assert len(oracle_cmds) == 1
    assert len(cmds) == 7


# ---------------------------------------------------------------------------
# Test 2: same-zone pairs are skipped
# ---------------------------------------------------------------------------


def test_plan_skips_same_zone_pairs():
    """No (zone, zone) self-pair should appear in send_probe commands."""
    sc = _make_scenario()
    cfg = _base_cfg(sc)
    runner = RuleCoverageMatrixRunner(sc)
    cmds = runner.plan(cfg)

    probe_cmds = [c for c in cmds if c.kind == "send_probe"]
    for cmd in probe_cmds:
        assert cmd.spec["src_zone"] != cmd.spec["dst_zone"], (
            f"Self-pair found: {cmd.spec['src_zone']} -> {cmd.spec['dst_zone']}"
        )


# ---------------------------------------------------------------------------
# Test 3: deterministic ordering across two plan() calls
# ---------------------------------------------------------------------------


def test_plan_deterministic_ordering():
    """Two plan() calls on the same scenario must produce identical commands."""
    sc = _make_scenario()
    cfg = _base_cfg(sc)
    runner = RuleCoverageMatrixRunner(sc)

    cmds_a = runner.plan(cfg)
    cmds_b = runner.plan(cfg)

    assert len(cmds_a) == len(cmds_b)
    for a, b in zip(cmds_a, cmds_b):
        assert a == b, f"Commands differ:\n  {a}\n  {b}"


# ---------------------------------------------------------------------------
# Test 4: summarize returns ok=True when all probes pass
# ---------------------------------------------------------------------------


def test_summarize_pass_no_mismatches():
    """All probes with ok=True and no oracle_mismatch → ScenarioResult(ok=True)."""
    sc = _make_scenario()
    runner = RuleCoverageMatrixRunner(sc)

    probe_results = [
        {"src_zone": "lan", "dst_zone": "dmz", "proto": "tcp", "dst_port": 80, "ok": True},
        {"src_zone": "lan", "dst_zone": "dmz", "proto": "tcp", "dst_port": 443, "ok": True},
        {"src_zone": "dmz", "dst_zone": "lan", "proto": "udp", "dst_port": 53, "ok": True},
    ]
    result = runner.summarize(probe_results)

    assert result.ok is True
    assert result.scenario_id == "rcm1"
    assert result.kind == "rule_coverage_matrix"
    assert result.raw["total_probes"] == 3
    assert result.raw["passed"] == 3
    assert result.raw["mismatches"] == 0
    # Matrix must be populated with at least one entry.
    assert len(result.raw["matrix"]) >= 1


# ---------------------------------------------------------------------------
# Test 5: summarize returns ok=False when any probe has oracle_mismatch
# ---------------------------------------------------------------------------


def test_summarize_fail_on_mismatch():
    """A probe with oracle_mismatch=True must set ScenarioResult(ok=False)."""
    sc = _make_scenario()
    runner = RuleCoverageMatrixRunner(sc)

    probe_results = [
        {"src_zone": "lan", "dst_zone": "dmz", "proto": "tcp", "dst_port": 80, "ok": True},
        {
            "src_zone": "lan",
            "dst_zone": "dmz",
            "proto": "tcp",
            "dst_port": 443,
            "ok": False,
            "oracle_mismatch": True,
        },
    ]
    result = runner.summarize(probe_results)

    assert result.ok is False
    assert result.raw["mismatches"] >= 1
