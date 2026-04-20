"""Unit tests for TuningSweepRunner and related config/report integration."""

from __future__ import annotations

from shorewall_nft_stagelab.config import (
    Dut,
    Endpoint,
    Host,
    MetricsSpec,
    ReportSpec,
    StagelabConfig,
    TuningSweepScenario,
)
from shorewall_nft_stagelab.scenarios import TuningSweepRunner, build_runner  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_native_ep(name: str, host: str, ipv4: str, vlan: int) -> Endpoint:
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
            _make_native_ep("src", "host1", "10.0.10.1/24", vlan=10),
            _make_native_ep("sink", "host1", "10.0.20.1/24", vlan=20),
        ],
        scenarios=scenarios,
        metrics=MetricsSpec(),
        report=ReportSpec(output_dir="/tmp/stagelab-test"),
    )


def _sweep_scenario(**kwargs) -> TuningSweepScenario:
    defaults = {
        "id": "sweep-1",
        "kind": "tuning_sweep",
        "source": "src",
        "sink": "sink",
    }
    defaults.update(kwargs)
    return TuningSweepScenario(**defaults)


# ---------------------------------------------------------------------------
# Test 1: plan emits a triplet per grid point
# ---------------------------------------------------------------------------


def test_plan_emits_trio_per_point() -> None:
    """2×2 grid (rss_queues=[1,8], rmem_max=[1048576,16777216]) → 4 combos → 12 commands."""
    sc = _sweep_scenario(rss_queues=[1, 8], rmem_max=[1_048_576, 16_777_216])
    cfg = _base_cfg([sc])
    runner = TuningSweepRunner(sc)
    cmds = runner.plan(cfg)

    assert len(cmds) == 12, f"Expected 12, got {len(cmds)}"

    # Verify interleaving pattern: apply, server, client, apply, server, client, ...
    for i in range(0, 12, 3):
        assert cmds[i].kind == "apply_tuning", f"Expected apply_tuning at position {i}"
        assert cmds[i + 1].kind == "run_iperf3_server", f"Expected server at {i + 1}"
        assert cmds[i + 2].kind == "run_iperf3_client", f"Expected client at {i + 2}"

    # apply_tuning goes to source; server goes to sink; client goes to source
    for i in range(0, 12, 3):
        assert cmds[i].endpoint_name == "src"
        assert cmds[i + 1].endpoint_name == "sink"
        assert cmds[i + 2].endpoint_name == "src"


# ---------------------------------------------------------------------------
# Test 2: empty grid → single baseline point
# ---------------------------------------------------------------------------


def test_plan_empty_grid_is_single_baseline_point() -> None:
    """All axes empty → 1 combo (empty params) → 3 commands."""
    sc = _sweep_scenario()  # all axes default to []
    cfg = _base_cfg([sc])
    runner = TuningSweepRunner(sc)
    cmds = runner.plan(cfg)

    assert len(cmds) == 3
    apply_cmd = cmds[0]
    assert apply_cmd.kind == "apply_tuning"
    assert apply_cmd.spec["rss_queues"] is None
    assert apply_cmd.spec["sysctls"] == {}


# ---------------------------------------------------------------------------
# Test 3: summarize finds optimum
# ---------------------------------------------------------------------------


def test_summarize_finds_optimum() -> None:
    """Three points at 5/8/12 Gbps — optimum must be 12.0 Gbps."""
    sc = _sweep_scenario(rss_queues=[1, 4, 8])
    runner = TuningSweepRunner(sc)

    # Craft 9 cmd_results: (apply, server, client) × 3
    def _trio(tput: float, rss: int) -> list[dict]:
        return [
            {"tool": "apply_tuning", "ok": True, "_sweep_point": {"rss_queues": rss}},
            {"tool": "iperf3", "ok": True, "throughput_gbps": 0.0},  # server (ignored)
            {"tool": "iperf3", "ok": True, "throughput_gbps": tput, "_sweep_point": {"rss_queues": rss}},
        ]

    cmd_results = _trio(5.0, 1) + _trio(8.0, 4) + _trio(12.0, 8)
    result = runner.summarize(cmd_results)

    assert result.ok is True
    assert result.raw["optimum"] is not None
    assert result.raw["optimum"]["throughput_gbps"] == 12.0
    assert result.raw["optimum"]["point"] == {"rss_queues": 8}
    assert len(result.raw["points"]) == 3


# ---------------------------------------------------------------------------
# Test 4: summarize with all failed → scenario_result.ok False, optimum None
# ---------------------------------------------------------------------------


def test_summarize_all_failed_reports_fail() -> None:
    """All client results ok=False → ScenarioResult.ok=False, optimum=None."""
    sc = _sweep_scenario(rss_queues=[1, 4])
    runner = TuningSweepRunner(sc)

    def _failed_trio(rss: int) -> list[dict]:
        return [
            {"tool": "apply_tuning", "ok": True, "_sweep_point": {"rss_queues": rss}},
            {"tool": "iperf3", "ok": False, "throughput_gbps": 0.0},
            {"tool": "iperf3", "ok": False, "throughput_gbps": 0.0, "_sweep_point": {"rss_queues": rss}},
        ]

    cmd_results = _failed_trio(1) + _failed_trio(4)
    result = runner.summarize(cmd_results)

    assert result.ok is False
    assert result.raw["optimum"] is None


# ---------------------------------------------------------------------------
# Test 5: build_runner dispatches tuning_sweep
# ---------------------------------------------------------------------------


def test_build_runner_dispatches_tuning_sweep() -> None:
    """build_runner(TuningSweepScenario) returns TuningSweepRunner."""
    sc = _sweep_scenario()
    runner = build_runner(sc)
    assert isinstance(runner, TuningSweepRunner)
