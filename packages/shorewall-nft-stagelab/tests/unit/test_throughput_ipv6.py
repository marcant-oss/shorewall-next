"""Unit tests for IPv6 family support in ThroughputRunner and config."""

from __future__ import annotations

import pytest

from shorewall_nft_stagelab.config import (
    Dut,
    Endpoint,
    Host,
    StagelabConfig,
    ThroughputScenario,
)
from shorewall_nft_stagelab.scenarios import ThroughputRunner


def _make_cfg(
    *,
    src_ipv6: str | None = "fd00::1/64",
    sink_ipv6: str | None = "fd00::2/64",
    src_ipv4: str | None = "10.0.0.1/24",
    sink_ipv4: str | None = "10.0.0.2/24",
) -> StagelabConfig:
    """Build a minimal StagelabConfig with two native endpoints."""
    return StagelabConfig(
        hosts=[
            Host(name="h1", address="local:"),
            Host(name="h2", address="local:"),
        ],
        dut=Dut(kind="netns"),
        endpoints=[
            Endpoint(
                name="src-ep",
                host="h1",
                mode="native",
                nic="eth0",
                vlan=10,
                ipv4=src_ipv4,
                ipv4_gw="10.0.0.254",
                ipv6=src_ipv6,
                ipv6_gw="fd00::fe" if src_ipv6 else None,
            ),
            Endpoint(
                name="sink-ep",
                host="h2",
                mode="native",
                nic="eth0",
                vlan=10,
                ipv4=sink_ipv4,
                ipv4_gw="10.0.0.254",
                ipv6=sink_ipv6,
                ipv6_gw="fd00::fe" if sink_ipv6 else None,
            ),
        ],
        scenarios=[],
        report={"output_dir": "/tmp/test"},
    )


def _make_scenario(family: str = "ipv6", proto: str = "tcp") -> ThroughputScenario:
    return ThroughputScenario(
        id="test-ipv6-throughput",
        kind="throughput",
        source="src-ep",
        sink="sink-ep",
        proto=proto,  # type: ignore[arg-type]
        duration_s=10,
        parallel=2,
        expect_min_gbps=1.0,
        family=family,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# ThroughputScenario config field
# ---------------------------------------------------------------------------


def test_throughput_scenario_default_family_is_ipv4() -> None:
    """family defaults to 'ipv4' — no breaking change."""
    sc = ThroughputScenario(
        id="t", kind="throughput", source="s", sink="k",
        proto="tcp", duration_s=10, parallel=1, expect_min_gbps=0.0,
    )
    assert sc.family == "ipv4"


def test_throughput_scenario_accepts_ipv6() -> None:
    sc = _make_scenario(family="ipv6")
    assert sc.family == "ipv6"


def test_throughput_scenario_rejects_bad_family() -> None:
    with pytest.raises(Exception):
        ThroughputScenario(
            id="t", kind="throughput", source="s", sink="k",
            proto="tcp", duration_s=10, parallel=1, expect_min_gbps=0.0,
            family="invalid",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# ThroughputRunner.plan() — IPv6 path
# ---------------------------------------------------------------------------


def test_plan_ipv6_uses_ipv6_addresses() -> None:
    """plan() with family='ipv6' must bind to the IPv6 addresses, not IPv4."""
    cfg = _make_cfg()
    runner = ThroughputRunner(_make_scenario(family="ipv6"))
    cmds = runner.plan(cfg)

    server_cmd = next(c for c in cmds if c.kind == "run_iperf3_server")
    client_cmd = next(c for c in cmds if c.kind == "run_iperf3_client")

    # Addresses must be stripped IPv6 (no prefix length).
    assert server_cmd.spec["bind"] == "fd00::2"
    assert client_cmd.spec["bind"] == "fd00::1"
    assert client_cmd.spec["server_ip"] == "fd00::2"

    # family must propagate into both specs.
    assert server_cmd.spec["family"] == "ipv6"
    assert client_cmd.spec["family"] == "ipv6"


def test_plan_ipv4_still_uses_ipv4_addresses() -> None:
    """Default family='ipv4' behaviour is unchanged."""
    cfg = _make_cfg()
    runner = ThroughputRunner(_make_scenario(family="ipv4"))
    cmds = runner.plan(cfg)

    server_cmd = next(c for c in cmds if c.kind == "run_iperf3_server")
    client_cmd = next(c for c in cmds if c.kind == "run_iperf3_client")

    assert server_cmd.spec["bind"] == "10.0.0.2"
    assert client_cmd.spec["bind"] == "10.0.0.1"
    assert client_cmd.spec["server_ip"] == "10.0.0.2"
    assert server_cmd.spec["family"] == "ipv4"
    assert client_cmd.spec["family"] == "ipv4"


def test_plan_ipv6_missing_sink_raises() -> None:
    """plan() raises ValueError with endpoint name when sink has no ipv6."""
    cfg = _make_cfg(sink_ipv6=None)
    runner = ThroughputRunner(_make_scenario(family="ipv6"))
    with pytest.raises(ValueError, match="sink-ep"):
        runner.plan(cfg)


def test_plan_ipv6_missing_source_raises() -> None:
    """plan() raises ValueError with endpoint name when source has no ipv6."""
    cfg = _make_cfg(src_ipv6=None)
    runner = ThroughputRunner(_make_scenario(family="ipv6"))
    with pytest.raises(ValueError, match="src-ep"):
        runner.plan(cfg)


def test_plan_ipv6_udp() -> None:
    """family='ipv6' works for UDP scenarios too."""
    cfg = _make_cfg()
    runner = ThroughputRunner(_make_scenario(family="ipv6", proto="udp"))
    cmds = runner.plan(cfg)
    client_cmd = next(c for c in cmds if c.kind == "run_iperf3_client")
    assert client_cmd.spec["proto"] == "udp"
    assert client_cmd.spec["family"] == "ipv6"
