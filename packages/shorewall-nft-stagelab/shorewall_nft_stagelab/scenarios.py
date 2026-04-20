"""High-level test scenarios: throughput_sweep, conn_storm, rule_scan, failover_drill."""

from __future__ import annotations

import ipaddress
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Union

from .config import (
    ConnStormScenario,
    RuleScanScenario,
    StagelabConfig,
    ThroughputScenario,
)
from .report import ScenarioResult

# ---------------------------------------------------------------------------
# AgentCommand
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentCommand:
    """A single command the controller sends to one agent via IPC.

    The controller resolves ``endpoint_name`` → host for transport.
    Scenarios do not know transport details.
    """

    endpoint_name: str
    kind: str   # "run_iperf3_server" | "run_iperf3_client" | "run_tcpkali" |
                # "run_nmap" | "send_probe" | "collect_oracle_verdict"
    spec: dict


# ---------------------------------------------------------------------------
# Scenario ABC
# ---------------------------------------------------------------------------


class Scenario(ABC):
    """Abstract base for all scenario runners."""

    @abstractmethod
    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        """Return the ordered list of commands the controller must execute."""

    @abstractmethod
    def summarize(self, results: list[dict]) -> ScenarioResult:
        """Aggregate agent result dicts into a ScenarioResult."""


# ---------------------------------------------------------------------------
# ThroughputRunner
# ---------------------------------------------------------------------------


class ThroughputRunner(Scenario):
    """Wraps ``config.ThroughputScenario``.

    ``plan()`` emits two commands:
    1. run_iperf3_server on the *sink* endpoint.
    2. run_iperf3_client on the *source* endpoint (delay_before_s=1 head-start).
    """

    def __init__(self, scenario: ThroughputScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        ep_map = {ep.name: ep for ep in cfg.endpoints}
        sink_ep = ep_map[sc.sink]
        src_ep = ep_map[sc.source]

        # Derive bind/server IPs from endpoint config (strip prefix len).
        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else ""
        src_ip = src_ep.ipv4.split("/")[0] if src_ep.ipv4 else ""

        server_cmd = AgentCommand(
            endpoint_name=sc.sink,
            kind="run_iperf3_server",
            spec={
                "bind": sink_ip,
                "port": 5201,
                "scenario_id": sc.id,
            },
        )
        client_cmd = AgentCommand(
            endpoint_name=sc.source,
            kind="run_iperf3_client",
            spec={
                "bind": src_ip,
                "server_ip": sink_ip,
                "port": 5201,
                "duration_s": sc.duration_s,
                "parallel": sc.parallel,
                "proto": sc.proto,
                "delay_before_s": 1,
                "scenario_id": sc.id,
            },
        )
        return [server_cmd, client_cmd]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        # Expect one client result dict (server produces no throughput metric).
        client_results = [r for r in results if r.get("role") != "server"]
        if not client_results:
            client_results = results  # fallback: use all

        total_duration = 0.0
        throughput_gbps = 0.0
        ok = False

        for r in client_results:
            throughput_gbps += r.get("throughput_gbps", 0.0)
            total_duration = max(total_duration, r.get("duration_s", 0.0))
            ok = r.get("ok", False)

        ok = ok and throughput_gbps >= sc.expect_min_gbps

        return ScenarioResult(
            scenario_id=sc.id,
            kind="throughput",
            ok=ok,
            duration_s=total_duration,
            raw={"throughput_gbps": throughput_gbps},
        )


# ---------------------------------------------------------------------------
# ConnStormRunner
# ---------------------------------------------------------------------------


class ConnStormRunner(Scenario):
    """Wraps ``config.ConnStormScenario``.

    ``plan()`` emits a single ``run_tcpkali`` command on the *source* endpoint.
    The sink is expected to have an iperf3-server or similar listener running.
    """

    def __init__(self, scenario: ConnStormScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        ep_map = {ep.name: ep for ep in cfg.endpoints}
        sink_ep = ep_map[sc.sink]
        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else ""

        return [
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_tcpkali",
                spec={
                    "server_ip": sink_ip,
                    "port": 5201,
                    "target_conns": sc.target_conns,
                    "rate_per_s": sc.rate_per_s,
                    "hold_s": sc.hold_s,
                    "scenario_id": sc.id,
                },
            )
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        r = results[0] if results else {}
        established = r.get("established", 0)
        failed = r.get("failed", 0)
        ok = r.get("ok", False) and established >= sc.target_conns

        return ScenarioResult(
            scenario_id=sc.id,
            kind="conn_storm",
            ok=ok,
            duration_s=r.get("duration_s", 0.0),
            raw={
                "target_conns": sc.target_conns,
                "established": established,
                "failed": failed,
            },
        )


# ---------------------------------------------------------------------------
# RuleScanRunner
# ---------------------------------------------------------------------------

_PROTOS = ["tcp", "udp"]


class RuleScanRunner(Scenario):
    """Wraps ``config.RuleScanScenario``.

    ``plan()`` emits ``random_count`` send_probe commands (one per probe)
    plus one trailing ``collect_oracle_verdict`` command as a hint to the
    controller.  Probe generation is seeded (seed=42) so runs are reproducible.
    """

    def __init__(self, scenario: RuleScanScenario) -> None:
        self._sc = scenario

    def _make_rng(self) -> random.Random:
        return random.Random(42)

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        ep_map = {ep.name: ep for ep in cfg.endpoints}
        src_ep = ep_map[sc.source]
        src_ip = src_ep.ipv4.split("/")[0] if src_ep.ipv4 else "0.0.0.0"

        network = ipaddress.ip_network(sc.target_subnet, strict=False)
        hosts = list(network.hosts())

        rng = self._make_rng()
        commands: list[AgentCommand] = []

        for i in range(sc.random_count):
            probe_id = i + 1
            dst_ip = str(rng.choice(hosts)) if hosts else str(network.network_address)
            src_port = rng.randint(1024, 65535)
            dst_port = rng.randint(1, 65535)
            proto = _PROTOS[i % len(_PROTOS)]

            commands.append(
                AgentCommand(
                    endpoint_name=sc.source,
                    kind="send_probe",
                    spec={
                        "probe_id": probe_id,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "proto": proto,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "scenario_id": sc.id,
                    },
                )
            )

        # Hint command: tells the controller to run oracle correlation locally.
        commands.append(
            AgentCommand(
                endpoint_name=sc.source,
                kind="collect_oracle_verdict",
                spec={"scenario_id": sc.id, "probe_count": sc.random_count},
            )
        )
        return commands

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        probe_results = [r for r in results if r.get("kind") != "oracle"]
        total = len(probe_results)
        mismatches = [r for r in probe_results if not r.get("ok", True)]
        passed = total - len(mismatches)

        return ScenarioResult(
            scenario_id=sc.id,
            kind="rule_scan",
            ok=len(mismatches) == 0,
            duration_s=sum(r.get("duration_s", 0.0) for r in probe_results),
            raw={
                "total_probes": total,
                "passed": passed,
                "mismatches": mismatches,
            },
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_ScenarioCfg = Union[ThroughputScenario, ConnStormScenario, RuleScanScenario]


def build_runner(scenario: _ScenarioCfg) -> Scenario:
    """Dispatch on scenario.kind and return the matching runner."""
    if scenario.kind == "throughput":
        return ThroughputRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "conn_storm":
        return ConnStormRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "rule_scan":
        return RuleScanRunner(scenario)  # type: ignore[arg-type]
    raise ValueError(f"Unknown scenario kind: {scenario.kind!r}")


__all__ = [
    "AgentCommand",
    "Scenario",
    "ThroughputRunner",
    "ConnStormRunner",
    "RuleScanRunner",
    "build_runner",
]
