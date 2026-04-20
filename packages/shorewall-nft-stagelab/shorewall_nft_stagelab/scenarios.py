"""High-level test scenarios: throughput_sweep, conn_storm, rule_scan, failover_drill."""

from __future__ import annotations

import ipaddress
import itertools
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Union

from .config import (
    ConnStormAstfScenario,
    ConnStormScenario,
    RuleScanScenario,
    StagelabConfig,
    ThroughputDpdkScenario,
    ThroughputScenario,
    TuningSweepScenario,
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
                    "target": f"{sink_ip}:5001",
                    "connections": sc.target_conns,
                    "connect_rate": sc.rate_per_s,
                    "duration_s": sc.hold_s,
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
# TuningSweepRunner
# ---------------------------------------------------------------------------


class TuningSweepRunner(Scenario):
    """Wraps ``config.TuningSweepScenario``.

    ``plan()`` emits a triplet of (apply_tuning, run_iperf3_server,
    run_iperf3_client) for every Cartesian-product grid point derived from
    ``rss_queues``, ``rmem_max``, and ``wmem_max`` axes.
    """

    def __init__(self, scenario: TuningSweepScenario) -> None:
        self._scen = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        scen = self._scen
        src_ep = next(ep for ep in cfg.endpoints if ep.name == scen.source)
        sink_ep = next(ep for ep in cfg.endpoints if ep.name == scen.sink)

        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else ""
        src_ip = src_ep.ipv4.split("/")[0] if src_ep.ipv4 else ""

        # Cartesian product of non-empty grid axes.
        axes: list[tuple[str, list]] = []
        if scen.rss_queues:
            axes.append(("rss_queues", scen.rss_queues))
        if scen.rmem_max:
            axes.append(("rmem_max", scen.rmem_max))
        if scen.wmem_max:
            axes.append(("wmem_max", scen.wmem_max))

        value_lists = [vs for _, vs in axes]
        keys = [k for k, _ in axes]
        combos: list[tuple] = list(itertools.product(*value_lists)) if value_lists else [()]

        commands: list[AgentCommand] = []
        # Rotate iperf3 port across sweep points so a prior --one-off server
        # still in TIME_WAIT on the previous port cannot race the next client.
        for idx, combo in enumerate(combos):
            params: dict = dict(zip(keys, combo))
            port = 5201 + idx
            sysctls: dict[str, str] = {}
            if "rmem_max" in params:
                sysctls["net.core.rmem_max"] = str(params["rmem_max"])
            if "wmem_max" in params:
                sysctls["net.core.wmem_max"] = str(params["wmem_max"])

            commands.append(AgentCommand(
                endpoint_name=scen.source,
                kind="apply_tuning",
                spec={
                    "iface": src_ep.nic,
                    "rss_queues": params.get("rss_queues"),
                    "sysctls": sysctls,
                    "_sweep_point": params,
                },
            ))
            commands.append(AgentCommand(
                endpoint_name=scen.sink,
                kind="run_iperf3_server",
                spec={
                    "bind": sink_ip,
                    "duration_s": scen.duration_per_point_s + 2,
                    "port": port,
                },
            ))
            commands.append(AgentCommand(
                endpoint_name=scen.source,
                kind="run_iperf3_client",
                spec={
                    "bind": src_ip,
                    "server_ip": sink_ip,
                    "duration_s": scen.duration_per_point_s,
                    "parallel": 1,
                    "proto": scen.proto,
                    "delay_before_s": 0.5,
                    "port": port,
                    "_sweep_point": params,
                },
            ))
        return commands

    def summarize(self, cmd_results: list[dict]) -> ScenarioResult:
        scen = self._scen
        points: list[dict] = []
        for i in range(0, len(cmd_results), 3):
            if i + 2 >= len(cmd_results):
                break
            client_res = cmd_results[i + 2]
            point = client_res.get("_sweep_point") or {}
            tput = float(client_res.get("throughput_gbps", 0.0))
            points.append({
                "point": point,
                "throughput_gbps": tput,
                "ok": client_res.get("ok", False),
            })
        best = max(
            (p for p in points if p["ok"]),
            key=lambda p: p["throughput_gbps"],
            default=None,
        )
        ok = best is not None
        return ScenarioResult(
            scenario_id=scen.id,
            kind="tuning_sweep",
            ok=ok,
            duration_s=0.0,
            raw={"points": points, "optimum": best, "tool": "tuning_sweep"},
        )


# ---------------------------------------------------------------------------
# ThroughputDpdkRunner
# ---------------------------------------------------------------------------


class ThroughputDpdkRunner(Scenario):
    """Wraps ``config.ThroughputDpdkScenario``.

    ``plan()`` emits a single ``run_trex_stateless`` command on the *source*
    endpoint (TX side).  Sink-side RX counter collection is deferred to the
    agent (T24) as a POLL_METRICS call.
    """

    def __init__(self, scenario: ThroughputDpdkScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        if src_ep.trex_port_id is None:
            raise RuntimeError(
                f"scenario {sc.id!r}: source endpoint {sc.source!r} is not a DPDK "
                "endpoint — throughput_dpdk requires mode=dpdk endpoints."
            )
        ports = (src_ep.trex_port_id,)
        spec: dict = {
            "ports": ports,
            "duration_s": sc.duration_s,
            "multiplier": sc.multiplier,
            "_scenario_id": sc.id,
        }
        if sc.pcap_file:
            spec["pcap_files"] = (sc.pcap_file,)
        else:
            spec["packet_size_b"] = sc.packet_size_b
        return [
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_trex_stateless",
                spec=spec,
            )
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        r = results[0] if results else {}
        if not r.get("ok", False):
            return ScenarioResult(
                scenario_id=sc.id,
                kind="throughput_dpdk",
                ok=False,
                duration_s=float(r.get("duration_s", 0.0)),
                raw=r,
            )
        throughput_gbps = float(r.get("throughput_gbps", 0.0))
        return ScenarioResult(
            scenario_id=sc.id,
            kind="throughput_dpdk",
            ok=True,
            duration_s=float(r.get("duration_s", 0.0)),
            raw={
                "throughput_gbps": throughput_gbps,
                "pps": r.get("pps", 0.0),
                "errors": r.get("errors", 0),
                "tool": r.get("tool", "trex-stl"),
                **r,
            },
        )


# ---------------------------------------------------------------------------
# ConnStormAstfRunner
# ---------------------------------------------------------------------------


class ConnStormAstfRunner(Scenario):
    """Wraps ``config.ConnStormAstfScenario``.

    ``plan()`` emits a single ``run_trex_astf`` command on the *source*
    endpoint.  The ASTF profile drives both client and server sides (TRex
    ASTF is single-box dual-port).
    """

    def __init__(self, scenario: ConnStormAstfScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        sink_ep = cfg.endpoint_by_name(sc.sink)
        if src_ep.trex_port_id is None:
            raise RuntimeError(
                f"scenario {sc.id!r}: source endpoint {sc.source!r} is not a DPDK "
                "endpoint — conn_storm_astf requires mode=dpdk endpoints."
            )
        if sink_ep.trex_port_id is None:
            raise RuntimeError(
                f"scenario {sc.id!r}: sink endpoint {sc.sink!r} is not a DPDK "
                "endpoint — conn_storm_astf requires mode=dpdk endpoints."
            )
        # ASTF is single-box dual-port: include both client and server port IDs.
        if src_ep.host == sink_ep.host:
            ports = (src_ep.trex_port_id, sink_ep.trex_port_id)
        else:
            ports = (src_ep.trex_port_id,)
        return [
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_trex_astf",
                spec={
                    "ports": ports,
                    "profile_py": sc.profile_py,
                    "duration_s": sc.duration_s,
                    "multiplier": sc.multiplier,
                    "_scenario_id": sc.id,
                },
            )
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        r = results[0] if results else {}
        concurrent_sessions = int(r.get("concurrent_sessions", 0))
        new_sessions_per_s = float(r.get("new_sessions_per_s", 0.0))
        errors = int(r.get("errors", 0))
        base_ok = r.get("ok", False)
        threshold_ok = concurrent_sessions >= sc.expect_min_concurrent
        ok = bool(base_ok) and threshold_ok
        return ScenarioResult(
            scenario_id=sc.id,
            kind="conn_storm_astf",
            ok=ok,
            duration_s=float(r.get("duration_s", 0.0)),
            raw={
                "concurrent_sessions": concurrent_sessions,
                "new_sessions_per_s": new_sessions_per_s,
                "errors": errors,
                "expect_min_concurrent": sc.expect_min_concurrent,
                "tool": r.get("tool", "trex-astf"),
                **r,
            },
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_ScenarioCfg = Union[
    ThroughputScenario,
    ConnStormScenario,
    RuleScanScenario,
    TuningSweepScenario,
    ThroughputDpdkScenario,
    ConnStormAstfScenario,
]


def build_runner(scenario: _ScenarioCfg) -> Scenario:
    """Dispatch on scenario.kind and return the matching runner."""
    if scenario.kind == "throughput":
        return ThroughputRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "conn_storm":
        return ConnStormRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "rule_scan":
        return RuleScanRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "tuning_sweep":
        return TuningSweepRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "throughput_dpdk":
        return ThroughputDpdkRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "conn_storm_astf":
        return ConnStormAstfRunner(scenario)  # type: ignore[arg-type]
    raise ValueError(f"Unknown scenario kind: {scenario.kind!r}")


__all__ = [
    "AgentCommand",
    "Scenario",
    "ThroughputRunner",
    "ConnStormRunner",
    "RuleScanRunner",
    "TuningSweepRunner",
    "ThroughputDpdkRunner",
    "ConnStormAstfRunner",
    "build_runner",
]
