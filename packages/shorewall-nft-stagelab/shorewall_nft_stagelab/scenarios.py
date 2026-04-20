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
    ConntrackOverflowScenario,
    DnsDosScenario,
    EvasionProbesScenario,
    HaFailoverDrillScenario,
    HalfOpenDosScenario,
    LongFlowSurvivalScenario,
    ReloadAtomicityScenario,
    RuleCoverageMatrixScenario,
    RuleScanScenario,
    StagelabConfig,
    StatefulHelperFtpScenario,
    SynFloodDosScenario,
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
        if sc.family == "ipv6":
            if not sink_ep.ipv6:
                raise ValueError(
                    f"throughput scenario {sc.id!r}: family=ipv6 requires "
                    f"ipv6 address on sink endpoint {sc.sink!r}"
                )
            if not src_ep.ipv6:
                raise ValueError(
                    f"throughput scenario {sc.id!r}: family=ipv6 requires "
                    f"ipv6 address on source endpoint {sc.source!r}"
                )
            sink_ip = sink_ep.ipv6.split("/")[0]
            src_ip = src_ep.ipv6.split("/")[0]
        else:
            sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else ""
            src_ip = src_ep.ipv4.split("/")[0] if src_ep.ipv4 else ""

        server_cmd = AgentCommand(
            endpoint_name=sc.sink,
            kind="run_iperf3_server",
            spec={
                "bind": sink_ip,
                "port": 5201,
                "family": sc.family,
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
                "family": sc.family,
                "delay_before_s": 1,
                "measure_latency": sc.measure_latency,
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

        # Collect latency percentiles from the first client result that has them.
        latency_p50_ms: float | None = None
        latency_p95_ms: float | None = None
        latency_p99_ms: float | None = None
        if sc.measure_latency and client_results:
            r0 = client_results[0]
            latency_p50_ms = r0.get("latency_p50_ms")
            latency_p95_ms = r0.get("latency_p95_ms")
            latency_p99_ms = r0.get("latency_p99_ms")

        # Evaluate acceptance_criteria for latency keys.
        criteria_results: dict[str, bool] = {}
        if sc.measure_latency and sc.acceptance_criteria:
            if "latency_p95_ms_max" in sc.acceptance_criteria and latency_p95_ms is not None:
                criteria_results["latency_p95_ms"] = latency_p95_ms <= sc.acceptance_criteria["latency_p95_ms_max"]
            if "latency_p99_ms_max" in sc.acceptance_criteria and latency_p99_ms is not None:
                criteria_results["latency_p99_ms"] = latency_p99_ms <= sc.acceptance_criteria["latency_p99_ms_max"]
            if "latency_p50_ms_max" in sc.acceptance_criteria and latency_p50_ms is not None:
                criteria_results["latency_p50_ms"] = latency_p50_ms <= sc.acceptance_criteria["latency_p50_ms_max"]

        raw: dict = {"throughput_gbps": throughput_gbps}
        if sc.measure_latency:
            raw["latency_p50_ms"] = latency_p50_ms
            raw["latency_p95_ms"] = latency_p95_ms
            raw["latency_p99_ms"] = latency_p99_ms

        return ScenarioResult(
            scenario_id=sc.id,
            kind="throughput",
            ok=ok,
            duration_s=total_duration,
            raw=raw,
            criteria_results=criteria_results,
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
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
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
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
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
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
            test_id=getattr(self._scen, "test_id", None),
            standard_refs=list(getattr(self._scen, "standard_refs", []) or []),
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
                test_id=getattr(self._sc, "test_id", None),
                standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
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
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
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
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# _parse_port_range helper
# ---------------------------------------------------------------------------


def _parse_port_range(spec: str) -> list[int]:
    """Parse a port spec string into a list of ints.

    Accepts comma-separated values and/or hyphenated ranges, e.g.:
      "80,443"       → [80, 443]
      "1000-1010"    → [1000, 1001, …, 1010]
      "80,443,8000-8003" → [80, 443, 8000, 8001, 8002, 8003]
    """
    result: list[int] = []
    for token in spec.split(","):
        token = token.strip()
        if "-" in token:
            lo_s, hi_s = token.split("-", 1)
            lo, hi = int(lo_s.strip()), int(hi_s.strip())
            result.extend(range(lo, hi + 1))
        else:
            result.append(int(token))
    return result


# ---------------------------------------------------------------------------
# SynFloodDosRunner
# ---------------------------------------------------------------------------


class SynFloodDosRunner(Scenario):
    """Wraps ``config.SynFloodDosScenario``.

    ``plan()`` emits a single ``run_trex_stateless`` command on the *source*
    endpoint carrying an inline STL profile that generates spoofed-source SYN
    packets at the configured rate.
    """

    def __init__(self, scenario: SynFloodDosScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        from .trafgen_trex_profiles import build_syn_flood_profile

        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        sink_ep = cfg.endpoint_by_name(sc.sink)
        if src_ep.mode != "dpdk" or sink_ep.mode != "dpdk":
            raise RuntimeError(
                f"scenario {sc.id!r}: dos_syn_flood requires both source and sink "
                "to be mode=dpdk endpoints"
            )

        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else "0.0.0.0"
        dst_ports = tuple(_parse_port_range(sc.dst_port_range))
        profile_text = build_syn_flood_profile(
            src_cidr=sc.src_ip_range,
            dst_ips=(sink_ip,),
            dst_ports=dst_ports,
            rate_pps=sc.rate_pps,
        )

        return [
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_trex_stateless",
                spec={
                    "ports": (src_ep.trex_port_id or 0,),
                    "duration_s": sc.duration_s,
                    "multiplier": f"{sc.rate_pps}pps",
                    "profile_text": profile_text,
                    "scenario_id": sc.id,
                },
            ),
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        r = results[0] if results else {}
        passed_ratio = float(r.get("passed_ratio", 0.0))
        ok = r.get("ok", False) and passed_ratio <= sc.expect_max_passed_ratio
        return ScenarioResult(
            scenario_id=sc.id,
            kind="dos_syn_flood",
            ok=ok,
            duration_s=r.get("duration_s", 0.0),
            raw={
                "passed_ratio": passed_ratio,
                "rate_pps": sc.rate_pps,
                "observed_tx_pps": r.get("pps", 0.0),
                "errors": r.get("errors", 0),
            },
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# DnsDosRunner
# ---------------------------------------------------------------------------


def _qnames_for_pattern(pattern: str, fixed_qname: str) -> list[str]:
    """Return a list of qnames for the given query_name_pattern."""
    if pattern == "fixed":
        return [fixed_qname]
    if pattern == "amplification":
        return ["example.com"]
    # random: 100 random 8-hex-char labels + ".example.com"
    import secrets
    return [f"{secrets.token_hex(4)}.example.com" for _ in range(100)]


class DnsDosRunner(Scenario):
    """Wraps ``config.DnsDosScenario``.

    ``plan()`` emits a single ``run_trex_stateless`` command on the *source*
    endpoint carrying an inline STL profile that generates UDP-53 DNS query
    packets at the configured rate.
    """

    def __init__(self, scenario: DnsDosScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        from .trafgen_trex_profiles import build_dns_query_profile

        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        if src_ep.mode != "dpdk":
            raise RuntimeError(
                f"scenario {sc.id!r}: dos_dns_query requires source to be mode=dpdk"
            )
        src_cidr = src_ep.ipv4 if src_ep.ipv4 else "0.0.0.0/32"
        qnames = _qnames_for_pattern(sc.query_name_pattern, sc.fixed_qname)
        qtype = "ANY" if sc.query_name_pattern == "amplification" else "A"
        profile_text = build_dns_query_profile(
            src_cidr=src_cidr,
            resolver_ip=sc.target_resolver,
            qnames=tuple(qnames),
            qps=sc.queries_per_s,
            qtype=qtype,
        )
        return [
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_trex_stateless",
                spec={
                    "ports": (src_ep.trex_port_id or 0,),
                    "duration_s": sc.duration_s,
                    "multiplier": f"{sc.queries_per_s}pps",
                    "profile_text": profile_text,
                    "scenario_id": sc.id,
                },
            ),
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        r = results[0] if results else {}
        latency_increase_ratio = float(r.get("latency_increase_ratio", 0.0))
        ok = r.get("ok", False)
        return ScenarioResult(
            scenario_id=sc.id,
            kind="dos_dns_query",
            ok=ok,
            duration_s=r.get("duration_s", 0.0),
            raw={
                "queries_per_s": sc.queries_per_s,
                "observed_tx_pps": r.get("pps", 0.0),
                "errors": r.get("errors", 0),
                "latency_increase_ratio": latency_increase_ratio,
                "query_name_pattern": sc.query_name_pattern,
            },
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# HalfOpenDosRunner
# ---------------------------------------------------------------------------


class HalfOpenDosRunner(Scenario):
    """Wraps ``config.HalfOpenDosScenario``.

    ``plan()`` emits a single ``run_trex_astf`` command on the *source*
    endpoint.  The embedded ASTF profile opens TCP connections to the sink
    and idles (no FIN, no RST) to saturate the conntrack table.
    """

    def __init__(self, scenario: HalfOpenDosScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        from .trafgen_trex_profiles import build_half_open_profile

        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        sink_ep = cfg.endpoint_by_name(sc.sink)
        if src_ep.mode != "dpdk" or sink_ep.mode != "dpdk":
            raise RuntimeError(
                f"scenario {sc.id!r}: dos_half_open requires both endpoints "
                "to be mode=dpdk"
            )
        src_cidr = src_ep.ipv4 if src_ep.ipv4 else "0.0.0.0/32"
        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else "0.0.0.0"
        profile_text = build_half_open_profile(
            src_cidr=src_cidr,
            dst_ip=sink_ip,
            dst_port=sc.dst_port,
            target_conns=sc.target_conns,
            open_rate_per_s=sc.open_rate_per_s,
        )
        return [
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_trex_astf",
                spec={
                    "duration_s": sc.duration_s,
                    "multiplier": 1.0,
                    "profile_text": profile_text,
                    "scenario_id": sc.id,
                },
            ),
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        r = results[0] if results else {}
        observed_conns = int(r.get("concurrent_sessions", 0))
        saturated = observed_conns < int(0.5 * sc.target_conns)
        ok = r.get("ok", False) and observed_conns >= sc.target_conns
        return ScenarioResult(
            scenario_id=sc.id,
            kind="dos_half_open",
            ok=ok,
            duration_s=r.get("duration_s", 0.0),
            raw={
                "target_conns": sc.target_conns,
                "observed_conns": observed_conns,
                "open_rate_per_s": sc.open_rate_per_s,
                "errors": r.get("errors", 0),
                "conntrack_saturated": saturated,
            },
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# RuleCoverageMatrixRunner
# ---------------------------------------------------------------------------


class RuleCoverageMatrixRunner(Scenario):
    """Systematic zone x zone x proto x port coverage.

    Emits one send_probe command per tuple, iterating through tcp_ports,
    udp_ports, and icmp combinations exhaustively (no random sampling).
    Same-zone pairs are skipped — intra-zone is typically implicit-accept.
    """

    def __init__(self, scenario: RuleCoverageMatrixScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        commands: list[AgentCommand] = []
        probe_id = 0

        # Deterministic iteration order: sorted zone names → consistent test+report.
        zones = sorted(sc.zone_subnets.keys())
        for src_zone in zones:
            src_net = ipaddress.ip_network(sc.zone_subnets[src_zone], strict=False)
            src_hosts = list(src_net.hosts()) or [src_net.network_address]
            src_ip = str(src_hosts[0])

            for dst_zone in zones:
                if dst_zone == src_zone:
                    continue  # skip same-zone (usually accepted implicitly)
                dst_net = ipaddress.ip_network(sc.zone_subnets[dst_zone], strict=False)
                dst_hosts = list(dst_net.hosts()) or [dst_net.network_address]
                dst_ip = str(dst_hosts[0])

                for proto in sc.protos:
                    ports: list[int] = (
                        sc.tcp_ports if proto == "tcp"
                        else sc.udp_ports if proto == "udp"
                        else [0]
                    )
                    for port in ports:
                        for _ in range(sc.probe_count_per_tuple):
                            probe_id += 1
                            commands.append(AgentCommand(
                                endpoint_name=sc.source,
                                kind="send_probe",
                                spec={
                                    "probe_id": probe_id,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_zone": src_zone,
                                    "dst_zone": dst_zone,
                                    "proto": proto,
                                    "dst_port": port,
                                    "scenario_id": sc.id,
                                },
                            ))

        # One oracle hint at the end (consistent with RuleScanRunner pattern).
        commands.append(AgentCommand(
            endpoint_name=sc.source,
            kind="collect_oracle_verdict",
            spec={"scenario_id": sc.id},
        ))
        return commands

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        # Exclude the oracle-marker command from probe counts.
        probe_results = [r for r in results if r.get("tool") != "oracle_marker"]
        total = len(probe_results)
        ok_count = sum(1 for r in probe_results if r.get("ok") is True)
        mismatches = [r for r in probe_results if r.get("oracle_mismatch") is True]

        # Structured matrix: (src_zone, dst_zone, proto, port) → pass|fail
        matrix: dict[tuple[str, str, str, int], bool] = {}
        for r in probe_results:
            key = (
                r.get("src_zone", ""),
                r.get("dst_zone", ""),
                r.get("proto", ""),
                r.get("dst_port", 0),
            )
            matrix[key] = bool(r.get("ok", False))

        ok = len(mismatches) == 0 and total > 0
        return ScenarioResult(
            scenario_id=sc.id,
            kind="rule_coverage_matrix",
            ok=ok,
            duration_s=0.0,
            raw={
                "total_probes": total,
                "passed": ok_count,
                "mismatches": len(mismatches),
                "matrix": {f"{k[0]}\u2192{k[1]}/{k[2]}/{k[3]}": v for k, v in matrix.items()},
            },
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# StatefulHelperFtpRunner
# ---------------------------------------------------------------------------


class StatefulHelperFtpRunner(Scenario):
    """Validates nf_conntrack_ftp helper: sends an FTP request through the
    FW; success requires the helper to track the negotiated data channel."""

    def __init__(self, scenario: StatefulHelperFtpScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        sink_ep = cfg.endpoint_by_name(sc.sink)
        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else ""
        return [
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_ftp_helper_probe",
                spec={
                    "sink_ip": sink_ip,
                    "ftp_port": sc.ftp_port,
                    "mode": sc.mode,
                    "user": sc.user,
                    "password": sc.password,
                    "test_file": sc.test_file,
                    "scenario_id": sc.id,
                },
            ),
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        r = results[0] if results else {}
        data_ok = bool(r.get("data_transfer_ok", False))
        control_ok = bool(r.get("control_ok", False))
        ok = control_ok and (data_ok == sc.expect_data_connection)
        return ScenarioResult(
            scenario_id=sc.id,
            kind="stateful_helper_ftp",
            ok=ok,
            duration_s=r.get("duration_s", 0.0),
            raw={
                "control_ok": control_ok,
                "data_transfer_ok": data_ok,
                "expected_data_connection": sc.expect_data_connection,
                "mode": sc.mode,
            },
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# EvasionProbesRunner
# ---------------------------------------------------------------------------


class EvasionProbesRunner(Scenario):
    """Battery of evasion probes. Each probe is expected to be DROPPED by
    the FW (oracle-side: ``expected_verdict = drop``). A probe that passes
    is a real finding — summarize() flags the failing probe_ids."""

    def __init__(self, scenario: EvasionProbesScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        src_ip = src_ep.ipv4.split("/")[0] if src_ep.ipv4 else "0.0.0.0"

        commands: list[AgentCommand] = []
        for idx, probe_type in enumerate(sc.probe_types, start=1):
            probe_spec: dict = {
                "probe_id": idx,
                "probe_type": probe_type,
                "src_ip": sc.spoof_src_ip if probe_type == "ip_spoof" else src_ip,
                "dst_ip": sc.target_ip,
                "dst_port": sc.target_port,
                "scenario_id": sc.id,
                "expected_verdict": "drop",
            }
            if probe_type == "tcp_null":
                probe_spec["proto"] = "tcp"
                probe_spec["tcp_flags"] = ""
            elif probe_type == "tcp_xmas":
                probe_spec["proto"] = "tcp"
                probe_spec["tcp_flags"] = "FPU"
            elif probe_type == "tcp_fin_no_syn":
                probe_spec["proto"] = "tcp"
                probe_spec["tcp_flags"] = "F"
            elif probe_type == "tcp_shrinking_window":
                probe_spec["proto"] = "tcp"
                probe_spec["tcp_flags"] = "A"
                probe_spec["tcp_window"] = 1
            elif probe_type == "ip_spoof":
                probe_spec["proto"] = "tcp"
                probe_spec["tcp_flags"] = "S"
            elif probe_type == "ip_overlap_fragments":
                probe_spec["proto"] = "icmp"
                probe_spec["frag_overlap"] = True
            elif probe_type == "udp_malformed_checksum":
                probe_spec["proto"] = "udp"
                probe_spec["udp_bad_checksum"] = True

            commands.append(AgentCommand(
                endpoint_name=sc.source,
                kind="send_probe",
                spec=probe_spec,
            ))

        commands.append(AgentCommand(
            endpoint_name=sc.source,
            kind="collect_oracle_verdict",
            spec={"scenario_id": sc.id},
        ))
        return commands

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        probe_results = [r for r in results if r.get("tool") != "oracle_marker"]
        total = len(probe_results)
        leaked = [r for r in probe_results if r.get("observed_verdict") == "accept"]
        ok = len(leaked) == 0 and total > 0
        return ScenarioResult(
            scenario_id=sc.id,
            kind="evasion_probes",
            ok=ok,
            duration_s=0.0,
            raw={
                "total_probes": total,
                "dropped_by_fw": total - len(leaked),
                "leaked_through": len(leaked),
                "leaked_probe_types": [r.get("probe_type", "?") for r in leaked],
                "probe_types_attempted": list(sc.probe_types),
            },
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# ReloadAtomicityRunner
# ---------------------------------------------------------------------------


class ReloadAtomicityRunner(Scenario):
    """Reload-atomicity drill. Emits three commands in sequence:

    1. run_iperf3_server on sink (duration = total + 10 s grace)
    2. run_iperf3_client on source with delay_before_s=1
    3. trigger_fw_reload — agent on source SSHes into fw_host mid-stream and
       executes the reload command, then returns continuity signal.

    Prerequisite: the agent host must have passwordless SSH access to the
    fw_host specified in the scenario config.
    """

    def __init__(self, scenario: ReloadAtomicityScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        sink_ep = cfg.endpoint_by_name(sc.sink)
        src_ip = src_ep.ipv4.split("/")[0] if src_ep.ipv4 else ""
        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else ""

        return [
            AgentCommand(
                endpoint_name=sc.sink,
                kind="run_iperf3_server",
                spec={
                    "bind": sink_ip,
                    "port": 5201,
                    "duration_s": sc.duration_s + 10,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_iperf3_client",
                spec={
                    "bind": src_ip,
                    "server_ip": sink_ip,
                    "port": 5201,
                    "duration_s": sc.duration_s,
                    "parallel": 1,
                    "proto": "tcp",
                    "delay_before_s": 1,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.source,  # agent on source runs the ssh trigger
                kind="trigger_fw_reload",
                spec={
                    "fw_host": sc.fw_host,
                    "reload_command": sc.reload_command,
                    "delay_before_s": sc.reload_at_s,
                    "scenario_id": sc.id,
                },
            ),
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        # Expect: [server_result, client_result, trigger_result]
        client_r = next(
            (r for r in results if r.get("tool") == "iperf3" and r.get("role") != "server"),
            {},
        )
        trigger_r = next(
            (r for r in results if r.get("tool") == "fw_reload"),
            {},
        )

        retrans = int(client_r.get("retransmits", 0))
        stream_ok = bool(client_r.get("ok", False))
        reload_ok = bool(trigger_r.get("ok", False))
        ok = stream_ok and reload_ok and retrans <= sc.max_retrans_during_reload

        return ScenarioResult(
            scenario_id=sc.id,
            kind="reload_atomicity",
            ok=ok,
            duration_s=client_r.get("duration_s", 0.0),
            raw={
                "retransmits_observed": retrans,
                "max_retrans_allowed": sc.max_retrans_during_reload,
                "stream_survived": stream_ok,
                "reload_triggered_ok": reload_ok,
                "reload_at_s": sc.reload_at_s,
            },
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# LongFlowSurvivalRunner
# ---------------------------------------------------------------------------


class LongFlowSurvivalRunner(Scenario):
    """Long-flow survivability drill. Emits three commands:

    1. set_fw_sysctl — lower nf_conntrack_tcp_timeout_established temporarily
    2. run_iperf3_server (duration = scenario.duration_s + 20 s grace)
    3. run_iperf3_client (duration = scenario.duration_s, delay_before_s=2)

    No restore step — operator reverts the sysctl after the run or reboots
    the FW; documented in the scenario's raw output.
    """

    def __init__(self, scenario: LongFlowSurvivalScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        sink_ep = cfg.endpoint_by_name(sc.sink)
        src_ip = src_ep.ipv4.split("/")[0] if src_ep.ipv4 else ""
        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else ""

        return [
            AgentCommand(
                endpoint_name=sc.source,  # any endpoint can drive the SSH call
                kind="set_fw_sysctl",
                spec={
                    "fw_host": sc.fw_host,
                    "sysctl_key": sc.sysctl_key,
                    "sysctl_value": sc.sysctl_value,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.sink,
                kind="run_iperf3_server",
                spec={
                    "bind": sink_ip,
                    "port": 5201,
                    "duration_s": sc.duration_s + 20,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_iperf3_client",
                spec={
                    "bind": src_ip,
                    "server_ip": sink_ip,
                    "port": 5201,
                    "duration_s": sc.duration_s,
                    "parallel": 1,
                    "proto": "tcp",
                    "delay_before_s": 2,   # a beat after the sysctl lands
                    "scenario_id": sc.id,
                },
            ),
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        client_r = next(
            (r for r in results if r.get("tool") == "iperf3" and r.get("role") != "server"),
            {},
        )
        sysctl_r = next(
            (r for r in results if r.get("tool") == "fw_sysctl"),
            {},
        )

        observed_duration = float(client_r.get("duration_s", 0.0))
        # iperf3 reports "ok=True" if the stream completed without fatal error.
        # If the flow died at the conntrack timeout, duration_s will be
        # noticeably shorter than the configured duration_s.
        flow_survived = observed_duration >= (sc.duration_s * 0.95)  # 5% tolerance

        if sc.expect_flow_dies:
            # Flow SHOULD have died → pass iff it did not survive.
            ok = sysctl_r.get("ok", False) and not flow_survived
        else:
            # Flow SHOULD have survived the full duration.
            ok = sysctl_r.get("ok", False) and flow_survived

        return ScenarioResult(
            scenario_id=sc.id,
            kind="long_flow_survival",
            ok=ok,
            duration_s=observed_duration,
            raw={
                "expected_flow_dies": sc.expect_flow_dies,
                "observed_flow_survived": flow_survived,
                "observed_duration_s": observed_duration,
                "configured_duration_s": sc.duration_s,
                "sysctl_applied": sysctl_r.get("ok", False),
                "sysctl_key": sc.sysctl_key,
                "sysctl_value": sc.sysctl_value,
                "note": (
                    "Operator should revert the sysctl after the run or reboot "
                    "the FW; this scenario does not restore it automatically."
                ),
            },
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# HaFailoverDrillRunner
# ---------------------------------------------------------------------------


class HaFailoverDrillRunner(Scenario):
    """HA VRRP failover drill.  Emits five commands in order (plus an optional sixth):

    1. run_iperf3_server on sink (duration = scenario.duration_s + 20 s)
    2. run_iperf3_client on source (duration = duration_s, delay_before_s=1)
    3. stop_fw_service on primary_fw_host (delay_before_s = stop_at_s)
    4. start_fw_service on primary_fw_host (delay_before_s = restart_at_s)
    5. query_conntrack_count on secondary_fw_host (read-only, for drift report)
    6. poll_vrrp_state on source (only when vrrp_snmp_source is set)

    This is strictly ephemeral: no disk writes on the FWs, no persistent
    service-unit changes. ``systemctl stop/start`` only — operator or reboot
    restores default state.
    """

    def __init__(self, scenario: HaFailoverDrillScenario) -> None:
        self._sc = scenario

    def _build_vrrp_poll_cmd(self, cfg: StagelabConfig) -> AgentCommand | None:
        sc = self._sc
        if sc.vrrp_snmp_source is None:
            return None
        # vrrp_snmp_source is validated to be exactly [primary_src, secondary_src]
        primary_src_name, secondary_src_name = sc.vrrp_snmp_source
        source_map = {s.name: s for s in cfg.metrics.sources}
        primary_src = source_map.get(primary_src_name)
        secondary_src = source_map.get(secondary_src_name)
        if primary_src is None:
            raise RuntimeError(
                f"scenario {sc.id!r}: vrrp_snmp_source[0]={primary_src_name!r} "
                "not found in metrics.sources"
            )
        if secondary_src is None:
            raise RuntimeError(
                f"scenario {sc.id!r}: vrrp_snmp_source[1]={secondary_src_name!r} "
                "not found in metrics.sources"
            )
        return AgentCommand(
            endpoint_name=sc.source,
            kind="poll_vrrp_state",
            spec={
                "snmp_host_primary": getattr(primary_src, "host", ""),
                "snmp_host_secondary": getattr(secondary_src, "host", ""),
                "community": getattr(primary_src, "community", "public"),
                "port": getattr(primary_src, "port", 161),
                "duration_s": sc.duration_s,
                "poll_interval_ms": sc.vrrp_poll_interval_ms,
                "instance_name": sc.vrrp_instance_name,
                "scenario_id": sc.id,
            },
        )

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        sink_ep = cfg.endpoint_by_name(sc.sink)
        src_ip = src_ep.ipv4.split("/")[0] if src_ep.ipv4 else ""
        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else ""

        cmds = [
            AgentCommand(
                endpoint_name=sc.sink,
                kind="run_iperf3_server",
                spec={
                    "bind": sink_ip,
                    "port": 5201,
                    "duration_s": sc.duration_s + 20,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.source,
                kind="run_iperf3_client",
                spec={
                    "bind": src_ip,
                    "server_ip": sink_ip,
                    "port": 5201,
                    "duration_s": sc.duration_s,
                    "parallel": 1,
                    "proto": "tcp",
                    "delay_before_s": 1,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.source,
                kind="stop_fw_service",
                spec={
                    "fw_host": sc.primary_fw_host,
                    "service_name": sc.service_name,
                    "delay_before_s": sc.stop_at_s,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.source,
                kind="start_fw_service",
                spec={
                    "fw_host": sc.primary_fw_host,
                    "service_name": sc.service_name,
                    "delay_before_s": sc.restart_at_s,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.source,
                kind="query_conntrack_count",
                spec={
                    "fw_host": sc.secondary_fw_host,
                    "delay_before_s": sc.duration_s + 2,  # after the run
                    "scenario_id": sc.id,
                },
            ),
        ]
        vrrp_cmd = self._build_vrrp_poll_cmd(cfg)
        if vrrp_cmd is not None:
            cmds.append(vrrp_cmd)
        return cmds

    @staticmethod
    def _compute_vrrp_downtime(
        transitions: list[tuple[float, str, int]],
    ) -> float | None:
        """Compute downtime from a VRRP state transition log.

        Returns seconds between primary leaving MASTER state and secondary
        reaching MASTER state, or None if data is insufficient.
        State encoding: 0=init 1=backup 2=master 3=fault.
        """
        # Find last timestamp where primary was 2 (MASTER) before it left.
        primary_left_ts: float | None = None
        secondary_became_master_ts: float | None = None

        # Walk transitions in time order to find the handoff sequence.
        primary_state: int | None = None
        secondary_state: int | None = None

        for ts, host, state in sorted(transitions, key=lambda x: x[0]):
            if host == "primary":
                if primary_state == 2 and state != 2:
                    primary_left_ts = ts
                primary_state = state
            elif host == "secondary":
                if secondary_state != 2 and state == 2:
                    secondary_became_master_ts = ts
                secondary_state = state

        if primary_left_ts is None or secondary_became_master_ts is None:
            return None
        if secondary_became_master_ts < primary_left_ts:
            # Secondary was already master before primary left — unclear topology;
            # return 0 rather than negative value.
            return 0.0
        return secondary_became_master_ts - primary_left_ts

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc
        client_r = next(
            (r for r in results if r.get("tool") == "iperf3" and r.get("role") != "server"),
            {},
        )
        stop_r = next(
            (r for r in results if r.get("tool") == "fw_service" and r.get("action") == "stop"),
            {},
        )
        start_r = next(
            (r for r in results if r.get("tool") == "fw_service" and r.get("action") == "start"),
            {},
        )
        conntrack_r = next(
            (r for r in results if r.get("tool") == "conntrack_count"),
            {},
        )
        vrrp_r = next(
            (r for r in results if r.get("tool") == "poll_vrrp_state"),
            None,
        )

        retrans = int(client_r.get("retransmits", 0))
        stream_survived = bool(client_r.get("ok", False))
        stop_ok = bool(stop_r.get("ok", False))
        start_ok = bool(start_r.get("ok", False))

        # Downtime: prefer VRRP-SNMP transitions when available; fall back to
        # retransmit heuristic. VRRP failover typically bursts ~50-200 retrans
        # in the few seconds around the switch; anything much higher = problem.
        downtime_source: str
        downtime_s: float | None

        if vrrp_r is not None:
            transitions = [
                (float(t[0]), str(t[1]), int(t[2]))
                for t in (vrrp_r.get("transitions") or [])
            ]
            vrrp_dt = self._compute_vrrp_downtime(transitions)
            if vrrp_dt is not None:
                downtime_s = vrrp_dt
                downtime_source = "vrrp_snmp"
            else:
                # VRRP data present but insufficient — fall back.
                downtime_s = None
                downtime_source = "retrans_heuristic"
        else:
            downtime_s = None
            downtime_source = "retrans_heuristic"

        failover_plausible = retrans > 0 and retrans < 2000  # non-zero but not stormed
        ok = stream_survived and stop_ok and start_ok and failover_plausible

        raw: dict = {
            "primary_fw": sc.primary_fw_host,
            "secondary_fw": sc.secondary_fw_host,
            "service_stopped": stop_ok,
            "service_started": start_ok,
            "retransmits_observed": retrans,
            "stream_survived": stream_survived,
            "secondary_conntrack_count": conntrack_r.get("count", -1),
            "stop_at_s": sc.stop_at_s,
            "restart_at_s": sc.restart_at_s,
            "downtime_source": downtime_source,
        }
        if downtime_s is not None:
            raw["downtime_s"] = downtime_s
        return ScenarioResult(
            scenario_id=sc.id,
            kind="ha_failover_drill",
            ok=ok,
            duration_s=client_r.get("duration_s", 0.0),
            raw=raw,
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# ConntrackOverflowRunner
# ---------------------------------------------------------------------------


class ConntrackOverflowRunner(Scenario):
    """Fills the conntrack table to nf_conntrack_max and verifies drop behaviour.

    Emits three AgentCommands:
    1. conntrack_overflow_fill  — burst new connections from source to exhaust table
    2. conntrack_overflow_probe — small SYN burst after fill; probes should be dropped
    3. conntrack_overflow_inspect — SSH to fw_host to read /proc counters + dmesg
    """

    def __init__(self, scenario: ConntrackOverflowScenario) -> None:
        self._sc = scenario

    def plan(self, cfg: StagelabConfig) -> list[AgentCommand]:
        sc = self._sc
        src_ep = cfg.endpoint_by_name(sc.source)
        sink_ep = cfg.endpoint_by_name(sc.sink)
        src_ip = src_ep.ipv4.split("/")[0] if src_ep.ipv4 else "0.0.0.0"
        sink_ip = sink_ep.ipv4.split("/")[0] if sink_ep.ipv4 else "0.0.0.0"

        return [
            AgentCommand(
                endpoint_name=sc.source,
                kind="conntrack_overflow_fill",
                spec={
                    "src_ip": src_ip,
                    "sink_ip": sink_ip,
                    "duration_s": sc.duration_s,
                    "rate_new_per_s": sc.rate_new_per_s,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.source,
                kind="conntrack_overflow_probe",
                spec={
                    "src_ip": src_ip,
                    "sink_ip": sink_ip,
                    "probe_count": 10,
                    "scenario_id": sc.id,
                },
            ),
            AgentCommand(
                endpoint_name=sc.source,
                kind="conntrack_overflow_inspect",
                spec={
                    "fw_host": sc.fw_host,
                    "scenario_id": sc.id,
                },
            ),
        ]

    def summarize(self, results: list[dict]) -> ScenarioResult:
        sc = self._sc

        fill_r = next((r for r in results if r.get("tool") == "conntrack_overflow_fill"), {})
        probe_r = next((r for r in results if r.get("tool") == "conntrack_overflow_probe"), {})
        inspect_r = next((r for r in results if r.get("tool") == "conntrack_overflow_inspect"), {})

        ct_count = int(inspect_r.get("count", 0))
        ct_max = int(inspect_r.get("max", 1))
        dmesg_hits = int(inspect_r.get("dmesg_hits", 0))
        probe_accepted = int(probe_r.get("accepted_count", 0))

        observed_fill_pct = (100 * ct_count // ct_max) if ct_max > 0 else 0

        # Accept acceptance_criteria overrides if provided.
        ac = sc.acceptance_criteria
        fill_pct_min = int(ac.get("expect_table_fill_pct_min", sc.expect_table_fill_pct_min))
        check_no_new = bool(ac.get("expect_no_new_conntracks_when_full",
                                   sc.expect_no_new_conntracks_when_full))

        criteria_results: dict[str, bool] = {
            "table_fill_reached": observed_fill_pct >= fill_pct_min,
            "drops_reported": dmesg_hits > 0,
        }
        if check_no_new:
            criteria_results["probe_after_fill_blocked"] = probe_accepted == 0

        ok = all(criteria_results.values())

        return ScenarioResult(
            scenario_id=sc.id,
            kind="conntrack_overflow",
            ok=ok,
            duration_s=float(fill_r.get("duration_s", sc.duration_s)),
            raw={
                "fill_pct": observed_fill_pct,
                "count": ct_count,
                "max": ct_max,
                "dmesg_hits": dmesg_hits,
                "probe_accepted": probe_accepted,
                "probe_dropped": int(probe_r.get("dropped_count", 0)),
                "criteria_results": criteria_results,
            },
            test_id=getattr(self._sc, "test_id", None),
            standard_refs=list(getattr(self._sc, "standard_refs", []) or []),
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_ScenarioCfg = Union[
    ThroughputScenario,
    ConnStormScenario,
    ConntrackOverflowScenario,
    RuleScanScenario,
    TuningSweepScenario,
    ThroughputDpdkScenario,
    ConnStormAstfScenario,
    SynFloodDosScenario,
    DnsDosScenario,
    HalfOpenDosScenario,
    RuleCoverageMatrixScenario,
    StatefulHelperFtpScenario,
    EvasionProbesScenario,
    ReloadAtomicityScenario,
    LongFlowSurvivalScenario,
    HaFailoverDrillScenario,
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
    if scenario.kind == "dos_syn_flood":
        return SynFloodDosRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "dos_dns_query":
        return DnsDosRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "dos_half_open":
        return HalfOpenDosRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "conntrack_overflow":
        return ConntrackOverflowRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "rule_coverage_matrix":
        return RuleCoverageMatrixRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "stateful_helper_ftp":
        return StatefulHelperFtpRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "evasion_probes":
        return EvasionProbesRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "reload_atomicity":
        return ReloadAtomicityRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "long_flow_survival":
        return LongFlowSurvivalRunner(scenario)  # type: ignore[arg-type]
    if scenario.kind == "ha_failover_drill":
        return HaFailoverDrillRunner(scenario)  # type: ignore[arg-type]
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
    "SynFloodDosRunner",
    "DnsDosRunner",
    "HalfOpenDosRunner",
    "ConntrackOverflowRunner",
    "RuleCoverageMatrixRunner",
    "StatefulHelperFtpRunner",
    "EvasionProbesRunner",
    "ReloadAtomicityRunner",
    "LongFlowSurvivalRunner",
    "HaFailoverDrillRunner",
    "_parse_port_range",
    "_qnames_for_pattern",
    "build_runner",
]
