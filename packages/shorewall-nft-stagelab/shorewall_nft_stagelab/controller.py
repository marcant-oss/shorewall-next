"""asyncio orchestrator: agent-pool management, scenario dispatch, result aggregation."""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from asyncio.subprocess import PIPE
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .advisor import AdvisorInput, analyze
from .config import Host, StagelabConfig
from .ipc import (
    AckMessage,
    ConnectionClosedError,
    ErrorMessage,
    JsonLineChannel,
    PingMessage,
    RunScenarioMessage,
    ShutdownMessage,
    new_id,
)
from .metrics import MetricRow
from .metrics_ingest import MetricSource, build_source, scrape_all
from .report import RunReport, ScenarioResult

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PowerDNS extend-MIB aggregation helper
# ---------------------------------------------------------------------------
#
# SNMPScraper emits pdns rows with:
#   source = "<snmp-source-name>:pdns"
#   key    = "pdns_extend_output.<len>.<byte1>.<byte2>..."
#
# The key suffix encodes the extend-name as OID bytes (len + ASCII codepoints).
# We decode the suffix back to the ASCII label so we can match
# "pdns-all-queries", "pdns-cache-hits", "pdns-answers-0-1" by string
# containment without embedding raw byte sequences in caller code.


def _decode_oid_name_suffix(suffix: str) -> str:
    """Decode an OID name-encoding suffix "<len>.<b1>.<b2>..." → ASCII string.

    Returns an empty string if the suffix is malformed or non-ASCII.
    """
    if not suffix:
        return ""
    try:
        parts = suffix.split(".")
        length = int(parts[0])
        if len(parts) != length + 1:
            return ""
        return "".join(chr(int(b)) for b in parts[1:])
    except (ValueError, IndexError):
        return ""


def _aggregate_pdns_metrics(rows: list["MetricRow"]) -> dict[str, float]:
    """Extract pdns QPS / cache-hit-ratio / latency-approx from SNMP pdns rows.

    Looks for MetricRows whose source ends with ":pdns" and whose key contains
    the extend-name string decoded from the OID suffix.  Returns a dict with
    keys:
      "pdns_qps"              — (last - first) all-queries delta / time window
      "pdns_cache_hit_ratio"  — cache-hits delta / all-queries delta (clamped 0–1)
      "pdns_latency_approx"   — 1.0 - cache_hit_ratio  (miss-rate proxy;
                                 higher = more upstream lookups = more latency)

    All values default to 0.0 when no pdns rows are present or when the
    necessary counters are missing.
    """
    _PREFIX = "pdns_extend_output."

    # Collect (ts_unix, extend_name, value) triples from pdns rows.
    observations: list[tuple[float, str, float]] = []
    for row in rows:
        if not row.source.endswith(":pdns"):
            continue
        key = row.key
        if not key.startswith(_PREFIX):
            continue
        suffix = key[len(_PREFIX):]
        extend_name = _decode_oid_name_suffix(suffix)
        if not extend_name:
            continue
        observations.append((row.ts_unix, extend_name, row.value))

    if not observations:
        return {"pdns_qps": 0.0, "pdns_cache_hit_ratio": 0.0, "pdns_latency_approx": 0.0}

    # Group by extend_name → sorted list of (ts, value).
    by_name: dict[str, list[tuple[float, float]]] = {}
    for ts, name, val in observations:
        by_name.setdefault(name, []).append((ts, val))
    for name in by_name:
        by_name[name].sort()

    def _delta(name: str) -> float:
        pts = by_name.get(name, [])
        if len(pts) < 2:
            return 0.0
        return max(0.0, pts[-1][1] - pts[0][1])

    def _window_s(name: str) -> float:
        pts = by_name.get(name, [])
        if len(pts) < 2:
            return 1.0
        return max(1.0, pts[-1][0] - pts[0][0])

    all_queries_delta = _delta("pdns-all-queries")
    cache_hits_delta = _delta("pdns-cache-hits")
    window_s = _window_s("pdns-all-queries")

    pdns_qps = all_queries_delta / window_s

    if all_queries_delta > 0:
        pdns_cache_hit_ratio = min(1.0, max(0.0, cache_hits_delta / all_queries_delta))
    else:
        pdns_cache_hit_ratio = 0.0

    # pdns_latency_approx: miss-rate proxy (1.0 = all cache misses = max latency).
    # This is a pragmatic stand-in until pdns Stats-API latency metrics are wired.
    pdns_latency_approx = 1.0 - pdns_cache_hit_ratio

    return {
        "pdns_qps": pdns_qps,
        "pdns_cache_hit_ratio": pdns_cache_hit_ratio,
        "pdns_latency_approx": pdns_latency_approx,
    }


# ---------------------------------------------------------------------------
# DoS window-delta helper
# ---------------------------------------------------------------------------


def _window_delta(
    rows: "list[MetricRow]",
    start_ts: float,
    end_ts: float,
    metric_key: str,
) -> "list[MetricRow]":
    """Return MetricRows whose ts_unix falls in [start_ts, end_ts] for the given key.

    NOTE: If start_ts >= end_ts the window is empty and an empty list is returned.
    Overlapping baseline/dos windows are not prevented here — callers should
    ensure the windows are disjoint by construction.
    """
    if start_ts >= end_ts:
        return []
    return [r for r in rows if r.key == metric_key and start_ts <= r.ts_unix <= end_ts]


def _compute_conntrack_window_delta(
    rows: "list[MetricRow]",
    scenario_start: float,
    baseline_window_s: float,
    dos_window_s: float,
) -> "dict[str, object]":
    """Compute conntrack_count increase ratio from two sampling windows.

    Returns a dict with:
      - conntrack_count_increase_ratio: float (dos_max / baseline_min; inf when baseline_min==0)
      - conntrack_baseline_rows: int (sample count in baseline window)
      - conntrack_dos_rows: int (sample count in DoS window)
    """
    baseline_end = scenario_start
    baseline_start = scenario_start - baseline_window_s
    dos_start = scenario_start
    dos_end = scenario_start + dos_window_s

    baseline = _window_delta(rows, baseline_start, baseline_end, "node_conntrack_count")
    dos = _window_delta(rows, dos_start, dos_end, "node_conntrack_count")

    result: dict[str, object] = {
        "conntrack_baseline_rows": len(baseline),
        "conntrack_dos_rows": len(dos),
    }

    if not baseline or not dos:
        result["conntrack_count_increase_ratio"] = float("inf") if not baseline else 0.0
        return result

    baseline_min = min(r.value for r in baseline)
    dos_max = max(r.value for r in dos)

    if baseline_min == 0:
        # Baseline is zero: ratio is undefined → use inf to signal "unbounded increase"
        result["conntrack_count_increase_ratio"] = float("inf")
    else:
        result["conntrack_count_increase_ratio"] = dos_max / baseline_min

    return result


def _compute_syn_pass_ratio_delta(
    baseline_pass_ratio: float,
    dos_pass_ratio: float,
) -> float:
    """Return delta = dos_pass_ratio - baseline_pass_ratio."""
    return dos_pass_ratio - baseline_pass_ratio


# ---------------------------------------------------------------------------
# AgentConnection
# ---------------------------------------------------------------------------


@dataclass
class AgentConnection:
    host_name: str
    process: asyncio.subprocess.Process
    channel: JsonLineChannel


# ---------------------------------------------------------------------------
# Transport factories
# ---------------------------------------------------------------------------


async def spawn_local(host: Host) -> asyncio.subprocess.Process:
    """Spawn the agent as a local subprocess (no SSH).

    Used in tests and when host.address starts with "local:".
    """
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "shorewall_nft_stagelab.agent",
        "--host-name",
        host.name,
        stdin=PIPE,
        stdout=PIPE,
        stderr=None,
    )


async def spawn_ssh(host: Host) -> asyncio.subprocess.Process:
    """Spawn the agent via SSH on the remote host.

    Plain SSH invocation — no ControlMaster plumbing (MVP).
    """
    return await asyncio.create_subprocess_exec(
        "ssh",
        host.address,
        f"{host.work_dir}/.venv/bin/python",
        "-m",
        "shorewall_nft_stagelab.agent",
        "--host-name",
        host.name,
        stdin=PIPE,
        stdout=PIPE,
        stderr=None,
    )


async def _auto_factory(host: Host) -> asyncio.subprocess.Process:
    """Per-host dispatch: hosts with address starting with "local:" run via
    spawn_local (no SSH); all others go through spawn_ssh.

    This is the default factory wired into StagelabController when the
    caller does not pass an explicit transport_factory.
    """
    if host.address.startswith("local:"):
        return await spawn_local(host)
    return await spawn_ssh(host)


# ---------------------------------------------------------------------------
# StagelabController
# ---------------------------------------------------------------------------


class StagelabController:
    """Orchestrates a stagelab run: spawn one agent per host, dispatch
    scenario AgentCommands, collect AgentCommand results, build RunReport.

    Transport factory: a function ``(host: Host) -> asyncio.subprocess.Process``.
    Two built-in factories:
      - ``spawn_local(host)`` — spawns ``python -m shorewall_nft_stagelab.agent
        --host-name <name>`` as a local subprocess (no SSH). Used in tests
        and when ``host.address`` starts with "local:".
      - ``spawn_ssh(host)`` — spawns ``ssh <host.address> <workdir>/.venv/bin/python
        -m shorewall_nft_stagelab.agent --host-name <name>``. Used in production.
    """

    def __init__(
        self,
        config: StagelabConfig,
        transport_factory: Callable | None = None,
        config_path: str = "<in-memory>",
    ) -> None:
        self._config = config
        self._config_path = config_path
        self._factory = transport_factory if transport_factory is not None else _auto_factory
        self._connections: dict[str, AgentConnection] = {}
        self._metric_rows: list[MetricRow] = []
        self._scrape_task: asyncio.Task | None = None
        self._scrape_sources: list[MetricSource] = []

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Start agents for every host. Send PING to each to confirm alive.

        Raises RuntimeError if any agent fails to ACK within 5 s.
        """
        for host in self._config.hosts:
            log.debug("spawning agent for host %r", host.name)
            proc = await self._factory(host)

            # proc.stdin is asyncio.StreamWriter; proc.stdout is asyncio.StreamReader.
            # Pass them directly to JsonLineChannel.
            assert proc.stdin is not None
            assert proc.stdout is not None

            channel = JsonLineChannel(proc.stdout, proc.stdin)
            conn = AgentConnection(
                host_name=host.name,
                process=proc,
                channel=channel,
            )
            self._connections[host.name] = conn

            # Confirm alive via PING
            ping = PingMessage(id=new_id())
            await channel.send(ping)
            try:
                response = await asyncio.wait_for(channel.recv(), timeout=5.0)
            except asyncio.TimeoutError as exc:
                raise RuntimeError(
                    f"agent for host {host.name!r} did not ACK PING within 5 s"
                ) from exc
            except ConnectionClosedError as exc:
                raise RuntimeError(
                    f"agent for host {host.name!r} closed connection before PING ACK"
                ) from exc
            if not isinstance(response, AckMessage):
                raise RuntimeError(
                    f"agent for host {host.name!r} responded to PING with "
                    f"{response!r} instead of ACK"
                )
            log.debug("agent %r alive (ping ACK received)", host.name)

    async def setup_endpoints(self) -> None:
        """Send SETUP_ENDPOINT for every configured endpoint to its host.

        Must be called after connect() and before run_scenarios(). The agent
        creates the netns and topology (native NIC-in-netns or probe bridge
        + TAP) based on the endpoint spec.
        """
        from .ipc import SetupEndpointMessage

        for ep in self._config.endpoints:
            conn = self._connections.get(ep.host)
            if conn is None:
                raise RuntimeError(
                    f"endpoint {ep.name!r}: host {ep.host!r} has no agent connection"
                )
            spec = ep.model_dump()
            msg = SetupEndpointMessage(id=new_id(), endpoint_spec=spec)
            await conn.channel.send(msg)
            response = await asyncio.wait_for(conn.channel.recv(), timeout=30.0)
            if not isinstance(response, AckMessage):
                raise RuntimeError(
                    f"endpoint {ep.name!r}: agent returned "
                    f"{type(response).__name__} instead of ACK "
                    f"(error: {getattr(response, 'message', '?')!r})"
                )
            log.debug("endpoint %r set up on host %r", ep.name, ep.host)

    async def teardown_endpoints(self) -> None:
        """Send TEARDOWN_ENDPOINT for every endpoint before SHUTDOWN. Best-effort
        — log and continue on individual failures so cleanup proceeds."""
        from .ipc import TeardownEndpointMessage

        for ep in self._config.endpoints:
            conn = self._connections.get(ep.host)
            if conn is None:
                continue
            try:
                msg = TeardownEndpointMessage(id=new_id(), endpoint_name=ep.name)
                await conn.channel.send(msg)
                await asyncio.wait_for(conn.channel.recv(), timeout=10.0)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "teardown of endpoint %r on host %r failed: %s",
                    ep.name, ep.host, exc,
                )

    async def start_scraping(self) -> None:
        """Build MetricSource objects and start a background polling task.
        No-op when config.metrics.sources is empty."""
        specs = self._config.metrics.sources
        if not specs:
            return
        self._scrape_sources = [build_source(s) for s in specs]
        interval = self._config.metrics.poll_interval_s
        log.info("scraping %d source(s) every %ds", len(self._scrape_sources), interval)

        async def _poll_loop() -> None:
            try:
                while True:
                    rows = await scrape_all(self._scrape_sources, time.time(), on_error="log")
                    self._metric_rows.extend(rows)
                    await asyncio.sleep(interval)
            except asyncio.CancelledError:
                pass

        self._scrape_task = asyncio.create_task(_poll_loop())

    async def stop_scraping(self) -> None:
        """Cancel the background polling task. Idempotent."""
        if self._scrape_task is None:
            return
        self._scrape_task.cancel()
        with suppress(asyncio.CancelledError):
            await self._scrape_task
        self._scrape_task = None
        log.info("scraping stopped; collected %d metric rows", len(self._metric_rows))

    async def run_scenarios(self) -> RunReport:
        """For each scenario: build_runner().plan(cfg) -> AgentCommands, group
        them by target host, and dispatch the per-host groups concurrently so
        that e.g. an iperf3 server (blocking in accept()) on the sink can
        coexist with the client on the source. Within a single host group
        commands remain sequential so apply_tuning lands before the iperf3
        run that depends on it. Results are re-merged into the original
        global order before summarize()."""
        from .scenarios import build_runner

        # Build endpoint → host lookup table
        ep_to_host: dict[str, str] = {
            ep.name: ep.host for ep in self._config.endpoints
        }

        scenario_results: list[ScenarioResult] = []
        run_id = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        async def _run_one(idx: int, cmd) -> tuple[int, dict]:
            host_name = ep_to_host.get(cmd.endpoint_name)
            if host_name is None:
                return idx, {"ok": False, "error": "endpoint not found"}
            conn = self._connections.get(host_name)
            if conn is None:
                return idx, {"ok": False, "error": "host not connected"}

            msg = RunScenarioMessage(
                id=new_id(),
                scenario_spec={
                    "endpoint_name": cmd.endpoint_name,
                    "kind": cmd.kind,
                    "spec": cmd.spec,
                },
            )
            log.debug("→ host %r: kind=%r", host_name, cmd.kind)
            # For iperf3 server the agent timeout = spec.duration_s + 30 s.
            # Add another 30 s safety margin so the controller does not give up
            # before the agent finishes cleaning up the subprocess.
            if cmd.kind == "run_iperf3_server":
                _cmd_timeout = float(cmd.spec.get("duration_s", 60)) + 60.0
            elif cmd.kind in ("run_iperf3_client", "run_tcpkali"):
                _cmd_timeout = float(cmd.spec.get("duration_s", 60)) + 30.0
            else:
                _cmd_timeout = 120.0
            try:
                await conn.channel.send(msg)
                response = await asyncio.wait_for(conn.channel.recv(), timeout=_cmd_timeout)
            except asyncio.TimeoutError:
                log.error("host %r timed out on RUN_SCENARIO kind=%r", host_name, cmd.kind)
                return idx, {"ok": False, "error": "timeout"}
            except ConnectionClosedError:
                log.error("host %r closed connection during RUN_SCENARIO kind=%r", host_name, cmd.kind)
                return idx, {"ok": False, "error": "connection closed"}

            if isinstance(response, AckMessage):
                return idx, {"ok": True, **response.result}
            if isinstance(response, ErrorMessage):
                log.warning("host %r returned ERROR for RUN_SCENARIO kind=%r: %s",
                            host_name, cmd.kind, response.message)
                return idx, {"ok": False, "error": response.message}
            log.warning("host %r unexpected response type %r for RUN_SCENARIO",
                        host_name, type(response).__name__)
            return idx, {"ok": False, "error": "unexpected response"}

        async def _run_host_group(group: list[tuple[int, object]]) -> list[tuple[int, dict]]:
            out: list[tuple[int, dict]] = []
            for idx, cmd in group:
                out.append(await _run_one(idx, cmd))
            return out

        for scenario_cfg in self._config.scenarios:
            runner = build_runner(scenario_cfg)
            try:
                commands = runner.plan(self._config)
            except ValueError as exc:
                # plan() raises ValueError when a prerequisite is missing
                # (e.g. family=ipv6 but endpoint has no IPv6 address).
                # Emit a warning and skip the scenario rather than aborting
                # the entire run — other scenarios in the same config are
                # unaffected.
                log.warning(
                    "scenario %r: plan() raised ValueError — skipping: %s",
                    scenario_cfg.id,
                    exc,
                )
                print(
                    f"WARNING: scenario {scenario_cfg.id!r} skipped: {exc}",
                    file=sys.stderr,
                )
                continue
            log.debug("scenario %r: %d commands", scenario_cfg.id, len(commands))

            # Capture wall-clock start time for DoS window-delta computation.
            scenario_start_ts = time.time()

            # Group by host, preserving intra-host order via the global index.
            groups: dict[str, list[tuple[int, object]]] = {}
            for idx, cmd in enumerate(commands):
                host_name = ep_to_host.get(cmd.endpoint_name, "__unknown__")
                groups.setdefault(host_name, []).append((idx, cmd))

            group_results = await asyncio.gather(
                *(_run_host_group(g) for g in groups.values())
            )
            indexed: list[tuple[int, dict]] = [pair for grp in group_results for pair in grp]
            indexed.sort(key=lambda p: p[0])
            cmd_results: list[dict] = [r for _, r in indexed]

            scenario_result = runner.summarize(cmd_results)

            # ── Window-delta injection for DoS scenarios ──────────────────────
            # Use getattr so scenarios without these fields are unaffected.
            baseline_window_s: float | None = getattr(scenario_cfg, "baseline_window_s", None)
            dos_window_s: float | None = getattr(scenario_cfg, "dos_window_s", None)
            if baseline_window_s is not None and dos_window_s is not None:
                current_rows = list(self._metric_rows)
                ac = getattr(scenario_cfg, "acceptance_criteria", {}) or {}

                if scenario_cfg.kind == "conntrack_overflow":
                    delta_info = _compute_conntrack_window_delta(
                        current_rows,
                        scenario_start_ts,
                        baseline_window_s,
                        dos_window_s,
                    )
                    ratio = delta_info.get("conntrack_count_increase_ratio")
                    if ratio is not None and "conntrack_count_increase_ratio_max" in ac:
                        threshold = float(ac["conntrack_count_increase_ratio_max"])
                        over = (
                            ratio == float("inf") or float(ratio) > threshold  # type: ignore[arg-type]
                        )
                        extra_criteria = dict(scenario_result.criteria_results)
                        extra_criteria["conntrack_count_increase_ratio"] = ratio
                        extra_criteria["conntrack_count_increase_ratio_over_threshold"] = over
                        scenario_result = scenario_result.__class__(
                            scenario_id=scenario_result.scenario_id,
                            kind=scenario_result.kind,
                            ok=scenario_result.ok,
                            duration_s=scenario_result.duration_s,
                            raw=scenario_result.raw,
                            criteria_results=extra_criteria,
                        )
                        log.debug(
                            "scenario %r: conntrack_count_increase_ratio=%.3f "
                            "over_threshold=%s",
                            scenario_cfg.id,
                            float("inf") if ratio == float("inf") else ratio,
                            over,
                        )

                elif scenario_cfg.kind == "dos_syn_flood":
                    # dos_pass_ratio from raw; baseline_pass_ratio defaults 0.0
                    # (legitimate traffic before DoS is typically near-zero).
                    dos_pass_ratio = float(scenario_result.raw.get("passed_ratio", 0.0))
                    # Baseline pass ratio: use acceptance_criteria or default 0.0.
                    baseline_pass_ratio = float(ac.get("syn_baseline_pass_ratio", 0.0))
                    delta = _compute_syn_pass_ratio_delta(baseline_pass_ratio, dos_pass_ratio)
                    threshold_max = float(ac.get("syn_pass_ratio_delta_max", 0.05))
                    regressed = delta > threshold_max
                    if "syn_pass_ratio_delta_max" in ac:
                        extra_criteria = dict(scenario_result.criteria_results)
                        extra_criteria["syn_pass_ratio_delta"] = delta
                        extra_criteria["syn_pass_ratio_regressed"] = regressed
                        scenario_result = scenario_result.__class__(
                            scenario_id=scenario_result.scenario_id,
                            kind=scenario_result.kind,
                            ok=scenario_result.ok,
                            duration_s=scenario_result.duration_s,
                            raw=scenario_result.raw,
                            criteria_results=extra_criteria,
                        )
                        log.debug(
                            "scenario %r: syn_pass_ratio_delta=%.4f regressed=%s",
                            scenario_cfg.id,
                            delta,
                            regressed,
                        )

            scenario_results.append(scenario_result)

        # ── Build AdvisorInput from scenario results + metric rows ─────────────
        rows = tuple(self._metric_rows)
        pdns_metrics = _aggregate_pdns_metrics(list(rows))
        best_gbps, total_retrans, parallel = 0.0, 0, 1
        for sr in scenario_results:
            raw = sr.raw
            if raw.get("tool") == "iperf3":
                g = raw.get("gbps") or raw.get("throughput_gbps", 0.0)
                if isinstance(g, (int, float)) and g > best_gbps:
                    best_gbps = float(g)
                total_retrans += int(raw.get("retransmits", 0) or 0)
                parallel = int(raw.get("parallel", 1) or 1)
        ct_count = max(
            (int(r.value) for r in rows if r.key == "node_conntrack_count"), default=0
        )
        ct_max = max(
            (int(r.value) for r in rows if r.key == "node_conntrack_max"), default=0
        )
        cmap: dict[str, int] = {}
        for row in rows:
            if row.source.endswith(":counter"):
                cmap[row.key] = max(cmap.get(row.key, 0), int(row.value))
        ranking = tuple(
            sorted(cmap.items(), key=lambda kv: kv[1], reverse=True)
        )[:20]
        # DoS-scenario signals — populated when any scenario.kind starts with "dos_".
        dos_scenario_ran = any(sr.kind.startswith("dos_") for sr in scenario_results)
        dos_syn_pass_ratio = 0.0
        dns_resolve_latency_increase_ratio = 0.0
        for sr in scenario_results:
            if sr.kind == "dos_syn_flood":
                ratio = float(sr.raw.get("passed_ratio", 0.0))
                dos_syn_pass_ratio = max(dos_syn_pass_ratio, ratio)
            elif sr.kind == "dos_dns_query":
                ratio = float(sr.raw.get("latency_increase_ratio", 0.0))
                dns_resolve_latency_increase_ratio = max(dns_resolve_latency_increase_ratio, ratio)
        # pdns_qps_increase_ratio: no baseline-vs-DoS windowing exists in
        # the current single-pass aggregation, so we use pdns_latency_approx
        # (miss-rate proxy) as the ratio value.  A future DoS-window-aware
        # pass (tied to T-4 DoS scenario metadata) will compute a proper
        # before/after ratio; until then the value is meaningful only when
        # SNMP pdns rows are present and the proxy is non-trivial.
        pdns_qps_increase_ratio = pdns_metrics.get("pdns_latency_approx", 0.0) * 10.0

        recommendations = tuple(analyze(AdvisorInput(
            metric_rows=rows,
            iperf3_throughput_gbps=best_gbps,
            iperf3_parallel=parallel,
            iperf3_retransmits=total_retrans,
            conntrack_count=ct_count,
            conntrack_max=ct_max,
            nft_counter_ranking=ranking,
            dos_scenario_ran=dos_scenario_ran,
            dos_syn_pass_ratio=dos_syn_pass_ratio,
            dns_resolve_latency_increase_ratio=dns_resolve_latency_increase_ratio,
            pdns_qps_increase_ratio=pdns_qps_increase_ratio,
        )))

        return RunReport(
            run_id=run_id,
            config_path=self._config_path,
            scenarios=scenario_results,
            recommendations=recommendations,
        )

    async def close(self) -> None:
        """Send SHUTDOWN to each agent, await ACK, terminate subprocess."""
        for host_name, conn in list(self._connections.items()):
            shutdown = ShutdownMessage(id=new_id())
            try:
                await conn.channel.send(shutdown)
                try:
                    response = await asyncio.wait_for(
                        conn.channel.recv(), timeout=5.0
                    )
                    if not isinstance(response, AckMessage):
                        log.warning(
                            "agent %r did not ACK SHUTDOWN (got %r)",
                            host_name,
                            type(response).__name__,
                        )
                except (asyncio.TimeoutError, ConnectionClosedError):
                    log.warning("agent %r did not respond to SHUTDOWN", host_name)
            except Exception:  # noqa: BLE001
                log.warning("error sending SHUTDOWN to agent %r", host_name)

            try:
                conn.process.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(conn.process.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                conn.process.kill()

        self._connections.clear()


__all__ = [
    "AgentConnection",
    "StagelabController",
    "spawn_local",
    "spawn_ssh",
    "_window_delta",
    "_compute_conntrack_window_delta",
    "_compute_syn_pass_ratio_delta",
]
