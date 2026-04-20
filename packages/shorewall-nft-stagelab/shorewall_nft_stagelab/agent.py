"""Subprocess agent running on the test host: netns setup, traffic-gen lifecycle."""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
import sys
from typing import Any

from shorewall_nft_stagelab import metrics as _metrics
from shorewall_nft_stagelab import (
    topology_dpdk,
    trafgen_iperf3,
    trafgen_nmap,
    trafgen_scapy,
    trafgen_tcpkali,
    trafgen_trex,
    tuning,
)
from shorewall_nft_stagelab.ipc import (
    AckMessage,
    ErrorMessage,
    JsonLineChannel,
    Message,
    PollMetricsMessage,
    RunScenarioMessage,
    SetupEndpointMessage,
    ShutdownMessage,
    TeardownEndpointMessage,
    decode,
    new_id,
)
from shorewall_nft_stagelab.topology_bridge import (
    BridgeMemberSpec,
    ProbeBridgeHandle,
    ProbeBridgeSpec,
    setup_probe_bridge,
    teardown_probe_bridge,
)
from shorewall_nft_stagelab.topology_native import (
    NativeEndpointHandle,
    NativeEndpointSpec,
    setup_native_endpoint,
    teardown_native_endpoint,
)

# ── State type ────────────────────────────────────────────────────────────────

# state dict keys:
#   "host_name": str
#   "stubs": dict[str, int]   — name → pid (legacy from T5; kept for back-compat)
#   "endpoints": dict[str, NativeEndpointHandle | ProbeBridgeHandle]


# ── netns exec helper ─────────────────────────────────────────────────────────


def _exec_in_netns(
    netns: str,
    argv: list[str],
    *,
    check: bool = False,
    text: bool = True,
    capture_output: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
    """Prepend ``ip netns exec <netns>`` to *argv* and run subprocess."""
    full_argv = ["ip", "netns", "exec", netns] + argv
    return subprocess.run(
        full_argv,
        check=check,
        text=text,
        capture_output=capture_output,
        timeout=timeout,
    )


# ── Local metrics runner ──────────────────────────────────────────────────────


def _local_runner(argv: list[str]) -> str:
    """Run a command locally and return its stdout (agent is on the host)."""
    proc = subprocess.run(argv, check=True, text=True, capture_output=True)
    return proc.stdout


# ── Handler implementations ───────────────────────────────────────────────────


async def handle_ping(msg: Message, state: dict[str, Any]) -> dict[str, Any]:
    """Return empty ACK body."""
    return {}


_IPERF3_FIELDS = frozenset({
    "mode", "bind", "server_ip", "duration_s", "parallel",
    "proto", "udp_bandwidth_mbps", "port",
})
_TCPKALI_FIELDS = frozenset({
    "target", "bind", "connections", "connect_rate",
    "duration_s", "message_rate", "message_size_b",
})
_NMAP_FIELDS = frozenset({
    "target", "ports", "proto", "source_ip", "timing", "extra_args",
})
_PROBE_FIELDS = frozenset({
    "proto", "src_ip", "dst_ip", "src_port", "dst_port", "family",
    "flags", "payload_len", "vlan", "src_mac", "dst_mac",
})


async def handle_setup_endpoint(
    msg: SetupEndpointMessage, state: dict[str, Any]
) -> dict[str, Any]:
    """Create endpoint topology (native NIC or probe bridge) and record handle."""
    spec = msg.endpoint_spec
    name: str = spec["name"]
    mode: str = spec.get("mode", "native")

    if mode == "native":
        ep_spec = NativeEndpointSpec(
            name=name, nic=spec["nic"], vlan=int(spec["vlan"]),
            ipv4=spec["ipv4"], ipv4_gw=spec["ipv4_gw"],
            ipv6=spec.get("ipv6"), ipv6_gw=spec.get("ipv6_gw"),
        )
        h: NativeEndpointHandle = await asyncio.to_thread(setup_native_endpoint, ep_spec)
        state["endpoints"][name] = h
        return {
            "mode": "native", "netns": h.netns,
            "nsstub_pid": h.nsstub_pid, "vlan_iface": h.vlan_iface,
        }

    if mode == "probe":
        vlan = int(spec.get("vlan", 1))
        bridge = spec.get("bridge", f"br-{name}")
        tap_name = f"{name}-tap"[:15]
        members = (BridgeMemberSpec(kind="tap", name=tap_name, vlan=vlan),)
        br_spec = ProbeBridgeSpec(netns=f"NS_TEST_{name}", bridge=bridge, members=members)
        bh: ProbeBridgeHandle = await asyncio.to_thread(setup_probe_bridge, br_spec)
        state["endpoints"][name] = bh
        return {
            "mode": "probe", "netns": bh.netns,
            "nsstub_pid": bh.nsstub_pid, "bridge": bh.bridge,
            "tap_count": len(bh.tap_fds),
        }

    if mode == "dpdk":
        dpdk_spec = topology_dpdk.DpdkEndpointSpec(
            name=name,
            pci_addr=spec["pci_addr"],
            dpdk_cores=tuple(spec["dpdk_cores"]),
            hugepages_gib=int(spec["hugepages_gib"]),
        )
        handle = await asyncio.to_thread(topology_dpdk.setup_dpdk_endpoint, dpdk_spec)
        state["endpoints"][name] = handle
        return {
            "mode": "dpdk",
            "pci_addr": handle.pci_addr,
            "orig_driver": handle.orig_driver,
            "bound_at_ts": handle.bound_at_ts,
        }

    raise ValueError(f"unknown endpoint mode: {mode!r}")


async def handle_teardown_endpoint(
    msg: TeardownEndpointMessage, state: dict[str, Any]
) -> dict[str, Any]:
    """Teardown the endpoint and remove it from state."""
    name = msg.endpoint_name
    if name not in state["endpoints"]:
        raise ValueError(f"unknown endpoint: {name!r}")
    handle = state["endpoints"].pop(name)
    if isinstance(handle, NativeEndpointHandle):
        await asyncio.to_thread(teardown_native_endpoint, handle)
    elif isinstance(handle, topology_dpdk.DpdkEndpointHandle):
        await asyncio.to_thread(topology_dpdk.teardown_dpdk_endpoint, handle)
    else:
        await asyncio.to_thread(teardown_probe_bridge, handle)
    return {"ok": True}


async def handle_run_scenario(
    msg: RunScenarioMessage, state: dict[str, Any]
) -> dict[str, Any]:
    """Execute the scenario action on the agent host."""
    scenario = msg.scenario_spec
    endpoint_name: str = scenario["endpoint_name"]
    kind: str = scenario["kind"]
    spec: dict[str, Any] = scenario.get("spec", {})

    delay = spec.get("delay_before_s", 0)
    if delay:
        await asyncio.sleep(float(delay))

    if kind in ("run_iperf3_server", "run_iperf3_client"):
        netns = state["endpoints"][endpoint_name].netns
        mode = "server" if kind == "run_iperf3_server" else "client"
        i3_kwargs = {k: v for k, v in spec.items() if k in _IPERF3_FIELDS}
        i3_kwargs["mode"] = mode
        i3_spec = trafgen_iperf3.Iperf3Spec(**i3_kwargs)
        proc = await asyncio.to_thread(
            _exec_in_netns, netns, trafgen_iperf3.build_argv(i3_spec)
        )
        r = trafgen_iperf3.parse_result(proc.stdout)
        result: dict[str, Any] = {
            "tool": "iperf3", "ok": r.ok, "throughput_gbps": r.throughput_gbps,
            "retransmits": r.retransmits, "duration_s": r.duration_s,
        }
        if spec.get("_sweep_point") is not None:
            result["_sweep_point"] = spec["_sweep_point"]
        return result

    if kind == "apply_tuning":
        iface: str | None = spec.get("iface")
        rss_queues: int | None = spec.get("rss_queues")
        sysctls: dict[str, str] = spec.get("sysctls") or {}
        if rss_queues is not None and iface:
            await asyncio.to_thread(tuning.apply_rss, iface, rss_queues)
        if sysctls:
            await asyncio.to_thread(tuning.apply_sysctls, sysctls)
        result_tuning: dict[str, Any] = {
            "tool": "apply_tuning", "ok": True,
            "applied": {"iface": iface, "rss_queues": rss_queues, "sysctls": sysctls},
        }
        if spec.get("_sweep_point") is not None:
            result_tuning["_sweep_point"] = spec["_sweep_point"]
        return result_tuning

    if kind == "run_tcpkali":
        tk_spec = trafgen_tcpkali.TcpkaliSpec(
            **{k: v for k, v in spec.items() if k in _TCPKALI_FIELDS}
        )
        netns = state["endpoints"][endpoint_name].netns
        proc = await asyncio.to_thread(
            _exec_in_netns, netns, trafgen_tcpkali.build_argv(tk_spec)
        )
        r = trafgen_tcpkali.parse_stdout(proc.stdout)
        return {
            "tool": "tcpkali", "ok": r.ok,
            "connections_established": r.connections_established,
            "connections_failed": r.connections_failed,
            "traffic_bps": r.traffic_bits_per_sec,
            "duration_s": r.duration_s,
        }

    if kind == "run_nmap":
        netns = state["endpoints"][endpoint_name].netns
        nm_spec = trafgen_nmap.NmapSpec(
            **{k: v for k, v in spec.items() if k in _NMAP_FIELDS}
        )
        proc = await asyncio.to_thread(
            _exec_in_netns, netns, trafgen_nmap.build_argv(nm_spec)
        )
        r = trafgen_nmap.parse_xml(proc.stdout, nm_spec.target)
        return {
            "tool": "nmap", "ok": r.ok,
            "ports": [
                {"port": p.port, "proto": p.proto, "state": p.state, "service": p.service}
                for p in r.ports
            ],
        }

    if kind == "send_probe":
        handle = state["endpoints"][endpoint_name]
        if not isinstance(handle, ProbeBridgeHandle):
            raise TypeError(
                f"send_probe requires probe endpoint; {endpoint_name!r} is {type(handle).__name__}"
            )
        frame = trafgen_scapy.build_frame(
            trafgen_scapy.ProbeSpec(**{k: v for k, v in spec.items() if k in _PROBE_FIELDS})
        )
        if not handle.tap_fds:
            raise RuntimeError(f"endpoint {endpoint_name!r} has no TAP fds")
        nbytes = trafgen_scapy.send_tap(next(iter(handle.tap_fds.values())), frame)
        return {"tool": "scapy", "ok": True, "bytes_sent": nbytes, "probe_id": spec.get("probe_id")}

    if kind == "collect_oracle_verdict":
        return {"tool": "oracle_marker", "ok": True}

    if kind == "run_trex_stateless":
        trex_spec = trafgen_trex.TrexStatelessSpec(
            ports=tuple(spec.get("ports", (0,))),
            duration_s=int(spec.get("duration_s", 10)),
            multiplier=str(spec.get("multiplier", "10gbps")),
            pcap_files=tuple(spec.get("pcap_files", ())),
            profile_py=str(spec.get("profile_py", "")),
            trex_daemon_port=int(spec.get("trex_daemon_port", 4501)),
            trex_host=str(spec.get("trex_host", "127.0.0.1")),
        )
        result = await asyncio.to_thread(trafgen_trex.run_trex_stl, trex_spec)
        return {
            "tool": "trex-stl", "ok": result.ok,
            "throughput_gbps": result.throughput_gbps, "pps": result.pps,
            "errors": result.errors, "duration_s": result.duration_s,
            "_sweep_point": spec.get("_sweep_point"),
        }

    if kind == "run_trex_astf":
        trex_spec_astf = trafgen_trex.TrexAstfSpec(
            profile_py=str(spec["profile_py"]),
            duration_s=int(spec.get("duration_s", 30)),
            multiplier=float(spec.get("multiplier", 1.0)),
            trex_daemon_port=int(spec.get("trex_daemon_port", 4502)),
            trex_host=str(spec.get("trex_host", "127.0.0.1")),
        )
        result_astf = await asyncio.to_thread(trafgen_trex.run_trex_astf, trex_spec_astf)
        return {
            "tool": "trex-astf", "ok": result_astf.ok,
            "throughput_gbps": result_astf.throughput_gbps, "pps": result_astf.pps,
            "concurrent_sessions": result_astf.concurrent_sessions,
            "new_sessions_per_s": result_astf.new_sessions_per_s,
            "errors": result_astf.errors, "duration_s": result_astf.duration_s,
        }

    raise ValueError(f"unknown scenario kind: {kind!r}")


async def handle_poll_metrics(
    msg: PollMetricsMessage, state: dict[str, Any]
) -> dict[str, Any]:
    """Poll a local metric source and return serialised MetricRows."""
    kind = msg.kind
    source = msg.source  # used as iface name for nic_ethtool

    if kind == "nft_counters":
        rows = await asyncio.to_thread(_metrics.poll_nft_counters, _local_runner)
    elif kind == "conntrack_stats":
        rows = await asyncio.to_thread(_metrics.poll_conntrack, _local_runner)
    elif kind == "nic_ethtool":
        rows = await asyncio.to_thread(_metrics.poll_ethtool, _local_runner, source)
    elif kind == "cpu_softirq":
        rows = await asyncio.to_thread(_metrics.poll_softirq, _local_runner)
    else:
        raise ValueError(f"unknown metrics kind: {kind!r}")

    return {"rows": [
        {"source": r.source, "ts_unix": r.ts_unix, "key": r.key, "value": r.value}
        for r in rows
    ]}


# ── Dispatch table ────────────────────────────────────────────────────────────

_HANDLERS = {
    "PING": handle_ping,
    "SETUP_ENDPOINT": handle_setup_endpoint,
    "TEARDOWN_ENDPOINT": handle_teardown_endpoint,
    "RUN_SCENARIO": handle_run_scenario,
    "POLL_METRICS": handle_poll_metrics,
}


# ── Cleanup helpers ───────────────────────────────────────────────────────────


def _cleanup_stubs(state: dict[str, Any]) -> None:
    """Stop all remaining nsstub processes (legacy stubs dict)."""
    import shorewall_nft_netkit.nsstub as nsstub
    for name, pid in list(state["stubs"].items()):
        try:
            nsstub.stop_nsstub(f"NS_TEST_{name}", pid)
        except Exception:  # noqa: BLE001
            pass
    state["stubs"].clear()


def _cleanup_endpoints(state: dict[str, Any]) -> None:
    """Teardown all active endpoint handles, swallowing errors."""
    for name, handle in list(state["endpoints"].items()):
        try:
            if isinstance(handle, NativeEndpointHandle):
                teardown_native_endpoint(handle)
            else:
                teardown_probe_bridge(handle)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"agent: cleanup error for endpoint {name!r}: {exc}\n")
    state["endpoints"].clear()


# ── Async streams helper ──────────────────────────────────────────────────────


async def _make_stdio_channel() -> JsonLineChannel:
    """Attach asyncio streams to stdin/stdout and return a JsonLineChannel."""
    loop = asyncio.get_event_loop()

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    write_transport, write_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(write_transport, write_protocol, None, loop)

    return JsonLineChannel(reader, writer)


# ── Main loop ─────────────────────────────────────────────────────────────────


log = logging.getLogger(__name__)


async def run_agent(host_name: str) -> int:
    """Read JSON-line messages from stdin, dispatch, write ACK/ERROR to stdout."""
    state: dict[str, Any] = {
        "host_name": host_name,
        "stubs": {},
        "endpoints": {},
    }

    try:
        recovered = await asyncio.to_thread(topology_dpdk.recover_from_crash)
        if recovered:
            log.info("recovered %d orphaned DPDK binding(s): %s", len(recovered), recovered)
    except Exception as exc:  # noqa: BLE001 — best-effort, never fatal at startup
        log.warning("DPDK recovery failed at startup: %s", exc)

    try:
        channel = await _make_stdio_channel()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"agent: failed to attach stdio streams: {exc}\n")
        return 1

    import json

    while True:
        try:
            raw_line = await channel._reader.readline()
        except Exception:  # noqa: BLE001
            _cleanup_endpoints(state)
            _cleanup_stubs(state)
            return 0

        if not raw_line:
            _cleanup_endpoints(state)
            _cleanup_stubs(state)
            return 0

        msg_id: str | None = None
        try:
            data = json.loads(raw_line.rstrip(b"\n"))
            if not isinstance(data, dict):
                raise ValueError("message must be a JSON object")
            msg_id = data.get("id")
            msg = decode(data)
        except Exception as exc:  # noqa: BLE001
            await channel.send(ErrorMessage(
                id=new_id(), reply_to=msg_id or "unknown",
                error_type=type(exc).__name__, message=str(exc),
            ))
            continue

        if isinstance(msg, ShutdownMessage):
            _cleanup_endpoints(state)
            _cleanup_stubs(state)
            await channel.send(AckMessage(id=new_id(), reply_to=msg.id, result={}))
            return 0

        handler = _HANDLERS.get(msg.type)  # type: ignore[attr-defined]
        if handler is None:
            await channel.send(ErrorMessage(
                id=new_id(), reply_to=msg.id,  # type: ignore[attr-defined]
                error_type="ValueError",
                message=f"no handler for message type {msg.type!r}",  # type: ignore[attr-defined]
            ))
            continue

        try:
            result = await handler(msg, state)
        except Exception as exc:  # noqa: BLE001
            await channel.send(ErrorMessage(
                id=new_id(), reply_to=msg.id,  # type: ignore[attr-defined]
                error_type=type(exc).__name__, message=str(exc),
            ))
            continue

        await channel.send(AckMessage(id=new_id(), reply_to=msg.id, result=result))  # type: ignore[attr-defined]


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """CLI entry: argparse --host-name, asyncio.run(run_agent(...)), sys.exit(code)."""
    parser = argparse.ArgumentParser(description="shorewall-nft-stagelab agent")
    parser.add_argument(
        "--host-name",
        required=True,
        help="Logical name for this test host (used in log/metrics labels)",
    )
    args = parser.parse_args()
    code = asyncio.run(run_agent(args.host_name))
    sys.exit(code)


if __name__ == "__main__":
    main()
