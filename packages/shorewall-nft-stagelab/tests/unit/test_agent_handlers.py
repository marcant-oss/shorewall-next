"""Unit tests for agent handlers (no root, topology/trafgen/nsstub mocked)."""

from __future__ import annotations

import asyncio
import subprocess
from unittest.mock import patch

from shorewall_nft_stagelab.agent import (
    handle_ping,
    handle_poll_metrics,
    handle_run_scenario,
    handle_setup_endpoint,
    handle_teardown_endpoint,
)
from shorewall_nft_stagelab.ipc import (
    PingMessage,
    PollMetricsMessage,
    RunScenarioMessage,
    SetupEndpointMessage,
    TeardownEndpointMessage,
)
from shorewall_nft_stagelab.topology_bridge import ProbeBridgeHandle
from shorewall_nft_stagelab.topology_dpdk import DpdkEndpointHandle
from shorewall_nft_stagelab.topology_native import NativeEndpointHandle
from shorewall_nft_stagelab.trafgen_trex import TrexResult


def _state() -> dict:
    return {"host_name": "test-host", "stubs": {}, "endpoints": {}, "trex_daemons": {}}


# ── Existing tests (keep green) ───────────────────────────────────────────────


def test_handle_ping_returns_empty() -> None:
    """handle_ping must return an empty dict regardless of message content."""
    msg = PingMessage(id="ping-1")
    state = _state()
    result = asyncio.run(handle_ping(msg, state))
    assert result == {}


def test_setup_and_teardown_endpoint_uses_nsstub() -> None:
    """Legacy path: setup/teardown with bare name (no mode) falls through to native."""
    setup_msg = SetupEndpointMessage(
        id="setup-1",
        endpoint_spec={
            "name": "alpha", "mode": "native",
            "nic": "eth0", "vlan": 10,
            "ipv4": "10.0.0.1/24", "ipv4_gw": "10.0.0.254",
        },
    )
    teardown_msg = TeardownEndpointMessage(id="teardown-1", endpoint_name="alpha")
    state = _state()

    fake_handle = NativeEndpointHandle(
        name="alpha", netns="NS_TEST_alpha", nsstub_pid=42, vlan_iface="eth0.10"
    )
    with (
        patch(
            "shorewall_nft_stagelab.agent.setup_native_endpoint",
            return_value=fake_handle,
        ) as mock_setup,
        patch("shorewall_nft_stagelab.agent.teardown_native_endpoint") as mock_tear,
    ):
        result = asyncio.run(handle_setup_endpoint(setup_msg, state))
        assert result["netns"] == "NS_TEST_alpha"
        assert result["nsstub_pid"] == 42
        assert state["endpoints"]["alpha"] is fake_handle
        mock_setup.assert_called_once()

        result2 = asyncio.run(handle_teardown_endpoint(teardown_msg, state))
        assert result2 == {"ok": True}
        assert "alpha" not in state["endpoints"]
        mock_tear.assert_called_once_with(fake_handle)


# ── New tests (T14) ───────────────────────────────────────────────────────────


def test_setup_native_stores_handle() -> None:
    """handle_setup_endpoint(mode=native) stores NativeEndpointHandle in state."""
    spec = {
        "name": "ep1", "mode": "native",
        "nic": "enp1s0f0", "vlan": 20,
        "ipv4": "10.0.20.10/24", "ipv4_gw": "10.0.20.1",
    }
    msg = SetupEndpointMessage(id="s1", endpoint_spec=spec)
    state = _state()

    fake = NativeEndpointHandle(
        name="ep1", netns="NS_TEST_ep1", nsstub_pid=99, vlan_iface="enp1s0f0.20"
    )
    with patch(
        "shorewall_nft_stagelab.agent.setup_native_endpoint", return_value=fake
    ):
        resp = asyncio.run(handle_setup_endpoint(msg, state))

    assert state["endpoints"]["ep1"] is fake
    assert resp == {
        "mode": "native",
        "netns": "NS_TEST_ep1",
        "nsstub_pid": 99,
        "vlan_iface": "enp1s0f0.20",
    }


def test_setup_probe_stores_handle() -> None:
    """handle_setup_endpoint(mode=probe) stores ProbeBridgeHandle in state."""
    spec = {"name": "probe1", "mode": "probe", "vlan": 30, "bridge": "br-probes"}
    msg = SetupEndpointMessage(id="s2", endpoint_spec=spec)
    state = _state()

    fake = ProbeBridgeHandle(
        netns="NS_TEST_probe1", bridge="br-probes", nsstub_pid=77, tap_fds={"probe1-tap": 5}
    )
    with patch(
        "shorewall_nft_stagelab.agent.setup_probe_bridge", return_value=fake
    ):
        resp = asyncio.run(handle_setup_endpoint(msg, state))

    assert state["endpoints"]["probe1"] is fake
    assert resp["mode"] == "probe"
    assert resp["netns"] == "NS_TEST_probe1"
    assert resp["tap_count"] == 1
    assert "tap_fds" not in resp


def test_teardown_dispatches_native() -> None:
    """handle_teardown_endpoint calls teardown_native_endpoint for NativeEndpointHandle."""
    handle = NativeEndpointHandle(
        name="ep2", netns="NS_TEST_ep2", nsstub_pid=10, vlan_iface="eth0.5"
    )
    state = _state()
    state["endpoints"]["ep2"] = handle
    msg = TeardownEndpointMessage(id="t1", endpoint_name="ep2")

    with patch("shorewall_nft_stagelab.agent.teardown_native_endpoint") as mock_tear:
        resp = asyncio.run(handle_teardown_endpoint(msg, state))

    assert resp == {"ok": True}
    assert "ep2" not in state["endpoints"]
    mock_tear.assert_called_once_with(handle)


def test_teardown_dispatches_probe() -> None:
    """handle_teardown_endpoint calls teardown_probe_bridge for ProbeBridgeHandle."""
    handle = ProbeBridgeHandle(
        netns="NS_TEST_pr", bridge="br-pr", nsstub_pid=20, tap_fds={}
    )
    state = _state()
    state["endpoints"]["pr"] = handle
    msg = TeardownEndpointMessage(id="t2", endpoint_name="pr")

    with patch("shorewall_nft_stagelab.agent.teardown_probe_bridge") as mock_tear:
        resp = asyncio.run(handle_teardown_endpoint(msg, state))

    assert resp == {"ok": True}
    assert "pr" not in state["endpoints"]
    mock_tear.assert_called_once_with(handle)


def test_run_scenario_send_probe_calls_scapy() -> None:
    """send_probe scenario builds frame and writes to TAP fd."""
    tap_fd = 99
    handle = ProbeBridgeHandle(
        netns="NS_TEST_pr2", bridge="br-pr2", nsstub_pid=30,
        tap_fds={"pr2-tap": tap_fd},
    )
    state = _state()
    state["endpoints"]["pr2"] = handle

    msg = RunScenarioMessage(
        id="r1",
        scenario_spec={
            "endpoint_name": "pr2",
            "kind": "send_probe",
            "spec": {
                "proto": "tcp",
                "src_ip": "10.0.1.1",
                "dst_ip": "10.0.2.1",
                "dst_port": 80,
                "probe_id": "p-001",
            },
        },
    )
    fake_frame = b"\x00" * 60
    with (
        patch("shorewall_nft_stagelab.trafgen_scapy.build_frame", return_value=fake_frame) as mock_build,
        patch("shorewall_nft_stagelab.trafgen_scapy.send_tap", return_value=60) as mock_send,
    ):
        resp = asyncio.run(handle_run_scenario(msg, state))

    mock_build.assert_called_once()
    mock_send.assert_called_once_with(tap_fd, fake_frame)
    assert resp == {"tool": "scapy", "ok": True, "bytes_sent": 60, "probe_id": "p-001"}


def test_run_scenario_iperf3_client_calls_netns_exec() -> None:
    """iperf3 client scenario calls _exec_in_netns with the correct netns + iperf3 argv."""
    handle = NativeEndpointHandle(
        name="ep3", netns="NS_TEST_ep3", nsstub_pid=50, vlan_iface="eth0.3"
    )
    state = _state()
    state["endpoints"]["ep3"] = handle

    fake_json = (
        '{"end":{"sum_received":{"bits_per_second":1e10,"seconds":10.0},'
        '"sum_sent":{"retransmits":0}}}'
    )
    fake_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=fake_json, stderr="")

    msg = RunScenarioMessage(
        id="r2",
        scenario_spec={
            "endpoint_name": "ep3",
            "kind": "run_iperf3_client",
            "spec": {
                "mode": "client",
                "bind": "10.0.3.10",
                "server_ip": "10.0.3.1",
                "duration_s": 10,
                "parallel": 1,
            },
        },
    )
    captured_netns: list[str] = []
    captured_argv: list[list[str]] = []

    def fake_exec_in_netns(netns, argv, **kwargs):
        captured_netns.append(netns)
        captured_argv.append(list(argv))
        return fake_proc

    with patch("shorewall_nft_stagelab.agent._exec_in_netns", side_effect=fake_exec_in_netns):
        resp = asyncio.run(handle_run_scenario(msg, state))

    assert captured_argv, "_exec_in_netns was not called"
    assert captured_netns[0] == "NS_TEST_ep3"
    assert "iperf3" in captured_argv[0]
    assert resp["tool"] == "iperf3"
    assert resp["ok"] is True
    assert abs(resp["throughput_gbps"] - 10.0) < 0.01


def test_run_scenario_oracle_marker_is_noop() -> None:
    """collect_oracle_verdict returns oracle_marker ok without touching state."""
    state = _state()
    msg = RunScenarioMessage(
        id="r3",
        scenario_spec={
            "endpoint_name": "irrelevant",
            "kind": "collect_oracle_verdict",
            "spec": {},
        },
    )
    resp = asyncio.run(handle_run_scenario(msg, state))
    assert resp == {"tool": "oracle_marker", "ok": True}


def test_run_scenario_unknown_kind_raises() -> None:
    """Unknown scenario kind raises ValueError."""
    state = _state()
    msg = RunScenarioMessage(
        id="r4",
        scenario_spec={
            "endpoint_name": "x",
            "kind": "does_not_exist",
            "spec": {},
        },
    )
    try:
        asyncio.run(handle_run_scenario(msg, state))
        raise AssertionError("Expected ValueError")
    except ValueError as exc:
        assert "does_not_exist" in str(exc)


def test_run_scenario_apply_tuning_calls_tuning_module() -> None:
    """apply_tuning scenario calls tuning.apply_rss and tuning.apply_sysctls."""
    handle = NativeEndpointHandle(
        name="ep_tune", netns="NS_TEST_ep_tune", nsstub_pid=55, vlan_iface="eth0.10"
    )
    state = _state()
    state["endpoints"]["ep_tune"] = handle

    msg = RunScenarioMessage(
        id="r-tune",
        scenario_spec={
            "endpoint_name": "ep_tune",
            "kind": "apply_tuning",
            "spec": {
                "iface": "eth0",
                "rss_queues": 4,
                "sysctls": {"net.core.rmem_max": "16777216"},
            },
        },
    )

    with (
        patch("shorewall_nft_stagelab.agent.tuning.apply_rss") as mock_rss,
        patch("shorewall_nft_stagelab.agent.tuning.apply_sysctls") as mock_sysctls,
    ):
        resp = asyncio.run(handle_run_scenario(msg, state))

    mock_rss.assert_called_once_with("eth0", 4)
    mock_sysctls.assert_called_once_with({"net.core.rmem_max": "16777216"})
    assert resp["tool"] == "apply_tuning"
    assert resp["ok"] is True
    assert resp["applied"]["rss_queues"] == 4
    assert resp["applied"]["sysctls"] == {"net.core.rmem_max": "16777216"}


def test_setup_dpdk_stores_handle() -> None:
    """handle_setup_endpoint(mode=dpdk) stores DpdkEndpointHandle in state."""
    spec = {
        "name": "dpdk0", "mode": "dpdk",
        "pci_addr": "0000:01:00.0",
        "dpdk_cores": [4, 5],
        "hugepages_gib": 2,
    }
    msg = SetupEndpointMessage(id="s-dpdk", endpoint_spec=spec)
    state = _state()

    fake = DpdkEndpointHandle(
        name="dpdk0", pci_addr="0000:01:00.0",
        orig_driver="ixgbe", bound_at_ts=1234567890.0,
    )
    with patch(
        "shorewall_nft_stagelab.agent.topology_dpdk.setup_dpdk_endpoint",
        return_value=fake,
    ):
        resp = asyncio.run(handle_setup_endpoint(msg, state))

    assert state["endpoints"]["dpdk0"] is fake
    assert resp["mode"] == "dpdk"
    assert resp["pci_addr"] == "0000:01:00.0"
    assert resp["orig_driver"] == "ixgbe"
    assert "bound_at_ts" in resp


def test_run_scenario_trex_stateless_calls_trafgen_trex() -> None:
    """run_trex_stateless scenario calls trafgen_trex.run_trex_stl and returns result."""
    state = _state()
    # No endpoint needed for TRex (daemon-based, not netns-based)
    state["endpoints"]["trex0"] = NativeEndpointHandle(
        name="trex0", netns="NS_TEST_trex0", nsstub_pid=0, vlan_iface="eth0.0"
    )

    msg = RunScenarioMessage(
        id="r-trex",
        scenario_spec={
            "endpoint_name": "trex0",
            "kind": "run_trex_stateless",
            "spec": {
                "ports": [0, 1],
                "duration_s": 10,
                "multiplier": "10gbps",
            },
        },
    )
    fake_result = TrexResult(
        tool="trex-stl", ok=True, duration_s=10,
        throughput_gbps=9.5, pps=1e6,
        concurrent_sessions=0, new_sessions_per_s=0,
        errors=0, raw={},
    )
    with patch(
        "shorewall_nft_stagelab.agent.trafgen_trex.run_trex_stl",
        return_value=fake_result,
    ):
        resp = asyncio.run(handle_run_scenario(msg, state))

    assert resp["tool"] == "trex-stl"
    assert resp["ok"] is True
    assert resp["throughput_gbps"] == 9.5


def test_run_scenario_tcpkali_calls_trafgen() -> None:
    """run_tcpkali scenario calls trafgen_pyconn.run_pyconn (pyconn backend)."""
    from shorewall_nft_stagelab.trafgen_pyconn import PyConnResult

    handle = NativeEndpointHandle(
        name="ep_tk", netns="NS_TEST_ep_tk", nsstub_pid=88, vlan_iface="eth0.10"
    )
    state = _state()
    state["endpoints"]["ep_tk"] = handle

    fake_result = PyConnResult(
        ok=True, established_conns=998, failed_conns=2,
        elapsed_s=30.0, connect_rate_observed=33.27, bytes_sent=0,
    )

    msg = RunScenarioMessage(
        id="r-tk",
        scenario_spec={
            "endpoint_name": "ep_tk",
            "kind": "run_tcpkali",
            "spec": {
                "target": "10.0.1.1:5001",
                "connections": 1000,
                "connect_rate": 200,
                "duration_s": 30,
            },
        },
    )
    with patch(
        "shorewall_nft_stagelab.trafgen_pyconn.run_pyconn",
        return_value=fake_result,
    ) as mock_run:
        resp = asyncio.run(handle_run_scenario(msg, state))

    mock_run.assert_called_once()
    assert resp["tool"] == "pyconn"
    assert resp["ok"] is True
    assert resp["connections_established"] == 998
    assert resp["connections_failed"] == 2


def test_start_trex_daemon_dispatches_to_trex_module() -> None:
    """start_trex_daemon scenario calls trex_daemon.ensure_running and stores handle."""
    from pathlib import Path

    from shorewall_nft_stagelab.trex_daemon import TrexDaemonHandle

    fake_handle = TrexDaemonHandle(
        mode="stl", port=4501, pid=42,
        started_at_ts=1000.0, cfg_path=Path("/tmp/trex-stl-4501.yaml"),
    )
    state = _state()
    msg = RunScenarioMessage(
        id="r-trex-start",
        scenario_spec={
            "endpoint_name": "trex0",
            "kind": "start_trex_daemon",
            "spec": {
                "mode": "stl",
                "port": 4501,
                "pci_ports": ["0000:01:00.0", "0000:01:00.1"],
                "cores": [4, 5],
            },
        },
    )
    with patch(
        "shorewall_nft_stagelab.trex_daemon.ensure_running",
        return_value=fake_handle,
    ):
        resp = asyncio.run(handle_run_scenario(msg, state))

    assert resp["tool"] == "trex_daemon"
    assert resp["ok"] is True
    assert resp["port"] == 4501
    assert state["trex_daemons"][4501] is fake_handle


def test_stop_trex_daemon_pops_and_stops() -> None:
    """stop_trex_daemon pops handle from state and calls trex_daemon.stop."""
    from pathlib import Path

    from shorewall_nft_stagelab.trex_daemon import TrexDaemonHandle

    fake_handle = TrexDaemonHandle(
        mode="stl", port=4501, pid=42,
        started_at_ts=1000.0, cfg_path=Path("/tmp/trex-stl-4501.yaml"),
    )
    state = _state()
    state["trex_daemons"][4501] = fake_handle

    msg = RunScenarioMessage(
        id="r-trex-stop",
        scenario_spec={
            "endpoint_name": "trex0",
            "kind": "stop_trex_daemon",
            "spec": {"port": 4501},
        },
    )
    with patch("shorewall_nft_stagelab.trex_daemon.stop") as mock_stop:
        resp = asyncio.run(handle_run_scenario(msg, state))

    mock_stop.assert_called_once_with(fake_handle)
    assert resp["tool"] == "trex_daemon"
    assert resp["ok"] is True
    assert resp["port"] == 4501
    assert resp["pid"] == 42
    assert 4501 not in state["trex_daemons"]


def test_run_ftp_helper_probe_invokes_curl_in_netns() -> None:
    """run_ftp_helper_probe dispatches to _exec_in_netns with curl argv."""
    handle = NativeEndpointHandle(
        name="ftp-src", netns="NS_TEST_ftp_src", nsstub_pid=77, vlan_iface="eth0.10"
    )
    state = _state()
    state["endpoints"]["ftp-src"] = handle

    fake_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    msg = RunScenarioMessage(
        id="r-ftp",
        scenario_spec={
            "endpoint_name": "ftp-src",
            "kind": "run_ftp_helper_probe",
            "spec": {
                "sink_ip": "10.0.20.1",
                "ftp_port": 21,
                "mode": "passive",
                "user": "ftpuser",
                "password": "ftpuser",
                "test_file": "/tmp/stagelab-ftp-test.txt",
                "scenario_id": "ftp-test-1",
            },
        },
    )
    captured: list[list[str]] = []

    def fake_exec_in_netns(netns: str, argv: list[str]) -> subprocess.CompletedProcess:
        captured.append(argv)
        return fake_proc

    with patch("shorewall_nft_stagelab.agent._exec_in_netns", side_effect=fake_exec_in_netns):
        resp = asyncio.run(handle_run_scenario(msg, state))

    assert resp["tool"] == "ftp_probe"
    assert resp["ok"] is True
    assert captured, "_exec_in_netns was not called"
    argv = captured[0]
    assert argv[:2] == ["curl", "--silent"]


def test_run_scenario_iperf3_server_timeout_returns_error() -> None:
    """run_iperf3_server must return ok=False when iperf3 process times out.

    The key invariant: the handler must NOT propagate the TimeoutExpired
    exception — it must catch it, kill iperf3, and return a structured error
    so the agent message loop stays responsive (SHUTDOWN can be processed).
    """
    handle = NativeEndpointHandle(
        name="ep-srv", netns="NS_TEST_ep_srv", nsstub_pid=11, vlan_iface="eth0.10"
    )
    state = _state()
    state["endpoints"]["ep-srv"] = handle

    msg = RunScenarioMessage(
        id="r-srv-timeout",
        scenario_spec={
            "endpoint_name": "ep-srv",
            "kind": "run_iperf3_server",
            "spec": {
                "mode": "server",
                "bind": "10.0.10.1",
                "duration_s": 10,
                "port": 5201,
            },
        },
    )

    # _exec_in_netns raises TimeoutExpired (subprocess level) when the
    # iperf3 server sits in accept() past duration_s + 30 s grace.
    # On timeout the handler calls _exec_in_netns again with pkill to clean up.
    call_count = [0]
    pkill_calls: list = []

    def _raise_then_pkill(netns, argv, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            # First call — the iperf3 server itself — times out.
            raise subprocess.TimeoutExpired(cmd=["iperf3"], timeout=40)
        # Subsequent calls — pkill cleanup.
        pkill_calls.append(list(argv))
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    with patch("shorewall_nft_stagelab.agent._exec_in_netns", side_effect=_raise_then_pkill):
        resp = asyncio.run(handle_run_scenario(msg, state))

    assert resp["tool"] == "iperf3"
    assert resp["ok"] is False
    assert "timeout" in resp["error"].lower()
    assert resp["throughput_gbps"] == 0.0
    # pkill must have been invoked to clean up the wedged subprocess.
    assert pkill_calls, "pkill was not called to clean up iperf3"
    assert "iperf3" in pkill_calls[0]


def test_run_scenario_iperf3_server_timeout_uses_duration_plus_grace() -> None:
    """The server timeout is spec.duration_s + 30 s (not the raw duration alone)."""
    handle = NativeEndpointHandle(
        name="ep-grace", netns="NS_TEST_ep_grace", nsstub_pid=12, vlan_iface="eth0.10"
    )
    state = _state()
    state["endpoints"]["ep-grace"] = handle

    msg = RunScenarioMessage(
        id="r-grace",
        scenario_spec={
            "endpoint_name": "ep-grace",
            "kind": "run_iperf3_server",
            "spec": {
                "mode": "server",
                "bind": "10.0.10.2",
                "duration_s": 20,
            },
        },
    )

    captured_timeout: list = []
    call_count_grace = [0]

    def _capture_and_raise(netns, argv, *, timeout=None, **kwargs):
        call_count_grace[0] += 1
        if call_count_grace[0] == 1:
            # First call — the iperf3 server — record timeout and raise.
            captured_timeout.append(timeout)
            raise subprocess.TimeoutExpired(cmd=["iperf3"], timeout=timeout or 0)
        # Second call — pkill cleanup — succeed silently.
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    with patch("shorewall_nft_stagelab.agent._exec_in_netns", side_effect=_capture_and_raise):
        resp = asyncio.run(handle_run_scenario(msg, state))

    assert captured_timeout, "_exec_in_netns was not called"
    # Expected: 20 (duration_s) + 30 (grace) = 50 s
    assert captured_timeout[0] == 50, f"expected timeout=50, got {captured_timeout[0]}"
    assert resp["ok"] is False


def test_run_scenario_iperf3_client_no_timeout_by_default() -> None:
    """run_iperf3_client does not impose an extra process timeout (clients are self-bounded)."""
    handle = NativeEndpointHandle(
        name="ep-cli", netns="NS_TEST_ep_cli", nsstub_pid=13, vlan_iface="eth0.10"
    )
    state = _state()
    state["endpoints"]["ep-cli"] = handle

    fake_json = (
        '{"end":{"sum_received":{"bits_per_second":5e9,"seconds":10.0},'
        '"sum_sent":{"retransmits":2}}}'
    )
    fake_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=fake_json, stderr="")

    captured_timeout: list = []

    def _capture(netns, argv, *, timeout=None, **kwargs):
        captured_timeout.append(timeout)
        return fake_proc

    msg = RunScenarioMessage(
        id="r-cli-notimeout",
        scenario_spec={
            "endpoint_name": "ep-cli",
            "kind": "run_iperf3_client",
            "spec": {
                "mode": "client",
                "bind": "10.0.10.3",
                "server_ip": "10.0.10.1",
                "duration_s": 10,
                "parallel": 2,
            },
        },
    )
    with patch("shorewall_nft_stagelab.agent._exec_in_netns", side_effect=_capture):
        resp = asyncio.run(handle_run_scenario(msg, state))

    assert resp["ok"] is True
    assert captured_timeout, "_exec_in_netns was not called"
    assert captured_timeout[0] is None, (
        f"client should pass timeout=None, got {captured_timeout[0]}"
    )


def test_poll_metrics_nft_counters() -> None:
    """poll_metrics(kind=nft_counters) returns serialised rows from poll_nft_counters."""
    from shorewall_nft_stagelab.metrics import MetricRow

    fake_rows = [
        MetricRow(source="nft-counters-packets", ts_unix=1000.0, key="cnt_accept", value=42.0),
        MetricRow(source="nft-counters-bytes", ts_unix=1000.0, key="cnt_accept", value=5040.0),
    ]
    state = _state()
    msg = PollMetricsMessage(id="m1", source="fw", kind="nft_counters")

    with patch("shorewall_nft_stagelab.agent._metrics.poll_nft_counters", return_value=fake_rows):
        resp = asyncio.run(handle_poll_metrics(msg, state))

    rows = resp["rows"]
    assert len(rows) == 2
    assert rows[0]["key"] == "cnt_accept"
    assert rows[0]["value"] == 42.0
    assert rows[1]["value"] == 5040.0


# ── HTTP listener handler tests ────────────────────────────────────────────────


def test_start_http_listener_spawns_subprocess_in_netns() -> None:
    """start_http_listener spawns python3 -m http.server and returns pid + port."""
    handle = NativeEndpointHandle(
        name="sink", netns="NS_TEST_sink", nsstub_pid=20, vlan_iface="eth0.20"
    )
    state = _state()
    state["endpoints"]["sink"] = handle
    state["http_listeners"] = {}

    msg = RunScenarioMessage(
        id="r-http-start",
        scenario_spec={
            "endpoint_name": "sink",
            "kind": "start_http_listener",
            "spec": {
                "bind_ip": "10.0.20.1",
                "port": 80,
                "_http_sidecar": True,
                "scenario_id": "cs-test",
            },
        },
    )

    class FakeProc:
        pid = 12345
        def send_signal(self, sig): pass  # noqa: E704
        def wait(self, *a, **kw): pass    # noqa: E704

    fake_proc = FakeProc()

    with (
        patch("subprocess.Popen", return_value=fake_proc),
        patch("asyncio.sleep", return_value=None),
    ):
        resp = asyncio.run(handle_run_scenario(msg, state))

    assert resp["tool"] == "http_listener"
    assert resp["ok"] is True
    assert resp["pid"] == 12345
    assert resp["port"] == 80
    assert resp["_http_sidecar"] is True
    # Listener must be tracked in state
    assert ("sink", 80) in state["http_listeners"]


def test_stop_http_listener_sends_sigterm() -> None:
    """stop_http_listener sends SIGTERM to the tracked subprocess and removes from state."""
    import signal as _signal

    handle = NativeEndpointHandle(
        name="sink2", netns="NS_TEST_sink2", nsstub_pid=21, vlan_iface="eth0.20"
    )
    state = _state()
    state["endpoints"]["sink2"] = handle

    signals_sent: list[int] = []

    class FakeProc:
        pid = 9999
        def send_signal(self, sig): signals_sent.append(sig)  # noqa: E704
        def wait(self, *a, **kw): pass                        # noqa: E704

    fake_proc = FakeProc()
    state["http_listeners"] = {("sink2", 8080): fake_proc}

    msg = RunScenarioMessage(
        id="r-http-stop",
        scenario_spec={
            "endpoint_name": "sink2",
            "kind": "stop_http_listener",
            "spec": {
                "bind_ip": "10.0.20.2",
                "port": 8080,
                "_http_sidecar": True,
                "scenario_id": "cs-test",
            },
        },
    )

    resp = asyncio.run(handle_run_scenario(msg, state))

    assert resp["tool"] == "http_listener"
    assert resp["ok"] is True
    assert resp["pid"] == 9999
    assert resp["port"] == 8080
    assert resp["_http_sidecar"] is True
    assert _signal.SIGTERM in signals_sent
    # Must be removed from state after stop
    assert ("sink2", 8080) not in state["http_listeners"]


def test_stop_http_listener_missing_returns_ok_false() -> None:
    """stop_http_listener returns ok=False if no listener is registered."""
    handle = NativeEndpointHandle(
        name="sink3", netns="NS_TEST_sink3", nsstub_pid=22, vlan_iface="eth0.20"
    )
    state = _state()
    state["endpoints"]["sink3"] = handle
    state["http_listeners"] = {}

    msg = RunScenarioMessage(
        id="r-http-stop-missing",
        scenario_spec={
            "endpoint_name": "sink3",
            "kind": "stop_http_listener",
            "spec": {"port": 80, "_http_sidecar": True},
        },
    )
    resp = asyncio.run(handle_run_scenario(msg, state))
    assert resp["tool"] == "http_listener"
    assert resp["ok"] is False
    assert resp["_http_sidecar"] is True
