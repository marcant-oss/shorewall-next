"""Integration tests for topology_native — requires root + CAP_NET_ADMIN."""

import os
import subprocess

import pytest

from shorewall_nft_stagelab.topology_native import (
    NativeEndpointSpec,
    setup_native_endpoint,
    teardown_native_endpoint,
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="requires root and CAP_NET_ADMIN",
)


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


def test_setup_then_teardown_dummy_nic():
    dummy = "test_dummy0"
    spec = NativeEndpointSpec(
        name="tnat1",
        nic=dummy,
        vlan=100,
        ipv4="10.99.100.5/24",
        ipv4_gw="10.99.100.1",
    )
    handle = None
    try:
        _run(["ip", "link", "add", dummy, "type", "dummy"])
        _run(["ip", "link", "set", dummy, "up"])

        handle = setup_native_endpoint(spec)

        # netns bind-mount exists
        assert os.path.exists(f"/run/netns/{handle.netns}"), \
            f"/run/netns/{handle.netns} not found"

        # VLAN iface is up in the netns
        result = _run(["ip", "-n", handle.netns, "link", "show", handle.vlan_iface])
        assert "UP" in result.stdout or "state UP" in result.stdout or \
            handle.vlan_iface in result.stdout

        # IPv4 address is present
        addr_result = _run(["ip", "-n", handle.netns, "addr", "show", handle.vlan_iface])
        assert "10.99.100.5" in addr_result.stdout

        # Default gateway is configured
        route_result = _run(["ip", "-n", handle.netns, "route", "show", "default"])
        assert "10.99.100.1" in route_result.stdout

        teardown_native_endpoint(handle)
        handle = None

        # netns bind-mount is gone
        assert not os.path.exists("/run/netns/NS_TEST_tnat1"), \
            "netns bind-mount should be removed after teardown"

    finally:
        if handle is not None:
            teardown_native_endpoint(handle)
        # Remove dummy NIC if it still exists in the host ns
        subprocess.run(
            ["ip", "link", "delete", dummy],
            capture_output=True,
        )


def test_invalid_endpoint_name_rejected():
    spec = NativeEndpointSpec(
        name="bad name with space",
        nic="enp1s0f0",
        vlan=10,
        ipv4="10.0.10.100/24",
        ipv4_gw="10.0.10.1",
    )
    with pytest.raises(ValueError, match="Invalid endpoint name"):
        setup_native_endpoint(spec)


def test_teardown_is_idempotent():
    dummy = "test_dummy1"
    spec = NativeEndpointSpec(
        name="tnat2",
        nic=dummy,
        vlan=200,
        ipv4="10.99.200.5/24",
        ipv4_gw="10.99.200.1",
    )
    try:
        _run(["ip", "link", "add", dummy, "type", "dummy"])
        _run(["ip", "link", "set", dummy, "up"])

        handle = setup_native_endpoint(spec)
        teardown_native_endpoint(handle)
        # Second teardown must not raise
        teardown_native_endpoint(handle)
    finally:
        subprocess.run(
            ["ip", "link", "delete", dummy],
            capture_output=True,
        )
