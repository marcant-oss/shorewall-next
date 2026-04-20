"""Integration tests for topology_bridge.py — requires root + CAP_NET_ADMIN."""

import os
import subprocess

import pytest

from shorewall_nft_stagelab.topology_bridge import (
    BridgeMemberSpec,
    ProbeBridgeSpec,
    setup_probe_bridge,
    teardown_probe_bridge,
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="requires root and CAP_NET_ADMIN",
)


def _ip(*args: str) -> str:
    result = subprocess.run(["ip", *args], check=True, text=True, capture_output=True)
    return result.stdout


def _bridge(*args: str) -> str:
    result = subprocess.run(["bridge", *args], check=True, text=True, capture_output=True)
    return result.stdout


def test_bridge_with_two_taps() -> None:
    """Two TAP members on vlans 10 and 20; verify bridge and VLAN state."""
    spec = ProbeBridgeSpec(
        netns="tb-test-taps",
        bridge="br-probes",
        members=(
            BridgeMemberSpec(kind="tap", name="tap-vlan10", vlan=10),
            BridgeMemberSpec(kind="tap", name="tap-vlan20", vlan=20),
        ),
    )
    handle = setup_probe_bridge(spec)
    try:
        # Bridge exists and is UP
        br_out = _ip("-n", "tb-test-taps", "link", "show", "br-probes")
        assert "br-probes" in br_out
        assert "UP" in br_out

        # Both TAPs are present in the netns
        all_links = _ip("-n", "tb-test-taps", "link", "show")
        assert "tap-vlan10" in all_links
        assert "tap-vlan20" in all_links

        # Both are enslaved to br-probes
        assert "master br-probes" in all_links

        # VLAN table: vid 10 for tap-vlan10, pvid untagged
        vlan_out = _bridge("-n", "tb-test-taps", "vlan", "show")
        # Find the lines for each tap device and verify VID + pvid flag
        assert "tap-vlan10" in vlan_out
        assert "tap-vlan20" in vlan_out
        lines = vlan_out.splitlines()
        # Collect lines associated with each tap (line after device name or same line)
        tap10_lines = []
        tap20_lines = []
        current = None
        for line in lines:
            if "tap-vlan10" in line:
                current = tap10_lines
                tap10_lines.append(line)
            elif "tap-vlan20" in line:
                current = tap20_lines
                tap20_lines.append(line)
            elif line and not line[0].isspace() and line[0].isalpha():
                current = None
            elif current is not None:
                current.append(line)

        tap10_block = "\n".join(tap10_lines)
        tap20_block = "\n".join(tap20_lines)
        assert "10" in tap10_block, f"vid 10 not found in tap-vlan10 block: {tap10_block!r}"
        assert "pvid" in tap10_block or "PVID" in tap10_block, \
            f"pvid flag not found for tap-vlan10: {tap10_block!r}"
        assert "20" in tap20_block, f"vid 20 not found in tap-vlan20 block: {tap20_block!r}"
        assert "pvid" in tap20_block or "PVID" in tap20_block, \
            f"pvid flag not found for tap-vlan20: {tap20_block!r}"

        # handle.tap_fds has 2 entries, both ints
        assert len(handle.tap_fds) == 2
        for name, fd in handle.tap_fds.items():
            assert isinstance(fd, int), f"tap_fds[{name!r}] is not int: {fd!r}"

    finally:
        teardown_probe_bridge(handle)

    # After teardown the netns should be gone
    ns_list = subprocess.run(
        ["ip", "netns", "list"], check=True, text=True, capture_output=True
    ).stdout
    assert "tb-test-taps" not in ns_list


def test_rejects_invalid_name() -> None:
    """Netns name with path traversal characters must raise ValueError."""
    with pytest.raises(ValueError):
        setup_probe_bridge(
            ProbeBridgeSpec(
                netns="../bad-name",
                bridge="br-probes",
                members=(),
            )
        )


def test_teardown_is_idempotent() -> None:
    """Calling teardown twice must not raise."""
    spec = ProbeBridgeSpec(
        netns="tb-test-idem",
        bridge="br-idem",
        members=(
            BridgeMemberSpec(kind="tap", name="tap-idem", vlan=100),
        ),
    )
    handle = setup_probe_bridge(spec)
    teardown_probe_bridge(handle)
    # Second teardown must not raise
    teardown_probe_bridge(handle)
