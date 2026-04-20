"""Native NIC topology: physical NIC VLAN-subinterface moved into NS_TEST (native mode)."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from shorewall_nft_netkit.nsstub import spawn_nsstub, stop_nsstub

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _run(cmd: list[str], step: str) -> None:
    try:
        subprocess.run(cmd, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{step} failed: {exc.stderr}") from exc


@dataclass(frozen=True)
class NativeEndpointSpec:
    name: str           # endpoint name, used for netns name NS_TEST_<name>
    nic: str            # host-side physical NIC name, e.g. "enp1s0f0"
    vlan: int           # 1..4094
    ipv4: str           # "10.0.10.100/24" — CIDR
    ipv4_gw: str        # "10.0.10.1"
    ipv6: str | None = None
    ipv6_gw: str | None = None


@dataclass(frozen=True)
class NativeEndpointHandle:
    name: str
    netns: str          # "NS_TEST_<name>"
    nsstub_pid: int
    vlan_iface: str     # "<nic>.<vlan>", e.g. "enp1s0f0.10"


def setup_native_endpoint(spec: NativeEndpointSpec) -> NativeEndpointHandle:
    """Create netns, create VLAN subiface on parent NIC, move it to netns,
    bring up, set IPs + default GW. Returns handle for teardown.

    Preconditions: caller is root and CAP_NET_ADMIN.
    The parent NIC ``spec.nic`` must exist in the caller's netns.
    """
    if not _NAME_RE.match(spec.name):
        raise ValueError(
            f"Invalid endpoint name {spec.name!r}: "
            "must match ^[A-Za-z0-9_-]{1,32}$"
        )

    netns = f"NS_TEST_{spec.name}"
    vlan_iface = f"{spec.nic}.{spec.vlan}"

    pid = spawn_nsstub(netns)
    handle = NativeEndpointHandle(
        name=spec.name,
        netns=netns,
        nsstub_pid=pid,
        vlan_iface=vlan_iface,
    )

    try:
        # Parent NIC must be up before VLAN add, otherwise the subsequent
        # `ip link set <vlan> up` inside the netns fails with
        # "Network is down". This is common on hosts where the test NIC is
        # NM-unmanaged and has no boot-time enslavement: eth2 starts DOWN.
        _run(
            ["ip", "link", "set", spec.nic, "up"],
            "bring up parent NIC",
        )
        # Create VLAN sub-interface. If it already exists (e.g. created by a
        # systemd service at boot — tester02-downstream.service) we reuse it
        # directly rather than failing; "File exists" from `ip link add` is
        # the only safe-to-ignore CalledProcessError here.
        try:
            subprocess.run(
                ["ip", "link", "add", "link", spec.nic,
                 "name", vlan_iface, "type", "vlan", "id", str(spec.vlan)],
                check=True, text=True, capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            if "File exists" not in exc.stderr:
                raise RuntimeError(f"create VLAN iface failed: {exc.stderr}") from exc
            # Interface pre-exists; take it over by moving it to our netns.
        _run(
            ["ip", "link", "set", vlan_iface, "netns", netns],
            "move VLAN iface to netns",
        )
        _run(
            ["ip", "-n", netns, "link", "set", "lo", "up"],
            "bring up loopback",
        )
        _run(
            ["ip", "-n", netns, "link", "set", vlan_iface, "up"],
            "bring up VLAN iface",
        )
        _run(
            ["ip", "-n", netns, "addr", "add", spec.ipv4, "dev", vlan_iface],
            "add IPv4 address",
        )
        _run(
            ["ip", "-n", netns, "route", "add", "default", "via", spec.ipv4_gw],
            "add IPv4 default route",
        )
        if spec.ipv6 is not None:
            _run(
                ["ip", "-n", netns, "addr", "add", spec.ipv6, "dev", vlan_iface],
                "add IPv6 address",
            )
        if spec.ipv6_gw is not None:
            _run(
                ["ip", "-n", netns, "route", "add", "default",
                 "via", spec.ipv6_gw],
                "add IPv6 default route",
            )
    except Exception:
        teardown_native_endpoint(handle)
        raise

    return handle


def teardown_native_endpoint(handle: NativeEndpointHandle) -> None:
    """Delete the VLAN iface (it dies with the netns, but we explicitly
    remove it before stopping the stub to avoid lingering state).
    Then stop_nsstub() to remove the netns.
    """
    # Best-effort: delete the VLAN iface from inside the netns first.
    try:
        subprocess.run(
            ["ip", "-n", handle.netns, "link", "delete", handle.vlan_iface],
            check=True, text=True, capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Remove the netns (stop the stub). Swallow errors to stay idempotent.
    try:
        stop_nsstub(handle.netns, handle.nsstub_pid)
    except Exception:
        pass
