"""Native NIC topology: physical NIC VLAN-subinterface moved into NS_TEST (native mode)."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass

from pyroute2 import IPRoute, NetNS
from pyroute2.netlink.exceptions import NetlinkError
from shorewall_nft_netkit.nsstub import spawn_nsstub, stop_nsstub

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

# errno constants
_EEXIST = 17
_ENODEV = 19
_ENOENT = 2
_EADDRNOTAVAIL = 99


def _nl_step(step: str, fn, *args, **kwargs):
    """Call fn(*args, **kwargs); translate NetlinkError to RuntimeError(step …)."""
    try:
        return fn(*args, **kwargs)
    except NetlinkError as exc:
        raise RuntimeError(f"{step} failed: {exc}") from exc


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
        with IPRoute() as ipr:
            # Parent NIC must be up before VLAN add, otherwise the subsequent
            # `ip link set <vlan> up` inside the netns fails with
            # "Network is down". This is common on hosts where the test NIC is
            # NM-unmanaged and has no boot-time enslavement: eth2 starts DOWN.
            nic_idx = ipr.link_lookup(ifname=spec.nic)
            if not nic_idx:
                raise RuntimeError(
                    f"bring up parent NIC failed: {spec.nic!r} not found"
                )
            _nl_step("bring up parent NIC",
                     ipr.link, "set", index=nic_idx[0], state="up")

            # Create VLAN sub-interface. If it already exists (e.g. created by a
            # systemd service at boot — tester02-downstream.service) we reuse it
            # directly rather than failing. The kernel emits two distinct error
            # strings for this depending on whether the interface exists in the
            # current netns ("File exists" from RTNETLINK) or the 8021q layer
            # remembers the VLAN-on-parent mapping from a previous setup in
            # another netns ("8021q: VLAN device already exists"). Both are
            # safe to ignore — we adopt the interface.
            try:
                ipr.link(
                    "add",
                    ifname=vlan_iface,
                    kind="vlan",
                    link=nic_idx[0],
                    vlan_id=spec.vlan,
                )
            except NetlinkError as exc:
                if exc.code != _EEXIST:
                    raise RuntimeError(
                        f"create VLAN iface failed: {exc}"
                    ) from exc
                # Interface pre-exists; check visibility. The 8021q kernel
                # layer sometimes reports EEXIST even after the user-space
                # interface has been destroyed by a prior netns-delete — in
                # that case `link_lookup` returns empty and any subsequent
                # `set netns` fails with "Cannot find device". Sledgehammer:
                # reset the 8021q module and retry the add.
                vlan_idx = ipr.link_lookup(ifname=vlan_iface)
                if not vlan_idx:
                    subprocess.run(
                        ["rmmod", "8021q"],
                        check=False, text=True, capture_output=True,
                    )
                    subprocess.run(
                        ["modprobe", "8021q"],
                        check=False, text=True, capture_output=True,
                    )
                    # Re-lookup parent NIC (index may have changed after rmmod).
                    nic_idx = ipr.link_lookup(ifname=spec.nic)
                    if not nic_idx:
                        raise RuntimeError(
                            f"create VLAN iface failed: parent {spec.nic!r} "
                            f"vanished after 8021q reset"
                        )
                    ipr.link(
                        "add",
                        ifname=vlan_iface,
                        kind="vlan",
                        link=nic_idx[0],
                        vlan_id=spec.vlan,
                    )
                else:
                    # Interface genuinely exists; flush any stray IPs so our
                    # assignment is clean.
                    try:
                        ipr.flush_addr(index=vlan_idx[0])
                    except NetlinkError:
                        pass

            # Move VLAN iface to netns — open the netns fd for the move
            vlan_idx = ipr.link_lookup(ifname=vlan_iface)
            if not vlan_idx:
                raise RuntimeError(
                    f"move VLAN iface to netns failed: {vlan_iface!r} not found after create"
                )
            ns_fd = os.open(f"/run/netns/{netns}", os.O_RDONLY)
            try:
                _nl_step("move VLAN iface to netns",
                         ipr.link, "set", index=vlan_idx[0], net_ns_fd=ns_fd)
            finally:
                os.close(ns_fd)

        # All subsequent ops happen inside the new netns
        with NetNS(netns) as ipns:
            lo_idx = ipns.link_lookup(ifname="lo")
            if lo_idx:
                _nl_step("bring up loopback",
                         ipns.link, "set", index=lo_idx[0], state="up")

            vi_idx = ipns.link_lookup(ifname=vlan_iface)
            if not vi_idx:
                raise RuntimeError(
                    f"bring up VLAN iface failed: {vlan_iface!r} not found in {netns}"
                )
            idx = vi_idx[0]

            _nl_step("bring up VLAN iface",
                     ipns.link, "set", index=idx, state="up")

            # Parse CIDR for addr add (e.g. "10.0.10.100/24")
            ipv4_addr, ipv4_plen = spec.ipv4.split("/")
            _nl_step("add IPv4 address",
                     ipns.addr, "add",
                     index=idx, address=ipv4_addr, prefixlen=int(ipv4_plen),
                     family=2)

            _nl_step("add IPv4 default route",
                     ipns.route, "add",
                     dst="0.0.0.0/0", gateway=spec.ipv4_gw, family=2)

            if spec.ipv6 is not None:
                ipv6_addr, ipv6_plen = spec.ipv6.split("/")
                # IFA_F_NODAD (0x02) skips Duplicate Address Detection so the
                # address is usable immediately. Without this, callers that
                # bind() to the address (iperf3, nmap, scapy raw sockets) fail
                # with "Cannot assign requested address" during the ~1s DAD
                # window because the address is still in `tentative` state.
                _nl_step("add IPv6 address",
                         ipns.addr, "add",
                         index=idx, address=ipv6_addr,
                         prefixlen=int(ipv6_plen), family=10,
                         flags=0x02)

            if spec.ipv6_gw is not None:
                _nl_step("add IPv6 default route",
                         ipns.route, "add",
                         dst="::/0", gateway=spec.ipv6_gw, family=10)

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
        with NetNS(handle.netns) as ipns:
            vi_idx = ipns.link_lookup(ifname=handle.vlan_iface)
            if vi_idx:
                ipns.link("del", index=vi_idx[0])
    except Exception:
        pass

    # Remove the netns (stop the stub). Swallow errors to stay idempotent.
    try:
        stop_nsstub(handle.netns, handle.nsstub_pid)
    except Exception:
        pass
