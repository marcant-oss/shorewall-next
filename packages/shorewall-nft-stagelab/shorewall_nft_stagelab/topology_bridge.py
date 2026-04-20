"""VLAN-bridge topology: bridge creation, PVID assignment, TAP attachment (probe mode)."""

from __future__ import annotations

import os
import re
import subprocess
import uuid
from dataclasses import dataclass

from pyroute2 import IPRoute, NetNS
from pyroute2.netlink.exceptions import NetlinkError

from shorewall_nft_netkit.nsstub import spawn_nsstub, stop_nsstub
from shorewall_nft_netkit.tundev import close_tuntap, create_tuntap

# Validation regexes
_IFACE_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")
_NETNS_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

# errno constants
_EEXIST = 17
_ENODEV = 19
_ENOENT = 2


def _validate_iface(name: str, label: str) -> None:
    if not _IFACE_RE.match(name):
        raise ValueError(f"{label} {name!r} is not a valid interface name (^[A-Za-z0-9_-]{{1,15}}$)")


def _validate_netns(name: str) -> None:
    if not _NETNS_RE.match(name):
        raise ValueError(f"netns name {name!r} is invalid (^[A-Za-z0-9_-]{{1,32}}$)")


def _nl_step(step: str, fn, *args, **kwargs):
    """Call fn(*args, **kwargs); translate NetlinkError to RuntimeError(step …)."""
    try:
        return fn(*args, **kwargs)
    except NetlinkError as exc:
        raise RuntimeError(f"{step} failed: {exc}") from exc


def _run(*cmd: str) -> None:
    """Run a command; raise RuntimeError with stderr on failure."""
    result = subprocess.run(list(cmd), check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command {cmd!r} failed (rc={result.returncode}): {result.stderr.strip()}"
        )


def _run_in_ns(netns: str, *cmd: str) -> None:
    """Run *cmd* with the forked child pre-entered into *netns* via setns().

    Uses the same exec-reduction pattern as simulate.py._ns(): the child
    process calls setns(CLONE_NEWNET) right after fork and before exec, so
    no ``ip netns exec`` wrapper binary is needed.  The ``bridge`` command
    (used for VLAN filter config) is the only consumer; pyroute2 has no
    bridge-vlan API.
    """
    import ctypes

    _CLONE_NEWNET = 0x40000000
    ns_path = f"/run/netns/{netns}"

    def _enter_ns() -> None:  # runs in child, post-fork, pre-exec
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        fd = os.open(ns_path, os.O_RDONLY)
        try:
            if _libc.setns(fd, _CLONE_NEWNET) != 0:
                raise OSError(ctypes.get_errno(), "setns failed")
        finally:
            os.close(fd)

    result = subprocess.run(
        list(cmd), check=False, text=True, capture_output=True,
        preexec_fn=_enter_ns,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command {cmd!r} in {netns} failed (rc={result.returncode}): "
            f"{result.stderr.strip()}"
        )


@dataclass(frozen=True)
class BridgeMemberSpec:
    """One member of the bridge."""

    kind: str          # "nic_vlan" | "tap"
    name: str          # kernel iface name once inside netns
    vlan: int          # 1..4094
    parent_nic: str | None = None  # required for kind="nic_vlan"


@dataclass(frozen=True)
class ProbeBridgeSpec:
    netns: str          # netns name (created by this module)
    bridge: str         # e.g. "br-probes"
    members: tuple[BridgeMemberSpec, ...]


@dataclass(frozen=True)
class ProbeBridgeHandle:
    netns: str
    bridge: str
    nsstub_pid: int
    tap_fds: dict[str, int]  # member_name -> tap file descriptor


def _validate_spec(spec: ProbeBridgeSpec) -> None:
    _validate_netns(spec.netns)
    _validate_iface(spec.bridge, "bridge")
    for m in spec.members:
        _validate_iface(m.name, f"member {m.kind}")
        if m.vlan < 1 or m.vlan > 4094:
            raise ValueError(f"vlan {m.vlan} out of range 1..4094")
        if m.kind == "nic_vlan" and not m.parent_nic:
            raise ValueError(f"member {m.name!r}: kind=nic_vlan requires parent_nic")
        if m.kind not in ("nic_vlan", "tap"):
            raise ValueError(f"member {m.name!r}: unknown kind {m.kind!r}")


def setup_probe_bridge(spec: ProbeBridgeSpec) -> ProbeBridgeHandle:
    """Set up a VLAN-filtering bridge inside a fresh netns.

    1. spawn_nsstub(netns)
    2. Create bridge with vlan_filtering=1, vlan_default_pvid=1
    3. For each member:
       - kind="nic_vlan": create VLAN subiface on parent_nic in host ns,
         move to netns, enslave to bridge, bridge vlan add vid <vlan> (tagged)
       - kind="tap": create with a temp name in host ns (avoids collisions),
         move to netns, rename inside netns to final name, enslave to bridge,
         bridge vlan add vid <vlan> pvid untagged. Remember fd in tap_fds.
    4. Bring bridge and all members up.

    TAP strategy: create with temp name, move to netns, rename inside — this
    is the simplest approach and matches the simlab debug lesson about keeping
    canonical names out of the host NS.
    """
    _validate_spec(spec)

    pid = spawn_nsstub(spec.netns)
    tap_fds: dict[str, int] = {}

    try:
        # Create the bridge inside the netns.
        with NetNS(spec.netns) as ipns:
            try:
                ipns.link(
                    "add",
                    ifname=spec.bridge,
                    kind="bridge",
                    br_vlan_filtering=1,
                    br_vlan_default_pvid=1,
                )
            except NetlinkError as exc:
                if exc.code != _EEXIST:
                    raise RuntimeError(f"create bridge failed: {exc}") from exc

        for m in spec.members:
            if m.kind == "tap":
                # Use a short temp name (uuid hex, max 8 chars) to avoid collision in host ns
                tmp_name = "t" + uuid.uuid4().hex[:7]
                fd, actual_tmp = create_tuntap(tmp_name, "tap", no_pi=True)
                tap_fds[m.name] = fd
                try:
                    # Move TAP to the target netns via the /run/netns fd.
                    with IPRoute() as ipr:
                        tap_idx = ipr.link_lookup(ifname=actual_tmp)
                        if not tap_idx:
                            raise RuntimeError(
                                f"move TAP to netns failed: {actual_tmp!r} not found"
                            )
                        ns_fd = os.open(f"/run/netns/{spec.netns}", os.O_RDONLY)
                        try:
                            _nl_step("move TAP to netns",
                                     ipr.link, "set", index=tap_idx[0], net_ns_fd=ns_fd)
                        finally:
                            os.close(ns_fd)

                    # Rename + enslave inside netns.
                    with NetNS(spec.netns) as ipns:
                        tmp_idx = ipns.link_lookup(ifname=actual_tmp)
                        if not tmp_idx:
                            raise RuntimeError(
                                f"rename TAP failed: {actual_tmp!r} not found in {spec.netns}"
                            )
                        _nl_step("rename TAP",
                                 ipns.link, "set", index=tmp_idx[0], ifname=m.name)
                        br_idx = ipns.link_lookup(ifname=spec.bridge)
                        if not br_idx:
                            raise RuntimeError(
                                f"enslave TAP failed: bridge {spec.bridge!r} not found"
                            )
                        _nl_step("enslave TAP to bridge",
                                 ipns.link, "set", index=tmp_idx[0], master=br_idx[0])

                except Exception:
                    # If move/rename fails, fd still valid; close it so device is freed
                    close_tuntap(fd)
                    tap_fds.pop(m.name, None)
                    raise

                # bridge vlan: remove default PVID=1, add the correct VLAN as pvid+untagged.
                # pyroute2 has no bridge-vlan API; keep the 'bridge' CLI for this step.
                _run_in_ns(spec.netns,
                           "bridge", "vlan", "del", "dev", m.name, "vid", "1")
                _run_in_ns(spec.netns,
                           "bridge", "vlan", "add", "dev", m.name,
                           "vid", str(m.vlan), "pvid", "untagged")

            elif m.kind == "nic_vlan":
                assert m.parent_nic is not None  # validated above
                _validate_iface(m.parent_nic, "parent_nic")
                subiface = f"{m.parent_nic}.{m.vlan}"

                with IPRoute() as ipr:
                    parent_idx = ipr.link_lookup(ifname=m.parent_nic)
                    if not parent_idx:
                        raise RuntimeError(
                            f"create VLAN iface failed: parent NIC {m.parent_nic!r} not found"
                        )
                    try:
                        ipr.link(
                            "add",
                            ifname=subiface,
                            kind="vlan",
                            link=parent_idx[0],
                            vlan_id=m.vlan,
                        )
                    except NetlinkError as exc:
                        if exc.code != _EEXIST:
                            raise RuntimeError(
                                f"create VLAN iface failed: {exc}"
                            ) from exc

                    # Move VLAN iface to netns.
                    vlan_idx = ipr.link_lookup(ifname=subiface)
                    if not vlan_idx:
                        raise RuntimeError(
                            f"move VLAN iface to netns failed: "
                            f"{subiface!r} not found after create"
                        )
                    ns_fd = os.open(f"/run/netns/{spec.netns}", os.O_RDONLY)
                    try:
                        _nl_step("move VLAN iface to netns",
                                 ipr.link, "set", index=vlan_idx[0], net_ns_fd=ns_fd)
                    finally:
                        os.close(ns_fd)

                # Rename to canonical member name + enslave to bridge inside netns.
                with NetNS(spec.netns) as ipns:
                    sub_idx = ipns.link_lookup(ifname=subiface)
                    if not sub_idx:
                        raise RuntimeError(
                            f"rename VLAN iface failed: {subiface!r} not found in {spec.netns}"
                        )
                    _nl_step("rename VLAN iface",
                             ipns.link, "set", index=sub_idx[0], ifname=m.name)
                    br_idx = ipns.link_lookup(ifname=spec.bridge)
                    if not br_idx:
                        raise RuntimeError(
                            f"enslave VLAN iface failed: bridge {spec.bridge!r} not found"
                        )
                    _nl_step("enslave VLAN iface to bridge",
                             ipns.link, "set", index=sub_idx[0], master=br_idx[0])

                # bridge vlan: remove default PVID=1, add the correct VLAN tagged.
                # pyroute2 has no bridge-vlan API; keep the 'bridge' CLI for this step.
                _run_in_ns(spec.netns,
                           "bridge", "vlan", "del", "dev", m.name, "vid", "1")
                _run_in_ns(spec.netns,
                           "bridge", "vlan", "add", "dev", m.name,
                           "vid", str(m.vlan), "tagged")

        # Bring all member interfaces + bridge up.
        with NetNS(spec.netns) as ipns:
            for m in spec.members:
                mem_idx = ipns.link_lookup(ifname=m.name)
                if mem_idx:
                    _nl_step(f"bring up {m.name}",
                             ipns.link, "set", index=mem_idx[0], state="up")

            br_idx = ipns.link_lookup(ifname=spec.bridge)
            if br_idx:
                _nl_step("bring up bridge",
                         ipns.link, "set", index=br_idx[0], state="up")

    except Exception:
        # Partial cleanup on setup failure
        partial = ProbeBridgeHandle(
            netns=spec.netns,
            bridge=spec.bridge,
            nsstub_pid=pid,
            tap_fds=tap_fds,
        )
        try:
            teardown_probe_bridge(partial)
        except Exception:
            pass
        raise

    return ProbeBridgeHandle(
        netns=spec.netns,
        bridge=spec.bridge,
        nsstub_pid=pid,
        tap_fds=tap_fds,
    )


def teardown_probe_bridge(handle: ProbeBridgeHandle) -> None:
    """Tear down a probe bridge.

    1. close_tuntap(fd) for every TAP fd in handle.tap_fds
    2. stop_nsstub(netns, pid) — this unmounts the netns bind-mount and reaps the stub
    """
    for fd in handle.tap_fds.values():
        close_tuntap(fd)
    stop_nsstub(handle.netns, handle.nsstub_pid)
