"""VLAN-bridge topology: bridge creation, PVID assignment, TAP attachment (probe mode)."""

from __future__ import annotations

import re
import subprocess
import uuid
from dataclasses import dataclass

from shorewall_nft_netkit.nsstub import spawn_nsstub, stop_nsstub
from shorewall_nft_netkit.tundev import close_tuntap, create_tuntap

# Validation regexes
_IFACE_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")
_NETNS_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _validate_iface(name: str, label: str) -> None:
    if not _IFACE_RE.match(name):
        raise ValueError(f"{label} {name!r} is not a valid interface name (^[A-Za-z0-9_-]{{1,15}}$)")


def _validate_netns(name: str) -> None:
    if not _NETNS_RE.match(name):
        raise ValueError(f"netns name {name!r} is invalid (^[A-Za-z0-9_-]{{1,32}}$)")


def _run(*cmd: str) -> None:
    """Run a command; raise RuntimeError with stderr on failure."""
    result = subprocess.run(list(cmd), check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command {cmd!r} failed (rc={result.returncode}): {result.stderr.strip()}"
        )


def _run_ns(netns: str, *cmd: str) -> None:
    """Run a command inside a netns."""
    _run("ip", "netns", "exec", netns, *cmd)


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
        # Create the bridge inside the netns
        _run_ns(spec.netns, "ip", "link", "add", spec.bridge, "type", "bridge",
                "vlan_filtering", "1", "vlan_default_pvid", "1")

        for m in spec.members:
            if m.kind == "tap":
                # Use a short temp name (uuid hex, max 8 chars) to avoid collision in host ns
                tmp_name = "t" + uuid.uuid4().hex[:7]
                fd, actual_tmp = create_tuntap(tmp_name, "tap", no_pi=True)
                tap_fds[m.name] = fd
                try:
                    # Move TAP to the target netns
                    _run("ip", "link", "set", actual_tmp, "netns", spec.netns)
                    # Rename to final name inside netns
                    _run_ns(spec.netns, "ip", "link", "set", actual_tmp, "name", m.name)
                except Exception:
                    # If move/rename fails, fd still valid; close it so device is freed
                    close_tuntap(fd)
                    tap_fds.pop(m.name, None)
                    raise
                # Enslave to bridge
                _run_ns(spec.netns, "ip", "link", "set", m.name, "master", spec.bridge)
                # Remove default PVID=1 and set the correct VLAN as pvid + untagged
                _run_ns(spec.netns, "bridge", "vlan", "del", "dev", m.name, "vid", "1")
                _run_ns(spec.netns, "bridge", "vlan", "add", "dev", m.name,
                        "vid", str(m.vlan), "pvid", "untagged")

            elif m.kind == "nic_vlan":
                assert m.parent_nic is not None  # validated above
                _validate_iface(m.parent_nic, "parent_nic")
                subiface = f"{m.parent_nic}.{m.vlan}"
                _run("ip", "link", "add", "link", m.parent_nic, "name", subiface,
                     "type", "vlan", "id", str(m.vlan))
                _run("ip", "link", "set", subiface, "netns", spec.netns)
                # Rename to the canonical member name inside netns
                _run_ns(spec.netns, "ip", "link", "set", subiface, "name", m.name)
                _run_ns(spec.netns, "ip", "link", "set", m.name, "master", spec.bridge)
                _run_ns(spec.netns, "bridge", "vlan", "del", "dev", m.name, "vid", "1")
                _run_ns(spec.netns, "bridge", "vlan", "add", "dev", m.name,
                        "vid", str(m.vlan), "tagged")

        # Bring all member interfaces up
        for m in spec.members:
            _run_ns(spec.netns, "ip", "link", "set", m.name, "up")

        # Bring the bridge up
        _run_ns(spec.netns, "ip", "link", "set", spec.bridge, "up")

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
