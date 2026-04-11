"""pyroute2-based netns + link/addr/route topology manager.

Used by the simulate runtime to build multi-netns test topologies
without forking `ip` / `sudo run-netns` hundreds of times. Requires
the caller to run as root — the shorewall-nft simulate CLI is
invoked as root on the dedicated test host, which is the only
supported deployment for this path.

Design notes:
  * Each netns is kept open via pyroute2.NetNS and re-used across
    calls. Closing happens in ``destroy()``.
  * Link/addr/route operations use the per-ns NetNS handle.
  * Moving an interface between netns uses net_ns_fd from an
    opened file descriptor on /run/netns/<target>.
  * sysctl writes go via /proc/<self-entered-ns>/sys/... — we
    briefly setns() into the target for the write and restore
    after. pyroute2 has no sysctl API, and shelling out just for
    a handful of sysctls is pointless when we are already root
    in the right capability set.
  * nft ruleset loading, conntrack, and packet probes (nc, ping)
    still go via subprocess ``ip netns exec`` because those are
    external binaries; pyroute2 can't replace them.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any

try:
    from pyroute2 import NDB, NetNS, netns  # noqa: F401
    from pyroute2.netlink.exceptions import NetlinkError
    _PYROUTE_OK = True
except ImportError:
    _PYROUTE_OK = False
    NetlinkError = Exception  # type: ignore


_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
_CLONE_NEWNET = 0x40000000


def _setns(fd: int) -> None:
    """Enter the network namespace referenced by the given fd."""
    if _libc.setns(fd, _CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), "setns failed")


@dataclass
class NetnsTopology:
    """High-level wrapper around a set of network namespaces.

    Opens each netns lazily, keeps the pyroute2 handles cached, and
    exposes a small vocabulary of idempotent link/addr/route helpers.
    """

    _handles: dict[str, "NetNS"] = field(default_factory=dict)
    _fds: dict[str, int] = field(default_factory=dict)
    _host_fd: int | None = None

    def __post_init__(self) -> None:
        if not _PYROUTE_OK:
            raise RuntimeError(
                "pyroute2 is not available — install python3-pyroute2")
        if os.geteuid() != 0:
            raise PermissionError(
                "NetnsTopology requires root (pyroute2.NetNS needs "
                "CAP_SYS_ADMIN via setns); got euid={}".format(os.geteuid()))
        self._host_fd = os.open("/proc/self/ns/net", os.O_RDONLY)

    # ── lifecycle ─────────────────────────────────────────────────────

    def ns_create(self, name: str) -> None:
        """Create a named netns if it doesn't already exist, and pre-open
        its /run/netns/<name> file descriptor.

        Opening the fd eagerly matters because ``ns()`` forks a helper
        process the first time it's called, and the helper only
        inherits file descriptors that are already open at fork time.
        Without this pre-open, later ``link_set_netns`` calls that
        need to pass the target ns_fd fail with EBADF in the helper.
        """
        if name not in netns.listnetns():
            netns.create(name)
        if name not in self._fds:
            self._fds[name] = os.open(f"/run/netns/{name}", os.O_RDONLY)

    def ns_delete(self, name: str) -> None:
        """Remove a named netns and drop any cached handle."""
        handle = self._handles.pop(name, None)
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass
        fd = self._fds.pop(name, None)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            netns.remove(name)
        except Exception:
            pass

    def refresh_handles(self) -> None:
        """Drop all cached NetNS handles so the next ns() call re-forks.

        Use after opening additional /run/netns/<name> file descriptors
        so the helper child processes can inherit them. (pyroute2.NetNS
        forks at construction time and the helper only sees fds open
        in its parent at the fork moment.)
        """
        for handle in self._handles.values():
            try:
                handle.close()
            except Exception:
                pass
        self._handles.clear()

    def ns(self, name: str) -> "NetNS":
        """Return a cached NetNS handle for name, creating it if missing."""
        handle = self._handles.get(name)
        if handle is None:
            self.ns_create(name)
            handle = NetNS(name)
            self._handles[name] = handle
        return handle

    def ns_fd(self, name: str) -> int:
        """Return a cached file descriptor for /run/netns/<name>."""
        fd = self._fds.get(name)
        if fd is None:
            self.ns_create(name)
            fd = os.open(f"/run/netns/{name}", os.O_RDONLY)
            self._fds[name] = fd
        return fd

    def close(self) -> None:
        """Drop all cached netns handles + file descriptors."""
        for handle in self._handles.values():
            try:
                handle.close()
            except Exception:
                pass
        self._handles.clear()
        for fd in self._fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds.clear()
        if self._host_fd is not None:
            try:
                os.close(self._host_fd)
            except OSError:
                pass
            self._host_fd = None

    # ── link ──────────────────────────────────────────────────────────

    def _link_index(self, ns_name: str, ifname: str) -> int | None:
        try:
            links = self.ns(ns_name).link_lookup(ifname=ifname)
            return links[0] if links else None
        except NetlinkError:
            return None

    def veth_add_peer(self, ns_name: str, a: str, b: str) -> None:
        """Add a veth pair (a,b) inside ns_name. Idempotent."""
        if self._link_index(ns_name, a) is not None:
            return
        try:
            self.ns(ns_name).link(
                "add", ifname=a, kind="veth", peer={"ifname": b})
        except NetlinkError as e:
            if e.code != 17:  # EEXIST
                raise

    def link_set_netns(self, ns_src: str, ifname: str, ns_dst: str) -> None:
        """Move an interface from one netns to another."""
        idx = self._link_index(ns_src, ifname)
        if idx is None:
            return
        target_fd = self.ns_fd(ns_dst)
        self.ns(ns_src).link("set", index=idx, net_ns_fd=target_fd)

    def link_rename(self, ns_name: str, old: str, new: str) -> None:
        idx = self._link_index(ns_name, old)
        if idx is None:
            return
        self.ns(ns_name).link("set", index=idx, ifname=new)

    def link_up(self, ns_name: str, ifname: str) -> None:
        idx = self._link_index(ns_name, ifname)
        if idx is None:
            return
        try:
            self.ns(ns_name).link("set", index=idx, state="up")
        except NetlinkError:
            pass

    # ── addr + route ──────────────────────────────────────────────────

    def addr_add(self, ns_name: str, ifname: str, addr: str,
                 prefixlen: int, *, family: int = 4) -> None:
        """Add an address to ifname inside ns_name. Idempotent."""
        idx = self._link_index(ns_name, ifname)
        if idx is None:
            return
        try:
            self.ns(ns_name).addr(
                "add", index=idx, address=addr, prefixlen=prefixlen,
                family=(10 if family == 6 else 2))
        except NetlinkError as e:
            if e.code != 17:  # EEXIST
                pass  # best effort

    def route_add(self, ns_name: str, dst: str, *,
                  dev: str | None = None, gw: str | None = None,
                  family: int = 4, src: str | None = None,
                  table: int | None = None) -> None:
        """Add a route. Use dev for link-scope routes, gw for next-hop routes.

        If ``table`` is given, the route is installed in a non-main
        routing table (for policy routing).
        """
        kwargs: dict[str, Any] = {
            "dst": dst,
            "family": 10 if family == 6 else 2,
        }
        if dev is not None:
            idx = self._link_index(ns_name, dev)
            if idx is None:
                return
            kwargs["oif"] = idx
        if gw is not None:
            kwargs["gateway"] = gw
        if src is not None:
            kwargs["prefsrc"] = src
        if table is not None:
            kwargs["table"] = table
        try:
            self.ns(ns_name).route("add", **kwargs)
        except NetlinkError:
            pass  # best effort

    def rule_add(self, ns_name: str, src: str, *,
                 table: int, family: int = 4) -> None:
        """Add a routing policy rule `ip rule add from SRC table N`."""
        try:
            self.ns(ns_name).rule(
                "add",
                src=src,
                table=table,
                family=10 if family == 6 else 2,
            )
        except NetlinkError:
            pass

    # ── sysctl + sub-process exec ─────────────────────────────────────

    def sysctl_set(self, ns_name: str, key: str | list[str], value: str) -> None:
        """Write a sysctl value inside a netns via brief setns().

        ``key`` can be either a single /-separated path ("net/ipv4/
        ip_forward") or a list of components (["net","ipv4","conf",
        "bond0.20","rp_filter"]) — use the list form when a component
        itself contains dots (like a VLAN interface name) so we don't
        split on them.
        """
        target_fd = self.ns_fd(ns_name)
        saved_fd = os.open("/proc/self/ns/net", os.O_RDONLY)
        try:
            _setns(target_fd)
            if isinstance(key, list):
                path = "/proc/sys/" + "/".join(key)
            else:
                path = f"/proc/sys/{key}"
            with open(path, "w") as f:
                f.write(value)
        finally:
            _setns(saved_fd)
            os.close(saved_fd)

    def exec_in_ns(self, ns_name: str, argv: list[str], *,
                   timeout: int = 10,
                   capture_output: bool = True) -> subprocess.CompletedProcess:
        """Run an external binary inside a named netns.

        Uses a ``preexec_fn`` that calls ``setns(CLONE_NEWNET)``
        right after fork and before exec, so the child lands in
        the target namespace while the parent's namespace is
        untouched. Avoids the ``ip netns exec`` wrapper binary
        entirely — one less fork, one less dependency on iproute2
        binary path, and it still works when ``/sbin/ip`` isn't in
        PATH.

        Keeps shell-out for the external binaries themselves (nft,
        conntrack, ping, …) — those aren't Python-callable. Phase B
        of the exec-reduction plan replaces the *wrapper*, not the
        targets.
        """
        ns_path = f"/run/netns/{ns_name}"

        def _enter_ns() -> None:  # runs post-fork, pre-exec in child
            fd = os.open(ns_path, os.O_RDONLY)
            try:
                _setns(fd)
            finally:
                os.close(fd)

        return subprocess.run(
            argv,
            capture_output=capture_output, text=True, timeout=timeout,
            preexec_fn=_enter_ns,
        )
