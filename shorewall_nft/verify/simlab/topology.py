"""Build the NS_FW simulation namespace from parsed dump state.

For every parsed interface we:
  1. Create a TUN or TAP device in the host namespace (the caller's
     current NS). The file descriptor belongs to the calling process;
     this is important because the worker we spawn later will inherit
     it via ``pass_fds``.
  2. Rename the device to the real interface name (``bond1``,
     ``bond0.20`` …) so nft rules match literally.
  3. Move the device into NS_FW via ``ip link set … netns …``.
  4. Apply the primary + secondary addresses (v4 + v6) as recorded
     in the dump. MTU is copied from the dump too.
  5. After all interfaces are present, apply the route table.

Routes that reference interfaces we didn't recreate (e.g. ``dummy0``
with its BGP VTEP addresses, ``lo``) are silently dropped. The
``ip6routes`` dump contains a ``table 1000`` view — we honour
``table`` keyword during install.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from pyroute2 import NetNS, netns
from pyroute2.netlink.exceptions import NetlinkError

from .dumps import FwState, Interface, Route, iface_needs_tap
from .nsstub import spawn_nsstub, stop_nsstub
from .tundev import close_tuntap, create_tuntap

if TYPE_CHECKING:
    pass


NS_FW_DEFAULT = "simlab-fw"


class SimFwTopology:
    """Controller-owned representation of NS_FW + its TUN/TAPs.

    Call :meth:`build` once after construction; call :meth:`destroy`
    on shutdown. The per-interface fd is kept in :attr:`tun_fds` —
    the :class:`simlab.worker.Worker` wrapper passes these to the
    forked worker children and then closes its own copy.
    """

    def __init__(self, fw_state: FwState, ns_name: str = NS_FW_DEFAULT,
                 *, iface_rp_filter: dict[str, str] | None = None):
        self.state = fw_state
        self.ns_name = ns_name
        # Per-iface rp_filter values resolved from the parsed
        # shorewall config (matches the per-iface routefilter
        # option). When None, the previous behaviour applies:
        # rp_filter is forced to 0 globally so the simlab can
        # inject spoofed-source probes for autorepair coverage.
        # When supplied, values are written per-iface AFTER the
        # interface lands in the netns so the test environment
        # mirrors what production would see.
        self.iface_rp_filter: dict[str, str] = dict(
            iface_rp_filter or {})
        # iface name → file descriptor (owned by this process)
        self.tun_fds: dict[str, int] = {}
        # iface name → device kind ("tap" or "tun")
        self.tun_kind: dict[str, str] = {}
        # iface name → MTU copied from the dump
        self.tun_mtu: dict[str, int] = {}
        # iface name → MAC address string (only for TAP devices).
        # Captured after the interface lands in NS_FW so probes sent
        # from a worker can set the correct destination MAC.
        self.tun_mac: dict[str, str] = {}
        self._ns_fd: int | None = None
        self._stub_pid: int | None = None
        self._built = False

    # ── lifecycle ─────────────────────────────────────────────────

    def build(self) -> None:
        """Create NS_FW, emit TUN/TAPs, apply addrs + routes."""
        self._ensure_ns()
        self._create_all_tuntaps()
        self._move_all_to_ns()
        self._configure_all_interfaces()
        self._apply_routes()
        self._built = True

    def destroy(self) -> None:
        """Tear down — close fds, tell the nsstub to clean up, reap it."""
        for fd in self.tun_fds.values():
            close_tuntap(fd)
        self.tun_fds.clear()
        if self._ns_fd is not None:
            try:
                os.close(self._ns_fd)
            except OSError:
                pass
            self._ns_fd = None
        if self._stub_pid is not None:
            try:
                stop_nsstub(self.ns_name, self._stub_pid)
            except Exception:
                pass
            self._stub_pid = None
        # Fallback: if the stub-path didn't clean up the bind mount,
        # try the classic removal too.
        try:
            netns.remove(self.ns_name)
        except Exception:
            pass

    # ── internals ─────────────────────────────────────────────────

    def _ensure_ns(self) -> None:
        # The nsstub holds the netns alive via a bind-mount that will
        # be cleaned up automatically when this controller process
        # dies — much more robust than plain netns.create().
        if self.ns_name in netns.listnetns():
            # Stale leftover from a crashed previous run. Remove.
            try:
                netns.remove(self.ns_name)
            except Exception:
                pass
        self._stub_pid = spawn_nsstub(self.ns_name)
        self._ns_fd = os.open(f"/run/netns/{self.ns_name}", os.O_RDONLY)
        # Bring lo up + enable forwarding + kill rp_filter inside NS_FW
        with NetNS(self.ns_name) as ipr:
            lo = ipr.link_lookup(ifname="lo")
            if lo:
                try:
                    ipr.link("set", index=lo[0], state="up")
                except NetlinkError:
                    pass
        # Sysctls via setns trick
        self._sysctl_write(["net", "ipv4", "ip_forward"], "1")
        self._sysctl_write(["net", "ipv6", "conf", "all", "forwarding"], "1")
        # If we don't have per-iface rp_filter overrides we keep
        # the historical behaviour: force rp_filter=0 globally so
        # autorepair-rewritten spoofed-src probes can be injected
        # without the kernel discarding them at ingress. With
        # overrides we let the per-iface step (in
        # ``_configure_all_interfaces``) write the real values.
        if not self.iface_rp_filter:
            self._sysctl_write(
                ["net", "ipv4", "conf", "all", "rp_filter"], "0")
            self._sysctl_write(
                ["net", "ipv4", "conf", "default", "rp_filter"], "0")

    def _sysctl_write(self, path_parts: list[str], value: str) -> None:
        """Write a sysctl inside NS_FW via a short setns() hop."""
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                           use_errno=True)
        saved = os.open("/proc/self/ns/net", os.O_RDONLY)
        try:
            if libc.setns(self._ns_fd, 0x40000000) != 0:
                raise OSError(ctypes.get_errno(), "setns failed")
            with open("/proc/sys/" + "/".join(path_parts), "w") as f:
                f.write(value)
        except (OSError, FileNotFoundError):
            pass
        finally:
            libc.setns(saved, 0x40000000)
            os.close(saved)

    def _create_all_tuntaps(self) -> None:
        """Step 1: for each real iface, create a TUN or TAP in host NS
        under a **temporary** name. We do NOT rename here — renaming
        happens after the device has been moved into NS_FW so the
        canonical name (bond1, bond0.20, ...) never appears in the
        host namespace and can't clash with real interfaces there.
        """
        # name (canonical) → temp name used during creation
        self.tun_tmpname: dict[str, str] = {}
        for name, iface in self.state.interfaces.items():
            if iface.kind == "loopback":
                continue  # lo is provided by the kernel
            mode = "tap" if iface_needs_tap(iface) else "tun"
            tmp = f"simlab{len(self.tun_fds):02d}"
            try:
                fd, actual = create_tuntap(tmp, mode=mode, no_pi=True)
            except OSError as e:
                raise RuntimeError(
                    f"create_tuntap({tmp}) failed for target {name!r}: {e}"
                ) from e
            self.tun_fds[name] = fd
            self.tun_kind[name] = mode
            self.tun_mtu[name] = iface.mtu
            self.tun_tmpname[name] = actual

    def _move_all_to_ns(self) -> None:
        """Step 2: move each tempname'd TUN/TAP into NS_FW, then
        rename to the canonical name **inside** NS_FW."""
        from pyroute2 import IPRoute
        with IPRoute() as host_ipr:
            for name in self.tun_fds:
                tmp = self.tun_tmpname[name]
                links = host_ipr.link_lookup(ifname=tmp)
                if not links:
                    continue
                host_ipr.link("set", index=links[0], net_ns_fd=self._ns_fd)
        # Now rename to canonical names inside NS_FW.
        with NetNS(self.ns_name) as ipr:
            for name in self.tun_fds:
                tmp = self.tun_tmpname[name]
                links = ipr.link_lookup(ifname=tmp)
                if not links:
                    continue
                if tmp == name:
                    continue
                try:
                    ipr.link("set", index=links[0], ifname=name)
                except NetlinkError as e:
                    if e.code == 17:  # EEXIST in target NS
                        raise RuntimeError(
                            f"interface {name!r} already exists in "
                            f"{self.ns_name} — aborting"
                        ) from e
                    raise

    def _configure_all_interfaces(self) -> None:
        """Step 3: inside NS_FW, apply MTU, addresses, link up, capture MAC."""
        with NetNS(self.ns_name) as ipr:
            for name, iface in self.state.interfaces.items():
                if iface.kind == "loopback":
                    continue
                if name not in self.tun_fds:
                    continue
                links = ipr.link_lookup(ifname=name)
                if not links:
                    continue
                idx = links[0]
                # Capture MAC for TAP — workers need dst_mac when injecting
                if self.tun_kind[name] == "tap":
                    try:
                        link_info = ipr.get_links(idx)[0]
                        mac = link_info.get_attr("IFLA_ADDRESS")
                        if mac:
                            self.tun_mac[name] = mac
                    except NetlinkError:
                        pass
                try:
                    ipr.link("set", index=idx, mtu=iface.mtu)
                except NetlinkError:
                    pass
                for a in iface.addrs4:
                    try:
                        ipr.addr("add", index=idx, address=a.addr,
                                 prefixlen=a.prefixlen, family=2,
                                 broadcast=a.broadcast)
                    except NetlinkError as e:
                        if e.code != 17:  # EEXIST
                            pass
                for a in iface.addrs6:
                    if a.addr.startswith("fe80::"):
                        continue  # link-local is auto-assigned
                    try:
                        ipr.addr("add", index=idx, address=a.addr,
                                 prefixlen=a.prefixlen, family=10)
                    except NetlinkError:
                        pass
                try:
                    ipr.link("set", index=idx, state="up")
                except NetlinkError:
                    pass

        # Apply per-iface rp_filter overrides AFTER all interfaces
        # are configured. The values come from the parsed shorewall
        # config (routefilter / noroutefilter / routefilter=N option
        # on the interfaces file). Without overrides we keep the
        # historical "all=0 default=0" forcing applied earlier in
        # _ensure_ns so spoofed-src probes still work.
        if self.iface_rp_filter:
            for name, value in self.iface_rp_filter.items():
                if name not in self.tun_fds:
                    continue
                self._sysctl_write(
                    ["net", "ipv4", "conf", name, "rp_filter"], value)

    def _apply_routes(self) -> None:
        """Step 4: install every parsed route in NS_FW, skipping
        routes that reference interfaces we didn't create."""
        with NetNS(self.ns_name) as ipr:
            for r in self.state.routes4:
                self._install_route(ipr, r, family=4)
            for r in self.state.routes6:
                self._install_route(ipr, r, family=6)

    def _install_route(self, ipr: NetNS, r: Route, family: int) -> None:
        # Skip unicast routes whose dev we didn't emulate.
        if r.dev and r.dev not in self.tun_fds and r.dev != "lo":
            return
        # Skip v6 link-local next-hops — those need MAC resolution
        # we can't easily perform against a TAP with no neighbours.
        if family == 6 and r.via and r.via.startswith("fe80::"):
            return
        # Translate `default` to 0.0.0.0/0 or ::/0 so pyroute2 accepts it.
        dst = r.dst
        if dst == "default":
            dst = "::/0" if family == 6 else "0.0.0.0/0"
        # Map rtype → pyroute2 kwarg
        extra: dict = {}
        if r.rtype != "unicast":
            extra["type"] = r.rtype
        kwargs = dict(dst=dst, family=10 if family == 6 else 2, **extra)
        if r.via:
            kwargs["gateway"] = r.via
        if r.dev and r.dev in self.tun_fds:
            idx = ipr.link_lookup(ifname=r.dev)
            if idx:
                kwargs["oif"] = idx[0]
        if r.src:
            kwargs["prefsrc"] = r.src
        if r.table and r.table != 254:
            kwargs["table"] = r.table
        if r.scope:
            kwargs["scope"] = r.scope
        try:
            ipr.route("add", **kwargs)
        except (NetlinkError, OSError, ValueError):
            pass  # best-effort — collisions, bad refs, unknown tables OK
