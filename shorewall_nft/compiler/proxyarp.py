"""Proxy ARP / Proxy NDP support.

Shorewall's ``proxyarp`` and ``proxyndp`` config files declare
addresses that the firewall should publish on a different
interface — i.e. answer ARP/NDP for an IP that lives elsewhere
without doing NAT. Useful for routed bridges, transparent
deployments, IPSec passthrough, etc.

This module turns the parsed config into runnable shell snippets:

* sysctls (``net.ipv4.conf.<iface>.proxy_arp = 1`` /
  ``net.ipv6.conf.<iface>.proxy_ndp = 1``)
* ``ip -4 neigh add proxy <addr> dev <ext_iface>`` lines
  (or the v6 equivalent)
* optional ``ip route add <addr>/32 dev <iface>`` lines for the
  HAVEROUTE=no case

The shell snippets are emitted via the new
``shorewall-nft generate-proxyarp`` / ``generate-proxyndp`` CLI
subcommands, and the runtime ``start`` command applies them
automatically after loading the nft ruleset (best effort —
failures don't block start).

Config formats::

    # proxyarp
    ADDRESS  INTERFACE  EXTERNAL  HAVEROUTE  PERSISTENT
    # proxyndp
    ADDRESS  INTERFACE  EXTERNAL  HAVEROUTE  PERSISTENT
"""

from __future__ import annotations

from dataclasses import dataclass

from shorewall_nft.config.parser import ConfigLine


@dataclass
class ProxyArpEntry:
    address: str
    iface: str        # where the address actually lives (route target)
    ext_iface: str    # where to publish ARP/NDP (proxy interface)
    haveroute: bool   # True → don't add a route; False → add /32 or /128
    persistent: bool  # True → keep alive even when shorewall stops


def parse_proxyarp(lines: list[ConfigLine]) -> list[ProxyArpEntry]:
    """Parse a proxyarp / proxyndp config file into entries.

    The two files share an identical column layout, so a single
    parser handles both. Address-family detection happens at emit
    time, not here.
    """
    out: list[ProxyArpEntry] = []
    for line in lines:
        cols = line.columns
        if len(cols) < 3:
            continue
        haveroute = (
            len(cols) > 3 and cols[3] not in ("-", "no", "No", "NO", ""))
        persistent = (
            len(cols) > 4 and cols[4] in ("yes", "Yes", "YES", "1"))
        out.append(ProxyArpEntry(
            address=cols[0], iface=cols[1], ext_iface=cols[2],
            haveroute=haveroute, persistent=persistent,
        ))
    return out


def _is_v6(addr: str) -> bool:
    return ":" in addr.split("/", 1)[0]


def generate_proxyarp_sysctl(proxyarp_lines: list[ConfigLine]) -> list[str]:
    """Generate sysctl commands for proxy ARP (back-compat shim).

    Returns list of 'sysctl -w ...' commands. Kept for any
    existing callers — the structured emitter below is preferred
    for new code.
    """
    sysctls: list[str] = []
    interfaces: set[str] = set()

    for line in proxyarp_lines:
        cols = line.columns
        if len(cols) < 3:
            continue
        iface = cols[1]
        ext_iface = cols[2]
        interfaces.add(iface)
        interfaces.add(ext_iface)

    for iface in sorted(interfaces):
        sysctls.append(f"sysctl -w net.ipv4.conf.{iface}.proxy_arp=1")

    return sysctls


def apply_proxyarp(
    entries: list[ProxyArpEntry], *, netns: str | None = None,
) -> tuple[int, int, list[str]]:
    """Apply parsed proxyarp/proxyndp entries to the running kernel.

    Uses pyroute2 directly — no shelling out to ``ip`` or
    ``sysctl``. Inside an optional ``netns`` if given (so the
    netns-scoped ``shorewall-nft start --netns NAME`` works).

    For each entry the helper:

    1. Writes ``net.ipv{4,6}.conf.<iface>.proxy_arp/proxy_ndp = 1``
       on both the publishing (``ext_iface``) and the route-target
       (``iface``) interface — Shorewall does the same.
    2. Adds an NTF_PROXY neighbour entry pinning the address to
       ``ext_iface`` so the kernel answers ARP/NDP for it.
    3. If ``HAVEROUTE`` is no, installs a ``/32`` (v4) or ``/128``
       (v6) route through ``iface``.

    All operations are idempotent — neigh and route existence
    errors are swallowed and treated as success. Returns
    ``(applied, skipped, errors)`` where ``errors`` is a list of
    human-readable failure descriptions for entries that could
    not be applied (e.g. iface missing).

    The pyroute2 path is preferred over the shell snippet path
    because it survives chroots without ``ip`` / ``sysctl``
    binaries, doesn't fork per entry, and lets us run inside a
    netns via a single ``IPRoute(netns=…)`` ctor instead of
    ``ip netns exec``.
    """
    try:
        from pyroute2 import IPRoute
        from pyroute2.netlink.exceptions import NetlinkError
    except ImportError:
        return 0, 0, ["pyroute2 not installed"]

    applied = 0
    skipped = 0
    errors: list[str] = []

    # Sysctl writes are netns-aware via /proc inside the target
    # netns — we use a tiny setns() hop helper rather than
    # importing it from elsewhere because runtime/topology already
    # has its own copy and we don't want a cyclical import.
    def _sysctl_write(path: str, value: str) -> None:
        if netns is None:
            try:
                with open("/proc/sys/" + path, "w") as f:
                    f.write(value)
            except OSError:
                pass
            return
        # netns-scoped: setns + write + restore
        import ctypes
        import ctypes.util
        import os
        libc = ctypes.CDLL(
            ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        try:
            ns_fd = os.open(f"/run/netns/{netns}", os.O_RDONLY)
        except OSError:
            return
        saved = os.open("/proc/self/ns/net", os.O_RDONLY)
        try:
            if libc.setns(ns_fd, 0x40000000) != 0:
                return
            try:
                with open("/proc/sys/" + path, "w") as f:
                    f.write(value)
            except OSError:
                pass
        finally:
            libc.setns(saved, 0x40000000)
            os.close(saved)
            os.close(ns_fd)

    # 1. Sysctls — collected once per (family, iface) pair so we
    #    don't write the same key 200 times for a busy proxyarp
    #    file.
    sysctl_targets: set[tuple[int, str]] = set()
    for e in entries:
        fam = 6 if _is_v6(e.address) else 4
        sysctl_targets.add((fam, e.ext_iface))
        sysctl_targets.add((fam, e.iface))
    for fam, iface in sorted(sysctl_targets):
        if fam == 6:
            _sysctl_write(
                f"net/ipv6/conf/{iface}/proxy_ndp", "1")
        else:
            _sysctl_write(
                f"net/ipv4/conf/{iface}/proxy_arp", "1")

    # 2. + 3. Neighbour proxies and (optional) routes via netlink.
    try:
        ipr = IPRoute(netns=netns) if netns else IPRoute()
    except Exception as ex:
        return 0, len(entries), [f"IPRoute init failed: {ex}"]

    try:
        # Cache iface name → index lookups so we don't probe
        # for the same dev multiple times in a row.
        iface_idx: dict[str, int] = {}

        def _idx(name: str) -> int | None:
            if name in iface_idx:
                return iface_idx[name]
            try:
                links = ipr.link_lookup(ifname=name)
            except NetlinkError:
                return None
            if not links:
                return None
            iface_idx[name] = links[0]
            return links[0]

        for e in entries:
            fam_v6 = _is_v6(e.address)
            family_const = 10 if fam_v6 else 2  # AF_INET6/AF_INET
            ext_idx = _idx(e.ext_iface)
            if ext_idx is None:
                errors.append(
                    f"{e.address}: external iface "
                    f"{e.ext_iface} not present, skipped")
                skipped += 1
                continue

            addr = e.address.split("/", 1)[0]

            # Idempotent neigh proxy — replace works for both
            # add-fresh and update-existing cases.
            try:
                ipr.neigh(
                    "replace",
                    dst=addr,
                    ifindex=ext_idx,
                    family=family_const,
                    flags=0x08,  # NTF_PROXY
                )
            except NetlinkError as ex:
                errors.append(
                    f"{e.address}: neigh replace failed: {ex}")
                skipped += 1
                continue

            if not e.haveroute:
                int_idx = _idx(e.iface)
                if int_idx is None:
                    errors.append(
                        f"{e.address}: interior iface "
                        f"{e.iface} not present, route skipped")
                else:
                    prefix_len = 128 if fam_v6 else 32
                    try:
                        ipr.route(
                            "replace",
                            dst=f"{addr}/{prefix_len}",
                            oif=int_idx,
                            family=family_const,
                        )
                    except NetlinkError as ex:
                        errors.append(
                            f"{e.address}: route replace failed: {ex}")

            applied += 1
    finally:
        try:
            ipr.close()
        except Exception:
            pass

    return applied, skipped, errors


def remove_proxyarp(
    entries: list[ProxyArpEntry], *, netns: str | None = None,
) -> int:
    """Remove neighbour proxies / routes installed by ``apply_proxyarp``.

    Used by the runtime ``stop`` command. Entries marked
    ``persistent=True`` are kept (Shorewall semantics).
    Returns the number of entries actually removed.
    """
    try:
        from pyroute2 import IPRoute
        from pyroute2.netlink.exceptions import NetlinkError
    except ImportError:
        return 0

    removed = 0
    try:
        ipr = IPRoute(netns=netns) if netns else IPRoute()
    except Exception:
        return 0
    try:
        for e in entries:
            if e.persistent:
                continue
            fam_v6 = _is_v6(e.address)
            family_const = 10 if fam_v6 else 2
            try:
                links = ipr.link_lookup(ifname=e.ext_iface)
            except NetlinkError:
                continue
            if not links:
                continue
            ext_idx = links[0]
            addr = e.address.split("/", 1)[0]
            try:
                ipr.neigh(
                    "del",
                    dst=addr,
                    ifindex=ext_idx,
                    family=family_const,
                    flags=0x08,
                )
            except NetlinkError:
                pass
            if not e.haveroute:
                prefix_len = 128 if fam_v6 else 32
                try:
                    ipr.route(
                        "del",
                        dst=f"{addr}/{prefix_len}",
                        family=family_const,
                    )
                except NetlinkError:
                    pass
            removed += 1
    finally:
        try:
            ipr.close()
        except Exception:
            pass
    return removed


def emit_proxyarp_script(
    entries: list[ProxyArpEntry], *, family: int = 4
) -> str:
    """Render a runnable shell snippet for the parsed entries.

    ``family`` selects between proxyarp (4) and proxyndp (6).
    Entries whose address doesn't match the requested family are
    skipped silently — callers can pass a single combined entry
    list and emit both scripts.

    Output layout::

        # shorewall-nft proxyarp
        sysctl -w net.ipv4.conf.<ext>.proxy_arp=1
        ...
        ip -4 neigh replace proxy <addr> dev <ext>
        ip -4 route replace <addr>/32 dev <iface>     # only when HAVEROUTE=no
        ...

    ``replace`` (rather than ``add``) is intentional — re-running
    the script during a config reload must be idempotent.
    """
    if family not in (4, 6):
        raise ValueError(f"family must be 4 or 6, got {family}")

    fam_v6 = family == 6
    sysctl_key = "proxy_ndp" if fam_v6 else "proxy_arp"
    sysctl_root = "net.ipv6.conf" if fam_v6 else "net.ipv4.conf"
    ip_fam = "-6" if fam_v6 else "-4"
    prefix_len = "128" if fam_v6 else "32"
    label = "proxyndp" if fam_v6 else "proxyarp"

    selected = [e for e in entries if _is_v6(e.address) == fam_v6]
    if not selected:
        return ""

    lines: list[str] = [
        "#!/bin/sh",
        "# Generated by shorewall-nft — do not edit manually",
        f"# {label} runtime helper",
        "set -e",
        "",
    ]

    # Sysctls — one per unique iface (de-dup keeps the script
    # short on configs with many addresses on the same external).
    ifaces: set[str] = set()
    for e in selected:
        ifaces.add(e.ext_iface)
        # Shorewall also enables it on the interior interface so
        # the kernel ARP-stuffing actually fires there.
        ifaces.add(e.iface)
    for i in sorted(ifaces):
        lines.append(f"sysctl -wq {sysctl_root}.{i}.{sysctl_key}=1 || true")
    lines.append("")

    for e in selected:
        addr = e.address.split("/", 1)[0]
        lines.append(
            f"ip {ip_fam} neigh replace proxy {addr} dev {e.ext_iface}")
        if not e.haveroute:
            lines.append(
                f"ip {ip_fam} route replace {addr}/{prefix_len} "
                f"dev {e.iface}")
    lines.append("")
    return "\n".join(lines)
