"""Packet-level firewall simulation with 3 network namespaces.

Validates that the compiled nft ruleset actually accepts/drops packets
as the iptables baseline says it should. This catches rule-ordering
bugs that the static verifier misses.

Topology:
    shorewall-next-sim-src  ←veth→  shorewall-next-sim-fw  ←veth→  shorewall-next-sim-dst
    (source)                        (firewall)                     (destination)

Uses sudo /usr/local/bin/run-netns for all namespace operations.
"""

from __future__ import annotations

import os
import random
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

RUN_NETNS = ["sudo", "/usr/local/bin/run-netns"]

NS_SRC = "shorewall-next-sim-src"
NS_FW = "shorewall-next-sim-fw"
NS_DST = "shorewall-next-sim-dst"

# Multi-zone slave namespace name pattern. Each zone in the test
# topology gets its own NS_SLAVE_PREFIX + zone_name namespace, with
# a single veth pair to NS_FW. The FW-side end of the veth is renamed
# to the zone's actual iface name so nft rules match it; the slave-side
# end stays "fw" inside the slave.
NS_SLAVE_PREFIX = "sw-z-"

def slave_ns(zone_name: str) -> str:
    """Return the slave-namespace name for a zone."""
    # netns names cap out at IFNAMSIZ (16 chars). With the prefix at
    # 5 chars we have 11 chars for the zone name — long enough for
    # marcant-style zones.
    return f"{NS_SLAVE_PREFIX}{zone_name[:11]}"

# Topology addressing — IPv4
SRC_FW_GW = "10.200.1.1"
SRC_PEER = "10.200.1.2"
SRC_IFACE_DEFAULT = "bond1"       # default net-zone interface
DST_FW_GW = "10.200.2.1"
DST_PEER = "10.200.2.2"
DST_IFACE_DEFAULT = "bond0.20"    # default host-zone interface
DEFAULT_SRC = "192.0.2.69"

# Topology addressing — IPv6 (dual-stack on the same veths)
SRC_FW_GW6 = "fd00:200:1::1"
SRC_PEER6 = "fd00:200:1::2"
DST_FW_GW6 = "fd00:200:2::1"
DST_PEER6 = "fd00:200:2::2"
DEFAULT_SRC6 = "2001:db8::69"

# Back-compat aliases (some callers still import these names)
SRC_IFACE = SRC_IFACE_DEFAULT
DST_IFACE = DST_IFACE_DEFAULT


@dataclass
class TestCase:
    """A single packet test."""
    src_ip: str
    dst_ip: str
    proto: Literal["tcp", "udp", "icmp", "vrrp", "esp", "ah", "gre"]
    port: int | None
    expected: Literal["ACCEPT", "DROP", "REJECT"]
    family: int = 4  # 4 or 6
    src_zone: str | None = None
    dst_zone: str | None = None
    raw: str = ""


# Map proto names / numeric ids that the iptables-save dump uses
# onto our internal proto labels. derive_tests_all_zones consults
# this so a rule with ``-p 112`` or ``-p vrrp`` produces a probe
# even though our TestCase Literal is otherwise tcp/udp/icmp-only.
_PROTO_ALIAS: dict[str, str] = {
    "112": "vrrp",
    "vrrp": "vrrp",
    "50": "esp",
    "esp": "esp",
    "51": "ah",
    "ah": "ah",
    "47": "gre",
    "gre": "gre",
}


@dataclass
class TestResult:
    test: TestCase
    got: str  # ACCEPT or DROP
    passed: bool
    ms: int = 0


def _ns(ns: str, cmd: str, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a shell command inside a network namespace.

    Exec-reduction Phase B: instead of shelling out via
    ``ip netns exec NS sh -c CMD`` (two extra fork+execs), we use a
    ``preexec_fn`` that calls ``setns(CLONE_NEWNET)`` on
    ``/run/netns/<ns>`` right after fork and before exec. The child
    lands in the target namespace directly; the parent's namespace
    stays untouched. One less fork, no iproute2 binary dependency.
    """
    ns_path = f"/run/netns/{ns}"

    def _enter_ns() -> None:  # runs in child, post-fork, pre-exec
        import ctypes
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        _CLONE_NEWNET = 0x40000000
        fd = os.open(ns_path, os.O_RDONLY)
        try:
            if _libc.setns(fd, _CLONE_NEWNET) != 0:
                raise OSError(ctypes.get_errno(), "setns failed")
        finally:
            os.close(fd)

    return subprocess.run(
        ["sh", "-c", cmd],
        capture_output=True, text=True, timeout=timeout,
        preexec_fn=_enter_ns,
    )


def _ns_check(ns: str, cmd: str, timeout: int = 10) -> None:
    """Run a command inside a namespace, raise on failure."""
    r = _ns(ns, cmd, timeout)
    if r.returncode != 0:
        raise RuntimeError(f"Command failed in {ns}: {cmd}\n{r.stderr}")


def _kill_ns_pids(ns: str) -> None:
    """SIGKILL every pid whose net namespace matches ``ns``.

    Exec-reduction Phase B: replaces ``ip netns pids NS`` with a
    direct /proc scan. For each pid, read the inode of
    ``/proc/<pid>/ns/net`` and compare against ``/run/netns/<name>``.
    Matching pids get SIGKILL'd. No subprocess, no iproute2
    dependency, and much faster than fork+exec for large pid
    spaces because we only stat — no exec of ``ip``.

    Never targets ``kill -9 -1`` in-namespace (that would reach host
    processes since ip netns doesn't isolate PIDs).
    """
    try:
        target_inode = os.stat(f"/run/netns/{ns}").st_ino
    except (OSError, FileNotFoundError):
        return
    try:
        pid_entries = os.listdir("/proc")
    except OSError:
        return
    for entry in pid_entries:
        if not entry.isdigit():
            continue
        try:
            pid_ns_inode = os.stat(f"/proc/{entry}/ns/net").st_ino
        except (OSError, FileNotFoundError, PermissionError):
            continue
        if pid_ns_inode != target_inode:
            continue
        try:
            os.kill(int(entry), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


class SimTopology:
    """Manages the 3-namespace simulation topology (pyroute2-backed)."""

    def __init__(self, src_iface: str = SRC_IFACE_DEFAULT,
                 dst_iface: str = DST_IFACE_DEFAULT,
                 zones: dict[str, str] | None = None):
        """Create a topology manager.

        src_iface / dst_iface: single-pair legacy mode (one src zone,
            one dst zone).
        zones: multi-zone mode — mapping of zone_name → iface_name.
            When present, setup_src_multi / setup_dst_multi can be
            called and the single-pair setup_src / setup_dst methods
            delegate to them.
        """
        from shorewall_nft.verify.netns_topology import NetnsTopology

        self.src_iface = src_iface
        self.dst_iface = dst_iface
        self.zones: dict[str, str] = zones or {}
        # Deterministic /30 + /64 slots per zone, cached.
        self._zone_subnets: dict[str, tuple[str, str, str, str]] = {}
        self._zone_table_ids: dict[str, int] = {}
        # Slave namespaces created in setup_zone_slaves()
        self._slave_ns_names: list[str] = []
        # Fork-worker process + parent-side Pipe per slave zone.
        # Keyed by zone_name, not ns_name, so test runner dispatch
        # can look up directly via tc.src_zone.
        self._slave_workers: dict[str, tuple[Any, Any]] = {}
        self._slave_worker_lock = None  # created lazily — threading.Lock

        self.src_ips: list[str] = []
        self.src_ips6: list[str] = []
        self.dst_ips: list[str] = []
        self.dst_ips6: list[str] = []
        self._created = False
        self._listener_pids: list[int] = []

        self._net = NetnsTopology()

    def create(self) -> None:
        """Create the 3 test namespaces (idempotent).

        All three fds are opened before any pyroute2.NetNS handle is
        constructed so helper-process forks inherit them (needed for
        link_set_netns later on).
        """
        # 1. Create + pre-open fds for all 3 netns
        for ns_name in (NS_SRC, NS_FW, NS_DST):
            self._net.ns_create(ns_name)
        # 2. Now construct NetNS handles lazily — any fork happens
        #    after the fds above are already open in this process.
        self._net.link_up(NS_FW, "lo")
        self._net.link_up(NS_SRC, "lo")
        self._net.link_up(NS_DST, "lo")
        self._net.sysctl_set(NS_FW, "net/ipv4/ip_forward", "1")
        self._net.sysctl_set(NS_FW, "net/ipv6/conf/all/forwarding", "1")
        self._net.sysctl_set(NS_FW, "net/ipv4/conf/all/rp_filter", "0")
        self._net.sysctl_set(NS_FW, "net/ipv4/conf/default/rp_filter", "0")
        self._created = True

    def _zone_subnet(self, zone_name: str, side: str) -> tuple[str, str, str, str]:
        """Stable per-zone /30 + /64 slots for multi-zone mode.

        Returns (peer4, fw_gw4, peer6, fw_gw6).
        """
        key = f"{side}:{zone_name}"
        cached = self._zone_subnets.get(key)
        if cached:
            return cached
        h = abs(hash(zone_name)) % 4000
        third = 201 if side == "src" else 202
        base = f"10.{third}.{h // 64}.{(h % 64) * 4}"
        octets = base.split(".")
        fw_gw4 = f"10.{third}.{octets[2]}.{int(octets[3]) + 1}"
        peer4 = f"10.{third}.{octets[2]}.{int(octets[3]) + 2}"
        base6 = f"fd00:{third}:{h:x}::"
        fw_gw6 = f"{base6}1"
        peer6 = f"{base6}2"
        tup = (peer4, fw_gw4, peer6, fw_gw6)
        self._zone_subnets[key] = tup
        return tup

    def setup_src(self, src_ips: list[str], src_ips6: list[str] | None = None) -> None:
        """Set up the source namespace with a dual-stack veth to fw.

        Single-pair form: one veth pair with legacy 10.200.1.0/30
        addressing. Multi-zone callers should use setup_src_multi.
        """
        self.src_ips = src_ips
        self.src_ips6 = src_ips6 or []
        net = self._net

        net.veth_add_peer(NS_FW, "src-fw-tmp", "src-z")
        net.link_set_netns(NS_FW, "src-z", NS_SRC)
        net.link_rename(NS_FW, "src-fw-tmp", self.src_iface)
        net.addr_add(NS_FW, self.src_iface, SRC_FW_GW, 30, family=4)
        net.addr_add(NS_FW, self.src_iface, SRC_FW_GW6, 64, family=6)
        net.link_up(NS_FW, self.src_iface)
        net.sysctl_set(
            NS_FW, ["net", "ipv4", "conf", self.src_iface, "rp_filter"], "0")

        for ip in [DEFAULT_SRC] + src_ips:
            net.route_add(NS_FW, f"{ip}/32", dev=self.src_iface, family=4)
        for ip in [DEFAULT_SRC6] + self.src_ips6:
            net.route_add(NS_FW, f"{ip}/128", dev=self.src_iface, family=6)

        net.link_up(NS_SRC, "src-z")
        net.addr_add(NS_SRC, "src-z", SRC_PEER, 30, family=4)
        net.addr_add(NS_SRC, "src-z", SRC_PEER6, 64, family=6)
        net.route_add(NS_SRC, "default", gw=SRC_FW_GW, family=4)
        net.route_add(NS_SRC, "default", gw=SRC_FW_GW6, family=6)
        net.addr_add(NS_SRC, "src-z", DEFAULT_SRC, 32, family=4)
        net.addr_add(NS_SRC, "src-z", DEFAULT_SRC6, 128, family=6)
        for ip in src_ips:
            if ip != DEFAULT_SRC:
                net.addr_add(NS_SRC, "src-z", ip, 32, family=4)
        for ip in self.src_ips6:
            if ip != DEFAULT_SRC6:
                net.addr_add(NS_SRC, "src-z", ip, 128, family=6)

    def setup_dst(self, dst_ips: list[str], dst_ips6: list[str] | None = None) -> None:
        """Set up the destination namespace with a dual-stack veth to fw."""
        self.dst_ips = dst_ips
        self.dst_ips6 = dst_ips6 or []
        net = self._net

        net.veth_add_peer(NS_FW, "dst-fw-tmp", "dst-z")
        net.link_set_netns(NS_FW, "dst-z", NS_DST)
        net.link_rename(NS_FW, "dst-fw-tmp", self.dst_iface)
        net.addr_add(NS_FW, self.dst_iface, DST_FW_GW, 30, family=4)
        net.addr_add(NS_FW, self.dst_iface, DST_FW_GW6, 64, family=6)
        net.link_up(NS_FW, self.dst_iface)
        net.sysctl_set(
            NS_FW, ["net", "ipv4", "conf", self.dst_iface, "rp_filter"], "0")

        for ip in dst_ips:
            net.route_add(NS_FW, f"{ip}/32", dev=self.dst_iface, family=4)
        for ip in self.dst_ips6:
            net.route_add(NS_FW, f"{ip}/128", dev=self.dst_iface, family=6)

        net.link_up(NS_DST, "dst-z")
        net.addr_add(NS_DST, "dst-z", DST_PEER, 30, family=4)
        net.addr_add(NS_DST, "dst-z", DST_PEER6, 64, family=6)
        net.route_add(NS_DST, "default", gw=DST_FW_GW, family=4)
        net.route_add(NS_DST, "default", gw=DST_FW_GW6, family=6)
        for ip in dst_ips:
            net.addr_add(NS_DST, "dst-z", ip, 32, family=4)
        for ip in self.dst_ips6:
            net.addr_add(NS_DST, "dst-z", ip, 128, family=6)

    # ── Multi-zone slave model ──────────────────────────────────────
    #
    # One slave namespace per zone with:
    #   - dual-stack veth pair to NS_FW (FW side renamed to zone iface)
    #   - source IPs bound on the slave-side veth so probes egress
    #   - dest IPs bound on the slave-side veth too — REDIRECT in the
    #     slave's nft prerouting hook catches incoming traffic and
    #     hands it to the local listener
    #   - a python listener that accepts TCP 65000 + UDP 65001 echo
    #
    # Test runner picks the slave matching tc.src_zone and execs nc
    # there. Reply traffic comes back through the FW; conntrack reverses
    # the REDIRECT NAT.

    def setup_zone_slaves(
        self,
        zone_src_ips: dict[str, list[str]],
        zone_dst_ips: dict[str, list[str]],
        zone_src_ips6: dict[str, list[str]] | None = None,
        zone_dst_ips6: dict[str, list[str]] | None = None,
    ) -> None:
        """Build the multi-zone slave topology.

        zone_src_ips / zone_dst_ips: {zone_name: [ip, ip, ...]} — IPs
        bound on the corresponding zone's slave namespace.
        """
        zone_src_ips6 = zone_src_ips6 or {}
        zone_dst_ips6 = zone_dst_ips6 or {}

        net = self._net

        # 1. Create + pre-open all slave netns FDs BEFORE any NetNS handle
        #    is forked, so the helper child processes inherit them.
        for zone_name in self.zones:
            net.ns_create(slave_ns(zone_name))
        # NS_FW (and NS_SRC/NS_DST) NetNS handles were forked in create()
        # before the slave fds existed. Drop and recreate so subsequent
        # link_set_netns calls work.
        net.refresh_handles()

        # 2. Build per-zone veth + addrs + REDIRECT + listener.
        for zone_name, iface in self.zones.items():
            slave = slave_ns(zone_name)
            peer4, fw_gw4, peer6, fw_gw6 = self._zone_subnet(zone_name, "src")
            slave_iface = "fw"  # slave-side veth name

            net.link_up(slave, "lo")

            # Veth pair: created in NS_FW, one end moved to slave
            net.veth_add_peer(NS_FW, "tmp-fw", "tmp-sl")
            net.link_set_netns(NS_FW, "tmp-sl", slave)
            net.link_rename(NS_FW, "tmp-fw", iface)
            net.link_rename(slave, "tmp-sl", slave_iface)
            net.addr_add(NS_FW, iface, fw_gw4, 30, family=4)
            net.addr_add(NS_FW, iface, fw_gw6, 64, family=6)
            net.link_up(NS_FW, iface)
            net.sysctl_set(
                NS_FW, ["net", "ipv4", "conf", iface, "rp_filter"], "0")

            net.link_up(slave, slave_iface)
            net.addr_add(slave, slave_iface, peer4, 30, family=4)
            net.addr_add(slave, slave_iface, peer6, 64, family=6)
            net.sysctl_set(
                slave, ["net", "ipv4", "conf", "all", "rp_filter"], "0")
            net.sysctl_set(
                slave, ["net", "ipv4", "conf", slave_iface, "rp_filter"], "0")
            # Default route in slave: back via FW
            net.route_add(slave, "default", gw=fw_gw4, family=4)
            net.route_add(slave, "default", gw=fw_gw6, family=6)

            # Bind source IPs as /32 aliases. Probes from this slave
            # use these as their source.
            for ip in zone_src_ips.get(zone_name, []):
                net.addr_add(slave, slave_iface, ip, 32, family=4)
            for ip in zone_src_ips6.get(zone_name, []):
                net.addr_add(slave, slave_iface, ip, 128, family=6)

            # Bind destination IPs too — they live HERE so the
            # listener (after REDIRECT) can serve them.
            for ip in zone_dst_ips.get(zone_name, []):
                net.addr_add(slave, slave_iface, ip, 32, family=4)
            for ip in zone_dst_ips6.get(zone_name, []):
                net.addr_add(slave, slave_iface, ip, 128, family=6)

            # FW-side: routes for spoofed src IPs (return path) and
            # for dst IPs (forward path), both via the slave's peer.
            for ip in zone_src_ips.get(zone_name, []):
                net.route_add(NS_FW, f"{ip}/32", gw=peer4, family=4)
            for ip in zone_src_ips6.get(zone_name, []):
                net.route_add(NS_FW, f"{ip}/128", gw=peer6, family=6)
            for ip in zone_dst_ips.get(zone_name, []):
                net.route_add(NS_FW, f"{ip}/32", gw=peer4, family=4)
            for ip in zone_dst_ips6.get(zone_name, []):
                net.route_add(NS_FW, f"{ip}/128", gw=peer6, family=6)

            # 3. nft REDIRECT inside the slave: catch every TCP/UDP
            #    packet arriving on the veth and rewrite dst → 127.0.0.1
            #    so the local listener handles it without needing
            #    /32 routes for every individual dst IP.
            self._install_slave_redirect(slave)

        # Track slaves so destroy() can clean them up.
        self._slave_ns_names = [slave_ns(z) for z in self.zones]

        # 4. Spawn one worker process per zone (fork, no exec). Each
        #    worker setns()'s into its slave and runs native Python
        #    listeners + on-demand probes over an mp.Pipe. All test
        #    traffic uses the socket API from here on — no nc / ping.
        #
        # Drop cached pyroute2 NetNS helper handles BEFORE forking so
        # the worker children don't inherit live netlink sockets that
        # both parent and child would try to use.
        self._net.refresh_handles()
        import threading

        from shorewall_nft.verify.slave_worker import spawn_worker
        self._slave_worker_lock = threading.Lock()
        for zone_name in self.zones:
            slave = slave_ns(zone_name)
            proc, conn = spawn_worker(slave)
            self._slave_workers[zone_name] = (proc, conn)

    def _install_slave_redirect(self, slave: str) -> None:
        """Load a tiny nft REDIRECT rule into a slave namespace."""
        nft_script = (
            "table inet sw_redir { }\n"
            "delete table inet sw_redir\n"
            "table inet sw_redir {\n"
            "  chain pre {\n"
            "    type nat hook prerouting priority dstnat;\n"
            "    meta l4proto tcp redirect to :65000\n"
            "    meta l4proto udp redirect to :65001\n"
            "  }\n"
            "}\n"
        )
        self._net.exec_in_ns(slave, ["nft", "-f", "-"],
                             timeout=10, capture_output=True)
        # nft -f - via subprocess.run can't take stdin via Popen here;
        # use a temp file.
        import tempfile
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".nft", delete=False,
                prefix="sw-slave-redir-") as f:
            f.write(nft_script)
            path = f.name
        try:
            r = self._net.exec_in_ns(slave, ["nft", "-f", path], timeout=10)
            if r.returncode != 0:
                print(f"  WARNING: slave {slave} REDIRECT install failed: "
                      f"{r.stderr[:200]}")
        finally:
            Path(path).unlink(missing_ok=True)

    def probe(self, tc: "TestCase", timeout_s: float = 2.0) -> "TestResult":
        """Run a single probe via the slave worker for tc.src_zone.

        Uses the persistent fork-worker's pipe connection — zero fork
        cost per probe, pure Python socket API on the worker side.
        Falls back to a DROP result if the worker is missing.
        """
        worker = self._slave_workers.get(tc.src_zone or "")
        if worker is None:
            return TestResult(test=tc, got="DROP", passed=False, ms=0)
        proc, conn = worker
        start = time.monotonic_ns()
        # Serialise pipe access — mp.Pipe isn't thread-safe.
        with self._slave_worker_lock:
            try:
                conn.send((
                    "probe", tc.proto, tc.src_ip, tc.dst_ip,
                    tc.port or 0, tc.family, float(timeout_s),
                ))
                msg = conn.recv()
            except (BrokenPipeError, EOFError, ConnectionError):
                ms = (time.monotonic_ns() - start) // 1_000_000
                return TestResult(test=tc, got="ERROR", passed=False, ms=ms)
        ms = (time.monotonic_ns() - start) // 1_000_000
        if not msg or msg[0] != "ok":
            return TestResult(test=tc, got="ERROR", passed=False, ms=ms)
        _, verdict, _ = msg
        return TestResult(test=tc, got=verdict,
                          passed=(verdict == tc.expected), ms=ms)

    def setup_src_multi(self, zone_src_ips: dict[str, list[str]],
                        zone_src_ips6: dict[str, list[str]] | None = None) -> None:
        """Create one veth pair per source zone in the FW netns.

        Uses the zones dict passed to __init__ to map zone → iface.
        Each zone gets its own /30 in 10.201.0.0/16 and its own /64
        in fd00:201:..::/64 so routes remain independent.

        Spoofed source IPs are bound to the zone-matching leg inside
        NS_SRC; `ping -I <src_ip>` then egresses through the right
        veth because the IP is only reachable from that interface.
        """
        zone_src_ips6 = zone_src_ips6 or {}
        net = self._net
        self.src_ips = [ip for ips in zone_src_ips.values() for ip in ips]
        self.src_ips6 = [ip for ips in zone_src_ips6.values() for ip in ips]

        for zone_name, src_ips in zone_src_ips.items():
            iface = self.zones.get(zone_name)
            if not iface:
                continue
            peer4, fw_gw4, peer6, fw_gw6 = self._zone_subnet(zone_name, "src")
            leg_name = f"szl-{zone_name[:10]}"

            # Veth: FW-side temp name, NS_SRC-side final name
            net.veth_add_peer(NS_FW, "src-fw-tmp", leg_name)
            net.link_set_netns(NS_FW, leg_name, NS_SRC)
            net.link_rename(NS_FW, "src-fw-tmp", iface)
            net.addr_add(NS_FW, iface, fw_gw4, 30, family=4)
            net.addr_add(NS_FW, iface, fw_gw6, 64, family=6)
            net.link_up(NS_FW, iface)
            net.sysctl_set(NS_FW, ["net", "ipv4", "conf", iface, "rp_filter"], "0")

            for ip in src_ips:
                net.route_add(NS_FW, f"{ip}/32", dev=iface, family=4)
            for ip in zone_src_ips6.get(zone_name, []):
                net.route_add(NS_FW, f"{ip}/128", dev=iface, family=6)

            net.link_up(NS_SRC, leg_name)
            net.addr_add(NS_SRC, leg_name, peer4, 30, family=4)
            net.addr_add(NS_SRC, leg_name, peer6, 64, family=6)
            for ip in src_ips:
                net.addr_add(NS_SRC, leg_name, ip, 32, family=4)
            for ip in zone_src_ips6.get(zone_name, []):
                net.addr_add(NS_SRC, leg_name, ip, 128, family=6)

            # Per-zone routing table + policy rule: traffic sourced
            # from a src IP in this zone leaves NS_SRC through the
            # correct leg regardless of what the main table says.
            tid = 100 + len(self._zone_table_ids)
            self._zone_table_ids[zone_name] = tid
            net.route_add(
                NS_SRC, "default", gw=fw_gw4, dev=leg_name,
                family=4, table=tid)
            net.route_add(
                NS_SRC, "default", gw=fw_gw6, dev=leg_name,
                family=6, table=tid)
            for ip in src_ips:
                net.rule_add(NS_SRC, ip, table=tid, family=4)
            for ip in zone_src_ips6.get(zone_name, []):
                net.rule_add(NS_SRC, ip, table=tid, family=6)

    def setup_dst_multi(self, zone_dst_ips: dict[str, list[str]],
                        zone_dst_ips6: dict[str, list[str]] | None = None) -> None:
        """Register destination IPs in the multi-zone topology.

        In multi-zone mode we collapse NS_SRC and NS_DST into a single
        "peer" namespace so the same zone (e.g. `host`) can serve both
        as src and dst without needing two separate veths in the FW
        netns for the same iface name (which would conflict with the
        nft ruleset's literal iifname/oifname matches).

        Destination IPs are bound on the zone's existing leg inside
        NS_SRC — setup_src_multi must have already created the leg.
        Listeners run in NS_SRC as well.
        """
        zone_dst_ips6 = zone_dst_ips6 or {}
        net = self._net
        self.dst_ips = [ip for ips in zone_dst_ips.values() for ip in ips]
        self.dst_ips6 = [ip for ips in zone_dst_ips6.values() for ip in ips]

        for zone_name, dst_ips in zone_dst_ips.items():
            iface = self.zones.get(zone_name)
            if not iface:
                continue
            leg_name = f"szl-{zone_name[:10]}"

            # Leg must already exist from setup_src_multi. If not, the
            # zone never showed up as a src_zone in any test case and
            # we'd need to create the leg ourselves. Do it now as a
            # "dst-only" zone — same subnet slots under "src" so the
            # iface stays unique per zone.
            peer4, fw_gw4, peer6, fw_gw6 = self._zone_subnet(zone_name, "src")
            if net._link_index(NS_SRC, leg_name) is None:
                net.veth_add_peer(NS_FW, "dst-fw-tmp", leg_name)
                net.link_set_netns(NS_FW, leg_name, NS_SRC)
                net.link_rename(NS_FW, "dst-fw-tmp", iface)
                net.addr_add(NS_FW, iface, fw_gw4, 30, family=4)
                net.addr_add(NS_FW, iface, fw_gw6, 64, family=6)
                net.link_up(NS_FW, iface)
                net.sysctl_set(
                    NS_FW, ["net", "ipv4", "conf", iface, "rp_filter"], "0")
                net.link_up(NS_SRC, leg_name)
                net.addr_add(NS_SRC, leg_name, peer4, 30, family=4)
                net.addr_add(NS_SRC, leg_name, peer6, 64, family=6)
                net.route_add(NS_SRC, f"{fw_gw4}/32", dev=leg_name, family=4)

            # Destination IPs: route via iface in FW. Do NOT bind locally
            # in NS_SRC — that would turn outgoing traffic into loopback
            # and skip the FW entirely. Instead, REDIRECT catches the
            # packet when it arrives on dst-leg and sends it to the
            # local listener (see setup_listeners iptables rules).
            for ip in dst_ips:
                net.route_add(NS_FW, f"{ip}/32", dev=iface, family=4)
            for ip in zone_dst_ips6.get(zone_name, []):
                net.route_add(NS_FW, f"{ip}/128", dev=iface, family=6)

    def setup_fw(self, nft_script_path: str) -> None:
        """Load nft ruleset in fw namespace (sysctls already done in create()).

        Any non-zero return from nft -f aborts the simulation. Previously
        the legacy code only raised on "syntax error" substrings and
        printed a WARNING for everything else, which silently turned
        simulate runs into pure topology smoke tests when the ruleset
        failed to load — every probe appeared to fail even though the
        FW was empty.
        """
        r = _ns(NS_FW, f"nft -f {nft_script_path}", timeout=30)
        if r.returncode != 0:
            # Any non-zero nft return aborts simulate — a half-loaded
            # ruleset makes every probe look like a DROP. Previously
            # this only raised on "syntax error" text and silently
            # warned on everything else, turning simulate into a
            # topology smoke test whenever nft complained.
            raise RuntimeError(
                f"nft -f failed (rc={r.returncode}) in {NS_FW}:\n"
                f"{r.stderr[:2000]}"
            )

    def setup_listeners(self) -> None:
        """Start TCP and UDP listeners on destination, set up REDIRECT (v4+v6).

        In multi-zone mode the listeners run in NS_SRC because that's
        where destination IPs are bound (both sides of every flow live
        in the same "peer" namespace to avoid iface-name collisions).
        In single-pair mode they stay in NS_DST as before.
        """
        listener_ns = NS_SRC if self.zones else NS_DST
        _ns(listener_ns,
            "iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port 65000 2>/dev/null || true")
        _ns(listener_ns,
            "iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-port 65001 2>/dev/null || true")
        _ns(listener_ns,
            "ip6tables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port 65000 2>/dev/null || true")
        _ns(listener_ns,
            "ip6tables -t nat -A PREROUTING -p udp -j REDIRECT --to-port 65001 2>/dev/null || true")

        # TCP listener — dual-stack via ncat if available, else two nc instances
        _ns(listener_ns, "nc -l -k -p 65000 >/dev/null 2>&1 &")
        _ns(listener_ns, "nc -l -k -p 65000 -s ::0 >/dev/null 2>&1 &")

        # UDP echo server — single python process binds both families
        _ns(listener_ns, """python3 -c "
import socket, threading
def echo(fam, addr):
    s = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        s.bind((addr, 65001))
    except OSError:
        return
    while True:
        data, peer = s.recvfrom(1024)
        s.sendto(b'PONG', peer)
threading.Thread(target=echo, args=(socket.AF_INET, '0.0.0.0'), daemon=True).start()
threading.Thread(target=echo, args=(socket.AF_INET6, '::'), daemon=True).start()
import time
while True: time.sleep(60)
" >/dev/null 2>&1 &""")

    def destroy(self) -> None:
        """Kill all processes and remove all namespaces."""
        # Stop fork-workers first — quit msg + join, no exec cleanup.
        for zone_name, (proc, conn) in list(self._slave_workers.items()):
            try:
                conn.send(("quit",))
            except Exception:
                pass
            try:
                proc.join(timeout=2)
            except Exception:
                pass
            if proc.is_alive():
                try:
                    proc.terminate()
                    proc.join(timeout=1)
                except Exception:
                    pass
            try:
                conn.close()
            except Exception:
                pass
        self._slave_workers.clear()

        # Slave namespaces (multi-zone mode)
        for slave in list(self._slave_ns_names):
            _kill_ns_pids(slave)
            time.sleep(0.05)
            self._net.ns_delete(slave)
        self._slave_ns_names.clear()
        # Legacy single-pair namespaces
        for ns in (NS_DST, NS_FW, NS_SRC):
            _kill_ns_pids(ns)
            time.sleep(0.1)
            self._net.ns_delete(ns)
        try:
            self._net.close()
        except Exception:
            pass
        self._created = False


def run_tcp_test(src_ip: str, dst_ip: str, port: int, family: int = 4,
                 ns_name: str = NS_SRC) -> tuple[str, int]:
    """Send a TCP connect test. Returns (verdict, ms)."""
    start = time.monotonic_ns()
    flag = "-6" if family == 6 else "-4"
    r = _ns(ns_name, f"nc {flag} -z -w 2 -s {src_ip} {dst_ip} {port} 2>/dev/null",
            timeout=5)
    ms = (time.monotonic_ns() - start) // 1_000_000
    verdict = "ACCEPT" if r.returncode == 0 else "DROP"
    return verdict, ms


def run_udp_test(src_ip: str, dst_ip: str, port: int, family: int = 4,
                 ns_name: str = NS_SRC) -> tuple[str, int]:
    """Send a UDP echo test. Returns (verdict, ms)."""
    start = time.monotonic_ns()
    flag = "-6" if family == 6 else "-4"
    r = _ns(ns_name,
            f"echo PING | timeout 2 nc {flag} -u -w 1 -s {src_ip} {dst_ip} {port} 2>/dev/null",
            timeout=5)
    ms = (time.monotonic_ns() - start) // 1_000_000
    verdict = "ACCEPT" if "PONG" in (r.stdout or "") else "DROP"
    return verdict, ms


def run_icmp_test(src_ip: str, dst_ip: str, family: int = 4,
                  ns_name: str = NS_SRC) -> tuple[str, int]:
    """Send an ICMP echo request. Returns (verdict, ms)."""
    start = time.monotonic_ns()
    cmd = "ping6" if family == 6 else "ping"
    r = _ns(ns_name, f"{cmd} -c 1 -W 2 -I {src_ip} {dst_ip} 2>/dev/null",
            timeout=5)
    ms = (time.monotonic_ns() - start) // 1_000_000
    verdict = "ACCEPT" if r.returncode == 0 else "DROP"
    return verdict, ms


def _run_single_test(tc: TestCase, ns_name: str = NS_SRC,
                     topo: "SimTopology | None" = None) -> TestResult:
    """Run a single test case. Suitable for parallel execution.

    In multi-zone mode (``topo.zones`` non-empty) the probe is
    dispatched to the persistent worker process bound to the
    matching src_zone slave namespace. That avoids forking ``nc``
    for every test case.
    """
    if topo is not None and topo.zones and tc.src_zone in topo.zones:
        return topo.probe(tc)

    start = time.monotonic_ns()
    try:
        if tc.proto == "tcp":
            got, ms = run_tcp_test(tc.src_ip, tc.dst_ip, tc.port,
                                    family=tc.family, ns_name=ns_name)
        elif tc.proto == "udp":
            got, ms = run_udp_test(tc.src_ip, tc.dst_ip, tc.port,
                                    family=tc.family, ns_name=ns_name)
        elif tc.proto == "icmp":
            got, ms = run_icmp_test(tc.src_ip, tc.dst_ip,
                                     family=tc.family, ns_name=ns_name)
        else:
            got, ms = "SKIP", 0
    except Exception:
        got, ms = "ERROR", 0

    return TestResult(test=tc, got=got, passed=(got == tc.expected), ms=ms)


def derive_tests_all_zones(
    iptables_dump: Path,
    zones: set[str],
    max_tests: int = 40,
    seed: int | None = 42,
    family: int = 4,
    random_per_rule: int = 1,
) -> list[TestCase]:
    """Derive test cases across every (src_zone, dst_zone) chain in the dump.

    Unlike :func:`derive_tests`, this walks the entire filter table and
    picks up rules in any chain whose name parses as ``<src>2<dst>``
    with both sides in ``zones``. Each generated TestCase carries its
    ``src_zone`` and ``dst_zone`` annotations so the simulate runtime
    knows which veth leg to bind.

    Per-pair budget is ``max_tests`` sampled stochastically, with
    DROP/REJECT rules prioritised (they're the interesting security
    properties; ACCEPT rules are the common case).
    """
    from shorewall_nft.verify.iptables_parser import parse_iptables_save

    ipt = parse_iptables_save(iptables_dump)
    flt = ipt.get("filter")
    if not flt:
        return []

    rng = random.Random(seed)
    per_pair: dict[tuple[str, str], list[TestCase]] = {}

    default_src = DEFAULT_SRC6 if family == 6 else DEFAULT_SRC

    for chain_name, rules in flt.rules.items():
        src_zone, dst_zone = _split_chain_zones(chain_name)
        if src_zone is None or dst_zone is None:
            continue
        if src_zone not in zones or dst_zone not in zones:
            continue
        pair = (src_zone, dst_zone)

        for rule in rules:
            if "--ctstate" in rule.raw or "--ctstatus" in rule.raw:
                continue
            if rule.target not in ("ACCEPT", "DROP", "REJECT"):
                continue
            # Translate proto aliases (e.g. "112" → "vrrp",
            # "50" → "esp", "47" → "gre", "51" → "ah"). Anything
            # not in the alias map is passed through verbatim — the
            # simlab dispatch resolves arbitrary names/numbers via
            # ``packets.proto_number()``.
            rule_proto = _PROTO_ALIAS.get(rule.proto, rule.proto)
            # tcp/udp/icmp keep their dedicated builders. Everything
            # else falls through to ``build_unknown_proto`` and is
            # accepted here as long as the dispatch can resolve it
            # to a number at probe-build time.
            from shorewall_nft_simlab.packets import proto_number
            if rule_proto not in ("tcp", "udp", "icmp"):
                if proto_number(rule_proto) is None:
                    continue
            # VRRP / OSPF / IGMP are multicast — there's no daddr
            # in the rule (the kernel matches the well-known
            # multicast group implicitly). Generate one probe per
            # matching rule using the source pool only and let the
            # simlab builder set the multicast destination.
            multicast_protos = {"vrrp", "ospf", "igmp", "pim"}
            if rule_proto not in multicast_protos and not rule.daddr:
                continue

            import ipaddress as _ipaddr
            raw_daddr = rule.daddr
            # Multicast destinations for known protocols. Falls
            # back to the all-routers multicast (224.0.0.2 / ff02::2)
            # for anything else that needs a placeholder dst.
            _MCAST_DST = {
                "vrrp": ("224.0.0.18", "ff02::12"),
                "ospf": ("224.0.0.5", "ff02::5"),
                "igmp": ("224.0.0.1", "ff02::1"),
                "pim":  ("224.0.0.13", "ff02::d"),
            }
            if rule_proto in _MCAST_DST and not raw_daddr:
                v4, v6 = _MCAST_DST[rule_proto]
                daddr_clean = v6 if family == 6 else v4
                raw_daddr = daddr_clean
            else:
                if (not raw_daddr
                        or raw_daddr.startswith("+")
                        or raw_daddr.startswith("@")):
                    continue
                daddr_clean = raw_daddr.split("/")[0]
                try:
                    _ipaddr.ip_address(daddr_clean)
                except ValueError:
                    continue
            # ``raw_daddr`` is now safe to use in the dst_pool below.
            # Build candidate src/dst pools from the rule's own CIDRs so
            # the randomised variants still satisfy the rule's constraints
            # (we sample within rule.saddr / rule.daddr rather than using
            # placeholder globals).
            saddr = rule.saddr
            src_pool: list[str] = [default_src]
            if saddr and not saddr.startswith(("+", "@")):
                if "/" in saddr:
                    try:
                        net = _ipaddr.ip_network(saddr, strict=False)
                        if net.version != family:
                            continue
                        hosts = list(net.hosts())
                        if not hosts:
                            continue
                        # Up to 64 distinct candidates from the subnet.
                        if len(hosts) <= 64:
                            src_pool = [str(h) for h in hosts]
                        else:
                            src_pool = [str(hosts[i])
                                        for i in rng.sample(range(len(hosts)), 64)]
                    except ValueError:
                        continue
                else:
                    try:
                        _ipaddr.ip_address(saddr)
                        src_pool = [saddr]
                    except ValueError:
                        continue

            # Same treatment for dst — rules with a /N daddr allow every
            # host in the subnet, so sample rather than always hitting
            # the same concrete IP.
            dst_pool: list[str] = [daddr_clean]
            if raw_daddr and "/" in raw_daddr and not raw_daddr.startswith(("+", "@")):
                try:
                    dnet = _ipaddr.ip_network(raw_daddr, strict=False)
                    if dnet.version == family:
                        dhosts = list(dnet.hosts())
                        if dhosts:
                            if len(dhosts) <= 64:
                                dst_pool = [str(h) for h in dhosts]
                            else:
                                dst_pool = [str(dhosts[i])
                                            for i in rng.sample(range(len(dhosts)), 64)]
                except ValueError:
                    pass

            # Port pool: if the rule matches a range (``1024:65535``) or
            # a comma-list, sample up to 64 distinct ports from it.
            port_pool: list[int | None] = [None]
            if rule.proto in ("tcp", "udp"):
                port_pool = _expand_port_spec(rule.dport, rng, cap=64)
                if not port_pool:
                    continue  # unparseable or empty

            expected = "DROP" if rule.target == "REJECT" else rule.target

            # Emit up to ``random_per_rule`` distinct (src,dst,port) tuples
            # drawn from the pools. random_per_rule=1 preserves the legacy
            # deterministic single-probe behaviour.
            n_variants = max(1, random_per_rule)
            chosen: set[tuple[str, str, int | None]] = set()
            attempts = 0
            while len(chosen) < n_variants and attempts < n_variants * 4:
                attempts += 1
                s = rng.choice(src_pool)
                d = rng.choice(dst_pool)
                p = rng.choice(port_pool)
                chosen.add((s, d, p))
            for s, d, p in chosen:
                per_pair.setdefault(pair, []).append(TestCase(
                    src_ip=s, dst_ip=d,
                    proto=rule_proto, port=p,
                    expected=expected,
                    family=family,
                    src_zone=src_zone, dst_zone=dst_zone,
                    raw=rule.raw[:120],
                ))

    # Sample per-pair: drops first, then accepts. Keep budget per pair so
    # heavy chains don't starve small ones.
    out: list[TestCase] = []
    for pair, cases in per_pair.items():
        seen = set()
        unique: list[TestCase] = []
        for tc in cases:
            key = (tc.src_ip, tc.dst_ip, tc.proto, tc.port, tc.expected)
            if key in seen:
                continue
            seen.add(key)
            unique.append(tc)
        drops = [t for t in unique if t.expected != "ACCEPT"]
        accepts = [t for t in unique if t.expected == "ACCEPT"]
        rng.shuffle(drops)
        rng.shuffle(accepts)
        picked = drops[:max_tests]
        picked.extend(accepts[:max(0, max_tests - len(picked))])
        out.extend(picked)
    return out


def _expand_port_spec(
    dport: str | None, rng: "random.Random", cap: int = 64,
) -> list[int | None]:
    """Expand an iptables-style dport spec into up to ``cap`` concrete ports.

    Accepts single ``80``, list ``80,443,8080``, range ``1024:65535``,
    or combinations thereof (``80,443,1024:2048``). Returns a list of
    ``int`` ports; ``[]`` on parse failure so the caller can skip.
    """
    if not dport:
        return [None]
    out: set[int] = set()
    try:
        for tok in dport.split(","):
            tok = tok.strip()
            if not tok:
                continue
            if ":" in tok:
                lo_s, hi_s = tok.split(":", 1)
                lo = int(lo_s) if lo_s else 1
                hi = int(hi_s) if hi_s else 65535
                if lo > hi:
                    lo, hi = hi, lo
                span = hi - lo + 1
                if span <= cap:
                    out.update(range(lo, hi + 1))
                else:
                    out.update(rng.sample(range(lo, hi + 1), cap))
            else:
                out.add(int(tok))
            if len(out) >= cap * 4:
                break
    except ValueError:
        return []
    if len(out) > cap:
        out = set(rng.sample(list(out), cap))
    return sorted(out)  # type: ignore[return-value]


def _split_chain_zones(chain_name: str) -> tuple[str | None, str | None]:
    """Parse an iptables zone-pair chain like 'adm2host' → ('adm','host').

    Returns (None, None) for base chains or helpers we don't recognise.
    Helper suffixes (_frwd, _dnat, _ctrk, _masq, _input, _output) are
    stripped from the dst side so chains like 'net2adm_frwd' parse as
    ('net','adm').
    """
    if chain_name in ("INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"):
        return None, None
    if "2" not in chain_name:
        return None, None
    parts = chain_name.split("2", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None, None
    dst = parts[1]
    for suf in ("_frwd", "_dnat", "_ctrk", "_masq", "_input", "_output"):
        if dst.endswith(suf):
            dst = dst[: -len(suf)]
    return parts[0], dst


def derive_tests(
    iptables_dump: Path,
    target_ip: str = "203.0.113.5",
    max_tests: int = 60,
    seed: int | None = None,
    family: int = 4,
) -> list[TestCase]:
    """Derive test cases from an iptables-save dump.

    Extracts rules targeting target_ip, samples stochastically,
    and returns TestCase objects. ``family`` selects 4 or 6 —
    the caller is responsible for supplying an ip6tables-save dump
    when family=6.
    """
    from shorewall_nft.verify.iptables_parser import parse_iptables_save

    ipt = parse_iptables_save(iptables_dump)
    flt = ipt.get("filter")
    if not flt:
        return []

    candidates: list[TestCase] = []

    for chain_name, rules in flt.rules.items():
        src_zone, dst_zone = _split_chain_zones(chain_name)
        for rule in rules:
            # Skip boilerplate
            if "--ctstate" in rule.raw or "--ctstatus" in rule.raw:
                continue

            daddr = rule.daddr
            if not daddr:
                continue
            daddr_clean = daddr.rstrip("/32").split("/")[0]
            if daddr_clean != target_ip:
                continue

            # Need a deterministic action
            target = rule.target
            if target not in ("ACCEPT", "DROP", "REJECT"):
                continue

            proto = rule.proto
            if proto not in ("tcp", "udp", "icmp"):
                continue

            saddr = rule.saddr
            default_src = DEFAULT_SRC6 if family == 6 else DEFAULT_SRC
            src = saddr.rstrip("/32").split("/")[0] if saddr else default_src

            # For broad subnets, pick a concrete host IP instead of skipping.
            # Covers real-world configs where firewalls allow whole /20s or
            # /16s from trusted nets — we still want to exercise these rules.
            if saddr and "/" in saddr:
                import ipaddress as _ipaddr
                try:
                    net = _ipaddr.ip_network(saddr, strict=False)
                    if net.version != family:
                        continue  # wrong family for this pass
                    # Deterministic pick: second usable host (.1 + 1).
                    hosts = list(net.hosts())
                    if not hosts:
                        continue
                    src = str(hosts[1] if len(hosts) > 1 else hosts[0])
                except ValueError:
                    continue

            port = None
            if proto in ("tcp", "udp") and rule.dport:
                try:
                    port = int(rule.dport.split(",")[0].split(":")[0])
                except ValueError:
                    continue

            if proto == "icmp":
                port = None
            elif port is None:
                continue

            expected = "DROP" if target == "REJECT" else target

            candidates.append(TestCase(
                src_ip=src,
                dst_ip=target_ip,
                proto=proto,
                port=port,
                expected=expected,
                family=family,
                src_zone=src_zone,
                dst_zone=dst_zone,
                raw=rule.raw[:120],
            ))

    # Deduplicate
    seen = set()
    unique = []
    for tc in candidates:
        key = (tc.src_ip, tc.dst_ip, tc.proto, tc.port, tc.expected)
        if key not in seen:
            seen.add(key)
            unique.append(tc)

    # Stochastic sampling
    rng = random.Random(seed)
    if len(unique) > max_tests:
        # Prioritize DROP/REJECT (more interesting)
        drops = [t for t in unique if t.expected != "ACCEPT"]
        accepts = [t for t in unique if t.expected == "ACCEPT"]
        rng.shuffle(drops)
        rng.shuffle(accepts)
        # Take all drops, fill with accepts
        sampled = drops[:max_tests]
        remaining = max_tests - len(sampled)
        sampled.extend(accepts[:remaining])
        unique = sampled

    return unique


def _start_trace(trace_log: Path) -> subprocess.Popen | None:
    """Start nft monitor trace in the fw namespace, writing to a log file.

    Runs in background. Returns the Popen handle to kill later.
    Captures packet verdicts for debugging failures.
    """
    try:
        f = open(trace_log, "w")
        proc = subprocess.Popen(
            [*RUN_NETNS, "exec", NS_FW, "nft", "monitor", "trace"],
            stdout=f, stderr=subprocess.DEVNULL,
        )
        return proc
    except Exception:
        return None


def run_simulation(
    *,
    config_dir: Path,
    iptables_dump: Path,
    target_ip: str = "203.0.113.5",
    targets: list[str] | None = None,
    ip6tables_dump: Path | None = None,
    targets6: list[str] | None = None,
    max_tests: int = 60,
    seed: int | None = 42,
    verbose: bool = False,
    parallel: int = 4,
    trace: bool = True,
    src_iface: str = SRC_IFACE_DEFAULT,
    dst_iface: str = DST_IFACE_DEFAULT,
    zones: dict[str, str] | None = None,
    all_zones_from_config: bool = False,
) -> list[TestResult]:
    """Run the full packet-level simulation.

    1. Compile shorewall-nft config
    2. Create 3-namespace topology
    3. Load nft rules + start trace
    4. Derive and run test cases (parallel)
    5. Report results
    6. Cleanup
    """
    import tempfile
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from shorewall_nft.compiler.ir import build_ir

    # Step 1: Compile
    from shorewall_nft.config.parser import load_config
    from shorewall_nft.nft.emitter import emit_nft
    from shorewall_nft.nft.sets import parse_init_for_sets

    config = load_config(config_dir)
    ir = build_ir(config)
    sets = parse_init_for_sets(config_dir / "init", config_dir)
    static_nft = None
    if (config_dir / "static.nft").exists():
        static_nft = (config_dir / "static.nft").read_text()
    nft_script = emit_nft(ir, static_nft=static_nft, nft_sets=sets)

    # Multi-zone mode: derive the zone → iface mapping from the
    # shorewall config itself, one entry per zone's primary interface.
    if all_zones_from_config and zones is None:
        zones = {}
        for zone_name, zone in ir.zones.zones.items():
            if zone.is_firewall:
                continue
            for iface in zone.interfaces:
                if iface.name:
                    zones.setdefault(zone_name, iface.name)
                    break

    # Write to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft",
                                     delete=False,
                                     prefix="shorewall-next-sim-") as f:
        f.write(nft_script)
        nft_path = f.name

    # Step 2: Derive tests — one or many targets sharing a single topology.
    tests_by_target: dict[str, list[TestCase]] = {}
    if zones:
        # Multi-zone: walk the full iptables dump, picking every rule
        # whose chain resolves to a known zone pair. No target_ip gate.
        tests_by_target["*"] = derive_tests_all_zones(
            iptables_dump, zones=set(zones.keys()),
            max_tests=max_tests, seed=seed, family=4)
        if ip6tables_dump:
            tests_by_target["*6"] = derive_tests_all_zones(
                ip6tables_dump, zones=set(zones.keys()),
                max_tests=max_tests, seed=seed, family=6)
    else:
        # v4 targets
        target_list = list(targets) if targets else [target_ip]
        for t_ip in target_list:
            t_tests = derive_tests(iptables_dump, target_ip=t_ip,
                                   max_tests=max_tests, seed=seed, family=4)
            tests_by_target[t_ip] = t_tests
        # v6 targets (optional)
        if ip6tables_dump and targets6:
            for t_ip in targets6:
                t_tests = derive_tests(ip6tables_dump, target_ip=t_ip,
                                       max_tests=max_tests, seed=seed, family=6)
                tests_by_target[t_ip] = t_tests
    # Flatten for topology setup / bulk execution.
    tests = [tc for lst in tests_by_target.values() for tc in lst]
    if not tests:
        print("No test cases derived.")
        Path(nft_path).unlink(missing_ok=True)
        return []

    # Collect unique IPs across ALL targets so the topology is set up once.
    src_ips = list({t.src_ip for t in tests if t.family == 4})
    src_ips6 = list({t.src_ip for t in tests if t.family == 6})
    dst_ips = list({t.dst_ip for t in tests if t.family == 4})
    dst_ips6 = list({t.dst_ip for t in tests if t.family == 6})

    # Step 3: Setup topology
    topo = SimTopology(src_iface=src_iface, dst_iface=dst_iface, zones=zones)
    results: list[TestResult] = []
    trace_proc = None
    trace_log = Path(tempfile.gettempdir()) / "shorewall-next-sim-trace.log"

    try:
        topo.create()
        if zones:
            # Multi-zone: per-zone slave namespace, each running its own
            # listener + REDIRECT, packets travel src_slave → FW → dst_slave.
            zone_src_ips: dict[str, list[str]] = {z: [] for z in zones}
            zone_src_ips6: dict[str, list[str]] = {z: [] for z in zones}
            zone_dst_ips: dict[str, list[str]] = {z: [] for z in zones}
            zone_dst_ips6: dict[str, list[str]] = {z: [] for z in zones}
            for tc in tests:
                sz = tc.src_zone or ""
                dz = tc.dst_zone or ""
                if sz in zones:
                    (zone_src_ips6 if tc.family == 6 else zone_src_ips)[sz].append(tc.src_ip)
                if dz in zones:
                    (zone_dst_ips6 if tc.family == 6 else zone_dst_ips)[dz].append(tc.dst_ip)
            for d in (zone_src_ips, zone_src_ips6, zone_dst_ips, zone_dst_ips6):
                for k in list(d.keys()):
                    d[k] = sorted(set(d[k]))
            topo.setup_zone_slaves(
                zone_src_ips=zone_src_ips,
                zone_dst_ips=zone_dst_ips,
                zone_src_ips6=zone_src_ips6,
                zone_dst_ips6=zone_dst_ips6,
            )
        else:
            topo.setup_src(src_ips, src_ips6=src_ips6)
            topo.setup_dst(dst_ips, dst_ips6=dst_ips6)
        topo.setup_fw(nft_path)
        topo.setup_listeners()
        time.sleep(0.5)  # Let listeners start

        # Start nft trace in background for debugging
        if trace:
            # Enable tracing on the forward chain
            _ns(NS_FW,
                "nft add rule inet shorewall forward meta nftrace set 1 2>/dev/null || true")
            _ns(NS_FW,
                "nft add rule inet shorewall input meta nftrace set 1 2>/dev/null || true")
            trace_proc = _start_trace(trace_log)

        # Step 4a: Infrastructure validation (routing, tc, nft loaded)
        from shorewall_nft.verify.tc_validate import run_all_validations
        print("  Infrastructure validation:")
        infra_results = run_all_validations(config_dir)
        for vr in infra_results:
            status = "PASS" if vr.passed else "FAIL"
            print(f"    [{status}] {vr.name}: {vr.detail}")
        infra_passed = sum(1 for r in infra_results if r.passed)
        print(f"  Infrastructure: {infra_passed}/{len(infra_results)}")
        print()

        # Step 4b: Connection state + small conntrack probe.
        # Connstate tests assume the legacy NS_SRC + DEFAULT_SRC binding
        # which doesn't exist in multi-zone slave mode — skip them there.
        from shorewall_nft.verify.connstate import (
            run_connstate_tests,
            run_small_conntrack_probe,
        )
        if zones:
            print("  Connection state tests: SKIPPED in multi-zone mode")
            connstate_results = []
        else:
            print("  Connection state tests:")
            connstate_results = run_connstate_tests(
                dst_ip=target_ip, allowed_port=tests[0].port or 80)
            connstate_results.extend(
                run_small_conntrack_probe(
                    dst_ip=target_ip, port=tests[0].port or 80))
        for cr in connstate_results:
            status = "PASS" if cr.passed else "FAIL"
            print(f"    [{status}] {cr.name}: {cr.detail}")
        connstate_passed = sum(1 for r in connstate_results if r.passed)
        connstate_total = len(connstate_results)
        print(f"  Connstate: {connstate_passed}/{connstate_total}")
        print()

        # Convert connstate results to TestResults for unified reporting
        for cr in connstate_results:
            results.append(TestResult(
                test=TestCase(
                    src_ip=DEFAULT_SRC, dst_ip=target_ip,
                    proto="tcp", port=None, expected="PASS",
                    raw=f"connstate:{cr.name}",
                ),
                got="PASS" if cr.passed else "FAIL",
                passed=cr.passed,
                ms=cr.ms,
            ))

        def _ns_for(tc: TestCase) -> str:
            """Pick the right netns to launch the probe from."""
            if zones and tc.src_zone and tc.src_zone in zones:
                return slave_ns(tc.src_zone)
            return NS_SRC

        # Step 4b: Run derived tests (parallel)
        if parallel > 1 and len(tests) > 1:
            with ThreadPoolExecutor(max_workers=parallel) as pool:
                futures = {pool.submit(_run_single_test, tc, _ns_for(tc), topo): tc
                           for tc in tests}
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
                    if verbose or not result.passed:
                        tc = result.test
                        status = "PASS" if result.passed else "FAIL"
                        port_str = f":{tc.port}" if tc.port else ""
                        print(f"  [{status}] {tc.src_ip} -> {tc.dst_ip} "
                              f"{tc.proto}{port_str} "
                              f"expect={tc.expected} got={result.got} "
                              f"({result.ms}ms)")
        else:
            # Sequential fallback
            for tc in tests:
                result = _run_single_test(tc, _ns_for(tc), topo)
                results.append(result)
                if verbose or not result.passed:
                    status = "PASS" if result.passed else "FAIL"
                    port_str = f":{tc.port}" if tc.port else ""
                    print(f"  [{status}] {tc.src_ip} -> {tc.dst_ip} "
                          f"{tc.proto}{port_str} "
                          f"expect={tc.expected} got={result.got} "
                          f"({result.ms}ms)")

    finally:
        # Stop trace
        if trace_proc:
            trace_proc.terminate()
            trace_proc.wait(timeout=2)

        # Show trace for failed tests
        failed = [r for r in results if not r.passed]
        if failed and trace and trace_log.exists():
            trace_content = trace_log.read_text()
            if trace_content:
                print(f"\n  nft trace log ({len(trace_content)} bytes):")
                # Show trace entries relevant to failed IPs
                for r in failed[:3]:
                    tc = r.test
                    relevant = [l for l in trace_content.splitlines()
                                if tc.dst_ip in l or tc.src_ip in l]
                    if relevant:
                        print(f"    Trace for {tc.src_ip}->{tc.dst_ip}:")
                        for l in relevant[:5]:
                            print(f"      {l}")

        topo.destroy()
        Path(nft_path).unlink(missing_ok=True)
        trace_log.unlink(missing_ok=True)

    return results
