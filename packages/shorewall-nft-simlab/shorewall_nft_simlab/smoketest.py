"""simlab smoke + stress driver.

Exercises the controller end-to-end against the real marcant-fw state
and the marcant-fw shorewall46 config. Intended to be invoked on the
dedicated test VM as root:

    python -m shorewall_nft_simlab.smoketest

Three modes (pick via argv):
  * ``smoke`` (default) — one build, one probe per representative
    zone pair, destroy.
  * ``stress N`` — N × (build + 1 probe + destroy) cycles in
    sequence, printing per-cycle timings plus before/after resource
    counts so we can see any leaks.
  * ``limit`` — push build/destroy as hard as we can, watching FD,
    process, and netns counts until something breaks or degrades.

This file is **not** part of the test suite (pytest discovers
test_*.py only). It's an operator tool for the simlab bring-up.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# Defaults assume the bootstrap state laid down by
# tools/setup-remote-test-host.sh
DEFAULT_CONFIG_DIR = Path("/etc/shorewall46")
DEFAULT_SIM_DATA = Path("/root/simulate-data")


def _resource_counts(ns_name: str = "simlab-fw") -> dict[str, int]:
    """Best-effort read of fd/proc/netns counts for leak detection."""
    counts: dict[str, int] = {}
    try:
        counts["open_fds"] = len(os.listdir("/proc/self/fd"))
    except OSError:
        counts["open_fds"] = -1
    try:
        counts["all_netns"] = len(os.listdir("/run/netns"))
    except OSError:
        counts["all_netns"] = -1
    try:
        r = subprocess.run(
            ["pgrep", "-c", "-f", "simlab[:-]"],
            capture_output=True, text=True, timeout=2,
        )
        counts["simlab_procs"] = int(r.stdout.strip() or 0)
    except Exception:
        counts["simlab_procs"] = -1
    try:
        counts["fw_iface_count"] = len([
            d for d in os.listdir("/sys/class/net") if d.startswith("simlab")
        ])
    except OSError:
        counts["fw_iface_count"] = -1
    try:
        counts["loadavg_x100"] = int(os.getloadavg()[0] * 100)
    except OSError:
        counts["loadavg_x100"] = -1
    return counts


class _PeakSampler:
    """Background thread that tracks max fd + process count + loadavg.

    Samples every 100 ms. Cheap enough to run during the stress loop
    without skewing timings. Call :meth:`start` before the cycle,
    :meth:`stop` to retrieve the peaks.
    """

    def __init__(self, interval_s: float = 0.1):
        import threading
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.peak_fds = 0
        self.peak_procs = 0
        self.peak_load = 0.0
        self.samples = 0

    def start(self) -> None:
        import threading
        self._stop.clear()
        self.peak_fds = 0
        self.peak_procs = 0
        self.peak_load = 0.0
        self.samples = 0
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="simlab-peak")
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            rc = _resource_counts()
            self.peak_fds = max(self.peak_fds, rc.get("open_fds", 0))
            self.peak_procs = max(self.peak_procs, rc.get("simlab_procs", 0))
            self.peak_load = max(self.peak_load, rc.get("loadavg_x100", 0) / 100.0)
            self.samples += 1
            self._stop.wait(self.interval_s)

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        return {
            "peak_fds": self.peak_fds,
            "peak_procs": self.peak_procs,
            "peak_load": round(self.peak_load, 2),
            "samples": self.samples,
        }


def _set_low_priority(pid: int = 0) -> None:
    """Drop CPU + I/O priority of ``pid`` (0 = self) to the lowest class.

    Used so a long simlab run never preempts the rest of the box. CPU
    nice goes to +19; I/O is moved into the idle scheduler class.
    Best-effort: failures are silent.
    """
    if pid == 0:
        try:
            os.nice(19)
        except OSError:
            pass
    if hasattr(os, "ioprio_set"):
        try:
            # IOPRIO_WHO_PROCESS = 1, IOPRIO_CLASS_IDLE = 3
            os.ioprio_set(1, pid, (3 << 13))  # type: ignore[attr-defined]
            return
        except (OSError, AttributeError):
            pass
    try:
        subprocess.run(
            ["ionice", "-c", "3", "-p", str(pid or os.getpid())],
            check=False, capture_output=True,
        )
    except FileNotFoundError:
        pass


def _read_psi(kind: str) -> float:
    """Return ``avg10`` of PSI ``some`` for cpu/io/memory, 0.0 if absent."""
    path = f"/proc/pressure/{kind}"
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("some"):
                    for part in line.split()[1:]:
                        k, _, v = part.partition("=")
                        if k == "avg10":
                            return float(v)
    except (OSError, ValueError):
        pass
    return 0.0


def _system_busy(load_limit: float, psi_limit: float = 40.0) -> tuple[bool, str]:
    """Multi-signal busy check.

    PSI is checked first because it reacts in seconds; loadavg lags by
    tens of seconds. Memory PSI uses a high (80) cutoff so we don't
    pause for normal pagecache churn.
    """
    cpu_psi = _read_psi("cpu")
    if cpu_psi >= psi_limit:
        return True, f"cpu PSI avg10={cpu_psi:.0f}"
    io_psi = _read_psi("io")
    if io_psi >= psi_limit:
        return True, f"io PSI avg10={io_psi:.0f}"
    mem_psi = _read_psi("memory")
    if mem_psi >= 80.0:
        return True, f"mem PSI avg10={mem_psi:.0f}"
    try:
        la1 = os.getloadavg()[0]
    except OSError:
        la1 = 0.0
    if la1 >= load_limit:
        return True, f"loadavg1={la1:.2f}>={load_limit}"
    return False, "ok"


def _load_ok(limit: float) -> bool:
    """True if the box is idle enough to start more work."""
    busy, _ = _system_busy(limit)
    return not busy


def _wait_until_idle(load_limit: float, *, max_wait_s: float = 60.0) -> tuple[float, str]:
    """Block until :func:`_system_busy` clears, capped at ``max_wait_s``.

    Returns ``(waited_s, last_reason)``. Sleeps in 0.5 s steps so we
    react quickly once headroom appears.
    """
    waited = 0.0
    last_why = "ok"
    while waited < max_wait_s:
        busy, why = _system_busy(load_limit)
        last_why = why
        if not busy:
            return waited, why
        time.sleep(0.5)
        waited += 0.5
    return waited, last_why


# ─────────────────────────────────────────────────────────────────────
#  sysctl / sysfs health check
# ─────────────────────────────────────────────────────────────────────


# Tunables relevant for high-volume TUN/TAP testing. Each entry:
# (path, expected_min_value_as_int, description)
_SYSCTL_CHECKS: list[tuple[str, int, str]] = [
    ("/proc/sys/fs/file-max", 65536,
     "global fd ceiling — each worker holds ~4 fds"),
    ("/proc/sys/fs/nr_open", 65536,
     "per-process fd limit"),
    ("/proc/sys/kernel/pid_max", 65536,
     "pid namespace cap — many workers/stubs"),
    ("/proc/sys/net/core/somaxconn", 1024,
     "TCP accept backlog — listener sockets"),
    ("/proc/sys/net/core/rmem_max", 1048576,
     "SO_RCVBUF ceiling for raw / AF_PACKET sockets"),
    ("/proc/sys/net/core/wmem_max", 1048576,
     "SO_SNDBUF ceiling"),
    ("/proc/sys/net/netfilter/nf_conntrack_max", 131072,
     "conntrack table size — probe flows"),
    ("/proc/sys/net/ipv4/ip_local_port_range", 0,
     "range of ephemeral ports (informational)"),
]

_SYSCTL_OFF_OR_ON: list[tuple[str, str, str]] = [
    ("/proc/sys/net/ipv4/conf/all/rp_filter", "0",
     "rp_filter breaks spoofed-source injection"),
    ("/proc/sys/net/ipv4/ip_forward", "1",
     "forwarding must be on for routed probes"),
]


# Sysctls that the simlab controller writes automatically before a run
# unless --no-auto-sysctl is passed. Entries: (path, value).
# Only /proc/sys paths (writable with root privileges).
_SYSCTL_APPLY: list[tuple[str, str]] = [
    ("/proc/sys/net/ipv4/ip_forward",              "1"),
    ("/proc/sys/net/ipv6/conf/all/forwarding",     "1"),
    ("/proc/sys/net/ipv4/conf/all/rp_filter",      "0"),
    ("/proc/sys/net/ipv4/conf/default/rp_filter",  "0"),
    ("/proc/sys/net/core/rmem_max",                "4194304"),
    ("/proc/sys/net/core/wmem_max",                "4194304"),
]


def _apply_sysctls(ns_name: str | None = None) -> list[str]:
    """Write the required sysctl values in the host namespace (and optionally
    inside ``ns_name`` for per-netns forwarding flags).

    Returns a list of human-readable messages for each value that was
    actually changed (already-correct values are silently skipped).
    """
    applied: list[str] = []
    for path, value in _SYSCTL_APPLY:
        try:
            current = open(path).read().strip()
        except OSError:
            continue
        if current == value:
            continue
        try:
            with open(path, "w") as f:
                f.write(value + "\n")
            applied.append(f"{path}: {current} → {value}")
        except OSError as e:
            applied.append(f"{path}: FAILED ({e})")
    # Also set forwarding inside the FW netns if given, so the netns
    # kernel sees forwarded packets from its own perspective.
    if ns_name:
        _fwd_paths = [
            ("/proc/sys/net/ipv4/ip_forward",          "1"),
            ("/proc/sys/net/ipv6/conf/all/forwarding", "1"),
        ]
        for rel_path, value in _fwd_paths:
            cmd = ["sudo", "/usr/local/bin/run-netns", "exec", ns_name,
                   "sh", "-c", f"echo {value} > {rel_path}"]
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=5)
                if r.returncode == 0:
                    applied.append(f"[{ns_name}] {rel_path} → {value}")
            except Exception:
                pass
    return applied


def _check_sysctls(verbose: bool = False) -> list[str]:
    """Return a list of human-readable warnings, empty if everything OK."""
    warnings: list[str] = []
    for path, minimum, desc in _SYSCTL_CHECKS:
        try:
            raw = open(path).read().strip()
        except OSError:
            warnings.append(f"sysctl {path} unreadable ({desc})")
            continue
        if verbose:
            print(f"  {path} = {raw}")
        if minimum <= 0:
            continue
        try:
            first = int(raw.split()[0]) if raw else 0
        except ValueError:
            continue
        if first < minimum:
            warnings.append(
                f"{path}={first} below recommended {minimum} ({desc})"
            )

    for path, expected, desc in _SYSCTL_OFF_OR_ON:
        try:
            raw = open(path).read().strip()
        except OSError:
            continue
        if raw != expected:
            warnings.append(
                f"{path}={raw} should be {expected} ({desc})"
            )

    # CPU governor — performance helps deterministic probe timing
    try:
        governors = set()
        for d in os.listdir("/sys/devices/system/cpu"):
            gov_path = f"/sys/devices/system/cpu/{d}/cpufreq/scaling_governor"
            if os.path.exists(gov_path):
                governors.add(open(gov_path).read().strip())
        if governors and governors - {"performance"}:
            warnings.append(
                f"CPU governors {sorted(governors)} — consider 'performance'"
            )
    except OSError:
        pass

    return warnings


def _compile_ruleset(config_dir: Path, out_path: Path) -> None:
    """Shell-out to shorewall-nft to emit the ruleset."""
    r = subprocess.run(
        ["/root/shorewall-nft/.venv/bin/shorewall-nft", "compile",
         str(config_dir), "-o", str(out_path)],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        raise RuntimeError(f"compile failed: {r.stderr[:500]}")


async def _smoke_one(controller, probes: list) -> list:
    return await controller.run_probes(probes)


class TestCategory:
    POSITIVE = "positive"     # ruleset says ACCEPT, simlab should also ACCEPT
    NEGATIVE = "negative"     # ruleset says DROP/REJECT, simlab should DROP
    RANDOM = "random"         # no a-priori expectation; plausibility vs oracle


def _match(**kw):
    def inner(obs):
        for k, v in kw.items():
            if obs.get(k) != v:
                return False
        return True
    return inner


def _build_static_probes(topo_tun_mac: dict) -> list[tuple]:
    """Representative hand-picked probes across POSITIVE + NEGATIVE.

    Returns a list of (category, expected_verdict, ProbeSpec, meta).
    """
    from . import packets as P
    from .controller import ProbeSpec

    out: list[tuple] = []
    pid = 100

    def add(cat, expect, inject, observe, payload, match, meta):
        nonlocal pid
        out.append((cat, expect, ProbeSpec(
            probe_id=pid, inject_iface=inject, expect_iface=observe,
            payload=payload, match=match,
        ), meta))
        pid += 1

    # POSITIVE: net → adm ICMP (net2adm has ACCEPT rules for ICMP)
    add(TestCategory.POSITIVE, "ACCEPT",
        "bond1", "bond0.18",
        P.build_icmp("203.0.113.69", "203.0.113.34",
                      dst_mac=topo_tun_mac.get("bond1")),
        _match(proto="icmp", dst="203.0.113.34"),
        {"desc": "net → adm ICMP (host-r)"})

    # POSITIVE: adm → cdn tcp:443 (explicit ACCEPT in adm2cdn)
    add(TestCategory.POSITIVE, "ACCEPT",
        "bond0.18", "bond0.23",
        P.build_tcp("203.0.113.34", "198.51.100.11", 443,
                     dst_mac=topo_tun_mac.get("bond0.18")),
        _match(proto="tcp", dst="198.51.100.11", dport=443),
        {"desc": "adm → cdn tcp:443"})

    # NEGATIVE: host-r (net) → host:100:80 (no net2host rule)
    add(TestCategory.NEGATIVE, "DROP",
        "bond1", "bond0.20",
        P.build_tcp("203.0.113.69", "203.0.113.230", 80,
                     dst_mac=topo_tun_mac.get("bond1")),
        _match(proto="tcp", dst="203.0.113.230", dport=80),
        {"desc": "net → host tcp:80 (should be dropped — no rule)"})

    # NEGATIVE: net → fw tcp:22 (net2fw drops ssh unless src is host-r)
    add(TestCategory.NEGATIVE, "DROP",
        "bond1", "bond1",   # fw zone — input chain
        P.build_tcp("1.2.3.4", "203.0.113.75", 22,
                     dst_mac=topo_tun_mac.get("bond1")),
        _match(proto="tcp", dst="203.0.113.75", dport=22),
        {"desc": "random net IP → fw tcp:22 (should be dropped)"})

    return out


def _build_random_probes(
    n: int, topo_tun_mac: dict, iface_to_zone: dict, fw_state,
    oracle, seed: int | None = None,
) -> list[tuple]:
    """Generate `n` random probe plans from routable IPs; oracle-classify each.

    Returns lightweight plan dicts (no ProbeSpec, no scapy payload
    bytes, no match closure) so the full probe list can stay in
    memory cheaply. ProbeSpec construction happens on demand in the
    cmd_full batch loop via :func:`_plan_to_spec`.
    """
    from .oracle import RandomProbeGenerator

    rgen = RandomProbeGenerator(fw_state, iface_to_zone, seed=seed)
    out: list[tuple] = []
    pid_v4 = 1000
    pid_v6 = 0x11000   # above 16-bit range; no collision with IPv4 IDs
    for _ in range(n):
        r = rgen.next()
        if r is None:
            break
        if r.proto not in ("tcp", "udp", "icmp", "icmpv6"):
            continue
        if r.family == 6:
            probe_id = pid_v6 & 0xfffff
            pid_v6 += 1
        else:
            probe_id = pid_v4 & 0xffff
            pid_v4 += 1
        verdict = oracle.classify(
            src_zone=r.src_zone, dst_zone=r.dst_zone,
            src_ip=r.src_ip, dst_ip=r.dst_ip,
            proto=r.proto, port=r.port,
            family=r.family,
        )
        plan = {
            "probe_id": probe_id,
            "src_iface": r.src_iface,
            "dst_iface": r.dst_iface,
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "proto": r.proto,
            "port": r.port,
            "family": r.family,
        }
        meta = {
            "desc": f"{r.src_zone}→{r.dst_zone} "
                    f"{r.src_ip}→{r.dst_ip} {r.proto}:{r.port}",
            "oracle_reason": verdict.reason,
        }
        out.append((TestCategory.RANDOM, verdict.verdict, plan, meta))
    return out


# ─────────────────────────────────────────────────────────────────────


def _routed_iface_for(dst_ip: str, fw_state) -> str | None:
    """Resolve which interface the kernel would forward ``dst_ip`` out of.

    Walks ``fw_state.routes4`` (or routes6 for IPv6) longest-prefix-
    match style and returns the ``dev`` of the best matching route,
    or ``None`` if no route is found. This is used by autorepair
    pass 3 to spot test cases whose ``dst_iface`` (derived from the
    rule's destination zone) doesn't agree with actual routing —
    typical for rules whose destination is reachable via a bird
    BGP-learned uplink route rather than the zone's own iface.
    """
    import ipaddress as _ipaddr
    try:
        addr = _ipaddr.ip_address(dst_ip)
    except ValueError:
        return None
    routes = fw_state.routes4 if addr.version == 4 else fw_state.routes6

    best_prefix = -1
    best_dev: str | None = None
    for r in routes:
        dev = r.dev
        if not dev:
            continue
        if r.dst == "default":
            # Remember default only if nothing more specific matches.
            if best_prefix < 0:
                best_dev = dev
                best_prefix = 0
            continue
        try:
            net = _ipaddr.ip_network(r.dst, strict=False)
        except ValueError:
            continue
        if net.version != addr.version:
            continue
        if addr in net and net.prefixlen > best_prefix:
            best_prefix = net.prefixlen
            best_dev = dev
    return best_dev


def _build_zone_to_concrete_src(
    fw_state, iface_to_zone: dict[str, str],
    family: int = 4,
) -> dict[str, str]:
    """For each zone, pick a routable host IP from its interface subnet.

    This is the "autorepair" for the 192.0.2.69 placeholder-src bug
    in ``derive_tests_all_zones``: when a rule has no explicit SOURCE
    CIDR, derive_tests falls back to DEFAULT_SRC which is in TEST-NET-1
    and therefore not in ANY real zone. The firewall kernel's rp_filter
    drops it on ingress before the nft rule evaluates, so every probe
    for that rule shows up as a spurious fail_drop.

    The fix: at probe-construction time, look up the source zone's
    first interface's first IPv4 subnet, then pick a host in that
    subnet that's

      * not the firewall's own address (any of them — interfaces
        often carry multiple secondaries)
      * not the network or broadcast address
      * preferably towards the high end of the subnet so we don't
        collide with .1/.2 addresses commonly used by gateways or
        VRRP virtual IPs

    Without the "skip all fw-local addrs" rule we used to pick e.g.
    203.0.113.25 on bond0.10 — which was a secondary IP on that
    very interface — and the kernel rejected those probes as a
    martian source before they ever reached the nft ruleset.
    """
    import ipaddress as _ipaddr

    # Collect every IP the firewall owns across every interface so we
    # can avoid colliding with secondaries on a different iface too.
    fw_local_ips: set[str] = set()
    for iface in fw_state.interfaces.values():
        for addr in getattr(iface, "addrs4", []) or []:
            fw_local_ips.add(addr.addr)
        for addr in getattr(iface, "addrs6", []) or []:
            fw_local_ips.add(addr.addr)

    addr_attr = "addrs6" if family == 6 else "addrs4"

    out: dict[str, str] = {}
    for iface_name, zone in iface_to_zone.items():
        if zone in out:
            continue
        iface = fw_state.interfaces.get(iface_name)
        if not iface:
            continue
        addrs = getattr(iface, addr_attr, []) or []
        if not addrs:
            continue
        for addr in addrs:
            if family == 6 and addr.scope != "global":
                continue
            if family == 6 and addr.addr.startswith("fe80::"):
                continue
            try:
                net = _ipaddr.ip_network(
                    f"{addr.addr}/{addr.prefixlen}", strict=False)
            except ValueError:
                continue
            n_total = net.num_addresses
            if n_total < 2:
                continue
            # Walk from the high end of the subnet downwards (up to
            # 256 candidates) to pick a host that is not fw-local.
            # Do NOT use list(net.hosts()) — on a /8 or /16 that
            # materialises 16 M objects and blows the heap.
            #
            # For IPv6 /64+, n_total is 2^64+ which causes integer overflow
            # in the offset calculation. Use direct host construction instead.
            found: str | None = None
            if family == 6 and addr.prefixlen >= 64:
                # For large IPv6 subnets, construct a host address directly
                # by setting the host bits to a high value. Use 0xFF00 as the
                # host part (avoiding ::1 which might be in use, and avoiding
                # ffff:ffff:ffff:fffe which is broken).
                net_addr = int(net.network_address)
                host_bits = 128 - addr.prefixlen
                # Set the host bits to 0x00...FF00 (high but not max)
                host_part = 0xFF00 if host_bits >= 16 else (1 << host_bits) - 2
                candidate = str(_ipaddr.ip_address(net_addr | host_part))
                if candidate not in fw_local_ips:
                    found = candidate
            else:
                # For IPv4 and small IPv6 subnets, use the offset method
                # with a reasonable upper bound to avoid overflow.
                base = int(net.network_address)
                n_hosts = min(n_total - 2, 65536)  # Cap for IPv6 /112 etc.
                limit = min(256, n_hosts)
                for offset in range(n_hosts, n_hosts - limit, -1):
                    candidate = str(_ipaddr.ip_address(base + offset))
                    if candidate not in fw_local_ips:
                        found = candidate
                        break
            if found is None:
                continue
            out[zone] = found
            break  # got a host for this zone, move to next iface
    return out


def _ndp_warmup(all_probes: list, topo_tun_mac: dict,
                ctl, timeout_s: float = 2.0) -> None:
    """Populate the kernel's IPv6 neighbor cache before real batches.

    Sends one throw-away probe per unique (expect_iface, dst_ip) so
    every IPv6 destination has a REACHABLE neighbor entry when the
    first real batch fires.  Probes are sent in small batches (32)
    to avoid flooding the reader threads with NDP NS/NA exchanges.
    """
    seen: set[tuple[str, str]] = set()
    warmup: list[tuple] = []
    pid = 0x1ff00
    for _cat, _exp, plan, _meta in all_probes:
        if plan.get("family") != 6:
            continue
        key = (plan["dst_iface"], plan["dst_ip"])
        if key in seen:
            continue
        seen.add(key)
        warmup.append(plan | {"probe_id": pid & 0xfffff})
        pid += 1

    if not warmup:
        return

    # Fire in small batches so NDP doesn't overwhelm the readers.
    # Use a generous timeout — the first probe to each dst_ip triggers
    # NDP neighbor resolution which can take >1s in a fresh namespace
    # with many interfaces.
    WARMUP_BATCH = 32
    WARMUP_TIMEOUT = max(timeout_s, 2.0)
    for i in range(0, len(warmup), WARMUP_BATCH):
        chunk = warmup[i:i + WARMUP_BATCH]
        specs = [s for s in (_plan_to_spec(p, topo_tun_mac,
                                           timeout_s=WARMUP_TIMEOUT)
                             for p in chunk) if s is not None]
        if specs:
            asyncio.run(_smoke_one(ctl, specs))
    _flush_print(f"ndp warmup: {len(warmup)} dst IPs primed")


def _plan_to_spec(plan: dict, topo_tun_mac: dict,
                  timeout_s: float = 2.0):
    """Build a ProbeSpec from a lightweight plan dict on demand."""
    from . import packets as P
    from .controller import ProbeSpec

    src_iface = plan["src_iface"]
    dst_iface = plan["dst_iface"]
    proto = plan["proto"]
    pid = plan["probe_id"]
    src_ip = plan["src_ip"]
    dst_ip = plan["dst_ip"]
    port = plan.get("port")
    family = plan.get("family", 4)
    dst_mac = topo_tun_mac.get(src_iface)

    if proto == "tcp":
        payload = P.build_tcp(src_ip, dst_ip, port, dst_mac=dst_mac,
                              probe_id=pid, family=family)
        match = _match(proto="tcp", dst=dst_ip, dport=port)
    elif proto == "udp":
        payload = P.build_udp(src_ip, dst_ip, port, dst_mac=dst_mac,
                              probe_id=pid, family=family)
        match = _match(proto="udp", dst=dst_ip, dport=port)
    elif proto == "icmp" and family == 4:
        payload = P.build_icmp(src_ip, dst_ip, dst_mac=dst_mac,
                               probe_id=pid)
        match = _match(proto="icmp", dst=dst_ip)
    elif proto in ("icmpv6", "ipv6-icmp") or (proto == "icmp" and family == 6):
        payload = P.build_icmpv6(src_ip, dst_ip, dst_mac=dst_mac,
                                 probe_id=pid)
        match = _match(proto="icmpv6", dst=dst_ip)
    else:
        # Generic fallback for any other IP protocol — esp, ah, gre,
        # vrrp, ospf, igmp, sctp, pim, …. The auto-generator emits
        # a minimal IPv4/IPv6 header with ``proto`` set to the
        # right number, ``probe_id`` in the id / flow-label field,
        # and a payload of 0xfe × 16 (small + distinctive). Avoids
        # the maintenance burden of a hand-rolled builder per
        # exotic protocol while still exercising the matching nft
        # rule. Multicast/zero-daddr cases (vrrp, ospf hello) get
        # an inject destination from the per-rule walker which
        # already pre-populates the well-known multicast group.
        payload = P.build_unknown_proto(
            src_ip, dst_ip, proto, dst_mac=dst_mac, probe_id=pid,
            family=family)
        if payload is None:
            return None
        match = _match(proto=proto)

    return ProbeSpec(
        probe_id=pid, inject_iface=src_iface,
        expect_iface=dst_iface, payload=payload, match=match,
        timeout_s=timeout_s,
    )


def _build_per_rule_probes(
    iptables_dump: Path, fw_state, iface_to_zone: dict,
    topo_tun_mac: dict, *, max_per_pair: int = 10000,
    random_per_rule: int = 64,
    ip6tables_dump: Path | None = None,
) -> list[tuple]:
    """Build lightweight plan dicts for every (src,dst) chain rule we understand.

    Returns ``list[(category, expected, plan_dict, meta)]`` where
    ``plan_dict`` is cheap (~200 bytes) compared to a full ProbeSpec
    (~3 KB with payload + match closure). The batch loop in cmd_full
    converts plan → ProbeSpec just before firing a batch and discards
    after, keeping parent RSS bounded to ~batch_size ProbeSpecs.
    """
    from shorewall_nft.verify.simulate import (
        DEFAULT_SRC,
        derive_tests_all_zones,
    )

    zone_set = set(iface_to_zone.values())
    cases = derive_tests_all_zones(
        iptables_dump, zones=zone_set, max_tests=max_per_pair, family=4,
        random_per_rule=random_per_rule)

    # Autorepair pass 1: replace the DEFAULT_SRC placeholder with a
    # concrete host from the source zone's own subnet so rp_filter
    # doesn't drop the probe at ingress. See
    # :func:`_build_zone_to_concrete_src` for the rationale.
    zone_src_map = _build_zone_to_concrete_src(fw_state, iface_to_zone)
    repaired_rpf = 0
    for tc in cases:
        if tc.src_ip == DEFAULT_SRC and tc.src_zone in zone_src_map:
            tc.src_ip = zone_src_map[tc.src_zone]
            repaired_rpf += 1
    if repaired_rpf:
        print(f"autorepair: rewrote {repaired_rpf} placeholder-src "
              f"probes to zone-local IPs", flush=True)

    # Autorepair pass 2: re-classify every TestCase via the oracle
    # (full chain walk of iptables.txt = Point of Truth). A random
    # variant may hit a *different* rule earlier in the chain than the
    # one that generated it, so the generator-inherited expected
    # verdict can be wrong. The oracle's answer replaces it.
    # See docs/testing/point-of-truth.md.
    from .oracle import RulesetOracle
    oracle_pot = RulesetOracle(iptables_dump)
    reclassified = 0
    dropped_unverifiable = 0
    kept: list = []
    for tc in cases:
        v = oracle_pot.classify(
            src_zone=tc.src_zone, dst_zone=tc.dst_zone,
            src_ip=tc.src_ip, dst_ip=tc.dst_ip,
            proto=tc.proto, port=tc.port,
        )
        if v.verdict == "UNKNOWN":
            # Oracle can't answer this tuple against iptables.txt —
            # don't count it. Usually means the chain has no rule
            # matching this specific (src,dst,port) combination.
            dropped_unverifiable += 1
            continue
        if v.verdict != tc.expected:
            reclassified += 1
            tc.expected = v.verdict
        # Attach the matching rule raw so per-probe triage can read
        # "which rule the oracle used" directly out of the report.
        tc.raw = v.matched_rule_raw or tc.raw
        kept.append(tc)
    cases = kept
    if reclassified or dropped_unverifiable:
        print(f"autorepair: oracle reclassified {reclassified} "
              f"TestCases, dropped {dropped_unverifiable} unverifiable",
              flush=True)

    zone_to_iface = {z: ifc for ifc, z in iface_to_zone.items()}

    _V4_PROTOS = frozenset({"tcp", "udp", "icmp", "vrrp", "esp", "ah", "gre"})
    _V6_PROTOS = frozenset({"tcp", "udp", "icmpv6", "ipv6-icmp",
                             "esp", "ah", "gre"})

    out: list[tuple] = []
    pid_v4 = 10000
    pid_v6 = 0x10000   # IPv6 IDs start above 16-bit range (uses 20-bit flow label)
    for tc in cases:
        if tc.src_zone is None or tc.dst_zone is None:
            continue
        src_iface = zone_to_iface.get(tc.src_zone)
        dst_iface = zone_to_iface.get(tc.dst_zone)
        if not src_iface or not dst_iface:
            continue
        if tc.proto not in _V4_PROTOS:
            continue
        cat = (TestCategory.POSITIVE if tc.expected == "ACCEPT"
               else TestCategory.NEGATIVE)
        plan = {
            "probe_id": pid_v4 & 0xffff,
            "src_iface": src_iface,
            "dst_iface": dst_iface,
            "src_ip": tc.src_ip,
            "dst_ip": tc.dst_ip,
            "proto": tc.proto,
            "port": tc.port,
            "family": 4,
        }
        meta = {
            "desc": f"{tc.src_zone}→{tc.dst_zone} "
                    f"{tc.src_ip}→{tc.dst_ip} {tc.proto}:{tc.port}",
            "raw": tc.raw,
            # The matching iptables-save rule line is the oracle's
            # reasoning — carry it as oracle_reason so mismatches.txt
            # explains WHY the expectation was what it was.
            "oracle_reason": tc.raw,
        }
        out.append((cat, tc.expected, plan, meta))
        pid_v4 += 1

    # ── IPv6 arm ──────────────────────────────────────────────────
    # Mirror the IPv4 arm above against ip6tables.txt when available.
    if ip6tables_dump and ip6tables_dump.exists():
        from shorewall_nft.verify.simulate import DEFAULT_SRC6

        cases6 = derive_tests_all_zones(
            ip6tables_dump, zones=zone_set, max_tests=max_per_pair,
            family=6, random_per_rule=random_per_rule)

        # Autorepair pass 1 (v6): replace 2001:db8::69 placeholder
        zone_src_map6 = _build_zone_to_concrete_src(
            fw_state, iface_to_zone, family=6)
        repaired6 = 0
        for tc in cases6:
            if tc.src_ip == DEFAULT_SRC6 and tc.src_zone in zone_src_map6:
                tc.src_ip = zone_src_map6[tc.src_zone]
                repaired6 += 1
        if repaired6:
            print(f"autorepair v6: rewrote {repaired6} placeholder-src "
                  f"probes to zone-local IPv6", flush=True)

        # Autorepair pass 2 (v6): re-classify via ip6tables oracle.
        # oracle_pot6 is built with ip6tables_dump as its primary (_ipt)
        # table, so classify() must be called with family=4 to dispatch
        # to that primary table — the Oracle's "family" param selects
        # which internal slot to read, not the IP version of the addresses.
        oracle_pot6 = RulesetOracle(ip6tables_dump)
        reclassified6 = 0
        dropped6 = 0
        kept6: list = []
        for tc in cases6:
            v = oracle_pot6.classify(
                src_zone=tc.src_zone, dst_zone=tc.dst_zone,
                src_ip=tc.src_ip, dst_ip=tc.dst_ip,
                proto=tc.proto, port=tc.port, family=4,
            )
            if v.verdict == "UNKNOWN":
                dropped6 += 1
                continue
            if v.verdict != tc.expected:
                reclassified6 += 1
                tc.expected = v.verdict
            tc.raw = v.matched_rule_raw or tc.raw
            kept6.append(tc)
        cases6 = kept6
        if reclassified6 or dropped6:
            print(f"autorepair v6: oracle reclassified {reclassified6} "
                  f"TestCases, dropped {dropped6} unverifiable", flush=True)

        for tc in cases6:
            if tc.src_zone is None or tc.dst_zone is None:
                continue
            src_iface = zone_to_iface.get(tc.src_zone)
            dst_iface = zone_to_iface.get(tc.dst_zone)
            if not src_iface or not dst_iface:
                continue
            if tc.proto not in _V6_PROTOS:
                continue
            cat = (TestCategory.POSITIVE if tc.expected == "ACCEPT"
                   else TestCategory.NEGATIVE)
            plan = {
                "probe_id": pid_v6 & 0xfffff,
                "src_iface": src_iface,
                "dst_iface": dst_iface,
                "src_ip": tc.src_ip,
                "dst_ip": tc.dst_ip,
                "proto": tc.proto,
                "port": tc.port,
                "family": 6,
            }
            meta = {
                "desc": f"{tc.src_zone}→{tc.dst_zone} "
                        f"{tc.src_ip}→{tc.dst_ip} {tc.proto}:{tc.port} [v6]",
                "raw": tc.raw,
                "oracle_reason": tc.raw,
            }
            out.append((cat, tc.expected, plan, meta))
            pid_v6 += 1

    return out


def _iface_to_zone_map(config_dir: Path) -> dict[str, str]:
    """Read shorewall interfaces file → iface → zone."""
    out: dict[str, str] = {}
    path = config_dir / "interfaces"
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            zone, iface = parts[0], parts[1]
            if zone != "-" and iface != "-":
                out[iface] = zone
    return out


def _flowtable_state(ns_name: str) -> str | None:
    """Best-effort post-run flowtable inspection inside ``ns_name``.

    Returns a single-line summary suitable for the smoketest log,
    or ``None`` if the flowtable doesn't exist (configs without
    FLOWTABLE=…), nft is missing, or the netns is unreachable.
    The intent is to give a yes/no signal that the flow offload
    fast-path is engaged at the end of a run — non-zero entry
    count proves at least one flow took the bypass.

    Implementation: shells out to nft because libnftables doesn't
    surface flowtable entry counts. Single subprocess at the end
    of the run, not in the hot path.
    """
    import subprocess
    try:
        cmd = ["nft", "-j", "list", "flowtables"]
        env_run = ["sudo", "/usr/local/bin/run-netns", "exec", ns_name] + cmd
        out = subprocess.run(
            env_run, capture_output=True, text=True, timeout=5)
        if out.returncode != 0:
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    import json as _json
    try:
        data = _json.loads(out.stdout or "{}")
    except _json.JSONDecodeError:
        return None
    flowtables = [
        x.get("flowtable") for x in data.get("nftables", [])
        if isinstance(x, dict) and "flowtable" in x
    ]
    if not flowtables:
        return None
    parts: list[str] = []
    for ft in flowtables:
        if not isinstance(ft, dict):
            continue
        fam = ft.get("family", "?")
        tbl = ft.get("table", "?")
        name = ft.get("name", "?")
        devs = ft.get("dev", [])
        if isinstance(devs, str):
            devs = [devs]
        parts.append(
            f"{fam}/{tbl}/{name} ({len(devs)} devs)")
    return ", ".join(parts) if parts else None


def _iface_rp_filter_map(config_dir: Path) -> dict[str, str]:
    """Parse the routefilter / noroutefilter option per iface.

    Returns ``{iface: "0"|"1"|"2"}`` for every iface that has an
    explicit setting in the interfaces file. Ifaces without an
    explicit option are absent — the simlab topology then leaves
    the kernel default in place (or applies the historical
    rp_filter=0 forcing if the dict is empty entirely).
    """
    out: dict[str, str] = {}
    path = config_dir / "interfaces"
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        iface = parts[1]
        if iface == "-":
            continue
        opts_str = parts[3] if len(parts) > 3 else ""
        opts = {o.strip() for o in opts_str.split(",") if o.strip()}
        for opt in opts:
            if opt == "routefilter":
                out[iface] = "1"
                break
            if opt.startswith("routefilter="):
                v = opt.split("=", 1)[1].strip() or "1"
                if v in ("0", "1", "2"):
                    out[iface] = v
                    break
        if "noroutefilter" in opts:
            out[iface] = "0"
    return out


def _percentiles(values: list[int], pcts: list[float]) -> dict[str, int]:
    if not values:
        return {f"p{int(p*100)}": 0 for p in pcts}
    vs = sorted(values)
    out: dict[str, int] = {}
    for p in pcts:
        idx = min(len(vs) - 1, int(len(vs) * p))
        out[f"p{int(p*100)}"] = vs[idx]
    return out


def _print_category(
    name: str,
    probes: list[tuple],  # (category, expected, ProbeSpec, meta, result)
) -> None:
    """Pretty-print per-category stats with the four-way pass/fail split.

    Always surfaces *which direction* mismatches go:

      pass_accept  expected ACCEPT, got ACCEPT   (correct allow)
      pass_drop    expected DROP,   got DROP     (correct block)
      fail_drop    expected ACCEPT, got DROP     (should have had access)
      fail_accept  expected DROP,   got ACCEPT   (shouldn't have had access)
      unknown_exp  oracle could not classify     (RANDOM only, typically)
    """
    total = len(probes)
    if total == 0:
        print(f"{name}: (none)")
        return

    pass_accept = sum(1 for p in probes if p[1] == "ACCEPT" and p[4].verdict == "ACCEPT")
    pass_drop   = sum(1 for p in probes if p[1] == "DROP"   and p[4].verdict == "DROP")
    fail_drop   = sum(1 for p in probes if p[1] == "ACCEPT" and p[4].verdict == "DROP")
    fail_accept = sum(1 for p in probes if p[1] == "DROP"   and p[4].verdict == "ACCEPT")
    unknown_exp = sum(1 for p in probes if p[1] == "UNKNOWN")
    errored     = sum(1 for p in probes if p[4].verdict not in ("ACCEPT", "DROP"))

    latencies = [p[4].elapsed_ms for p in probes if p[4].elapsed_ms > 0]
    pct = _percentiles(latencies, [0.5, 0.9, 0.99])
    avg = sum(latencies) // len(latencies) if latencies else 0

    passed = pass_accept + pass_drop
    failed = fail_drop + fail_accept
    pct_ok = (100.0 * passed / max(1, total - unknown_exp - errored))
    print(
        f"{name:>9}: {total:4d}  "
        f"ok={passed:4d} ({pct_ok:5.1f}%)  "
        f"fail_drop={fail_drop:4d}  fail_accept={fail_accept:4d}  "
        f"(pass_acc={pass_accept} pass_drp={pass_drop})  "
        f"unknown={unknown_exp:3d}  err={errored:3d}   "
        f"lat avg={avg}ms p50={pct['p50']}ms p99={pct['p99']}ms",
        flush=True,
    )
    if failed:
        print(
            "           ↳ fail_drop  = should have had access but was DROPPED\n"
            "           ↳ fail_accept = should have been blocked but was ACCEPTED",
            flush=True,
        )


def _flush_print(*a: object, **kw: object) -> None:
    """print() with an unconditional stdout flush.

    systemd-run captures stdout to a file, which Python defaults to
    block-buffered (4 KB). Runs can then go minutes without writing
    anything visible even though work is progressing. Every
    operator-visible line in cmd_full goes through this helper so
    the log file stays current and an operator ``tail -f`` sees
    the real current state.
    """
    kw["flush"] = True
    print(*a, **kw)  # type: ignore[misc]


def cmd_full(args: argparse.Namespace) -> int:
    """Per-rule positive/negative coverage + N random probes + report."""
    from .controller import SimController
    from .oracle import RulesetOracle
    _set_low_priority()
    _flush_print("=== simlab FULL ===")

    if not getattr(args, "no_auto_sysctl", False):
        applied = _apply_sysctls()   # ns_name not known yet; host-side only
        if applied:
            _flush_print("sysctl: auto-applied host settings:")
            for msg in applied:
                _flush_print(f"  + {msg}")
        else:
            _flush_print("sysctl: host settings already correct")

    warns = _check_sysctls(verbose=args.verbose)
    if warns:
        _flush_print("sysctl health WARNINGS:")
        for w in warns:
            _flush_print(f"  ! {w}")
    else:
        _flush_print("sysctl health: ok")

    before = _resource_counts()
    _flush_print(f"before: {before}")

    # Production-faithful per-iface rp_filter from the parsed
    # interfaces config (TODO #12 — routefilter parity). The
    # autorepair pass 4 already enforces that every kept probe
    # has a src_ip routing back to the same inject iface, so
    # strict RPF on a per-iface basis is functionally a no-op
    # for surviving probes and gives us a test environment
    # that mirrors what production would see.
    iface_rp = _iface_rp_filter_map(args.config)

    t0 = time.monotonic()
    ctl = SimController(
        ip4add=args.data / "ip4add",
        ip4routes=args.data / "ip4routes",
        ip6add=args.data / "ip6add",
        ip6routes=args.data / "ip6routes",
        iface_rp_filter=iface_rp,
        dump_config=not args.no_dump_config,
        pcap_dir=args.pcap_dir,
    )

    # Pre-load fw state WITHOUT starting the topology (no reader threads yet).
    # All probe generation — including the expensive oracle classify loop —
    # runs here, before ctl.build() spawns reader threads. That way the
    # classify loop doesn't race against thread-pool traffic filling the
    # _iface_trace deques, and peak RSS stays bounded to the probe list alone.
    ctl.reload_dumps()

    iface_to_zone = _iface_to_zone_map(args.config)
    _flush_print("oracle: parsing iptables.txt for point-of-truth …")
    ip6tables_path = args.data / "ip6tables.txt"
    oracle = RulesetOracle(
        args.data / "iptables.txt",
        ip6t_dump=ip6tables_path if ip6tables_path.exists() else None,
    )
    if ip6tables_path.exists():
        _flush_print("oracle: ip6tables.txt loaded (IPv6 random probes enabled)")
    else:
        _flush_print("oracle: ip6tables.txt not found — IPv6 random probes disabled")
    _flush_print("oracle: ready")

    # Build probes across categories.
    # topo_tun_mac is not needed by the probe *planners* (only by
    # _plan_to_spec when materialising packets in the batch loop later).
    # Pass {} here; the batch loop reads topo_mac = ctl.topo.tun_mac after
    # ctl.build() completes.
    t_build_p0 = time.monotonic()
    _flush_print(f"probes: generating per-rule (random_per_rule="
                 f"{args.random_per_rule}) …")
    rules_probes = _build_per_rule_probes(
        args.data / "iptables.txt", ctl.state, iface_to_zone,
        {},   # tun_mac not needed at plan-build time
        max_per_pair=args.max_per_pair,
        random_per_rule=args.random_per_rule,
        ip6tables_dump=ip6tables_path if ip6tables_path.exists() else None,
    )
    _flush_print(f"probes: per-rule built, {len(rules_probes)} cases")
    _flush_print(f"probes: generating {args.random} random …")
    random_probes = _build_random_probes(
        args.random, {},   # tun_mac not needed at plan-build time
        iface_to_zone, ctl.state, oracle, seed=args.seed,
    )
    t_build_probes = time.monotonic() - t_build_p0
    _flush_print(f"probes: ready in {t_build_probes:.2f}s")

    all_probes = rules_probes + random_probes

    # Autorepair pass 3: drop test cases whose dst_ip doesn't route
    # to the expected dst_iface. The shorewall-nft chain for zone
    # pair (src, dst) only fires when ``oifname == dst_iface``, so
    # a probe whose dst_ip is reachable via a different interface
    # (e.g. a bird-learned BGP route to an upstream) never enters
    # the chain and will always report fail_drop no matter what the
    # nft ruleset emits. These are config-level dead rules on the
    # reference side, not emitter or oracle regressions.
    #
    # Rather than rewriting expectations, we drop the probe and
    # count it under ``routing_incompatible`` so the report still
    # carries the signal "this rule's dst is unreachable from
    # this zone pair".
    # Build a {iface → zone} reverse map and a {zone → set(ifaces)}
    # forward map so the routing checks accept ANY iface in the
    # destination zone (multi-iface zones are common — host has
    # bond0.20+bond0.21, net has bond1+bond0.19+bond0.61, etc.).
    zone_to_ifaces: dict[str, set[str]] = {}
    for ifc, zn in iface_to_zone.items():
        zone_to_ifaces.setdefault(zn, set()).add(ifc)

    def _accept_iface(iface: str | None, zone_iface: str) -> bool:
        if iface is None:
            return False
        if iface == zone_iface:
            return True
        zn = iface_to_zone.get(zone_iface)
        if zn is None:
            return False
        return iface in zone_to_ifaces.get(zn, set())

    # Pre-compute the set of fw-local addresses so we can drop
    # probes whose dst is a fw-owned IP — those packets are
    # delivered to the INPUT chain instead of FORWARD, so the
    # zone-pair chain we expected to fire never runs.
    fw_local_ips: set[str] = set()
    for ifc in ctl.state.interfaces.values():
        for a in getattr(ifc, "addrs4", []) or []:
            fw_local_ips.add(a.addr)
        for a in getattr(ifc, "addrs6", []) or []:
            fw_local_ips.add(a.addr)

    dropped_dst_routing = 0
    dropped_dst_local = 0
    kept: list = []
    for cat, expected, plan, meta in all_probes:
        if plan["dst_ip"] in fw_local_ips:
            dropped_dst_local += 1
            continue
        routed = _routed_iface_for(plan["dst_ip"], ctl.state)
        if not _accept_iface(routed, plan["dst_iface"]):
            dropped_dst_routing += 1
            continue
        # Multi-iface zone: rewrite dst_iface to the actually-routed
        # iface so the controller observes on the right TAP. The
        # nft chain dispatch already has both ifaces in its
        # ``oifname { … }`` set, so the chain still matches.
        if routed != plan["dst_iface"]:
            plan["dst_iface"] = routed
        kept.append((cat, expected, plan, meta))
    if dropped_dst_local:
        _flush_print(
            f"autorepair: dropped {dropped_dst_local} probes whose "
            f"dst_ip is a fw-local address (delivered to INPUT, "
            f"not FORWARD — zone-pair chain never fires)")
    if dropped_dst_routing:
        _flush_print(
            f"autorepair: dropped {dropped_dst_routing} probes whose "
            f"dst_ip routes to a different zone than the dst zone "
            f"implies (dst_routing_incompatible)")
    all_probes = kept

    # Autorepair pass 4: drop test cases whose src_ip isn't
    # reachable via src_iface either. Symmetric to pass 3 — the
    # iptables rule was in an <adm>2<siem> chain meaning "traffic
    # from src IP going adm→siem", but the src IP (often pulled
    # from a rule's explicit saddr CIDR) may be a customer range
    # that's only routable over a completely different upstream
    # iface. When simlab injects that probe on bond0.18 (adm),
    # the kernel either rp_filters it at ingress or drops it
    # because there's no matching route back, so the adm-siem
    # nft chain never fires even though the rule exists.
    #
    # Same filter as pass 3 but for src_ip / src_iface.
    # Source routing is checked strictly: if src_ip doesn't route
    # back to the SPECIFIC inject iface in the simlab netns, the
    # kernel will silently discard the probe at ingress (rp_filter
    # is forced off but the kernel still does sanity checks on
    # forwarded packets). Multi-iface zones don't get the dst-side
    # relaxation here — we want the inject path to be deterministic.
    dropped_src_routing = 0
    kept2: list = []
    for cat, expected, plan, meta in all_probes:
        routed = _routed_iface_for(plan["src_ip"], ctl.state)
        if routed is None or routed != plan["src_iface"]:
            dropped_src_routing += 1
            continue
        kept2.append((cat, expected, plan, meta))
    if dropped_src_routing:
        _flush_print(
            f"autorepair: dropped {dropped_src_routing} probes whose "
            f"src_ip is not reachable via the src zone's iface "
            f"(src_routing_incompatible)")
    all_probes = kept2

    # All probe planning is done. NOW compile the ruleset and build the
    # topology — reader threads start here, AFTER the expensive classify loop.
    nft = Path("/tmp/simlab-ruleset.nft")
    _flush_print("compile: shorewall-nft compile …")
    _compile_ruleset(args.config, nft)
    _flush_print("compile: ok")

    t_topo0 = time.monotonic()
    _flush_print("topology: building …")
    ctl.build()
    t_build = time.monotonic() - t_topo0
    _flush_print(f"build: {t_build:.2f}s ({len(ctl.workers)} ifaces)")
    if iface_rp:
        _flush_print(
            f"rp_filter: replaying {len(iface_rp)} per-iface "
            f"routefilter values from interfaces config")

    try:
        _flush_print("nft load: …")
        ctl.load_nft(str(nft))
    except RuntimeError as e:
        _flush_print(f"nft LOAD FAILED: {e}")
        ctl.shutdown()
        return 2
    t_load = time.monotonic() - t_topo0 - t_build
    _flush_print(f"nft load: {t_load:.2f}s")
    time.sleep(0.2)

    # Split by category for reporting (we'll also run them together)
    by_cat: dict[str, list] = {
        TestCategory.POSITIVE: [],
        TestCategory.NEGATIVE: [],
        TestCategory.RANDOM: [],
    }
    for p in all_probes:
        by_cat[p[0]].append(p)

    _flush_print(
        f"build={t_build:.2f}s load={t_load:.2f}s "
        f"probes={len(all_probes)} "
        f"(pos={len(by_cat[TestCategory.POSITIVE])} "
        f"neg={len(by_cat[TestCategory.NEGATIVE])} "
        f"rnd={len(by_cat[TestCategory.RANDOM])}) "
        f"gen={t_build_probes:.2f}s"
    )

    peak = _PeakSampler(interval_s=0.25)
    peak.start()
    t_run0 = time.monotonic()

    # Streaming probes: all_probes holds lightweight plan dicts (cheap).
    # Per batch, we materialise ProbeSpecs via _plan_to_spec, fire them,
    # collect (verdict, elapsed_ms) per probe_id, then let the
    # ProbeSpec objects go out of scope so the GC reclaims their
    # payload bytes and match closures. Peak parent RSS during the
    # run stays at ~batch_size ProbeSpecs, not at N × ProbeSpec.
    topo_mac = ctl.topo.tun_mac if ctl.topo else {}
    results_by_pid: dict[int, tuple[str | None, int]] = {}

    # ── NDP warmup ─────────────────────────────────────────────────
    # Fire one throw-away probe per unique (inject, expect) interface
    # pair so the kernel's IPv6 neighbor cache is populated before the
    # real batches start.  Without this, the first batch floods the
    # reader threads with NDP NS/NA exchanges and some forwarded
    # packets time out waiting for neighbor resolution.
    # ── optional nft trace for debugging ────────────────────────
    # Insert a trace rule + start nft monitor so the kernel logs
    # which nft rule each IPv6 packet hits.  Writes to nft-trace.log.
    _nft_trace_proc = None
    if os.environ.get("SIMLAB_NFT_TRACE"):
        import subprocess as _sp
        _trace_target = os.environ["SIMLAB_NFT_TRACE"]  # e.g. ip6 daddr
        _sp.run(["ip", "netns", "exec", ctl.ns_name, "nft", "insert",
                 "rule", "inet", "shorewall", "forward",
                 "meta", "nfproto", "ipv6",
                 "ip6", "daddr", _trace_target,
                 "meta", "nftrace", "set", "1"],
                capture_output=True)
        _trace_log = open("nft-trace.log", "w")
        _nft_trace_proc = _sp.Popen(
            ["ip", "netns", "exec", ctl.ns_name, "nft", "monitor", "trace"],
            stdout=_trace_log, stderr=_sp.DEVNULL)
        _flush_print(f"nft trace: enabled for ip6 daddr {_trace_target}")

    _ndp_warmup(all_probes, topo_mac, ctl, timeout_s=args.probe_timeout)

    batch_size = max(1, args.batch_size)
    total_throttle = 0.0
    n_batches = (len(all_probes) + batch_size - 1) // batch_size
    report_every = max(1, n_batches // 200)
    _flush_print(f"run: {n_batches} batches × {batch_size} probes, "
                 f"progress every {report_every} batches")
    last_log = time.monotonic()
    for bi in range(n_batches):
        batch = all_probes[bi * batch_size : (bi + 1) * batch_size]
        # Materialise specs for this batch only
        batch_specs: list = []
        for _cat, _exp, plan, _meta in batch:
            spec = _plan_to_spec(plan, topo_mac,
                                 timeout_s=args.probe_timeout)
            if spec is not None:
                batch_specs.append(spec)
        waited, why = _wait_until_idle(args.load_limit, max_wait_s=120.0)
        if waited > 0:
            total_throttle += waited
            _flush_print(
                f"  [batch {bi+1}/{n_batches}] throttled "
                f"{waited:.1f}s ({why})")
        asyncio.run(_smoke_one(ctl, batch_specs))
        # Collect results keyed by probe_id so the full-N categorisation
        # still works after the ProbeSpec batch is discarded.
        for spec in batch_specs:
            results_by_pid[spec.probe_id] = (spec.verdict, spec.elapsed_ms)
        del batch_specs  # make the GC hint explicit
        now = time.monotonic()
        if (bi + 1) % report_every == 0 or (now - last_log) > 30:
            elapsed = now - t_run0
            rate = ((bi + 1) * batch_size) / max(0.001, elapsed)
            eta = (n_batches - bi - 1) * batch_size / max(0.001, rate)
            _flush_print(
                f"  progress: batch {bi+1}/{n_batches} "
                f"({(bi+1)*100//n_batches}%)  "
                f"{rate:.0f} probes/s  "
                f"elapsed={elapsed:.0f}s  eta={eta:.0f}s")
            last_log = now
    t_run = time.monotonic() - t_run0
    if _nft_trace_proc:
        _nft_trace_proc.kill()
        _trace_log.close()
        _flush_print("nft trace: written to nft-trace.log")
    peaks_summary = peak.stop()
    peaks_summary["throttle_s"] = round(total_throttle, 1)
    peaks = peaks_summary

    # Rebuild the all_probes list with spec-like SimpleNamespaces carrying
    # just the fields downstream code reads (verdict, elapsed_ms,
    # probe_id, inject/expect iface, payload — regenerated only for
    # failed probes so the pcap writer still has real bytes).
    from types import SimpleNamespace
    enriched_probes: list[tuple] = []
    for cat, expected, plan, meta in all_probes:
        pid = plan["probe_id"]
        verdict, elapsed = results_by_pid.get(pid, (None, 0))
        # Only regenerate payload bytes if this probe is a failure
        # needing pcap output; otherwise leave None to save memory.
        payload = None
        if verdict is not None and verdict != expected and expected != "UNKNOWN":
            rebuilt = _plan_to_spec(plan, topo_mac)
            if rebuilt is not None:
                payload = rebuilt.payload
        spec_like = SimpleNamespace(
            probe_id=pid,
            inject_iface=plan["src_iface"],
            expect_iface=plan["dst_iface"],
            verdict=verdict,
            elapsed_ms=elapsed,
            payload=payload,
            trace=[],
        )
        enriched_probes.append((cat, expected, spec_like, meta))
    all_probes = enriched_probes

    by_cat_res: dict[str, list] = {
        TestCategory.POSITIVE: [],
        TestCategory.NEGATIVE: [],
        TestCategory.RANDOM: [],
    }
    for cat, expect, spec, meta in all_probes:
        by_cat_res[cat].append((cat, expect, spec, meta, spec))

    _flush_print()
    _flush_print(f"=== results (run {t_run:.2f}s) ===")
    _print_category("POSITIVE", by_cat_res[TestCategory.POSITIVE])
    _print_category("NEGATIVE", by_cat_res[TestCategory.NEGATIVE])
    _print_category("RANDOM  ", by_cat_res[TestCategory.RANDOM])

    _flush_print()
    _flush_print(f"peak fds:   {peaks['peak_fds']}")
    _flush_print(f"peak procs: {peaks['peak_procs']}")
    _flush_print(f"peak load:  {peaks['peak_load']}")

    # TODO #7: flowtable offload sanity check. After the run we
    # ask the kernel how many flows are sitting in the flowtable
    # — non-zero proves the fast-path is engaged. Best-effort:
    # missing nft binary, missing flowtable, or empty result are
    # all just informational.
    ft_summary = _flowtable_state(ctl.ns_name)
    if ft_summary is not None:
        _flush_print(f"flowtable: {ft_summary}")

    # --sleep-before-shutdown: sleep N seconds before destroying the namespace.
    # Useful for live debugging (inspect with ip netns exec while process waits).
    if getattr(args, "sleep_before_shutdown", 0) > 0:
        import time as _time
        _flush_print("")
        _flush_print(f"=== SLEEPING {args.sleep_before_shutdown}s BEFORE SHUTDOWN ===")
        _flush_print(f"Namespace '{ctl.ns_name}' is alive. Inspect with:")
        _flush_print(f"  sudo ip netns exec {ctl.ns_name} bash")
        try:
            _time.sleep(args.sleep_before_shutdown)
        except KeyboardInterrupt:
            _flush_print("Sleep interrupted by user — proceeding with shutdown")

    if getattr(args, "keep_namespace", False):
        _flush_print("")
        _flush_print("=== NAMESPACE PRESERVED ===")
        _flush_print(f"Namespace '{ctl.ns_name}' is kept alive for debugging.")
        _flush_print(f"Inspect with: sudo ip netns exec {ctl.ns_name} bash")
        _flush_print(f"Clean up later: sudo ip netns delete {ctl.ns_name}")
        _flush_print("")
        after = _resource_counts(ns_name=ctl.ns_name)
    else:
        ctl.shutdown()
        after = _resource_counts()
    _flush_print(f"after: {after}")
    delta = {k: after.get(k, 0) - before.get(k, 0) for k in after}
    _flush_print(f"delta: {delta}")

    # Persist a full archive report for later regression hunts.
    try:
        from .report import DEFAULT_REPORT_DIR, write_report
        run_dir = write_report(
            archive_root=args.report_dir or DEFAULT_REPORT_DIR,
            run_name="full",
            probes=all_probes,
            timings={
                "build": t_build, "nft_load": t_load,
                "probe_build": t_build_probes, "run": t_run,
            },
            peaks=peaks,
            resource_delta=delta,
            sysctl_warnings=warns,
            iface_count=len(ctl.state.interfaces) if ctl.state else 0,
            route_count_v4=len(ctl.state.routes4) if ctl.state else 0,
            route_count_v6=len(ctl.state.routes6) if ctl.state else 0,
        )
        print(f"report written: {run_dir}")
    except Exception as e:
        print(f"report FAILED to write: {e}")
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    from .controller import SimController
    _set_low_priority()
    print("=== simlab smoke ===")
    if not getattr(args, "no_auto_sysctl", False):
        applied = _apply_sysctls()
        if applied:
            print("sysctl: auto-applied:", applied)
    before = _resource_counts()
    print(f"before: {before}")

    t0 = time.monotonic()
    ctl = SimController(
        ip4add=args.data / "ip4add",
        ip4routes=args.data / "ip4routes",
        ip6add=args.data / "ip6add",
        ip6routes=args.data / "ip6routes",
        dump_config=not args.no_dump_config,
        pcap_dir=args.pcap_dir,
    )
    ctl.build()
    t_build = time.monotonic() - t0
    print(f"build: {t_build:.3f}s  ifaces={len(ctl.workers)}")

    nft = Path("/tmp/simlab-ruleset.nft")
    _compile_ruleset(args.config, nft)
    try:
        ctl.load_nft(str(nft))
    except RuntimeError as e:
        print(f"nft LOAD FAILED: {e}")
        ctl.shutdown()
        return 2
    t_load = time.monotonic() - t0 - t_build
    print(f"load:  {t_load:.3f}s")

    # Give workers a moment to become listener-ready
    time.sleep(0.2)

    # cmd_smoke uses the hand-picked static probes (positive + negative).
    # Full rule coverage + random is handled by cmd_full.
    static = _build_static_probes(ctl.topo.tun_mac if ctl.topo else {})
    specs = [p[2] for p in static]
    print(f"probes: {len(specs)}")
    asyncio.run(_smoke_one(ctl, specs))
    for cat, expected, spec, meta in static:
        ok = "PASS" if spec.verdict == expected else "FAIL"
        print(f"  [{ok}] {spec.inject_iface}→{spec.expect_iface} "
              f"expected={expected} got={spec.verdict} "
              f"id={spec.probe_id} {spec.elapsed_ms}ms — {meta.get('desc','')}")

    ctl.shutdown()
    after = _resource_counts()
    print(f"after:  {after}")
    leaked = {k: after.get(k, 0) - before.get(k, 0) for k in after}
    print(f"delta:  {leaked}")
    return 0


def cmd_stress(args: argparse.Namespace) -> int:
    from .controller import SimController
    _set_low_priority()
    print(f"=== simlab stress × {args.iterations} ===")
    baseline = _resource_counts()
    print(f"baseline: {baseline}")
    per_cycle: list[dict] = []
    overall_peak = _PeakSampler(interval_s=0.05)
    overall_peak.start()

    for i in range(args.iterations):
        # Load throttle — wait until loadavg drops back below the
        # ceiling before kicking off another cycle. Prevents thrash
        # when build/destroy pile up.
        throttled = 0
        while not _load_ok(args.load_limit):
            throttled += 1
            time.sleep(0.5)
            if throttled > 60:  # max 30s wait
                break

        cycle_peak = _PeakSampler(interval_s=0.05)
        cycle_peak.start()
        t0 = time.monotonic()
        ctl = SimController(
            ip4add=args.data / "ip4add",
            ip4routes=args.data / "ip4routes",
            ip6add=args.data / "ip6add",
            ip6routes=args.data / "ip6routes",
            ns_name=f"simlab-fw-{i}",
            dump_config=not args.no_dump_config,
            pcap_dir=args.pcap_dir,
        )
        try:
            ctl.build()
            build_s = time.monotonic() - t0
        except Exception as e:
            print(f"[{i}] BUILD FAILED: {e}")
            cycle_peak.stop()
            return 3
        try:
            ctl.shutdown()
        except Exception as e:
            print(f"[{i}] DESTROY FAILED: {e}")
            cycle_peak.stop()
            return 4
        cycle_s = time.monotonic() - t0
        peaks = cycle_peak.stop()
        rc = _resource_counts()
        per_cycle.append({"cycle": i, "build_s": build_s,
                          "total_s": cycle_s, **rc, **peaks})
        print(
            f"[{i:3}] build={build_s:.2f}s total={cycle_s:.2f}s  "
            f"fds={rc['open_fds']:>3} (peak={peaks['peak_fds']:>3}) "
            f"procs={rc['simlab_procs']:>2} (peak={peaks['peak_procs']:>2}) "
            f"load={rc.get('loadavg_x100', 0)/100:.2f} "
            f"peak={peaks['peak_load']:.2f}"
            + (f"  [throttled {throttled*0.5:.1f}s]" if throttled else "")
        )

    overall = overall_peak.stop()
    print()
    print(f"overall peak fds:    {overall['peak_fds']}")
    print(f"overall peak procs:  {overall['peak_procs']}")
    print(f"overall peak load:   {overall['peak_load']}")
    start_fd = baseline.get("open_fds", 0)
    end_fd = per_cycle[-1]["open_fds"] if per_cycle else 0
    print(f"fd delta after {args.iterations} cycles: {end_fd - start_fd}")
    return 0


def cmd_limit(args: argparse.Namespace) -> int:
    """Push until build/destroy degrades or fails."""
    from .controller import SimController
    _set_low_priority()
    print("=== simlab limit ===")
    i = 0
    prev_cycle_s = 0.0
    while True:
        t0 = time.monotonic()
        try:
            ctl = SimController(
                ip4add=args.data / "ip4add",
                ip4routes=args.data / "ip4routes",
                ns_name=f"simlab-lim-{i}",
                dump_config=not args.no_dump_config,
                pcap_dir=args.pcap_dir,
            )
            ctl.build()
            ctl.shutdown()
        except Exception as e:
            print(f"[{i}] FAILURE: {type(e).__name__}: {e}")
            return 0
        cycle_s = time.monotonic() - t0
        rc = _resource_counts()
        ratio = (cycle_s / prev_cycle_s) if prev_cycle_s else 1.0
        print(f"[{i:4}] {cycle_s:.2f}s (ratio {ratio:.2f}) fds={rc['open_fds']} "
              f"ns={rc['all_netns']}")
        prev_cycle_s = cycle_s
        if i > 0 and i % 10 == 0 and cycle_s > 5 * prev_cycle_s:
            print("[limit] runtime ballooned — stopping.")
            return 0
        i += 1
        if i > 1000:
            print("[limit] capped at 1000 cycles.")
            return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="simlab-smoketest")
    ap.add_argument("--data", type=Path, default=DEFAULT_SIM_DATA,
                    help="Dir containing ip4add/ip4routes/ip6add/ip6routes")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG_DIR,
                    help="shorewall46 config directory")
    ap.add_argument("--load-limit", type=float, default=4.0,
                    help="Pause new work while loadavg1 >= this OR cpu/io PSI avg10 >= 40")
    ap.add_argument("--report-dir", type=Path, default=None,
                    help="Override archive directory for run reports")
    ap.add_argument("--no-dump-config", action="store_true", default=False,
                    dest="no_dump_config",
                    help="Disable ip addr/route dump from NS_FW after build")
    ap.add_argument("--pcap-dir", type=str, default=None,
                    metavar="DIR",
                    help="Write pcap files per interface to DIR for debugging")
    sub = ap.add_subparsers(dest="cmd")
    p_smoke = sub.add_parser("smoke",
        help="one build, one probe per representative pair")
    p_smoke.add_argument("--no-auto-sysctl", action="store_true",
        dest="no_auto_sysctl", default=False,
        help="Skip automatic sysctl tuning")
    p_stress = sub.add_parser("stress", help="N build+destroy cycles")
    p_stress.add_argument("iterations", type=int, nargs="?", default=10)
    sub.add_parser("limit", help="push build/destroy until something breaks")
    p_full = sub.add_parser("full",
        help="every rule positive+negative, plus N random probes, "
             "archive report")
    p_full.add_argument("--max-per-pair", type=int, default=10000,
        help="Cap probes per (src,dst) chain — high default = 'all'")
    p_full.add_argument("--random", type=int, default=50,
        help="Number of random probes to add on top of rule coverage")
    p_full.add_argument("--seed", type=int, default=None,
        help="Seed for the random probe generator (None = wall clock)")
    p_full.add_argument("--random-per-rule", type=int, default=64,
        help="Number of random variants sampled per rule within that rule's "
             "own src/dst/port constraints (default 64)")
    p_full.add_argument("--batch-size", type=int, default=512,
        help="Max probes in flight per batch. Higher = more throughput, "
             "more transient RAM for the ProbeSpec batch (default 512)")
    p_full.add_argument("--probe-timeout", type=float, default=0.25,
        help="Per-probe timeout in seconds. IPv6 forwarding needs "
             "NDP neighbor resolution which adds ~100-150 ms on top "
             "of the base TUN/TAP round-trip; 0.25 s covers p99 for "
             "dual-stack runs.  Lower to 0.15 for IPv4-only configs "
             "or raise to 0.5/1.0 if false fail_drops persist "
             "(default 0.25)")
    p_full.add_argument("-v", "--verbose", action="store_true",
        help="Dump raw sysctl values before the run")
    p_full.add_argument("--no-auto-sysctl", action="store_true",
        dest="no_auto_sysctl", default=False,
        help="Skip automatic sysctl tuning (ip_forward, rp_filter, "
             "rmem/wmem_max). Use when running inside a container or "
             "when sysctls are managed externally.")
    p_full.add_argument("--keep-namespace", action="store_true",
        dest="keep_namespace", default=False,
        help="Preserve the simulator namespace after the run for "
             "debugging. You must manually clean it up later with "
             "'sudo ip netns delete <name>'.")
    p_full.add_argument("--sleep-before-shutdown", type=int, default=0,
        metavar="SECONDS",
        help="Sleep N seconds before shutting down the namespace. "
             "Useful for live debugging without a TTY. "
             "Example: --sleep-before-shutdown 300 gives you 5 minutes to inspect.")

    args = ap.parse_args()
    if args.cmd == "smoke" or args.cmd is None:
        return cmd_smoke(args)
    if args.cmd == "stress":
        return cmd_stress(args)
    if args.cmd == "limit":
        return cmd_limit(args)
    if args.cmd == "full":
        return cmd_full(args)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
