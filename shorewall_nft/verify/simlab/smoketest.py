"""simlab smoke + stress driver.

Exercises the controller end-to-end against the real marcant-fw state
and the marcant-fw shorewall46 config. Intended to be invoked on the
dedicated test VM as root:

    python -m shorewall_nft.verify.simlab.smoketest

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
            d for d in os.listdir(f"/sys/class/net") if d.startswith("simlab")
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
    from .controller import ProbeSpec
    from . import packets as P

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
        P.build_icmp("217.14.160.69", "217.14.160.34",
                      dst_mac=topo_tun_mac.get("bond1")),
        _match(proto="icmp", dst="217.14.160.34"),
        {"desc": "net → adm ICMP (rossini)"})

    # POSITIVE: adm → cdn tcp:443 (explicit ACCEPT in adm2cdn)
    add(TestCategory.POSITIVE, "ACCEPT",
        "bond0.18", "bond0.23",
        P.build_tcp("217.14.160.34", "46.231.239.11", 443,
                     dst_mac=topo_tun_mac.get("bond0.18")),
        _match(proto="tcp", dst="46.231.239.11", dport=443),
        {"desc": "adm → cdn tcp:443"})

    # NEGATIVE: rossini (net) → host:100:80 (no net2host rule)
    add(TestCategory.NEGATIVE, "DROP",
        "bond1", "bond0.20",
        P.build_tcp("217.14.160.69", "217.14.168.100", 80,
                     dst_mac=topo_tun_mac.get("bond1")),
        _match(proto="tcp", dst="217.14.168.100", dport=80),
        {"desc": "net → host tcp:80 (should be dropped — no rule)"})

    # NEGATIVE: net → fw tcp:22 (net2fw drops ssh unless src is rossini)
    add(TestCategory.NEGATIVE, "DROP",
        "bond1", "bond1",   # fw zone — input chain
        P.build_tcp("1.2.3.4", "217.14.160.75", 22,
                     dst_mac=topo_tun_mac.get("bond1")),
        _match(proto="tcp", dst="217.14.160.75", dport=22),
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
    pid = 1000
    for _ in range(n):
        r = rgen.next()
        if r is None:
            break
        if r.proto not in ("tcp", "udp", "icmp"):
            continue
        pid16 = pid & 0xffff
        verdict = oracle.classify(
            src_zone=r.src_zone, dst_zone=r.dst_zone,
            src_ip=r.src_ip, dst_ip=r.dst_ip,
            proto=r.proto, port=r.port,
        )
        plan = {
            "probe_id": pid16,
            "src_iface": r.src_iface,
            "dst_iface": r.dst_iface,
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "proto": r.proto,
            "port": r.port,
        }
        meta = {
            "desc": f"{r.src_zone}→{r.dst_zone} "
                    f"{r.src_ip}→{r.dst_ip} {r.proto}:{r.port}",
            "oracle_reason": verdict.reason,
        }
        out.append((TestCategory.RANDOM, verdict.verdict, plan, meta))
        pid += 1
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
    subnet that's NOT the firewall's own address. That gives us a
    valid spoof-free source for every rule.
    """
    import ipaddress as _ipaddr
    out: dict[str, str] = {}
    for iface_name, zone in iface_to_zone.items():
        if zone in out:
            continue
        iface = fw_state.interfaces.get(iface_name)
        if not iface or not iface.addrs4:
            continue
        for addr in iface.addrs4:
            try:
                net = _ipaddr.ip_network(
                    f"{addr.addr}/{addr.prefixlen}", strict=False)
            except ValueError:
                continue
            hosts = [str(h) for h in net.hosts()]
            if not hosts:
                continue
            fw_ip = addr.addr
            for h in hosts:
                if h != fw_ip:
                    out[zone] = h
                    break
            if zone in out:
                break
    return out


def _plan_to_spec(plan: dict, topo_tun_mac: dict,
                  timeout_s: float = 2.0):
    """Build a ProbeSpec from a lightweight plan dict on demand."""
    from .controller import ProbeSpec
    from . import packets as P

    src_iface = plan["src_iface"]
    dst_iface = plan["dst_iface"]
    proto = plan["proto"]
    pid16 = plan["probe_id"]
    src_ip = plan["src_ip"]
    dst_ip = plan["dst_ip"]
    port = plan.get("port")
    dst_mac = topo_tun_mac.get(src_iface)

    if proto == "tcp":
        payload = P.build_tcp(src_ip, dst_ip, port, dst_mac=dst_mac,
                              probe_id=pid16)
        match = _match(proto="tcp", dst=dst_ip, dport=port)
    elif proto == "udp":
        payload = P.build_udp(src_ip, dst_ip, port, dst_mac=dst_mac,
                              probe_id=pid16)
        match = _match(proto="udp", dst=dst_ip, dport=port)
    elif proto == "icmp":
        payload = P.build_icmp(src_ip, dst_ip, dst_mac=dst_mac,
                               probe_id=pid16)
        match = _match(proto="icmp", dst=dst_ip)
    else:
        return None

    return ProbeSpec(
        probe_id=pid16, inject_iface=src_iface,
        expect_iface=dst_iface, payload=payload, match=match,
        timeout_s=timeout_s,
    )


def _build_per_rule_probes(
    iptables_dump: Path, fw_state, iface_to_zone: dict,
    topo_tun_mac: dict, *, max_per_pair: int = 10000,
    random_per_rule: int = 64,
) -> list[tuple]:
    """Build lightweight plan dicts for every (src,dst) chain rule we understand.

    Returns ``list[(category, expected, plan_dict, meta)]`` where
    ``plan_dict`` is cheap (~200 bytes) compared to a full ProbeSpec
    (~3 KB with payload + match closure). The batch loop in cmd_full
    converts plan → ProbeSpec just before firing a batch and discards
    after, keeping parent RSS bounded to ~batch_size ProbeSpecs.
    """
    from shorewall_nft.verify.simulate import (
        DEFAULT_SRC, derive_tests_all_zones,
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

    out: list[tuple] = []
    pid = 10000
    for tc in cases:
        if tc.src_zone is None or tc.dst_zone is None:
            continue
        src_iface = zone_to_iface.get(tc.src_zone)
        dst_iface = zone_to_iface.get(tc.dst_zone)
        if not src_iface or not dst_iface:
            continue
        if tc.proto not in ("tcp", "udp", "icmp"):
            continue
        pid16 = pid & 0xffff
        cat = (TestCategory.POSITIVE if tc.expected == "ACCEPT"
               else TestCategory.NEGATIVE)
        plan = {
            "probe_id": pid16,
            "src_iface": src_iface,
            "dst_iface": dst_iface,
            "src_ip": tc.src_ip,
            "dst_ip": tc.dst_ip,
            "proto": tc.proto,
            "port": tc.port,
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
        pid += 1
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
            f"           ↳ fail_drop  = should have had access but was DROPPED\n"
            f"           ↳ fail_accept = should have been blocked but was ACCEPTED",
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

    warns = _check_sysctls(verbose=args.verbose)
    if warns:
        _flush_print("sysctl health WARNINGS:")
        for w in warns:
            _flush_print(f"  ! {w}")
    else:
        _flush_print("sysctl health: ok")

    before = _resource_counts()
    _flush_print(f"before: {before}")

    t0 = time.monotonic()
    ctl = SimController(
        ip4add=args.data / "ip4add",
        ip4routes=args.data / "ip4routes",
        ip6add=args.data / "ip6add",
        ip6routes=args.data / "ip6routes",
    )
    ctl.build()
    t_build = time.monotonic() - t0
    _flush_print(f"build: {t_build:.2f}s ({len(ctl.workers)} ifaces)")

    nft = Path("/tmp/simlab-ruleset.nft")
    _flush_print("compile: shorewall-nft compile …")
    _compile_ruleset(args.config, nft)
    _flush_print("compile: ok")
    try:
        _flush_print("nft load: …")
        ctl.load_nft(str(nft))
    except RuntimeError as e:
        _flush_print(f"nft LOAD FAILED: {e}")
        ctl.shutdown()
        return 2
    t_load = time.monotonic() - t0 - t_build
    _flush_print(f"nft load: {t_load:.2f}s")
    time.sleep(0.2)

    iface_to_zone = _iface_to_zone_map(args.config)
    _flush_print("oracle: parsing iptables.txt for point-of-truth …")
    oracle = RulesetOracle(args.data / "iptables.txt")
    _flush_print("oracle: ready")

    # Build probes across categories
    t_build_p0 = time.monotonic()
    _flush_print(f"probes: generating per-rule (random_per_rule="
                 f"{args.random_per_rule}) …")
    rules_probes = _build_per_rule_probes(
        args.data / "iptables.txt", ctl.state, iface_to_zone,
        ctl.topo.tun_mac if ctl.topo else {},
        max_per_pair=args.max_per_pair,
        random_per_rule=args.random_per_rule,
    )
    _flush_print(f"probes: per-rule built, {len(rules_probes)} cases")
    _flush_print(f"probes: generating {args.random} random …")
    random_probes = _build_random_probes(
        args.random, ctl.topo.tun_mac if ctl.topo else {},
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
    dropped_routing = 0
    kept: list = []
    for cat, expected, plan, meta in all_probes:
        routed = _routed_iface_for(plan["dst_ip"], ctl.state)
        if routed is None or routed != plan["dst_iface"]:
            dropped_routing += 1
            continue
        kept.append((cat, expected, plan, meta))
    if dropped_routing:
        _flush_print(
            f"autorepair: dropped {dropped_routing} probes whose dst_ip "
            f"routes to a different iface than the dst zone implies "
            f"(routing_incompatible)")
    all_probes = kept

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
    before = _resource_counts()
    print(f"before: {before}")

    t0 = time.monotonic()
    ctl = SimController(
        ip4add=args.data / "ip4add",
        ip4routes=args.data / "ip4routes",
        ip6add=args.data / "ip6add",
        ip6routes=args.data / "ip6routes",
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
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("smoke", help="one build, one probe per representative pair")
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
    p_full.add_argument("--batch-size", type=int, default=256,
        help="Max probes in flight per batch. Higher = more throughput, "
             "more transient RAM for the ProbeSpec batch (default 256)")
    p_full.add_argument("--probe-timeout", type=float, default=0.7,
        help="Per-probe timeout in seconds. On TUN/TAP loopback a probe "
             "round-trip is <10 ms, so 0.7 s is massive headroom while "
             "giving ~3x throughput vs the old 2 s default. Raise back "
             "to 2.0 for pathological forwarding behaviour (default 0.7)")
    p_full.add_argument("-v", "--verbose", action="store_true",
        help="Dump raw sysctl values before the run")

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
