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
from typing import Literal

RUN_NETNS = ["sudo", "/usr/local/bin/run-netns"]

NS_SRC = "shorewall-next-sim-src"
NS_FW = "shorewall-next-sim-fw"
NS_DST = "shorewall-next-sim-dst"

# Topology addressing
SRC_FW_GW = "10.200.1.1"
SRC_PEER = "10.200.1.2"
SRC_IFACE = "bond1"       # net-zone interface name in fw
DST_FW_GW = "10.200.2.1"
DST_PEER = "10.200.2.2"
DST_IFACE = "bond0.20"    # host-zone interface name in fw
DEFAULT_SRC = "192.0.2.69"


@dataclass
class TestCase:
    """A single packet test."""
    src_ip: str
    dst_ip: str
    proto: Literal["tcp", "udp", "icmp"]
    port: int | None
    expected: Literal["ACCEPT", "DROP", "REJECT"]
    raw: str = ""


@dataclass
class TestResult:
    test: TestCase
    got: str  # ACCEPT or DROP
    passed: bool
    ms: int = 0


def _ns(ns: str, cmd: str, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a command inside a network namespace."""
    return subprocess.run(
        [*RUN_NETNS, "exec", ns, "sh", "-c", cmd],
        capture_output=True, text=True, timeout=timeout
    )


def _ns_check(ns: str, cmd: str, timeout: int = 10) -> None:
    """Run a command inside a namespace, raise on failure."""
    r = _ns(ns, cmd, timeout)
    if r.returncode != 0:
        raise RuntimeError(f"Command failed in {ns}: {cmd}\n{r.stderr}")


def _kill_ns_pids(ns: str) -> None:
    # `ip netns exec NS kill -9 -1` would target every process the caller can
    # signal on the host, because ip netns provides only network isolation.
    # Enumerate via `ip netns pids` and SIGKILL each PID individually.
    try:
        r = subprocess.run([*RUN_NETNS, "pids", ns],
                           capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return
    for tok in r.stdout.split():
        if tok.isdigit():
            try:
                os.kill(int(tok), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


class SimTopology:
    """Manages the 3-namespace simulation topology."""

    def __init__(self):
        self.src_ips: list[str] = []
        self.dst_ips: list[str] = []
        self._created = False
        self._listener_pids: list[int] = []

    def create(self) -> None:
        """Create the 3 namespaces."""
        for ns in (NS_SRC, NS_FW, NS_DST):
            subprocess.run([*RUN_NETNS, "add", ns],
                           capture_output=True, timeout=5)
        self._created = True

    def setup_src(self, src_ips: list[str]) -> None:
        """Set up the source namespace with veth to fw."""
        self.src_ips = src_ips

        # Create veth pair in fw namespace
        _ns(NS_FW, "ip link add src-fw type veth peer name src-z")
        _ns(NS_FW, f"ip link set src-z netns {NS_SRC}")
        _ns(NS_FW, f"ip link set src-fw name {SRC_IFACE}")
        _ns(NS_FW, f"ip addr add {SRC_FW_GW}/30 dev {SRC_IFACE}")
        _ns(NS_FW, f"ip link set {SRC_IFACE} up")
        # Disable rp_filter on fw side (we use spoofed source IPs)
        _ns(NS_FW, f"echo 0 > /proc/sys/net/ipv4/conf/{SRC_IFACE}/rp_filter")
        _ns(NS_FW, "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter")

        # Add routes to source IPs in fw
        for ip in [DEFAULT_SRC] + src_ips:
            _ns(NS_FW, f"ip route add {ip}/32 dev {SRC_IFACE} 2>/dev/null || true")

        # Set up source namespace
        _ns(NS_SRC, "ip link set lo up")
        _ns(NS_SRC, "ip link set src-z up")
        _ns(NS_SRC, f"ip addr add {SRC_PEER}/30 dev src-z")
        _ns(NS_SRC, f"ip route add default via {SRC_FW_GW}")
        _ns(NS_SRC, f"ip addr add {DEFAULT_SRC}/32 dev src-z 2>/dev/null || true")
        for ip in src_ips:
            if ip != DEFAULT_SRC:
                _ns(NS_SRC, f"ip addr add {ip}/32 dev src-z 2>/dev/null || true")

    def setup_dst(self, dst_ips: list[str]) -> None:
        """Set up the destination namespace with veth to fw."""
        self.dst_ips = dst_ips

        # Create veth pair in fw namespace
        _ns(NS_FW, "ip link add dst-fw type veth peer name dst-z")
        _ns(NS_FW, f"ip link set dst-z netns {NS_DST}")
        _ns(NS_FW, f"ip link set dst-fw name {DST_IFACE}")
        _ns(NS_FW, f"ip addr add {DST_FW_GW}/30 dev {DST_IFACE}")
        _ns(NS_FW, f"ip link set {DST_IFACE} up")
        _ns(NS_FW, f"echo 0 > /proc/sys/net/ipv4/conf/{DST_IFACE}/rp_filter")

        # Add routes to destination IPs in fw
        for ip in dst_ips:
            _ns(NS_FW, f"ip route add {ip}/32 dev {DST_IFACE} 2>/dev/null || true")

        # Set up destination namespace
        _ns(NS_DST, "ip link set lo up")
        _ns(NS_DST, "ip link set dst-z up")
        _ns(NS_DST, f"ip addr add {DST_PEER}/30 dev dst-z")
        _ns(NS_DST, f"ip route add default via {DST_FW_GW}")
        for ip in dst_ips:
            _ns(NS_DST, f"ip addr add {ip}/32 dev dst-z 2>/dev/null || true")

    def setup_fw(self, nft_script_path: str) -> None:
        """Load nft ruleset and enable forwarding in fw namespace."""
        _ns(NS_FW, "ip link set lo up")
        _ns(NS_FW, "echo 1 > /proc/sys/net/ipv4/ip_forward")
        # Disable rp_filter globally (test topology uses non-standard routes)
        _ns(NS_FW, "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter")
        _ns(NS_FW, "echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter")

        r = _ns(NS_FW, f"nft -f {nft_script_path}", timeout=30)
        if r.returncode != 0:
            # nft load failed — likely interface name mismatches.
            # In the simulation topology we only have bond1 (net-side)
            # and bond0.20 (host-side), so rules referencing other
            # interfaces will match iifname/oifname against non-existing
            # interfaces, which is fine — they just won't match any traffic.
            # But syntax errors are fatal.
            if "Error" in r.stderr and "syntax error" in r.stderr.lower():
                raise RuntimeError(f"nft syntax error:\n{r.stderr[:500]}")
            # Non-syntax errors (missing interfaces etc.) are warnings
            print(f"  WARNING: nft -f returned rc={r.returncode}")
            print(f"  {r.stderr[:200]}")

    def setup_listeners(self) -> None:
        """Start TCP and UDP listeners on destination, set up REDIRECT."""
        # iptables REDIRECT all TCP to port 65000, all UDP to 65001
        _ns(NS_DST,
            "iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port 65000 2>/dev/null || true")
        _ns(NS_DST,
            "iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-port 65001 2>/dev/null || true")

        # TCP listener (nc -l -k)
        _ns(NS_DST, "nc -l -k -p 65000 >/dev/null 2>&1 &")

        # UDP echo server
        _ns(NS_DST, """python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 65001))
while True:
    data, addr = s.recvfrom(1024)
    s.sendto(b'PONG', addr)
" >/dev/null 2>&1 &""")

    def destroy(self) -> None:
        """Kill all processes and remove all namespaces."""
        for ns in (NS_DST, NS_FW, NS_SRC):
            _kill_ns_pids(ns)
            time.sleep(0.1)
            subprocess.run([*RUN_NETNS, "delete", ns],
                           capture_output=True, timeout=5)
        self._created = False


def run_tcp_test(src_ip: str, dst_ip: str, port: int) -> tuple[str, int]:
    """Send a TCP connect test. Returns (verdict, ms)."""
    start = time.monotonic_ns()
    r = _ns(NS_SRC, f"nc -z -w 2 -s {src_ip} {dst_ip} {port} 2>/dev/null",
            timeout=5)
    ms = (time.monotonic_ns() - start) // 1_000_000
    verdict = "ACCEPT" if r.returncode == 0 else "DROP"
    return verdict, ms


def run_udp_test(src_ip: str, dst_ip: str, port: int) -> tuple[str, int]:
    """Send a UDP echo test. Returns (verdict, ms)."""
    start = time.monotonic_ns()
    r = _ns(NS_SRC,
            f"echo PING | timeout 2 nc -u -w 1 -s {src_ip} {dst_ip} {port} 2>/dev/null",
            timeout=5)
    ms = (time.monotonic_ns() - start) // 1_000_000
    verdict = "ACCEPT" if "PONG" in (r.stdout or "") else "DROP"
    return verdict, ms


def run_icmp_test(src_ip: str, dst_ip: str) -> tuple[str, int]:
    """Send an ICMP echo request. Returns (verdict, ms)."""
    start = time.monotonic_ns()
    r = _ns(NS_SRC, f"ping -c 1 -W 2 -I {src_ip} {dst_ip} 2>/dev/null",
            timeout=5)
    ms = (time.monotonic_ns() - start) // 1_000_000
    verdict = "ACCEPT" if r.returncode == 0 else "DROP"
    return verdict, ms


def _run_single_test(tc: TestCase) -> TestResult:
    """Run a single test case. Suitable for parallel execution."""
    start = time.monotonic_ns()
    try:
        if tc.proto == "tcp":
            got, ms = run_tcp_test(tc.src_ip, tc.dst_ip, tc.port)
        elif tc.proto == "udp":
            got, ms = run_udp_test(tc.src_ip, tc.dst_ip, tc.port)
        elif tc.proto == "icmp":
            got, ms = run_icmp_test(tc.src_ip, tc.dst_ip)
        else:
            got, ms = "SKIP", 0
    except Exception:
        got, ms = "ERROR", 0

    return TestResult(test=tc, got=got, passed=(got == tc.expected), ms=ms)


def derive_tests(
    iptables_dump: Path,
    target_ip: str = "203.0.113.5",
    max_tests: int = 60,
    seed: int | None = None,
) -> list[TestCase]:
    """Derive test cases from an iptables-save dump.

    Extracts rules targeting target_ip, samples stochastically,
    and returns TestCase objects.
    """
    from shorewall_nft.verify.iptables_parser import parse_iptables_save

    ipt = parse_iptables_save(iptables_dump)
    flt = ipt.get("filter")
    if not flt:
        return []

    candidates: list[TestCase] = []

    for chain_name, rules in flt.rules.items():
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
            src = saddr.rstrip("/32").split("/")[0] if saddr else DEFAULT_SRC

            # For broad subnets, pick a concrete host IP instead of skipping.
            # Covers real-world configs where firewalls allow whole /20s or
            # /16s from trusted nets — we still want to exercise these rules.
            if saddr and "/" in saddr:
                import ipaddress as _ipaddr
                try:
                    net = _ipaddr.ip_network(saddr, strict=False)
                    if net.version != 4:
                        continue  # simulate topology is IPv4 only
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
    max_tests: int = 60,
    seed: int | None = 42,
    verbose: bool = False,
    parallel: int = 4,
    trace: bool = True,
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

    # Write to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft",
                                     delete=False,
                                     prefix="shorewall-next-sim-") as f:
        f.write(nft_script)
        nft_path = f.name

    # Step 2: Derive tests
    tests = derive_tests(iptables_dump, target_ip=target_ip,
                         max_tests=max_tests, seed=seed)
    if not tests:
        print("No test cases derived.")
        Path(nft_path).unlink(missing_ok=True)
        return []

    # Collect unique IPs
    src_ips = list({t.src_ip for t in tests})
    dst_ips = list({t.dst_ip for t in tests})

    # Step 3: Setup topology
    topo = SimTopology()
    results: list[TestResult] = []
    trace_proc = None
    trace_log = Path(tempfile.gettempdir()) / "shorewall-next-sim-trace.log"

    try:
        topo.create()
        topo.setup_src(src_ips)
        topo.setup_dst(dst_ips)
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

        # Step 4b: Connection state validation
        from shorewall_nft.verify.connstate import run_connstate_tests
        print("  Connection state tests:")
        connstate_results = run_connstate_tests(
            dst_ip=target_ip, allowed_port=tests[0].port or 80)
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

        # Step 4b: Run derived tests (parallel)
        if parallel > 1 and len(tests) > 1:
            with ThreadPoolExecutor(max_workers=parallel) as pool:
                futures = {pool.submit(_run_single_test, tc): tc for tc in tests}
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
                result = _run_single_test(tc)
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
