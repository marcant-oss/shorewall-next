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
            ["pgrep", "-cf", "simlab-"],
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


def _load_ok(limit: float) -> bool:
    """True if current 1-min loadavg is below ``limit``."""
    try:
        return os.getloadavg()[0] < limit
    except OSError:
        return True


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


def _build_probes(topo_tun_mac: dict) -> list:
    """Build a representative set of probes covering every protocol.

    Destinations are chosen so each lands on a zone handled by the
    marcant ruleset: bond0.20 (host), bond0.18 (adm), bond0.17 (siem).
    """
    from .controller import ProbeSpec
    from . import packets as P
    probes: list = []
    pid = 1

    def m(**kw):
        """Return a match-callback that requires all kw to match obs."""
        def inner(obs):
            for k, v in kw.items():
                if obs.get(k) != v:
                    return False
            return True
        return inner

    # host-r (net) → host:203.0.113.230:80 TCP SYN
    probes.append(ProbeSpec(
        probe_id=pid, inject_iface="bond1", expect_iface="bond0.20",
        payload=P.build_tcp(
            "203.0.113.69", "203.0.113.230", 80,
            dst_mac=topo_tun_mac.get("bond1"),
        ),
        match=m(proto="tcp", dst="203.0.113.230", dport=80),
    ))
    pid += 1

    # net → host UDP/53 (DNS-style)
    probes.append(ProbeSpec(
        probe_id=pid, inject_iface="bond1", expect_iface="bond0.20",
        payload=P.build_udp(
            "203.0.113.69", "203.0.113.230", 53, sport=30000,
            dst_mac=topo_tun_mac.get("bond1"),
        ),
        match=m(proto="udp", dst="203.0.113.230", dport=53),
    ))
    pid += 1

    # net → adm ICMP echo
    probes.append(ProbeSpec(
        probe_id=pid, inject_iface="bond1", expect_iface="bond0.18",
        payload=P.build_icmp(
            "203.0.113.69", "203.0.113.34",
            dst_mac=topo_tun_mac.get("bond1"),
        ),
        match=m(proto="icmp", dst="203.0.113.34"),
    ))
    pid += 1

    return probes


# ─────────────────────────────────────────────────────────────────────


def cmd_smoke(args: argparse.Namespace) -> int:
    from .controller import SimController
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

    probes = _build_probes(ctl.topo.tun_mac if ctl.topo else {})
    print(f"probes: {len(probes)}")
    results = asyncio.run(_smoke_one(ctl, probes))
    for r in results:
        print(f"  [{r.verdict or 'NONE'}] {r.inject_iface}→{r.expect_iface} "
              f"id={r.probe_id} {r.elapsed_ms}ms")

    ctl.shutdown()
    after = _resource_counts()
    print(f"after:  {after}")
    leaked = {k: after.get(k, 0) - before.get(k, 0) for k in after}
    print(f"delta:  {leaked}")
    return 0


def cmd_stress(args: argparse.Namespace) -> int:
    from .controller import SimController
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
    ap.add_argument("--load-limit", type=float, default=10.0,
                    help="Pause new cycles while 1-min loadavg is >= this value")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("smoke", help="one build, one probe per representative pair")
    p_stress = sub.add_parser("stress", help="N build+destroy cycles")
    p_stress.add_argument("iterations", type=int, nargs="?", default=10)
    sub.add_parser("limit", help="push build/destroy until something breaks")

    args = ap.parse_args()
    if args.cmd == "smoke" or args.cmd is None:
        return cmd_smoke(args)
    if args.cmd == "stress":
        return cmd_stress(args)
    if args.cmd == "limit":
        return cmd_limit(args)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
