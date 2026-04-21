"""simlab orchestrator — single-process asyncio design.

Owns the :class:`SimFwTopology` **and** every TUN/TAP file
descriptor directly. One Python interpreter, one asyncio event
loop. No worker subprocesses, no multiprocessing pipes, no ARP/
NDP slaves. Everything the old worker did (packet parse, ARP
who-has reply, NDP NS → NA, observed-packet dispatch) runs
inline as asyncio reader callbacks on the fds.

Why single-process:

* Each extra Python interpreter ships ~80 MB of heap
  (stdlib + scapy + shorewall_nft imports). Twenty-four workers
  cost 2 GB of RAM purely for the interpreters. One process
  costs ~150 MB total.
* Inject path is ``os.write(fd, payload)`` — no pipe roundtrip.
* Shutdown is trivial: close fds, destroy topology. No
  subprocess join/terminate/kill dance.
* The packet-handling work is dominated by asyncio reader
  events and scapy parsing; both are fine in a single process.
"""

from __future__ import annotations

import asyncio
import atexit
import os
import signal
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from shorewall_nft_netkit.netns_fork import run_in_netns_fork

from .dumps import FwState, load_fw_state
from .packets import (
    PacketSummary,
    build_arp_reply,
    build_ndp_na,
    fast_build_arp_reply,
    fast_build_ndp_na,
    fast_extract_arp_request,
    fast_extract_ndp_ns,
    fast_is_arp_or_ndp_ns,
    fast_probe_id,
    parse,
)
from .topology import NS_FW_DEFAULT, SimFwTopology

# Synthetic MAC for every TAP the controller services. Same MAC on
# every TAP is fine: each TAP is its own L2 segment.
_WORKER_MAC = "02:00:00:5e:00:01"


# ---------------------------------------------------------------------------
# Module-level helpers for run_in_netns_fork (must be pickleable)
# ---------------------------------------------------------------------------


def _libnftables_load_script_in_child(script: str) -> tuple[int, str]:
    """Load an nft script via libnftables inside the target netns."""
    try:
        import nftables as _nft_mod
    except ImportError:
        import sys as _sys
        _sys.path.insert(0, "/usr/lib/python3/dist-packages")
        import nftables as _nft_mod
    nft = _nft_mod.Nftables()
    nft.set_json_output(False)
    nft.set_handle_output(False)
    rc, _out, err = nft.cmd(script)
    return (rc, err or "")


def _mac_to_link_local(mac: str) -> str:
    """Convert a MAC address to an IPv6 link-local address (EUI-64).

    MAC: 02:00:00:5e:00:01 → fe80::200:5eff:fe5e:1
    """
    parts = mac.split(":")
    if len(parts) != 6:
        # Fallback to hardcoded address if MAC format is unexpected
        return "fe80::200:5eff:fe00:1"
    # EUI-64: insert ff:fe in the middle
    return f"fe80::{parts[0]}{parts[1]}:{parts[2]}ff:fe{parts[3]}:{parts[4]}{parts[5]}"


def _extract_src_mac(raw: bytes) -> str:
    """Cheap Ethernet src-MAC extraction — bytes 6..12 of the frame."""
    if len(raw) < 12:
        return "ff:ff:ff:ff:ff:ff"
    return ":".join(f"{b:02x}" for b in raw[6:12])


@dataclass
class ProbeSpec:
    """A probe the controller wants to inject + observe."""
    probe_id: int
    inject_iface: str     # iface whose worker writes the packet
    expect_iface: str     # iface whose worker should see it come out
    payload: bytes        # already-built raw bytes (from packets.build_*)
    match: Callable[[dict], bool]  # filter on observed packet summary
    timeout_s: float = 2.0
    # Filled in as the probe progresses
    started_ns: int = 0
    verdict: str | None = None  # "ACCEPT" / "DROP" / "ERROR"
    elapsed_ms: int = 0
    trace: list[dict] = field(default_factory=list)


class SimController:
    """Top-level simlab controller."""

    def __init__(
        self,
        *,
        ip4add: Path,
        ip4routes: Path,
        ip6add: Path | None = None,
        ip6routes: Path | None = None,
        ns_name: str = NS_FW_DEFAULT,
        workers_max: int | None = None,  # unused in single-process mode
        trace_depth: int = 128,
        num_threads: int | None = None,
        iface_rp_filter: dict[str, str] | None = None,
        dump_config: bool = True,  # default to True for debugging
        pcap_dir: str | None = None,  # write pcap files per interface to this dir
    ):
        self.paths = (ip4add, ip4routes, ip6add, ip6routes)
        self.ns_name = ns_name
        self._dump_config = dump_config
        self._pcap_dir = pcap_dir
        # Forward to SimFwTopology so per-iface routefilter values
        # from the parsed shorewall config replace the historical
        # rp_filter=0 forcing.
        self._iface_rp_filter = dict(iface_rp_filter or {})
        self.state: FwState | None = None
        self.topo: SimFwTopology | None = None
        # Per-iface state held inline by the controller. Replaces the
        # whole subprocess-based worker pool.
        self._iface_fds: dict[str, int] = {}
        self._iface_kind: dict[str, str] = {}
        self._iface_mac: dict[str, str | None] = {}
        self._iface_trace: dict[str, deque[PacketSummary]] = {}
        self._trace_depth = trace_depth
        self._probes: dict[int, ProbeSpec] = {}
        self._probe_futures: dict[int, asyncio.Future] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown_done = False
        self._cleanup_registered = False
        # Pcap writers per interface (if pcap_dir is set)
        self._iface_pcap: dict[str, Any] = {}
        self._pcap_lock: threading.Lock | None = None
        # Thread pool — one (reader, writer) pair per CPU core by
        # default. The reader drains a partition of TUN/TAP fds,
        # parses every frame, answers ARP/NDP by pushing replies
        # onto its paired writer's queue, and enqueues observed IP
        # packets onto the main thread's ``_obs_queue``. The writer
        # runs a tight ``queue.get → os.write`` loop. Split reader
        # and writer so a slow os.write can't block the read path
        # and vice versa.
        if num_threads is None:
            try:
                num_threads = max(1, os.cpu_count() or 2)
            except Exception:
                num_threads = 2
        self._num_threads = num_threads
        self._reader_threads: list = []
        self._writer_threads: list = []
        self._reader_stop_events: list = []
        self._writer_stop_events: list = []
        # One write queue per (reader, writer) pair. Every os.write
        # targeting a fd owned by pair N goes through
        # ``self._write_queues[N].put((fd, bytes))``.
        self._write_queues: list = []
        # iface_name → pair index, populated at run_probes() time so
        # the main thread can dispatch a probe inject to the right
        # writer queue in O(1).
        self._iface_to_pair: dict[str, int] = {}
        self._obs_queue: "Any | None" = None
        # No-op back-compat alias used by legacy tests / callers that
        # inspect ``workers`` to see which interfaces exist.
        self.workers: dict[str, tuple[Any, Any]] = {}
        # Firewall-owned IPv6 addresses — populated in build().
        # NDP responder skips NS for these to avoid DAD conflicts.
        self._fw_owned_v6: set[str] = set()

    # ── lifecycle ─────────────────────────────────────────────────

    def reload_dumps(self) -> FwState:
        """Re-read the FW state dumps from disk and return the fresh state."""
        self.state = load_fw_state(*self.paths)
        return self.state

    def build(self) -> None:
        """Build the NS_FW topology and take ownership of every TUN/TAP fd.

        Single-process mode: the controller keeps the fds in its own
        address space. No workers are forked. ``run_probes`` will
        register one asyncio reader per fd on the controller's own
        event loop and handle packets inline.
        """
        self._register_cleanup()
        self.reload_dumps()
        assert self.state is not None
        self.topo = SimFwTopology(
            self.state, ns_name=self.ns_name,
            iface_rp_filter=self._iface_rp_filter,
        )
        self.topo.build(dump_config=self._dump_config)

        # Take ownership of each TUN/TAP fd + per-iface metadata
        for name, fd in list(self.topo.tun_fds.items()):
            self._iface_fds[name] = fd
            self._iface_kind[name] = self.topo.tun_kind[name]
            self._iface_mac[name] = self.topo.tun_mac.get(name)
            self._iface_trace[name] = deque(maxlen=self._trace_depth)
            try:
                os.set_blocking(fd, False)
            except OSError:
                pass
            # Back-compat marker so callers that iterate self.workers
            # to find "which interfaces exist" still see the full set.
            self.workers[name] = (None, None)
        # Clear topo.tun_fds so topo.destroy() doesn't try to close
        # them a second time — we close them in _shutdown.
        self.topo.tun_fds.clear()

        # Collect firewall-owned IPv6 addresses (global + link-local)
        # by querying the live namespace. Static computation from the
        # dump misses the kernel-auto-generated link-local addresses
        # (derived from the random TAP MAC assigned at creation time).
        # Answering NS for any of these causes DAD conflicts ("NA: XX
        # advertised our address") and the kernel discards the NA.
        self._fw_owned_v6 = set()
        from pyroute2 import NetNS
        with NetNS(self.ns_name) as ipr:
            for addr in ipr.get_addr(family=10):
                a = addr.get_attr("IFA_ADDRESS")
                if a:
                    self._fw_owned_v6.add(a)

        # Initialize pcap writers if requested
        if self._pcap_dir:
            import threading
            self._pcap_lock = threading.Lock()
            from pathlib import Path
            pcap_path = Path(self._pcap_dir)
            pcap_path.mkdir(parents=True, exist_ok=True)
            import scapy.all as s
            for iface in self._iface_fds:
                pcap_file = pcap_path / f"{iface}.pcap"
                # linktype=1 is DLT_EN10MB (Ethernet)
                writer = s.PcapWriter(str(pcap_file), sync=True, linktype=1)
                self._iface_pcap[iface] = writer

    def load_nft(self, nft_script_path: str) -> None:
        """Load an nft script into NS_FW via run_in_netns_fork (safe from event loop).

        Reads the script text in the parent (path is always accessible here)
        then passes the text to a forked child that enters NS_FW and feeds it
        to a fresh libnftables handle — avoids cached netlink socket issues.
        """
        script = Path(nft_script_path).read_text()
        rc, err = run_in_netns_fork(
            self.ns_name, _libnftables_load_script_in_child, script
        )
        if rc != 0:
            raise RuntimeError(f"nft -f failed (rc={rc}):\n{err[:2000]}")

    # ── probe dispatch ────────────────────────────────────────────

    def _start_thread_pool(self) -> None:
        """Spawn the reader+writer thread pool once per controller.

        Idempotent: does nothing if the pool is already running.
        The pool lives from first ``run_probes`` call until
        ``_shutdown``; individual batch calls reuse it so the
        ~5 ms per-thread setup cost is amortised across the whole
        scan instead of being paid once per batch.
        """
        if self._reader_threads:
            return
        import queue as _queue
        import threading as _threading

        ifaces = sorted(self._iface_fds.keys())
        n_pairs = max(1, min(self._num_threads, len(ifaces)))
        groups: list[list[str]] = [[] for _ in range(n_pairs)]
        for i, iface in enumerate(ifaces):
            groups[i % n_pairs].append(iface)
        self._iface_to_pair = {
            iface: pair_idx
            for pair_idx, group in enumerate(groups)
            for iface in group
        }

        # Writers first so reader's first ARP/NDP reply has a queue.
        for pid, group in enumerate(groups):
            wq: _queue.SimpleQueue = _queue.SimpleQueue()
            self._write_queues.append(wq)
            w_stop = _threading.Event()
            self._writer_stop_events.append(w_stop)
            w = _threading.Thread(
                target=self._writer_thread_main,
                args=(pid, wq, w_stop),
                name=f"simlab-writer-{pid}",
                daemon=True,
            )
            w.start()
            self._writer_threads.append(w)

            r_stop = _threading.Event()
            self._reader_stop_events.append(r_stop)
            r = _threading.Thread(
                target=self._reader_thread_main,
                args=(pid, group, r_stop, self._iface_mac, self._iface_kind,
                      self._fw_owned_v6),
                name=f"simlab-reader-{pid}",
                daemon=True,
            )
            r.start()
            self._reader_threads.append(r)

        active_threads = _threading.active_count()
        print(
            f"threads: spawned {len(self._reader_threads)} reader + "
            f"{len(self._writer_threads)} writer thread(s) "
            f"(total alive={active_threads}); ifaces/pair="
            f"{[len(g) for g in groups]}",
            flush=True,
        )

    async def run_probes(self, probes: list[ProbeSpec]) -> list[ProbeSpec]:
        """Inject every probe and wait for its matching response.

        Uses the persistent reader+writer thread pool (see
        :meth:`_start_thread_pool`). Threads live across all
        ``run_probes`` calls so their setup cost is paid exactly
        once per controller. Per-call state: a fresh
        ``asyncio.Queue``-free observation queue and the drainer
        task.
        """
        import queue as _queue

        self._loop = asyncio.get_running_loop()
        self._start_thread_pool()
        # Per-run observation queue. Reset every call so the
        # previous call's drained items don't leak into this one.
        self._obs_queue = _queue.SimpleQueue()

        drainer_task = asyncio.create_task(self._drain_observations())

        futures: list[asyncio.Future] = []
        for probe in probes:
            self._probes[probe.probe_id] = probe
            fut = self._loop.create_future()
            self._probe_futures[probe.probe_id] = fut
            probe.started_ns = time.monotonic_ns()
            self._inject(probe)
            futures.append(self._wait_probe(probe, fut))

        await asyncio.gather(*futures, return_exceptions=True)

        drainer_task.cancel()
        try:
            await drainer_task
        except (asyncio.CancelledError, Exception):
            pass
        self._obs_queue = None

        return probes

    async def _drain_observations(self) -> None:
        """Feed observations from reader threads into probe correlation.

        Each queue item is a ``(iface_name, probe_id_int)`` tuple
        pushed by the reader thread's fast path. Correlation is a
        single dict lookup plus expect_iface check — no scapy, no
        dict allocation per packet.
        """
        import queue as _queue
        try:
            while True:
                drained = 0
                while True:
                    try:
                        iface, pid_val = self._obs_queue.get_nowait()  # type: ignore[union-attr]
                    except _queue.Empty:
                        break
                    self._on_observed_fast(iface, pid_val)
                    drained += 1
                    if drained >= 256:
                        break
                await asyncio.sleep(0 if drained else 0.001)
        except asyncio.CancelledError:
            try:
                while True:
                    iface, pid_val = self._obs_queue.get_nowait()  # type: ignore[union-attr]
                    self._on_observed_fast(iface, pid_val)
            except _queue.Empty:
                pass
            except Exception:
                pass
            raise

    def _on_observed_fast(self, obs_iface: str, probe_id: int) -> None:
        """Match an observed probe_id against outstanding probes.

        No packet summary, no match() fallback — correlation is the
        primary ``probe_id → probe`` dict lookup only. If a probe
        has been NAT-rewritten (rare on simlab, no nat rules by
        default), it'll fall through to a timeout; the test
        infrastructure can re-run it at full scapy parse fidelity
        by toggling a debug flag (not wired yet).
        """
        probe = self._probes.get(probe_id)
        if probe is None:
            return
        if probe.expect_iface != obs_iface:
            return
        probe.verdict = "ACCEPT"
        probe.elapsed_ms = int(
            (time.monotonic_ns() - probe.started_ns) / 1e6)
        fut = self._probe_futures.get(probe.probe_id)
        if fut and not fut.done():
            fut.set_result(None)

    def _writer_thread_main(self, pid: int, wq, stop_ev) -> None:
        """Entry point for one writer thread.

        Tight ``queue.get → os.write`` loop. Consumes ``(fd, iface_name, bytes)``
        tuples from its paired write queue and writes them out.
        All os.write calls in simlab go through a writer thread so
        probe injection and ARP/NDP replies can't stall the main
        event loop or the reader threads. The writer has its own
        core slot under the GIL while the reader parses the next
        frame in parallel (parse releases the GIL briefly during
        scapy's C-accelerated paths).
        """
        import queue as _queue
        while not stop_ev.is_set():
            try:
                cmd = wq.get(timeout=0.1)
            except _queue.Empty:
                continue
            if cmd is None:
                break
            fd, iface_name, payload = cmd
            try:
                os.write(fd, payload)
            except OSError:
                pass
            # Write to pcap if enabled
            if self._pcap_dir and self._pcap_lock:
                with self._pcap_lock:
                    writer = self._iface_pcap.get(iface_name)
                    if writer:
                        try:
                            writer.write(payload)
                        except Exception:
                            pass
        # Drain any remaining queued writes so the last few probes /
        # ARP replies still hit the wire before we tear down.
        try:
            while True:
                fd, iface_name, payload = wq.get_nowait()
                try:
                    os.write(fd, payload)
                except OSError:
                    pass
                if self._pcap_dir and self._pcap_lock:
                    with self._pcap_lock:
                        writer = self._iface_pcap.get(iface_name)
                        if writer:
                            try:
                                writer.write(payload)
                            except Exception:
                                pass
        except _queue.Empty:
            pass
        except Exception:
            pass

    def _reader_thread_main(self, tid: int, ifaces: list[str], stop_ev, iface_mac: dict[str, str], iface_kind: dict[str, str], fw_owned_v6: set[str] | None = None) -> None:
        """Entry point for one reader thread.

        Runs its own asyncio loop with the assigned subset of TUN/TAP
        fds. ARP / NDP replies are **queued to the paired writer
        thread** instead of written inline — splits read and write
        into separate GIL slots so a slow write never stalls the
        parse loop. Observed IP packets are pushed onto
        ``self._obs_queue`` for the main thread to correlate.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        write_q = self._write_queues[tid]

        def on_read(iface_name: str) -> None:
            fd = self._iface_fds[iface_name]
            is_tap = self._iface_kind[iface_name] == "tap"
            try:
                while True:
                    try:
                        buf = os.read(fd, 65536)
                    except BlockingIOError:
                        return
                    except OSError:
                        return
                    if not buf:
                        return

                    # Write to pcap if enabled (received packet)
                    if self._pcap_dir and self._pcap_lock:
                        with self._pcap_lock:
                            writer = self._iface_pcap.get(iface_name)
                            if writer:
                                try:
                                    writer.write(buf)
                                except Exception:
                                    pass

                    # Fast path: observed IP traffic doesn't need
                    # the scapy parse — pull the probe_id straight
                    # out of the IPv4 id / IPv6 flow-label bytes
                    # and push it onto the observation queue. This
                    # is ~100x cheaper than scapy.Ether(buf), which
                    # matters for >1000 probes/s workloads where
                    # the GIL would otherwise serialise the parse
                    # across every thread onto a single core.
                    if not fast_is_arp_or_ndp_ns(buf, is_tap):
                        pid_val = fast_probe_id(buf, is_tap)
                        if pid_val is not None and self._obs_queue is not None:
                            self._obs_queue.put((iface_name, pid_val))
                        continue

                    # ── Fast path for ARP / NDP ──────────────────
                    # Pure byte-level extraction + reply build.
                    # No scapy parse, no GIL-heavy C extensions —
                    # keeps the reader's asyncio loop responsive so
                    # fds assigned to the same thread don't starve
                    # while we handle NDP on another interface.

                    # ARP who-has → reply
                    arp = fast_extract_arp_request(buf, is_tap)
                    if arp is not None:
                        a_src_mac, a_src_ip, _, a_dst_ip = arp
                        if iface_name in iface_mac:
                            src_mac_for_reply = iface_mac[iface_name]
                        else:
                            src_mac_for_reply = _WORKER_MAC
                        reply = fast_build_arp_reply(
                            src_mac=src_mac_for_reply,
                            src_ip=a_dst_ip,
                            dst_mac=a_src_mac,
                            dst_ip=a_src_ip,
                        )
                        write_q.put((fd, iface_name, reply))
                        continue

                    # NDP NS → NA
                    ndp = fast_extract_ndp_ns(buf, is_tap)
                    if ndp is not None:
                        ns_src_mac, ns_src_ip, target = ndp
                        # Do NOT answer NS for addresses that the
                        # firewall itself owns inside NS_FW. Doing
                        # so causes DAD conflicts ("NA: XX
                        # advertised our address") and the kernel
                        # discards the NA entirely.
                        if fw_owned_v6 and target in fw_owned_v6:
                            continue
                        if iface_name in iface_mac:
                            src_ll = _mac_to_link_local(iface_mac[iface_name])
                            src_mac_for_na = iface_mac[iface_name]
                        else:
                            src_ll = "fe80::200:5eff:fe00:1"
                            src_mac_for_na = _WORKER_MAC
                        # DAD-style NS (src=::) → multicast NA
                        if ns_src_ip and ns_src_ip != "::":
                            dst_ip = ns_src_ip
                        else:
                            dst_ip = "ff02::1"
                        na = fast_build_ndp_na(
                            src_mac=src_mac_for_na,
                            src_ip=src_ll,
                            dst_mac=ns_src_mac,
                            dst_ip=dst_ip,
                            target_ip=target,
                        )
                        write_q.put((fd, iface_name, na))
                        continue
            except Exception:
                return

        for iface_name in ifaces:
            loop.add_reader(self._iface_fds[iface_name],
                            on_read, iface_name)

        async def _waiter() -> None:
            while not stop_ev.is_set():
                await asyncio.sleep(0.02)

        try:
            loop.run_until_complete(_waiter())
        finally:
            for iface_name in ifaces:
                try:
                    loop.remove_reader(self._iface_fds[iface_name])
                except Exception:
                    pass
            try:
                loop.close()
            except Exception:
                pass

    async def _wait_probe(self, probe: ProbeSpec, fut: asyncio.Future) -> None:
        try:
            await asyncio.wait_for(fut, timeout=probe.timeout_s)
        except asyncio.TimeoutError:
            probe.verdict = "DROP"
            probe.elapsed_ms = int(
                (time.monotonic_ns() - probe.started_ns) / 1e6)
            # Snapshot every iface's trace ring so the report can
            # explain where the packet disappeared.
            probe.trace = self._snapshot_traces()
        finally:
            self._probes.pop(probe.probe_id, None)
            self._probe_futures.pop(probe.probe_id, None)

    def _inject(self, probe: ProbeSpec) -> None:
        fd = self._iface_fds.get(probe.inject_iface)
        if fd is None:
            probe.verdict = "ERROR"
            fut = self._probe_futures.get(probe.probe_id)
            if fut and not fut.done():
                fut.set_result(None)
            return
        # Route the write through the paired writer thread's queue.
        # Writer threads own all os.write calls so a slow/blocked
        # write can't stall the main event loop.
        pair_idx = self._iface_to_pair.get(probe.inject_iface, 0)
        try:
            self._write_queues[pair_idx].put((fd, probe.inject_iface, probe.payload))
        except Exception:
            probe.verdict = "ERROR"
            fut = self._probe_futures.get(probe.probe_id)
            if fut and not fut.done():
                fut.set_result(None)

    # ── inline TUN/TAP reader (was the worker loop) ───────────────

    def _on_tap_read(self, iface_name: str) -> None:
        """Drain packets from one TUN/TAP fd and handle them inline.

        Replaces the old InterfaceWorker._on_tap_read plus its
        subprocess ↔ controller pipe. ARP / NDP replies are
        written back to the same fd; observed packets dispatch
        straight into self._probes / self._probe_futures so a
        probe's response latency is now one asyncio event round,
        not one pipe round plus one asyncio round.
        """
        fd = self._iface_fds[iface_name]
        try:
            while True:
                try:
                    buf = os.read(fd, 65536)
                except BlockingIOError:
                    return
                except OSError:
                    return
                if not buf:
                    return
                self._handle_packet(iface_name, buf)
        except Exception:  # pragma: no cover — worker-level safety net
            return

    def _handle_packet(self, iface_name: str, raw: bytes) -> None:
        # Write to pcap if enabled (thread-safe)
        if self._pcap_dir and self._pcap_lock:
            with self._pcap_lock:
                writer = self._iface_pcap.get(iface_name)
                if writer:
                    try:
                        writer.write(raw)
                    except Exception:
                        pass

        is_tap = self._iface_kind[iface_name] == "tap"
        pkt = parse(raw, is_tap=is_tap)
        self._iface_trace[iface_name].append(pkt)
        fd = self._iface_fds[iface_name]

        # ARP who-has → reply as if we owned the requested IP
        if (pkt.proto == "arp" and pkt.arp_op == 1
                and pkt.src and pkt.dst):
            # Use interface MAC for ARP replies if available
            if iface_name in self._iface_mac:
                src_mac_for_reply = self._iface_mac[iface_name]
            else:
                src_mac_for_reply = _WORKER_MAC
            reply = build_arp_reply(
                src_mac=src_mac_for_reply,
                src_ip=pkt.dst,
                dst_mac=_extract_src_mac(raw),
                dst_ip=pkt.src,
            )
            try:
                os.write(fd, reply)
            except OSError:
                pass
            # Write reply to pcap if enabled
            if self._pcap_dir and self._pcap_lock:
                with self._pcap_lock:
                    writer = self._iface_pcap.get(iface_name)
                    if writer:
                        try:
                            writer.write(reply)
                        except Exception:
                            pass
            return

        # IPv6 NDP Neighbor Solicitation → reply with NA
        if (pkt.proto == "ndp" and pkt.ndp_type == 135):
            try:
                import scapy.all as s
                from scapy.layers.inet6 import ICMPv6ND_NS
                layer = s.Ether(raw)
                if layer.haslayer(ICMPv6ND_NS):
                    target = str(layer[ICMPv6ND_NS].tgt)
                    # Skip NS for addresses owned by NS_FW (DAD conflict)
                    if target in self._fw_owned_v6:
                        return
                    # Generate correct link-local address from interface MAC
                    if iface_name in self._iface_mac:
                        src_ll = _mac_to_link_local(self._iface_mac[iface_name])
                        src_mac_for_na = self._iface_mac[iface_name]
                    else:
                        # Fallback for TUN or if MAC not available
                        src_ll = "fe80::200:5eff:fe00:1"
                        src_mac_for_na = _WORKER_MAC
                    # If NS has no source (DAD-style NS with src=::), send NA
                    # to all-nodes multicast ff02::1. Otherwise unicast to NS source.
                    if pkt.src and pkt.src != "::":
                        dst_ip = pkt.src
                    else:
                        dst_ip = "ff02::1"
                    na = build_ndp_na(
                        src_mac=src_mac_for_na,
                        src_ip=src_ll,
                        dst_mac=_extract_src_mac(raw),
                        dst_ip=dst_ip,
                        target_ip=target,
                    )
                    os.write(fd, na)
                    # Write NA to pcap if enabled
                    if self._pcap_dir and self._pcap_lock:
                        with self._pcap_lock:
                            writer = self._iface_pcap.get(iface_name)
                            if writer:
                                try:
                                    writer.write(na)
                                except Exception:
                                    pass
            except Exception:
                pass
            return

        # Observed IP packet → dispatch into the probe correlation
        # table directly, no pipe.
        summary = {
            "family": pkt.family, "proto": pkt.proto,
            "src": pkt.src, "dst": pkt.dst,
            "sport": pkt.sport, "dport": pkt.dport,
            "flags": pkt.flags, "length": pkt.length,
            "probe_id": pkt.probe_id,
        }
        self._on_observed(iface_name, summary)

    def _on_observed(self, obs_iface: str, summary: dict) -> None:
        """Match an observed packet against outstanding probes."""
        obs_id = summary.get("probe_id")
        if obs_id is not None:
            probe = self._probes.get(obs_id & 0xffff)
            if probe and probe.expect_iface == obs_iface:
                probe.verdict = "ACCEPT"
                probe.elapsed_ms = int(
                    (time.monotonic_ns() - probe.started_ns) / 1e6)
                fut = self._probe_futures.get(probe.probe_id)
                if fut and not fut.done():
                    fut.set_result(summary)
                return
        # Fallback: scan for any probe whose match() likes this
        # packet on the right iface (DNAT / NAT rewrite cases).
        for probe_id, probe in list(self._probes.items()):
            if probe.expect_iface != obs_iface:
                continue
            if probe.match(summary):
                probe.verdict = "ACCEPT"
                probe.elapsed_ms = int(
                    (time.monotonic_ns() - probe.started_ns) / 1e6)
                fut = self._probe_futures.get(probe_id)
                if fut and not fut.done():
                    fut.set_result(summary)
                break

    def _snapshot_traces(self) -> list[dict]:
        """Collect the per-iface trace ring buffers as a list."""
        out: list[dict] = []
        for iface, ring in self._iface_trace.items():
            for s in ring:
                out.append({
                    "iface": iface,
                    "family": s.family, "proto": s.proto,
                    "src": s.src, "dst": s.dst,
                    "sport": s.sport, "dport": s.dport,
                    "flags": s.flags, "arp_op": s.arp_op,
                    "ndp_type": s.ndp_type, "length": s.length,
                })
        return out

    # ── shutdown ──────────────────────────────────────────────────

    def _register_cleanup(self) -> None:
        if self._cleanup_registered:
            return
        atexit.register(self._shutdown)
        # Signal handlers — best effort, fine if they conflict with the
        # caller's own handlers.
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._sig_handler)
            except (ValueError, OSError):
                pass
        self._cleanup_registered = True

    def _sig_handler(self, signum: int, frame: Any) -> None:  # noqa: ARG002
        self._shutdown()
        os._exit(128 + signum)

    def shutdown(self) -> None:
        self._shutdown()

    def _shutdown(self) -> None:
        if self._shutdown_done:
            return
        self._shutdown_done = True
        # Close pcap writers before closing fds
        if self._pcap_dir and self._pcap_lock:
            with self._pcap_lock:
                for writer in self._iface_pcap.values():
                    try:
                        writer.close()
                    except Exception:
                        pass
                self._iface_pcap.clear()
        # 0. Signal reader + writer threads to stop and join them.
        for stop_ev in list(self._reader_stop_events):
            try:
                stop_ev.set()
            except Exception:
                pass
        for stop_ev in list(self._writer_stop_events):
            try:
                stop_ev.set()
            except Exception:
                pass
        for t in list(self._reader_threads):
            try:
                t.join(timeout=1.0)
            except Exception:
                pass
        for t in list(self._writer_threads):
            try:
                t.join(timeout=1.0)
            except Exception:
                pass
        self._reader_threads = []
        self._writer_threads = []
        self._reader_stop_events = []
        self._writer_stop_events = []
        self._write_queues = []
        self._iface_to_pair = {}
        # 1. Remove asyncio readers if the loop is still alive.
        if self._loop is not None:
            for fd in list(self._iface_fds.values()):
                try:
                    self._loop.remove_reader(fd)
                except Exception:
                    pass
        # 2. Close every TUN/TAP fd we own.
        for iface_name, fd in list(self._iface_fds.items()):
            try:
                os.close(fd)
            except OSError:
                pass
        self._iface_fds.clear()
        self._iface_kind.clear()
        self._iface_mac.clear()
        self._iface_trace.clear()
        self.workers.clear()
        # 3. Destroy the topology (unmounts the netns bind via
        #    nsstub, destroys the TUN/TAP interfaces).
        if self.topo is not None:
            try:
                self.topo.destroy()
            except Exception:
                pass
            self.topo = None
