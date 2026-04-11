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
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .dumps import FwState, load_fw_state
from .packets import (
    PacketSummary,
    build_arp_reply,
    build_ndp_na,
    fast_is_arp_or_ndp_ns,
    fast_probe_id,
    parse,
)
from .topology import NS_FW_DEFAULT, SimFwTopology


# Synthetic MAC for every TAP the controller services. Same MAC on
# every TAP is fine: each TAP is its own L2 segment.
_WORKER_MAC = "02:00:00:5e:00:01"


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
    ):
        self.paths = (ip4add, ip4routes, ip6add, ip6routes)
        self.ns_name = ns_name
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
        self.topo.build()

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

    def load_nft(self, nft_script_path: str) -> None:
        """Load an nft script into NS_FW via `ip netns exec`."""
        import subprocess
        r = subprocess.run(
            ["ip", "netns", "exec", self.ns_name, "nft", "-f", nft_script_path],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"nft -f failed (rc={r.returncode}):\n{r.stderr[:2000]}")

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
                args=(pid, group, r_stop),
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
        probe = self._probes.get(probe_id & 0xffff)
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

        Tight ``queue.get → os.write`` loop. Consumes ``(fd, bytes)``
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
            fd, payload = cmd
            try:
                os.write(fd, payload)
            except OSError:
                pass
        # Drain any remaining queued writes so the last few probes /
        # ARP replies still hit the wire before we tear down.
        try:
            while True:
                fd, payload = wq.get_nowait()
                try:
                    os.write(fd, payload)
                except OSError:
                    pass
        except _queue.Empty:
            pass
        except Exception:
            pass

    def _reader_thread_main(self, tid: int, ifaces: list[str], stop_ev) -> None:
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

                    # Slow path: ARP / NDP. Full scapy parse so we
                    # can build the reply frame and also push into
                    # the diagnostic trace ring.
                    pkt = parse(buf, is_tap=is_tap)
                    self._iface_trace[iface_name].append(pkt)

                    if (pkt.proto == "arp" and pkt.arp_op == 1
                            and pkt.src and pkt.dst):
                        reply = build_arp_reply(
                            src_mac=_WORKER_MAC,
                            src_ip=pkt.dst,
                            dst_mac=_extract_src_mac(buf),
                            dst_ip=pkt.src,
                        )
                        write_q.put((fd, reply))
                        continue

                    if (pkt.proto == "ndp" and pkt.ndp_type == 135
                            and pkt.src and pkt.dst):
                        try:
                            from scapy.layers.inet6 import ICMPv6ND_NS
                            import scapy.all as s
                            layer = s.Ether(buf)
                            if layer.haslayer(ICMPv6ND_NS):
                                target = layer[ICMPv6ND_NS].tgt
                                src_ll = "fe80::200:5eff:fe00:1"
                                na = build_ndp_na(
                                    src_mac=_WORKER_MAC,
                                    src_ip=src_ll,
                                    dst_mac=_extract_src_mac(buf),
                                    dst_ip=pkt.src,
                                    target_ip=str(target),
                                )
                                write_q.put((fd, na))
                        except Exception:
                            pass
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
            self._write_queues[pair_idx].put((fd, probe.payload))
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
        is_tap = self._iface_kind[iface_name] == "tap"
        pkt = parse(raw, is_tap=is_tap)
        self._iface_trace[iface_name].append(pkt)
        fd = self._iface_fds[iface_name]

        # ARP who-has → reply as if we owned the requested IP
        if (pkt.proto == "arp" and pkt.arp_op == 1
                and pkt.src and pkt.dst):
            reply = build_arp_reply(
                src_mac=_WORKER_MAC,
                src_ip=pkt.dst,
                dst_mac=_extract_src_mac(raw),
                dst_ip=pkt.src,
            )
            try:
                os.write(fd, reply)
            except OSError:
                pass
            return

        # IPv6 NDP Neighbor Solicitation → reply with NA
        if (pkt.proto == "ndp" and pkt.ndp_type == 135
                and pkt.src and pkt.dst):
            try:
                from scapy.layers.inet6 import ICMPv6ND_NS
                import scapy.all as s
                layer = s.Ether(raw)
                if layer.haslayer(ICMPv6ND_NS):
                    target = layer[ICMPv6ND_NS].tgt
                    src_ll = "fe80::200:5eff:fe00:1"
                    na = build_ndp_na(
                        src_mac=_WORKER_MAC,
                        src_ip=src_ll,
                        dst_mac=_extract_src_mac(raw),
                        dst_ip=pkt.src,
                        target_ip=str(target),
                    )
                    os.write(fd, na)
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
