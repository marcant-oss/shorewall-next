"""simlab orchestrator.

Owns the :class:`SimFwTopology`, forks one worker per interface,
drives probes through the pipe to the matching worker, correlates
observed packets back to their probe via a dispatch table, and
tears everything down (workers + namespace + fds) on exit.

Design points:

* **Workers stay in host NS.** Each worker inherits a single
  TUN/TAP fd via ``pass_fds``. Parent closes its own copy after
  fork so only the child holds it.
* **Asyncio event loop in the parent** — we register each worker
  pipe as an asyncio reader and dispatch results on arrival.
* **Cleanup is layered** — an ``atexit`` hook plus a signal
  handler cover "normal exit", "user ^C", "unhandled exception",
  and "controller killed". Every layer calls :meth:`_shutdown`,
  which is idempotent.
"""

from __future__ import annotations

import asyncio
import atexit
import multiprocessing as mp
import os
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .dumps import FwState, load_fw_state
from .packets import PacketSummary, parse
from .topology import NS_FW_DEFAULT, SimFwTopology
from .worker import _proc_name_for, worker_main, worker_main_multi


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
        workers_max: int | None = None,
    ):
        self.paths = (ip4add, ip4routes, ip6add, ip6routes)
        self.ns_name = ns_name
        self.state: FwState | None = None
        self.topo: SimFwTopology | None = None
        # iface_name → (Process, Pipe) mapping. In the consolidated
        # worker model multiple iface names share the same (Process,
        # Pipe) pair — all distinct entries just happen to point at
        # the same worker. The _probe dispatch code reads by iface
        # name and doesn't care that the process is shared.
        self.workers: dict[str, tuple[mp.Process, Any]] = {}
        # Unique list of (Process, Pipe) so shutdown iterates each
        # worker exactly once.
        self._worker_procs: list[tuple[mp.Process, Any]] = []
        self._probes: dict[int, ProbeSpec] = {}
        self._probe_futures: dict[int, asyncio.Future] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown_done = False
        self._cleanup_registered = False
        # None = auto-detect based on CPU count (fallback to 4)
        self._workers_max = workers_max

    # ── lifecycle ─────────────────────────────────────────────────

    def reload_dumps(self) -> FwState:
        """Re-read the FW state dumps from disk and return the fresh state."""
        self.state = load_fw_state(*self.paths)
        return self.state

    def build(self) -> None:
        """Build the NS_FW topology and spawn consolidated workers.

        Instead of one fork per interface (which burns ~80 MB of
        Python heap per worker = ~2 GB for 24 interfaces), we
        partition the TUN/TAP fds across a small pool of workers.
        Each worker handles N fds via asyncio, sharing one Python
        interpreter. The number of workers defaults to
        ``max(2, cpu_count)`` so every core can process packets
        in parallel but no core is starved by a heap-heavy process.
        Override with ``SimController(workers_max=N)``.
        """
        self._register_cleanup()
        self.reload_dumps()
        assert self.state is not None
        self.topo = SimFwTopology(self.state, ns_name=self.ns_name)
        self.topo.build()

        # Decide how many workers to spawn
        if self._workers_max is not None:
            n_workers = max(1, self._workers_max)
        else:
            try:
                n_workers = max(2, os.cpu_count() or 4)
            except Exception:
                n_workers = 4
        iface_list = list(self.topo.tun_fds.items())
        n_workers = min(n_workers, max(1, len(iface_list)))

        # Partition iface_list into n_workers chunks round-robin.
        # Round-robin over a sorted list gives stable assignment
        # so the same iface lands on the same worker across runs.
        chunks: list[list[tuple[str, int]]] = [[] for _ in range(n_workers)]
        for i, entry in enumerate(sorted(iface_list)):
            chunks[i % n_workers].append(entry)

        ctx = mp.get_context("fork")
        for wi, chunk in enumerate(chunks):
            if not chunk:
                continue
            ifaces_arg = {
                name: {
                    "fd": fd,
                    "kind": self.topo.tun_kind[name],
                    "mac": self.topo.tun_mac.get(name),
                }
                for name, fd in chunk
            }
            parent_conn, child_conn = ctx.Pipe(duplex=True)
            # Name the process after the first iface (or ``w<i>:Nifs``
            # when there are many). The worker will rename its own
            # /proc/comm to a 15-char variant once it starts.
            if len(chunk) == 1:
                proc_name = _proc_name_for(chunk[0][0])
            else:
                proc_name = _proc_name_for(f"w{wi}:{len(chunk)}ifs")
            proc = ctx.Process(
                target=worker_main_multi,
                args=(ifaces_arg, child_conn),
                name=proc_name,
                daemon=False,
            )
            proc.start()
            child_conn.close()
            self._worker_procs.append((proc, parent_conn))
            for name, _fd in chunk:
                self.workers[name] = (proc, parent_conn)
        # Parent no longer needs the TUN/TAP fds — the workers own them.
        for name, fd in list(self.topo.tun_fds.items()):
            try:
                os.close(fd)
            except OSError:
                pass
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

    async def run_probes(self, probes: list[ProbeSpec]) -> list[ProbeSpec]:
        """Inject every probe and wait for its matching response."""
        self._loop = asyncio.get_running_loop()
        # Register a reader for every distinct worker process pipe
        # (not one per iface — multiple ifaces share the same pipe
        # now).
        registered_fds: set[int] = set()
        for _proc, conn in self._worker_procs:
            fd = conn.fileno()
            if fd in registered_fds:
                continue
            registered_fds.add(fd)
            self._loop.add_reader(fd, self._on_worker_msg, None, conn)

        # Kick off each probe — fire-and-observe, async per probe.
        futures: list[asyncio.Future] = []
        for probe in probes:
            self._probes[probe.probe_id] = probe
            fut = self._loop.create_future()
            self._probe_futures[probe.probe_id] = fut
            probe.started_ns = time.monotonic_ns()
            self._inject(probe)
            futures.append(self._wait_probe(probe, fut))

        # Wait for all probes to complete (with their individual
        # timeouts handled by _wait_probe).
        await asyncio.gather(*futures, return_exceptions=True)

        for fd in registered_fds:
            try:
                self._loop.remove_reader(fd)
            except Exception:
                pass
        return probes

    async def _wait_probe(self, probe: ProbeSpec, fut: asyncio.Future) -> None:
        try:
            await asyncio.wait_for(fut, timeout=probe.timeout_s)
        except asyncio.TimeoutError:
            probe.verdict = "DROP"
            probe.elapsed_ms = int((time.monotonic_ns() - probe.started_ns) / 1e6)
            # Ask workers for their trace buffers to explain the failure.
            probe.trace = await self._collect_traces()
        finally:
            self._probes.pop(probe.probe_id, None)
            self._probe_futures.pop(probe.probe_id, None)

    def _inject(self, probe: ProbeSpec) -> None:
        worker = self.workers.get(probe.inject_iface)
        if worker is None:
            probe.verdict = "ERROR"
            fut = self._probe_futures.get(probe.probe_id)
            if fut and not fut.done():
                fut.set_result(None)
            return
        _, conn = worker
        try:
            # Modern 3-tuple routes the inject to the right fd inside
            # a multi-iface worker. Single-iface workers still accept
            # this shape.
            conn.send(("inject", probe.inject_iface, probe.payload))
        except (BrokenPipeError, ConnectionError):
            probe.verdict = "ERROR"
            fut = self._probe_futures.get(probe.probe_id)
            if fut and not fut.done():
                fut.set_result(None)

    def _on_worker_msg(self, iface: str, conn: Any) -> None:
        try:
            if not conn.poll():
                return
            msg = conn.recv()
        except (EOFError, BrokenPipeError, ConnectionError):
            return
        if not msg:
            return
        tag = msg[0]
        if tag == "observed":
            _, obs_iface, _ts, summary = msg
            # Primary correlation: probe_id stashed in IP.id / IPv6.fl.
            # Falls back to the per-probe match() callback if the id
            # didn't survive (e.g. DNAT rewrote the packet).
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
        elif tag == "trace":
            _, _iface, _summaries = msg
            # Trace responses are returned via _collect_traces()
            # which installs its own temporary consumer.
        elif tag == "error":
            _, _iface, _detail = msg
            # Could log to controller trace
        elif tag == "injected":
            pass  # ack

    async def _collect_traces(self) -> list[dict]:
        """Ask every worker for its ring-buffer snapshot.

        Iterates ``_worker_procs`` (unique per process) rather than
        ``workers`` (per iface) so a multi-iface worker only gets
        one trace_dump request and dumps all its ifaces in one go.
        """
        out: list[dict] = []
        for _proc, conn in self._worker_procs:
            try:
                conn.send(("trace_dump",))
            except Exception:
                continue
        await asyncio.sleep(0.05)  # let workers reply
        for _proc, conn in self._worker_procs:
            try:
                while conn.poll():
                    msg = conn.recv()
                    if msg and msg[0] == "trace":
                        _, iface, summaries = msg
                        for s in summaries:
                            out.append({"iface": iface, **s})
            except Exception:
                continue
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
        # Iterate _worker_procs so each process is shut down exactly
        # once, no matter how many ifaces it owned.
        # 1. Tell workers to quit
        for _proc, conn in self._worker_procs:
            try:
                conn.send(("quit",))
            except Exception:
                pass
        # 2. Wait briefly, then SIGTERM stragglers
        deadline = time.monotonic() + 2.0
        for proc, _conn in self._worker_procs:
            left = max(0.0, deadline - time.monotonic())
            try:
                proc.join(timeout=left)
            except Exception:
                pass
        for proc, _conn in self._worker_procs:
            if proc.is_alive():
                try:
                    proc.terminate()
                    proc.join(timeout=1.0)
                except Exception:
                    pass
            if proc.is_alive():
                try:
                    proc.kill()
                except Exception:
                    pass
        for _proc, conn in self._worker_procs:
            try:
                conn.close()
            except Exception:
                pass
        self._worker_procs.clear()
        self.workers.clear()
        # 3. Destroy the topology (closes any remaining TUN fds,
        #    deletes the NS_FW netns).
        if self.topo is not None:
            try:
                self.topo.destroy()
            except Exception:
                pass
            self.topo = None
