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
from .worker import _proc_name_for, worker_main


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
    ):
        self.paths = (ip4add, ip4routes, ip6add, ip6routes)
        self.ns_name = ns_name
        self.state: FwState | None = None
        self.topo: SimFwTopology | None = None
        self.workers: dict[str, tuple[mp.Process, Any]] = {}
        self._probes: dict[int, ProbeSpec] = {}
        self._probe_futures: dict[int, asyncio.Future] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown_done = False
        self._cleanup_registered = False

    # ── lifecycle ─────────────────────────────────────────────────

    def reload_dumps(self) -> FwState:
        """Re-read the FW state dumps from disk and return the fresh state."""
        self.state = load_fw_state(*self.paths)
        return self.state

    def build(self) -> None:
        """Build the NS_FW topology and spawn one worker per interface."""
        self._register_cleanup()
        self.reload_dumps()
        assert self.state is not None
        self.topo = SimFwTopology(self.state, ns_name=self.ns_name)
        self.topo.build()

        # Fork one worker per TUN/TAP. We use the fork context so
        # children inherit the fds we just opened.
        ctx = mp.get_context("fork")
        for name, fd in self.topo.tun_fds.items():
            parent_conn, child_conn = ctx.Pipe(duplex=True)
            proc = ctx.Process(
                target=worker_main,
                args=(name, fd, self.topo.tun_kind[name],
                      self.topo.tun_mac.get(name), child_conn),
                name=_proc_name_for(name),
                daemon=False,
            )
            # Only pass the relevant fd + the child pipe end to the
            # child; Python's fork implicitly inherits everything
            # else, but close_fds=True isn't available on Process.
            proc.start()
            # Parent closes its child-end copy.
            child_conn.close()
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
        # Register a reader for every worker pipe.
        for name, (_, conn) in self.workers.items():
            self._loop.add_reader(
                conn.fileno(), self._on_worker_msg, name, conn)

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

        for name, (_, conn) in list(self.workers.items()):
            try:
                self._loop.remove_reader(conn.fileno())
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
            conn.send(("inject", probe.payload))
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
        """Ask every worker for its ring-buffer snapshot."""
        out: list[dict] = []
        for name, (_, conn) in self.workers.items():
            try:
                conn.send(("trace_dump",))
            except Exception:
                continue
        await asyncio.sleep(0.05)  # let workers reply
        for name, (_, conn) in self.workers.items():
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
        # 1. Tell workers to quit
        for name, (proc, conn) in list(self.workers.items()):
            try:
                conn.send(("quit",))
            except Exception:
                pass
        # 2. Wait briefly, then SIGTERM stragglers
        deadline = time.monotonic() + 2.0
        for name, (proc, conn) in list(self.workers.items()):
            left = max(0.0, deadline - time.monotonic())
            try:
                proc.join(timeout=left)
            except Exception:
                pass
        for name, (proc, _) in list(self.workers.items()):
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
        for _, conn in self.workers.values():
            try:
                conn.close()
            except Exception:
                pass
        self.workers.clear()
        # 3. Destroy the topology (closes any remaining TUN fds,
        #    deletes the NS_FW netns).
        if self.topo is not None:
            try:
                self.topo.destroy()
            except Exception:
                pass
            self.topo = None
