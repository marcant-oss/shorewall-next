"""Per-interface asyncio worker.

One worker process owns one TUN/TAP file descriptor. The worker
*stays in the host network namespace* — the interface lives in
NS_FW after being moved by the controller, but the fd itself is
a property of the process, so the worker can read/write it from
the host.

Each worker runs an asyncio event loop with two readers:

  * TUN/TAP fd → packets from NS_FW (the real kernel, post-
    forwarding). Classified, buffered in a ring for trace, and
    dispatched to the controller as ``("observed", summary)``
    when they look like probe responses.
  * Controller pipe → incoming commands (inject, quit, dump_trace).

ARP and NDP handling is done in-worker: any ARP who-has the TAP
receives is replied to with the worker's synthetic MAC — no matter
which IP was requested. This makes the TAP behave as "everything
is reachable on the wire", so the FW kernel stops ARP-probing and
happily forwards.

Workers are forked (mp.get_context("fork")) so they inherit all
open file descriptors from the controller. Only one fd is kept
open per worker: the rest are closed after fork.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from typing import Any

from .packets import (
    PacketSummary,
    build_arp_reply,
    build_ndp_na,
    parse,
)


def _proc_name_for(iface: str) -> str:
    """Build a /proc/comm name for a worker.

    Linux caps comm at 15 bytes (TASK_COMM_LEN = 16 incl NUL). We try
    progressively shorter prefixes so the iface name itself stays
    visible — `ps` shows e.g. ``simlab:bond1`` or ``s:bond0.123``.
    """
    for prefix in ("simlab:", "sim:", "s:", ""):
        candidate = f"{prefix}{iface}"
        if len(candidate.encode()) <= 15:
            return candidate
    return iface[:15]


# Synthetic MAC for the worker-side of every TAP — used as
# hwsrc in ARP replies and ether src in outgoing frames. Same MAC
# on every worker is fine: each TAP is a separate L2 segment.
WORKER_MAC = "02:00:00:5e:00:01"


class InterfaceWorker:
    """asyncio driver for one or more TUN/TAP fds.

    The constructor accepts either the legacy single-interface shape
    (``iface_name=…, fd=…, kind=…, fw_mac=…``) **or** the modern
    multi-interface shape (``ifaces={name: {fd, kind, mac}, …}``).
    The multi-interface form consolidates N TUN/TAPs onto one
    Python process — drop-in replacement for spinning up one worker
    per fd, but with **one** 80 MB Python heap instead of N.

    Per-interface state (trace ring, MAC, kind) lives in a dict
    keyed by iface_name. The asyncio loop registers one reader
    per fd; each reader is a closure that knows which iface it
    belongs to.
    """

    def __init__(
        self,
        *,
        iface_name: str | None = None,
        fd: int | None = None,
        kind: str | None = None,
        fw_mac: str | None = None,
        ifaces: dict[str, dict] | None = None,
        pipe_conn: Any = None,
        trace_depth: int = 128,
    ):
        # Normalise to the multi-interface dict shape.
        if ifaces is None:
            # Legacy single-interface invocation
            if iface_name is None or fd is None or kind is None:
                raise ValueError(
                    "InterfaceWorker needs either ifaces=… or "
                    "iface_name/fd/kind")
            ifaces = {iface_name: {"fd": fd, "kind": kind, "mac": fw_mac}}

        self.ifaces: dict[str, dict] = ifaces
        self.conn = pipe_conn
        self._trace_depth = trace_depth
        # Per-iface trace ring
        self.trace: dict[str, deque[PacketSummary]] = {
            name: deque(maxlen=trace_depth) for name in ifaces
        }
        self.running = False
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def iface_names(self) -> list[str]:
        return list(self.ifaces.keys())

    @property
    def primary_comm_name(self) -> str:
        """Comm rename: use the first iface's name when there's one,
        or ``sim:<N>ifs`` when the worker handles multiple."""
        names = self.iface_names
        if len(names) == 1:
            return _proc_name_for(names[0])
        return _proc_name_for(f"{len(names)}ifs")[:15]

    # ── entrypoint ─────────────────────────────────────────────────

    def run(self) -> None:
        """Main entry — starts the asyncio loop and returns on quit."""
        # Reset signal handlers inherited from the controller fork —
        # the controller's atexit/_shutdown would try to join *our*
        # sibling workers as if we were the parent, hitting
        # "can only test a child process" on every signal.
        import signal as _signal
        for sig in (_signal.SIGTERM, _signal.SIGINT, _signal.SIGHUP):
            try:
                _signal.signal(sig, _signal.SIG_DFL)
            except (ValueError, OSError):
                pass
        # Also clear atexit handlers inherited from the parent so
        # the controller's _shutdown doesn't fire in the child.
        import atexit as _atexit
        _atexit._clear()  # type: ignore[attr-defined]

        # Lower CPU + I/O priority of this worker so a long simlab run
        # cannot starve the rest of the box. nice +19 + ioprio idle.
        try:
            os.nice(19)
        except OSError:
            pass
        if hasattr(os, "ioprio_set"):
            try:
                os.ioprio_set(1, 0, (3 << 13))  # type: ignore[attr-defined]
            except (OSError, AttributeError):
                pass

        # Rename /proc/<pid>/comm so `ps` / `top` show which ifaces
        # this worker is bound to (``simlab:bond1`` for single,
        # ``sim:4ifs`` etc for multi).
        try:
            import ctypes as _ct
            _libc = _ct.CDLL("libc.so.6", use_errno=True)
            _PR_SET_NAME = 15
            _libc.prctl(_PR_SET_NAME, self.primary_comm_name.encode(),
                        0, 0, 0)
        except Exception:
            pass

        # Non-blocking mode on every TAP/TUN fd
        for meta in self.ifaces.values():
            try:
                os.set_blocking(meta["fd"], False)
            except OSError:
                pass

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            for name, meta in self.ifaces.items():
                # closure-capture the iface name per reader
                fd = meta["fd"]
                self._loop.add_reader(
                    fd, self._on_tap_read, name)
            self._loop.add_reader(self.conn.fileno(), self._on_cmd_read)
            self.running = True
            self._loop.run_forever()
        finally:
            try:
                for meta in self.ifaces.values():
                    try:
                        self._loop.remove_reader(meta["fd"])
                    except Exception:
                        pass
                self._loop.remove_reader(self.conn.fileno())
            except Exception:
                pass
            try:
                self._loop.close()
            except Exception:
                pass

    def _stop(self) -> None:
        self.running = False
        if self._loop and self._loop.is_running():
            self._loop.stop()

    # ── readers (non-blocking) ─────────────────────────────────────

    def _on_tap_read(self, iface_name: str) -> None:
        """Drain packets from one TUN/TAP fd and process them.

        Called by asyncio for each iface-specific fd; ``iface_name``
        is the closure capture from ``add_reader``.
        """
        fd = self.ifaces[iface_name]["fd"]
        try:
            while True:
                try:
                    buf = os.read(fd, 65536)
                except BlockingIOError:
                    return
                except OSError:
                    self._stop()
                    return
                if not buf:
                    return
                self._handle_packet(iface_name, buf)
        except Exception as e:  # pragma: no cover
            try:
                self.conn.send(("error", iface_name, repr(e)))
            except Exception:
                pass

    def _on_cmd_read(self) -> None:
        """Pull the next command from the controller pipe and dispatch.

        Command format (multi-iface aware):
          ("inject", iface_name, data)
          ("trace_dump",)  — dumps every iface's ring
          ("trace_dump", iface_name) — one iface only
          ("quit",)
        """
        try:
            if not self.conn.poll():
                return
            msg = self.conn.recv()
        except (EOFError, BrokenPipeError, ConnectionError):
            self._stop()
            return
        if not msg:
            return
        cmd = msg[0]
        if cmd == "quit":
            self._stop()
            return
        if cmd == "inject":
            # Legacy 2-tuple ("inject", data) routes to the single
            # iface if this worker owns exactly one; modern 3-tuple
            # carries the iface name explicitly.
            if len(msg) == 2:
                names = self.iface_names
                if len(names) != 1:
                    self.conn.send(("error", "?",
                                    "inject without iface on multi-worker"))
                    return
                iface_name, data = names[0], msg[1]
            else:
                _, iface_name, data = msg
            meta = self.ifaces.get(iface_name)
            if meta is None:
                self.conn.send(("error", iface_name,
                                "inject for unknown iface"))
                return
            try:
                os.write(meta["fd"], data)
                self.conn.send(("injected", iface_name, len(data)))
            except OSError as e:
                self.conn.send(("error", iface_name, f"write: {e}"))
            return
        if cmd == "trace_dump":
            # Optional second element selects a single iface
            want = msg[1] if len(msg) > 1 else None
            for iface_name, ring in self.trace.items():
                if want is not None and iface_name != want:
                    continue
                summaries = [
                    {
                        "family": s.family, "proto": s.proto,
                        "src": s.src, "dst": s.dst,
                        "sport": s.sport, "dport": s.dport,
                        "flags": s.flags, "arp_op": s.arp_op,
                        "ndp_type": s.ndp_type, "length": s.length,
                    }
                    for s in ring
                ]
                self.conn.send(("trace", iface_name, summaries))
            return
        # Unknown command — report and keep running
        self.conn.send(("error", "?", f"unknown cmd {cmd!r}"))

    # ── packet handling ────────────────────────────────────────────

    def _handle_packet(self, iface_name: str, raw: bytes) -> None:
        meta = self.ifaces[iface_name]
        fd = meta["fd"]
        is_tap = meta["kind"] == "tap"
        pkt = parse(raw, is_tap=is_tap)
        pkt_ts = time.monotonic()
        self.trace[iface_name].append(pkt)

        # ARP who-has → build and send reply (TAP only)
        if pkt.proto == "arp" and pkt.arp_op == 1 and pkt.src and pkt.dst:
            reply = build_arp_reply(
                src_mac=WORKER_MAC,
                src_ip=pkt.dst,      # we pretend to own the requested IP
                dst_mac=_extract_src_mac(raw),
                dst_ip=pkt.src,
            )
            try:
                os.write(fd, reply)
            except OSError:
                pass
            return

        # IPv6 NDP Neighbor Solicitation → reply with NA (TAP only)
        if pkt.proto == "ndp" and pkt.ndp_type == 135 and pkt.src and pkt.dst:
            try:
                from scapy.layers.inet6 import ICMPv6ND_NS
                import scapy.all as s
                layer = s.Ether(raw)
                if layer.haslayer(ICMPv6ND_NS):
                    target = layer[ICMPv6ND_NS].tgt
                    src_ll = "fe80::200:5eff:fe00:1"
                    na = build_ndp_na(
                        src_mac=WORKER_MAC,
                        src_ip=src_ll,
                        dst_mac=_extract_src_mac(raw),
                        dst_ip=pkt.src,
                        target_ip=str(target),
                    )
                    os.write(fd, na)
            except Exception:
                pass
            return

        # Any other packet: hand off to controller as "observed"
        try:
            self.conn.send((
                "observed", iface_name, pkt_ts,
                {
                    "family": pkt.family, "proto": pkt.proto,
                    "src": pkt.src, "dst": pkt.dst,
                    "sport": pkt.sport, "dport": pkt.dport,
                    "flags": pkt.flags, "length": pkt.length,
                    "probe_id": pkt.probe_id,
                },
            ))
        except (BrokenPipeError, ConnectionError):
            self._stop()


def _extract_src_mac(raw: bytes) -> str:
    """Cheap Ethernet src-MAC extraction — bytes 6..12 of the frame."""
    if len(raw) < 12:
        return "ff:ff:ff:ff:ff:ff"
    return ":".join(f"{b:02x}" for b in raw[6:12])


# ── fork entrypoint ──────────────────────────────────────────────────


def worker_main(
    iface_name: str,
    fd: int,
    kind: str,
    fw_mac: str | None,
    pipe_conn: Any,
) -> None:
    """Child-process entry point — legacy single-iface shape.

    Kept so existing single-worker-per-iface callers keep working
    unchanged. New multi-iface callers should use
    :func:`worker_main_multi`.
    """
    worker = InterfaceWorker(
        iface_name=iface_name,
        fd=fd,
        kind=kind,
        fw_mac=fw_mac,
        pipe_conn=pipe_conn,
    )
    worker.run()


def worker_main_multi(
    ifaces: dict[str, dict],
    pipe_conn: Any,
) -> None:
    """Child-process entry point — multi-iface shape.

    ``ifaces`` is a dict of ``{iface_name: {"fd": int, "kind":
    "tap"/"tun", "mac": str|None}}``. The worker registers one
    asyncio reader per fd + one for ``pipe_conn`` and services
    everything from a single event loop. Saves ~80 MB Python
    interpreter overhead per additional iface vs
    one-worker-per-iface.
    """
    worker = InterfaceWorker(
        ifaces=ifaces,
        pipe_conn=pipe_conn,
    )
    worker.run()
