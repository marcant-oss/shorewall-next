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


# Synthetic MAC for the worker-side of every TAP — used as
# hwsrc in ARP replies and ether src in outgoing frames. Same MAC
# on every worker is fine: each TAP is a separate L2 segment.
WORKER_MAC = "02:00:00:5e:00:01"


class InterfaceWorker:
    """asyncio driver for one TUN/TAP fd."""

    def __init__(
        self,
        *,
        iface_name: str,
        fd: int,
        kind: str,           # "tap" or "tun"
        fw_mac: str | None,  # MAC of the interface inside NS_FW (for TAP)
        pipe_conn: Any,      # multiprocessing.Pipe() parent-end
        trace_depth: int = 128,
    ):
        self.iface_name = iface_name
        self.fd = fd
        self.kind = kind
        self.is_tap = kind == "tap"
        self.fw_mac = fw_mac
        self.conn = pipe_conn
        self.trace: deque[PacketSummary] = deque(maxlen=trace_depth)
        self.running = False
        self._loop: asyncio.AbstractEventLoop | None = None

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

        os.set_blocking(self.fd, False)
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.add_reader(self.fd, self._on_tap_read)
            self._loop.add_reader(self.conn.fileno(), self._on_cmd_read)
            self.running = True
            self._loop.run_forever()
        finally:
            try:
                self._loop.remove_reader(self.fd)
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

    def _on_tap_read(self) -> None:
        """Drain packets from the TUN/TAP fd and process them."""
        try:
            while True:
                try:
                    buf = os.read(self.fd, 65536)
                except BlockingIOError:
                    return
                except OSError:
                    self._stop()
                    return
                if not buf:
                    return
                self._handle_packet(buf)
        except Exception as e:  # pragma: no cover
            try:
                self.conn.send(("error", self.iface_name, repr(e)))
            except Exception:
                pass

    def _on_cmd_read(self) -> None:
        """Pull the next command from the controller pipe and dispatch."""
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
            _, data = msg
            try:
                os.write(self.fd, data)
                self.conn.send(("injected", self.iface_name, len(data)))
            except OSError as e:
                self.conn.send(("error", self.iface_name, f"write: {e}"))
            return
        if cmd == "trace_dump":
            summaries = [
                {
                    "family": s.family, "proto": s.proto, "src": s.src,
                    "dst": s.dst, "sport": s.sport, "dport": s.dport,
                    "flags": s.flags, "arp_op": s.arp_op,
                    "ndp_type": s.ndp_type, "length": s.length,
                }
                for s in self.trace
            ]
            self.conn.send(("trace", self.iface_name, summaries))
            return
        # Unknown command — report and keep running
        self.conn.send(("error", self.iface_name, f"unknown cmd {cmd!r}"))

    # ── packet handling ────────────────────────────────────────────

    def _handle_packet(self, raw: bytes) -> None:
        pkt = parse(raw, is_tap=self.is_tap)
        pkt_ts = time.monotonic()
        self.trace.append(pkt)

        # ARP who-has → build and send reply (TAP only)
        if pkt.proto == "arp" and pkt.arp_op == 1 and pkt.src and pkt.dst:
            reply = build_arp_reply(
                src_mac=WORKER_MAC,
                src_ip=pkt.dst,      # we pretend to own the requested IP
                dst_mac=_extract_src_mac(raw),
                dst_ip=pkt.src,
            )
            try:
                os.write(self.fd, reply)
            except OSError:
                pass
            return

        # IPv6 NDP Neighbor Solicitation → reply with NA (TAP only)
        if pkt.proto == "ndp" and pkt.ndp_type == 135 and pkt.src and pkt.dst:
            # Reply from a made-up link-local to the NS source
            try:
                from scapy.layers.inet6 import ICMPv6ND_NS
                import scapy.all as s
                layer = s.Ether(raw)
                if layer.haslayer(ICMPv6ND_NS):
                    target = layer[ICMPv6ND_NS].tgt
                    src_ll = f"fe80::200:5eff:fe00:1"
                    na = build_ndp_na(
                        src_mac=WORKER_MAC,
                        src_ip=src_ll,
                        dst_mac=_extract_src_mac(raw),
                        dst_ip=pkt.src,
                        target_ip=str(target),
                    )
                    os.write(self.fd, na)
            except Exception:
                pass
            return

        # Any other packet: hand off to controller as "observed"
        try:
            self.conn.send((
                "observed", self.iface_name, pkt_ts,
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
    """Child-process entry point after ``multiprocessing.Process`` fork."""
    worker = InterfaceWorker(
        iface_name=iface_name,
        fd=fd,
        kind=kind,
        fw_mac=fw_mac,
        pipe_conn=pipe_conn,
    )
    worker.run()
