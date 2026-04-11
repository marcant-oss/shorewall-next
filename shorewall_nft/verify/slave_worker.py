"""Per-slave worker process for the multi-zone simulate topology.

Each zone slave namespace gets one long-running worker child forked
from the parent via :mod:`multiprocessing` (fork context — no exec).
The worker ``setns()``'s into its slave on startup, binds the dual-
stack TCP/UDP echo listeners in threads, and then loops reading probe
commands over a pipe. Probes are implemented with Python's ``socket``
module — no ``nc``, ``ping``, or subprocess shell-outs.

This eliminates all per-probe fork/exec overhead. A full --all-zones
run with ~400 test cases spawns exactly N workers (one per zone) up
front and reuses them for every probe.

Protocol (parent → child):

    ("probe", proto, src_ip, dst_ip, port, family, timeout_s)

Protocol (child → parent):

    ("ok", verdict, elapsed_ms)
    ("err", exception_str, elapsed_ms)

Where ``verdict`` is one of ``"ACCEPT"`` or ``"DROP"``, mirroring the
existing ``run_tcp_test`` / ``run_udp_test`` helpers.

``("quit",)`` tells the worker to exit its loop and return. The parent
calls ``Process.join()`` afterwards.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import multiprocessing as mp
import os
import socket
import threading
import time
from typing import Any

# CLONE_NEWNET — net-namespace bit for setns()
_CLONE_NEWNET = 0x40000000
_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _setns_net(ns_name: str) -> None:
    """Enter the given named netns in the current thread."""
    fd = os.open(f"/run/netns/{ns_name}", os.O_RDONLY)
    try:
        if _libc.setns(fd, _CLONE_NEWNET) != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"setns({ns_name}) failed: {os.strerror(err)}")
    finally:
        os.close(fd)


# ── listener threads ──────────────────────────────────────────────────


def _listener_tcp(family: int, port: int) -> None:
    """Accept loop for a single TCP listener socket.

    Binds wildcard. REDIRECT in the slave's nft prerouting rewrites
    inbound tcp dst to :port, so every incoming probe lands here.
    """
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    try:
        s.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
    except OSError:
        return
    s.listen(128)
    while True:
        try:
            c, _ = s.accept()
            c.close()
        except OSError:
            return


def _listener_udp(family: int, port: int) -> None:
    """Echo loop for a single UDP listener socket."""
    s = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    try:
        s.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
    except OSError:
        return
    while True:
        try:
            _, peer = s.recvfrom(4096)
            s.sendto(b"PONG", peer)
        except OSError:
            return


def _start_listeners(tcp_port: int = 65000, udp_port: int = 65001) -> None:
    """Spawn four daemon threads — dual-stack TCP + UDP."""
    for target, fam, port in [
        (_listener_tcp, socket.AF_INET,  tcp_port),
        (_listener_tcp, socket.AF_INET6, tcp_port),
        (_listener_udp, socket.AF_INET,  udp_port),
        (_listener_udp, socket.AF_INET6, udp_port),
    ]:
        threading.Thread(target=target, args=(fam, port), daemon=True).start()


# ── probes (socket API, no exec) ──────────────────────────────────────


def _probe_tcp(src_ip: str, dst_ip: str, port: int,
               family: int, timeout_s: float) -> str:
    """TCP connect probe. Returns 'ACCEPT' or 'DROP'."""
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    s = socket.socket(af, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        s.bind((src_ip, 0))
    except OSError:
        s.close()
        return "DROP"
    try:
        s.connect((dst_ip, port))
        return "ACCEPT"
    except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError):
        return "DROP"
    finally:
        try:
            s.close()
        except OSError:
            pass


def _probe_udp(src_ip: str, dst_ip: str, port: int,
               family: int, timeout_s: float) -> str:
    """UDP echo probe. Returns 'ACCEPT' if PONG received, else 'DROP'."""
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    s = socket.socket(af, socket.SOCK_DGRAM)
    s.settimeout(timeout_s)
    try:
        s.bind((src_ip, 0))
    except OSError:
        s.close()
        return "DROP"
    try:
        s.sendto(b"PING", (dst_ip, port))
        data, _ = s.recvfrom(4096)
        return "ACCEPT" if b"PONG" in data else "DROP"
    except (socket.timeout, TimeoutError, OSError):
        return "DROP"
    finally:
        try:
            s.close()
        except OSError:
            pass


def _probe_icmp(src_ip: str, dst_ip: str,
                family: int, timeout_s: float) -> str:
    """ICMP echo probe using a raw socket.

    Requires CAP_NET_RAW in the worker. Sends one echo request and
    waits for the reply. Returns 'ACCEPT' on reply, 'DROP' on timeout.
    """
    import struct
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    proto = socket.getprotobyname("ipv6-icmp" if family == 6 else "icmp")
    try:
        s = socket.socket(af, socket.SOCK_RAW, proto)
    except PermissionError:
        return "DROP"
    s.settimeout(timeout_s)
    try:
        s.bind((src_ip, 0))
    except OSError:
        s.close()
        return "DROP"
    # Build a minimal ICMP/ICMPv6 echo request
    echo_type = 128 if family == 6 else 8  # v6: ECHO_REQUEST=128, v4: 8
    pkt_id = os.getpid() & 0xffff
    header = struct.pack("!BBHHH", echo_type, 0, 0, pkt_id, 1)
    payload = b"simulate"
    # Checksum (kernel fills in v6; v4 needs manual checksum)
    if family == 4:
        def _checksum(data: bytes) -> int:
            s = 0
            for i in range(0, len(data) - 1, 2):
                s += (data[i] << 8) + data[i + 1]
            if len(data) % 2:
                s += data[-1] << 8
            while s >> 16:
                s = (s & 0xffff) + (s >> 16)
            return ~s & 0xffff
        chksum = _checksum(header + payload)
        header = struct.pack("!BBHHH", echo_type, 0, chksum, pkt_id, 1)
    packet = header + payload
    try:
        s.sendto(packet, (dst_ip, 0))
        data, _ = s.recvfrom(4096)
        return "ACCEPT" if data else "DROP"
    except (socket.timeout, TimeoutError, OSError):
        return "DROP"
    finally:
        try:
            s.close()
        except OSError:
            pass


# ── main worker entrypoint ────────────────────────────────────────────


def worker_main(ns_name: str, conn: Any) -> None:
    """Long-running worker loop for a single slave namespace.

    Forked from the parent. First thing it does is enter its netns via
    setns(), then start listener threads, then drain probe commands
    from ``conn`` until a ``("quit",)`` message arrives.
    """
    try:
        _setns_net(ns_name)
    except OSError as e:
        conn.send(("err", f"setns failed: {e}", 0))
        conn.close()
        return

    _start_listeners()

    while True:
        try:
            msg = conn.recv()
        except (EOFError, ConnectionError):
            return
        if not msg:
            return
        cmd = msg[0]
        if cmd == "quit":
            return
        if cmd != "probe":
            conn.send(("err", f"unknown cmd {cmd!r}", 0))
            continue
        _, proto, src_ip, dst_ip, port, family, timeout_s = msg
        t0 = time.monotonic_ns()
        try:
            if proto == "tcp":
                verdict = _probe_tcp(src_ip, dst_ip, port, family, timeout_s)
            elif proto == "udp":
                verdict = _probe_udp(src_ip, dst_ip, port, family, timeout_s)
            elif proto == "icmp":
                verdict = _probe_icmp(src_ip, dst_ip, family, timeout_s)
            else:
                verdict = "SKIP"
        except Exception as e:  # noqa: BLE001
            conn.send(("err", repr(e), (time.monotonic_ns() - t0) // 1_000_000))
            continue
        ms = (time.monotonic_ns() - t0) // 1_000_000
        conn.send(("ok", verdict, ms))


# ── parent-side helper ────────────────────────────────────────────────


def spawn_worker(ns_name: str) -> tuple[mp.Process, Any]:
    """Fork a worker process for a slave namespace.

    Returns (process_handle, parent-side pipe connection). The caller
    is responsible for sending ``("quit",)`` and joining the process.
    """
    ctx = mp.get_context("fork")
    parent_conn, child_conn = ctx.Pipe(duplex=True)
    proc = ctx.Process(
        target=worker_main,
        args=(ns_name, child_conn),
        name=f"sw-worker-{ns_name}",
        daemon=False,
    )
    proc.start()
    child_conn.close()  # parent doesn't use the child end
    return proc, parent_conn
