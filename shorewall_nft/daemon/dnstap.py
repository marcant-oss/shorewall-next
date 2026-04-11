"""Real dnstap consumer for shorewalld.

Architecture (matches the Phase 4 section of the plan):

* ``asyncio.start_unix_server`` at the configured socket path — one
  reader task per recursor connection.
* Each reader:
    1. runs the FrameStream bidirectional handshake
    2. reads data frames until STOP
    3. hands each frame's raw bytes to a bounded ``queue.Queue``
* A worker pool of real ``threading.Thread`` workers (``os.cpu_count()``
  by default) drains the queue. Each worker:
    4. decodes the dnstap Dnstap protobuf (hand-rolled 3-field subset)
    5. parses the embedded DNS wire response via ``dnspython``
    6. produces ``DnsUpdate(qname, rrs, ttl)`` and pushes it back to
       the main event loop via ``loop.call_soon_threadsafe`` → ``SetWriter``.
* ``SetWriter`` runs as a single coroutine on the main loop and owns
  all nft set add/delete calls (libnftables is not reliably
  thread-safe).

Queue overflow policy: **drop the incoming frame and increment a
counter**. Dropping at the shorewalld-side queue stage is preferable
to letting the kernel socket buffer fill, because from pdns's
perspective the reader is always fast enough. Counters are wired
into the ``shorewalld_dnstap_*`` Prometheus family so operators can
see they are dropping frames.

All of this is opt-in: the consumer only binds when ``--listen-api``
is set. The module is importable without the optional dependencies;
``start()`` raises a clear error if they're missing.
"""

from __future__ import annotations

import asyncio
import logging
import os
import queue
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from shorewall_nft.nft.netlink import NftError, NftInterface

from .exporter import CollectorBase, _MetricFamily
from .framestream import (
    CONTROL_STOP,
    FrameStreamError,
    accept_handshake,
    decode_control,
    finish_handshake,
    read_frame,
)

log = logging.getLogger("shorewalld.dnstap")


# ── DnsUpdate record — the "answer → nft set" instruction ────────────


@dataclass
class DnsUpdate:
    """One (qname → [ips]) update with TTL.

    Produced by a decode worker, consumed by the SetWriter coroutine.
    """
    qname: str
    a_rrs: list[str] = field(default_factory=list)
    aaaa_rrs: list[str] = field(default_factory=list)
    ttl: int = 0
    rcode: int = 0


# ── Minimal protobuf decoder ────────────────────────────────────────


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    """Decode a protobuf varint starting at ``buf[i]``; return (value, new_i)."""
    value = 0
    shift = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _decode_fields(buf: bytes) -> dict[int, Any]:
    """Decode a protobuf message into ``{field_number: value}``.

    Supports wire types 0 (varint) and 2 (length-delimited). Unknown
    wire types raise ValueError — fine for our use because dnstap uses
    only 0 and 2 on the fields we care about.
    """
    out: dict[int, Any] = {}
    i = 0
    n = len(buf)
    while i < n:
        key, i = _read_varint(buf, i)
        wire_type = key & 0x7
        field_num = key >> 3
        if wire_type == 0:  # varint
            val, i = _read_varint(buf, i)
            out[field_num] = val
        elif wire_type == 2:  # length-delimited
            length, i = _read_varint(buf, i)
            if i + length > n:
                raise ValueError("length-delimited field exceeds buffer")
            out[field_num] = buf[i:i + length]
            i += length
        elif wire_type == 1:  # 64-bit fixed
            if i + 8 > n:
                raise ValueError("truncated 64-bit field")
            out[field_num] = struct.unpack("<Q", buf[i:i + 8])[0]
            i += 8
        elif wire_type == 5:  # 32-bit fixed
            if i + 4 > n:
                raise ValueError("truncated 32-bit field")
            out[field_num] = struct.unpack("<I", buf[i:i + 4])[0]
            i += 4
        else:
            raise ValueError(f"unsupported wire type {wire_type}")
    return out


# dnstap.proto field numbers (see
# https://dnstap.info/Dnstap-proto.html):
#
#   message Dnstap {
#     ... identity, version, extra ...
#     message Message {
#       Type type = 1;        // enum
#       ...
#       bytes response_message = 14;    // raw DNS wire format
#       fixed64 response_time_sec = 13; // (or: .nsec at 12)
#       ...
#     }
#     Message message = 14;
#     ...
#   }
#
# Only the fields above are parsed. Everything else is ignored.

DNSTAP_MESSAGE_FIELD = 14  # inside Dnstap
MESSAGE_TYPE_FIELD = 1     # inside Dnstap.Message
MESSAGE_RESPONSE_FIELD = 14  # bytes response_message (raw DNS wire)

# Message.Type values we care about.
CLIENT_RESPONSE = 6  # dnstap.Message.Type.CLIENT_RESPONSE


def decode_dnstap_frame(buf: bytes) -> tuple[int, bytes] | None:
    """Parse a dnstap protobuf frame into ``(msg_type, dns_wire_bytes)``.

    Returns None if the frame isn't a Message we recognise (e.g.
    an identity-only frame). Raises ValueError on malformed bytes.
    """
    top = _decode_fields(buf)
    msg = top.get(DNSTAP_MESSAGE_FIELD)
    if not isinstance(msg, bytes):
        return None
    inner = _decode_fields(msg)
    msg_type = inner.get(MESSAGE_TYPE_FIELD, 0)
    wire = inner.get(MESSAGE_RESPONSE_FIELD)
    if not isinstance(wire, bytes):
        return None
    return int(msg_type), wire


# ── DNS wire parse (via dnspython) ──────────────────────────────────


def parse_dns_response(wire: bytes) -> DnsUpdate | None:
    """Parse a raw DNS response wire buffer and extract A/AAAA answers.

    Returns ``None`` on any parse failure or when the response has
    no A/AAAA RRs (e.g. NXDOMAIN, MX-only). Uses dnspython; the
    daemon's optional ``daemon`` extra declares it.
    """
    try:
        import dns.message  # type: ignore[import-untyped]
        import dns.rdatatype  # type: ignore[import-untyped]
    except ImportError:
        return None

    try:
        msg = dns.message.from_wire(wire)
    except Exception:
        return None
    if not msg.question:
        return None
    qname = str(msg.question[0].name).rstrip(".")
    rcode = msg.rcode()
    a_rrs: list[str] = []
    aaaa_rrs: list[str] = []
    min_ttl = 0
    for rrset in msg.answer:
        if rrset.rdtype == dns.rdatatype.A:
            a_rrs.extend(r.address for r in rrset)
            if min_ttl == 0 or rrset.ttl < min_ttl:
                min_ttl = int(rrset.ttl)
        elif rrset.rdtype == dns.rdatatype.AAAA:
            aaaa_rrs.extend(r.address for r in rrset)
            if min_ttl == 0 or rrset.ttl < min_ttl:
                min_ttl = int(rrset.ttl)
    if not a_rrs and not aaaa_rrs:
        return None
    return DnsUpdate(
        qname=qname, a_rrs=a_rrs, aaaa_rrs=aaaa_rrs,
        ttl=min_ttl, rcode=int(rcode))


# ── Metrics + queue bookkeeping ─────────────────────────────────────


class DnstapMetrics:
    """In-memory counters for the dnstap pipeline.

    Exposed to Prometheus by a dedicated collector (registered from
    the daemon when --listen-api is on). Kept separate from the rest
    of the exporter module so the dnstap machinery can operate
    headless in unit tests.
    """

    def __init__(self) -> None:
        self.frames_accepted = 0
        self.frames_decode_error = 0
        self.frames_dropped_queue_full = 0
        self.frames_dropped_not_client_response = 0
        self.frames_dropped_not_a_or_aaaa = 0
        self.connections = 0
        self.workers_busy = 0
        self._lock = threading.Lock()

    def inc(self, field: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "frames_accepted": self.frames_accepted,
                "frames_decode_error": self.frames_decode_error,
                "frames_dropped_queue_full": self.frames_dropped_queue_full,
                "frames_dropped_not_client_response":
                    self.frames_dropped_not_client_response,
                "frames_dropped_not_a_or_aaaa":
                    self.frames_dropped_not_a_or_aaaa,
                "connections": self.connections,
                "workers_busy": self.workers_busy,
            }


# ── Filter (shorewalld-side qname allowlist) ────────────────────────


class QnameFilter:
    """Optional qname allowlist applied after DNS-wire parse.

    Default: accept everything. Set ``allowlist`` to a set of lowercase
    dot-free-trailing qnames (e.g. ``{"github.com", "example.com"}``)
    to only pass matching responses.
    """

    def __init__(self, allowlist: set[str] | None = None) -> None:
        self.allowlist = allowlist

    def allows(self, qname: str) -> bool:
        if self.allowlist is None:
            return True
        return qname.lower().rstrip(".") in self.allowlist


# ── SetWriter (coroutine, owns all nft writes) ──────────────────────


def qname_to_set_name(qname: str, rrtype: str) -> str:
    """Map ``github.com + A`` → ``dns_github_com_v4`` (filesystem-safe).

    Sanitises underscores for any non-alnum char. Caps at 31 chars so
    the set name fits nft's 32-byte identifier limit.
    """
    clean = "".join(c if c.isalnum() else "_" for c in qname.rstrip("."))
    suffix = "_v4" if rrtype == "A" else "_v6"
    name = f"dns_{clean}{suffix}".lower()
    return name[:31] if len(name) > 31 else name


class SetWriter:
    """Applies ``DnsUpdate`` records to nft sets across configured netns."""

    def __init__(self, nft: NftInterface, netns_list: list[str],
                 metrics: DnstapMetrics) -> None:
        self._nft = nft
        self._netns_list = netns_list
        self._metrics = metrics

    def apply(self, upd: DnsUpdate) -> None:
        timeout = f"{max(upd.ttl, 1)}s"
        for ns in self._netns_list:
            ns_arg = ns or None
            for ip in upd.a_rrs:
                name = qname_to_set_name(upd.qname, "A")
                try:
                    self._nft.add_set_element(
                        name, ip, timeout=timeout, netns=ns_arg)
                except NftError:
                    log.debug("add A %s %s failed (set missing?)",
                              name, ip)
            for ip in upd.aaaa_rrs:
                name = qname_to_set_name(upd.qname, "AAAA")
                try:
                    self._nft.add_set_element(
                        name, ip, timeout=timeout, netns=ns_arg)
                except NftError:
                    log.debug("add AAAA %s %s failed (set missing?)",
                              name, ip)


# ── Worker pool ─────────────────────────────────────────────────────


class DecodeWorkerPool:
    """os.cpu_count() real threads reading raw frames from ``frame_q``,
    decoding them, pushing ``DnsUpdate`` records onto the event loop
    via ``loop.call_soon_threadsafe``.

    Overflow on the frame queue: ``queue.Full`` → dropped + counter.
    Decode errors: logged + counter. Unknown message types: silently
    counted + dropped.
    """

    def __init__(
        self,
        frame_q: queue.Queue[bytes],
        metrics: DnstapMetrics,
        on_update,  # Callable[[DnsUpdate], None], runs on the event loop
        loop: asyncio.AbstractEventLoop,
        qname_filter: QnameFilter,
        n_workers: int | None = None,
    ) -> None:
        self._q = frame_q
        self._metrics = metrics
        self._on_update = on_update
        self._loop = loop
        self._filter = qname_filter
        self._n_workers = n_workers or (os.cpu_count() or 1)
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    def start(self) -> None:
        for idx in range(self._n_workers):
            t = threading.Thread(
                target=self._loop_worker,
                name=f"dnstap-decode-{idx}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        # Unblock workers that are parked on Queue.get.
        for _ in self._threads:
            try:
                self._q.put_nowait(b"")
            except queue.Full:
                pass
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads = []

    def _loop_worker(self) -> None:
        while not self._stop.is_set():
            try:
                frame = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            if self._stop.is_set() or not frame:
                return
            self._metrics.inc("workers_busy")
            try:
                self._decode_one(frame)
            except Exception:
                log.exception("dnstap decode worker crashed on frame")
                self._metrics.inc("frames_decode_error")
            finally:
                self._metrics.inc("workers_busy", n=-1)

    def _decode_one(self, frame: bytes) -> None:
        try:
            decoded = decode_dnstap_frame(frame)
        except Exception:
            self._metrics.inc("frames_decode_error")
            return
        if decoded is None:
            return
        msg_type, wire = decoded
        if msg_type != CLIENT_RESPONSE:
            self._metrics.inc("frames_dropped_not_client_response")
            return
        upd = parse_dns_response(wire)
        if upd is None:
            self._metrics.inc("frames_dropped_not_a_or_aaaa")
            return
        if not self._filter.allows(upd.qname):
            return
        self._metrics.inc("frames_accepted")
        self._loop.call_soon_threadsafe(self._on_update, upd)


# ── DnstapServer (asyncio, socket-facing) ───────────────────────────


class DnstapServer:
    """Unix-socket dnstap ingestor.

    Holds one ``asyncio.Server`` + one ``DecodeWorkerPool`` +
    bookkeeping. Constructed by the ``Daemon`` and driven from the
    event loop; the worker pool runs on real threads so it isn't
    throttled by the event loop scheduling.
    """

    def __init__(
        self,
        socket_path: str,
        nft: NftInterface,
        netns_list: list[str],
        *,
        queue_size: int = 10_000,
        n_workers: int | None = None,
        qname_allowlist: set[str] | None = None,
        socket_mode: int = 0o660,
    ) -> None:
        self.socket_path = socket_path
        self.queue_size = queue_size
        self.n_workers = n_workers
        self.socket_mode = socket_mode

        self.metrics = DnstapMetrics()
        self._frame_q: queue.Queue[bytes] = queue.Queue(maxsize=queue_size)
        self._filter = QnameFilter(qname_allowlist)
        self._nft = nft
        self._netns_list = netns_list
        self._set_writer = SetWriter(nft, netns_list, self.metrics)

        self._server: asyncio.base_events.Server | None = None
        self._pool: DecodeWorkerPool | None = None
        self._recent_qnames: deque[tuple[float, str]] = deque(maxlen=1024)
        self._close_lock = threading.Lock()
        self._closed = False

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._pool = DecodeWorkerPool(
            self._frame_q, self.metrics,
            on_update=self._on_update,
            loop=loop, qname_filter=self._filter,
            n_workers=self.n_workers,
        )
        self._pool.start()

        # Unlink stale socket left over from a crashed previous run.
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except OSError:
            pass
        parent = os.path.dirname(self.socket_path)
        if parent:
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError:
                pass

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=self.socket_path)
        try:
            os.chmod(self.socket_path, self.socket_mode)
        except OSError:
            log.warning("could not chmod %s to %o",
                        self.socket_path, self.socket_mode)
        log.info("shorewalld dnstap endpoint live on %s (queue=%d, workers=%d)",
                 self.socket_path, self.queue_size,
                 self.n_workers or (os.cpu_count() or 1))

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        if self._pool is not None:
            try:
                self._pool.stop()
            except Exception:
                pass
            self._pool = None
        if self._server is not None:
            try:
                self._server.close()
            except Exception:
                pass
            self._server = None
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except OSError:
            pass

    # ── internal handlers ────────────────────────────────────────

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        self.metrics.inc("connections")
        log.info("dnstap client connected (peer=%s)", peer)
        try:
            await accept_handshake(reader, writer)
            while True:
                try:
                    is_control, body = await read_frame(reader)
                except asyncio.IncompleteReadError:
                    break
                if is_control:
                    ctrl = decode_control(body)
                    if ctrl.ctype == CONTROL_STOP:
                        await finish_handshake(writer)
                        break
                    # Unknown control frame — ignore per fstrm spec.
                    continue
                try:
                    self._frame_q.put_nowait(body)
                except queue.Full:
                    self.metrics.inc("frames_dropped_queue_full")
        except FrameStreamError:
            log.exception("framestream protocol error")
        finally:
            self.metrics.inc("connections", n=-1)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            log.info("dnstap client disconnected (peer=%s)", peer)

    def _on_update(self, upd: DnsUpdate) -> None:
        """Runs on the event loop. Delegates nft writes to SetWriter."""
        try:
            self._set_writer.apply(upd)
        except Exception:
            log.exception("set_writer.apply failed")
        self._recent_qnames.append((time.monotonic(), upd.qname))

    @property
    def queue_depth(self) -> int:
        return self._frame_q.qsize()

    @property
    def queue_capacity(self) -> int:
        return self.queue_size


class DnstapMetricsCollector(CollectorBase):
    """Prometheus collector that surfaces the dnstap pipeline counters.

    Registered from ``Daemon._start_dnstap_server`` when the dnstap
    consumer is enabled. One collector per server; the ``netns``
    label is empty because dnstap ingest is a daemon-level pipeline,
    not a per-netns one.
    """

    def __init__(self, server: DnstapServer) -> None:
        super().__init__(netns="")
        self._server = server

    def collect(self) -> list[_MetricFamily]:
        snap = self._server.metrics.snapshot()

        fams: list[_MetricFamily] = []

        def counter(name: str, help_text: str, value: int) -> None:
            fam = _MetricFamily(name, help_text, [], mtype="counter")
            fam.add([], float(value))
            fams.append(fam)

        def gauge(name: str, help_text: str, value: float) -> None:
            fam = _MetricFamily(name, help_text, [])
            fam.add([], float(value))
            fams.append(fam)

        counter("shorewalld_dnstap_frames_accepted_total",
                "dnstap frames that produced a DnsUpdate",
                snap["frames_accepted"])
        counter("shorewalld_dnstap_frames_decode_error_total",
                "dnstap frames that failed protobuf or DNS parse",
                snap["frames_decode_error"])
        counter("shorewalld_dnstap_frames_dropped_queue_full_total",
                "dnstap frames dropped because the decode queue was full",
                snap["frames_dropped_queue_full"])
        counter("shorewalld_dnstap_frames_dropped_not_client_response_total",
                "dnstap frames that were not CLIENT_RESPONSE",
                snap["frames_dropped_not_client_response"])
        counter("shorewalld_dnstap_frames_dropped_not_a_or_aaaa_total",
                "dnstap frames with no A/AAAA answers",
                snap["frames_dropped_not_a_or_aaaa"])

        gauge("shorewalld_dnstap_connections",
              "Currently connected dnstap producers (pdns_recursor)",
              snap["connections"])
        gauge("shorewalld_dnstap_workers_busy",
              "Decode workers currently holding a frame",
              snap["workers_busy"])
        gauge("shorewalld_dnstap_queue_depth",
              "Current dnstap decode queue depth",
              self._server.queue_depth)
        gauge("shorewalld_dnstap_queue_capacity",
              "Maximum dnstap decode queue size",
              self._server.queue_capacity)
        return fams
