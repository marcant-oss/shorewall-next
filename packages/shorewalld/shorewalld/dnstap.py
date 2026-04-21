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

from ._ingress_metrics import _IngressMetricsBase
from .dns_wire import extract_qname
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

# Pre-computed tag bytes for the two fields we peek:
#   tag = (field_number << 3) | wire_type
#   Dnstap.message → field 14, wire type 2 (length-delimited) → 0x72
#   Message.type   → field 1,  wire type 0 (varint)           → 0x08
_TAG_DNSTAP_MESSAGE = 0x72   # (14 << 3) | 2
_TAG_MESSAGE_TYPE   = 0x08   # ( 1 << 3) | 0


def _peek_message_type(frame: bytes | memoryview) -> int | None:
    """Return the dnstap ``Message.Type`` enum int without a full protobuf parse.

    Walks the outer Dnstap varint stream until it finds the ``message``
    field (field 14, wire type 2 / length-delimited), then walks the
    inner ``Message`` bytes until it finds the ``type`` field (field 1,
    wire type 0 / varint), and returns its value.

    Returns ``None`` if the frame is malformed or does not contain a
    ``Message`` with a ``type`` field.

    Allocation profile: zero Python-level objects beyond the return
    int.  The helper operates directly on the ``memoryview`` of the
    caller's buffer; no ``bytes(...)`` slicing is performed.
    """
    mv = memoryview(frame) if not isinstance(frame, memoryview) else frame
    n = len(mv)
    i = 0
    # --- Outer Dnstap: scan for field 14, wire type 2 ---
    while i < n:
        # Read tag varint
        b = mv[i]
        i += 1
        if b & 0x80:
            # Multi-byte varint tag (rare for small field numbers, but handle it)
            tag = b & 0x7F
            shift = 7
            while True:
                if i >= n:
                    return None
                b = mv[i]
                i += 1
                tag |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
                if shift > 63:
                    return None
        else:
            tag = b
        wire_type = tag & 0x7
        if wire_type == 0:  # varint value — skip
            while i < n:
                b = mv[i]
                i += 1
                if not (b & 0x80):
                    break
            else:
                return None
        elif wire_type == 2:  # length-delimited
            # Read length varint
            length = 0
            shift = 0
            while True:
                if i >= n:
                    return None
                b = mv[i]
                i += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
                if shift > 63:
                    return None
            if tag == _TAG_DNSTAP_MESSAGE:
                # Found the Message field — now scan inner bytes for type
                end = i + length
                if end > n:
                    return None
                j = i
                while j < end:
                    b = mv[j]
                    j += 1
                    if b & 0x80:
                        inner_tag = b & 0x7F
                        shift = 7
                        while True:
                            if j >= end:
                                return None
                            b = mv[j]
                            j += 1
                            inner_tag |= (b & 0x7F) << shift
                            if not (b & 0x80):
                                break
                            shift += 7
                            if shift > 63:
                                return None
                    else:
                        inner_tag = b
                    inner_wire = inner_tag & 0x7
                    if inner_tag == _TAG_MESSAGE_TYPE:
                        # field 1, varint — decode it
                        val = 0
                        shift = 0
                        while True:
                            if j >= end:
                                return None
                            b = mv[j]
                            j += 1
                            val |= (b & 0x7F) << shift
                            if not (b & 0x80):
                                return val
                            shift += 7
                            if shift > 63:
                                return None
                    elif inner_wire == 0:  # varint — skip
                        while j < end:
                            b = mv[j]
                            j += 1
                            if not (b & 0x80):
                                break
                        else:
                            return None
                    elif inner_wire == 2:  # length-delimited — skip
                        inner_len = 0
                        shift = 0
                        while True:
                            if j >= end:
                                return None
                            b = mv[j]
                            j += 1
                            inner_len |= (b & 0x7F) << shift
                            if not (b & 0x80):
                                break
                            shift += 7
                            if shift > 63:
                                return None
                        j += inner_len
                    elif inner_wire == 1:  # 64-bit fixed
                        j += 8
                    elif inner_wire == 5:  # 32-bit fixed
                        j += 4
                    else:
                        return None  # unsupported wire type
                return None  # Message present but no type field
            # Not the field we want — skip over the payload
            i += length
        elif wire_type == 1:  # 64-bit fixed — skip
            i += 8
        elif wire_type == 5:  # 32-bit fixed — skip
            i += 4
        else:
            return None  # unsupported wire type
    return None  # No Message field found

# Message.Type values we care about. pdns_recursor emits
# RESOLVER_RESPONSE frames when ``logResponses=true`` — the
# responses from upstream authoritatives, which carry the A/AAAA
# RRs we want to populate into the nft set. CLIENT_RESPONSE is
# what other dnstap producers (e.g. dnsdist, unbound) emit to log
# the final answer they send back to their own clients. Accept
# both so the consumer is producer-agnostic.
AUTH_RESPONSE = 2       # dnstap.Message.Type.AUTH_RESPONSE
RESOLVER_RESPONSE = 4   # dnstap.Message.Type.RESOLVER_RESPONSE
CLIENT_RESPONSE = 6     # dnstap.Message.Type.CLIENT_RESPONSE
FORWARDER_RESPONSE = 8  # dnstap.Message.Type.FORWARDER_RESPONSE
STUB_RESPONSE = 10      # dnstap.Message.Type.STUB_RESPONSE
# Every even-numbered dnstap Message.Type is a *_RESPONSE; odd
# numbers are *_QUERY. We accept all responses — the parse layer
# further filters by rcode and answer presence.
RESPONSE_MESSAGE_TYPES = frozenset({
    AUTH_RESPONSE,
    RESOLVER_RESPONSE,
    CLIENT_RESPONSE,
    FORWARDER_RESPONSE,
    STUB_RESPONSE,
})


def decode_dnstap_frame(buf: bytes) -> tuple[int, bytes] | None:
    """Parse a dnstap protobuf frame into ``(msg_type, dns_wire_bytes)``.

    Uses the generated :mod:`shorewalld.proto.dnstap_pb2`
    module (protoc output of the vendored ``dnstap.proto``). Falls
    back to the hand-rolled varint decoder if the protobuf runtime
    is missing — keeps the daemon importable on minimal test hosts
    while the production wheel declares ``protobuf>=4.25`` as a
    hard dependency.

    Returns ``None`` if the frame isn't a Message we recognise
    (e.g. an identity-only frame, non-response message type, or a
    frame without ``response_message`` bytes). Raises ``ValueError``
    on malformed bytes.
    """
    try:
        from shorewalld.proto import dnstap_pb2
    except ImportError:
        # Protobuf runtime missing — fall back to the legacy
        # hand-rolled decoder path. This branch lets the module
        # import on hosts without the runtime but the production
        # daemon never takes it because ``protobuf`` is a hard
        # dependency declared in ``pyproject.toml``.
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

    frame = dnstap_pb2.Dnstap()
    try:
        frame.ParseFromString(buf)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"dnstap protobuf decode error: {e}") from e
    if not frame.HasField("message"):
        return None
    message = frame.message
    if not message.HasField("response_message"):
        return None
    return int(message.type), message.response_message


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


class DnstapMetrics(_IngressMetricsBase):
    """In-memory counters for the dnstap pipeline.

    Exposed to Prometheus by a dedicated collector (registered from
    the daemon when --listen-api is on). Kept separate from the rest
    of the exporter module so the dnstap machinery can operate
    headless in unit tests.

    Inherits lock-free ``inc`` / ``snapshot`` / ``set_last_frame_now``
    from :class:`_IngressMetricsBase`.  All counter names are
    pre-registered in ``_COUNTER_NAMES`` so that ``inc`` fails fast
    (``KeyError``) if a developer forgets to add a new name here.
    """

    _COUNTER_NAMES: tuple[str, ...] = (
        "frames_accepted",
        "frames_decode_error",
        "frames_dropped_queue_full",
        "frames_dropped_not_client_response",
        "frames_dropped_not_a_or_aaaa",
        "frames_dropped_not_allowlisted",
        "frames_skipped_by_type",
        "connections",
        "workers_busy",
    )


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
                name=f"shwd-dnsdec-{idx}", daemon=True)
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
        # Pass 0: cheap varint peek — skip full protobuf parse for the
        # ~99 % of frames whose message type is not a response type.
        # _peek_message_type() allocates no Python objects beyond the
        # return int; it operates on a memoryview of ``frame``.
        msg_type_peek = _peek_message_type(frame)
        if msg_type_peek is None or msg_type_peek not in RESPONSE_MESSAGE_TYPES:
            self._metrics.inc("frames_skipped_by_type")
            return

        try:
            decoded = decode_dnstap_frame(frame)
        except Exception:
            self._metrics.inc("frames_decode_error")
            return
        if decoded is None:
            return
        msg_type, wire = decoded
        if msg_type not in RESPONSE_MESSAGE_TYPES:
            # Defensive: peek said response but full parse disagrees —
            # count as skipped (should never happen with a well-formed frame).
            self._metrics.inc("frames_dropped_not_client_response")
            return

        # Two-pass filter (CLAUDE.md §Performance doctrine "Filter
        # before decode"): a cheap qname walk + allowlist check
        # before dnspython's from_wire(). Typical deployments have
        # >95 % drop rate against the allowlist, so skipping the
        # full parse on misses is the single biggest CPU win in
        # the hot path. When no allowlist is configured every frame
        # is accepted and the walk would be wasted work — bypass.
        if self._filter.allowlist is not None:
            extracted = extract_qname(wire)
            if extracted is None:
                self._metrics.inc("frames_decode_error")
                return
            qname, _ = extracted
            if not self._filter.allows(qname):
                self._metrics.inc("frames_dropped_not_allowlisted")
                return

        upd = parse_dns_response(wire)
        if upd is None:
            self._metrics.inc("frames_dropped_not_a_or_aaaa")
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
        socket_path: str | None,
        nft: NftInterface,
        netns_list: list[str],
        *,
        queue_size: int = 10_000,
        n_workers: int | None = None,
        qname_allowlist: set[str] | None = None,
        socket_mode: int = 0o660,
        socket_owner: str | int | None = None,
        socket_group: str | int | None = None,
        tcp_host: str | None = None,
        tcp_port: int | None = None,
        bridge: Any | None = None,
    ) -> None:
        # At least one of the two listen targets must be configured.
        # Both may be active simultaneously — pdns_recursor supports
        # tcp://host:port alongside unix:/path/to/sock so operators
        # can keep the local recursor on the unix socket and receive
        # replicated frames from a remote recursor over TCP.
        tcp_configured = bool(tcp_host) and tcp_port is not None
        if not socket_path and not tcp_configured:
            raise ValueError(
                "DnstapServer requires a unix socket_path, a "
                "(tcp_host, tcp_port) pair, or both")
        self.socket_path = socket_path
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.queue_size = queue_size
        self.n_workers = n_workers
        self.socket_mode = socket_mode
        self.socket_owner = socket_owner
        self.socket_group = socket_group

        self.metrics = DnstapMetrics()
        self._frame_q: queue.Queue[bytes] = queue.Queue(maxsize=queue_size)
        self._filter = QnameFilter(qname_allowlist)
        self._nft = nft
        self._netns_list = netns_list
        # When a ``bridge`` is supplied the legacy per-netns nft.add_set_element
        # path is bypassed entirely: DnsUpdate records are routed through the
        # Phase 2 tracker → setwriter → worker pipeline. The legacy SetWriter
        # stays in the object for tests that still drive it directly.
        self._bridge = bridge
        self._set_writer = SetWriter(nft, netns_list, self.metrics)

        self._server: asyncio.base_events.Server | None = None
        self._tcp_server: asyncio.base_events.Server | None = None
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

        # Unix listener (optional).
        if self.socket_path:
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
            from .sockperms import apply_socket_perms
            apply_socket_perms(
                self.socket_path,
                mode=self.socket_mode,
                owner=self.socket_owner,
                group=self.socket_group,
            )
            log.info(
                "dnstap unix endpoint live on %s "
                "(queue=%d, workers=%d)",
                self.socket_path, self.queue_size,
                self.n_workers or (os.cpu_count() or 1))

        # TCP listener (optional). pdns_recursor can emit dnstap
        # over TCP via ``dnstapFrameStreamServer({"tcp://host:port"})``
        # — useful when the recursor lives in a different mount NS,
        # container, or host from shorewalld and a unix socket isn't
        # reachable. Same FrameStream handshake, same decoder, same
        # downstream pipeline — only the listener is different.
        if self.tcp_host and self.tcp_port is not None:
            self._tcp_server = await asyncio.start_server(
                self._handle_client,
                host=self.tcp_host,
                port=self.tcp_port,
                # SO_REUSEADDR so a crashed shorewalld's TIME_WAIT
                # socket doesn't keep the port hostage.
                reuse_address=True,
            )
            log.info(
                "dnstap tcp endpoint live on %s:%d "
                "(queue=%d, workers=%d)",
                self.tcp_host, self.tcp_port, self.queue_size,
                self.n_workers or (os.cpu_count() or 1))

    async def serve_forever(self) -> None:
        """Block until every configured listener stops.

        Runs both listeners concurrently if both are active so the
        daemon sees a single 'serve' coroutine regardless of
        deployment shape.
        """
        tasks = []
        if self._server is not None:
            tasks.append(asyncio.create_task(
                self._server.serve_forever(),
                name="shorewalld.dnstap.unix"))
        if self._tcp_server is not None:
            tasks.append(asyncio.create_task(
                self._tcp_server.serve_forever(),
                name="shorewalld.dnstap.tcp"))
        if not tasks:
            return
        await asyncio.gather(*tasks, return_exceptions=True)

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
        if self._tcp_server is not None:
            try:
                self._tcp_server.close()
            except Exception:
                pass
            self._tcp_server = None
        if self.socket_path:
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
        """Runs on the event loop. Dispatches nft writes.

        If a ``TrackerBridge`` was supplied at construction time, the
        update flows through the Phase 2 pipeline (tracker.propose →
        SetWriter batch → WorkerRouter → persistent nft worker).
        Otherwise the legacy direct-nft SetWriter is used.
        """
        try:
            if self._bridge is not None:
                self._bridge.apply(
                    upd.qname, upd.a_rrs, upd.aaaa_rrs, upd.ttl)
            else:
                self._set_writer.apply(upd)
        except Exception:
            log.exception("dnstap on_update failed")
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
        counter("shorewalld_dnstap_frames_dropped_not_allowlisted_total",
                "dnstap frames whose qname was not in the allowlist "
                "(rejected by the two-pass filter before dnspython parse)",
                snap["frames_dropped_not_allowlisted"])
        counter("shorewalld_dnstap_frames_skipped_by_type_total",
                "dnstap frames skipped by the pre-filter varint peek "
                "before protobuf ParseFromString (message type not in "
                "RESPONSE_MESSAGE_TYPES or malformed outer message field)",
                snap["frames_skipped_by_type"])

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
