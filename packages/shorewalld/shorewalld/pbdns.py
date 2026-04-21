"""PowerDNS recursor protobuf logger ingestion.

This is the second of the two DNS answer sources shorewalld
supports. Same downstream pipeline as :mod:`dnstap` — decoded
:class:`DnsUpdate` records flow through :class:`TrackerBridge`
into the Phase 2 SetWriter — but a different wire format on
the ingest side:

* **No FrameStream handshake.** pdns' protobufServer is just
  length-prefixed protobuf messages on a unix stream socket:
  ``[4B big-endian length][protobuf bytes]``. Drop-on-overflow
  happens at the recursor via its own bounded queue, not via a
  client-side ACCEPT.
* **Pre-decomposed answer records.** PBDNSMessage carries a list
  of ``DNSRR`` entries with typed ``name``, ``type``, ``ttl``,
  ``rdata`` fields. Unlike dnstap (which wraps raw DNS wire)
  there is *no DNS wire parse step* — we just walk the repeated
  field and push the rdata bytes straight into the tracker.
  That's the major efficiency win: zero dnspython, zero wire
  parse per frame, measurable CPU savings at 10k+ fps.

Metrics mirror the dnstap layout exactly (``shorewalld_pbdns_*``)
so a Grafana dashboard can compare the two sources side by side.

Socket lifecycle matches :class:`DnstapServer`: listen on a unix
socket at a configured path, accept each recursor connection in
its own asyncio reader task, hand frames off to the shared
decode worker pool, bail cleanly on SIGTERM.
"""

from __future__ import annotations

import asyncio
import struct
import time
from pathlib import Path

from ._ingress_metrics import _IngressMetricsBase
from .dnstap_bridge import TrackerBridge
from .logsetup import get_logger
from .proto import dnsmessage_pb2

log = get_logger("pbdns")


# ── Constants mirrored from the protobuf enum ────────────────────────
PBDNS_TYPE_QUERY = 1
PBDNS_TYPE_RESPONSE = 2             # — we care about this
# DNSIncomingResponseType is the recursor's "response received from
# upstream" frame type (value 4). Accept both so a single shorewalld
# instance can ingest from a recursor configured to log both CLIENT and
# INCOMING response events.
PBDNS_TYPE_INCOMING_RESPONSE = 4

RESPONSE_TYPES = frozenset({PBDNS_TYPE_RESPONSE, PBDNS_TYPE_INCOMING_RESPONSE})

# DNS RR types we extract
RRTYPE_A = 1
RRTYPE_AAAA = 28

# ── PBDNSMessage wire-tag constants ───────────────────────────────────
# Pre-computed tag bytes for the fields peeked by _peek_type_and_qname.
# tag = (field_number << 3) | wire_type.
#
# PBDNSMessage:
#   type      → field 1,  wire type 0 (varint)           → 0x08
#   question  → field 12, wire type 2 (length-delimited) → 0x62
#
# DNSQuestion:
#   qName     → field 1,  wire type 2 (length-delimited) → 0x0A
_TAG_PBDNS_TYPE     = 0x08   # (1  << 3) | 0
_TAG_PBDNS_QUESTION = 0x62   # (12 << 3) | 2
_TAG_DNSQ_QNAME    = 0x0A   # (1  << 3) | 2

# Soft cap on a single protobuf message body. pdns recursor's
# typical response frame is < 2 KiB; anything over 64 KiB is
# pathological and most likely a desync. Reject rather than
# allocate multi-MB buffers for bogus length prefixes.
MAX_FRAME_BYTES = 65536


# ── Metrics ──────────────────────────────────────────────────────────


class PbdnsMetrics(_IngressMetricsBase):
    """Prometheus counter bundle, exposed via the exporter.

    Symmetric with :class:`shorewalld.dnstap.DnstapMetrics`
    so operators can A/B compare the two ingestion paths in a single
    Grafana panel.

    Inherits lock-free ``inc`` / ``snapshot`` / ``set_last_frame_now``
    from :class:`_IngressMetricsBase`.  All counter names are
    pre-registered in ``_COUNTER_NAMES`` so that ``inc`` fails fast
    (``KeyError``) if a developer forgets to add a new name here.
    """

    # Two-pass pre-filter counters (mirroring dnstap's skipped_by_type):
    # frames_skipped_by_type_total  — type peek said non-response before
    #     the full ParseFromString.
    # frames_skipped_by_qname_total — type peek passed, but qname peek
    #     showed the qname is not in the tracker allowlist.
    _COUNTER_NAMES: tuple[str, ...] = (
        "frames_accepted_total",
        "frames_decode_error_total",
        "frames_dropped_queue_full_total",
        "frames_by_type_query_total",
        "frames_by_type_response_total",
        "frames_by_type_other_total",
        "frames_by_rcode_noerror_total",
        "frames_by_rcode_nxdomain_total",
        "frames_by_rcode_servfail_total",
        "frames_by_rcode_refused_total",
        "frames_by_rcode_other_total",
        "frames_family_v4_total",
        "frames_family_v6_total",
        "frames_empty_rrs_total",
        "bytes_received_total",
        "connections",
        "connections_total",
        "frames_skipped_by_type_total",
        "frames_skipped_by_qname_total",
    )

    def snapshot(self) -> dict[str, float]:  # type: ignore[override]
        """Return a counter snapshot plus the derived ``last_frame_age_seconds``.

        Extends the base ``snapshot()`` with a computed gauge so the
        Prometheus collector does not need to read ``last_frame_mono``
        directly.
        """
        snap: dict[str, float] = dict(self._counters)
        snap["last_frame_age_seconds"] = (
            (time.monotonic() - self.last_frame_mono)
            if self.last_frame_mono else 0.0
        )
        return snap


# ── Two-pass pre-filter ───────────────────────────────────────────────


def _peek_type_and_qname(
    frame: bytes | memoryview,
) -> tuple[int | None, bytes | None]:
    """Return ``(type_int, qname_bytes)`` from a PBDNSMessage without a
    full protobuf parse.

    Walks the outer PBDNSMessage varint stream and extracts:

    * ``type``     — field 1, wire type 0 (varint). The
      ``PBDNSMessage.Type`` enum value (1 = QUERY, 2 = RESPONSE, …).
    * ``question`` — field 12, wire type 2 (length-delimited). Descends
      into the ``DNSQuestion`` sub-message and extracts ``qName`` (field
      1, wire type 2 / string). Returned as lowercase ``bytes``.

    The walk stops as soon as both fields have been found. Unknown
    fields at both the outer and inner level are skipped using only
    the wire type — no copies, no string construction.

    Returns ``(None, None)`` on any malformed / truncated frame.

    Allocation budget: one ``memoryview`` wrap (if the caller passes
    ``bytes``), then one ``bytes`` object for the returned qname.
    No intermediate allocations.
    """
    mv = memoryview(frame) if not isinstance(frame, memoryview) else frame
    n = len(mv)
    i = 0
    found_type: int | None = None
    found_qname: bytes | None = None

    while i < n:
        # ── Read tag varint ──────────────────────────────────────────
        b = mv[i]
        i += 1
        if b & 0x80:
            tag = b & 0x7F
            shift = 7
            while True:
                if i >= n:
                    return None, None
                b = mv[i]
                i += 1
                tag |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
                if shift > 63:
                    return None, None
        else:
            tag = b

        wire_type = tag & 0x7

        if wire_type == 0:  # varint value
            if tag == _TAG_PBDNS_TYPE:
                # Decode varint in place
                val = 0
                shift = 0
                while True:
                    if i >= n:
                        return None, None
                    b = mv[i]
                    i += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                    if shift > 63:
                        return None, None
                found_type = val
            else:
                # Skip varint
                while i < n:
                    b = mv[i]
                    i += 1
                    if not (b & 0x80):
                        break
                else:
                    return None, None

        elif wire_type == 2:  # length-delimited
            # Read length varint
            length = 0
            shift = 0
            while True:
                if i >= n:
                    return None, None
                b = mv[i]
                i += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
                if shift > 63:
                    return None, None

            if tag == _TAG_PBDNS_QUESTION:
                # Descend into DNSQuestion sub-message
                end = i + length
                if end > n:
                    return None, None
                j = i
                while j < end:
                    # Read inner tag
                    b = mv[j]
                    j += 1
                    if b & 0x80:
                        inner_tag = b & 0x7F
                        shift = 7
                        while True:
                            if j >= end:
                                return None, None
                            b = mv[j]
                            j += 1
                            inner_tag |= (b & 0x7F) << shift
                            if not (b & 0x80):
                                break
                            shift += 7
                            if shift > 63:
                                return None, None
                    else:
                        inner_tag = b

                    inner_wire = inner_tag & 0x7

                    if inner_tag == _TAG_DNSQ_QNAME:
                        # Read qName length then bytes
                        qlen = 0
                        shift = 0
                        while True:
                            if j >= end:
                                return None, None
                            b = mv[j]
                            j += 1
                            qlen |= (b & 0x7F) << shift
                            if not (b & 0x80):
                                break
                            shift += 7
                            if shift > 63:
                                return None, None
                        if j + qlen > end:
                            return None, None
                        # One allocation: the qname bytes (lowercase)
                        found_qname = bytes(mv[j:j + qlen]).lower()
                        break
                    elif inner_wire == 0:  # varint — skip
                        while j < end:
                            b = mv[j]
                            j += 1
                            if not (b & 0x80):
                                break
                        else:
                            return None, None
                    elif inner_wire == 2:  # length-delimited — skip
                        ilen = 0
                        shift = 0
                        while True:
                            if j >= end:
                                return None, None
                            b = mv[j]
                            j += 1
                            ilen |= (b & 0x7F) << shift
                            if not (b & 0x80):
                                break
                            shift += 7
                            if shift > 63:
                                return None, None
                        j += ilen
                    elif inner_wire == 1:  # 64-bit fixed — skip
                        j += 8
                    elif inner_wire == 5:  # 32-bit fixed — skip
                        j += 4
                    else:
                        return None, None
                i = end
            else:
                # Skip over the payload
                i += length

        elif wire_type == 1:  # 64-bit fixed — skip
            if i + 8 > n:
                return None, None
            i += 8
        elif wire_type == 5:  # 32-bit fixed — skip
            if i + 4 > n:
                return None, None
            i += 4
        else:
            return None, None  # unsupported wire type

        # Early-exit once both fields have been found
        if found_type is not None and found_qname is not None:
            return found_type, found_qname

    return found_type, found_qname


# ── Decoder ──────────────────────────────────────────────────────────


def decode_pbdns_frame(
    buf: bytes,
    bridge: TrackerBridge,
    metrics: PbdnsMetrics,
) -> None:
    """Decode one PBDNSMessage and hand RRs to the bridge.

    Two-pass pre-filter (CLAUDE.md §Performance doctrine "Filter
    before decode"):

    Pass 0 — cheap varint peek: read ``type`` + ``question.qName``
    from the wire without calling ``ParseFromString``.  Non-response
    types are discarded immediately (both the new
    ``frames_skipped_by_type_total`` counter *and* the legacy
    ``frames_by_type_query/other_total`` counters are incremented so
    existing dashboards keep working). Unknown / non-allowlisted
    qnames are counted in ``frames_skipped_by_qname_total`` and
    dropped before the full parse.

    Pass 1 — full parse: only reached for RESPONSE frames whose
    qname is registered in the tracker. Walks the repeated RR list
    extracting A/AAAA rdata bytes directly — no DNS wire parse.

    Errors increment ``frames_decode_error_total`` and return
    without raising so the server loop keeps draining frames.
    """
    # ── Pass 0: cheap varint peek ────────────────────────────────────
    peeked_type, peeked_qname = _peek_type_and_qname(buf)

    if peeked_type is None:
        # Malformed / truncated frame — fall through to full parse so
        # the decode-error counter fires on the actual parse error.
        pass
    elif peeked_type not in RESPONSE_TYPES:
        # Skip the full parse for non-response frames — the ~majority
        # of pdns traffic is queries.
        metrics.inc("frames_skipped_by_type_total")
        # Also maintain legacy per-type counters so existing dashboards
        # and tests that check frames_by_type_query_total keep working.
        if peeked_type == PBDNS_TYPE_QUERY:
            metrics.inc("frames_by_type_query_total")
        else:
            metrics.inc("frames_by_type_other_total")
        return
    else:
        # Type is a response — check qname allowlist before full parse.
        if peeked_qname is not None and not bridge.has_qname_bytes(
                peeked_qname):
            metrics.inc("frames_skipped_by_qname_total")
            return

    # ── Pass 1: full protobuf parse ──────────────────────────────────
    try:
        msg = dnsmessage_pb2.PBDNSMessage()
        msg.ParseFromString(buf)
    except Exception as e:  # noqa: BLE001
        metrics.inc("frames_decode_error_total")
        log.debug("pbdns decode error: %s", e)
        return

    metrics.inc("frames_accepted_total")
    metrics.inc("bytes_received_total", len(buf))
    metrics.set_last_frame_now()

    if msg.type in RESPONSE_TYPES:
        metrics.inc("frames_by_type_response_total")
    elif msg.type == PBDNS_TYPE_QUERY:
        metrics.inc("frames_by_type_query_total")
        return
    else:
        metrics.inc("frames_by_type_other_total")
        return

    if not msg.HasField("question"):
        return
    qname = msg.question.qName
    if not qname:
        return

    # RCODE breakdown
    rcode = msg.response.rcode if msg.HasField("response") else 0
    _bump_rcode(metrics, rcode)

    if rcode != 0:
        # NXDOMAIN / SERVFAIL / REFUSED etc. — no addresses to
        # learn, but we still count the frame for visibility.
        return

    # Walk the RRs — pre-decomposed, no DNS wire parse needed.
    a_rrs: list[bytes] = []
    aaaa_rrs: list[bytes] = []
    min_ttl = 0
    # protobuf returns rdata as an immutable ``bytes`` already — no
    # need to wrap in ``bytes()`` again. Avoids ~2 allocations per
    # accepted frame on the 20 k fps hot path.
    for rr in msg.response.rrs:
        rtype = rr.type
        if rtype == RRTYPE_A and len(rr.rdata) == 4:
            a_rrs.append(rr.rdata)
            if min_ttl == 0 or rr.ttl < min_ttl:
                min_ttl = rr.ttl
        elif rtype == RRTYPE_AAAA and len(rr.rdata) == 16:
            aaaa_rrs.append(rr.rdata)
            if min_ttl == 0 or rr.ttl < min_ttl:
                min_ttl = rr.ttl

    if not a_rrs and not aaaa_rrs:
        metrics.inc("frames_empty_rrs_total")
        return
    if a_rrs:
        metrics.inc("frames_family_v4_total", len(a_rrs))
    if aaaa_rrs:
        metrics.inc("frames_family_v6_total", len(aaaa_rrs))
    bridge.apply(
        qname=qname,
        a_rrs=a_rrs,
        aaaa_rrs=aaaa_rrs,
        ttl=int(min_ttl) if min_ttl else 60,
    )


def _bump_rcode(metrics: PbdnsMetrics, rcode: int) -> None:
    if rcode == 0:
        metrics.inc("frames_by_rcode_noerror_total")
    elif rcode == 3:
        metrics.inc("frames_by_rcode_nxdomain_total")
    elif rcode == 2:
        metrics.inc("frames_by_rcode_servfail_total")
    elif rcode == 5:
        metrics.inc("frames_by_rcode_refused_total")
    else:
        metrics.inc("frames_by_rcode_other_total")


# ── Server ───────────────────────────────────────────────────────────


class PbdnsServer:
    """asyncio server reading length-prefixed PBDNSMessage frames from
    pdns recursor and feeding them through the :class:`TrackerBridge`
    into Phase 2's SetWriter.

    Supports both unix-socket and TCP ingestion on the same server
    instance. pdns-recursor's ``protobufServer()`` Lua directive
    speaks TCP only (unlike ``dnstapFrameStreamServer()`` which
    accepts both), so every realistic setup that wants to use the
    PBDNSMessage ingress path needs TCP support; the unix path
    stays available for out-of-tree producers that can speak it.

    One instance per daemon. Multiple recursor connections are
    handled concurrently (each connection gets its own reader
    coroutine). Decode happens inline on the event loop — protobuf
    is fast enough at realistic rates that a thread pool hop costs
    more than it saves. If profiling ever shows otherwise, swap
    :func:`decode_pbdns_frame` to run via ``asyncio.to_thread``.
    """

    def __init__(
        self,
        *,
        socket_path: str | None = None,
        bridge: TrackerBridge,
        socket_mode: int = 0o660,
        socket_owner: str | int | None = None,
        socket_group: str | int | None = None,
        tcp_host: str | None = None,
        tcp_port: int | None = None,
    ) -> None:
        tcp_configured = bool(tcp_host) and tcp_port is not None
        if not socket_path and not tcp_configured:
            raise ValueError(
                "PbdnsServer requires a unix socket_path, a "
                "(tcp_host, tcp_port) pair, or both")
        self._socket_path = socket_path
        self._bridge = bridge
        self._socket_mode = socket_mode
        self._socket_owner = socket_owner
        self._socket_group = socket_group
        self._tcp_host = tcp_host
        self._tcp_port = tcp_port
        self._server: asyncio.base_events.Server | None = None
        self._tcp_server: asyncio.base_events.Server | None = None
        self.metrics = PbdnsMetrics()

    async def start(self) -> None:
        if self._socket_path:
            path = Path(self._socket_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            self._server = await asyncio.start_unix_server(
                self._handle_client, path=str(path))
            from .sockperms import apply_socket_perms
            apply_socket_perms(
                path,
                mode=self._socket_mode,
                owner=self._socket_owner,
                group=self._socket_group,
            )
            log.info("pbdns server listening on %s", path)
        if bool(self._tcp_host) and self._tcp_port is not None:
            self._tcp_server = await asyncio.start_server(
                self._handle_client,
                host=self._tcp_host,
                port=self._tcp_port,
                reuse_address=True,
            )
            log.info(
                "pbdns server listening on tcp://%s:%d",
                self._tcp_host, self._tcp_port)

    async def close(self) -> None:
        if self._tcp_server is not None:
            self._tcp_server.close()
            try:
                await self._tcp_server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._tcp_server = None
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        if self._socket_path:
            try:
                Path(self._socket_path).unlink()
            except FileNotFoundError:
                pass

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.metrics.inc("connections", 1)
        self.metrics.inc("connections_total", 1)
        try:
            while True:
                # pdns-recursor's protobufServer() frames every
                # PBDNSMessage with a 2-byte big-endian length
                # prefix (``uint16_t mlen = htons(data.length())``
                # in rec-protobuf.cc). A 4-byte read would pull
                # the header plus the first two bytes of the
                # protobuf body, interpret that as the length,
                # and disconnect the client with a garbage cap
                # overflow. Match the on-wire 2-byte framing
                # exactly.
                header = await reader.readexactly(2)
                length = struct.unpack(">H", header)[0]
                if length == 0:
                    continue
                if length > MAX_FRAME_BYTES:
                    log.warning(
                        "pbdns frame length %d exceeds cap %d; "
                        "disconnecting", length, MAX_FRAME_BYTES)
                    return
                body = await reader.readexactly(length)
                decode_pbdns_frame(body, self._bridge, self.metrics)
        except asyncio.IncompleteReadError:
            return
        except (ConnectionResetError, BrokenPipeError):
            return
        finally:
            self.metrics.inc("connections", -1)
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass


# ── Helper: build a length-prefixed frame for producers/tests ────────


def encode_length_prefixed(msg: "dnsmessage_pb2.PBDNSMessage") -> bytes:
    """Encode a PBDNSMessage into the recursor's wire format.

    Matches pdns-recursor's ``protobufServer()`` framing exactly:
    a 2-byte big-endian length followed by the serialised
    PBDNSMessage. Used by tests and by the simlab integration
    test (Phase 10) to synthesise pdns-like frames without
    running a real recursor.
    """
    body = msg.SerializeToString()
    if len(body) > 0xFFFF:
        raise ValueError(
            f"PBDNSMessage {len(body)} bytes exceeds 2-byte length "
            f"prefix limit (0xFFFF)")
    return struct.pack(">H", len(body)) + body


# ── Prometheus collector ─────────────────────────────────────────────


class PbdnsMetricsCollector:
    """Prometheus collector that surfaces the pbdns pipeline counters.

    Mirrors :class:`shorewalld.dnstap.DnstapMetricsCollector`
    so operators running both ingestion paths see a symmetric
    ``shorewalld_pbdns_*`` / ``shorewalld_dnstap_*`` metric set and
    can A/B compare the two in a single Grafana dashboard.
    """

    def __init__(self, server: PbdnsServer) -> None:
        from .exporter import CollectorBase
        CollectorBase.__init__(self, netns="")
        self._server = server
        self.netns = ""

    def collect(self):  # type: ignore[no-untyped-def]
        from .exporter import _MetricFamily
        snap = self._server.metrics.snapshot()
        fams: list = []

        def counter(name: str, help_text: str, value: float) -> None:
            fam = _MetricFamily(name, help_text, [], mtype="counter")
            fam.add([], float(value))
            fams.append(fam)

        def gauge(name: str, help_text: str, value: float) -> None:
            fam = _MetricFamily(name, help_text, [])
            fam.add([], float(value))
            fams.append(fam)

        counter("shorewalld_pbdns_frames_accepted_total",
                "PBDNSMessage frames that produced a DnsUpdate",
                snap["frames_accepted_total"])
        counter("shorewalld_pbdns_frames_decode_error_total",
                "PBDNSMessage frames that failed protobuf decode",
                snap["frames_decode_error_total"])
        counter("shorewalld_pbdns_frames_empty_rrs_total",
                "PBDNSMessage frames with no A/AAAA answers",
                snap["frames_empty_rrs_total"])
        counter("shorewalld_pbdns_frames_family_v4_total",
                "Per-frame A record counts (v4 RRs seen)",
                snap["frames_family_v4_total"])
        counter("shorewalld_pbdns_frames_family_v6_total",
                "Per-frame AAAA record counts (v6 RRs seen)",
                snap["frames_family_v6_total"])
        counter("shorewalld_pbdns_frames_by_rcode_noerror_total",
                "NOERROR PBDNSMessage frames",
                snap["frames_by_rcode_noerror_total"])
        counter("shorewalld_pbdns_frames_by_rcode_nxdomain_total",
                "NXDOMAIN PBDNSMessage frames",
                snap["frames_by_rcode_nxdomain_total"])
        counter("shorewalld_pbdns_bytes_received_total",
                "Bytes of PBDNSMessage protobuf received",
                snap["bytes_received_total"])
        counter("shorewalld_pbdns_connections_total",
                "Cumulative PBDNSMessage producer connections",
                snap["connections_total"])
        counter("shorewalld_pbdns_frames_skipped_by_type_total",
                "PBDNSMessage frames dropped by the pre-filter varint peek "
                "before ParseFromString (message type not in RESPONSE_TYPES "
                "or peek returned None for a malformed outer message)",
                snap["frames_skipped_by_type_total"])
        counter("shorewalld_pbdns_frames_skipped_by_qname_total",
                "PBDNSMessage RESPONSE frames skipped before ParseFromString "
                "because the peeked qname is not in the tracker allowlist",
                snap["frames_skipped_by_qname_total"])
        gauge("shorewalld_pbdns_connections",
              "Currently connected PBDNSMessage producers",
              snap["connections"])
        return fams
