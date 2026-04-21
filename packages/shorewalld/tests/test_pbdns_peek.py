"""Tests for the _peek_type_and_qname two-pass pre-filter in pbdns.py.

Mirrors the structure of test_dnstap_peek.py.  All frames are crafted
inline using raw protobuf varint encoding — no real pdns-recursor socket
required.

Field numbers verified against proto/dnsmessage_pb2.py:
  PBDNSMessage.type     → field 1,  wire type 0 (varint)           tag 0x08
  PBDNSMessage.question → field 12, wire type 2 (length-delimited) tag 0x62
  DNSQuestion.qName     → field 1,  wire type 2 (length-delimited) tag 0x0A
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from shorewalld.pbdns import (
    PBDNS_TYPE_QUERY,
    PBDNS_TYPE_RESPONSE,
    PBDNS_TYPE_INCOMING_RESPONSE,
    _peek_type_and_qname,
    decode_pbdns_frame,
)
from shorewalld.proto import dnsmessage_pb2


# ── Frame-building helpers ───────────────────────────────────────────


def _enc_varint(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _enc_ld(fnum: int, body: bytes) -> bytes:
    """Encode a length-delimited (wire type 2) field."""
    tag = _enc_varint((fnum << 3) | 2)
    return tag + _enc_varint(len(body)) + body


def _enc_varint_field(fnum: int, value: int) -> bytes:
    """Encode a varint (wire type 0) field."""
    tag = _enc_varint((fnum << 3) | 0)
    return tag + _enc_varint(value)


def _make_pbdns_frame(
    msg_type: int = PBDNS_TYPE_RESPONSE,
    qname: str | None = "example.com",
) -> bytes:
    """Build a minimal PBDNSMessage protobuf frame.

    Only encodes the fields that _peek_type_and_qname needs:
      * type     → field 1 (varint)
      * question → field 12 (length-delimited message)
        * qName  → field 1 (string / length-delimited)
    """
    parts: list[bytes] = []
    parts.append(_enc_varint_field(1, msg_type))  # PBDNSMessage.type
    if qname is not None:
        qname_bytes = qname.encode()
        inner = _enc_ld(1, qname_bytes)  # DNSQuestion.qName
        parts.append(_enc_ld(12, inner))  # PBDNSMessage.question
    return b"".join(parts)


def _make_full_response(
    qname: str = "example.com",
    rcode: int = 0,
    a: list[bytes] | None = None,
    ttl: int = 300,
) -> bytes:
    """Use the real protobuf library to build a complete PBDNSMessage."""
    msg = dnsmessage_pb2.PBDNSMessage()
    msg.type = dnsmessage_pb2.PBDNSMessage.DNSResponseType
    msg.question.qName = qname
    msg.question.qType = 1
    msg.response.rcode = rcode
    for addr in a or []:
        rr = msg.response.rrs.add()
        rr.name = qname
        rr.type = 1
        rr.ttl = ttl
        rr.rdata = addr
    return msg.SerializeToString()


# ── _peek_type_and_qname unit tests ─────────────────────────────────


def test_peek_response_type_and_qname():
    """RESPONSE frame returns correct (type, qname)."""
    frame = _make_pbdns_frame(PBDNS_TYPE_RESPONSE, "example.com")
    t, q = _peek_type_and_qname(frame)
    assert t == PBDNS_TYPE_RESPONSE
    assert q == b"example.com"


def test_peek_query_type():
    """QUERY frame returns correct type."""
    frame = _make_pbdns_frame(PBDNS_TYPE_QUERY, "example.com")
    t, q = _peek_type_and_qname(frame)
    assert t == PBDNS_TYPE_QUERY
    assert q == b"example.com"


def test_peek_incoming_response_type():
    """DNSIncomingResponseType (4) is returned correctly."""
    frame = _make_pbdns_frame(PBDNS_TYPE_INCOMING_RESPONSE, "example.com")
    t, q = _peek_type_and_qname(frame)
    assert t == PBDNS_TYPE_INCOMING_RESPONSE


def test_peek_qname_lowercased():
    """qName is returned lowercase regardless of original case."""
    frame = _make_pbdns_frame(PBDNS_TYPE_RESPONSE, "Example.COM")
    _, q = _peek_type_and_qname(frame)
    assert q == b"example.com"


def test_peek_truncated_frame_returns_none():
    """Truncated frame → (None, None)."""
    frame = _make_pbdns_frame(PBDNS_TYPE_RESPONSE, "example.com")
    t, q = _peek_type_and_qname(frame[:3])
    assert t is None
    assert q is None


def test_peek_empty_frame_returns_none():
    """Empty bytes → (None, None)."""
    t, q = _peek_type_and_qname(b"")
    assert t is None
    assert q is None


def test_peek_missing_question_field():
    """Frame with type but no question field → (type, None)."""
    frame = _make_pbdns_frame(PBDNS_TYPE_RESPONSE, qname=None)
    t, q = _peek_type_and_qname(frame)
    assert t == PBDNS_TYPE_RESPONSE
    assert q is None


def test_peek_missing_type_field():
    """Frame with question but no type field → (None, qname)."""
    # Craft a frame with only the question field, no type.
    qname_bytes = b"example.com"
    inner = _enc_ld(1, qname_bytes)
    frame = _enc_ld(12, inner)  # PBDNSMessage.question only
    t, q = _peek_type_and_qname(frame)
    assert t is None
    assert q == b"example.com"


def test_peek_accepts_memoryview():
    """Accepts a memoryview directly without copying bytes."""
    frame = _make_pbdns_frame(PBDNS_TYPE_RESPONSE, "example.com")
    mv = memoryview(frame)
    t, q = _peek_type_and_qname(mv)
    assert t == PBDNS_TYPE_RESPONSE
    assert q == b"example.com"


def test_peek_accepts_bytes():
    """bytes input (not memoryview) works correctly."""
    frame = _make_pbdns_frame(PBDNS_TYPE_RESPONSE, "example.com")
    assert isinstance(frame, bytes)
    t, q = _peek_type_and_qname(frame)
    assert t == PBDNS_TYPE_RESPONSE
    assert q == b"example.com"


def test_peek_extra_fields_before_type():
    """Extra fields before type are skipped."""
    # Prepend a varint field 2 (messageId bytes) before type.
    extra = _enc_ld(2, b"\x00" * 4)  # messageId = 4 zero bytes
    suffix = _make_pbdns_frame(PBDNS_TYPE_RESPONSE, "skip.example")
    frame = extra + suffix
    t, q = _peek_type_and_qname(frame)
    assert t == PBDNS_TYPE_RESPONSE
    assert q == b"skip.example"


def test_peek_real_protobuf_round_trip():
    """Peek returns the same type/qname as full parse from a real frame."""
    msg = dnsmessage_pb2.PBDNSMessage()
    msg.type = dnsmessage_pb2.PBDNSMessage.DNSResponseType
    msg.question.qName = "github.com"
    raw = msg.SerializeToString()

    t, q = _peek_type_and_qname(raw)
    assert t == dnsmessage_pb2.PBDNSMessage.DNSResponseType
    assert q == b"github.com"


def test_peek_all_continuation_bytes_malformed():
    """All-continuation varint bytes → (None, None)."""
    t, q = _peek_type_and_qname(bytes([0x80] * 16))
    assert t is None
    assert q is None


# ── decode_pbdns_frame integration tests ────────────────────────────


class _MetricsDummy:
    """Minimal metrics stand-in for decode_pbdns_frame integration tests."""

    def __init__(self) -> None:
        self.frames_accepted_total = 0
        self.frames_decode_error_total = 0
        self.frames_dropped_queue_full_total = 0
        self.frames_by_type_query_total = 0
        self.frames_by_type_response_total = 0
        self.frames_by_type_other_total = 0
        self.frames_by_rcode_noerror_total = 0
        self.frames_by_rcode_nxdomain_total = 0
        self.frames_by_rcode_servfail_total = 0
        self.frames_by_rcode_refused_total = 0
        self.frames_by_rcode_other_total = 0
        self.frames_family_v4_total = 0
        self.frames_family_v6_total = 0
        self.frames_empty_rrs_total = 0
        self.bytes_received_total = 0
        self.last_frame_mono = 0.0
        self.frames_skipped_by_type_total = 0
        self.frames_skipped_by_qname_total = 0

    def inc(self, attr: str, n: int = 1) -> None:
        setattr(self, attr, getattr(self, attr) + n)

    def set_last_frame_now(self) -> None:
        import time
        self.last_frame_mono = time.monotonic()


class _FakeBridge:
    """Minimal bridge stand-in that records apply() calls."""

    def __init__(self, registered_qnames: set[str]) -> None:
        self._names = {q.lower() for q in registered_qnames}
        self.apply_calls: list[dict] = []

    def has_qname_bytes(self, qname_lower: bytes) -> bool:
        return qname_lower.decode("ascii", errors="replace") in self._names

    def apply(
        self,
        qname: str,
        a_rrs: list,
        aaaa_rrs: list,
        ttl: int,
    ) -> None:
        self.apply_calls.append(
            {"qname": qname, "a_rrs": a_rrs, "aaaa_rrs": aaaa_rrs, "ttl": ttl}
        )


def test_decode_allowlisted_response_calls_apply():
    """RESPONSE frame with allowlisted qname → apply() called."""
    bridge = _FakeBridge({"example.com"})
    metrics = _MetricsDummy()
    raw = _make_full_response(
        qname="example.com",
        a=[b"\x01\x02\x03\x04"],
        ttl=300,
    )
    decode_pbdns_frame(raw, bridge, metrics)
    assert metrics.frames_accepted_total == 1
    assert len(bridge.apply_calls) == 1
    assert bridge.apply_calls[0]["qname"] == "example.com"


def test_decode_non_allowlisted_qname_skipped_no_parse():
    """RESPONSE frame with non-allowlisted qname → skipped before ParseFromString."""
    bridge = _FakeBridge({"allowed.example"})
    metrics = _MetricsDummy()
    raw = _make_full_response(qname="other.example", a=[b"\x01\x02\x03\x04"])

    parse_call_count: list[int] = [0]
    real_parse = dnsmessage_pb2.PBDNSMessage.ParseFromString

    def counting_parse(self, data: bytes) -> int:
        parse_call_count[0] += 1
        return real_parse(self, data)

    with patch.object(dnsmessage_pb2.PBDNSMessage, "ParseFromString",
                      counting_parse):
        decode_pbdns_frame(raw, bridge, metrics)

    assert metrics.frames_skipped_by_qname_total == 1
    assert metrics.frames_accepted_total == 0
    assert parse_call_count[0] == 0, (
        f"ParseFromString must not be called for non-allowlisted qname, "
        f"but was called {parse_call_count[0]} time(s)"
    )
    assert len(bridge.apply_calls) == 0


def test_decode_query_type_skipped_no_parse():
    """QUERY frame → skipped before ParseFromString; query counter incremented."""
    bridge = _FakeBridge({"example.com"})
    metrics = _MetricsDummy()

    msg = dnsmessage_pb2.PBDNSMessage()
    msg.type = dnsmessage_pb2.PBDNSMessage.DNSQueryType
    msg.question.qName = "example.com"
    raw = msg.SerializeToString()

    parse_call_count: list[int] = [0]
    real_parse = dnsmessage_pb2.PBDNSMessage.ParseFromString

    def counting_parse(self, data: bytes) -> int:
        parse_call_count[0] += 1
        return real_parse(self, data)

    with patch.object(dnsmessage_pb2.PBDNSMessage, "ParseFromString",
                      counting_parse):
        decode_pbdns_frame(raw, bridge, metrics)

    assert metrics.frames_skipped_by_type_total == 1
    # Legacy per-type counter still fires from the peek
    assert metrics.frames_by_type_query_total == 1
    assert parse_call_count[0] == 0, (
        f"ParseFromString must not be called for QUERY frames, "
        f"but was called {parse_call_count[0]} time(s)"
    )


def test_decode_malformed_bytes_increment_error():
    """Malformed bytes → decode_error_total incremented."""
    bridge = _FakeBridge({"example.com"})
    metrics = _MetricsDummy()
    decode_pbdns_frame(b"\x00\xff\xff\xff", bridge, metrics)
    assert metrics.frames_decode_error_total == 1


# ── Benchmark (skipped by default; run with -m bench) ───────────────


@pytest.mark.bench
def test_bench_peek_parse_count_10k():
    """10 000-frame mix: 100 RESPONSE (allowlisted) + 9900 QUERY.

    Asserts that ParseFromString is called at most 100 times.
    """
    bridge = _FakeBridge({"example.com"})
    N_RESPONSE = 100
    N_QUERY = 9900

    response_raw = _make_full_response(
        qname="example.com", a=[b"\x01\x02\x03\x04"], ttl=300)
    query_raw = _make_pbdns_frame(PBDNS_TYPE_QUERY, "example.com")

    # Synthesise a real PBDNSMessage query frame via the library so the
    # peek can find the real wire-encoded type field.
    msg_q = dnsmessage_pb2.PBDNSMessage()
    msg_q.type = dnsmessage_pb2.PBDNSMessage.DNSQueryType
    msg_q.question.qName = "example.com"
    query_raw_real = msg_q.SerializeToString()

    frames = [response_raw] * N_RESPONSE + [query_raw_real] * N_QUERY

    parse_call_count: list[int] = [0]
    real_parse = dnsmessage_pb2.PBDNSMessage.ParseFromString

    def counting_parse(self, data: bytes) -> int:
        parse_call_count[0] += 1
        return real_parse(self, data)

    metrics = _MetricsDummy()
    with patch.object(dnsmessage_pb2.PBDNSMessage, "ParseFromString",
                      counting_parse):
        for raw in frames:
            decode_pbdns_frame(raw, bridge, metrics)

    # Query frames must have been dropped before ParseFromString.
    assert metrics.frames_skipped_by_type_total == N_QUERY
    assert parse_call_count[0] <= N_RESPONSE, (
        f"Expected at most {N_RESPONSE} ParseFromString calls, "
        f"got {parse_call_count[0]} (pre-filter not working)"
    )
