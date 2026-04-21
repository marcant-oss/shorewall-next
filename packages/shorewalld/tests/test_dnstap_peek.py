"""Tests for the _peek_message_type two-pass pre-filter.

Verifies that _peek_message_type correctly reads the dnstap Message.Type
from the varint stream without a full protobuf parse, and that the
DecodeWorkerPool._decode_one() skips ParseFromString for non-response
frames while still calling it for accepted ones.

All frames are crafted inline — no real dnstap socket required.
"""
from __future__ import annotations

import asyncio
import queue
from unittest.mock import patch

import pytest

from shorewalld.dnstap import (
    AUTH_RESPONSE,
    CLIENT_RESPONSE,
    DecodeWorkerPool,
    DnstapMetrics,
    FORWARDER_RESPONSE,
    QnameFilter,
    RESOLVER_RESPONSE,
    RESPONSE_MESSAGE_TYPES,
    STUB_RESPONSE,
    _peek_message_type,
)


# ── Frame-building helpers ───────────────────────────────────────────


def _enc_varint(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _enc_field(fnum: int, wire_type: int, body: bytes) -> bytes:
    return _enc_varint((fnum << 3) | wire_type) + body


def _make_dnstap_frame(msg_type: int, wire: bytes = b"\x00") -> bytes:
    """Build a minimal dnstap.Dnstap protobuf frame.

    Only encodes the fields that _peek_message_type and
    decode_dnstap_frame need: Dnstap.message (field 14) wrapping a
    Message with Message.type (field 1) and Message.response_message
    (field 14).
    """
    inner = (
        _enc_field(1, 0, _enc_varint(msg_type))
        + _enc_field(14, 2, _enc_varint(len(wire)) + wire)
    )
    outer = _enc_field(14, 2, _enc_varint(len(inner)) + inner)
    return outer


def _make_query_frame(msg_type: int) -> bytes:
    """Build a minimal dnstap frame for a query type (no response_message)."""
    inner = _enc_field(1, 0, _enc_varint(msg_type))
    outer = _enc_field(14, 2, _enc_varint(len(inner)) + inner)
    return outer


# ── _peek_message_type unit tests ────────────────────────────────────


def test_peek_message_type_client_response():
    """Frame with type=CLIENT_RESPONSE (6) returns 6."""
    frame = _make_dnstap_frame(CLIENT_RESPONSE)
    assert _peek_message_type(frame) == CLIENT_RESPONSE


def test_peek_message_type_resolver_query():
    """Frame with type=RESOLVER_QUERY (3) — a non-response type — returns 3."""
    # RESOLVER_QUERY = 3 per dnstap.proto
    RESOLVER_QUERY = 3
    frame = _make_query_frame(RESOLVER_QUERY)
    result = _peek_message_type(frame)
    assert result == RESOLVER_QUERY
    assert result not in RESPONSE_MESSAGE_TYPES


def test_peek_message_type_auth_response():
    frame = _make_dnstap_frame(AUTH_RESPONSE)
    assert _peek_message_type(frame) == AUTH_RESPONSE


def test_peek_message_type_resolver_response():
    frame = _make_dnstap_frame(RESOLVER_RESPONSE)
    assert _peek_message_type(frame) == RESOLVER_RESPONSE


def test_peek_message_type_forwarder_response():
    frame = _make_dnstap_frame(FORWARDER_RESPONSE)
    assert _peek_message_type(frame) == FORWARDER_RESPONSE


def test_peek_message_type_stub_response():
    frame = _make_dnstap_frame(STUB_RESPONSE)
    assert _peek_message_type(frame) == STUB_RESPONSE


def test_peek_message_type_malformed_empty():
    """Empty frame → None (no bytes to read)."""
    assert _peek_message_type(b"") is None


def test_peek_message_type_malformed_truncated_outer():
    """Frame truncated mid-outer-field → None."""
    frame = _make_dnstap_frame(CLIENT_RESPONSE)
    assert _peek_message_type(frame[:3]) is None


def test_peek_message_type_malformed_truncated_inner():
    """Frame truncated inside the inner Message bytes → None."""
    frame = _make_dnstap_frame(CLIENT_RESPONSE)
    # Truncate to leave the outer tag+length intact but cut inner short
    assert _peek_message_type(frame[:len(frame) // 2]) is None


def test_peek_message_type_malformed_all_continuation_bytes():
    """All-continuation varint bytes → None (varint too long / truncated)."""
    assert _peek_message_type(bytes([0x80] * 16)) is None


def test_peek_message_type_accepts_memoryview():
    """Accepts a memoryview directly without copying bytes."""
    frame = _make_dnstap_frame(CLIENT_RESPONSE)
    mv = memoryview(frame)
    assert _peek_message_type(mv) == CLIENT_RESPONSE


def test_peek_message_type_no_message_field():
    """Dnstap frame that has no Message field (only identity) → None."""
    # Encode only field 1 (identity bytes) in the outer Dnstap
    buf = _enc_field(1, 2, _enc_varint(4) + b"test")
    assert _peek_message_type(buf) is None


def test_peek_message_type_message_field_no_type():
    """Dnstap.message present but inner Message has no type field → None."""
    # Inner message with only response_message (field 14), no type (field 1)
    inner = _enc_field(14, 2, _enc_varint(2) + b"\x00\x00")
    outer = _enc_field(14, 2, _enc_varint(len(inner)) + inner)
    assert _peek_message_type(outer) is None


def test_peek_message_type_extra_outer_fields_before_message():
    """Extra fields before field 14 are skipped correctly."""
    # Add a varint field 1 and a length-delimited field 2 before message
    prefix = (
        _enc_field(1, 2, _enc_varint(4) + b"node")  # identity
        + _enc_field(2, 2, _enc_varint(3) + b"1.0")  # version
    )
    inner = _enc_field(1, 0, _enc_varint(CLIENT_RESPONSE))
    outer = prefix + _enc_field(14, 2, _enc_varint(len(inner)) + inner)
    assert _peek_message_type(outer) == CLIENT_RESPONSE


# ── _decode_one pre-filter integration tests ────────────────────────


def test_decode_one_skip_non_response_no_parse():
    """ParseFromString is called exactly once when one QUERY + one RESPONSE
    frame are fed: the query is dropped by the pre-filter, only the response
    triggers a full parse.
    """
    CLIENT_QUERY = 5  # not in RESPONSE_MESSAGE_TYPES

    query_frame = _make_query_frame(CLIENT_QUERY)
    response_frame = _make_dnstap_frame(CLIENT_RESPONSE, b"\x00")

    parse_call_count: list[int] = [0]

    # Patch ParseFromString on the Dnstap class inside the proto module
    try:
        from shorewalld.proto import dnstap_pb2
        real_parse = dnstap_pb2.Dnstap.ParseFromString

        def counting_parse(self, data: bytes) -> int:
            parse_call_count[0] += 1
            return real_parse(self, data)

        metrics = DnstapMetrics()
        frame_q: queue.Queue[bytes] = queue.Queue(maxsize=8)

        async def driver() -> None:
            loop = asyncio.get_running_loop()
            pool = DecodeWorkerPool(
                frame_q, metrics,
                on_update=lambda _u: None,
                loop=loop,
                qname_filter=QnameFilter(),
                n_workers=1,
            )
            with patch.object(dnstap_pb2.Dnstap, "ParseFromString",
                              counting_parse):
                pool.start()
                try:
                    frame_q.put(query_frame)
                    frame_q.put(response_frame)
                    # Wait until both frames are consumed
                    for _ in range(100):
                        await asyncio.sleep(0.02)
                        if metrics.frames_skipped_by_type >= 1:
                            # Give the response frame time to be processed too
                            await asyncio.sleep(0.1)
                            break
                finally:
                    pool.stop()

        asyncio.run(driver())

        # The query frame must be dropped before ParseFromString runs.
        # The response frame is accepted → exactly one parse call.
        assert metrics.frames_skipped_by_type == 1
        assert parse_call_count[0] == 1

    except ImportError:
        pytest.skip("protobuf runtime not available")


def test_decode_one_counter_increments_on_skip():
    """frames_skipped_by_type increments for each non-response frame."""
    CLIENT_QUERY = 5
    AUTH_QUERY = 1

    frames = [_make_query_frame(CLIENT_QUERY), _make_query_frame(AUTH_QUERY)]

    metrics = DnstapMetrics()
    frame_q: queue.Queue[bytes] = queue.Queue(maxsize=8)

    async def driver() -> None:
        loop = asyncio.get_running_loop()
        pool = DecodeWorkerPool(
            frame_q, metrics,
            on_update=lambda _u: None,
            loop=loop,
            qname_filter=QnameFilter(),
            n_workers=1,
        )
        pool.start()
        try:
            for f in frames:
                frame_q.put(f)
            for _ in range(100):
                await asyncio.sleep(0.02)
                if metrics.frames_skipped_by_type >= 2:
                    break
        finally:
            pool.stop()

    asyncio.run(driver())
    assert metrics.frames_skipped_by_type == 2


# ── Benchmark (skipped by default; run with -m bench) ───────────────


@pytest.mark.bench
def test_bench_peek_vs_full_parse_parse_count():
    """Synthetic 10 000-frame mix: 100 RESPONSE + 9900 QUERY.

    Asserts that with the pre-filter active, ParseFromString is called
    at most 100 times (only for RESPONSE frames), not 10 000 times.
    Marked @pytest.mark.bench — skipped in the normal test run.
    """
    try:
        from shorewalld.proto import dnstap_pb2
    except ImportError:
        pytest.skip("protobuf runtime not available")

    CLIENT_QUERY = 5
    N_RESPONSE = 100
    N_QUERY = 9900

    response_frame = _make_dnstap_frame(CLIENT_RESPONSE, b"\x00")
    query_frame = _make_query_frame(CLIENT_QUERY)
    frames = [response_frame] * N_RESPONSE + [query_frame] * N_QUERY

    parse_call_count: list[int] = [0]
    real_parse = dnstap_pb2.Dnstap.ParseFromString

    def counting_parse(self, data: bytes) -> int:
        parse_call_count[0] += 1
        return real_parse(self, data)

    metrics = DnstapMetrics()
    frame_q: queue.Queue[bytes] = queue.Queue(maxsize=len(frames) + 10)

    async def driver() -> None:
        loop = asyncio.get_running_loop()
        pool = DecodeWorkerPool(
            frame_q, metrics,
            on_update=lambda _u: None,
            loop=loop,
            qname_filter=QnameFilter(),
            n_workers=1,
        )
        with patch.object(dnstap_pb2.Dnstap, "ParseFromString",
                          counting_parse):
            pool.start()
            try:
                for f in frames:
                    frame_q.put(f)
                # Wait until all frames processed
                for _ in range(500):
                    await asyncio.sleep(0.05)
                    total = (metrics.frames_skipped_by_type
                             + metrics.frames_accepted
                             + metrics.frames_dropped_not_a_or_aaaa
                             + metrics.frames_decode_error
                             + metrics.frames_dropped_not_client_response)
                    if total >= len(frames):
                        break
            finally:
                pool.stop()

    asyncio.run(driver())

    # Pre-filter must have dropped all 9900 query frames before parsing.
    assert metrics.frames_skipped_by_type == N_QUERY
    # ParseFromString should only have been called for RESPONSE frames.
    assert parse_call_count[0] <= N_RESPONSE, (
        f"Expected at most {N_RESPONSE} ParseFromString calls, "
        f"got {parse_call_count[0]} (pre-filter not working)"
    )
