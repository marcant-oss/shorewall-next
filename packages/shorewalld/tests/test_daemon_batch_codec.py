"""Tests for the parent↔nft-worker batch wire codec.

The codec is hot-path critical: preallocated buffers, no ``bytes``
copying in the steady state, SEQPACKET-sized datagrams. These tests
verify the encode/decode round-trip, buffer-reuse semantics, and
error paths.
"""

from __future__ import annotations

import pytest

from shorewalld.batch_codec import (
    BATCH_OP_ADD,
    BATCH_OP_DEL,
    CTRL_SHUTDOWN,
    CTRL_SNAPSHOT,
    HEADER_LEN,
    MAGIC_REPLY,
    MAGIC_REQUEST,
    MAX_OPS_PER_BATCH,
    OP_LEN,
    REPLY_ERROR,
    REPLY_HEADER_LEN,
    REPLY_OK,
    WIRE_VERSION,
    BatchBuilder,
    WireError,
    decode_control,
    decode_header,
    decode_reply,
    encode_control,
    encode_reply_into,
    iter_ops,
)


def _v4(*octets: int) -> bytes:
    return bytes(octets)


def _v6(pattern: int) -> bytes:
    return bytes([pattern] * 16)


class TestBatchBuilderBasics:
    def test_empty_batch_has_just_header(self):
        b = BatchBuilder()
        view = b.finish(batch_id=1)
        assert len(view) == HEADER_LEN
        h = decode_header(view)
        assert h.magic == MAGIC_REQUEST
        assert h.version == WIRE_VERSION
        assert h.op_count == 0
        assert h.batch_id == 1

    def test_single_v4_op_round_trip(self):
        b = BatchBuilder()
        b.append(
            set_id=42, family=4, op_kind=BATCH_OP_ADD,
            ttl=300, ip_bytes=_v4(1, 2, 3, 4),
        )
        view = b.finish(batch_id=7)
        h = decode_header(view)
        assert h.op_count == 1
        assert h.batch_id == 7
        ops = list(iter_ops(view, h))
        assert len(ops) == 1
        op = ops[0]
        assert op.set_id == 42
        assert op.family == 4
        assert op.op_kind == BATCH_OP_ADD
        assert op.ttl == 300
        assert op.ip_bytes == _v4(1, 2, 3, 4)

    def test_v6_op_preserves_full_16_bytes(self):
        b = BatchBuilder()
        ip = _v6(0xAB)
        b.append(
            set_id=9, family=6, op_kind=BATCH_OP_ADD,
            ttl=600, ip_bytes=ip,
        )
        view = b.finish(batch_id=99)
        ops = list(iter_ops(view, decode_header(view)))
        assert ops[0].ip_bytes == ip

    def test_multiple_ops_packed_contiguously(self):
        b = BatchBuilder()
        for i in range(5):
            b.append(
                set_id=i, family=4, op_kind=BATCH_OP_ADD,
                ttl=60 * (i + 1), ip_bytes=_v4(10, 0, 0, i),
            )
        view = b.finish(batch_id=1)
        assert len(view) == HEADER_LEN + 5 * OP_LEN
        h = decode_header(view)
        assert h.op_count == 5
        ops = list(iter_ops(view, h))
        assert [o.set_id for o in ops] == [0, 1, 2, 3, 4]
        assert [o.ttl for o in ops] == [60, 120, 180, 240, 300]

    def test_add_and_del_mixed(self):
        b = BatchBuilder()
        b.append(
            set_id=1, family=4, op_kind=BATCH_OP_ADD,
            ttl=300, ip_bytes=_v4(1, 1, 1, 1))
        b.append(
            set_id=1, family=4, op_kind=BATCH_OP_DEL,
            ttl=0, ip_bytes=_v4(2, 2, 2, 2))
        ops = list(iter_ops(*_unpack(b.finish(batch_id=0))))
        assert ops[0].op_kind == BATCH_OP_ADD
        assert ops[1].op_kind == BATCH_OP_DEL


class TestBatchBuilderReuse:
    def test_reset_reuses_buffer(self):
        b = BatchBuilder()
        b.append(
            set_id=1, family=4, op_kind=BATCH_OP_ADD,
            ttl=100, ip_bytes=_v4(1, 2, 3, 4))
        v1 = b.finish(batch_id=1)
        raw1 = bytes(v1)

        b.reset()
        b.append(
            set_id=2, family=4, op_kind=BATCH_OP_ADD,
            ttl=200, ip_bytes=_v4(5, 6, 7, 8))
        v2 = b.finish(batch_id=2)
        raw2 = bytes(v2)

        # Second batch must decode correctly to the *new* content.
        h2 = decode_header(raw2)
        ops = list(iter_ops(raw2, h2))
        assert ops[0].set_id == 2
        assert ops[0].ttl == 200
        # First snapshot we copied is untouched; we proved v1 ≠ v2.
        assert raw1 != raw2

    def test_count_and_full_properties(self):
        b = BatchBuilder(max_ops=3)
        assert b.count == 0
        assert b.empty
        assert not b.full
        for i in range(3):
            b.append(set_id=i, family=4, op_kind=BATCH_OP_ADD,
                     ttl=60, ip_bytes=_v4(i, i, i, i))
        assert b.count == 3
        assert b.full
        assert not b.empty

    def test_overflow_raises(self):
        b = BatchBuilder(max_ops=2)
        for i in range(2):
            b.append(set_id=i, family=4, op_kind=BATCH_OP_ADD,
                     ttl=60, ip_bytes=_v4(0, 0, 0, i))
        with pytest.raises(OverflowError):
            b.append(set_id=99, family=4, op_kind=BATCH_OP_ADD,
                     ttl=60, ip_bytes=_v4(9, 9, 9, 9))


class TestControlMessages:
    def test_shutdown_round_trip(self):
        b = BatchBuilder()
        view = encode_control(b, CTRL_SHUTDOWN, batch_id=7)
        h = decode_header(view)
        assert h.op_count == 0
        control, inner = decode_control(h.batch_id)
        assert control == CTRL_SHUTDOWN
        assert inner == 7

    def test_snapshot_round_trip(self):
        b = BatchBuilder()
        view = encode_control(b, CTRL_SNAPSHOT, batch_id=123456789)
        control, inner = decode_control(decode_header(view).batch_id)
        assert control == CTRL_SNAPSHOT
        assert inner == 123456789


class TestDecodeHeaderErrors:
    def test_truncated_header(self):
        with pytest.raises(WireError):
            decode_header(b"\x00\x01\x02")

    def test_bad_magic(self):
        bad = b"BAD!" + b"\x00" * 12
        with pytest.raises(WireError):
            decode_header(bad)

    def test_bad_version(self):
        # Valid magic but invalid version byte.
        import struct
        payload = struct.pack(">I H H Q", MAGIC_REQUEST, 99, 0, 0)
        with pytest.raises(WireError):
            decode_header(payload)


class TestIterOpsErrors:
    def test_truncated_ops_region(self):
        b = BatchBuilder()
        b.append(set_id=1, family=4, op_kind=BATCH_OP_ADD,
                 ttl=60, ip_bytes=_v4(1, 2, 3, 4))
        view = bytes(b.finish(batch_id=1))
        h = decode_header(view)
        # Slice off half of the op region
        short = view[: HEADER_LEN + 4]
        with pytest.raises(WireError):
            list(iter_ops(short, h))

    def test_bad_family_byte(self):
        import struct
        buf = bytearray(HEADER_LEN + OP_LEN)
        struct.pack_into(">I H H Q", buf, 0,
                         MAGIC_REQUEST, WIRE_VERSION, 1, 0)
        struct.pack_into(">H B B I 16s", buf, HEADER_LEN,
                         1, 9, BATCH_OP_ADD, 60, b"\x00" * 16)
        h = decode_header(buf)
        with pytest.raises(WireError):
            list(iter_ops(buf, h))


class TestBadAppendInputs:
    def test_wrong_ip_length(self):
        b = BatchBuilder()
        with pytest.raises(ValueError):
            b.append(set_id=1, family=4, op_kind=BATCH_OP_ADD,
                     ttl=60, ip_bytes=b"\x01\x02\x03")


class TestReplyCodec:
    def test_empty_success(self):
        buf = bytearray(128)
        view = encode_reply_into(
            buf, status=REPLY_OK, batch_id=42, applied=5)
        assert len(view) == REPLY_HEADER_LEN
        r = decode_reply(view)
        assert r.magic == MAGIC_REPLY
        assert r.status == REPLY_OK
        assert r.batch_id == 42
        assert r.applied == 5
        assert r.error == ""

    def test_error_message_round_trip(self):
        buf = bytearray(512)
        view = encode_reply_into(
            buf, status=REPLY_ERROR, batch_id=7, applied=0,
            error="netlink: set not found")
        r = decode_reply(view)
        assert r.status == REPLY_ERROR
        assert r.error == "netlink: set not found"
        assert r.applied == 0

    def test_reply_buffer_too_small(self):
        small = bytearray(REPLY_HEADER_LEN + 5)
        with pytest.raises(OverflowError):
            encode_reply_into(
                small, status=REPLY_ERROR, batch_id=0, applied=0,
                error="this error text will not fit in the buffer")

    def test_reply_truncated(self):
        with pytest.raises(WireError):
            decode_reply(b"\x00\x00")

    def test_reply_bad_magic(self):
        import struct
        bad = struct.pack(
            ">I H H Q H H I",
            0xDEADBEEF, WIRE_VERSION, REPLY_OK, 1, 1, 0, 0)
        with pytest.raises(WireError):
            decode_reply(bad)


class TestCapacityLimits:
    def test_max_ops_per_batch_fits(self):
        b = BatchBuilder()
        for i in range(MAX_OPS_PER_BATCH):
            b.append(set_id=i & 0xFFFF, family=4, op_kind=BATCH_OP_ADD,
                     ttl=60, ip_bytes=_v4(10, 0, i >> 8 & 0xFF, i & 0xFF))
        view = b.finish(batch_id=1)
        assert len(view) == HEADER_LEN + MAX_OPS_PER_BATCH * OP_LEN
        assert len(view) < 1400  # must fit MTU-1 for peer link parity

    def test_finish_returns_view_not_bytes(self):
        b = BatchBuilder()
        b.append(set_id=1, family=4, op_kind=BATCH_OP_ADD,
                 ttl=60, ip_bytes=_v4(1, 2, 3, 4))
        view = b.finish(batch_id=1)
        # finish() returns a memoryview sharing the internal buffer.
        assert isinstance(view, memoryview)


def _unpack(view: memoryview | bytes) -> tuple[memoryview | bytes, object]:
    """Helper: return (view, decoded_header) for iter_ops chaining."""
    return view, decode_header(view)
