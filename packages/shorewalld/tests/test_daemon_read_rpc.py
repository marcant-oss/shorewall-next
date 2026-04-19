"""Unit tests for the file-read worker RPC.

Covers:

* :mod:`shorewalld.read_codec` — request/response encode/decode,
  boundary checks and error paths.
* :func:`shorewalld.nft_worker._handle_read` — file / line-count
  handler the worker runs in its own netns.
* :class:`shorewalld.worker_router.ParentWorker` read pipeline via
  :func:`inproc_worker_pair` — end-to-end dispatch + reply decode
  without forking a child.

The read RPC is parallel to the batch-op path; tests here are meant
to lock its wire format so collectors can depend on byte-for-byte
stability across releases.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from shorewalld.nft_worker import _handle_read
from shorewalld.read_codec import (
    MAGIC_READ_REQ,
    MAX_FILE_BYTES,
    READ_KIND_COUNT_LINES,
    READ_KIND_FILE,
    READ_STATUS_ERROR,
    READ_STATUS_NOT_FOUND,
    READ_STATUS_OK,
    READ_STATUS_TOO_LARGE,
    ReadWireError,
    decode_line_count,
    decode_read_request,
    decode_read_response,
    encode_line_count,
    encode_read_request,
    encode_read_response_into,
    peek_magic,
)


# ── Codec round-trip ─────────────────────────────────────────────────


def test_encode_decode_read_request_roundtrip_file():
    payload = encode_read_request(
        kind=READ_KIND_FILE, req_id=42,
        path="/proc/net/snmp")
    assert peek_magic(payload) == MAGIC_READ_REQ

    req = decode_read_request(payload)
    assert req.kind == READ_KIND_FILE
    assert req.req_id == 42
    assert req.path == "/proc/net/snmp"


def test_encode_decode_read_request_roundtrip_count_lines():
    payload = encode_read_request(
        kind=READ_KIND_COUNT_LINES, req_id=7,
        path="/proc/net/ipv6_route")
    req = decode_read_request(payload)
    assert req.kind == READ_KIND_COUNT_LINES
    assert req.req_id == 7
    assert req.path == "/proc/net/ipv6_route"


def test_encode_read_request_rejects_unknown_kind():
    with pytest.raises(ValueError):
        encode_read_request(kind=999, req_id=1, path="/tmp/x")


def test_decode_read_request_rejects_bad_magic():
    bad = bytearray(encode_read_request(
        kind=READ_KIND_FILE, req_id=1, path="/a"))
    bad[0] = 0xFF  # flip the magic
    with pytest.raises(ReadWireError):
        decode_read_request(bytes(bad))


def test_decode_read_request_rejects_truncated_path():
    # Header claims path_len=10 but we only supply 3 bytes of path.
    import struct
    from shorewalld.read_codec import READ_REQ_HEADER_LEN
    hdr = struct.pack(
        ">I H H Q H",
        MAGIC_READ_REQ, 1, READ_KIND_FILE, 99, 10)
    truncated = hdr + b"abc"
    with pytest.raises(ReadWireError):
        decode_read_request(truncated)
    assert len(truncated) < READ_REQ_HEADER_LEN + 10


def test_encode_decode_read_response_roundtrip_ok():
    buf = bytearray(4096)
    view = encode_read_response_into(
        buf, status=READ_STATUS_OK, req_id=123, data=b"hello world")
    resp = decode_read_response(bytes(view))
    assert resp.status == READ_STATUS_OK
    assert resp.req_id == 123
    assert resp.data == b"hello world"


def test_encode_read_response_rejects_too_small_buffer():
    buf = bytearray(10)
    with pytest.raises(OverflowError):
        encode_read_response_into(
            buf, status=READ_STATUS_OK,
            req_id=1, data=b"not going to fit")


def test_line_count_8byte_encoding_roundtrip():
    # Representative sizes: 0, 1, typical /proc/net/route, full BGP.
    for n in (0, 1, 42, 900_000, 2**50):
        assert decode_line_count(encode_line_count(n)) == n


def test_decode_line_count_short_input_returns_zero():
    assert decode_line_count(b"") == 0
    assert decode_line_count(b"abc") == 0  # <8 bytes → 0


# ── _handle_read against real files ──────────────────────────────────


def test_handle_read_file_returns_bytes(tmp_path: Path):
    p = tmp_path / "snmp"
    p.write_bytes(b"Ip: 1 2 3\n")
    status, data = _handle_read(READ_KIND_FILE, str(p))
    assert status == READ_STATUS_OK
    assert data == b"Ip: 1 2 3\n"


def test_handle_read_file_not_found(tmp_path: Path):
    status, data = _handle_read(
        READ_KIND_FILE, str(tmp_path / "missing"))
    assert status == READ_STATUS_NOT_FOUND
    assert data == b""


def test_handle_read_file_too_large(tmp_path: Path):
    p = tmp_path / "big"
    p.write_bytes(b"x" * (MAX_FILE_BYTES + 10))
    status, data = _handle_read(READ_KIND_FILE, str(p))
    assert status == READ_STATUS_TOO_LARGE
    # Error string is a human-readable hint.
    assert b"count_lines" in data


def test_handle_read_count_lines(tmp_path: Path):
    p = tmp_path / "route"
    p.write_bytes(b"header\nrow1\nrow2\nrow3\n")
    status, data = _handle_read(READ_KIND_COUNT_LINES, str(p))
    assert status == READ_STATUS_OK
    assert decode_line_count(data) == 4


def test_handle_read_count_lines_empty_file(tmp_path: Path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    status, data = _handle_read(READ_KIND_COUNT_LINES, str(p))
    assert status == READ_STATUS_OK
    assert decode_line_count(data) == 0


def test_handle_read_unknown_kind():
    status, data = _handle_read(9999, "/tmp/x")
    assert status == READ_STATUS_ERROR
    assert b"unknown read kind" in data


# ── ParentWorker end-to-end via inproc_worker_pair ───────────────────


@pytest.fixture
def event_loop():
    """Per-test event loop so ``run_until_complete`` is safe."""
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


def test_parent_worker_read_file_through_inproc_pair(
    tmp_path: Path, event_loop: asyncio.AbstractEventLoop,
):
    """Send a real SEQPACKET read-RPC via the inproc worker pair and
    verify the ParentWorker.read_file coroutine resolves with the
    file content.
    """
    from shorewalld.worker_router import inproc_worker_pair

    snmp_file = tmp_path / "snmp"
    snmp_file.write_bytes(b"Ip: 1 2 3\n")

    pw, _worker_t = inproc_worker_pair(
        tracker=None,
        loop=event_loop,
        set_name_lookup=lambda _k: None,
    )
    try:
        async def _drive() -> bytes | None:
            return await pw.read_file(str(snmp_file))
        data = event_loop.run_until_complete(_drive())
    finally:
        event_loop.run_until_complete(pw.shutdown())

    assert data == b"Ip: 1 2 3\n"


def test_parent_worker_count_lines_through_inproc_pair(
    tmp_path: Path, event_loop: asyncio.AbstractEventLoop,
):
    """The count_lines path must return an integer (not bytes) and
    survive a large payload — exercised via the inproc SEQPACKET pair.
    """
    from shorewalld.worker_router import inproc_worker_pair

    p = tmp_path / "route"
    p.write_bytes(b"header\n" + b"row\n" * 10_000)

    pw, _worker_t = inproc_worker_pair(
        tracker=None,
        loop=event_loop,
        set_name_lookup=lambda _k: None,
    )
    try:
        async def _drive() -> int | None:
            return await pw.count_lines(str(p))
        n = event_loop.run_until_complete(_drive())
    finally:
        event_loop.run_until_complete(pw.shutdown())

    assert n == 10_001


def test_parent_worker_read_file_returns_none_on_missing(
    tmp_path: Path, event_loop: asyncio.AbstractEventLoop,
):
    from shorewalld.worker_router import inproc_worker_pair

    pw, _worker_t = inproc_worker_pair(
        tracker=None,
        loop=event_loop,
        set_name_lookup=lambda _k: None,
    )
    try:
        async def _drive() -> bytes | None:
            return await pw.read_file(str(tmp_path / "nonexistent"))
        data = event_loop.run_until_complete(_drive())
    finally:
        event_loop.run_until_complete(pw.shutdown())

    assert data is None
