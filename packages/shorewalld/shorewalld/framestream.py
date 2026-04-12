"""Minimal FrameStream (fstrm) reader for dnstap consumers.

FrameStream is the transport protocol dnstap uses on top of a
unix-domain or TCP socket. It has two framing rules:

* **Data frame** — 4-byte big-endian length ``L > 0`` followed by ``L``
  bytes of payload (for us: one serialised dnstap protobuf message).
* **Control frame** — 4-byte length ``0`` followed by a 4-byte length
  ``C > 0`` followed by ``C`` bytes of control data. Control data is
  a 4-byte control-type tag + TLV fields.

This module implements only what a **reader** needs: the bidirectional
handshake (READY from writer, ACCEPT from us, START from writer, data
frames, STOP from writer, FINISH from us) and a frame iterator.

Reference:
  https://farsightsec.github.io/fstrm/framestream.html
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

# Control-type constants (from fstrm/control.h).
CONTROL_ACCEPT = 0x01
CONTROL_START = 0x02
CONTROL_STOP = 0x03
CONTROL_READY = 0x04
CONTROL_FINISH = 0x05

# Control-field constants.
FIELD_CONTENT_TYPE = 0x01

# The content-type we accept.
DNSTAP_CONTENT_TYPE = b"protobuf:dnstap.Dnstap"


class FrameStreamError(Exception):
    """Protocol violation on the framestream wire."""


@dataclass
class ControlFrame:
    ctype: int
    content_types: list[bytes]


def encode_control(ctype: int,
                   content_types: list[bytes] | None = None) -> bytes:
    """Serialise a control frame: [0][len][type][TLVs…]."""
    body = struct.pack(">I", ctype)
    for ct in content_types or []:
        body += struct.pack(">II", FIELD_CONTENT_TYPE, len(ct)) + ct
    return struct.pack(">II", 0, len(body)) + body


def decode_control(body: bytes) -> ControlFrame:
    """Parse a control-frame body (without the outer length prefix)."""
    if len(body) < 4:
        raise FrameStreamError("control frame shorter than 4 bytes")
    (ctype,) = struct.unpack(">I", body[:4])
    i = 4
    content_types: list[bytes] = []
    while i + 8 <= len(body):
        field_type, field_len = struct.unpack(">II", body[i:i + 8])
        i += 8
        if i + field_len > len(body):
            raise FrameStreamError(
                f"control TLV length {field_len} exceeds body")
        value = body[i:i + field_len]
        i += field_len
        if field_type == FIELD_CONTENT_TYPE:
            content_types.append(value)
    return ControlFrame(ctype=ctype, content_types=content_types)


async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    """Read exactly ``n`` bytes or raise ``ConnectionError``."""
    buf = await reader.readexactly(n)
    return buf


async def read_frame(reader: asyncio.StreamReader) -> tuple[bool, bytes]:
    """Read one framestream frame.

    Returns ``(is_control, body)``. For control frames ``body`` is the
    raw control-data bytes (including the 4-byte control type header);
    parse it via ``decode_control``. For data frames ``body`` is the
    payload (one serialised protobuf message).

    Raises ``asyncio.IncompleteReadError`` when the peer closes.
    """
    length_bytes = await _read_exact(reader, 4)
    (length,) = struct.unpack(">I", length_bytes)
    if length == 0:
        ctrl_len_bytes = await _read_exact(reader, 4)
        (ctrl_len,) = struct.unpack(">I", ctrl_len_bytes)
        if ctrl_len == 0:
            raise FrameStreamError("zero-length control frame")
        body = await _read_exact(reader, ctrl_len)
        return True, body
    body = await _read_exact(reader, length)
    return False, body


async def accept_handshake(reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> None:
    """Run the reader side of the bidirectional fstrm handshake.

    Sequence:
      writer → READY [content-type: protobuf:dnstap.Dnstap]
      us     → ACCEPT [same content-type]
      writer → START [content-type]

    After START returns, the caller reads data frames until STOP
    arrives, then calls ``finish_handshake``.
    """
    is_control, body = await read_frame(reader)
    if not is_control:
        raise FrameStreamError(
            "expected READY control frame at handshake start")
    ready = decode_control(body)
    if ready.ctype != CONTROL_READY:
        raise FrameStreamError(
            f"expected READY, got control type 0x{ready.ctype:02x}")
    if DNSTAP_CONTENT_TYPE not in ready.content_types:
        raise FrameStreamError(
            f"READY lacks {DNSTAP_CONTENT_TYPE!r} in its content types")

    writer.write(encode_control(
        CONTROL_ACCEPT, [DNSTAP_CONTENT_TYPE]))
    await writer.drain()

    is_control, body = await read_frame(reader)
    if not is_control:
        raise FrameStreamError("expected START, got data frame")
    start = decode_control(body)
    if start.ctype != CONTROL_START:
        raise FrameStreamError(
            f"expected START, got control type 0x{start.ctype:02x}")


async def finish_handshake(writer: asyncio.StreamWriter) -> None:
    """Send FINISH after we received STOP and are closing the session."""
    writer.write(encode_control(CONTROL_FINISH))
    try:
        await writer.drain()
    except ConnectionError:
        pass
