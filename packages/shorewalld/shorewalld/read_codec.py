"""Wire codec for parent → nft-worker file-read RPCs.

Parallel channel to :mod:`batch_codec`. While ``batch_codec`` carries
set-mutation batches from SetWriter to the nft-worker, ``read_codec``
carries per-netns ``/proc`` / ``/sys`` reads requested by the
Prometheus exporter collectors so that the scrape-thread never has to
``setns(2)`` — the worker is already pinned to the target netns and
can just ``open()`` the file for us.

Two message kinds:

* ``READ_KIND_FILE`` — read up to :data:`MAX_FILE_BYTES` bytes of a
  file, return raw bytes.
* ``READ_KIND_COUNT_LINES`` — stream-read a file and return its line
  count as a u64 (keeps transfer size O(20 bytes) regardless of file
  size, which matters for ``/proc/net/ipv6_route`` on BGP boxes).

Shares SEQPACKET transport + magic-based dispatch with ``batch_codec``:
the worker's main loop peeks the magic dword to route the datagram to
the right handler. Using distinct magics ("SWRR"/"SWRS") rather than
piggy-backing on the batch envelope keeps the decoder branch-free and
the wire format printable when snooped with ``strace``.

Wire format
-----------

Request (``MAGIC_READ_REQ``)::

    offset  size  field      notes
    0       4     magic      0x53575252 ('SWRR')
    4       2     version    WIRE_VERSION (shared with batch_codec)
    6       2     kind       READ_KIND_FILE=1, READ_KIND_COUNT_LINES=2
    8       8     req_id     parent-side sequencer
    16      2     path_len   number of UTF-8 bytes that follow
    18      N     path       UTF-8, N == path_len

Response (``MAGIC_READ_RESP``)::

    offset  size  field      notes
    0       4     magic      0x53575253 ('SWRS')
    4       2     version
    6       2     status     READ_STATUS_*
    8       8     req_id     mirrors request
    16      4     data_len   payload length in bytes
    20      N     data       see below

Response payload semantics (status==OK):

* ``READ_KIND_FILE`` — raw file bytes (caller decodes to str).
* ``READ_KIND_COUNT_LINES`` — exactly 8 bytes, big-endian u64, the
  file's line count.

For non-OK status the response carries an optional UTF-8 error string
in the data slot (no structured fields). ``NOT_FOUND`` means the path
couldn't be opened (ENOENT/EACCES); ``TOO_LARGE`` means the file
exceeded :data:`MAX_FILE_BYTES` (caller should use count_lines
instead); ``ERROR`` is everything else.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .batch_codec import WIRE_VERSION

MAGIC_READ_REQ = 0x53575252        # b"SWRR"
MAGIC_READ_RESP = 0x53575253       # b"SWRS"

READ_KIND_FILE = 1
READ_KIND_COUNT_LINES = 2

READ_STATUS_OK = 0
READ_STATUS_NOT_FOUND = 1
READ_STATUS_ERROR = 2
READ_STATUS_TOO_LARGE = 3

# Largest file payload we'll ship back over SEQPACKET. Keeps the
# response datagram under the worker's 64 KiB recv buffer even with
# the 20-byte header + safety margin. For files bigger than this
# (e.g. /proc/net/ipv6_route on a full-BGP box), callers use
# ``count_lines`` which returns an 8-byte integer regardless of size.
MAX_FILE_BYTES = 60_000

READ_REQ_HEADER_LEN = 18
READ_RESP_HEADER_LEN = 20

_STRUCT_READ_REQ = struct.Struct(">I H H Q H")      # 18 bytes
_STRUCT_READ_RESP = struct.Struct(">I H H Q I")     # 20 bytes


@dataclass
class ReadRequest:
    """Decoded view of a file-read request datagram."""
    magic: int
    version: int
    kind: int
    req_id: int
    path: str


@dataclass
class ReadResponse:
    """Decoded view of a file-read response datagram.

    ``data`` is a freshly allocated ``bytes`` object — detached from the
    transport's recv buffer so the caller can hold it past the next
    recv_into call.
    """
    magic: int
    version: int
    status: int
    req_id: int
    data: bytes


class ReadWireError(ValueError):
    """Raised on magic/version/length violations during decode."""


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def encode_read_request(
    *,
    kind: int,
    req_id: int,
    path: str,
) -> bytes:
    """Produce a read-request datagram.

    Returns a fresh ``bytes`` object — unlike :class:`BatchBuilder`,
    this path is not hot enough (< 1 request per scrape per file) to
    justify a preallocated buffer. A typical path is < 50 UTF-8 bytes,
    so the allocation is a few dozen bytes.
    """
    if kind not in (READ_KIND_FILE, READ_KIND_COUNT_LINES):
        raise ValueError(f"unknown read kind: {kind}")
    path_bytes = path.encode("utf-8")
    if len(path_bytes) > 0xFFFF:
        raise ValueError(f"path too long: {len(path_bytes)} bytes")
    out = bytearray(READ_REQ_HEADER_LEN + len(path_bytes))
    _STRUCT_READ_REQ.pack_into(
        out, 0,
        MAGIC_READ_REQ, WIRE_VERSION, kind, req_id, len(path_bytes),
    )
    out[READ_REQ_HEADER_LEN:] = path_bytes
    return bytes(out)


def encode_read_response_into(
    buf: bytearray,
    *,
    status: int,
    req_id: int,
    data: bytes,
) -> memoryview:
    """Serialise a read-response into a preallocated worker buffer.

    Returns a ``memoryview`` slice suitable for ``sendmsg``. Raises
    ``OverflowError`` if the buffer is too small — the worker sizes
    its reply buffer at :data:`MAX_FILE_BYTES` + header margin so
    this only triggers on a programming mistake.
    """
    total = READ_RESP_HEADER_LEN + len(data)
    if total > len(buf):
        raise OverflowError(
            f"reply buffer too small: need {total}, have {len(buf)}")
    _STRUCT_READ_RESP.pack_into(
        buf, 0,
        MAGIC_READ_RESP, WIRE_VERSION, status, req_id, len(data),
    )
    if data:
        buf[READ_RESP_HEADER_LEN:READ_RESP_HEADER_LEN + len(data)] = data
    return memoryview(buf)[:total]


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def peek_magic(view: memoryview | bytes) -> int:
    """Return the first 4 bytes of a datagram as a big-endian u32.

    Used by the worker main loop to dispatch between batch- and
    read-RPCs without fully parsing either header first.
    """
    if len(view) < 4:
        raise ReadWireError(f"datagram shorter than magic: {len(view)}")
    return struct.unpack_from(">I", view, 0)[0]


def decode_read_request(view: memoryview | bytes) -> ReadRequest:
    """Parse a ``MAGIC_READ_REQ`` datagram.

    Raises :class:`ReadWireError` on magic / version / truncation
    problems. Path is decoded to a ``str`` — the full datagram is
    small enough that the copy is harmless.
    """
    if len(view) < READ_REQ_HEADER_LEN:
        raise ReadWireError(
            f"read-req shorter than header: {len(view)}")
    magic, version, kind, req_id, path_len = \
        _STRUCT_READ_REQ.unpack_from(view, 0)
    if magic != MAGIC_READ_REQ:
        raise ReadWireError(f"bad read-req magic: 0x{magic:08x}")
    if version != WIRE_VERSION:
        raise ReadWireError(f"unknown read-req version: {version}")
    end = READ_REQ_HEADER_LEN + path_len
    if len(view) < end:
        raise ReadWireError(
            f"read-req path truncated: got {len(view)}, need {end}")
    path = bytes(view[READ_REQ_HEADER_LEN:end]).decode(
        "utf-8", errors="replace")
    return ReadRequest(
        magic=magic, version=version,
        kind=kind, req_id=req_id, path=path,
    )


def decode_read_response(view: memoryview | bytes) -> ReadResponse:
    """Parse a ``MAGIC_READ_RESP`` datagram.

    Copies the data payload into a fresh ``bytes`` so the caller may
    retain it past subsequent recv_into() calls (which reuse the
    same buffer).
    """
    if len(view) < READ_RESP_HEADER_LEN:
        raise ReadWireError(
            f"read-resp shorter than header: {len(view)}")
    magic, version, status, req_id, data_len = \
        _STRUCT_READ_RESP.unpack_from(view, 0)
    if magic != MAGIC_READ_RESP:
        raise ReadWireError(f"bad read-resp magic: 0x{magic:08x}")
    if version != WIRE_VERSION:
        raise ReadWireError(f"unknown read-resp version: {version}")
    end = READ_RESP_HEADER_LEN + data_len
    if len(view) < end:
        raise ReadWireError(
            f"read-resp data truncated: got {len(view)}, need {end}")
    data = bytes(view[READ_RESP_HEADER_LEN:end])
    return ReadResponse(
        magic=magic, version=version,
        status=status, req_id=req_id, data=data,
    )


def encode_line_count(n: int) -> bytes:
    """Encode a line-count result as 8 bytes big-endian."""
    return n.to_bytes(8, "big", signed=False)


def decode_line_count(data: bytes) -> int:
    """Inverse of :func:`encode_line_count`. Returns 0 on short input."""
    if len(data) < 8:
        return 0
    return int.from_bytes(data[:8], "big", signed=False)
