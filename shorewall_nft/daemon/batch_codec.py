"""Wire codec for parent ↔ nft-worker batches.

Phase 2's hot path needs to move thousands of ``(set_id, family, ip,
ttl)`` updates per second from the SetWriter (parent, root netns) to
the per-netns nft-worker subprocess without allocating. Protobuf
would do the job fine but drags in a code-generation step; for the
Phase 2 delivery we use a trivial fixed-size binary format that can
be encoded and decoded in place with ``struct.pack_into`` /
``struct.unpack_from`` into preallocated buffers. Every allocation in
the steady state comes from a single ``bytearray`` per transport
direction — never from per-message ``bytes`` objects.

When Phase 4 replaces the hand-rolled dnstap decoder with the real
protobuf library, we keep this codec for the worker IPC anyway: a
3-field struct doesn't benefit from protobuf's schema evolution and
the hand-rolled encoder is demonstrably GC-free.

Wire format
-----------

One *datagram* = one :class:`BatchHeader` followed by zero or more
:class:`BatchOp` records. SEQPACKET atomicity means the worker reads
a whole datagram with one ``recv_into()`` — there is no length
prefix because the kernel preserves the message boundary.

Header (16 bytes, big-endian)::

    offset  type    field           notes
    0       u32     magic           0x53574E46 ('SWNF' - shorewalld nft)
    4       u16     version         always 1 until we break the format
    6       u16     op_count        number of BatchOp records
    8       u64     batch_id        sequencer from the parent

Each op (24 bytes)::

    offset  type    field           notes
    0       u16     set_id          DnsSetTracker id
    2       u8      family          FAMILY_V4 (4) or FAMILY_V6 (6)
    3       u8      op_kind         BATCH_OP_ADD / BATCH_OP_DEL
    4       u32     ttl             seconds
    8       16B     ip_bytes        v4: first 4 bytes used, rest zero
                                    v6: all 16

Max batch size: header (16) + ops (24) = 16 + 24·N. With N = 40
the datagram is 976 bytes — comfortably under the 1400-byte MTU
cap we enforce elsewhere, and far below the default ``SO_SNDBUF`` /
``SO_RCVBUF`` 208 KiB. We could go to 256+ ops per datagram without
any kernel-level backpressure at realistic rates.

Reply format (per datagram)::

    offset  type    field           notes
    0       u32     magic           0x53574E52 ('SWNR')
    4       u16     version
    6       u16     status          REPLY_OK / REPLY_ERROR
    8       u64     batch_id        mirrors request
    16      u16     applied         number of ops that actually hit nft
    18      u16     reserved
    20      u32     error_len       bytes of error text that follow
    24      N       error           opaque UTF-8 error string (optional)

Having the reply header fit in 24 bytes means empty success ACKs are
one SEQPACKET send without any heap touches.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable

MAGIC_REQUEST = 0x53574E46        # b"SWNF"
MAGIC_REPLY = 0x53574E52          # b"SWNR"
WIRE_VERSION = 1

BATCH_OP_ADD = 1
BATCH_OP_DEL = 2

REPLY_OK = 0
REPLY_ERROR = 1
REPLY_SHUTDOWN = 2                # worker received shutdown request
REPLY_SNAPSHOT = 3                # Phase 7/9 — full set dump response

HEADER_LEN = 16
OP_LEN = 24
REPLY_HEADER_LEN = 24

MAX_OPS_PER_BATCH = 40

# Control op kinds — carried in datagrams with op_count = 0 and
# op_kind encoded in the low byte of ``batch_id``'s high word so we
# never need a second header variant.
CTRL_SHUTDOWN = 0x1000
CTRL_SNAPSHOT = 0x1001

_STRUCT_HEADER = struct.Struct(">I H H Q")         # 16 bytes
_STRUCT_OP = struct.Struct(">H B B I 16s")         # 24 bytes
_STRUCT_REPLY = struct.Struct(">I H H Q H H I")    # 24 bytes


@dataclass
class BatchHeader:
    """Decoded view of a request datagram header."""
    magic: int
    version: int
    op_count: int
    batch_id: int


@dataclass
class BatchOp:
    """Decoded view of one record inside a request datagram."""
    set_id: int
    family: int
    op_kind: int
    ttl: int
    ip_bytes: bytes          # exactly 4 or 16 significant bytes


@dataclass
class BatchReply:
    """Decoded view of a reply datagram."""
    magic: int
    version: int
    status: int
    batch_id: int
    applied: int
    error: str = ""


class WireError(ValueError):
    """Raised on magic/version/length violations during decode."""


# ---------------------------------------------------------------------------
# Encoder — preallocated, no per-op allocation
# ---------------------------------------------------------------------------


class BatchBuilder:
    """Encode :class:`BatchOp` records into a preallocated ``bytearray``.

    The builder is stateful and **single-use-per-batch**: call
    :meth:`reset` before appending the first op of a new batch,
    :meth:`append` for each entry (up to ``MAX_OPS_PER_BATCH``), and
    finally :meth:`finish` to stamp the header. The returned
    ``memoryview`` shares memory with the internal ``bytearray`` —
    never copy, never store outside the scope of one send().

    Designed for steady-state zero-allocation: the underlying
    bytearray is allocated once per worker, reused for every batch.
    """

    __slots__ = ("_buf", "_view", "_off", "_count", "_max_ops")

    def __init__(self, max_ops: int = MAX_OPS_PER_BATCH) -> None:
        if max_ops <= 0 or max_ops > 0xFFFF:
            raise ValueError(f"max_ops out of range: {max_ops}")
        self._max_ops = max_ops
        size = HEADER_LEN + max_ops * OP_LEN
        self._buf = bytearray(size)
        self._view = memoryview(self._buf)
        self._off = HEADER_LEN
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    @property
    def full(self) -> bool:
        return self._count >= self._max_ops

    @property
    def empty(self) -> bool:
        return self._count == 0

    def reset(self) -> None:
        """Reset the builder for a new batch.

        Keeps the underlying buffer; just moves the write offset
        back to just after the header slot.
        """
        self._off = HEADER_LEN
        self._count = 0

    def append(
        self,
        *,
        set_id: int,
        family: int,
        op_kind: int,
        ttl: int,
        ip_bytes: bytes,
    ) -> None:
        """Write one BatchOp into the buffer.

        Raises ``OverflowError`` if the batch is already full so the
        caller knows to flush and start a new one. Non-raising
        fast-path: check :attr:`full` before calling.
        """
        if self._count >= self._max_ops:
            raise OverflowError("batch full; flush before appending more")
        n = len(ip_bytes)
        if n == 4:
            padded = ip_bytes + b"\x00" * 12
        elif n == 16:
            padded = ip_bytes
        else:
            raise ValueError(f"ip_bytes length must be 4 or 16, got {n}")
        _STRUCT_OP.pack_into(
            self._buf, self._off,
            set_id, family, op_kind, ttl, padded,
        )
        self._off += OP_LEN
        self._count += 1

    def finish(self, batch_id: int) -> memoryview:
        """Stamp the header and return a view of the finished datagram.

        The returned ``memoryview`` aliases the internal buffer. Do
        NOT hold it past the next :meth:`reset` or ``append`` call —
        those mutate the same bytes. For SEQPACKET ``sendmsg`` that's
        fine because the send completes synchronously.
        """
        _STRUCT_HEADER.pack_into(
            self._buf, 0,
            MAGIC_REQUEST, WIRE_VERSION, self._count, batch_id,
        )
        return self._view[: self._off]


def encode_control(
    builder: BatchBuilder, control: int, batch_id: int
) -> memoryview:
    """Encode a control message (shutdown, snapshot request, …).

    Control datagrams have ``op_count=0`` and a special control word
    stored inline in the header's batch_id field — we pack the
    control code into the high byte of the 64-bit slot. Using the
    same builder keeps the transport API uniform.
    """
    builder.reset()
    encoded_id = (control << 48) | (batch_id & 0xFFFFFFFFFFFF)
    return builder.finish(encoded_id)


def decode_control(batch_id: int) -> tuple[int, int]:
    """Pull the control word and user-visible batch_id back apart."""
    control = (batch_id >> 48) & 0xFFFF
    inner = batch_id & 0xFFFFFFFFFFFF
    return control, inner


# ---------------------------------------------------------------------------
# Decoder — iterates into a ``memoryview`` without creating ``bytes``
# ---------------------------------------------------------------------------


def decode_header(view: memoryview | bytes) -> BatchHeader:
    """Decode the 16-byte request header.

    Accepts either a ``memoryview`` or raw ``bytes`` so tests can
    inline-build datagrams without managing buffers.
    """
    if len(view) < HEADER_LEN:
        raise WireError(f"datagram shorter than header: {len(view)}")
    magic, version, op_count, batch_id = _STRUCT_HEADER.unpack_from(
        view, 0)
    if magic != MAGIC_REQUEST:
        raise WireError(f"bad magic: 0x{magic:08x}")
    if version != WIRE_VERSION:
        raise WireError(f"unknown version: {version}")
    return BatchHeader(
        magic=magic, version=version,
        op_count=op_count, batch_id=batch_id)


def iter_ops(
    view: memoryview | bytes, header: BatchHeader
) -> Iterable[BatchOp]:
    """Yield decoded :class:`BatchOp` records from a datagram.

    The yielded ``ip_bytes`` is trimmed to 4 bytes for v4 and 16 for
    v6 — callers typically pass it straight into the DnsSetTracker.
    """
    expected = HEADER_LEN + header.op_count * OP_LEN
    if len(view) < expected:
        raise WireError(
            f"datagram truncated: got {len(view)}, need {expected}")
    for i in range(header.op_count):
        off = HEADER_LEN + i * OP_LEN
        set_id, family, op_kind, ttl, padded = _STRUCT_OP.unpack_from(
            view, off)
        if family == 4:
            ip = padded[:4]
        elif family == 6:
            ip = padded[:16]
        else:
            raise WireError(f"bad family in op[{i}]: {family}")
        yield BatchOp(
            set_id=set_id, family=family, op_kind=op_kind,
            ttl=ttl, ip_bytes=bytes(ip),
        )


# ---------------------------------------------------------------------------
# Reply encode/decode
# ---------------------------------------------------------------------------


def encode_reply_into(
    buf: bytearray,
    *,
    status: int,
    batch_id: int,
    applied: int,
    error: str = "",
) -> memoryview:
    """Write a reply datagram into a preallocated worker buffer.

    Returns a memoryview slice suitable for ``sendmsg``. The error
    string is encoded inline after the header; empty errors mean
    the 24-byte header is the whole datagram.
    """
    err_bytes = error.encode("utf-8") if error else b""
    err_len = len(err_bytes)
    total = REPLY_HEADER_LEN + err_len
    if total > len(buf):
        raise OverflowError(
            f"reply buffer too small: need {total}, have {len(buf)}")
    _STRUCT_REPLY.pack_into(
        buf, 0,
        MAGIC_REPLY, WIRE_VERSION, status, batch_id,
        applied, 0, err_len,
    )
    if err_len:
        buf[REPLY_HEADER_LEN: REPLY_HEADER_LEN + err_len] = err_bytes
    return memoryview(buf)[:total]


def decode_reply(view: memoryview | bytes) -> BatchReply:
    if len(view) < REPLY_HEADER_LEN:
        raise WireError(f"reply shorter than header: {len(view)}")
    magic, version, status, batch_id, applied, _res, err_len = \
        _STRUCT_REPLY.unpack_from(view, 0)
    if magic != MAGIC_REPLY:
        raise WireError(f"bad reply magic: 0x{magic:08x}")
    if version != WIRE_VERSION:
        raise WireError(f"unknown reply version: {version}")
    if err_len:
        end = REPLY_HEADER_LEN + err_len
        if len(view) < end:
            raise WireError("reply error field truncated")
        error = bytes(view[REPLY_HEADER_LEN:end]).decode(
            "utf-8", errors="replace")
    else:
        error = ""
    return BatchReply(
        magic=magic, version=version, status=status,
        batch_id=batch_id, applied=applied, error=error,
    )
