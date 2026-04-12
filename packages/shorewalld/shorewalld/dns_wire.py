"""Minimal DNS wire-format helpers for the two-pass filter.

dnspython is roughly 20-50 µs per ``from_wire()`` call — at 20 k fps
that alone is 40-100 % of a CPU core. In a typical deployment the
pdns_recursor answers for maybe 200-500 unique names that shorewalld
cares about, out of tens of thousands of total responses. Running
the full dnspython parse on every frame just to find out 95 %+ of
them aren't in the allowlist is straight up waste.

This module implements the cheap half of a two-pass filter:

1. Walk the DNS header to find where the question section starts.
2. Read exactly the QNAME (length-prefixed labels, terminated by
   0x00) into a bytes object.
3. Normalise to lower-case + strip trailing dot.
4. Return the canonical string so the caller can check it against
   the :class:`DnsSetTracker`-backed allowlist.

The walk never touches rdata, RR class, TTLs, or anything past the
question section — typically ~30 bytes for a normal qname. No
allocations beyond the returned string; the caller passes a
``memoryview`` that aliases the original frame buffer.

On malformed wire data (truncated, label-too-long, pointer-loop)
the function returns ``None``. Malformed frames should be dropped
by the caller — they are not a two-pass miss, they are a protocol
error (bumped into its own counter).
"""

from __future__ import annotations

# DNS header is fixed at 12 bytes:
#   ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
DNS_HEADER_LEN = 12
MAX_QNAME_LEN = 253          # RFC 1035
MAX_LABEL_LEN = 63


def extract_qname(
    buf: memoryview | bytes, offset: int = 0
) -> tuple[str, int] | None:
    """Read the QNAME from a DNS wire message.

    Returns ``(canonical_qname, offset_after_qname)`` on success,
    ``None`` on any parse error. ``offset`` is where the DNS header
    starts — for dnstap's ``response_message`` field the offset is
    0; for pcap captures that include framing it's non-zero.

    The returned ``offset_after_qname`` points at the QTYPE field
    (2 bytes) immediately after the terminating 0x00 label, so
    callers that want to verify the RR class or type can read on
    without re-walking.

    Why not use ``dnspython.name.from_wire``? It allocates a
    ``dns.name.Name`` object with per-label lists, builds a
    labelled tuple, and runs IDN escaping. We want bytes in,
    canonical str out, zero allocations beyond the result.
    """
    total = len(buf)
    if offset + DNS_HEADER_LEN > total:
        return None
    # Question count must be at least 1 — reject answers with an
    # empty question section, that's not a useful frame for us.
    qdcount = (buf[offset + 4] << 8) | buf[offset + 5]
    if qdcount < 1:
        return None

    pos = offset + DNS_HEADER_LEN
    labels: list[bytes] = []
    total_len = 0
    # Safety cap on label walk to prevent pointer loops — question
    # section must not contain compression pointers per RFC 1035.
    for _ in range(64):
        if pos >= total:
            return None
        length = buf[pos]
        pos += 1
        if length == 0:
            # End of name. Build canonical form and return.
            if not labels:
                return None
            joined = b".".join(labels).decode("ascii", errors="replace")
            return (joined.lower(), pos)
        if length & 0xC0:
            # Compression pointer — illegal in question section.
            return None
        if length > MAX_LABEL_LEN:
            return None
        if pos + length > total:
            return None
        if total_len + length + 1 > MAX_QNAME_LEN:
            return None
        labels.append(bytes(buf[pos:pos + length]))
        total_len += length + 1
        pos += length
    # Exceeded label-walk cap without terminator.
    return None


def extract_rcode(buf: memoryview | bytes, offset: int = 0) -> int | None:
    """Return the RCODE from a DNS wire header.

    RCODE lives in the low 4 bits of the FLAGS field's second byte
    (byte offset 3). No allocation, no parse.
    """
    if offset + 4 > len(buf):
        return None
    return buf[offset + 3] & 0x0F


def is_response(buf: memoryview | bytes, offset: int = 0) -> bool:
    """True if the QR bit in the header is set (byte 2, high bit).

    Used by the dnstap filter to verify we're looking at a response
    message (CLIENT_RESPONSE), not a query echoed through by the
    recursor configuration. The dnstap message type field is the
    authoritative source; this is a belt-and-suspenders check.
    """
    if offset + 3 > len(buf):
        return False
    return bool(buf[offset + 2] & 0x80)
