"""RFC 1035 DNS wire-format builders — pure, stdlib-only."""

from __future__ import annotations

import struct

_QTYPES: dict[str, int] = {
    "A": 1,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "ANY": 255,
}


def build_dns_question(
    qname: str,
    qtype: str = "A",
    transaction_id: int = 0x1234,
) -> bytes:
    """Build a full DNS query packet (header + question section) as wire
    bytes. qtype in {"A", "AAAA", "ANY", "TXT", "MX"}.

    Layout:
      - 12-byte header: id, flags=0x0100 (standard query, recursion
        desired), qdcount=1, ancount=0, nscount=0, arcount=0
      - Question section: QNAME (length-prefixed labels) + QTYPE + QCLASS
    """
    qtype_upper = qtype.upper()
    if qtype_upper not in _QTYPES:
        raise ValueError(
            f"unsupported qtype {qtype!r}; must be one of {sorted(_QTYPES)}"
        )
    qtype_val = _QTYPES[qtype_upper]

    # 12-byte header: id, flags, qdcount, ancount, nscount, arcount
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)

    # QNAME: length-prefixed labels, terminated with \x00
    qname_wire = b""
    for label in qname.split("."):
        if label:
            encoded = label.encode("ascii")
            qname_wire += struct.pack("!B", len(encoded)) + encoded
    qname_wire += b"\x00"

    # QTYPE + QCLASS=IN
    question = qname_wire + struct.pack("!HH", qtype_val, 1)

    return header + question


__all__ = ["build_dns_question"]
