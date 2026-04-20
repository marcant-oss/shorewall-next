"""scapy-backed probe builder via netkit.packets for probe-mode packet injection.

Translates a ``ProbeSpec`` into a raw Ethernet frame using the builders in
``shorewall_nft_netkit.packets`` and writes the frame to a TAP fd or a raw
AF_PACKET socket.  No probing logic (waits, response correlation) lives here.
"""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass

from shorewall_nft_netkit import packets as netkit_packets


@dataclass(frozen=True)
class ProbeSpec:
    proto: str                         # "tcp" | "udp" | "icmp" | "icmpv6" | "vrrp" | ...
    src_ip: str                        # "10.0.10.100"
    dst_ip: str                        # "10.0.20.50"
    src_port: int = 0                  # 0 for non-L4
    dst_port: int = 0                  # 0 for non-L4
    family: str = "ipv4"               # "ipv4" | "ipv6"
    flags: str = ""                    # proto-specific — e.g. "S" for TCP SYN
    payload_len: int = 0
    vlan: int = 0                      # 0 = untagged
    src_mac: str = "02:00:00:00:00:01"
    dst_mac: str = "02:00:00:00:00:02"


def _family_int(spec: ProbeSpec) -> int:
    """Return 4 or 6 from spec.family string."""
    return 6 if spec.family == "ipv6" else 4


def build_frame(spec: ProbeSpec) -> bytes:
    """Dispatch to the right netkit.packets.build_* function.

    Mapping:
      ("tcp",    "ipv4") → packets.build_tcp(..., family=4)
      ("tcp",    "ipv6") → packets.build_tcp(..., family=6)
      ("udp",    "ipv4") → packets.build_udp(..., family=4)
      ("udp",    "ipv6") → packets.build_udp(..., family=6)
      ("icmp",   "ipv4") → packets.build_icmp(...)
      ("icmpv6", "ipv6") → packets.build_icmpv6(...)
      ("vrrp",   "ipv4") → packets.build_vrrp(...)
      ("esp",    *)      → packets.build_esp(..., family=4|6)
      ("ah",     *)      → packets.build_ah(..., family=4|6)
      ("gre",    *)      → packets.build_gre(..., family=4|6)
      (other,    *)      → packets.build_unknown_proto(...)

    Returns raw Ethernet frame bytes.
    Raises NotImplementedError for unsupported (proto, family) combinations.
    """
    proto = spec.proto.lower()
    fam = _family_int(spec)

    src_mac = spec.src_mac or None
    dst_mac = spec.dst_mac or None
    payload = b"\x00" * spec.payload_len if spec.payload_len else b""

    if proto == "tcp":
        flags = spec.flags if spec.flags else "S"
        return netkit_packets.build_tcp(
            spec.src_ip, spec.dst_ip, spec.dst_port,
            sport=spec.src_port or None,
            flags=flags,
            family=fam,
            payload=payload,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    if proto == "udp":
        return netkit_packets.build_udp(
            spec.src_ip, spec.dst_ip, spec.dst_port,
            sport=spec.src_port or None,
            family=fam,
            payload=payload or b"PING",
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    if proto == "icmp":
        if spec.family == "ipv6":
            raise NotImplementedError(
                "proto='icmp' with family='ipv6' is ambiguous; use proto='icmpv6'"
            )
        return netkit_packets.build_icmp(
            spec.src_ip, spec.dst_ip,
            payload=payload or b"simlab",
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    if proto == "icmpv6":
        if spec.family != "ipv6":
            raise NotImplementedError(
                "proto='icmpv6' requires family='ipv6'"
            )
        return netkit_packets.build_icmpv6(
            spec.src_ip, spec.dst_ip,
            payload=payload or b"simlab",
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    if proto == "vrrp":
        if spec.family == "ipv6":
            raise NotImplementedError("VRRP builder only supports IPv4")
        return netkit_packets.build_vrrp(
            spec.src_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    if proto == "esp":
        return netkit_packets.build_esp(
            spec.src_ip, spec.dst_ip,
            family=fam,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    if proto == "ah":
        return netkit_packets.build_ah(
            spec.src_ip, spec.dst_ip,
            family=fam,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    if proto == "gre":
        return netkit_packets.build_gre(
            spec.src_ip, spec.dst_ip,
            family=fam,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    # Generic fallback via build_unknown_proto (resolves name→proto-number)
    result = netkit_packets.build_unknown_proto(
        spec.src_ip, spec.dst_ip, proto,
        family=fam,
        src_mac=src_mac,
        dst_mac=dst_mac,
    )
    if result is None:
        raise NotImplementedError(
            f"No builder for proto={spec.proto!r}, family={spec.family!r}"
        )
    return result


def send_tap(fd: int, frame: bytes) -> int:
    """Write *frame* to an open TAP file descriptor.

    Returns the number of bytes written.  Raises ``OSError`` on failure.
    """
    return os.write(fd, frame)


def send_raw(iface: str, frame: bytes) -> int:
    """Send *frame* via AF_PACKET SOCK_RAW bound to *iface*.

    Returns the number of bytes sent.  Raises ``OSError`` on failure.
    """
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((iface, 0))
        return sock.send(frame)
