"""Scapy-based packet construction + classification helpers.

Centralises the protocol-specific code so the worker and controller
stay protocol-agnostic. Every ``build_*`` returns the raw ``bytes``
that can be written directly to a TAP (with Ethernet header) or TUN
(bare IP packet) file descriptor. Every ``parse_*`` takes raw bytes
off the fd and returns a lightweight summary dict for the trace
buffer and the observed-probe correlation.

Supported protocols:
    TCP, UDP, ICMP, ICMPv6, ARP, NDP (NS/NA/RS/RA), ESP, GRE

Scapy lazy-imports: the top-level import cost is ~100ms. We defer
the import to first call so ``simlab.packets`` is cheap to import
from modules that only need type/constant definitions.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

# Random ephemeral source port seed (reused across builds)
_eph_counter = 32768 + (os.getpid() & 0xffff) % 28000


def _next_sport() -> int:
    global _eph_counter
    _eph_counter = 32768 + ((_eph_counter - 32768 + 1) % 28000)
    return _eph_counter


# ── Lazy scapy import ────────────────────────────────────────────────

_scapy: Any = None


def _sc() -> Any:
    """Return the scapy.all module, loading on first call."""
    global _scapy
    if _scapy is None:
        import scapy.all as _m  # noqa: F401
        from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: F401
        from scapy.layers.inet6 import (  # noqa: F401
            ICMPv6EchoRequest,
            ICMPv6ND_NA,
            ICMPv6ND_NS,
            ICMPv6ND_RA,
            ICMPv6ND_RS,
            IPv6,
        )
        from scapy.layers.l2 import ARP, Ether  # noqa: F401
        _scapy = _m
    return _scapy


@dataclass
class PacketSummary:
    """Condensed description of a captured packet for correlation/trace."""
    family: int                 # 4 or 6, 0 for ARP/NDP
    proto: str                  # 'tcp' | 'udp' | 'icmp' | 'icmpv6'
                                # | 'arp' | 'ndp' | 'esp' | 'gre' | 'other'
    src: str | None = None      # source address (IP or MAC for ARP)
    dst: str | None = None      # destination address
    sport: int | None = None
    dport: int | None = None
    flags: str | None = None    # TCP flags like 'S', 'SA'
    arp_op: int | None = None   # ARP opcode (1=req, 2=reply)
    ndp_type: int | None = None # ICMPv6 NDP subtype (NS=135, NA=136, …)
    length: int = 0
    raw: bytes = b""            # original bytes (for re-injection/debug)
    # Probe-id stash: encoded into IPv4 ``id`` (16 bits) or IPv6 flow
    # label (20 bits). The controller uses this to correlate an
    # observed packet to the probe that sourced it without relying on
    # fragile src/dst/port matching.
    probe_id: int | None = None


# ── Builders (host → wire) ───────────────────────────────────────────


def _ipv4(src: str, dst: str, proto: int | None = None,
          probe_id: int | None = None) -> Any:
    """Build an IPv4 layer with optional probe_id stashed in the id field."""
    s = _sc()
    kwargs: dict[str, Any] = {"src": src, "dst": dst}
    if proto is not None:
        kwargs["proto"] = proto
    if probe_id is not None:
        kwargs["id"] = probe_id & 0xffff
    return s.IP(**kwargs)


def _ipv6(src: str, dst: str, nh: int | None = None,
          probe_id: int | None = None) -> Any:
    """Build an IPv6 layer with optional probe_id stashed in fl."""
    s = _sc()
    kwargs: dict[str, Any] = {"src": src, "dst": dst}
    if nh is not None:
        kwargs["nh"] = nh
    if probe_id is not None:
        kwargs["fl"] = probe_id & 0xfffff
    return s.IPv6(**kwargs)


def build_tcp(src_ip: str, dst_ip: str, dport: int, *,
              sport: int | None = None, flags: str = "S",
              family: int = 4, payload: bytes = b"",
              probe_id: int | None = None,
              src_mac: str | None = None, dst_mac: str | None = None,
              wrap_ether: bool = True) -> bytes:
    """Build a TCP probe packet (default SYN). Returns raw bytes."""
    s = _sc()
    sport = sport or _next_sport()
    ip = _ipv6(src_ip, dst_ip, probe_id=probe_id) if family == 6 \
        else _ipv4(src_ip, dst_ip, probe_id=probe_id)
    layer = ip / s.TCP(sport=sport, dport=dport, flags=flags) / payload
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_udp(src_ip: str, dst_ip: str, dport: int, *,
              sport: int | None = None, family: int = 4,
              payload: bytes = b"PING",
              probe_id: int | None = None,
              src_mac: str | None = None, dst_mac: str | None = None,
              wrap_ether: bool = True) -> bytes:
    s = _sc()
    sport = sport or _next_sport()
    ip = _ipv6(src_ip, dst_ip, probe_id=probe_id) if family == 6 \
        else _ipv4(src_ip, dst_ip, probe_id=probe_id)
    layer = ip / s.UDP(sport=sport, dport=dport) / payload
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_icmp(src_ip: str, dst_ip: str, *,
               type: int = 8, code: int = 0, family: int = 4,
               payload: bytes = b"simlab",
               probe_id: int | None = None,
               src_mac: str | None = None, dst_mac: str | None = None,
               wrap_ether: bool = True) -> bytes:
    """Build an ICMP echo request (v4)."""
    s = _sc()
    ip = _ipv4(src_ip, dst_ip, probe_id=probe_id)
    layer = ip / s.ICMP(type=type, code=code) / payload
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_icmpv6(src_ip: str, dst_ip: str, *,
                 type: int = 128, code: int = 0,
                 payload: bytes = b"simlab",
                 probe_id: int | None = None,
                 src_mac: str | None = None, dst_mac: str | None = None,
                 wrap_ether: bool = True) -> bytes:
    """Build an ICMPv6 echo request (type 128)."""
    s = _sc()
    ip = _ipv6(src_ip, dst_ip, probe_id=probe_id)
    if type == 128:
        layer = ip / s.ICMPv6EchoRequest(data=payload)
    else:
        from scapy.layers.inet6 import ICMPv6Unknown
        layer = ip / ICMPv6Unknown(type=type, code=code)
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_raw_ip(src_ip: str, dst_ip: str, proto: int, *,
                 family: int = 4, payload: bytes = b"",
                 probe_id: int | None = None,
                 src_mac: str | None = None, dst_mac: str | None = None,
                 wrap_ether: bool = True) -> bytes:
    """Catch-all for arbitrary IP protocols (SCTP, AH, PIM, …).

    When scapy has a dedicated layer for the protocol use the
    specific builder instead — this helper's only role is to
    exercise chains whose rule says ``-p <unknown number>``.
    """
    s = _sc()
    ip = (
        _ipv6(src_ip, dst_ip, nh=proto, probe_id=probe_id)
        if family == 6 else
        _ipv4(src_ip, dst_ip, proto=proto, probe_id=probe_id)
    )
    layer = ip / s.Raw(load=payload)
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_arp_request(src_mac: str, src_ip: str, dst_ip: str) -> bytes:
    """Build an ARP who-has request (L2, broadcast)."""
    s = _sc()
    frame = (
        s.Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        s.ARP(op=1, hwsrc=src_mac, psrc=src_ip, pdst=dst_ip)
    )
    return bytes(frame)


def build_arp_reply(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    """Build an ARP reply (L2)."""
    s = _sc()
    frame = (
        s.Ether(src=src_mac, dst=dst_mac) /
        s.ARP(op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
    )
    return bytes(frame)


def build_ndp_ns(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    """Build an IPv6 Neighbor Solicitation (NS) for ``target_ip``."""
    s = _sc()
    from scapy.layers.inet6 import ICMPv6NDOptSrcLLAddr
    # Solicited-node multicast for the target
    suffix = target_ip.split(":")[-1]
    solicited = f"ff02::1:ff00:{suffix}" if ":" in target_ip else "ff02::1"
    frame = (
        s.Ether(src=src_mac, dst="33:33:ff:00:00:01") /
        s.IPv6(src=src_ip, dst=solicited) /
        s.ICMPv6ND_NS(tgt=target_ip) /
        ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    )
    return bytes(frame)


def build_ndp_na(src_mac: str, src_ip: str,
                 dst_mac: str, dst_ip: str, target_ip: str) -> bytes:
    """Build an IPv6 Neighbor Advertisement (NA)."""
    s = _sc()
    from scapy.layers.inet6 import ICMPv6NDOptDstLLAddr
    frame = (
        s.Ether(src=src_mac, dst=dst_mac) /
        s.IPv6(src=src_ip, dst=dst_ip) /
        s.ICMPv6ND_NA(tgt=target_ip, R=0, S=1, O=1) /
        ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    )
    return bytes(frame)


def build_esp(src_ip: str, dst_ip: str, *, spi: int = 0x1000, seq: int = 1,
              family: int = 4, payload: bytes = b"\x00" * 16,
              src_mac: str | None = None, dst_mac: str | None = None,
              wrap_ether: bool = True) -> bytes:
    """Build an ESP packet (IP proto 50, bare)."""
    s = _sc()
    from scapy.layers.ipsec import ESP
    if family == 6:
        layer = s.IPv6(src=src_ip, dst=dst_ip, nh=50) / ESP(spi=spi, seq=seq, data=payload)
    else:
        layer = s.IP(src=src_ip, dst=dst_ip, proto=50) / ESP(spi=spi, seq=seq, data=payload)
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_gre(src_ip: str, dst_ip: str, *,
              inner: Any = None, family: int = 4,
              src_mac: str | None = None, dst_mac: str | None = None,
              wrap_ether: bool = True) -> bytes:
    """Build a GRE packet (IP proto 47), carrying the given inner payload."""
    s = _sc()
    from scapy.layers.inet import GRE
    gre = GRE()
    if inner is not None:
        gre = gre / inner
    if family == 6:
        layer = s.IPv6(src=src_ip, dst=dst_ip, nh=47) / gre
    else:
        layer = s.IP(src=src_ip, dst=dst_ip, proto=47) / gre
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_vrrp(src_ip: str, vrid: int = 1, prio: int = 100, *,
               vips: list[str] | None = None,
               src_mac: str | None = None, dst_mac: str | None = None,
               wrap_ether: bool = True) -> bytes:
    """Build a VRRPv2 advertisement (proto 112 → multicast 224.0.0.18)."""
    s = _sc()
    from scapy.layers.vrrp import VRRP
    vrrp = VRRP(version=2, type=1, vrid=vrid, priority=prio,
                addrlist=vips or [src_ip])
    layer = s.IP(src=src_ip, dst="224.0.0.18", proto=112, ttl=255) / vrrp
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_bgp_open(src_ip: str, dst_ip: str, *,
                   sport: int | None = None,
                   my_as: int = 65001, hold: int = 180,
                   bgp_id: str | None = None,
                   src_mac: str | None = None, dst_mac: str | None = None,
                   wrap_ether: bool = True) -> bytes:
    """Build a BGP OPEN on tcp/179 (session setup probe)."""
    s = _sc()
    try:
        from scapy.contrib.bgp import BGPHeader, BGPOpen
    except ImportError:
        # Fallback: just a TCP SYN to 179 so at least the rule is tested
        return build_tcp(src_ip, dst_ip, 179, sport=sport, flags="S",
                         src_mac=src_mac, dst_mac=dst_mac,
                         wrap_ether=wrap_ether)
    sport = sport or _next_sport()
    bgp = BGPHeader() / BGPOpen(my_as=my_as, hold_time=hold,
                                 bgp_id=bgp_id or src_ip)
    layer = s.IP(src=src_ip, dst=dst_ip) / s.TCP(
        sport=sport, dport=179, flags="PA") / bgp
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_ospf_hello(src_ip: str, area: str = "0.0.0.0",
                     router_id: str | None = None, *,
                     src_mac: str | None = None, dst_mac: str | None = None,
                     wrap_ether: bool = True) -> bytes:
    """Build an OSPFv2 HELLO (proto 89, multicast 224.0.0.5)."""
    s = _sc()
    try:
        from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
    except ImportError:
        return build_tcp(src_ip, "224.0.0.5", 0, flags="S",
                         src_mac=src_mac, dst_mac=dst_mac, wrap_ether=wrap_ether)
    ospf = OSPF_Hdr(version=2, type=1, src=router_id or src_ip, area=area) / \
           OSPF_Hello(mask="255.255.255.0", helloint=10, deadint=40,
                      router=router_id or src_ip)
    layer = s.IP(src=src_ip, dst="224.0.0.5", proto=89, ttl=1) / ospf
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_dns_query(src_ip: str, dst_ip: str, qname: str, *,
                    qtype: str = "A", sport: int | None = None,
                    src_mac: str | None = None, dst_mac: str | None = None,
                    wrap_ether: bool = True) -> bytes:
    """Build a DNS query (UDP/53) for a given name."""
    s = _sc()
    from scapy.layers.dns import DNS, DNSQR
    sport = sport or _next_sport()
    dns = DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    layer = s.IP(src=src_ip, dst=dst_ip) / s.UDP(sport=sport, dport=53) / dns
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


def build_dhcp_discover(src_mac: str, *,
                        dst_mac: str = "ff:ff:ff:ff:ff:ff",
                        xid: int = 0x12345678) -> bytes:
    """Build a DHCP DISCOVER broadcast (udp 67/68)."""
    s = _sc()
    from scapy.layers.dhcp import BOOTP, DHCP
    layer = (
        s.IP(src="0.0.0.0", dst="255.255.255.255") /
        s.UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(src_mac.replace(":", "")),
              xid=xid, flags=0x8000) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    frame = s.Ether(src=src_mac, dst=dst_mac) / layer
    return bytes(frame)


def build_radius(src_ip: str, dst_ip: str, *,
                 auth_port: int = 1812, sport: int | None = None,
                 code: int = 1,  # Access-Request
                 src_mac: str | None = None, dst_mac: str | None = None,
                 wrap_ether: bool = True) -> bytes:
    """Build a RADIUS Access-Request (udp/1812 or udp/1813)."""
    s = _sc()
    try:
        from scapy.layers.radius import Radius
        rad = Radius(code=code, id=1, authenticator=b"\x00" * 16)
    except ImportError:
        return build_udp(src_ip, dst_ip, auth_port, sport=sport,
                         payload=b"\x01\x01\x00\x14" + b"\x00" * 16,
                         src_mac=src_mac, dst_mac=dst_mac,
                         wrap_ether=wrap_ether)
    sport = sport or _next_sport()
    layer = s.IP(src=src_ip, dst=dst_ip) / s.UDP(sport=sport, dport=auth_port) / rad
    return _finalize(layer, src_mac, dst_mac, wrap_ether)


# ── pcap export helper ──────────────────────────────────────────────


def export_trace_pcap(
    trace: list[dict],
    raw_by_iface: dict[str, list[bytes]] | None,
    path: str,
) -> None:
    """Write a trace-buffer dump to a pcap file.

    ``raw_by_iface`` maps interface name → list of raw bytes (the
    worker's ring buffer). The trace list is used for metadata only.
    """
    s = _sc()
    from scapy.utils import wrpcap
    pkts: list = []
    if raw_by_iface:
        for iface, raws in raw_by_iface.items():
            for raw in raws:
                try:
                    pkts.append(s.Ether(raw))
                except Exception:
                    pass
    wrpcap(path, pkts)


def _finalize(layer: Any, src_mac: str | None, dst_mac: str | None,
              wrap_ether: bool) -> bytes:
    """Wrap an IP/IPv6 scapy layer in Ethernet and return raw bytes.

    If ``wrap_ether=False`` (TUN mode) return the bare IP packet.
    """
    s = _sc()
    if not wrap_ether:
        return bytes(layer)
    if not src_mac:
        src_mac = "02:00:00:00:00:01"
    if not dst_mac:
        dst_mac = "ff:ff:ff:ff:ff:ff"
    etype = 0x86dd if layer.__class__.__name__ == "IPv6" else 0x0800
    frame = s.Ether(src=src_mac, dst=dst_mac, type=etype) / layer
    return bytes(frame)


# ── Parser (wire → summary) ─────────────────────────────────────────


def parse(raw: bytes, *, is_tap: bool = True) -> PacketSummary:
    """Parse raw bytes from a TUN/TAP fd into a PacketSummary.

    Returns ``proto='other'`` if the packet doesn't match any known
    shape. Never raises on malformed input — always returns a summary.
    """
    s = _sc()
    summary = PacketSummary(family=0, proto="other",
                            length=len(raw), raw=raw)
    try:
        if is_tap:
            pkt = s.Ether(raw)
        else:
            first = raw[0] >> 4 if raw else 0
            if first == 6:
                pkt = s.IPv6(raw)
            else:
                pkt = s.IP(raw)
    except Exception:
        return summary

    # ARP (TAP only)
    if is_tap and pkt.haslayer(s.ARP):
        arp = pkt[s.ARP]
        summary.family = 0
        summary.proto = "arp"
        summary.src = arp.psrc
        summary.dst = arp.pdst
        summary.arp_op = int(arp.op)
        return summary

    # IPv4
    if pkt.haslayer(s.IP):
        ip = pkt[s.IP]
        summary.family = 4
        summary.src = ip.src
        summary.dst = ip.dst
        try:
            summary.probe_id = int(ip.id)
        except Exception:
            pass
        if pkt.haslayer(s.TCP):
            tcp = pkt[s.TCP]
            summary.proto = "tcp"
            summary.sport = int(tcp.sport)
            summary.dport = int(tcp.dport)
            summary.flags = str(tcp.flags)
        elif pkt.haslayer(s.UDP):
            udp = pkt[s.UDP]
            summary.proto = "udp"
            summary.sport = int(udp.sport)
            summary.dport = int(udp.dport)
        elif pkt.haslayer(s.ICMP):
            summary.proto = "icmp"
        elif ip.proto == 50:
            summary.proto = "esp"
        elif ip.proto == 47:
            summary.proto = "gre"
        return summary

    # IPv6
    try:
        from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, IPv6
        if pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            summary.family = 6
            summary.src = ip6.src
            summary.dst = ip6.dst
            try:
                summary.probe_id = int(ip6.fl)
            except Exception:
                pass
            if pkt.haslayer(ICMPv6ND_NS):
                summary.proto = "ndp"
                summary.ndp_type = 135
                return summary
            if pkt.haslayer(ICMPv6ND_NA):
                summary.proto = "ndp"
                summary.ndp_type = 136
                return summary
            if pkt.haslayer(s.TCP):
                tcp = pkt[s.TCP]
                summary.proto = "tcp"
                summary.sport = int(tcp.sport)
                summary.dport = int(tcp.dport)
                summary.flags = str(tcp.flags)
                return summary
            if pkt.haslayer(s.UDP):
                udp = pkt[s.UDP]
                summary.proto = "udp"
                summary.sport = int(udp.sport)
                summary.dport = int(udp.dport)
                return summary
            # ICMPv6 / ESP / GRE
            nh = ip6.nh
            if nh == 58:
                summary.proto = "icmpv6"
            elif nh == 50:
                summary.proto = "esp"
            elif nh == 47:
                summary.proto = "gre"
    except ImportError:
        pass
    return summary
