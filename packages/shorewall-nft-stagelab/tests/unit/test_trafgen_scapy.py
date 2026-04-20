"""Unit tests for trafgen_scapy — pure build_frame + mocked send_tap."""
from __future__ import annotations

import pytest

pytest.importorskip("scapy.all", reason="scapy not installed")

from shorewall_nft_stagelab.trafgen_scapy import ProbeSpec, build_frame, send_tap


def test_build_tcp_ipv4_frame() -> None:
    spec = ProbeSpec(
        proto="tcp",
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=22,
        family="ipv4",
        flags="S",
    )
    frame = build_frame(spec)
    assert isinstance(frame, bytes)
    # Ethernet(14) + IP(20) + TCP(20) = 54 minimum
    assert len(frame) > 40


def test_build_udp_ipv6_frame() -> None:
    spec = ProbeSpec(
        proto="udp",
        src_ip="2001:db8::1",
        dst_ip="2001:db8::2",
        src_port=12345,
        dst_port=53,
        family="ipv6",
    )
    frame = build_frame(spec)
    assert isinstance(frame, bytes)
    # Ethernet(14) + IPv6(40) + UDP(8) = 62 minimum
    assert len(frame) > 60


def test_build_unsupported_proto_raises() -> None:
    spec = ProbeSpec(
        proto="bogus",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        family="ipv4",
    )
    with pytest.raises(NotImplementedError):
        build_frame(spec)


def test_send_tap_calls_os_write(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple] = []

    def fake_write(fd: int, data: bytes) -> int:
        calls.append((fd, data))
        return len(data)

    monkeypatch.setattr("shorewall_nft_stagelab.trafgen_scapy.os.write", fake_write)
    result = send_tap(42, b"payload")
    assert result == 7
    assert calls == [(42, b"payload")]
