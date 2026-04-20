"""Performance-addendum TEST_ID fragment (latency percentiles, IPv6 throughput, conntrack overflow).

Merged into standards.TEST_ID by M1.
"""
from __future__ import annotations

TEST_ID_FRAGMENT: dict[str, tuple[str, str, str]] = {
    "perf-ipv6-tcp-throughput": (
        "performance-ipv6",
        "IPv6-TCP-SLO",
        "IPv6 TCP throughput parity with IPv4",
    ),
    "perf-ipv6-udp-throughput": (
        "performance-ipv6",
        "IPv6-UDP-SLO",
        "IPv6 UDP throughput parity with IPv4",
    ),
}
