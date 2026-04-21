"""Performance-addendum TEST_ID fragment (latency percentiles, IPv6 throughput, conntrack overflow).

Merged into standards.TEST_ID by M1.
"""
from __future__ import annotations

TEST_ID_FRAGMENT: dict[str, tuple[str, str, str]] = {
    # IPv4 kernel-stack throughput (iperf3 / native endpoint)
    "perf-ipv4-tcp-throughput": (
        "performance-ipv4",
        "IPv4-TCP-SLO",
        "IPv4 TCP throughput — sustained iperf3 bandwidth meets SLO",
    ),
    "perf-ipv4-udp-throughput": (
        "performance-ipv4",
        "IPv4-UDP-SLO",
        "IPv4 UDP throughput — sustained iperf3 bandwidth meets SLO",
    ),
    # IPv6 kernel-stack throughput parity
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
    # DPDK / TRex line-rate tests
    "perf-dpdk-ipv4-line-rate-stl": (
        "performance-dpdk",
        "DPDK-IPv4-STL",
        "IPv4 TRex STL line-rate — sustained PPS meets SLO",
    ),
    "perf-dpdk-ipv6-line-rate-stl": (
        "performance-dpdk",
        "DPDK-IPv6-STL",
        "IPv6 TRex STL line-rate — sustained PPS meets SLO",
    ),
    "perf-dpdk-ipv4-astf-1m-sessions": (
        "performance-dpdk",
        "DPDK-ASTF-1M",
        "IPv4 TRex ASTF — 1 M concurrent TCP sessions without drop",
    ),
    # Conntrack observation under load
    "perf-conntrack-observe-throughput": (
        "performance-conntrack",
        "CONNTRACK-THROUGHPUT",
        "Conntrack table health under sustained throughput",
    ),
    "perf-conntrack-observe-conn-storm": (
        "performance-conntrack",
        "CONNTRACK-CONN-STORM",
        "Conntrack table health under high connection-rate storm",
    ),
}
