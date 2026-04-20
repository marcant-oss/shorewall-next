"""Unit tests for shorewall_nft_stagelab.advisor — exactly 9 tests."""

from __future__ import annotations

import time

from shorewall_nft_stagelab.advisor import (
    AdvisorInput,
    _h_conntrack_headroom,
    _h_conntrack_search_restart,
    _h_flat_parallel_scaling,
    _h_flowtable_stagnant,
    _h_rule_order_topN,
    _h_rx_no_buffer,
    _h_softirq_concentration,
    _h_tcp_retrans,
    analyze,
)
from shorewall_nft_stagelab.metrics import MetricRow


def _row(key: str, value: float, source: str = "test") -> MetricRow:
    return MetricRow(source=source, ts_unix=time.time(), key=key, value=value)


# ---------------------------------------------------------------------------
# 1. rx_no_buffer
# ---------------------------------------------------------------------------


def test_rx_no_buffer_triggers() -> None:
    data = AdvisorInput(
        metric_rows=(
            _row("rx_no_buffer_count", 42.0, source="thx1-eth0-ethtool"),
        )
    )
    rec = _h_rx_no_buffer(data)
    assert rec is not None
    assert rec.tier == "A"
    assert rec.signal == "rx_no_buffer"
    assert rec.target == "testhost"
    assert "42" in rec.rationale


# ---------------------------------------------------------------------------
# 2. softirq_concentration
# ---------------------------------------------------------------------------


def test_softirq_concentration_triggers() -> None:
    # CPU0 has 10× more NET_RX than CPUs 1-3
    rows = (
        _row("NET_RX", 100_000.0, source="softirq:cpu=0"),
        _row("NET_RX", 10_000.0,  source="softirq:cpu=1"),
        _row("NET_RX", 10_000.0,  source="softirq:cpu=2"),
        _row("NET_RX", 10_000.0,  source="softirq:cpu=3"),
    )
    data = AdvisorInput(metric_rows=rows)
    rec = _h_softirq_concentration(data)
    assert rec is not None
    assert rec.tier == "A"
    assert rec.signal == "softirq_concentration"
    assert rec.target == "testhost"
    assert "100000" in rec.rationale or "100,000" in rec.rationale or "1e5" in rec.rationale or "100000" in rec.rationale


# ---------------------------------------------------------------------------
# 3. conntrack_headroom
# ---------------------------------------------------------------------------


def test_conntrack_headroom_triggers() -> None:
    data = AdvisorInput(conntrack_count=820_000, conntrack_max=1_000_000)
    rec = _h_conntrack_headroom(data)
    assert rec is not None
    assert rec.tier == "B"
    assert rec.signal == "conntrack_headroom"
    assert rec.target == "fw"
    assert "820000" in rec.rationale
    assert "1000000" in rec.rationale


# ---------------------------------------------------------------------------
# 4. conntrack_search_restart
# ---------------------------------------------------------------------------


def test_search_restart_triggers() -> None:
    data = AdvisorInput(
        metric_rows=(_row("conntrack_search_restart", 42.0, source="conntrack"),)
    )
    rec = _h_conntrack_search_restart(data)
    assert rec is not None
    assert rec.tier == "B"
    assert rec.signal == "conntrack_search_restart"
    assert rec.confidence == "low"
    assert "42" in rec.rationale


# ---------------------------------------------------------------------------
# 5. tcp_retrans
# ---------------------------------------------------------------------------


def test_tcp_retrans_triggers() -> None:
    # retransmits=2000, well above 0.5% of 100k (threshold=500)
    data = AdvisorInput(iperf3_retransmits=2000, iperf3_throughput_gbps=8.0)
    rec = _h_tcp_retrans(data)
    assert rec is not None
    assert rec.tier == "A"
    assert rec.signal == "tcp_retrans"
    assert rec.target == "testhost"
    assert "2000" in rec.rationale


# ---------------------------------------------------------------------------
# 6. flat_parallel_scaling
# ---------------------------------------------------------------------------


def test_flat_parallel_scaling_triggers() -> None:
    # 8 streams, 2 Gbps total → 0.25 Gbps/stream, below 1.0 Gbps/stream
    data = AdvisorInput(iperf3_parallel=8, iperf3_throughput_gbps=2.0)
    rec = _h_flat_parallel_scaling(data)
    assert rec is not None
    assert rec.tier == "A"
    assert rec.signal == "flat_parallel_scaling"
    assert rec.target == "testhost"
    assert "8" in rec.rationale
    assert "2.00" in rec.rationale or "2.0" in rec.rationale


# ---------------------------------------------------------------------------
# 7. flowtable_stagnant
# ---------------------------------------------------------------------------


def test_flowtable_stagnant_triggers() -> None:
    data = AdvisorInput(
        metric_rows=(_row("flowtable_hits", 0.0, source="nft-counters-packets"),)
    )
    rec = _h_flowtable_stagnant(data)
    assert rec is not None
    assert rec.tier == "B"
    assert rec.signal == "flowtable_stagnant"
    assert rec.confidence == "low"
    assert "flowtable_hits" in rec.rationale


# ---------------------------------------------------------------------------
# 8. rule_order_topN
# ---------------------------------------------------------------------------


def test_rule_order_topN_triggers() -> None:
    # 12 entries; top-3 have 700 out of 800 total packets = 87.5%
    ranking: tuple[tuple[str, int], ...] = (
        ("hot_rule_a", 300),
        ("hot_rule_b", 250),
        ("hot_rule_c", 150),
        ("rule_d", 10),
        ("rule_e", 10),
        ("rule_f", 10),
        ("rule_g", 10),
        ("rule_h", 10),
        ("rule_i", 10),
        ("rule_j", 10),
        ("rule_k", 10),
        ("rule_l", 20),
    )
    data = AdvisorInput(nft_counter_ranking=ranking)
    rec = _h_rule_order_topN(data)
    assert rec is not None
    assert rec.tier == "C"
    assert rec.signal == "rule_order_topN"
    assert rec.target == "compiler"
    assert "hot_rule_a" in rec.rationale or "hot_rule_a" in rec.action


# ---------------------------------------------------------------------------
# 9. empty input produces no recommendations
# ---------------------------------------------------------------------------


def test_analyze_empty_input_returns_empty_list() -> None:
    result = analyze(AdvisorInput())
    assert result == []
