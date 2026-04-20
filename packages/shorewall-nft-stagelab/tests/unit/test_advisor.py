"""Unit tests for shorewall_nft_stagelab.advisor."""

from __future__ import annotations

import time

from shorewall_nft_stagelab.advisor import (
    AdvisorInput,
    _h_conntrack_headroom,
    _h_conntrack_search_restart,
    _h_dos_dns_latency_blowup,
    _h_flat_parallel_scaling,
    _h_flowtable_stagnant,
    _h_rule_order_topN,
    _h_rx_no_buffer,
    _h_softirq_concentration,
    _h_tcp_retrans,
    analyze,
)
from shorewall_nft_stagelab.controller import _aggregate_pdns_metrics
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


# ---------------------------------------------------------------------------
# 10. dos_syn_pass_ratio
# ---------------------------------------------------------------------------


def test_dos_syn_pass_ratio_triggers():
    inp = AdvisorInput(dos_scenario_ran=True, dos_syn_pass_ratio=0.10)
    recs = analyze(inp)
    matched = [r for r in recs if r.signal == "dos_syn_pass_ratio"]
    assert len(matched) == 1
    assert matched[0].tier == "B"


# ---------------------------------------------------------------------------
# 11. dos_conntrack_saturation
# ---------------------------------------------------------------------------


def test_dos_conntrack_saturation_triggers():
    inp = AdvisorInput(
        dos_scenario_ran=True,
        conntrack_count=950_000,
        conntrack_max=1_000_000,
    )
    recs = analyze(inp)
    matched = [r for r in recs if r.signal == "dos_conntrack_saturation"]
    assert len(matched) == 1
    assert "2000000" in matched[0].action  # new_max = 2 ×


# ---------------------------------------------------------------------------
# 12. dos_dns_latency_blowup
# ---------------------------------------------------------------------------


def test_dos_dns_latency_blowup_triggers():
    inp = AdvisorInput(
        dos_scenario_ran=True,
        dns_resolve_latency_increase_ratio=50.0,
    )
    recs = analyze(inp)
    matched = [r for r in recs if r.signal == "dos_dns_latency_blowup"]
    assert len(matched) == 1
    assert matched[0].tier == "B"


# ---------------------------------------------------------------------------
# 13. _aggregate_pdns_metrics — row parsing
# ---------------------------------------------------------------------------

def _pdns_row(extend_name: str, value: float, ts: float, source_name: str = "elgar-snmp") -> MetricRow:
    """Build a fake SNMP pdns MetricRow with OID-encoded extend name in key."""
    # Encode extend_name as OID suffix: <len>.<b1>.<b2>...
    suffix = f"{len(extend_name)}." + ".".join(str(ord(c)) for c in extend_name)
    key = f"pdns_extend_output.{suffix}"
    return MetricRow(source=f"{source_name}:pdns", ts_unix=ts, key=key, value=value)


def test_aggregate_pdns_metrics_computes_correctly() -> None:
    """_aggregate_pdns_metrics returns correct qps/cache_hit_ratio/latency_approx."""
    t0 = 1_000_000.0
    t1 = t0 + 10.0  # 10-second window
    rows = [
        # all-queries: 0 → 500  (50 qps)
        _pdns_row("pdns-all-queries", 0.0, t0),
        _pdns_row("pdns-all-queries", 500.0, t1),
        # cache-hits: 0 → 400  (80% hit rate)
        _pdns_row("pdns-cache-hits", 0.0, t0),
        _pdns_row("pdns-cache-hits", 400.0, t1),
    ]
    result = _aggregate_pdns_metrics(rows)
    assert abs(result["pdns_qps"] - 50.0) < 0.1, result
    assert abs(result["pdns_cache_hit_ratio"] - 0.8) < 1e-6, result
    # latency_approx = 1 - 0.8 = 0.2
    assert abs(result["pdns_latency_approx"] - 0.2) < 1e-6, result


def test_aggregate_pdns_metrics_empty_returns_zeros() -> None:
    """No pdns rows → all zeros (no crash)."""
    result = _aggregate_pdns_metrics([])
    assert result == {"pdns_qps": 0.0, "pdns_cache_hit_ratio": 0.0, "pdns_latency_approx": 0.0}


# ---------------------------------------------------------------------------
# 14. _h_dos_dns_latency_blowup fires on high pdns_qps_increase_ratio
# ---------------------------------------------------------------------------


def test_dos_dns_latency_blowup_fires_on_high_pdns_ratio() -> None:
    """Heuristic fires when pdns_qps_increase_ratio > 10 (SNMP path)."""
    inp = AdvisorInput(dos_scenario_ran=True, pdns_qps_increase_ratio=12.0)
    rec = _h_dos_dns_latency_blowup(inp)
    assert rec is not None
    assert rec.tier == "B"
    assert rec.signal == "dos_dns_latency_blowup"
    assert "12.0" in rec.rationale


def test_dos_dns_latency_blowup_no_fire_on_low_pdns_ratio() -> None:
    """Heuristic does NOT fire when pdns_qps_increase_ratio <= 10 and no shorewalld signal."""
    inp = AdvisorInput(dos_scenario_ran=True, pdns_qps_increase_ratio=5.0)
    rec = _h_dos_dns_latency_blowup(inp)
    assert rec is None
