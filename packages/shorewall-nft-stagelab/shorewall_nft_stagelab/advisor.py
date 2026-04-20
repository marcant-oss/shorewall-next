"""Rule-based advisor: ingests aggregated run metrics and emits tiered recommendations.

Each Recommendation carries a tier (A = auto-apply on testhost,
B = suggest for FW review, C = compiler hint), the triggering signal,
a concrete action, and a rationale string that embeds the observed value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .metrics import MetricRow

# ---------------------------------------------------------------------------
# Thresholds — tunable module-level constants
# ---------------------------------------------------------------------------

# rx_no_buffer: any non-zero value triggers
_RX_NO_BUFFER_MIN: float = 0.0

# softirq_concentration: max-per-cpu > N × median
_SOFTIRQ_CONCENTRATION_RATIO: float = 3.0

# conntrack_headroom: fill fraction above which we warn
_CONNTRACK_FILL_FRAC: float = 0.80

# tcp_retrans: retransmits / estimated_sent threshold (0.5 %)
_TCP_RETRANS_FRAC: float = 0.005
# heuristic divisor to estimate "sent" from retransmits alone (100 k packets)
_TCP_RETRANS_EST_SENT_DIVISOR: int = 100_000

# flat_parallel_scaling: below this Gbps-per-stream we flag the run
_FLAT_PARALLEL_GBPS_PER_STREAM: float = 1.0
# minimum parallel streams before the rule fires
_FLAT_PARALLEL_MIN_STREAMS: int = 4

# rule_order_topN: minimum ranking entries + top-3 fraction to flag
_RULE_ORDER_MIN_ENTRIES: int = 10
_RULE_ORDER_TOP3_FRAC: float = 0.70


# ---------------------------------------------------------------------------
# Data-transfer objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Recommendation:
    tier: Literal["A", "B", "C"]
    signal: str              # short id of the triggering signal
    action: str              # concrete one-liner command or procedural hint
    rationale: str           # why — includes observed value
    target: str              # "testhost" | "fw" | "compiler"
    confidence: Literal["low", "medium", "high"] = "medium"


@dataclass(frozen=True)
class AdvisorInput:
    """Aggregated signals from one stagelab run. All fields default to empty / zero."""

    metric_rows: tuple["MetricRow", ...] = field(default_factory=tuple)
    iperf3_throughput_gbps: float = 0.0
    iperf3_parallel: int = 1
    iperf3_retransmits: int = 0
    conntrack_count: int = 0
    conntrack_max: int = 0
    nft_counter_ranking: tuple[tuple[str, int], ...] = field(default_factory=tuple)
    # (counter_name, packets) sorted descending
    # DoS-scenario signals (populated by controller for kind.startswith("dos_")):
    dos_scenario_ran: bool = False
    dos_syn_pass_ratio: float = 0.0          # highest observed across syn_flood scenarios
    dns_resolve_latency_increase_ratio: float = 0.0
    # PowerDNS-recursor signal from SNMP NET-SNMP-EXTEND-MIB rows (S6).
    # Ratio of pdns QPS (or miss-rate proxy) during DoS window vs baseline.
    # Defaults to 0.0 so existing tests and non-SNMP runs are unaffected.
    # Populated by the controller's _aggregate_pdns_metrics helper when pdns
    # SNMP rows are present; left at 0.0 when no baseline/DoS windowing exists.
    pdns_qps_increase_ratio: float = 0.0


# ---------------------------------------------------------------------------
# Individual heuristics (exported for unit tests)
# ---------------------------------------------------------------------------


def _h_rx_no_buffer(data: AdvisorInput) -> Recommendation | None:
    """Trigger when any MetricRow with key="rx_no_buffer_count" has value > 0."""
    for row in data.metric_rows:
        if row.key == "rx_no_buffer_count" and row.value > _RX_NO_BUFFER_MIN:
            return Recommendation(
                tier="A",
                signal="rx_no_buffer",
                action=(
                    "ethtool -G <iface> rx 4096; "
                    "ethtool -L <iface> combined $(nproc)"
                ),
                rationale=(
                    f"rx_no_buffer_count={row.value:.0f} observed on source "
                    f"{row.source!r} — NIC ring is too small or RSS queues "
                    "are insufficient"
                ),
                target="testhost",
                confidence="high",
            )
    return None


def _h_softirq_concentration(data: AdvisorInput) -> Recommendation | None:
    """Trigger when max NET_RX softirq count per CPU > 3× the median across CPUs.

    Expects MetricRows with source like "softirq:cpu=N" and key="NET_RX".
    Falls back to source "softirq" if per-CPU rows are absent (no-op then).
    """
    per_cpu: list[float] = []
    for row in data.metric_rows:
        if row.key == "NET_RX" and "cpu=" in row.source:
            per_cpu.append(row.value)

    if len(per_cpu) < 2:
        return None

    sorted_vals = sorted(per_cpu)
    mid = len(sorted_vals) // 2
    if len(sorted_vals) % 2 == 0:
        median = (sorted_vals[mid - 1] + sorted_vals[mid]) / 2
    else:
        median = sorted_vals[mid]

    max_val = max(per_cpu)

    if median == 0:
        return None

    if max_val > _SOFTIRQ_CONCENTRATION_RATIO * median:
        return Recommendation(
            tier="A",
            signal="softirq_concentration",
            action=(
                "cat /proc/interrupts | grep -E 'eth|mlx|ixgbe' | "
                "awk '{print $1}' | xargs -I{} bash -c "
                "'echo N > /proc/irq/{}/smp_affinity_list'  "
                "# distribute IRQs across all cores; set-irq-affinity.sh preferred"
            ),
            rationale=(
                f"NET_RX softirqs: max_per_cpu={max_val:.0f} > "
                f"{_SOFTIRQ_CONCENTRATION_RATIO}× median={median:.0f} — "
                "IRQ affinity is not spread across cores"
            ),
            target="testhost",
            confidence="medium",
        )
    return None


def _h_conntrack_headroom(data: AdvisorInput) -> Recommendation | None:
    """Trigger when conntrack_count > 80% of conntrack_max."""
    if data.conntrack_max <= 0 or data.conntrack_count <= 0:
        return None

    frac = data.conntrack_count / data.conntrack_max
    if frac > _CONNTRACK_FILL_FRAC:
        pct = frac * 100.0
        return Recommendation(
            tier="B",
            signal="conntrack_headroom",
            action=(
                "sysctl -w net.netfilter.nf_conntrack_max=8388608; "
                "echo 'net.netfilter.nf_conntrack_max=8388608' "
                ">> /etc/sysctl.d/60-conntrack.conf"
            ),
            rationale=(
                f"conntrack_count={data.conntrack_count} / "
                f"conntrack_max={data.conntrack_max} "
                f"({pct:.1f}% — headroom below {(1 - _CONNTRACK_FILL_FRAC)*100:.0f}%)"
            ),
            target="fw",
            confidence="high",
        )
    return None


def _h_conntrack_search_restart(data: AdvisorInput) -> Recommendation | None:
    """Trigger when any MetricRow with key="conntrack_search_restart" has value > 0."""
    for row in data.metric_rows:
        if row.key == "conntrack_search_restart" and row.value > 0:
            return Recommendation(
                tier="B",
                signal="conntrack_search_restart",
                action=(
                    "sysctl -w net.netfilter.nf_conntrack_max=8388608; "
                    "echo 'net.netfilter.nf_conntrack_max=8388608' "
                    ">> /etc/sysctl.d/60-conntrack.conf"
                ),
                rationale=(
                    f"conntrack_search_restart={row.value:.0f} observed on "
                    f"source {row.source!r} — hash table is too small, causing "
                    "bucket chain restarts; raising nf_conntrack_max widens the table"
                ),
                target="fw",
                confidence="low",
            )
    return None


def _h_tcp_retrans(data: AdvisorInput) -> Recommendation | None:
    """Trigger when iperf3_retransmits > 0.5% of estimated sent packets.

    Estimated sent = retransmits / _TCP_RETRANS_FRAC gives a lower bound;
    equivalently we flag when retransmits > 0 at all with throughput > 0
    and the retransmit count exceeds the threshold ratio of 100k-packet units.
    """
    if data.iperf3_retransmits <= 0:
        return None
    if data.iperf3_throughput_gbps <= 0:
        return None

    # Heuristic: estimate sent_packets = throughput_gbps * 1e9 / (1500*8) * duration
    # Since we don't have duration, use a conservative estimate via the divisor constant.
    # Flag if retransmits > frac * est_sent where est_sent ~ retransmits / frac + 100k.
    # Simplified: flag if retransmits > _TCP_RETRANS_FRAC * _TCP_RETRANS_EST_SENT_DIVISOR
    threshold = _TCP_RETRANS_FRAC * _TCP_RETRANS_EST_SENT_DIVISOR
    if data.iperf3_retransmits > threshold:
        pct = (data.iperf3_retransmits / _TCP_RETRANS_EST_SENT_DIVISOR) * 100.0
        return Recommendation(
            tier="A",
            signal="tcp_retrans",
            action=(
                "sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216'; "
                "sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216'; "
                "ethtool -K <iface> tso on gso on gro on  "
                "# also verify TSO/GRO offloads are active"
            ),
            rationale=(
                f"iperf3_retransmits={data.iperf3_retransmits} at "
                f"{data.iperf3_throughput_gbps:.2f} Gbps "
                f"({pct:.2f}% of {_TCP_RETRANS_EST_SENT_DIVISOR:,} estimated "
                "packets — exceeds 0.5% retransmit rate threshold)"
            ),
            target="testhost",
            confidence="medium",
        )
    return None


def _h_flat_parallel_scaling(data: AdvisorInput) -> Recommendation | None:
    """Trigger when parallel >= 4 but throughput < 1 Gbps per stream."""
    if data.iperf3_parallel < _FLAT_PARALLEL_MIN_STREAMS:
        return None
    if data.iperf3_throughput_gbps <= 0:
        return None

    gbps_per_stream = data.iperf3_throughput_gbps / data.iperf3_parallel
    if gbps_per_stream < _FLAT_PARALLEL_GBPS_PER_STREAM:
        return Recommendation(
            tier="A",
            signal="flat_parallel_scaling",
            action=(
                "ethtool -N <iface> rx-flow-hash tcp4 sdfn; "
                "ethtool -N <iface> rx-flow-hash tcp6 sdfn  "
                "# ensure RSS hashes on src+dst IP+port to spread streams"
            ),
            rationale=(
                f"iperf3_parallel={data.iperf3_parallel} streams at "
                f"{data.iperf3_throughput_gbps:.2f} Gbps total = "
                f"{gbps_per_stream:.2f} Gbps/stream — below "
                f"{_FLAT_PARALLEL_GBPS_PER_STREAM:.1f} Gbps/stream threshold; "
                "RSS flow-hash likely not covering src/dst port tuple"
            ),
            target="testhost",
            confidence="medium",
        )
    return None


def _h_flowtable_stagnant(data: AdvisorInput) -> Recommendation | None:
    """Trigger when any row with key starting 'flowtable_' has value == 0."""
    for row in data.metric_rows:
        if row.key.startswith("flowtable_") and row.value == 0.0:
            return Recommendation(
                tier="B",
                signal="flowtable_stagnant",
                action=(
                    "nft list flowtables; "
                    "nft list table inet filter | grep -A5 flowtable; "
                    "# verify 'offload' flag and that flows are hitting the flowtable"
                ),
                rationale=(
                    f"flowtable metric {row.key!r}=0 on source {row.source!r} — "
                    "flowtable may be misconfigured, hw offload not active, "
                    "or traffic not matching flowtable rules"
                ),
                target="fw",
                confidence="low",
            )
    return None


def _h_dos_syn_pass_ratio(data: AdvisorInput) -> Recommendation | None:
    """Tier B — FW let too many SYNs through during dos_syn_flood."""
    if not data.dos_scenario_ran:
        return None
    if data.dos_syn_pass_ratio <= 0.05:
        return None
    return Recommendation(
        tier="B",
        signal="dos_syn_pass_ratio",
        action=(
            "Add `ct state new limit rate 1000/second` (or equivalent burst-"
            "limit) to the FW's forward/input chain for the source zone."
        ),
        rationale=(
            f"dos_syn_flood scenario let {data.dos_syn_pass_ratio:.1%} of SYNs "
            "through — FW rate-limiting is either absent or set too permissive."
        ),
        target="fw",
        confidence="medium",
    )


def _h_dos_conntrack_saturation(data: AdvisorInput) -> Recommendation | None:
    """Tier A (testhost-side) / B (FW-side) — conntrack saturation under DoS."""
    if not data.dos_scenario_ran:
        return None
    if data.conntrack_max == 0:
        return None
    ratio = data.conntrack_count / data.conntrack_max
    if ratio < 0.95:
        return None
    new_max = data.conntrack_max * 2
    return Recommendation(
        tier="B",
        signal="dos_conntrack_saturation",
        action=(
            f"Double nf_conntrack_max: `sysctl -w "
            f"net.netfilter.nf_conntrack_max={new_max}`. Also set "
            f"nf_conntrack_buckets={new_max // 4} for matching hash-table size."
        ),
        rationale=(
            f"conntrack_count={data.conntrack_count} "
            f"/ max={data.conntrack_max} ({ratio:.1%}) during a DoS scenario "
            "— flow-table is nearly exhausted."
        ),
        target="fw",
        confidence="high",
    )


_PDNS_QPS_INCREASE_RATIO_THRESHOLD: float = 10.0

# NOTE: This is a proxy calculation — real pdns windowing is deferred
# (pdns extend scripts not yet configured on the reference firewalls).
# See CLAUDE.md Open items; Task #11 covers windowing for conntrack_overflow
# and dos_syn_flood only.


def _h_dos_dns_latency_blowup(data: AdvisorInput) -> Recommendation | None:
    """Tier B — DNS resolver latency blew up during dos_dns_query.

    Fires when EITHER:
    - ``dns_resolve_latency_increase_ratio`` from shorewalld-derived timing
      exceeds 10× (original signal path — preserved for backward compat), OR
    - ``pdns_qps_increase_ratio`` from SNMP NET-SNMP-EXTEND-MIB pdns rows
      exceeds 10× (new S6 signal).
    """
    if not data.dos_scenario_ran:
        return None
    shorewalld_triggered = data.dns_resolve_latency_increase_ratio > 10.0
    pdns_triggered = data.pdns_qps_increase_ratio > _PDNS_QPS_INCREASE_RATIO_THRESHOLD
    if not shorewalld_triggered and not pdns_triggered:
        return None

    # Build a rationale that reflects whichever signal(s) fired.
    parts: list[str] = []
    if shorewalld_triggered:
        parts.append(
            f"dns_resolve latency increased "
            f"{data.dns_resolve_latency_increase_ratio:.1f}× (shorewalld signal)"
        )
    if pdns_triggered:
        parts.append(
            f"pdns QPS-increase ratio {data.pdns_qps_increase_ratio:.1f}× "
            f"(SNMP pdns-extend signal)"
        )
    rationale = "; ".join(parts) + " during dos_dns_query — resolver pipeline is a bottleneck."

    return Recommendation(
        tier="B",
        signal="dos_dns_latency_blowup",
        action=(
            "Increase shorewalld dns-resolver worker count (see "
            "`shorewalld.conf` → `[dns] workers = N`) and enable a caching "
            "tier in front of the upstream resolver to absorb query bursts."
        ),
        rationale=rationale,
        target="fw",
        confidence="medium",
    )


def _h_rule_order_topN(data: AdvisorInput) -> Recommendation | None:
    """Trigger when ranking has > 10 entries and top-3 account for > 70% of packets."""
    ranking = data.nft_counter_ranking
    if len(ranking) <= _RULE_ORDER_MIN_ENTRIES:
        return None

    total_packets = sum(pkts for _, pkts in ranking)
    if total_packets <= 0:
        return None

    top3_packets = sum(pkts for _, pkts in ranking[:3])
    frac = top3_packets / total_packets

    if frac > _RULE_ORDER_TOP3_FRAC:
        top3_names = ", ".join(name for name, _ in ranking[:3])
        pct = frac * 100.0
        return Recommendation(
            tier="C",
            signal="rule_order_topN",
            action=(
                "Reorder hot rules to the top of their chain in the shorewall-nft "
                "config so the nft compiler emits them before less-used rules. "
                f"Hot counters: {top3_names}"
            ),
            rationale=(
                f"top-3 counters ({top3_names}) account for "
                f"{top3_packets:,}/{total_packets:,} packets "
                f"({pct:.1f}% — above {_RULE_ORDER_TOP3_FRAC*100:.0f}% threshold) "
                f"across {len(ranking)} ranked counters"
            ),
            target="compiler",
            confidence="medium",
        )
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_HEURISTICS = [
    _h_rx_no_buffer,
    _h_softirq_concentration,
    _h_conntrack_headroom,
    _h_conntrack_search_restart,
    _h_tcp_retrans,
    _h_flat_parallel_scaling,
    _h_flowtable_stagnant,
    _h_rule_order_topN,
    _h_dos_syn_pass_ratio,
    _h_dos_conntrack_saturation,
    _h_dos_dns_latency_blowup,
]


def analyze(data: AdvisorInput) -> list[Recommendation]:
    """Run every heuristic against the input; return matching recommendations."""
    results: list[Recommendation] = []
    for heuristic in _HEURISTICS:
        rec = heuristic(data)
        if rec is not None:
            results.append(rec)
    return results


__all__ = [
    "Recommendation",
    "AdvisorInput",
    "analyze",
    "_h_rx_no_buffer",
    "_h_softirq_concentration",
    "_h_conntrack_headroom",
    "_h_conntrack_search_restart",
    "_h_tcp_retrans",
    "_h_flat_parallel_scaling",
    "_h_flowtable_stagnant",
    "_h_rule_order_topN",
    "_h_dos_syn_pass_ratio",
    "_h_dos_conntrack_saturation",
    "_h_dos_dns_latency_blowup",
]
