"""Unit tests for trafgen_iperf3: parse_result, build_argv, run_iperf3."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from shorewall_nft_stagelab.trafgen_iperf3 import (
    Iperf3Spec,
    build_argv,
    parse_result,
    run_iperf3,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parse_tcp_success() -> None:
    result = parse_result(_load("iperf3_tcp_success.json"))
    assert result.ok is True
    assert abs(result.throughput_gbps - 7.99) < 0.01
    assert result.retransmits == 42
    assert result.duration_s == 10.0


def test_parse_udp_success() -> None:
    result = parse_result(_load("iperf3_udp_success.json"))
    assert result.ok is True
    assert abs(result.throughput_gbps - 0.399) < 0.001
    assert result.retransmits == 0
    assert result.duration_s == 10.0


def test_parse_error_result() -> None:
    result = parse_result(_load("iperf3_error.json"))
    assert result.ok is False
    assert result.throughput_gbps == 0.0


def test_build_argv_tcp_client() -> None:
    spec = Iperf3Spec(
        mode="client",
        bind="10.0.0.2",
        server_ip="10.0.0.1",
        duration_s=30,
        parallel=8,
        proto="tcp",
        port=5201,
    )
    argv = build_argv(spec)
    assert "iperf3" in argv
    assert "--json" in argv
    assert "-c" in argv
    assert "10.0.0.1" in argv
    assert "-B" in argv
    assert "10.0.0.2" in argv
    assert "-t" in argv
    assert "30" in argv
    assert "-P" in argv
    assert "8" in argv
    # UDP flag must NOT appear for TCP
    assert "-u" not in argv


def test_run_iperf3_nonjson_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = subprocess.CompletedProcess(
        args=["iperf3"],
        returncode=1,
        stdout="garbage",
        stderr="boom",
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake)

    spec = Iperf3Spec(mode="client", bind="10.0.0.2", server_ip="10.0.0.1")
    with pytest.raises(RuntimeError, match="did not emit JSON"):
        run_iperf3(spec)


# ---------------------------------------------------------------------------
# Latency percentile tests (C1)
# ---------------------------------------------------------------------------


def test_parse_rtt_percentiles_populated() -> None:
    """iperf3 JSON with intervals[].streams[].rtt → percentiles computed correctly."""
    result = parse_result(_load("iperf3_tcp_with_rtt.json"), measure_latency=True)
    assert result.ok is True
    # All three percentiles must be present and non-negative.
    assert result.latency_p50_ms is not None
    assert result.latency_p95_ms is not None
    assert result.latency_p99_ms is not None
    assert result.latency_p50_ms > 0.0
    # Ordering invariant: p50 <= p95 <= p99.
    assert result.latency_p50_ms <= result.latency_p95_ms
    assert result.latency_p95_ms <= result.latency_p99_ms
    # The fixture has 12 RTT samples (max 1800 µs = 1.8 ms); p99 with exclusive
    # interpolation may extrapolate slightly above the max, so allow up to 3 ms.
    assert result.latency_p99_ms <= 3.0


def test_parse_rtt_no_samples() -> None:
    """iperf3 JSON without RTT samples → latency fields stay None."""
    # The standard TCP success fixture has no intervals.rtt fields.
    result = parse_result(_load("iperf3_tcp_success.json"), measure_latency=True)
    assert result.ok is True
    assert result.latency_p50_ms is None
    assert result.latency_p95_ms is None
    assert result.latency_p99_ms is None


def test_parse_rtt_empty_intervals() -> None:
    """Empty intervals list → percentiles None, no crash."""
    raw = {
        "end": {
            "sum_sent": {"bytes": 0, "bits_per_second": 0.0, "retransmits": 0, "seconds": 0.0},
            "sum_received": {"bytes": 0, "bits_per_second": 0.0, "seconds": 0.0},
        },
        "intervals": [],
    }
    result = parse_result(json.dumps(raw), measure_latency=True)
    assert result.ok is True
    assert result.latency_p50_ms is None
    assert result.latency_p95_ms is None
    assert result.latency_p99_ms is None


def test_parse_rtt_disabled_by_default() -> None:
    """measure_latency=False (default) → percentiles None even when RTT data present."""
    result = parse_result(_load("iperf3_tcp_with_rtt.json"))
    assert result.latency_p50_ms is None
    assert result.latency_p95_ms is None
    assert result.latency_p99_ms is None
