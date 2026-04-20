"""Unit tests for trafgen_iperf3: parse_result, build_argv, run_iperf3."""

from __future__ import annotations

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
