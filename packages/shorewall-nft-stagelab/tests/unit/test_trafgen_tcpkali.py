"""Unit tests for trafgen_tcpkali — no tcpkali binary required."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from shorewall_nft_stagelab.trafgen_tcpkali import (
    TcpkaliSpec,
    build_argv,
    parse_stdout,
    run_tcpkali,
)

_FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parse_fixture_success() -> None:
    """Fixture stdout parses to ok=True with correct connections/bandwidth/duration."""
    stdout = (_FIXTURES / "tcpkali_stdout.txt").read_text()
    r = parse_stdout(stdout)

    assert r.ok is True
    assert r.connections_established == 998
    assert r.connections_failed == 2
    assert abs(r.traffic_bits_per_sec - 235e6) < 1e4, (
        f"Expected ~235 Mbps, got {r.traffic_bits_per_sec}"
    )
    assert r.duration_s == pytest.approx(30.0, abs=0.1)
    assert r.tool == "tcpkali"


def test_parse_no_connections_line_not_ok() -> None:
    """stdout without a 'Connections:' line yields ok=False."""
    stdout = "Bandwidth: 10 Mbps ⇅ 10 Mbps\nTest duration: 5.0s.\n"
    r = parse_stdout(stdout)
    assert r.ok is False
    assert r.connections_established == 0
    assert r.connections_failed == 0
    assert r.traffic_bits_per_sec == 0.0


def test_build_argv_minimal() -> None:
    """Minimal spec builds argv with -c, -r, -T, and target."""
    spec = TcpkaliSpec(
        target="10.0.0.1:5001",
        connections=2000,
        connect_rate=500,
        duration_s=60,
    )
    argv = build_argv(spec)

    assert "-c" in argv
    assert "2000" in argv
    assert "-r" in argv
    assert "500" in argv
    assert "-T" in argv
    assert "60" in argv
    assert "10.0.0.1:5001" in argv

    # Verify relative ordering: flags before target
    assert argv.index("10.0.0.1:5001") == len(argv) - 1


def test_build_argv_with_bind() -> None:
    """bind='10.0.0.100' adds --source-ip flag."""
    spec = TcpkaliSpec(
        target="10.0.0.2:5001",
        bind="10.0.0.100",
    )
    argv = build_argv(spec)

    assert "--source-ip" in argv
    src_idx = argv.index("--source-ip")
    assert argv[src_idx + 1] == "10.0.0.100"


def test_run_tcpkali_nonzero_no_summary_raises() -> None:
    """rc=1 + empty stdout + non-empty stderr → RuntimeError with stderr text."""
    fake_proc = subprocess.CompletedProcess(
        args=["tcpkali"],
        returncode=1,
        stdout="",
        stderr="connect: Connection refused",
    )
    spec = TcpkaliSpec(target="127.0.0.1:9999")

    with patch("subprocess.run", return_value=fake_proc):
        with pytest.raises(RuntimeError, match="connect: Connection refused"):
            run_tcpkali(spec)
