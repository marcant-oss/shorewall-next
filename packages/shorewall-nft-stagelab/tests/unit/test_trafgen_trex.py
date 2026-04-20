"""Unit tests for trafgen_trex — pure parsers and mocked client flows."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from shorewall_nft_stagelab.trafgen_trex import (
    TrexAstfSpec,
    TrexResult,
    TrexStatelessSpec,
    parse_astf_stats,
    parse_stl_stats,
    run_trex_astf,
    run_trex_stl,
)

# ---------------------------------------------------------------------------
# 1. parse_stl_stats — success path
# ---------------------------------------------------------------------------

def test_parse_stl_stats_success():
    stats = {
        "global": {
            "total_tx_bps": 10e9,
            "total_tx_pps": 1e6,
            "err_counters": {},
        }
    }
    result = parse_stl_stats(stats, duration_s=10.0)

    assert isinstance(result, TrexResult)
    assert result.tool == "trex-stl"
    assert result.ok is True
    assert result.throughput_gbps == pytest.approx(10.0, rel=1e-6)
    assert result.pps == pytest.approx(1e6, rel=1e-6)
    assert result.errors == 0
    assert result.concurrent_sessions == 0
    assert result.new_sessions_per_s == 0.0
    assert result.duration_s == 10.0
    assert result.raw is stats


# ---------------------------------------------------------------------------
# 2. parse_stl_stats — reports errors → ok=False
# ---------------------------------------------------------------------------

def test_parse_stl_stats_reports_errors_not_ok():
    stats = {
        "global": {
            "total_tx_bps": 8e9,
            "total_tx_pps": 800_000.0,
            "err_counters": {"port_0_tx_drop": 42, "port_1_tx_drop": 13},
        }
    }
    result = parse_stl_stats(stats, duration_s=10.0)

    assert result.ok is False
    assert result.errors == 55


# ---------------------------------------------------------------------------
# 3. parse_astf_stats — success path
# ---------------------------------------------------------------------------

def test_parse_astf_stats_success():
    stats = {
        "global": {
            "m_active_flows": 100_000,
            "m_est_flows_ps": 5_000.0,
            "m_tx_bps": 5e9,
            "m_tx_pps": 500_000.0,
            "m_tx_drop": 0,
            "m_rx_drop": 0,
        }
    }
    result = parse_astf_stats(stats, duration_s=30.0)

    assert result.tool == "trex-astf"
    assert result.ok is True
    assert result.concurrent_sessions == 100_000
    assert result.new_sessions_per_s == pytest.approx(5_000.0)
    assert result.throughput_gbps == pytest.approx(5.0, rel=1e-6)
    assert result.pps == pytest.approx(500_000.0)
    assert result.errors == 0
    assert result.duration_s == 30.0


# ---------------------------------------------------------------------------
# 4. parse_astf_stats — non-zero drops → ok=False
# ---------------------------------------------------------------------------

def test_parse_astf_stats_reports_drops():
    stats = {
        "global": {
            "m_active_flows": 50_000,
            "m_est_flows_ps": 2_000.0,
            "m_tx_bps": 2e9,
            "m_tx_pps": 200_000.0,
            "m_tx_drop": 7,
            "m_rx_drop": 3,
        }
    }
    result = parse_astf_stats(stats, duration_s=30.0)

    assert result.ok is False
    assert result.errors == 10


# ---------------------------------------------------------------------------
# 5. run_trex_stl — ImportError when TRex not installed
# ---------------------------------------------------------------------------

def test_run_stl_raises_importerror_when_trex_missing():
    spec = TrexStatelessSpec(ports=(0, 1), duration_s=5)

    with patch(
        "shorewall_nft_stagelab.trafgen_trex._import_stl",
        side_effect=ImportError("trex_stl_lib not found — stagelab bootstrap --role stagelab-agent-dpdk"),
    ):
        with pytest.raises(ImportError, match="stagelab bootstrap"):
            run_trex_stl(spec)


# ---------------------------------------------------------------------------
# 6. run_trex_stl — uses mocked STLClient; checks connect/start/stop order
# ---------------------------------------------------------------------------

def test_run_stl_uses_mocked_client():
    canned_stats = {
        "global": {
            "total_tx_bps": 10e9,
            "total_tx_pps": 1e6,
            "err_counters": {},
        }
    }

    fake_client = MagicMock()
    fake_client.get_stats.return_value = canned_stats

    fake_api = SimpleNamespace(
        STLClient=MagicMock(return_value=fake_client),
    )

    spec = TrexStatelessSpec(ports=(0, 1), duration_s=1)

    with patch("shorewall_nft_stagelab.trafgen_trex._import_stl", return_value=fake_api), \
         patch("shorewall_nft_stagelab.trafgen_trex.time.sleep"):
        result = run_trex_stl(spec)

    assert isinstance(result, TrexResult)
    assert result.tool == "trex-stl"
    assert result.throughput_gbps == pytest.approx(10.0, rel=1e-6)

    # Verify call order on the fake client
    call_names = [c[0] for c in fake_client.method_calls]
    assert "connect" in call_names
    assert "start" in call_names
    assert "stop" in call_names
    assert call_names.index("connect") < call_names.index("start")
    assert call_names.index("start") < call_names.index("stop")


# ---------------------------------------------------------------------------
# 6-new. run_trex_stl — profile_text takes priority over profile_py
# ---------------------------------------------------------------------------

def test_run_stl_prefers_profile_text_over_py():
    """When both profile_text and profile_py are set, profile_text wins."""
    canned_stats = {
        "global": {
            "total_tx_bps": 1e9,
            "total_tx_pps": 100_000.0,
            "err_counters": {},
        }
    }

    loaded_paths: list[str] = []

    fake_profile = MagicMock()
    fake_profile.get_streams.return_value = []

    fake_stl_profile = MagicMock()

    def capture_load(path):
        loaded_paths.append(path)
        return fake_profile

    fake_stl_profile.load.side_effect = capture_load

    fake_client = MagicMock()
    fake_client.get_stats.return_value = canned_stats

    fake_api = SimpleNamespace(
        STLClient=MagicMock(return_value=fake_client),
        STLProfile=fake_stl_profile,
    )

    spec = TrexStatelessSpec(
        ports=(0,),
        duration_s=1,
        profile_text="# test profile content",
        profile_py="/ignored/path.py",
    )

    with patch("shorewall_nft_stagelab.trafgen_trex._import_stl", return_value=fake_api), \
         patch("shorewall_nft_stagelab.trafgen_trex.time.sleep"):
        run_trex_stl(spec)

    assert len(loaded_paths) == 1
    loaded_path = loaded_paths[0]
    assert loaded_path != "/ignored/path.py"
    assert loaded_path.endswith(".py")
    # Temp file is cleaned up after run; verify profile was loaded from it
    fake_profile.get_streams.assert_called_once()


# ---------------------------------------------------------------------------
# 7. run_trex_astf — RuntimeError on RPC error
# ---------------------------------------------------------------------------

def test_run_astf_raises_runtimeerror_on_rpc_error():
    class TRexError(Exception):
        pass

    fake_client = MagicMock()
    fake_client.start.side_effect = TRexError("RPC timeout: no response from daemon")

    fake_api = SimpleNamespace(
        ASTFClient=MagicMock(return_value=fake_client),
        ASTFProfile=MagicMock(),
    )

    spec = TrexAstfSpec(profile_py="/tmp/fake_profile.py", duration_s=5)

    with patch("shorewall_nft_stagelab.trafgen_trex._import_astf", return_value=fake_api):
        with pytest.raises(RuntimeError, match="TRex ASTF error"):
            run_trex_astf(spec)
