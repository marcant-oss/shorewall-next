"""Unit tests for trex_daemon — all subprocess + socket calls mocked."""

from __future__ import annotations

import os
import signal
from pathlib import Path
from unittest.mock import MagicMock, patch

from shorewall_nft_stagelab import trex_daemon
from shorewall_nft_stagelab.trex_daemon import (
    TrexDaemonHandle,
    TrexDaemonSpec,
    ensure_running,
    is_running,
    recover_orphaned,
    stop,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _spec(**kwargs) -> TrexDaemonSpec:
    defaults = dict(
        mode="stl",
        port=4501,
        pci_ports=("0000:01:00.0", "0000:01:00.1"),
        cores=(4, 5),
        binary_path=Path("/opt/trex/v3.04/t-rex-64"),
    )
    defaults.update(kwargs)
    return TrexDaemonSpec(**defaults)


def _handle(tmp_path: Path, pid: int = 42) -> TrexDaemonHandle:
    cfg = tmp_path / "trex-stl-4501.yaml"
    cfg.write_text("# placeholder")
    return TrexDaemonHandle(
        mode="stl",
        port=4501,
        pid=pid,
        started_at_ts=1000.0,
        cfg_path=cfg,
    )


# ---------------------------------------------------------------------------
# Test 1 — ensure_running writes cfg and spawns process
# ---------------------------------------------------------------------------


def test_ensure_running_writes_cfg_and_spawns(tmp_path, monkeypatch):
    """ensure_running writes a cfg file and spawns the daemon, returning pid=42."""
    spec = _spec(binary_path=Path("/opt/trex/v3.04/t-rex-64"))
    cfg_path = tmp_path / f"trex-{spec.mode}-{spec.port}.yaml"

    # Redirect CFG_DIR so files land in tmp_path
    monkeypatch.setattr(trex_daemon, "CFG_DIR", tmp_path)

    # is_running: first False (before spawn), then True (after spawn)
    call_count = {"n": 0}

    def fake_is_running(port: int) -> bool:
        call_count["n"] += 1
        return call_count["n"] > 1

    monkeypatch.setattr(trex_daemon, "is_running", fake_is_running)

    # binary must "exist"
    monkeypatch.setattr(Path, "exists", lambda self: True)

    fake_proc = MagicMock()
    fake_proc.pid = 42

    with patch("subprocess.Popen", return_value=fake_proc) as mock_popen:
        handle = ensure_running(spec)

    assert handle.pid == 42
    assert handle.port == 4501
    assert handle.mode == "stl"

    # Cfg file should have been written
    written_cfg = tmp_path / f"trex-{spec.mode}-{spec.port}.yaml"
    assert written_cfg.exists()
    content = written_cfg.read_text()
    assert "0000:01:00.0" in content
    assert "4" in content  # core number

    # Popen called with --daemon
    args, kwargs = mock_popen.call_args
    argv = args[0]
    assert "--daemon" in argv
    assert "--cfg" in argv
    assert kwargs.get("start_new_session") is True


# ---------------------------------------------------------------------------
# Test 2 — stop sends SIGTERM then escalates to SIGKILL
# ---------------------------------------------------------------------------


def test_stop_sends_sigterm_then_sigkill(tmp_path, monkeypatch):
    """stop() sends SIGTERM; if process persists it escalates to SIGKILL."""
    handle = _handle(tmp_path, pid=9999)

    kill_calls: list[tuple[int, int]] = []

    def fake_kill(pid: int, sig: int) -> None:
        kill_calls.append((pid, sig))
        # pid 0 (probe) never raises — process stays alive

    monkeypatch.setattr(os, "kill", fake_kill)
    # Make time fast by monkeypatching time.monotonic to advance past deadline
    # We use a counter: first call returns 0, subsequent calls return increasing values
    mono_calls = {"n": 0}
    base = [0.0]

    def fake_monotonic() -> float:
        mono_calls["n"] += 1
        # After the 2nd call (deadline set), start returning values > deadline
        return base[0] + (mono_calls["n"] - 1) * 1.5

    monkeypatch.setattr(trex_daemon.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(trex_daemon.time, "sleep", lambda _: None)

    stop(handle)

    # First kill call must be SIGTERM
    assert kill_calls[0] == (9999, signal.SIGTERM)
    # Should eventually send SIGKILL
    sigkill_calls = [(pid, sig) for pid, sig in kill_calls if sig == signal.SIGKILL]
    assert len(sigkill_calls) >= 1
    assert sigkill_calls[0][0] == 9999

    # cfg file should be deleted
    assert not handle.cfg_path.exists()


# ---------------------------------------------------------------------------
# Test 3 — is_running probes TCP port
# ---------------------------------------------------------------------------


def test_is_running_probes_tcp(monkeypatch):
    """is_running returns True when connect succeeds, False on ConnectionRefusedError."""
    # First: simulate successful connect → True
    mock_sock_success = MagicMock()
    mock_sock_success.connect.return_value = None

    with patch("socket.socket", return_value=mock_sock_success):
        result = is_running(4501)

    assert result is True
    mock_sock_success.connect.assert_called_once_with(("127.0.0.1", 4501))

    # Second: simulate ConnectionRefusedError → False
    mock_sock_fail = MagicMock()
    mock_sock_fail.connect.side_effect = ConnectionRefusedError("refused")

    with patch("socket.socket", return_value=mock_sock_fail):
        result2 = is_running(4501)

    assert result2 is False


# ---------------------------------------------------------------------------
# Test 4 — recover_orphaned SIGTERMs pids from .pid files
# ---------------------------------------------------------------------------


def test_recover_orphaned_sigterms_found_pids(tmp_path, monkeypatch):
    """recover_orphaned reads .pid file, SIGTERMs the pid, removes cfg+pid files."""
    monkeypatch.setattr(trex_daemon, "CFG_DIR", tmp_path)

    cfg_file = tmp_path / "trex-stl-4501.yaml"
    cfg_file.write_text("# placeholder")
    pid_file = tmp_path / "trex-stl-4501.pid"
    pid_file.write_text("12345")

    kill_calls: list[tuple[int, int]] = []

    def fake_kill(pid: int, sig: int) -> None:
        kill_calls.append((pid, sig))

    monkeypatch.setattr(os, "kill", fake_kill)

    recovered = recover_orphaned(binary_path=Path("/opt/trex/v3.04/t-rex-64"))

    assert recovered == [12345]
    assert (12345, signal.SIGTERM) in kill_calls
    # Both files should be cleaned up
    assert not cfg_file.exists()
    assert not pid_file.exists()
