"""Regression tests for runtime/monitor.py.

Verifies that trace_start() does NOT prepend "ip" / "netns" / "exec" to
the Popen argument list regardless of the netns parameter.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


from shorewall_nft.runtime.monitor import trace_start


def _make_mock_proc() -> MagicMock:
    proc = MagicMock()
    proc.wait.return_value = 0
    return proc


class TestTraceStartArgv:
    """Popen must be called with only ['nft', 'monitor', 'trace']."""

    def test_no_netns_argv(self):
        captured: list[list[str]] = []

        def _mock_popen(args, **kwargs):
            captured.append(list(args))
            return _make_mock_proc()

        with patch("shorewall_nft.runtime.monitor.subprocess.Popen", side_effect=_mock_popen):
            with patch("shorewall_nft.runtime.monitor._in_netns") as mock_ctx:
                mock_ctx.return_value.__enter__ = lambda s: None
                mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
                trace_start(netns=None)

        assert captured == [["nft", "monitor", "trace"]]

    def test_no_ip_netns_exec_in_argv(self):
        """Even with netns set, argv must not contain 'ip', 'netns', 'exec'."""
        captured: list[list[str]] = []

        def _mock_popen(args, **kwargs):
            captured.append(list(args))
            return _make_mock_proc()

        with patch("shorewall_nft.runtime.monitor.subprocess.Popen", side_effect=_mock_popen):
            with patch("shorewall_nft.runtime.monitor._in_netns") as mock_ctx:
                mock_ctx.return_value.__enter__ = lambda s: None
                mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
                trace_start(netns="testns")

        assert len(captured) == 1
        argv = captured[0]
        assert "ip" not in argv
        assert "netns" not in argv
        assert "exec" not in argv
        assert argv == ["nft", "monitor", "trace"]

    def test_keyboard_interrupt_terminates_proc(self):
        mock_proc = _make_mock_proc()
        mock_proc.wait.side_effect = KeyboardInterrupt

        with patch("shorewall_nft.runtime.monitor.subprocess.Popen", return_value=mock_proc):
            with patch("shorewall_nft.runtime.monitor._in_netns") as mock_ctx:
                mock_ctx.return_value.__enter__ = lambda s: None
                mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
                trace_start()  # should not raise

        mock_proc.terminate.assert_called_once()
