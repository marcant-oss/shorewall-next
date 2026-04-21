"""Tests for the netns-fork migration in nft/netlink.py.

These tests run without root by monkeypatching run_in_netns_fork so
no real netns is needed.  They verify:

- _subprocess_text with netns uses run_in_netns_fork and returns JSON
- _subprocess_text raises NftError on rc != 0 from the child
- load_file with netns uses run_in_netns_fork and respects check_only
- run_in_netns fallback path (EPERM) calls run_in_netns_fork and
  reconstructs a CompletedProcess
- _libnftables_cmd_in_child helper is importable and has the right signature
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from shorewall_nft.nft.netlink import (
    NftError,
    NftInterface,
    _libnftables_cmd_in_child,
    _invoke_subprocess,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_JSON = json.dumps({"nftables": [{"metainfo": {"version": "1.0.0"}}]})


def _mock_fork_ok(netns: str, fn, *args, **kwargs):
    """Simulate a successful run_in_netns_fork call returning (0, JSON, '')."""
    return (0, _SAMPLE_JSON, "")


def _mock_fork_fail(netns: str, fn, *args, **kwargs):
    """Simulate a child that returns rc=1 with an error message."""
    return (1, "", "kernel said no")


def _mock_fork_load_ok(netns: str, fn, *args, **kwargs):
    """Simulate a successful load_file fork (rc=0)."""
    return (0, "", "")


def _mock_fork_load_check_only(netns: str, fn, script: str, *, check_only: bool = False, **kwargs):
    """Capture the check_only flag and return success."""
    _mock_fork_load_check_only.last_check_only = check_only
    return (0, "", "")


_mock_fork_load_check_only.last_check_only = None


def _mock_fork_subprocess(netns: str, fn, args: list, **kwargs):
    """Simulate _invoke_subprocess returning a successful result."""
    return (0, b"stdout bytes", b"")


# ---------------------------------------------------------------------------
# Tests: _subprocess_text
# ---------------------------------------------------------------------------


class TestSubprocessTextNetns:
    """_subprocess_text with netns= uses run_in_netns_fork."""

    def test_netns_branch_returns_json(self):
        nft = NftInterface()
        with patch(
            "shorewall_nft.nft.netlink.run_in_netns_fork", side_effect=_mock_fork_ok
        ):
            result = nft._subprocess_text("list ruleset", netns="testns")
        assert isinstance(result, dict)
        assert "nftables" in result

    def test_netns_branch_raises_nfterror_on_failure(self):
        nft = NftInterface()
        with patch(
            "shorewall_nft.nft.netlink.run_in_netns_fork", side_effect=_mock_fork_fail
        ):
            with pytest.raises(NftError, match="kernel said no"):
                nft._subprocess_text("bad command", netns="testns")

    def test_no_netns_does_not_call_fork(self):
        """Without netns, run_in_netns_fork must not be called."""
        nft = NftInterface()
        with patch("shorewall_nft.nft.netlink.run_in_netns_fork") as mock_fork:
            with patch("shorewall_nft.nft.netlink.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=_SAMPLE_JSON)
                nft._subprocess_text("list ruleset")
        mock_fork.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: load_file
# ---------------------------------------------------------------------------


class TestLoadFileNetns:
    """load_file with netns= uses run_in_netns_fork."""

    def test_netns_branch_success(self, tmp_path):
        script_file = tmp_path / "rules.nft"
        script_file.write_text("add table inet test")
        nft = NftInterface()
        nft._use_lib = False  # force the subprocess/fork path
        with patch(
            "shorewall_nft.nft.netlink.run_in_netns_fork",
            side_effect=_mock_fork_load_ok,
        ):
            # Should not raise
            nft.load_file(script_file, netns="testns")

    def test_netns_branch_raises_on_failure(self, tmp_path):
        script_file = tmp_path / "rules.nft"
        script_file.write_text("bad nft script")
        nft = NftInterface()
        nft._use_lib = False

        def _fail(netns, fn, *args, **kwargs):
            return (1, "", "syntax error at 'bad'")

        with patch("shorewall_nft.nft.netlink.run_in_netns_fork", side_effect=_fail):
            with pytest.raises(NftError, match="syntax error"):
                nft.load_file(script_file, netns="testns")

    def test_check_only_propagated_to_fork(self, tmp_path):
        """check_only=True must be forwarded as a kwarg to the child fn."""
        script_file = tmp_path / "rules.nft"
        script_file.write_text("add table inet test")
        nft = NftInterface()
        nft._use_lib = False

        captured_kwargs: dict = {}

        def _capture(netns, fn, *args, **kwargs):
            captured_kwargs.update(kwargs)
            return (0, "", "")

        with patch("shorewall_nft.nft.netlink.run_in_netns_fork", side_effect=_capture):
            nft.load_file(script_file, check_only=True, netns="testns")

        assert captured_kwargs.get("check_only") is True


# ---------------------------------------------------------------------------
# Tests: run_in_netns EPERM fallback
# ---------------------------------------------------------------------------


class TestRunInNetnsEpermFallback:
    """EPERM fallback calls run_in_netns_fork and returns CompletedProcess."""

    def test_eperm_triggers_fork_path(self):
        nft = NftInterface()

        def _raise_eperm(*args, **kwargs):
            raise OSError(1, "Operation not permitted")

        with patch("shorewall_nft.nft.netlink._in_netns") as mock_ctx:
            mock_ctx.return_value.__enter__ = _raise_eperm
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            with patch(
                "shorewall_nft.nft.netlink.run_in_netns_fork",
                side_effect=_mock_fork_subprocess,
            ):
                result = nft.run_in_netns(["nft", "list", "ruleset"], netns="testns",
                                          capture_output=True)
        assert result.returncode == 0

    def test_eperm_fallback_result_has_stdout(self):
        nft = NftInterface()

        def _raise(netns_name):
            class _CM:
                def __enter__(self):
                    raise OSError(1, "EPERM")
                def __exit__(self, *a):
                    return False
            return _CM()

        with patch("shorewall_nft.nft.netlink._in_netns", side_effect=_raise):
            with patch(
                "shorewall_nft.nft.netlink.run_in_netns_fork",
                side_effect=_mock_fork_subprocess,
            ):
                result = nft.run_in_netns(["nft", "list", "ruleset"], netns="testns",
                                          capture_output=True)

        assert isinstance(result, subprocess.CompletedProcess)
        assert result.stdout == b"stdout bytes"


# ---------------------------------------------------------------------------
# Tests: module-level helpers are pickleable
# ---------------------------------------------------------------------------


class TestHelpersPickleable:
    def test_libnftables_cmd_in_child_pickleable(self):
        import pickle
        # Should not raise
        pickle.dumps(_libnftables_cmd_in_child)

    def test_invoke_subprocess_pickleable(self):
        import pickle
        pickle.dumps(_invoke_subprocess)
