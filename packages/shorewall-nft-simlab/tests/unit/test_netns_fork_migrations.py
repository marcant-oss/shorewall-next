"""Unit tests for the netns-fork migrations in smoketest, controller, topology.

All tests monkeypatch run_in_netns_fork so no real netns or root is needed.
"""

from __future__ import annotations

import pickle
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# smoketest helpers
# ---------------------------------------------------------------------------


class TestSmoketestHelpers:
    """Module-level helpers in smoketest.py must be pickleable."""

    def test_write_file_in_child_pickleable(self):
        from shorewall_nft_simlab.smoketest import _write_file_in_child
        pickle.dumps(_write_file_in_child)

    def test_libnftables_list_flowtables_pickleable(self):
        from shorewall_nft_simlab.smoketest import _libnftables_list_flowtables_in_child
        pickle.dumps(_libnftables_list_flowtables_in_child)

    def test_libnftables_run_cmd_pickleable(self):
        from shorewall_nft_simlab.smoketest import _libnftables_run_cmd_in_child
        pickle.dumps(_libnftables_run_cmd_in_child)


class TestApplySysctlsNetns:
    """_apply_sysctls uses run_in_netns_fork for the netns path."""

    def test_calls_fork_not_subprocess(self):
        from shorewall_nft_simlab.smoketest import _apply_sysctls

        fork_calls: list = []

        def _mock_fork(ns, fn, *args, **kwargs):
            fork_calls.append((ns, args))

        with patch("shorewall_nft_simlab.smoketest.run_in_netns_fork", side_effect=_mock_fork):
            result = _apply_sysctls(ns_name="testns")

        # Should have made exactly 2 fork calls (ip_forward + ipv6 forwarding)
        assert len(fork_calls) == 2
        ns_names = {c[0] for c in fork_calls}
        assert ns_names == {"testns"}
        # Paths should be the forwarding sysctls
        paths = [c[1][0] for c in fork_calls]
        assert any("ip_forward" in p for p in paths)
        assert any("forwarding" in p for p in paths)

    def test_no_ns_name_no_fork(self):
        from shorewall_nft_simlab.smoketest import _apply_sysctls

        with patch("shorewall_nft_simlab.smoketest.run_in_netns_fork") as mock_fork:
            _apply_sysctls(ns_name=None)
        mock_fork.assert_not_called()

    def test_fork_failure_logged_not_raised(self):
        from shorewall_nft_netkit.netns_fork import NetnsForkError

        from shorewall_nft_simlab.smoketest import _apply_sysctls

        def _fail(ns, fn, *args, **kwargs):
            raise NetnsForkError("no such netns")

        with patch("shorewall_nft_simlab.smoketest.run_in_netns_fork", side_effect=_fail):
            result = _apply_sysctls(ns_name="testns")

        # Should return FAILED messages, not raise
        assert any("FAILED" in r for r in result)


class TestFlowtableState:
    """_flowtable_state uses run_in_netns_fork."""

    def test_returns_none_on_fork_error(self):
        from shorewall_nft_netkit.netns_fork import NetnsForkError

        from shorewall_nft_simlab.smoketest import _flowtable_state

        with patch(
            "shorewall_nft_simlab.smoketest.run_in_netns_fork",
            side_effect=NetnsForkError("fail"),
        ):
            result = _flowtable_state("testns")

        assert result is None

    def test_returns_none_on_empty_data(self):
        from shorewall_nft_simlab.smoketest import _flowtable_state

        with patch(
            "shorewall_nft_simlab.smoketest.run_in_netns_fork",
            return_value={},
        ):
            result = _flowtable_state("testns")

        assert result is None


# ---------------------------------------------------------------------------
# controller helpers
# ---------------------------------------------------------------------------


class TestControllerHelpers:
    def test_libnftables_load_script_pickleable(self):
        from shorewall_nft_simlab.controller import _libnftables_load_script_in_child
        pickle.dumps(_libnftables_load_script_in_child)

    def test_load_nft_calls_fork(self, tmp_path):
        """SimController.load_nft reads the file and passes text to fork."""
        from shorewall_nft_simlab.controller import SimController

        script_file = tmp_path / "rules.nft"
        script_text = "add table inet test"
        script_file.write_text(script_text)

        # Minimal SimController construction without full topology
        ctl = object.__new__(SimController)
        ctl.ns_name = "testns"

        fork_calls: list = []

        def _mock_fork(ns, fn, *args, **kwargs):
            fork_calls.append((ns, args))
            return (0, "")  # rc=0, no error

        with patch("shorewall_nft_simlab.controller.run_in_netns_fork", side_effect=_mock_fork):
            ctl.load_nft(str(script_file))

        assert len(fork_calls) == 1
        assert fork_calls[0][0] == "testns"
        # The script text should be passed as the first positional arg
        assert fork_calls[0][1][0] == script_text

    def test_load_nft_raises_on_failure(self, tmp_path):
        from shorewall_nft_simlab.controller import SimController

        script_file = tmp_path / "rules.nft"
        script_file.write_text("bad nft")

        ctl = object.__new__(SimController)
        ctl.ns_name = "testns"

        def _fail(ns, fn, *args, **kwargs):
            return (1, "syntax error")

        with patch("shorewall_nft_simlab.controller.run_in_netns_fork", side_effect=_fail):
            with pytest.raises(RuntimeError, match="nft -f failed"):
                ctl.load_nft(str(script_file))


# ---------------------------------------------------------------------------
# topology helpers
# ---------------------------------------------------------------------------


class TestTopologyHelpers:
    def test_write_sysctl_pickleable(self):
        from shorewall_nft_simlab.topology import _write_sysctl_in_child
        pickle.dumps(_write_sysctl_in_child)

    def test_sysctl_write_calls_fork(self):
        from shorewall_nft_simlab.topology import SimFwTopology

        topo = object.__new__(SimFwTopology)
        topo.ns_name = "testns"

        fork_calls: list = []

        def _mock_fork(ns, fn, *args, **kwargs):
            fork_calls.append((ns, args))

        with patch(
            "shorewall_nft_simlab.topology.run_in_netns_fork", side_effect=_mock_fork
        ):
            topo._sysctl_write(["net", "ipv4", "ip_forward"], "1")

        assert len(fork_calls) == 1
        assert fork_calls[0][0] == "testns"
        assert fork_calls[0][1][0] == "/proc/sys/net/ipv4/ip_forward"
        assert fork_calls[0][1][1] == "1"

    def test_write_sysctl_ignores_file_not_found(self, tmp_path):
        """_write_sysctl_in_child must silently ignore missing sysctl paths."""
        from shorewall_nft_simlab.topology import _write_sysctl_in_child

        # Should not raise on a non-existent path
        _write_sysctl_in_child("/nonexistent/sysctl/path", "1")

    def test_write_sysctl_writes_value(self, tmp_path):
        """_write_sysctl_in_child writes the value to an existing path."""
        from shorewall_nft_simlab.topology import _write_sysctl_in_child

        target = tmp_path / "ip_forward"
        target.write_text("0")
        _write_sysctl_in_child(str(target), "1")
        assert target.read_text() == "1"
