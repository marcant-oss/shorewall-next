"""Tests for the pyroute2-backed TC apply path (apply_tc).

Unit tests use a fake IPRoute that records every tc() / link_lookup()
call without touching the kernel.  Integration tests that need a real
network namespace are decorated with skip_no_root and are not executed
in CI (they require root + a real kernel).

Patching strategy: apply_tc() imports pyroute2 inside the function body
(lazy import, same as proxyarp.py).  We therefore patch at the pyroute2
package level — ``patch("pyroute2.IPRoute", ...)`` — so the ``from
pyroute2 import IPRoute`` statement inside apply_tc picks up the mock.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from shorewall_nft.compiler.tc import (
    TcApplyResult,
    TcClass,
    TcConfig,
    TcDevice,
    TcFilter,
    apply_tc,
)


# ── skip marker for integration tests that need a real netns ────────────────
skip_no_root = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="requires root for real-netns TC operations",
)


# ── helpers ─────────────────────────────────────────────────────────────────

def _minimal_tc() -> TcConfig:
    """Minimal TcConfig: one device (egress only), one class, one filter."""
    return TcConfig(
        devices=[TcDevice(interface="eth0", out_bandwidth="10mbit")],
        classes=[TcClass(interface="eth0", mark=1, rate="5mbit", ceil="10mbit", priority=1)],
        filters=[TcFilter(tc_class="eth0:1")],
    )


def _make_fake_ipr(*, del_raises_enoent: bool = False) -> MagicMock:
    """Return a mock IPRoute instance.

    * link_lookup always returns [2] (ifindex 2 for eth0).
    * tc() calls are recorded.
    * If del_raises_enoent is True, the first tc('del', ...) call raises
      NetlinkError(errno=2) to simulate an absent qdisc.
    """
    from pyroute2.netlink.exceptions import NetlinkError

    fake = MagicMock()
    fake.__enter__ = lambda s: s
    fake.__exit__ = MagicMock(return_value=False)
    fake.link_lookup.return_value = [2]

    if del_raises_enoent:
        _del_call_count = {"n": 0}

        def _tc_side_effect(op, kind, *args, **kwargs):
            if op == "del":
                _del_call_count["n"] += 1
                if _del_call_count["n"] == 1:
                    err = NetlinkError(2)
                    raise err
            return MagicMock()

        fake.tc.side_effect = _tc_side_effect
    else:
        fake.tc.return_value = MagicMock()

    return fake


# ── unit tests ───────────────────────────────────────────────────────────────


class TestApplyTcCallSequence:
    """Verify that apply_tc issues the correct sequence of ipr.tc() calls."""

    def test_minimal_config_call_sequence(self):
        """One device (egress) + one class + one filter → expected tc() calls."""
        fake_ipr = _make_fake_ipr()

        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(_minimal_tc())

        assert isinstance(result, TcApplyResult)
        assert result.failed == 0
        assert result.applied > 0

        calls = fake_ipr.tc.call_args_list
        ops = [c[0][0] for c in calls]  # first positional arg = op

        # Must delete the root qdisc before adding it.
        assert "del" in ops
        del_idx = ops.index("del")
        add_indices = [i for i, op in enumerate(ops) if op == "add"]
        assert all(i > del_idx for i in add_indices), \
            "del must come before any add"

        # Must add an HTB qdisc, an HTB class (root 1:1), another class
        # (1:mark), and a filter.
        kinds = [c[0][1] for c in calls]
        assert "htb" in kinds
        assert "add-filter" in ops or any("filter" in str(c) for c in calls)

    def test_device_missing_interface_records_error(self):
        """If link_lookup returns [] the device is skipped with an error."""
        fake_ipr = MagicMock()
        fake_ipr.link_lookup.return_value = []
        fake_ipr.close = MagicMock()

        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(_minimal_tc())

        assert result.failed > 0
        assert any("not found" in e for e in result.errors)
        # tc() must never have been called for a missing interface
        fake_ipr.tc.assert_not_called()

    def test_ingress_qdisc_added_when_in_bandwidth_set(self):
        """in_bandwidth → ingress qdisc add must be issued."""
        fake_ipr = _make_fake_ipr()
        tc_cfg = TcConfig(
            devices=[TcDevice(interface="eth0", in_bandwidth="100mbit")],
        )

        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(tc_cfg)

        assert result.failed == 0
        calls = fake_ipr.tc.call_args_list
        kinds = [c[0][1] for c in calls]
        assert "ingress" in kinds

    def test_filter_bad_class_format_records_error(self):
        """A filter with no colon in tc_class must record an error."""
        fake_ipr = _make_fake_ipr()
        tc_cfg = TcConfig(
            devices=[TcDevice(interface="eth0", out_bandwidth="10mbit")],
            filters=[TcFilter(tc_class="eth0_1_no_colon")],
        )

        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(tc_cfg)

        assert result.failed > 0
        assert any("INTERFACE:MARK" in e for e in result.errors)


class TestTeardownIdempotence:
    """ENOENT on tc('del', ...) must not abort the apply."""

    def test_enoent_on_del_does_not_fail(self):
        """NetlinkError(errno=2) on the del call is swallowed; apply proceeds."""
        fake_ipr = _make_fake_ipr(del_raises_enoent=True)

        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(_minimal_tc())

        # The error on del must NOT count as a failure — it means qdisc
        # was absent, which is fine (first-run scenario).
        assert result.failed == 0, f"unexpected failures: {result.errors}"
        assert result.applied > 0

    def test_non_enoent_del_error_is_recorded(self):
        """NetlinkError with errno != 2 on del IS recorded as a failure."""
        from pyroute2.netlink.exceptions import NetlinkError

        fake_ipr = MagicMock()
        fake_ipr.link_lookup.return_value = [2]
        fake_ipr.close = MagicMock()

        def _tc_side_effect(op, kind, *args, **kwargs):
            if op == "del":
                raise NetlinkError(95)  # EOPNOTSUPP — not ENOENT
            return MagicMock()

        fake_ipr.tc.side_effect = _tc_side_effect

        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(_minimal_tc())

        assert result.failed > 0
        assert any("del" in e or "qdisc" in e for e in result.errors)


class TestNetnsKwarg:
    """Verify IPRoute is constructed with the correct netns kwarg."""

    def test_netns_none_constructs_without_kwarg(self):
        """netns=None → IPRoute() called with no netns argument."""
        fake_ipr = _make_fake_ipr()
        with patch("pyroute2.IPRoute", return_value=fake_ipr) as mock_cls:
            apply_tc(TcConfig(), netns=None)
        mock_cls.assert_called_once_with()

    def test_netns_name_constructs_with_kwarg(self):
        """netns='fw' → IPRoute(netns='fw') is called."""
        fake_ipr = _make_fake_ipr()
        with patch("pyroute2.IPRoute", return_value=fake_ipr) as mock_cls:
            apply_tc(TcConfig(), netns="fw")
        mock_cls.assert_called_once_with(netns="fw")

    def test_ipr_close_called_on_success(self):
        """IPRoute.close() must always be called (even on success)."""
        fake_ipr = _make_fake_ipr()
        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            apply_tc(TcConfig())
        fake_ipr.close.assert_called_once()

    def test_ipr_close_called_on_error(self):
        """IPRoute.close() must be called even when a tc() call raises."""
        from pyroute2.netlink.exceptions import NetlinkError

        fake_ipr = MagicMock()
        fake_ipr.link_lookup.return_value = [2]
        fake_ipr.tc.side_effect = NetlinkError(1)  # EPERM

        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(_minimal_tc())

        fake_ipr.close.assert_called_once()
        # At least one failure should have been recorded.
        assert result.failed > 0 or len(result.errors) > 0


class TestTcApplyResult:
    """TcApplyResult fields are populated correctly."""

    def test_all_success(self):
        """When every operation succeeds applied > 0 and failed == 0."""
        fake_ipr = _make_fake_ipr()
        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(_minimal_tc())
        assert result.applied > 0
        assert result.failed == 0
        assert result.errors == []

    def test_partial_failure(self):
        """When a filter add fails, failed == 1 and errors is non-empty."""
        from pyroute2.netlink.exceptions import NetlinkError

        fake_ipr = MagicMock()
        fake_ipr.link_lookup.return_value = [2]
        fake_ipr.close = MagicMock()

        call_count = {"n": 0}

        def _tc_side_effect(op, kind, *args, **kwargs):
            call_count["n"] += 1
            if op == "add-filter":
                raise NetlinkError(1)  # fail only on filter add
            return MagicMock()

        fake_ipr.tc.side_effect = _tc_side_effect

        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(_minimal_tc())

        assert result.failed == 1
        assert len(result.errors) == 1
        assert "filter" in result.errors[0]
        assert result.applied > 0  # device + class succeeded

    def test_pyroute2_not_installed(self):
        """Missing pyroute2 returns an error result without raising."""
        import sys

        # Remove pyroute2 from sys.modules so the lazy import inside
        # apply_tc() raises ImportError.
        saved = {k: v for k, v in sys.modules.items()
                 if k.startswith("pyroute2")}
        for k in list(saved):
            sys.modules.pop(k, None)

        try:
            with patch.dict("sys.modules",
                            {"pyroute2": None,
                             "pyroute2.netlink": None,
                             "pyroute2.netlink.exceptions": None}):
                result = apply_tc(TcConfig())
        finally:
            # Restore pyroute2 modules for subsequent tests.
            sys.modules.update(saved)

        assert result.applied == 0
        assert len(result.errors) >= 1


class TestEmptyConfig:
    """An empty TcConfig must not call tc() at all."""

    def test_empty_config_no_tc_calls(self):
        fake_ipr = _make_fake_ipr()
        with patch("pyroute2.IPRoute", return_value=fake_ipr):
            result = apply_tc(TcConfig())
        fake_ipr.tc.assert_not_called()
        assert result.applied == 0
        assert result.failed == 0
        assert result.errors == []


# ── integration tests (require root + real kernel netns) ────────────────────


@skip_no_root
class TestApplyTcRealNetns:
    """Integration tests that create a real veth pair in a temporary netns.

    These tests are skipped in CI (no root).  Run manually via
    tools/run-tests.sh or as root.
    """

    def test_apply_creates_htb_qdisc(self, tmp_path):
        """apply_tc on a real veth interface installs an HTB root qdisc."""
        import subprocess

        ns = "swnft-tc-test"
        veth = "tc-test-v0"
        try:
            subprocess.run(["ip", "netns", "add", ns], check=True)
            subprocess.run(
                ["ip", "netns", "exec", ns, "ip", "link", "add",
                 veth, "type", "dummy"],
                check=True)
            subprocess.run(
                ["ip", "netns", "exec", ns, "ip", "link",
                 "set", veth, "up"],
                check=True)

            tc_cfg = TcConfig(
                devices=[TcDevice(interface=veth, out_bandwidth="10mbit")],
                classes=[TcClass(interface=veth, mark=1,
                                 rate="5mbit", ceil="10mbit", priority=1)],
            )
            result = apply_tc(tc_cfg, netns=ns)
            assert result.failed == 0, result.errors
            assert result.applied > 0
        finally:
            subprocess.run(["ip", "netns", "del", ns], check=False)
