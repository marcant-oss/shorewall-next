"""Unit tests for large-set hardening of iplist tracker and plain-list tracker.

Covers:
* SHOREWALLD_IPLIST_CHUNK_SIZE env-tunable + clamping
* PlainListConfig.max_prefixes can exceed the module-level default
* IpListMetrics new methods (record_apply_duration / _path / _capacity)
* Capacity warning fires at 80%
* "Set is full" triggers set_capacity_exceeded error reason and returns (-1, 0)
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import os
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# 1. _CHUNK_SIZE env-tunable and clamping
# ---------------------------------------------------------------------------


class TestChunkSizeEnvTunable:
    """_CHUNK_SIZE must honour SHOREWALLD_IPLIST_CHUNK_SIZE and clamp to [100, 10000]."""

    def _reload_tracker(self, env_val: str | None):
        """Reload tracker module with env var set / unset."""
        env = dict(os.environ)
        if env_val is None:
            env.pop("SHOREWALLD_IPLIST_CHUNK_SIZE", None)
        else:
            env["SHOREWALLD_IPLIST_CHUNK_SIZE"] = env_val
        import shorewalld.iplist.tracker as mod
        with patch.dict(os.environ, env, clear=True):
            importlib.reload(mod)
        return mod

    def test_default_is_2000(self):
        mod = self._reload_tracker(None)
        assert mod._CHUNK_SIZE == 2000

    def test_custom_value(self):
        mod = self._reload_tracker("500")
        assert mod._CHUNK_SIZE == 500

    def test_clamp_minimum(self):
        """Values below 100 are clamped to 100."""
        mod = self._reload_tracker("10")
        assert mod._CHUNK_SIZE == 100

    def test_clamp_maximum(self):
        """Values above 10000 are clamped to 10000."""
        mod = self._reload_tracker("99999")
        assert mod._CHUNK_SIZE == 10_000

    def test_boundary_min(self):
        mod = self._reload_tracker("100")
        assert mod._CHUNK_SIZE == 100

    def test_boundary_max(self):
        mod = self._reload_tracker("10000")
        assert mod._CHUNK_SIZE == 10_000

    def test_plain_default_is_2000(self):
        import shorewalld.iplist.plain as mod
        with patch.dict(os.environ, {}, clear=True):
            importlib.reload(mod)
        assert mod._CHUNK_SIZE == 2000

    def test_plain_clamp_minimum(self):
        import shorewalld.iplist.plain as mod
        with patch.dict(os.environ, {"SHOREWALLD_IPLIST_CHUNK_SIZE": "5"}, clear=False):
            importlib.reload(mod)
        assert mod._CHUNK_SIZE == 100


# ---------------------------------------------------------------------------
# 2. PlainListConfig.max_prefixes can exceed the module-level default
# ---------------------------------------------------------------------------


class TestPlainListMaxPrefixes:
    def test_custom_max_prefixes_accepted(self):
        """PlainListConfig.max_prefixes can be set to 1_000_000 and _do_refresh accepts it."""
        from shorewalld.iplist.plain import PlainListConfig, PlainListTracker

        text = "\n".join(f"198.51.{i // 256}.{i % 256}" for i in range(100))
        cfg = PlainListConfig(
            name="large_list",
            source="/fake/path",
            set_v4="nfset_large_list_v4",
            set_v6="nfset_large_list_v6",
            max_prefixes=1_000_000,
        )
        assert cfg.max_prefixes == 1_000_000

        fake_nft = MagicMock()
        fake_nft.cmd.return_value = None
        tracker = PlainListTracker([cfg], fake_nft, {})
        state = tracker._states["large_list"]

        with patch("shorewalld.iplist.plain._read_file", return_value=text):
            asyncio.run(tracker._do_refresh(state))

        assert state.consecutive_errors == 0

    def test_module_default_max_prefixes_is_2m(self):
        import shorewalld.iplist.plain as mod
        assert mod._MAX_PREFIXES == 2_000_000

    def test_config_default_uses_module_constant(self):
        from shorewalld.iplist.plain import PlainListConfig, _MAX_PREFIXES
        cfg = PlainListConfig(name="x", source="/fake")
        assert cfg.max_prefixes == _MAX_PREFIXES


# ---------------------------------------------------------------------------
# 3. IpListMetrics new methods
# ---------------------------------------------------------------------------


class TestIpListMetricsNewMethods:
    def _make_metrics(self):
        from shorewalld.iplist.tracker import IpListMetrics
        return IpListMetrics()

    def test_record_apply_duration_accumulates(self):
        m = self._make_metrics()
        m.record_apply_duration("mylist", "v4", 1.5)
        m.record_apply_duration("mylist", "v4", 0.5)
        entry = m._apply_durations[("mylist", "v4")]
        assert entry["sum"] == 2.0
        assert entry["count"] == 2

    def test_record_apply_duration_separate_families(self):
        m = self._make_metrics()
        m.record_apply_duration("mylist", "v4", 1.0)
        m.record_apply_duration("mylist", "v6", 2.0)
        assert m._apply_durations[("mylist", "v4")]["sum"] == 1.0
        assert m._apply_durations[("mylist", "v6")]["sum"] == 2.0

    def test_record_apply_path_accumulates(self):
        m = self._make_metrics()
        m.record_apply_path("mylist", "v4", "diff")
        m.record_apply_path("mylist", "v4", "diff")
        m.record_apply_path("mylist", "v4", "swap")
        assert m._apply_paths[("mylist", "v4")]["diff"] == 2
        assert m._apply_paths[("mylist", "v4")]["swap"] == 1

    def test_record_apply_capacity_stores_values(self):
        m = self._make_metrics()
        m.record_apply_capacity("mylist", "v4", 500, 1000)
        cap = m._apply_capacity[("mylist", "v4")]
        assert cap["used"] == 500
        assert cap["declared"] == 1000

    def test_record_apply_capacity_overwrites(self):
        """Latest call overwrites previous — gauge semantics."""
        m = self._make_metrics()
        m.record_apply_capacity("mylist", "v4", 100, 1000)
        m.record_apply_capacity("mylist", "v4", 800, 1000)
        cap = m._apply_capacity[("mylist", "v4")]
        assert cap["used"] == 800

    def test_collect_includes_new_metric_families(self):
        m = self._make_metrics()
        m.record_apply_duration("l", "v4", 1.2)
        m.record_apply_path("l", "v4", "diff")
        m.record_apply_capacity("l", "v4", 300, 1000)

        try:
            families = m.collect()
        except ImportError:
            return  # exporter not installed in this env — skip

        names = {f.name for f in families}
        assert "shorewalld_iplist_apply_duration_seconds_sum" in names
        assert "shorewalld_iplist_apply_duration_seconds_count" in names
        assert "shorewalld_iplist_apply_path_total" in names
        assert "shorewalld_iplist_set_capacity" in names
        assert "shorewalld_iplist_set_headroom_ratio" in names

    def test_headroom_ratio_computed_correctly(self):
        m = self._make_metrics()
        m.record_apply_capacity("l", "v4", 500, 1000)

        try:
            families = m.collect()
        except ImportError:
            return

        ratio_fam = next(
            f for f in families if f.name == "shorewalld_iplist_set_headroom_ratio"
        )
        # Find sample for (l, v4)
        sample = next(
            (s for s in ratio_fam.samples if s[0] == ["l", "v4"]), None
        )
        assert sample is not None
        assert abs(sample[1] - 0.5) < 1e-9


# ---------------------------------------------------------------------------
# 4. Capacity warning fires at 80%
# ---------------------------------------------------------------------------


class TestCapacityWarning:
    """record_apply_capacity must emit WARN log when used/declared >= 0.8."""

    def test_warning_fires_at_80_percent(self, caplog):
        from shorewalld.iplist.tracker import IpListMetrics

        m = IpListMetrics()
        with caplog.at_level(logging.WARNING, logger="shorewalld.iplist"):
            m.record_apply_capacity("testlist", "v4", 800, 1000)

        assert any("80%" in r.message or "capacity" in r.message for r in caplog.records)

    def test_warning_fires_at_exactly_80_percent(self, caplog):
        from shorewalld.iplist.tracker import IpListMetrics

        m = IpListMetrics()
        with caplog.at_level(logging.WARNING, logger="shorewalld.iplist"):
            m.record_apply_capacity("testlist", "v4", 800, 1000)

        warn_records = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(warn_records) >= 1

    def test_no_warning_below_80_percent(self, caplog):
        from shorewalld.iplist.tracker import IpListMetrics

        m = IpListMetrics()
        with caplog.at_level(logging.WARNING, logger="shorewalld.iplist"):
            m.record_apply_capacity("testlist", "v4", 799, 1000)

        warn_records = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(warn_records) == 0

    def test_warning_via_mock_nft_cmd(self, caplog):
        """End-to-end: mock _nft.cmd returns JSON with declared=1000 and 800 elements."""
        from shorewalld.iplist.tracker import IpListTracker

        # Use a simple config-like object since IpListConfig is a protocol/ABC
        class _FakeCfg:
            name = "cap_test"
            provider = "aws"
            set_v4 = "nfset_cap_test_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 5_000
            filters: list = []

        # Build a set of 800 elements
        elements = {f"10.0.{i // 256}.{i % 256}/32" for i in range(800)}

        fake_nft = MagicMock()
        # First cmd calls (add element) return None, last one (list set) returns JSON
        nft_json = {
            "nftables": [
                {"set": {"name": "nfset_cap_test_v4", "size": 1000, "elem": []}}
            ]
        }

        def nft_cmd_side_effect(script, netns=None, json_output=False):
            if json_output:
                return nft_json
            return None

        fake_nft.cmd.side_effect = nft_cmd_side_effect

        fake_profile = MagicMock()
        fake_profile.has_table = True

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={"": fake_profile},
        )

        with caplog.at_level(logging.WARNING, logger="shorewalld.iplist"):
            asyncio.run(
                tracker._apply_set("", "nfset_cap_test_v4", set(), elements, "cap_test", "v4")
            )

        warn_records = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("capacity" in r.message.lower() or "%" in r.message for r in warn_records)


# ---------------------------------------------------------------------------
# 5. "Set is full" exception triggers set_capacity_exceeded
# ---------------------------------------------------------------------------


class TestSetFullDetection:
    def test_set_is_full_returns_minus_one(self):
        """'Set is full' error causes _apply_set to return (-1, 0)."""
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "full_test"
            provider = "aws"
            set_v4 = "nfset_full_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 5_000
            filters: list = []

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = RuntimeError("Set is full")

        fake_profile = MagicMock()
        fake_profile.has_table = True

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={"": fake_profile},
        )

        elements = {"10.0.0.1/32", "10.0.0.2/32"}
        result = asyncio.run(
            tracker._apply_set("", "nfset_full_v4", set(), elements, "full_test", "v4")
        )
        assert result == (-1, 0)

    def test_set_is_full_records_capacity_exceeded_error(self):
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "full_test2"
            provider = "aws"
            set_v4 = "nfset_full_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 5_000
            filters: list = []

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = RuntimeError("Set is full")

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={"": MagicMock(has_table=True)},
        )

        elements = {"10.0.0.1/32"}
        asyncio.run(
            tracker._apply_set("", "nfset_full_v4", set(), elements, "full_test2", "v4")
        )
        errors = tracker._metrics._fetch_errors.get("full_test2", {})
        assert errors.get("set_capacity_exceeded", 0) >= 1
        assert errors.get("nft_write_error", 0) == 0

    def test_cannot_resize_triggers_capacity_exceeded(self):
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "resize_test"
            provider = "aws"
            set_v4 = "nfset_resize_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 5_000
            filters: list = []

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = RuntimeError("Cannot resize: set has fixed size")

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={"": MagicMock(has_table=True)},
        )

        elements = {"10.0.0.1/32"}
        result = asyncio.run(
            tracker._apply_set("", "nfset_resize_v4", set(), elements, "resize_test", "v4")
        )
        assert result == (-1, 0)
        errors = tracker._metrics._fetch_errors.get("resize_test", {})
        assert errors.get("set_capacity_exceeded", 0) >= 1

    def test_generic_nft_error_records_nft_write_error(self):
        """Non-set-full errors still record nft_write_error (not capacity_exceeded)."""
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "generic_err"
            provider = "aws"
            set_v4 = "nfset_generic_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 5_000
            filters: list = []

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = RuntimeError("Some other nft error")

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={"": MagicMock(has_table=True)},
        )

        elements = {"10.0.0.1/32"}
        result = asyncio.run(
            tracker._apply_set("", "nfset_generic_v4", set(), elements, "generic_err", "v4")
        )
        assert result == (-1, 0)
        errors = tracker._metrics._fetch_errors.get("generic_err", {})
        assert errors.get("nft_write_error", 0) >= 1
        assert errors.get("set_capacity_exceeded", 0) == 0

    def test_plain_set_is_full_returns_minus_one(self):
        """Same detection in PlainListTracker._apply_set."""
        from shorewalld.iplist.plain import PlainListConfig, PlainListTracker

        cfg = PlainListConfig(
            name="plain_full",
            source="/fake/path",
            set_v4="nfset_plain_full_v4",
        )
        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = RuntimeError("Set is full")

        tracker = PlainListTracker([cfg], fake_nft, {})
        elements = {"10.0.0.1/32", "10.0.0.2/32"}
        result = asyncio.run(
            tracker._apply_set(None, "nfset_plain_full_v4", set(), elements, "plain_full", "v4")
        )
        assert result == (-1, 0)
        errors = tracker._metrics._fetch_errors.get("plain_full", {})
        assert errors.get("set_capacity_exceeded", 0) >= 1

    def test_plain_generic_error_records_nft_write_error(self):
        from shorewalld.iplist.plain import PlainListConfig, PlainListTracker

        cfg = PlainListConfig(
            name="plain_generic",
            source="/fake/path",
            set_v4="nfset_plain_generic_v4",
        )
        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = RuntimeError("unrelated error")

        tracker = PlainListTracker([cfg], fake_nft, {})
        elements = {"10.0.0.1/32"}
        result = asyncio.run(
            tracker._apply_set(None, "nfset_plain_generic_v4", set(), elements, "plain_generic", "v4")
        )
        assert result == (-1, 0)
        errors = tracker._metrics._fetch_errors.get("plain_generic", {})
        assert errors.get("nft_write_error", 0) >= 1
        assert errors.get("set_capacity_exceeded", 0) == 0


# ---------------------------------------------------------------------------
# 6. Timing wrapper is called on success
# ---------------------------------------------------------------------------


class TestTimingWrapper:
    def test_apply_duration_recorded_on_success(self):
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "timing_test"
            provider = "aws"
            set_v4 = "nfset_timing_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 5_000
            filters: list = []

        nft_json = {
            "nftables": [
                {"set": {"name": "nfset_timing_v4", "size": 10000, "elem": []}}
            ]
        }

        def nft_cmd_side_effect(script, netns=None, json_output=False):
            return nft_json if json_output else None

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = nft_cmd_side_effect

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={},
        )
        elements = {"10.0.0.1/32", "10.0.0.2/32"}
        asyncio.run(
            tracker._apply_set("", "nfset_timing_v4", set(), elements, "timing_test", "v4")
        )
        assert ("timing_test", "v4") in tracker._metrics._apply_durations
        assert tracker._metrics._apply_durations[("timing_test", "v4")]["count"] == 1

    def test_apply_path_diff_recorded(self):
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "path_test"
            provider = "aws"
            set_v4 = "nfset_path_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 5_000
            filters: list = []

        fake_nft = MagicMock()
        fake_nft.cmd.return_value = None

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={},
        )
        asyncio.run(
            tracker._apply_set("", "nfset_path_v4", set(), {"10.0.0.1/32"}, "path_test", "v4")
        )
        assert tracker._metrics._apply_paths[("path_test", "v4")].get("diff", 0) >= 1


# ---------------------------------------------------------------------------
# 7. _next_pow2 edge cases
# ---------------------------------------------------------------------------


class TestNextPow2:
    def test_zero(self):
        from shorewalld.iplist.tracker import _next_pow2
        assert _next_pow2(0) == 1

    def test_one(self):
        from shorewalld.iplist.tracker import _next_pow2
        assert _next_pow2(1) == 1

    def test_two(self):
        from shorewalld.iplist.tracker import _next_pow2
        assert _next_pow2(2) == 2

    def test_2_pow_20(self):
        from shorewalld.iplist.tracker import _next_pow2
        assert _next_pow2(2 ** 20) == 2 ** 20

    def test_2_pow_20_plus_1(self):
        from shorewalld.iplist.tracker import _next_pow2
        assert _next_pow2(2 ** 20 + 1) == 2 ** 21

    def test_three(self):
        from shorewalld.iplist.tracker import _next_pow2
        assert _next_pow2(3) == 4

    def test_65537(self):
        from shorewalld.iplist.tracker import _next_pow2
        assert _next_pow2(65537) == 131072


# ---------------------------------------------------------------------------
# 8. Swap-rename — disabled by default (_SWAP_ENABLED=False)
# ---------------------------------------------------------------------------


class TestSwapDisabledByDefault:
    """When SHOREWALLD_IPLIST_SWAP_RENAME is unset/0, diff path is always taken."""

    def _make_tracker(self):
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "swap_disabled"
            provider = "aws"
            set_v4 = "nfset_sd_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 10_000_000
            filters: list = []

        fake_nft = MagicMock()
        # Return None for all non-json calls, valid JSON for json calls.
        def side_effect(script, netns=None, json_output=False):
            if json_output:
                return {"nftables": [{"set": {"type": "ipv4_addr", "flags": ["interval"], "size": 262144}}]}
            return None
        fake_nft.cmd.side_effect = side_effect

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={},
        )
        return tracker, fake_nft

    def test_large_new_takes_diff_path(self):
        """1 M element set must use diff path when swap is disabled (default)."""
        import shorewalld.iplist.tracker as tracker_mod
        # Ensure swap is off (reload with env cleared)
        with patch.dict(os.environ, {}, clear=True):
            importlib.reload(tracker_mod)

        tracker, fake_nft = self._make_tracker()
        new = {f"10.{i >> 16 & 0xff}.{i >> 8 & 0xff}.{i & 0xff}/32" for i in range(60000)}

        asyncio.run(
            tracker._apply_set("", "nfset_sd_v4", set(), new, "swap_disabled", "v4")
        )
        paths = tracker._metrics._apply_paths.get(("swap_disabled", "v4"), {})
        assert paths.get("diff", 0) >= 1
        assert paths.get("swap", 0) == 0

    def test_no_swap_script_submitted(self):
        """No call to _nft.cmd should contain 'rename set' when swap is disabled."""
        import shorewalld.iplist.tracker as tracker_mod
        with patch.dict(os.environ, {}, clear=True):
            importlib.reload(tracker_mod)

        tracker, fake_nft = self._make_tracker()
        new = {f"10.{i >> 8 & 0xff}.{i & 0xff}.1/32" for i in range(60000)}

        asyncio.run(
            tracker._apply_set("", "nfset_sd_v4", set(), new, "swap_disabled", "v4")
        )
        for call in fake_nft.cmd.call_args_list:
            script = call.args[0] if call.args else ""
            assert "rename set" not in script


# ---------------------------------------------------------------------------
# 9. Swap-trigger decision matrix
# ---------------------------------------------------------------------------


def _make_probe_json(set_type="ipv4_addr", flags=None, size=262144):
    """Return a libnftables-style probe dict."""
    s: dict = {"type": set_type, "size": size}
    if flags is not None:
        s["flags"] = flags
    return {"nftables": [{"set": s}]}


def _make_swap_tracker(name="sw_trig"):
    """Return a tracker with SWAP_ENABLED=True via module-level patch."""
    from shorewalld.iplist.tracker import IpListTracker

    class _FakeCfg:
        provider = "aws"
        set_v4 = f"nfset_{name}_v4"
        set_v6 = ""
        refresh = 3600
        max_prefixes = 10_000_000
        filters: list = []

    _FakeCfg.name = name

    fake_nft = MagicMock()
    def side_effect(script, netns=None, json_output=False):
        if json_output:
            return _make_probe_json()
        return None
    fake_nft.cmd.side_effect = side_effect

    tracker = IpListTracker(
        configs=[_FakeCfg()],
        nft=fake_nft,
        profiles={},
    )
    return tracker, fake_nft


class TestSwapTriggerDecisionMatrix:
    """Verify swap is taken for the right combos, not taken otherwise."""

    def _run(self, tracker, set_name, current, new, list_name):
        import shorewalld.iplist.tracker as mod
        with patch.object(mod, "_SWAP_ENABLED", True):
            return asyncio.run(
                tracker._apply_set("", set_name, current, new, list_name, "v4")
            )

    def test_absolute_size_triggers_swap(self):
        """len(new) >= 50000 → swap."""
        import shorewalld.iplist.tracker as mod
        tracker, _ = _make_swap_tracker("abs_trig")
        new = {f"10.{i >> 8 & 0xff}.{i & 0xff}.1/32" for i in range(50000)}
        with patch.object(mod, "_SWAP_ENABLED", True), \
             patch.object(mod, "_SWAP_THRESHOLD_ABS", 50000):
            asyncio.run(
                tracker._apply_set("", "nfset_abs_trig_v4", set(), new, "abs_trig", "v4")
            )
        paths = tracker._metrics._apply_paths.get(("abs_trig", "v4"), {})
        assert paths.get("swap", 0) >= 1
        assert paths.get("diff", 0) == 0

    def test_below_absolute_threshold_uses_diff(self):
        """len(new) < 50000 and small churn → diff."""
        import shorewalld.iplist.tracker as mod
        tracker, _ = _make_swap_tracker("abs_below")
        new = {f"10.0.{i // 256}.{i % 256}/32" for i in range(100)}
        with patch.object(mod, "_SWAP_ENABLED", True), \
             patch.object(mod, "_SWAP_THRESHOLD_ABS", 50000), \
             patch.object(mod, "_SWAP_THRESHOLD_FRAC", 0.5):
            asyncio.run(
                tracker._apply_set("", "nfset_abs_below_v4", set(), new, "abs_below", "v4")
            )
        paths = tracker._metrics._apply_paths.get(("abs_below", "v4"), {})
        assert paths.get("diff", 0) >= 1
        assert paths.get("swap", 0) == 0

    def test_large_churn_fraction_triggers_swap(self):
        """100% size growth (5K → 10K) → delta/current = 1.0 ≥ 0.5 → swap."""
        import shorewalld.iplist.tracker as mod
        tracker, _ = _make_swap_tracker("frac_trig")
        current = {f"10.0.{i // 256}.{i % 256}/32" for i in range(5000)}
        # Double the set size — delta = 5000, current = 5000 → ratio = 1.0
        new = {f"10.0.{i // 256}.{i % 256}/32" for i in range(10000)}
        with patch.object(mod, "_SWAP_ENABLED", True), \
             patch.object(mod, "_SWAP_THRESHOLD_ABS", 999_999), \
             patch.object(mod, "_SWAP_THRESHOLD_FRAC", 0.5):
            asyncio.run(
                tracker._apply_set("", "nfset_frac_trig_v4", current, new, "frac_trig", "v4")
            )
        paths = tracker._metrics._apply_paths.get(("frac_trig", "v4"), {})
        assert paths.get("swap", 0) >= 1

    def test_small_churn_below_frac_uses_diff(self):
        """10% churn on a 10 K set → diff (below 50% threshold)."""
        import shorewalld.iplist.tracker as mod
        tracker, _ = _make_swap_tracker("frac_below")
        current = {f"10.0.{i // 256}.{i % 256}/32" for i in range(10000)}
        # Replace 5% — delta/current ~ 0.05
        new = set(list(current)[500:]) | {f"10.2.0.{i}/32" for i in range(500)}
        with patch.object(mod, "_SWAP_ENABLED", True), \
             patch.object(mod, "_SWAP_THRESHOLD_ABS", 999_999), \
             patch.object(mod, "_SWAP_THRESHOLD_FRAC", 0.5):
            asyncio.run(
                tracker._apply_set("", "nfset_frac_below_v4", current, new, "frac_below", "v4")
            )
        paths = tracker._metrics._apply_paths.get(("frac_below", "v4"), {})
        assert paths.get("diff", 0) >= 1
        assert paths.get("swap", 0) == 0


# ---------------------------------------------------------------------------
# 10. Autosize trigger
# ---------------------------------------------------------------------------


class TestAutosizeTrigger:
    """declared_size=100000, new=95000 → fill_ratio=0.95 → autosize fires."""

    def test_autosize_emits_larger_size_in_script(self, caplog):
        import shorewalld.iplist.tracker as mod
        from shorewalld.iplist.tracker import IpListTracker, _next_pow2

        class _FakeCfg:
            name = "autosize_test"
            provider = "aws"
            set_v4 = "nfset_autosize_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 10_000_000
            filters: list = []

        declared_size = 100_000
        new_count = 95_000
        # Generate distinct /32 entries across 10.x.y.z space.
        # 95000 entries: x from 0..5, y from 0..255, z computed from index.
        new = set()
        for i in range(new_count):
            a = i >> 16 & 0x7F  # 0..127
            b = i >> 8 & 0xFF   # 0..255
            c = i & 0xFF         # 0..255
            new.add(f"10.{a}.{b}.{c}/32")
        new_count = len(new)  # actual distinct count after dedup

        probe_json = _make_probe_json(
            set_type="ipv4_addr",
            flags=["interval"],
            size=declared_size,
        )

        captured_scripts: list[str] = []

        def side_effect(script, netns=None, json_output=False):
            if json_output:
                return probe_json
            captured_scripts.append(script)
            return None

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = side_effect

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={},
        )

        expected_new_size = min(
            _next_pow2(max(new_count * 2, declared_size * 2)),
            67_108_864,
        )

        with patch.object(mod, "_SWAP_ENABLED", True), \
             patch.object(mod, "_AUTOSIZE_HEADROOM", 0.90), \
             patch.object(mod, "_SWAP_THRESHOLD_ABS", 999_999), \
             patch.object(mod, "_SWAP_THRESHOLD_FRAC", 1.0), \
             caplog.at_level(logging.WARNING, logger="shorewalld.iplist"):
            asyncio.run(
                tracker._apply_set(
                    "", "nfset_autosize_v4", set(), new, "autosize_test", "v4"
                )
            )

        paths = tracker._metrics._apply_paths.get(("autosize_test", "v4"), {})
        assert paths.get("swap", 0) >= 1, "swap path should have fired"

        # At least one script should mention the new (larger) size.
        size_str = str(expected_new_size)
        assert any(size_str in s for s in captured_scripts), (
            f"Expected size {size_str} in one of the submitted scripts; "
            f"got: {[s[:120] for s in captured_scripts]}"
        )

        # The autosize WARNING must have been emitted.
        assert any(
            "autosize" in r.message.lower() or "operator should raise" in r.message
            for r in caplog.records
        ), "Expected autosize warning log"

    def test_autosize_records_capacity_with_new_size(self):
        import shorewalld.iplist.tracker as mod
        from shorewalld.iplist.tracker import IpListTracker, _next_pow2

        class _FakeCfg:
            name = "autosize_cap"
            provider = "aws"
            set_v4 = "nfset_autocap_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 10_000_000
            filters: list = []

        declared_size = 100_000
        new_count_target = 95_000
        new = set()
        for i in range(new_count_target):
            a = i >> 16 & 0x7F
            b = i >> 8 & 0xFF
            c = i & 0xFF
            new.add(f"10.{a}.{b}.{c}/32")
        new_count = len(new)

        probe_json = _make_probe_json(size=declared_size)
        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = lambda s, netns=None, json_output=False: (
            probe_json if json_output else None
        )

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={},
        )

        expected_new_size = min(
            _next_pow2(max(new_count * 2, declared_size * 2)),
            67_108_864,
        )

        with patch.object(mod, "_SWAP_ENABLED", True), \
             patch.object(mod, "_AUTOSIZE_HEADROOM", 0.90), \
             patch.object(mod, "_SWAP_THRESHOLD_ABS", 999_999), \
             patch.object(mod, "_SWAP_THRESHOLD_FRAC", 1.0):
            asyncio.run(
                tracker._apply_set(
                    "", "nfset_autocap_v4", set(), new, "autosize_cap", "v4"
                )
            )

        cap = tracker._metrics._apply_capacity.get(("autosize_cap", "v4"), {})
        assert cap.get("declared") == expected_new_size
        assert cap.get("used") == new_count


# ---------------------------------------------------------------------------
# 11. Fallback on probe failure
# ---------------------------------------------------------------------------


class TestFallbackOnProbeFailure:
    """When list set … raises, swap falls back to diff and result is correct."""

    def test_fallback_probe_raises(self):
        import shorewalld.iplist.tracker as mod
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "probe_fail"
            provider = "aws"
            set_v4 = "nfset_pf_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 10_000_000
            filters: list = []

        call_count = {"n": 0}

        def side_effect(script, netns=None, json_output=False):
            if json_output:
                raise RuntimeError("libnftables probe failed")
            # Non-JSON calls (diff adds/deletes) succeed normally.
            return None

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = side_effect

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={},
        )

        new = {f"10.0.0.{i}/32" for i in range(60000)}

        with patch.object(mod, "_SWAP_ENABLED", True), \
             patch.object(mod, "_SWAP_THRESHOLD_ABS", 50000):
            asyncio.run(
                tracker._apply_set("", "nfset_pf_v4", set(), new, "probe_fail", "v4")
            )

        paths = tracker._metrics._apply_paths.get(("probe_fail", "v4"), {})
        assert paths.get("fallback-from-swap", 0) >= 1, "fallback-from-swap must be recorded"
        assert paths.get("diff", 0) >= 1, "diff must follow fallback"
        assert paths.get("swap", 0) == 0


# ---------------------------------------------------------------------------
# 12. Fallback on libnftables script rejection
# ---------------------------------------------------------------------------


class TestFallbackOnScriptReject:
    """When the swap script itself is rejected, fall back to diff."""

    def test_fallback_swap_script_raises(self):
        import shorewalld.iplist.tracker as mod
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "script_rej"
            provider = "aws"
            set_v4 = "nfset_sr_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 10_000_000
            filters: list = []

        probe_json = _make_probe_json()
        call_log: list[str] = []

        def side_effect(script, netns=None, json_output=False):
            if json_output:
                return probe_json
            call_log.append(script)
            # Reject the swap script (contains "rename set"), allow diff scripts.
            if "rename set" in script:
                raise RuntimeError("rename not supported in this context")
            return None

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = side_effect

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={},
        )

        new = {f"10.0.0.{i}/32" for i in range(60000)}

        with patch.object(mod, "_SWAP_ENABLED", True), \
             patch.object(mod, "_SWAP_THRESHOLD_ABS", 50000):
            asyncio.run(
                tracker._apply_set("", "nfset_sr_v4", set(), new, "script_rej", "v4")
            )

        paths = tracker._metrics._apply_paths.get(("script_rej", "v4"), {})
        assert paths.get("fallback-from-swap", 0) >= 1
        assert paths.get("diff", 0) >= 1
        assert paths.get("swap", 0) == 0

        # After the fallback the diff script must NOT contain "rename set".
        diff_scripts = [s for s in call_log if "rename set" not in s]
        assert diff_scripts, "Expected at least one diff add/delete element script"


# ---------------------------------------------------------------------------
# 13. PlainListTracker swap parity
# ---------------------------------------------------------------------------


class TestPlainListTrackerSwapParity:
    """PlainListTracker._apply_set must take the swap path under the same conditions."""

    def _make_plain_tracker(self, name="plain_swap"):
        from shorewalld.iplist.plain import PlainListConfig, PlainListTracker

        cfg = PlainListConfig(
            name=name,
            source="/fake/path",
            set_v4=f"nfset_{name}_v4",
            max_prefixes=10_000_000,
        )
        probe_json = _make_probe_json()

        def side_effect(script, netns=None, json_output=False):
            if json_output:
                return probe_json
            return None

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = side_effect
        tracker = PlainListTracker([cfg], fake_nft, {})
        return tracker, fake_nft

    def test_large_new_takes_swap_path(self):
        import shorewalld.iplist.plain as plain_mod
        tracker, _ = self._make_plain_tracker("plain_swap")
        new = {f"10.{i >> 8 & 0xff}.{i & 0xff}.1/32" for i in range(60000)}

        with patch.object(plain_mod, "_SWAP_ENABLED", True), \
             patch.object(plain_mod, "_SWAP_THRESHOLD_ABS", 50000):
            asyncio.run(
                tracker._apply_set(
                    None, "nfset_plain_swap_v4", set(), new, "plain_swap", "v4"
                )
            )

        paths = tracker._metrics._apply_paths.get(("plain_swap", "v4"), {})
        assert paths.get("swap", 0) >= 1
        assert paths.get("diff", 0) == 0

    def test_fallback_probe_failure_plain(self):
        import shorewalld.iplist.plain as plain_mod
        from shorewalld.iplist.plain import PlainListConfig, PlainListTracker

        cfg = PlainListConfig(
            name="plain_probe_fail",
            source="/fake",
            set_v4="nfset_ppf_v4",
            max_prefixes=10_000_000,
        )

        def side_effect(script, netns=None, json_output=False):
            if json_output:
                raise RuntimeError("probe denied")
            return None

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = side_effect
        tracker = PlainListTracker([cfg], fake_nft, {})

        new = {f"10.0.0.{i}/32" for i in range(60000)}

        with patch.object(plain_mod, "_SWAP_ENABLED", True), \
             patch.object(plain_mod, "_SWAP_THRESHOLD_ABS", 50000):
            asyncio.run(
                tracker._apply_set(
                    None, "nfset_ppf_v4", set(), new, "plain_probe_fail", "v4"
                )
            )

        paths = tracker._metrics._apply_paths.get(("plain_probe_fail", "v4"), {})
        assert paths.get("fallback-from-swap", 0) >= 1
        assert paths.get("diff", 0) >= 1


# ---------------------------------------------------------------------------
# 14. _parse_set_probe helper
# ---------------------------------------------------------------------------


class TestParseSetProbe:
    def test_full_probe_result(self):
        from shorewalld.iplist.tracker import _parse_set_probe
        probe = {
            "nftables": [
                {"metainfo": {}},
                {"set": {"type": "ipv4_addr", "flags": ["timeout", "interval"], "size": 65536}},
            ]
        }
        t, f, s = _parse_set_probe(probe)
        assert t == "ipv4_addr"
        assert f == ["timeout", "interval"]
        assert s == 65536

    def test_no_flags_key(self):
        from shorewalld.iplist.tracker import _parse_set_probe
        probe = {"nftables": [{"set": {"type": "ipv6_addr", "size": 32768}}]}
        t, f, s = _parse_set_probe(probe)
        assert t == "ipv6_addr"
        assert f == []
        assert s == 32768

    def test_missing_size_defaults_to_65536(self):
        from shorewalld.iplist.tracker import _parse_set_probe
        probe = {"nftables": [{"set": {"type": "ipv4_addr"}}]}
        _, _, s = _parse_set_probe(probe)
        assert s == 65536

    def test_not_a_dict_raises(self):
        from shorewalld.iplist.tracker import _parse_set_probe
        import pytest
        with pytest.raises(ValueError, match="not a dict"):
            _parse_set_probe("bad")

    def test_no_set_entry_raises(self):
        from shorewalld.iplist.tracker import _parse_set_probe
        import pytest
        with pytest.raises(ValueError, match="no 'set' entry"):
            _parse_set_probe({"nftables": [{"table": {}}]})

    def test_string_flag_coerced_to_list(self):
        """Some libnftables versions return a string instead of a list for flags."""
        from shorewalld.iplist.tracker import _parse_set_probe
        probe = {"nftables": [{"set": {"type": "ipv4_addr", "flags": "interval", "size": 1024}}]}
        _, f, _ = _parse_set_probe(probe)
        assert f == ["interval"]


# ---------------------------------------------------------------------------
# 15. Flags string reconstruction in swap script
# ---------------------------------------------------------------------------


class TestFlagsStringInSwapScript:
    """Verify the generated swap script contains correctly formatted flags."""

    def _run_swap_and_capture(self, flags, declared_size=262144):
        import shorewalld.iplist.tracker as mod
        from shorewalld.iplist.tracker import IpListTracker

        class _FakeCfg:
            name = "flags_test"
            provider = "aws"
            set_v4 = "nfset_flags_v4"
            set_v6 = ""
            refresh = 3600
            max_prefixes = 10_000_000
            filters: list = []

        probe_json = _make_probe_json(flags=flags, size=declared_size)
        captured: list[str] = []

        def side_effect(script, netns=None, json_output=False):
            if json_output:
                return probe_json
            captured.append(script)
            return None

        fake_nft = MagicMock()
        fake_nft.cmd.side_effect = side_effect

        tracker = IpListTracker(
            configs=[_FakeCfg()],
            nft=fake_nft,
            profiles={},
        )
        new = {f"10.0.0.{i}/32" for i in range(60000)}

        with patch.object(mod, "_SWAP_ENABLED", True), \
             patch.object(mod, "_SWAP_THRESHOLD_ABS", 50000):
            asyncio.run(
                tracker._apply_set("", "nfset_flags_v4", set(), new, "flags_test", "v4")
            )
        return captured

    def test_two_flags(self):
        scripts = self._run_swap_and_capture(["timeout", "interval"])
        add_set_script = next(s for s in scripts if "add set" in s)
        assert "flags timeout, interval" in add_set_script

    def test_single_flag(self):
        scripts = self._run_swap_and_capture(["interval"])
        add_set_script = next(s for s in scripts if "add set" in s)
        assert "flags interval" in add_set_script

    def test_no_flags(self):
        scripts = self._run_swap_and_capture([])
        # The swap script is one multi-line string; find the "add set" line.
        add_set_script = next(s for s in scripts if "add set" in s)
        # Extract only the "add set" line(s) — flags keyword must not appear there.
        add_set_lines = [ln for ln in add_set_script.splitlines() if "add set" in ln]
        for line in add_set_lines:
            assert " flags " not in line, f"Unexpected 'flags' in add set line: {line!r}"
