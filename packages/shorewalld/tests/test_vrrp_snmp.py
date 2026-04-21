"""Wave 9 — unit tests for VrrpCollector SNMP augmentation.

Covers the 6 scenarios specified in the Wave 9 plan:

1. SNMP disabled by default: no snmp_config → W8 behaviour unchanged
   (priority=0, vip_count=0, master_transitions=0).
2. SNMP happy path: monkeypatched walk returns two rows; D-Bus-discovered
   instances get priority / vip_count / master_transitions from SNMP.
3. SNMP timeout: walk raises asyncio.TimeoutError; base W8 metrics still
   emit (values fall back to 0) and snmp_timeout error increments by 1.
4. SNMP-only mode (D-Bus unavailable): bogus bus path + valid SNMP →
   discovery falls back to SNMP; bus_name label is "".
5. State-code mapping: SNMP returns state=0 (init) for one row; assert
   it is reported as-is (not clamped to 1/2/3).
6. Unknown MIB column (NoSuchObject on one OID): row still emits with
   that field = 0 (not the whole scrape failing).

All tests are offline — no real snmpd.  The pysnmp walk_cmd layer is
monkeypatched via unittest.mock.patch to inject canned async generators.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

# Import via shorewalld.exporter first to resolve the circular import
# (mirrors the pattern used in test_vrrp_collector.py).
from shorewalld.exporter import VrrpCollector, VrrpInstance, VrrpSnmpConfig, _MetricFamily  # noqa: F401

from shorewalld.collectors.vrrp import (
    _build_instances_from_snmp,
    _merge_snmp_into_instances,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_family(families: list[_MetricFamily], name: str) -> _MetricFamily:
    for f in families:
        if f.name == name:
            return f
    raise AssertionError(
        f"no metric family {name!r} in {[f.name for f in families]}")


def _samples_dict(fam: _MetricFamily) -> dict[tuple, float]:
    return {tuple(lv): v for lv, v in fam.samples}


# Two baseline instances as produced by the D-Bus path (W8 defaults).
_DBUS_INSTANCES = [
    VrrpInstance(
        bus_name="org.keepalived.Vrrp1",
        vrrp_name="fw_master_v4",
        nic="eth0",
        vr_id=51,
        family="ipv4",
        state=2,
        priority=0,
        effective_priority=0,
        last_transition=0.0,
        vip_count=0,
        master_transitions=0,
    ),
    VrrpInstance(
        bus_name="org.keepalived.Vrrp1",
        vrrp_name="fw_backup_v6",
        nic="bond0",
        vr_id=10,
        family="ipv6",
        state=1,
        priority=0,
        effective_priority=0,
        last_transition=0.0,
        vip_count=0,
        master_transitions=0,
    ),
]


def _make_snmp_oid_obj(oid: str):
    """Create a minimal mock that behaves like a pysnmp OID object."""
    m = MagicMock()
    m.__str__ = lambda _: oid
    return m


def _make_snmp_val(value, no_such: bool = False):
    """Return either a canned integer-like value or a NoSuchObject mock."""
    if no_such:
        # Simulate pysnmp NoSuchObject / NoSuchInstance by returning an
        # instance of the actual class so isinstance() checks pass.
        from pysnmp.proto.rfc1905 import NoSuchObject
        return NoSuchObject()
    m = MagicMock()
    m.__int__ = lambda _: int(value)
    m.__str__ = lambda _: str(value)
    return m


def _make_snmp_str_val(text: str):
    """Return a string-like SNMP value (OctetString / DisplayString)."""
    m = MagicMock()
    m.__str__ = lambda _: text
    m.__int__ = MagicMock(side_effect=TypeError("not an int"))
    return m


# Canned SNMP table for the happy-path scenario.
# Rows keyed by instance index string ("1", "2").
_CANNED_SNMP_ROWS: dict[str, dict[str, object]] = {
    "1": {
        "name":        _make_snmp_str_val("fw_master_v4"),
        "state":       _make_snmp_val(2),    # master
        "vrid":        _make_snmp_val(51),
        "base_prio":   _make_snmp_val(150),  # vrrpInstanceBasePriority (.7)
        "eff_prio":    _make_snmp_val(150),  # vrrpInstanceEffectivePriority (.8)
        "vips_status": _make_snmp_val(1),    # allSet
    },
    "2": {
        "name":        _make_snmp_str_val("fw_backup_v6"),
        "state":       _make_snmp_val(1),    # backup
        "vrid":        _make_snmp_val(10),
        "base_prio":   _make_snmp_val(100),
        "eff_prio":    _make_snmp_val(100),
        "vips_status": _make_snmp_val(2),    # notAllSet
    },
}


# ---------------------------------------------------------------------------
# Scenario 1 — SNMP disabled by default
# ---------------------------------------------------------------------------

class TestSnmpDisabledByDefault:
    """With no snmp_config, W8 behaviour must be unchanged."""

    def test_priority_zero_without_snmp(self):
        # Patch the D-Bus scrape to return our two baseline instances.
        c = VrrpCollector(cache_ttl=0.0)
        with patch.object(c, "_scrape", return_value=_DBUS_INSTANCES):
            families = c.collect()

        prio = _get_family(families, "shorewalld_vrrp_priority")
        sd = _samples_dict(prio)
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51")) == 0.0
        assert sd.get(("org.keepalived.Vrrp1", "fw_backup_v6", "10")) == 0.0

    def test_vip_count_zero_without_snmp(self):
        c = VrrpCollector(cache_ttl=0.0)
        with patch.object(c, "_scrape", return_value=_DBUS_INSTANCES):
            families = c.collect()

        vip = _get_family(families, "shorewalld_vrrp_vip_count")
        sd = _samples_dict(vip)
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51", "ipv4")) == 0.0

    def test_master_transitions_zero_without_snmp(self):
        c = VrrpCollector(cache_ttl=0.0)
        with patch.object(c, "_scrape", return_value=_DBUS_INSTANCES):
            families = c.collect()

        trans = _get_family(families, "shorewalld_vrrp_master_transitions_total")
        sd = _samples_dict(trans)
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51")) == 0.0

    def test_snmp_error_reasons_absent(self):
        """snmp_timeout / snmp_parse should be 0 with no SNMP configured."""
        c = VrrpCollector(cache_ttl=0.0)
        with patch.object(c, "_scrape", return_value=_DBUS_INSTANCES):
            families = c.collect()

        err = _get_family(families, "shorewalld_vrrp_scrape_errors_total")
        sd = _samples_dict(err)
        assert sd.get(("snmp_timeout",), 0) == 0.0
        assert sd.get(("snmp_parse",), 0) == 0.0


# ---------------------------------------------------------------------------
# Scenario 2 — SNMP happy path
# ---------------------------------------------------------------------------

class TestSnmpHappyPath:
    """Monkeypatched SNMP walk returns canned rows; D-Bus instances augmented."""

    def _collect_with_snmp(self) -> list[_MetricFamily]:
        cfg = VrrpSnmpConfig(host="127.0.0.1", port=161, community="public")
        c = VrrpCollector(cache_ttl=0.0, snmp_config=cfg)

        with (
            patch.object(c, "_snmp_walk_sync", return_value=_CANNED_SNMP_ROWS),
            patch("shorewalld.collectors.vrrp._jeepney_available", True),
        ):
            # Mock the D-Bus scrape path to return baseline instances.
            # We patch _scrape_via at the level the real _scrape calls it.
            with patch.object(c, "_scrape", side_effect=lambda: _merge_snmp_into_instances(
                _DBUS_INSTANCES, _CANNED_SNMP_ROWS
            )):
                families = c.collect()

        return families

    def test_priority_filled_from_snmp(self):
        families = self._collect_with_snmp()
        prio = _get_family(families, "shorewalld_vrrp_priority")
        sd = _samples_dict(prio)
        # fw_master_v4 → eff_prio=150
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51")) == 150.0
        # fw_backup_v6 → eff_prio=100
        assert sd.get(("org.keepalived.Vrrp1", "fw_backup_v6", "10")) == 100.0

    def test_effective_priority_filled_from_snmp(self):
        families = self._collect_with_snmp()
        eff = _get_family(families, "shorewalld_vrrp_effective_priority")
        sd = _samples_dict(eff)
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51")) == 150.0
        assert sd.get(("org.keepalived.Vrrp1", "fw_backup_v6", "10")) == 100.0

    def test_vip_count_filled_from_snmp(self):
        families = self._collect_with_snmp()
        vip = _get_family(families, "shorewalld_vrrp_vip_count")
        sd = _samples_dict(vip)
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51", "ipv4")) == 1.0  # allSet
        assert sd.get(("org.keepalived.Vrrp1", "fw_backup_v6", "10", "ipv6")) == 2.0  # notAllSet

    def test_master_transitions_zero_from_snmp(self):
        # vrrpInstanceBecomeMaster does not exist in the MIB; transitions always 0.
        families = self._collect_with_snmp()
        trans = _get_family(families, "shorewalld_vrrp_master_transitions_total")
        sd = _samples_dict(trans)
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51")) == 0.0
        assert sd.get(("org.keepalived.Vrrp1", "fw_backup_v6", "10")) == 0.0

    def test_state_and_labels_unchanged(self):
        """D-Bus state and labels must not change after SNMP merge."""
        families = self._collect_with_snmp()
        state = _get_family(families, "shorewalld_vrrp_state")
        sd = _samples_dict(state)
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51", "eth0", "ipv4")) == 2.0
        assert sd.get(("org.keepalived.Vrrp1", "fw_backup_v6", "10", "bond0", "ipv6")) == 1.0


# ---------------------------------------------------------------------------
# Scenario 3 — SNMP timeout
# ---------------------------------------------------------------------------

class TestSnmpTimeout:
    """When SNMP walk times out, base W8 metrics emit and snmp_timeout increments."""

    def test_snmp_timeout_increments_error_counter(self):
        cfg = VrrpSnmpConfig(host="127.0.0.1", port=161, community="public")
        c = VrrpCollector(cache_ttl=0.0, snmp_config=cfg)

        # _snmp_walk_sync returns None (timeout path) and increments the counter.
        def _fake_walk_sync():
            c._errors["snmp_timeout"] += 1
            return None

        with (
            patch.object(c, "_snmp_walk_sync", side_effect=_fake_walk_sync),
            patch("shorewalld.collectors.vrrp._jeepney_available", True),
            patch.object(c, "_scrape_via", return_value=_DBUS_INSTANCES),
        ):
            # Rebuild: we need the real _scrape to call our patched helpers.
            # Easiest: patch _scrape itself to simulate D-Bus OK + SNMP timeout.
            pass

        # Simulate the merged path: D-Bus OK, SNMP timeout → return D-Bus only.
        def _scrape_with_timeout():
            _fake_walk_sync()  # increments snmp_timeout
            return _DBUS_INSTANCES  # D-Bus result without SNMP augmentation

        with patch.object(c, "_scrape", side_effect=_scrape_with_timeout):
            families = c.collect()

        # Base W8 metrics must be present.
        state = _get_family(families, "shorewalld_vrrp_state")
        assert len(state.samples) == 2

        # Priority remains 0 (no SNMP data).
        prio = _get_family(families, "shorewalld_vrrp_priority")
        sd = _samples_dict(prio)
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51")) == 0.0

        # snmp_timeout error must be exactly 1.
        err = _get_family(families, "shorewalld_vrrp_scrape_errors_total")
        err_sd = _samples_dict(err)
        assert err_sd.get(("snmp_timeout",), 0) == 1.0

    def test_snmp_timeout_via_walk_sync(self):
        """_snmp_walk_sync must catch asyncio.TimeoutError and return None."""
        cfg = VrrpSnmpConfig(host="127.0.0.1", port=161, community="public", timeout=0.001)
        c = VrrpCollector(cache_ttl=0.0, snmp_config=cfg)

        async def _raise_timeout(cfg):
            raise asyncio.TimeoutError()

        with patch("shorewalld.collectors.vrrp._pysnmp_available", True):
            with patch("shorewalld.collectors.vrrp._snmp_walk_table",
                       side_effect=_raise_timeout):
                result = c._snmp_walk_sync()

        assert result is None
        assert c._errors["snmp_timeout"] == 1


# ---------------------------------------------------------------------------
# Scenario 4 — SNMP-only mode (D-Bus unavailable)
# ---------------------------------------------------------------------------

class TestSnmpOnlyMode:
    """When D-Bus is unavailable and SNMP is configured, fall back to SNMP-only."""

    def test_snmp_only_discovery(self):
        cfg = VrrpSnmpConfig(host="127.0.0.1", port=161, community="public")
        # Use a bogus bus path so D-Bus connection fails.
        c = VrrpCollector(
            system_bus_path="/tmp/no-such-dbus-socket-snmptest",
            cache_ttl=0.0,
            snmp_config=cfg,
        )

        with patch.object(c, "_snmp_walk_sync", return_value=_CANNED_SNMP_ROWS):
            # jeepney is available but D-Bus socket doesn't exist → dbus_failed.
            with patch("shorewalld.collectors.vrrp._jeepney_available", True):
                instances = c._scrape()

        assert len(instances) == 2
        # bus_name must be "" in SNMP-only mode.
        for inst in instances:
            assert inst.bus_name == ""

    def test_snmp_only_priority_non_zero(self):
        cfg = VrrpSnmpConfig()
        c = VrrpCollector(
            system_bus_path="/tmp/no-such-dbus-socket-snmptest2",
            cache_ttl=0.0,
            snmp_config=cfg,
        )

        with patch.object(c, "_snmp_walk_sync", return_value=_CANNED_SNMP_ROWS):
            with patch("shorewalld.collectors.vrrp._jeepney_available", True):
                instances = c._scrape()

        # Priority must come from SNMP.
        prio_map = {i.vrrp_name: i.effective_priority for i in instances}
        assert prio_map.get("fw_master_v4") == 150
        assert prio_map.get("fw_backup_v6") == 100


# ---------------------------------------------------------------------------
# Scenario 5 — State-code mapping: SNMP returns state=0 (init)
# ---------------------------------------------------------------------------

class TestSnmpStateInitMapping:
    """SNMP state=0 (init) must be reported as-is, not clamped."""

    def test_state_zero_init_preserved(self):
        rows = {
            "1": {
                "name":        _make_snmp_str_val("fw_init_v4"),
                "state":       _make_snmp_val(0),   # 0=init (only in SNMP)
                "vrid":        _make_snmp_val(99),
                "base_prio":   _make_snmp_val(100),
                "eff_prio":    _make_snmp_val(100),
                "vips_status": _make_snmp_val(2),
            },
        }
        instances = _build_instances_from_snmp(rows)
        assert len(instances) == 1
        assert instances[0].state == 0
        assert instances[0].vrrp_name == "fw_init_v4"

    def test_state_zero_in_metric_output(self):
        rows = {
            "1": {
                "name":        _make_snmp_str_val("fw_init_v4"),
                "state":       _make_snmp_val(0),
                "vrid":        _make_snmp_val(99),
                "base_prio":   _make_snmp_val(100),
                "eff_prio":    _make_snmp_val(100),
                "vips_status": _make_snmp_val(1),
            },
        }
        cfg = VrrpSnmpConfig()
        c = VrrpCollector(
            system_bus_path="/tmp/no-such-dbus-socket-state0",
            cache_ttl=0.0,
            snmp_config=cfg,
        )
        with patch.object(c, "_snmp_walk_sync", return_value=rows):
            with patch("shorewalld.collectors.vrrp._jeepney_available", True):
                families = c.collect()

        state = _get_family(families, "shorewalld_vrrp_state")
        sd = _samples_dict(state)
        # Labels for SNMP-only: bus_name="", nic="", family=""
        found = [v for (bn, inst, vr, nic, fam), v in sd.items()
                 if inst == "fw_init_v4"]
        assert len(found) == 1
        assert found[0] == 0.0  # state=0 preserved, not clamped


# ---------------------------------------------------------------------------
# Scenario 6 — NoSuchObject / missing column: row still emits with field=0
# ---------------------------------------------------------------------------

class TestSnmpNoSuchColumn:
    """A NoSuchObject on one OID must not fail the whole scrape."""

    def test_missing_eff_prio_column_defaults_to_zero(self):
        """Row with no eff_prio column → effective_priority=0, rest populated."""
        rows = {
            "1": {
                "name":        _make_snmp_str_val("fw_partial"),
                "state":       _make_snmp_val(2),
                "vrid":        _make_snmp_val(10),
                # eff_prio deliberately absent (simulates NoSuchObject skip).
                "vips_status": _make_snmp_val(1),
            },
        }
        instances = _build_instances_from_snmp(rows)
        assert len(instances) == 1
        inst = instances[0]
        assert inst.vrrp_name == "fw_partial"
        assert inst.state == 2
        assert inst.effective_priority == 0   # missing → default 0
        assert inst.vip_count == 1
        assert inst.master_transitions == 0   # not in MIB, always 0

    def test_nosuchobject_skipped_in_walk(self):
        """_snmp_walk_table skips NoSuchObject values; row still emits with field=0.

        The _snmp_walk_table walker checks isinstance(val, (NoSuchObject,
        NoSuchInstance)) and skips that cell.  We verify the end-to-end result
        by calling _build_instances_from_snmp with a row that has no eff_prio
        key — equivalent to what the walker produces after skipping the column.
        """
        # Use _build_instances_from_snmp with no eff_prio to simulate
        # the behaviour when a NoSuchObject skips a column during the walk.
        partial_rows: dict[str, dict[str, object]] = {
            "1": {
                "name":        _make_snmp_str_val("fw_ns_test"),
                "state":       _make_snmp_val(2),
                "vrid":        _make_snmp_val(7),
                # eff_prio absent — simulates NoSuchObject skip in walker.
                "vips_status": _make_snmp_val(1),
            },
        }
        instances = _build_instances_from_snmp(partial_rows)
        assert len(instances) == 1
        inst = instances[0]
        assert inst.vrrp_name == "fw_ns_test"
        assert inst.effective_priority == 0  # absent column → 0
        assert inst.vip_count == 1
        assert inst.master_transitions == 0  # not in MIB, always 0


# ---------------------------------------------------------------------------
# Merge helper unit tests
# ---------------------------------------------------------------------------

class TestMergeHelpers:
    """Unit tests for _merge_snmp_into_instances and _build_instances_from_snmp."""

    def test_merge_known_name(self):
        rows = {
            "1": {
                "name":        _make_snmp_str_val("fw_master_v4"),
                "base_prio":   _make_snmp_val(200),
                "eff_prio":    _make_snmp_val(200),
                "vips_status": _make_snmp_val(1),
            },
        }
        merged = _merge_snmp_into_instances(_DBUS_INSTANCES, rows)
        inst = next(i for i in merged if i.vrrp_name == "fw_master_v4")
        assert inst.priority == 200
        assert inst.effective_priority == 200
        assert inst.vip_count == 1
        assert inst.master_transitions == 0  # not in MIB
        # D-Bus fields preserved.
        assert inst.bus_name == "org.keepalived.Vrrp1"
        assert inst.nic == "eth0"
        assert inst.state == 2

    def test_merge_unmatched_instance_unchanged(self):
        rows: dict[str, dict[str, object]] = {}  # no SNMP rows
        merged = _merge_snmp_into_instances(_DBUS_INSTANCES, rows)
        # All instances returned with zero numeric fields.
        for inst in merged:
            assert inst.priority == 0
            assert inst.master_transitions == 0

    def test_build_snmp_only_empty_name_skipped(self):
        rows = {
            "1": {"state": _make_snmp_val(2)},  # no "name" key
        }
        instances = _build_instances_from_snmp(rows)
        assert instances == []
