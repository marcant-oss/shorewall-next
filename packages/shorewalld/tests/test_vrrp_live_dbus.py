"""integration_dbus — live D-Bus + keepalived integration tests for VrrpCollector.

These tests require:
  - A running dbus-daemon on the system bus
  - keepalived started with ``--dbus`` and at least two VRRP instances
    configured (one MASTER VI_MASTER vrid=51 on dummy0, one BACKUP VI_BACKUP
    vrid=10 on dummy1 — matching the CI keepalived.conf).

Run with:
    pytest -m integration_dbus packages/shorewalld/tests/test_vrrp_live_dbus.py -v

All tests in this module are skipped automatically when the preconditions are
not met (handled by the ``live_dbus`` session fixture in conftest.py).
"""
from __future__ import annotations

import pytest

from shorewalld.exporter import VrrpCollector, _MetricFamily


# ---------------------------------------------------------------------------
# Helpers (duplicated here so this file is standalone-runnable)
# ---------------------------------------------------------------------------

def _get_family(families: list[_MetricFamily], name: str) -> _MetricFamily:
    for f in families:
        if f.name == name:
            return f
    raise AssertionError(f"no metric family {name!r} in {[f.name for f in families]}")


def _samples_dict(fam: _MetricFamily) -> dict[tuple, float]:
    return {tuple(lv): v for lv, v in fam.samples}


# ---------------------------------------------------------------------------
# Live D-Bus tests
# ---------------------------------------------------------------------------

@pytest.mark.integration_dbus
class TestVrrpCollectorLiveDbus:
    """VrrpCollector against a real dbus-daemon + keepalived process.

    Uses the ``live_dbus`` fixture from conftest.py which skips automatically
    when keepalived/dbus are not available.  The CI job writes a minimal
    keepalived.conf with VI_MASTER (vrid=51, dummy0) and VI_BACKUP (vrid=10,
    dummy1) before running these tests.
    """

    def test_collect_returns_nonempty(self, live_dbus):
        """collect() must return at least one metric family when keepalived is up."""
        c = VrrpCollector(cache_ttl=0.0)
        families = c.collect()
        assert families, "expected non-empty metric families from live keepalived"

    def test_state_family_present(self, live_dbus):
        """shorewalld_vrrp_state family must be present and have at least one sample."""
        c = VrrpCollector(cache_ttl=0.0)
        families = c.collect()
        state = _get_family(families, "shorewalld_vrrp_state")
        assert len(state.samples) >= 1, (
            "expected at least one VRRP instance in shorewalld_vrrp_state"
        )

    def test_master_instance_found(self, live_dbus):
        """The MASTER instance (vrid=51) must appear with state=2."""
        c = VrrpCollector(cache_ttl=0.0)
        families = c.collect()
        state = _get_family(families, "shorewalld_vrrp_state")
        sd = _samples_dict(state)

        # Find any sample with vr_id==51 and state==2.0 (MASTER).
        master_samples = [
            (labels, val) for labels, val in sd.items()
            if len(labels) >= 3 and labels[2] == "51" and val == 2.0
        ]
        assert master_samples, (
            f"no MASTER (state=2) sample with vr_id=51 found; got: {dict(sd)}"
        )

    def test_backup_instance_found(self, live_dbus):
        """The BACKUP instance (vrid=10) must appear with state=1."""
        c = VrrpCollector(cache_ttl=0.0)
        families = c.collect()
        state = _get_family(families, "shorewalld_vrrp_state")
        sd = _samples_dict(state)

        # Find any sample with vr_id==10 and state==1.0 (BACKUP).
        backup_samples = [
            (labels, val) for labels, val in sd.items()
            if len(labels) >= 3 and labels[2] == "10" and val == 1.0
        ]
        assert backup_samples, (
            f"no BACKUP (state=1) sample with vr_id=10 found; got: {dict(sd)}"
        )

    def test_bus_name_label_is_vrrp1(self, live_dbus):
        """All state samples must carry org.keepalived.Vrrp1 as bus_name."""
        c = VrrpCollector(cache_ttl=0.0)
        families = c.collect()
        state = _get_family(families, "shorewalld_vrrp_state")
        for labels, _val in state.samples:
            assert labels[0] == "org.keepalived.Vrrp1", (
                f"unexpected bus_name label: {labels[0]!r}"
            )

    def test_error_counter_zero_on_healthy_bus(self, live_dbus):
        """dbus_unavailable counter must be 0 when bus + keepalived are up."""
        c = VrrpCollector(cache_ttl=0.0)
        families = c.collect()
        err = _get_family(families, "shorewalld_vrrp_scrape_errors_total")
        sd = _samples_dict(err)
        assert sd.get(("dbus_unavailable",), 0.0) == 0.0, (
            f"dbus_unavailable > 0 despite live bus: {sd}"
        )

    def test_snapshot_matches_collect(self, live_dbus):
        """snapshot() must return the same instances as collect() produces."""
        c = VrrpCollector(cache_ttl=0.0)
        instances = c.snapshot()
        families = c.collect()
        state = _get_family(families, "shorewalld_vrrp_state")
        # Number of VrrpInstance objects must equal number of state samples.
        assert len(instances) == len(state.samples), (
            f"snapshot() returned {len(instances)} instances but "
            f"collect() has {len(state.samples)} state samples"
        )
