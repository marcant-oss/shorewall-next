"""Tests for DaemonConfig frozen dataclass and Daemon integration.

Covers:
- DaemonConfig is frozen (FrozenInstanceError on assign).
- DaemonConfig uses slots (no __dict__; undeclared attr raises AttributeError).
- Daemon(config=DaemonConfig(...)) uses the typed path — no DeprecationWarning.
- Daemon(prom_host=...) kwargs path emits DeprecationWarning.
- Mixed call (config= + kwargs) emits DeprecationWarning and ignores kwargs.
"""

from __future__ import annotations

import dataclasses
import warnings

import pytest

from shorewalld.daemon_config import DaemonConfig


# ── DaemonConfig invariants ────────────────────────────────────────────────


def _minimal_config(**overrides) -> DaemonConfig:
    """Return a minimal valid DaemonConfig for unit tests."""
    base = dict(
        prom_host="127.0.0.1",
        prom_port=9748,
        api_socket=None,
        netns_spec=[""],
        scrape_interval=30.0,
        reprobe_interval=300.0,
    )
    base.update(overrides)
    return DaemonConfig(**base)


def test_daemonconfig_is_frozen():
    """Assigning to any field after construction must raise FrozenInstanceError."""
    cfg = _minimal_config()
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.prom_port = 9999  # type: ignore[misc]


def test_daemonconfig_is_slots():
    """DaemonConfig must use __slots__; __dict__ must be absent."""
    cfg = _minimal_config()
    assert not hasattr(cfg, "__dict__"), (
        "DaemonConfig has __dict__; slots=True not working")


def test_daemonconfig_undeclared_attr_raises():
    """Setting an undeclared attribute on a slots+frozen dataclass must raise.

    Python raises FrozenInstanceError (a subclass of AttributeError) when
    the instance is frozen, and AttributeError / TypeError when slots are
    active. Either flavour proves that __dict__ assignment is blocked.
    """
    cfg = _minimal_config()
    with pytest.raises((AttributeError, TypeError)):
        cfg.undeclared_field = "oops"  # type: ignore[attr-defined]


def test_daemonconfig_field_count():
    """DaemonConfig exposes exactly the expected number of fields."""
    # 34 fields as of this writing — bump this number if you add a new field,
    # and update the docstring count in daemon_config.py.
    fields = dataclasses.fields(DaemonConfig)
    assert len(fields) == 34, (
        f"DaemonConfig has {len(fields)} fields; update this assertion "
        "if you intentionally added/removed a field")


def test_daemonconfig_defaults_reasonable():
    """Spot-check default values match the former Daemon.__init__ defaults."""
    cfg = _minimal_config()
    assert cfg.scrape_interval == 30.0
    assert cfg.reprobe_interval == 300.0
    assert cfg.peer_heartbeat_interval == 5.0
    assert cfg.state_enabled is True
    assert cfg.state_no_load is False
    assert cfg.state_flush is False
    assert cfg.enable_vrrp_collector is False
    assert cfg.vrrp_snmp_enabled is False
    assert cfg.vrrp_snmp_host == "127.0.0.1"
    assert cfg.vrrp_snmp_port == 161
    assert cfg.vrrp_snmp_community == "public"
    assert cfg.vrrp_snmp_timeout == 1.0
    assert cfg.dns_dedup_refresh_threshold == 0.5
    assert cfg.batch_window_seconds == 0.010
    assert cfg.instances == ()
    assert cfg.iplist_configs == ()


# ── Daemon integration ─────────────────────────────────────────────────────


def test_daemon_config_path_no_deprecation_warning():
    """Daemon(config=DaemonConfig(...)) must NOT emit DeprecationWarning."""
    from shorewalld.core import Daemon

    cfg = _minimal_config()
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        # Must not raise — the config path is the clean path.
        d = Daemon(config=cfg)
    assert d._config is cfg


def test_daemon_kwargs_path_emits_deprecation_warning():
    """Daemon(prom_host=..., ...) legacy kwargs must emit DeprecationWarning."""
    from shorewalld.core import Daemon

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _d = Daemon(
            prom_host="127.0.0.1",
            prom_port=9748,
            api_socket=None,
            netns_spec=[""],
            scrape_interval=30.0,
            reprobe_interval=300.0,
        )

    dep_warnings = [
        w for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "DaemonConfig" in str(w.message)
    ]
    assert dep_warnings, (
        "Expected a DeprecationWarning about DaemonConfig from the kwargs path")


def test_daemon_mixed_call_emits_deprecation_warning():
    """Daemon(config=..., prom_host=...) mixed call must emit DeprecationWarning."""
    from shorewalld.core import Daemon

    cfg = _minimal_config()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _d = Daemon(config=cfg, prom_host="10.0.0.1")

    dep_warnings = [
        w for w in caught
        if issubclass(w.category, DeprecationWarning)
    ]
    assert dep_warnings, (
        "Expected a DeprecationWarning for mixed config= + kwargs call")


def test_daemon_config_fields_accessible_via_properties():
    """Daemon exposes key config fields as read-only properties for back-compat."""
    from shorewalld.core import Daemon

    cfg = _minimal_config(prom_host="192.0.2.1", prom_port=9999)
    d = Daemon(config=cfg)

    assert d.prom_host == "192.0.2.1"
    assert d.prom_port == 9999
    assert d.api_socket is None
    assert d.netns_spec == [""]
    assert d.scrape_interval == 30.0
    assert d.reprobe_interval == 300.0
    assert d._config is cfg


def test_daemon_kwargs_path_constructs_correct_config():
    """Legacy kwargs path builds a DaemonConfig with matching values."""
    from shorewalld.core import Daemon

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        d = Daemon(
            prom_host="127.0.0.1",
            prom_port=9748,
            api_socket="/tmp/test.sock",
            netns_spec=["fw"],
            scrape_interval=60.0,
            reprobe_interval=120.0,
            dns_dedup_refresh_threshold=0.7,
            batch_window_seconds=0.020,
        )

    assert d._config.prom_host == "127.0.0.1"
    assert d._config.prom_port == 9748
    assert d._config.api_socket == "/tmp/test.sock"
    assert d._config.netns_spec == ["fw"]
    assert d._config.scrape_interval == 60.0
    assert d._config.reprobe_interval == 120.0
    assert d._config.dns_dedup_refresh_threshold == 0.7
    assert d._config.batch_window_seconds == 0.020


def test_daemon_missing_required_kwargs_raises():
    """Legacy kwargs path without prom_host/prom_port/netns_spec must raise TypeError."""
    from shorewalld.core import Daemon

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(TypeError, match="prom_host"):
            Daemon()
