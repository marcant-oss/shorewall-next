"""Wave 8 — unit tests for VrrpCollector.

Covers:
1. jeepney-missing path: collect() returns empty, no error.
2. dbus-unreachable path: collect() emits scrape_errors_total with
   reason=dbus_unavailable, no instance metrics.
3. Happy path with fake D-Bus: two instances (one MASTER v4, one
   BACKUP v6) → correct metric samples with correct labels.
4. TTL cache: collect() called twice within cache_ttl → underlying
   D-Bus call count == 1.
5. Glob filter: two bus names, only the matching one is scraped.

No real keepalived or D-Bus daemon is used.  All tests are offline.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

# Import via shorewalld.exporter which is the safe re-export path that
# resolves the collectors/__init__.py ↔ exporter.py circular import.
from shorewalld.exporter import VrrpCollector, VrrpInstance, _MetricFamily

# Private helpers live only in the vrrp module; import after the circular
# import has been resolved by the shorewalld.exporter import above.
from shorewalld.collectors.vrrp import (
    _parse_introspect_children,
    _parse_instance_reply,
    _parse_obj_path,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_family(families: list[_MetricFamily], name: str) -> _MetricFamily:
    for f in families:
        if f.name == name:
            return f
    raise AssertionError(f"no metric family {name!r} in {[f.name for f in families]}")


def _samples_dict(fam: _MetricFamily) -> dict[tuple, float]:
    return {tuple(lv): v for lv, v in fam.samples}


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------

class TestParseObjPath:
    def test_valid_ipv4(self):
        result = _parse_obj_path("/org/keepalived/Vrrp1/Instance/eth0/51/IPv4")
        assert result == ("eth0", 51, "ipv4")

    def test_valid_ipv6(self):
        result = _parse_obj_path("/org/keepalived/Vrrp1/Instance/bond0_20/10/IPv6")
        assert result == ("bond0_20", 10, "ipv6")

    def test_too_short(self):
        assert _parse_obj_path("/org/keepalived/Vrrp1/Instance/eth0/51") is None

    def test_wrong_prefix(self):
        assert _parse_obj_path("/org/keepalived/Other/eth0/51/IPv4") is None

    def test_non_int_vrid(self):
        assert _parse_obj_path("/org/keepalived/Vrrp1/Instance/eth0/abc/IPv4") is None

    def test_unknown_family(self):
        assert _parse_obj_path("/org/keepalived/Vrrp1/Instance/eth0/1/IPv5") is None


class TestParseInstanceReply:
    def test_master_v4(self):
        # keepalived returns (us) State = (2, "MASTER"), (s) Name = ("fw_v4",)
        body = ({"Name": ("fw_v4",), "State": (2, "MASTER")},)
        result = _parse_instance_reply(
            "org.keepalived.Vrrp1",
            "/org/keepalived/Vrrp1/Instance/eth0/51/IPv4",
            body,
        )
        assert result is not None
        assert result.vrrp_name == "fw_v4"
        assert result.state == 2
        assert result.vr_id == 51
        assert result.nic == "eth0"
        assert result.family == "ipv4"

    def test_backup_v6(self):
        body = ({"Name": "fw_v6", "State": (1, "BACKUP")},)
        result = _parse_instance_reply(
            "org.keepalived.Vrrp1",
            "/org/keepalived/Vrrp1/Instance/bond0/10/IPv6",
            body,
        )
        assert result is not None
        assert result.state == 1
        assert result.family == "ipv6"

    def test_missing_name(self):
        body = ({"State": (2, "MASTER")},)
        assert _parse_instance_reply(
            "org.keepalived.Vrrp1",
            "/org/keepalived/Vrrp1/Instance/eth0/1/IPv4",
            body,
        ) is None

    def test_empty_body(self):
        assert _parse_instance_reply(
            "org.keepalived.Vrrp1",
            "/org/keepalived/Vrrp1/Instance/eth0/1/IPv4",
            (),
        ) is None

    def test_bad_path(self):
        body = ({"Name": ("x",), "State": (2, "MASTER")},)
        assert _parse_instance_reply(
            "org.keepalived.Vrrp1",
            "/org/keepalived/Vrrp1/Instance/eth0/1",  # too short
            body,
        ) is None


class TestParseIntrospectChildren:
    def test_basic(self):
        xml = """<?xml version="1.0" ?>
        <node>
          <node name="eth0"/>
          <node name="bond0"/>
        </node>"""
        paths = _parse_introspect_children(xml, "/org/keepalived/Vrrp1/Instance")
        assert "/org/keepalived/Vrrp1/Instance/eth0" in paths
        assert "/org/keepalived/Vrrp1/Instance/bond0" in paths

    def test_malformed_xml(self):
        paths = _parse_introspect_children("<<not xml>>", "/foo")
        assert paths == []


# ---------------------------------------------------------------------------
# VrrpCollector integration-level tests (mocked D-Bus)
# ---------------------------------------------------------------------------

class TestVrrpCollectorJeeppeyMissing:
    """When jeepney is not importable, collect() must return empty silently."""

    def test_returns_empty_when_jeepney_absent(self):
        with patch("shorewalld.collectors.vrrp._jeepney_available", False):
            c = VrrpCollector()
            result = c.collect()
        assert result == []

    def test_snapshot_returns_empty_when_jeepney_absent(self):
        with patch("shorewalld.collectors.vrrp._jeepney_available", False):
            c = VrrpCollector()
            result = c.snapshot()
        assert result == []


class TestVrrpCollectorDbusUnreachable:
    """When the system bus socket is absent, collect() reports dbus_unavailable."""

    def test_dbus_unavailable_emits_error_counter(self):
        c = VrrpCollector(system_bus_path="/tmp/does-not-exist-dbus-socket-xyz")
        families = c.collect()
        # Must emit the error counter family
        err = _get_family(families, "shorewalld_vrrp_scrape_errors_total")
        sd = _samples_dict(err)
        # The dbus_unavailable count must be > 0
        assert sd.get(("dbus_unavailable",), 0) > 0

    def test_no_instance_metrics_when_unreachable(self):
        c = VrrpCollector(system_bus_path="/tmp/does-not-exist-dbus-socket-xyz")
        families = c.collect()
        # The state metric family is always emitted but must have no samples
        # (no instances scraped) when the bus is unreachable.
        state_families = [f for f in families if f.name == "shorewalld_vrrp_state"]
        if state_families:
            assert len(state_families[0].samples) == 0


# ---------------------------------------------------------------------------
# Happy-path with fully mocked D-Bus
# ---------------------------------------------------------------------------

# Two fake instances: MASTER IPv4 on eth0/vrid=51, BACKUP IPv6 on bond0/vrid=10
_FAKE_INSTANCES = [
    VrrpInstance(
        bus_name="org.keepalived.Vrrp1",
        vrrp_name="fw_master_v4",
        nic="eth0",
        vr_id=51,
        family="ipv4",
        state=2,         # MASTER
        priority=0,
        effective_priority=0,
        last_transition=0.0,
        vip_count=0,
    ),
    VrrpInstance(
        bus_name="org.keepalived.Vrrp1",
        vrrp_name="fw_backup_v6",
        nic="bond0",
        vr_id=10,
        family="ipv6",
        state=1,         # BACKUP
        priority=0,
        effective_priority=0,
        last_transition=0.0,
        vip_count=0,
    ),
]


def _make_fake_connection(bus_names: list[str], instances: list[VrrpInstance]):
    """Build a minimal fake jeepney-style connection object.

    The fake implements ``send_and_get_reply`` by dispatching on the
    D-Bus method name read from ``msg.header.fields[HeaderFields.member]``.
    """
    # Import HeaderFields here so the test module resolves after the
    # circular import has been settled by shorewalld.exporter import.
    from jeepney.low_level import HeaderFields

    def _make_reply(body):
        r = MagicMock()
        r.body = body
        return r

    # Build leaf-path XML from instances: one <node> per nic, then the
    # collector only calls Introspect once (at root) so we return all
    # unique nic children.  Leaf-level GetAll is triggered by the path.
    def make_introspect_xml(inst_list: list[VrrpInstance]) -> str:
        nics = sorted({i.nic for i in inst_list})
        nodes = "\n".join(f'<node name="{nic}"/>' for nic in nics)
        return f'<?xml version="1.0"?><node>{nodes}</node>'

    def send_and_get_reply(msg, timeout=1.0):
        fields = msg.header.fields
        member = fields.get(HeaderFields.member, "")
        path = fields.get(HeaderFields.path, "")

        if member == "ListNames":
            return _make_reply((bus_names,))

        if member == "Introspect":
            # Return XML that lists matching instance paths as direct children.
            # We return leaf-path style nodes (nic/vrid/family) assembled
            # from the instances list so _list_instance_paths yields paths
            # that GetAll can match.
            leaf_nodes = []
            for inst in instances:
                fam_str = "IPv4" if inst.family == "ipv4" else "IPv6"
                leaf_path = f"{inst.nic}/{inst.vr_id}/{fam_str}"
                leaf_nodes.append(f'<node name="{leaf_path}"/>')
            xml = f'<?xml version="1.0"?><node>{"".join(leaf_nodes)}</node>'
            return _make_reply((xml,))

        if member == "GetAll":
            parsed = _parse_obj_path(path)
            if parsed is None:
                return _make_reply(({},))
            nic, vr_id, family = parsed
            for inst in instances:
                if inst.nic == nic and inst.vr_id == vr_id and inst.family == family:
                    props = {
                        "Name": (inst.vrrp_name,),
                        "State": (inst.state, "MASTER" if inst.state == 2 else "BACKUP"),
                    }
                    return _make_reply((props,))
            return _make_reply(({},))

        return _make_reply(())

    conn = MagicMock()
    conn.send_and_get_reply.side_effect = send_and_get_reply
    conn.close = MagicMock()
    return conn


class TestVrrpCollectorHappyPath:
    """Mocked D-Bus returns two instances; verify metric output."""

    def _make_collector(self) -> tuple[VrrpCollector, MagicMock]:
        bus_names = ["org.keepalived.Vrrp1", "com.example.other"]
        fake_conn = _make_fake_connection(bus_names, _FAKE_INSTANCES)

        with patch("shorewalld.collectors.vrrp.open_dbus_connection",
                   return_value=fake_conn):
            c = VrrpCollector(cache_ttl=999.0)
            families = c.collect()
        return c, fake_conn, families

    def test_state_metrics_present(self):
        _c, _conn, families = self._make_collector()
        state = _get_family(families, "shorewalld_vrrp_state")
        sd = _samples_dict(state)
        # MASTER v4 instance
        assert sd.get(("org.keepalived.Vrrp1", "fw_master_v4", "51", "eth0", "ipv4")) == 2.0
        # BACKUP v6 instance
        assert sd.get(("org.keepalived.Vrrp1", "fw_backup_v6", "10", "bond0", "ipv6")) == 1.0

    def test_priority_metrics_present(self):
        _c, _conn, families = self._make_collector()
        prio = _get_family(families, "shorewalld_vrrp_priority")
        sd = _samples_dict(prio)
        assert ("org.keepalived.Vrrp1", "fw_master_v4", "51") in sd

    def test_error_counter_zero(self):
        _c, _conn, families = self._make_collector()
        err = _get_family(families, "shorewalld_vrrp_scrape_errors_total")
        sd = _samples_dict(err)
        assert sd.get(("dbus_unavailable",), 0) == 0.0

    def test_two_instances_found(self):
        _c, _conn, families = self._make_collector()
        state = _get_family(families, "shorewalld_vrrp_state")
        assert len(state.samples) == 2


# ---------------------------------------------------------------------------
# TTL cache test
# ---------------------------------------------------------------------------

class TestVrrpCollectorTtlCache:
    """D-Bus call count must be 1 when two collect() calls happen within TTL."""

    def test_cache_prevents_second_scrape(self):
        bus_names = ["org.keepalived.Vrrp1"]
        fake_conn = _make_fake_connection(bus_names, _FAKE_INSTANCES)
        open_conn_calls: list[int] = []

        def fake_open(**kwargs):
            open_conn_calls.append(1)
            return fake_conn

        with patch("shorewalld.collectors.vrrp.open_dbus_connection",
                   side_effect=fake_open):
            c = VrrpCollector(cache_ttl=60.0)
            c.collect()
            c.collect()  # second call within TTL

        # open_dbus_connection should have been called exactly once.
        assert len(open_conn_calls) == 1

    def test_cache_expires_triggers_new_scrape(self):
        bus_names = ["org.keepalived.Vrrp1"]
        fake_conn = _make_fake_connection(bus_names, _FAKE_INSTANCES)
        open_conn_calls: list[int] = []

        def fake_open(**kwargs):
            open_conn_calls.append(1)
            return fake_conn

        with patch("shorewalld.collectors.vrrp.open_dbus_connection",
                   side_effect=fake_open):
            c = VrrpCollector(cache_ttl=0.0)  # zero TTL = always expire
            c.collect()
            c.collect()

        assert len(open_conn_calls) == 2


# ---------------------------------------------------------------------------
# Glob filter test
# ---------------------------------------------------------------------------

class TestVrrpCollectorGlobFilter:
    """Only bus names matching the glob pattern should be scraped."""

    def test_non_matching_bus_not_scraped(self):
        # Two bus names: only one matches org.keepalived.*
        bus_names = ["org.keepalived.Vrrp1", "com.example.other"]
        # The com.example.other bus has an instance that should NOT appear.
        other_inst = VrrpInstance(
            bus_name="com.example.other",
            vrrp_name="should_not_appear",
            nic="eth1",
            vr_id=99,
            family="ipv4",
            state=2,
            priority=0,
            effective_priority=0,
            last_transition=0.0,
            vip_count=0,
        )
        fake_conn = _make_fake_connection(
            bus_names, _FAKE_INSTANCES + [other_inst])

        with patch("shorewalld.collectors.vrrp.open_dbus_connection",
                   return_value=fake_conn):
            c = VrrpCollector(bus_name_glob="org.keepalived.*", cache_ttl=0.0)
            families = c.collect()

        state = _get_family(families, "shorewalld_vrrp_state")
        sd = _samples_dict(state)
        # No sample from the non-matching bus
        assert all(
            lv[0] != "com.example.other"
            for lv in sd
        )

    def test_no_matching_bus_returns_empty_instances(self):
        bus_names = ["com.example.foo", "org.other.service"]
        fake_conn = _make_fake_connection(bus_names, _FAKE_INSTANCES)

        with patch("shorewalld.collectors.vrrp.open_dbus_connection",
                   return_value=fake_conn):
            c = VrrpCollector(bus_name_glob="org.keepalived.*", cache_ttl=0.0)
            families = c.collect()

        # Error counter family present but state family has no samples
        state = _get_family(families, "shorewalld_vrrp_state")
        assert len(state.samples) == 0
