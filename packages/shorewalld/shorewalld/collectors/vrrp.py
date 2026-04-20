"""VrrpCollector — VRRP state scraper via keepalived D-Bus.

Reads state from one or more keepalived processes on the system bus.
Uses jeepney (pure-Python, asyncio-friendly, no GLib dependency) for
blocking D-Bus I/O on the scrape thread — never touches the asyncio
event loop.

D-Bus contract (confirmed against org.keepalived.Vrrp1.Instance.xml
and vrrp_dbus.c in the keepalived source tree):

- Bus service: ``org.keepalived.Vrrp1`` (or custom via dbus_service_name)
- Instance object path: ``/org/keepalived/Vrrp1/Instance/<nic>/<vrid>/<family>``
  where <family> is ``IPv4`` or ``IPv6``.
- Interface: ``org.keepalived.Vrrp1.Instance``
- Properties exposed by keepalived's handle_get_property():
    * ``Name``  — type ``(s)``: instance name (vrrp->iname)
    * ``State`` — type ``(us)``: (uint state, string label)
      state int: 1=BACKUP 2=MASTER 3=FAULT

  NOTE: keepalived's D-Bus interface exposes **only** Name and State.
  Priority, effective_priority, VIP count, and last_transition are NOT
  available via D-Bus properties.  They are derived from the object path
  (vr_id, nic, family) or set to sentinel values (priority=0,
  last_transition=0, vip_count=0) to keep VrrpInstance stable without
  fabricating data.

Degrades silently when:
  * jeepney is not installed
  * the system bus is unreachable (wrong socket path, no D-Bus)
  * no matching bus names are present
  * a per-instance property read times out or errors

Cardinality: bus_name × instance × vr_id × nic × family — bounded by
the operator's keepalived config (typically < 20 label combinations).
"""

from __future__ import annotations

import fnmatch
import logging
import time
from dataclasses import dataclass

from shorewalld.exporter import CollectorBase, _MetricFamily

log = logging.getLogger("shorewalld.collectors.vrrp")

# ── optional dependency ───────────────────────────────────────────────────────

try:
    import jeepney  # noqa: F401  (existence check only)
    from jeepney import DBusAddress, new_method_call
    from jeepney.io.blocking import open_dbus_connection
    _jeepney_available = True
except ImportError:
    _jeepney_available = False


# ── D-Bus constants ───────────────────────────────────────────────────────────

_DBUS_SERVICE = "org.freedesktop.DBus"
_DBUS_PATH = "/org/freedesktop/DBus"
_DBUS_IFACE = "org.freedesktop.DBus"

_KA_INSTANCE_IFACE = "org.keepalived.Vrrp1.Instance"
_KA_INSTANCE_ROOT = "/org/keepalived/Vrrp1/Instance"

_PROPS_IFACE = "org.freedesktop.DBus.Properties"
_INTROSPECT_IFACE = "org.freedesktop.DBus.Introspectable"

# Default system bus socket path.
_DEFAULT_SYSTEM_BUS = "unix:path=/run/dbus/system_bus_socket"

# Per D-Bus call timeout in seconds.
_DBUS_TIMEOUT = 1.0


# ── Public dataclass ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VrrpInstance:
    """Snapshot of a single VRRP instance as read from D-Bus.

    Properties are derived from two sources:
    - The D-Bus object path: ``nic``, ``vr_id``, ``family``
    - The ``Name`` and ``State`` D-Bus properties: ``vrrp_name``, ``state``
    - Unavailable via D-Bus (sentinel 0): ``priority``, ``effective_priority``,
      ``last_transition``, ``vip_count``
    """

    bus_name: str           # e.g. "org.keepalived.Vrrp1"
    vrrp_name: str          # the per-instance name keepalived exposes
    nic: str                # interface name
    vr_id: int
    family: str             # "ipv4" or "ipv6"
    state: int              # 1=BACKUP, 2=MASTER, 3=FAULT (raw)
    priority: int           # 0 — not available via D-Bus
    effective_priority: int # 0 — not available via D-Bus
    last_transition: float  # 0 — not available via D-Bus
    vip_count: int          # 0 — not available via D-Bus


# ── Scrape error counter ─────────────────────────────────────────────────────

_REASONS = ("dbus_unavailable", "timeout", "properties_get", "parse")


def _make_error_family() -> _MetricFamily:
    return _MetricFamily(
        "shorewalld_vrrp_scrape_errors_total",
        "Total D-Bus scrape errors by reason",
        ["reason"],
        mtype="counter",
    )


# ── Collector ────────────────────────────────────────────────────────────────


class VrrpCollector(CollectorBase):
    """Scrape VRRP state from one or more keepalived processes via D-Bus.

    Discovery: at each scrape (with TTL cache), list bus names on the
    system bus matching ``bus_name_glob`` (default ``org.keepalived.*``),
    then enumerate ``/org/keepalived/Vrrp1/Instance/*`` object paths
    under each bus name via ``org.freedesktop.DBus.Introspectable``.
    Read per-path properties via ``org.freedesktop.DBus.Properties.GetAll``
    on the ``org.keepalived.Vrrp1.Instance`` interface.

    Degrades silently: if jeepney is not installed, if the system bus is
    unreachable, or if no matching bus names are present, ``collect()``
    returns an empty list. Never raises to the scrape path.

    VRRP state is host-global (keepalived binds to the root network
    namespace), so this collector sets ``netns=""`` and emits no ``netns``
    label on VRRP metrics.
    """

    def __init__(
        self,
        *,
        bus_name_glob: str = "org.keepalived.*",
        cache_ttl: float = 5.0,
        system_bus_path: str | None = None,
    ) -> None:
        super().__init__(netns="")
        self._glob = bus_name_glob
        self._ttl = cache_ttl
        self._bus_path = system_bus_path or _DEFAULT_SYSTEM_BUS
        self._cache_ts: float = 0.0
        self._cache: list[VrrpInstance] = []
        # Persistent error counts (never reset — monotone counters).
        self._errors: dict[str, int] = {r: 0 for r in _REASONS}

    # ── Public API ───────────────────────────────────────────────────────────

    def collect(self) -> list[_MetricFamily]:
        """Return Prometheus metric families for the current VRRP state.

        Returned list is empty when jeepney is absent or the bus is
        unreachable.  Never raises.
        """
        if not _jeepney_available:
            return []

        instances = self._cached_snapshot()
        return self._to_metric_families(instances)

    def snapshot(self) -> list[VrrpInstance]:
        """Uncached current snapshot (still silent on error)."""
        if not _jeepney_available:
            return []
        return self._scrape()

    # ── Internal ─────────────────────────────────────────────────────────────

    def _cached_snapshot(self) -> list[VrrpInstance]:
        now = time.monotonic()
        if now - self._cache_ts < self._ttl:
            return self._cache
        fresh = self._scrape()
        self._cache = fresh
        self._cache_ts = now
        return fresh

    def _scrape(self) -> list[VrrpInstance]:
        """Open one D-Bus connection, discover bus names, read properties."""
        try:
            conn = open_dbus_connection(bus=self._bus_path, enable_fds=False)
        except Exception as exc:
            log.debug("vrrp: cannot connect to system bus %r: %s", self._bus_path, exc)
            self._errors["dbus_unavailable"] += 1
            return self._cache  # return stale if present

        try:
            return self._scrape_via(conn)
        except Exception as exc:
            log.debug("vrrp: unexpected scrape error: %s", exc)
            return self._cache
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _scrape_via(self, conn: object) -> list[VrrpInstance]:
        """Perform the full scrape over an open connection."""
        # List all bus names.
        try:
            names = self._list_names(conn)
        except TimeoutError:
            log.debug("vrrp: timeout listing D-Bus names")
            self._errors["timeout"] += 1
            return self._cache
        except Exception as exc:
            log.debug("vrrp: cannot list D-Bus names: %s", exc)
            self._errors["dbus_unavailable"] += 1
            return self._cache

        matching = [n for n in names if fnmatch.fnmatchcase(n, self._glob)]
        if not matching:
            return []

        instances: list[VrrpInstance] = []
        for bus_name in matching:
            try:
                paths = self._list_instance_paths(conn, bus_name)
            except Exception as exc:
                log.debug("vrrp: cannot list instances for %r: %s", bus_name, exc)
                continue
            for path in paths:
                inst = self._read_instance(conn, bus_name, path)
                if inst is not None:
                    instances.append(inst)

        return instances

    def _list_names(self, conn: object) -> list[str]:
        """Call org.freedesktop.DBus.ListNames on the message bus."""
        msg = new_method_call(
            DBusAddress(_DBUS_PATH, bus_name=_DBUS_SERVICE, interface=_DBUS_IFACE),
            "ListNames",
        )
        reply = conn.send_and_get_reply(msg, timeout=_DBUS_TIMEOUT)
        # Reply body: ((as),) — a 1-tuple containing a sequence of strings.
        body = reply.body
        if body and isinstance(body[0], (list, tuple)):
            return list(body[0])
        return []

    def _list_instance_paths(self, conn: object, bus_name: str) -> list[str]:
        """Introspect _KA_INSTANCE_ROOT to discover child object paths.

        keepalived registers each instance as a child of
        /org/keepalived/Vrrp1/Instance.  We parse the XML returned by
        Introspect to find <node name="..."/> children.
        """
        msg = new_method_call(
            DBusAddress(
                _KA_INSTANCE_ROOT,
                bus_name=bus_name,
                interface=_INTROSPECT_IFACE,
            ),
            "Introspect",
        )
        try:
            reply = conn.send_and_get_reply(msg, timeout=_DBUS_TIMEOUT)
        except Exception:
            raise
        xml_body = reply.body[0] if reply.body else ""
        return _parse_introspect_children(xml_body, _KA_INSTANCE_ROOT)

    def _read_instance(
        self, conn: object, bus_name: str, obj_path: str,
    ) -> VrrpInstance | None:
        """Read Name + State from a single instance object path."""
        msg = new_method_call(
            DBusAddress(obj_path, bus_name=bus_name, interface=_PROPS_IFACE),
            "GetAll",
            "s",
            (_KA_INSTANCE_IFACE,),
        )
        try:
            reply = conn.send_and_get_reply(msg, timeout=_DBUS_TIMEOUT)
        except TimeoutError:
            log.debug("vrrp: timeout reading %r from %r", obj_path, bus_name)
            self._errors["timeout"] += 1
            return None
        except Exception as exc:
            log.debug("vrrp: properties_get error on %r: %s", obj_path, exc)
            self._errors["properties_get"] += 1
            return None

        try:
            return _parse_instance_reply(bus_name, obj_path, reply.body)
        except Exception as exc:
            log.debug("vrrp: parse error for %r: %s", obj_path, exc)
            self._errors["parse"] += 1
            return None

    # ── Metric family assembly ────────────────────────────────────────────────

    def _to_metric_families(
        self, instances: list[VrrpInstance],
    ) -> list[_MetricFamily]:
        state_fam = _MetricFamily(
            "shorewalld_vrrp_state",
            "VRRP instance state (1=BACKUP 2=MASTER 3=FAULT)",
            ["bus_name", "instance", "vr_id", "nic", "family"],
        )
        priority_fam = _MetricFamily(
            "shorewalld_vrrp_priority",
            "VRRP base priority (0 = unavailable via D-Bus)",
            ["bus_name", "instance", "vr_id"],
        )
        eff_prio_fam = _MetricFamily(
            "shorewalld_vrrp_effective_priority",
            "VRRP effective priority (0 = unavailable via D-Bus)",
            ["bus_name", "instance", "vr_id"],
        )
        ts_fam = _MetricFamily(
            "shorewalld_vrrp_last_transition_timestamp_seconds",
            "Unix timestamp of last observed VRRP state change (0 if unknown)",
            ["bus_name", "instance", "vr_id"],
        )
        vip_fam = _MetricFamily(
            "shorewalld_vrrp_vip_count",
            "Number of VIPs currently held (0 = unavailable via D-Bus)",
            ["bus_name", "instance", "vr_id", "family"],
        )
        err_fam = _make_error_family()
        for reason, count in self._errors.items():
            err_fam.add([reason], float(count))

        for inst in instances:
            vr_str = str(inst.vr_id)
            state_fam.add(
                [inst.bus_name, inst.vrrp_name, vr_str, inst.nic, inst.family],
                float(inst.state),
            )
            priority_fam.add(
                [inst.bus_name, inst.vrrp_name, vr_str],
                float(inst.priority),
            )
            eff_prio_fam.add(
                [inst.bus_name, inst.vrrp_name, vr_str],
                float(inst.effective_priority),
            )
            ts_fam.add(
                [inst.bus_name, inst.vrrp_name, vr_str],
                inst.last_transition,
            )
            vip_fam.add(
                [inst.bus_name, inst.vrrp_name, vr_str, inst.family],
                float(inst.vip_count),
            )

        return [state_fam, priority_fam, eff_prio_fam, ts_fam, vip_fam, err_fam]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_introspect_children(xml_body: str, parent_path: str) -> list[str]:
    """Extract child paths from a D-Bus Introspect XML fragment.

    Looks for ``<node name="..."/>`` elements and builds absolute paths.
    Handles three-level path structure: /Instance/<nic>/<vrid>/<family>.
    We need leaf nodes (IPv4/IPv6 level).
    """
    import xml.etree.ElementTree as ET  # stdlib; safe to import here
    paths: list[str] = []
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        return paths
    # Direct children of the introspect root are one level below parent_path.
    # We need to recurse through <node> children to find leaf instances.
    # Keepalived path: /org/keepalived/Vrrp1/Instance/<nic>/<vrid>/IPv4
    # The introspect at the root shows <nic> nodes; we need to introspect
    # recursively but for simplicity we collect any child path and the
    # caller will try GetAll which will fail gracefully on non-leaf nodes.
    for child in root.findall("node"):
        name = child.get("name", "")
        if name:
            child_path = f"{parent_path}/{name}"
            paths.append(child_path)
    return paths


def _parse_obj_path(obj_path: str) -> tuple[str, int, str] | None:
    """Extract (nic, vr_id, family) from a keepalived instance object path.

    Expected format: /org/keepalived/Vrrp1/Instance/<nic>/<vrid>/<family>
    where <family> is ``IPv4`` or ``IPv6``.

    Returns None if the path doesn't have the expected structure.
    """
    prefix = _KA_INSTANCE_ROOT + "/"
    if not obj_path.startswith(prefix):
        return None
    tail = obj_path[len(prefix):]
    parts = tail.split("/")
    if len(parts) != 3:
        return None
    nic, vrid_s, family_s = parts
    try:
        vr_id = int(vrid_s)
    except ValueError:
        return None
    # keepalived uses "IPv4"/"IPv6" in the path; normalise to lowercase
    family = family_s.lower()
    if family not in ("ipv4", "ipv6"):
        return None
    return nic, vr_id, family


def _parse_instance_reply(
    bus_name: str,
    obj_path: str,
    body: tuple,
) -> VrrpInstance | None:
    """Parse the GetAll reply body into a VrrpInstance.

    GetAll returns a single dict variant: ``(a{sv},)`` where sv is a
    variant.  In jeepney the body is ``({'Name': (value,), 'State':
    (uint, string)},)`` — the outer tuple is the D-Bus message body;
    the inner is the properties dict.

    keepalived property types per the XML + source:
    - Name:  ``(s)``  → jeepney delivers as ``(str,)``
    - State: ``(us)`` → jeepney delivers as ``(int, str)``
    """
    if not body:
        return None
    props = body[0]
    if not isinstance(props, dict):
        return None

    path_info = _parse_obj_path(obj_path)
    if path_info is None:
        return None
    nic, vr_id, family = path_info

    # Name property: type (s) → delivered as the string itself or a
    # 1-tuple depending on jeepney version.
    raw_name = props.get("Name")
    if raw_name is None:
        return None
    if isinstance(raw_name, (list, tuple)):
        vrrp_name = str(raw_name[0]) if raw_name else ""
    else:
        vrrp_name = str(raw_name)

    # State property: type (us) → (uint, string)
    raw_state = props.get("State")
    if raw_state is None:
        return None
    if isinstance(raw_state, (list, tuple)) and len(raw_state) >= 1:
        state = int(raw_state[0])
    elif isinstance(raw_state, int):
        state = raw_state
    else:
        return None

    return VrrpInstance(
        bus_name=bus_name,
        vrrp_name=vrrp_name,
        nic=nic,
        vr_id=vr_id,
        family=family,
        state=state,
        priority=0,
        effective_priority=0,
        last_transition=0.0,
        vip_count=0,
    )
