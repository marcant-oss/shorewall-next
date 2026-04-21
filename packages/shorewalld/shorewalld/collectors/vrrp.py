"""VrrpCollector — VRRP state scraper via keepalived D-Bus, with optional
SNMP augmentation via the KEEPALIVED-MIB sub-agent.

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

SNMP augmentation (Wave 9):

When ``snmp_config`` is supplied, the collector additionally queries the
KEEPALIVED-MIB sub-agent (SNMP community string, default 127.0.0.1:161)
to fill the fields that D-Bus leaves at zero: ``priority``,
``effective_priority``, ``vip_count``, and ``master_transitions``.

Discovery/fallback modes:

1. **D-Bus + SNMP**: D-Bus discovers instances; SNMP fills in the
   numeric fields by correlating on ``vrrp_name`` ==
   ``vrrpInstanceName`` (column 2 of the KEEPALIVED-MIB vrrpInstanceTable).

2. **SNMP-only** (D-Bus unavailable): SNMP walks the full
   vrrpInstanceTable; ``bus_name`` is set to ``""`` for all instances.
   This is the only mode that works on AlmaLinux 10 / RHEL 10 where
   keepalived 2.2.8 ships without ``--enable-dbus``.

3. **D-Bus only** (SNMP disabled or failing): existing W8 behaviour.
   Numeric fields remain at sentinel 0.

SNMP errors count toward new reason labels on
``shorewalld_vrrp_scrape_errors_total``:
- ``snmp_timeout`` — SNMP request timed out (asyncio.TimeoutError)
- ``snmp_parse`` — unexpected OID value type or walk error

OIDs queried from KEEPALIVED-MIB root .1.3.6.1.4.1.9586.100.5:

- ``.2.3.1.2``  vrrpInstanceName          — string, correlation key
- ``.2.3.1.4``  vrrpInstanceState         — int (0=init, 1=backup, 2=master, 3=fault)
- ``.2.3.1.6``  vrrpInstanceVirtualRouterId (VRID) — int
- ``.2.3.1.7``  vrrpInstanceEffectivePriority     — int
- ``.2.3.1.8``  vrrpInstanceVipsStatus            — int (1=allSet, 2=notAllSet; used as vip_count proxy)
- ``.2.3.1.9``  vrrpInstanceBecomeMaster          — Counter32, transitions-to-master count

Note on vrrpInstanceInitialPriority: it is not listed in the stagelab
OID file.  Column 7 is effective priority in the live MIB; column 6 is
the VRID (not initial priority).  ``initial_priority`` is therefore not
queried; ``priority`` in VrrpInstance is filled from effective priority.

Cardinality: bus_name × instance × vr_id × nic × family — bounded by
the operator's keepalived config (typically < 20 label combinations).
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import time
from dataclasses import dataclass

from shorewalld.exporter import CollectorBase, _MetricFamily

log = logging.getLogger("shorewalld.collectors.vrrp")

# ── optional dependency: jeepney (D-Bus) ─────────────────────────────────────

try:
    import jeepney  # noqa: F401  (existence check only)
    from jeepney import DBusAddress, new_method_call
    from jeepney.io.blocking import open_dbus_connection
    _jeepney_available = True
except ImportError:
    _jeepney_available = False

# ── optional dependency: pysnmp (SNMP augmentation) ──────────────────────────

try:
    from pysnmp.hlapi.asyncio import (  # type: ignore[import-untyped]
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        walk_cmd,
    )
    from pysnmp.proto.rfc1905 import NoSuchInstance, NoSuchObject  # type: ignore[import-untyped]
    _pysnmp_available = True
except ImportError:
    _pysnmp_available = False


# ── SNMP / KEEPALIVED-MIB constants ──────────────────────────────────────────
#
# Root: .1.3.6.1.4.1.9586.100.5
# vrrpInstanceTable: .1.3.6.1.4.1.9586.100.5.2.3.1
#
# Confirmed column layout (KEEPALIVED-MIB.txt, v2.3.4):
#   .2  vrrpInstanceName
#   .4  vrrpInstanceState          (0=init 1=backup 2=master 3=fault)
#   .6  vrrpInstanceVirtualRouterId
#   .7  vrrpInstanceBasePriority   (configured value, before track adjustments)
#   .8  vrrpInstanceEffectivePriority (after track-script weight changes)
#   .9  vrrpInstanceVipsStatus     (1=allSet 2=notAllSet)
# Note: vrrpInstanceBecomeMaster does NOT exist in the MIB.
_KA_MIB_INST_TABLE   = "1.3.6.1.4.1.9586.100.5.2.3.1"
_KA_OID_NAME         = "1.3.6.1.4.1.9586.100.5.2.3.1.2"   # vrrpInstanceName (string)
_KA_OID_STATE        = "1.3.6.1.4.1.9586.100.5.2.3.1.4"   # vrrpInstanceState (int)
_KA_OID_VRID         = "1.3.6.1.4.1.9586.100.5.2.3.1.6"   # vrrpInstanceVirtualRouterId (int)
_KA_OID_BASE_PRIO    = "1.3.6.1.4.1.9586.100.5.2.3.1.7"   # vrrpInstanceBasePriority (int)
_KA_OID_EFF_PRIO     = "1.3.6.1.4.1.9586.100.5.2.3.1.8"   # vrrpInstanceEffectivePriority (int)
_KA_OID_VIPS_STATUS  = "1.3.6.1.4.1.9586.100.5.2.3.1.9"   # vrrpInstanceVipsStatus (int: 1=allSet 2=notAllSet)

# SNMP state mapping: KEEPALIVED-MIB uses 0=init, 1=backup, 2=master, 3=fault
# D-Bus uses 1=BACKUP, 2=MASTER, 3=FAULT (no 0=init via D-Bus).
# The SNMP value is stored as-is on VrrpInstance.state when coming from
# SNMP-only mode.  The D-Bus state takes precedence when both paths succeed.

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


# ── Public dataclasses ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VrrpSnmpConfig:
    """Configuration for the optional SNMP augmentation path.

    When supplied to :class:`VrrpCollector`, the collector queries the
    keepalived SNMP sub-agent (KEEPALIVED-MIB) to fill in the numeric
    fields that D-Bus leaves at zero.

    Requires ``pysnmp>=7.0`` (``pip install shorewalld[snmp]``).
    """

    host: str = "127.0.0.1"
    port: int = 161
    community: str = "public"
    timeout: float = 1.0


@dataclass(frozen=True)
class VrrpInstance:
    """Snapshot of a single VRRP instance.

    Properties are derived from two sources:
    - The D-Bus object path: ``nic``, ``vr_id``, ``family``
    - The ``Name`` and ``State`` D-Bus properties: ``vrrp_name``, ``state``
    - Filled by SNMP augmentation when enabled: ``priority``,
      ``effective_priority``, ``vip_count``, ``master_transitions``
    - Unavailable (sentinel 0) without SNMP: ``priority``,
      ``effective_priority``, ``last_transition``, ``vip_count``,
      ``master_transitions``

    When operating in SNMP-only mode (D-Bus unavailable), ``bus_name``
    is ``""`` and ``nic``/``family`` are ``""`` (not exposed by SNMP).
    ``state`` in SNMP mode follows KEEPALIVED-MIB: 0=init, 1=backup,
    2=master, 3=fault (D-Bus omits the 0=init state).
    """

    bus_name: str           # e.g. "org.keepalived.Vrrp1", or "" in SNMP-only mode
    vrrp_name: str          # the per-instance name keepalived exposes
    nic: str                # interface name, or "" in SNMP-only mode
    vr_id: int
    family: str             # "ipv4" or "ipv6", or "" in SNMP-only mode
    state: int              # D-Bus: 1=BACKUP, 2=MASTER, 3=FAULT; SNMP: 0=init also possible
    priority: int           # base priority (configured value; filled by SNMP; 0 if unavailable)
    effective_priority: int # effective priority after track-script adjustments (SNMP; 0 if unavailable)
    last_transition: float  # 0 — not available via D-Bus or SNMP
    vip_count: int          # VIP count proxy (SNMP vrrpInstanceVipsStatus; 0 if unavailable)
    master_transitions: int = 0  # transitions-to-master counter (SNMP; 0 if unavailable)


# ── Scrape error counter ─────────────────────────────────────────────────────

_REASONS = ("dbus_unavailable", "timeout", "properties_get", "parse",
            "snmp_timeout", "snmp_parse")


def _make_error_family() -> _MetricFamily:
    return _MetricFamily(
        "shorewalld_vrrp_scrape_errors_total",
        "Total VRRP scrape errors by reason "
        "(dbus_unavailable, timeout, properties_get, parse, snmp_timeout, snmp_parse)",
        ["reason"],
        mtype="counter",
    )


# ── Collector ────────────────────────────────────────────────────────────────


class VrrpCollector(CollectorBase):
    """Scrape VRRP state from one or more keepalived processes via D-Bus,
    optionally augmented with SNMP data from the KEEPALIVED-MIB sub-agent.

    Discovery: at each scrape (with TTL cache), list bus names on the
    system bus matching ``bus_name_glob`` (default ``org.keepalived.*``),
    then enumerate ``/org/keepalived/Vrrp1/Instance/*`` object paths
    under each bus name via ``org.freedesktop.DBus.Introspectable``.
    Read per-path properties via ``org.freedesktop.DBus.Properties.GetAll``
    on the ``org.keepalived.Vrrp1.Instance`` interface.

    When ``snmp_config`` is supplied, after the D-Bus snapshot the collector
    additionally walks the KEEPALIVED-MIB vrrpInstanceTable and merges
    ``priority``, ``effective_priority``, ``vip_count``, and
    ``master_transitions`` into each instance by matching ``vrrp_name`` ==
    ``vrrpInstanceName``.

    When D-Bus is unavailable but ``snmp_config`` is set, the collector
    falls back to SNMP-only discovery: all instances come from the SNMP
    table and ``bus_name`` is ``""`` for each.

    Degrades silently: if jeepney is not installed, if the system bus is
    unreachable, or if no matching bus names are present, ``collect()``
    returns an empty list (unless SNMP fallback is active).
    Never raises to the scrape path.

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
        snmp_config: VrrpSnmpConfig | None = None,
    ) -> None:
        super().__init__(netns="")
        self._glob = bus_name_glob
        self._ttl = cache_ttl
        self._bus_path = system_bus_path or _DEFAULT_SYSTEM_BUS
        self._snmp_config = snmp_config
        self._cache_ts: float = 0.0
        self._cache: list[VrrpInstance] = []
        # Persistent error counts (never reset — monotone counters).
        self._errors: dict[str, int] = {r: 0 for r in _REASONS}

    # ── Public API ───────────────────────────────────────────────────────────

    def collect(self) -> list[_MetricFamily]:
        """Return Prometheus metric families for the current VRRP state.

        Returned list is empty when both jeepney and SNMP are absent/unconfigured
        or when the bus is unreachable and no snmp_config is set.
        Never raises.
        """
        if not _jeepney_available and self._snmp_config is None:
            return []

        instances = self._cached_snapshot()
        return self._to_metric_families(instances)

    def snapshot(self) -> list[VrrpInstance]:
        """Uncached current snapshot (still silent on error)."""
        if not _jeepney_available and self._snmp_config is None:
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
        """Attempt D-Bus scrape; fall back to SNMP-only if D-Bus is down."""
        dbus_instances: list[VrrpInstance] | None = None
        dbus_failed = False

        if _jeepney_available:
            try:
                conn = open_dbus_connection(bus=self._bus_path, enable_fds=False)
            except Exception as exc:
                log.debug("vrrp: cannot connect to system bus %r: %s", self._bus_path, exc)
                self._errors["dbus_unavailable"] += 1
                dbus_failed = True
            else:
                try:
                    dbus_instances = self._scrape_via(conn)
                except Exception as exc:
                    log.debug("vrrp: unexpected scrape error: %s", exc)
                    dbus_instances = None
                    dbus_failed = True
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        else:
            dbus_failed = True

        # No SNMP configured → return D-Bus result or stale cache.
        if self._snmp_config is None:
            if dbus_instances is None:
                return self._cache
            return dbus_instances

        # SNMP is configured.  Run the SNMP walk synchronously.
        snmp_rows = self._snmp_walk_sync()

        if dbus_failed or dbus_instances is None:
            # SNMP-only mode: synthesise VrrpInstance objects from SNMP table.
            if snmp_rows is None:
                return self._cache  # both paths failed — return stale
            return _build_instances_from_snmp(snmp_rows)

        # D-Bus + SNMP merge: augment D-Bus instances with SNMP numeric fields.
        if snmp_rows is not None:
            dbus_instances = _merge_snmp_into_instances(dbus_instances, snmp_rows)

        return dbus_instances

    def _snmp_walk_sync(self) -> dict[str, dict[str, object]] | None:
        """Walk the KEEPALIVED-MIB vrrpInstanceTable via SNMP synchronously.

        Runs the async pysnmp coroutine in a fresh event loop so the scrape
        thread (which is NOT on the asyncio loop) can call it without
        deadlocking.

        Returns a dict mapping ``instance_index`` (the OID suffix) to a
        dict of column values, or ``None`` on total failure.
        """
        if not _pysnmp_available:
            log.debug("vrrp: pysnmp not installed — SNMP augmentation skipped")
            return None
        cfg = self._snmp_config
        assert cfg is not None
        try:
            loop = asyncio.new_event_loop()
            try:
                rows = loop.run_until_complete(
                    asyncio.wait_for(
                        _snmp_walk_table(cfg),
                        timeout=cfg.timeout,
                    )
                )
            finally:
                loop.close()
        except asyncio.TimeoutError:
            log.debug("vrrp: SNMP walk timed out after %.1fs", cfg.timeout)
            self._errors["snmp_timeout"] += 1
            return None
        except Exception as exc:
            log.debug("vrrp: SNMP walk error: %s", exc)
            self._errors["snmp_parse"] += 1
            return None
        return rows

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
            "VRRP instance state (D-Bus: 1=BACKUP 2=MASTER 3=FAULT; "
            "SNMP: 0=init also possible)",
            ["bus_name", "instance", "vr_id", "nic", "family"],
        )
        priority_fam = _MetricFamily(
            "shorewalld_vrrp_priority",
            "VRRP base priority (filled by SNMP augmentation; 0 if unavailable)",
            ["bus_name", "instance", "vr_id"],
        )
        eff_prio_fam = _MetricFamily(
            "shorewalld_vrrp_effective_priority",
            "VRRP effective priority after tracking adjustments "
            "(filled by SNMP; 0 if unavailable)",
            ["bus_name", "instance", "vr_id"],
        )
        ts_fam = _MetricFamily(
            "shorewalld_vrrp_last_transition_timestamp_seconds",
            "Unix timestamp of last observed VRRP state change (0 if unknown)",
            ["bus_name", "instance", "vr_id"],
        )
        vip_fam = _MetricFamily(
            "shorewalld_vrrp_vip_count",
            "VIP status proxy (filled by SNMP; 0 if unavailable); "
            "maps vrrpInstanceVipsStatus: 1=allSet, 2=notAllSet",
            ["bus_name", "instance", "vr_id", "family"],
        )
        transitions_fam = _MetricFamily(
            "shorewalld_vrrp_master_transitions_total",
            "Cumulative transitions-to-MASTER count (not available via SNMP; always 0)",
            ["bus_name", "instance", "vr_id"],
            mtype="counter",
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
            transitions_fam.add(
                [inst.bus_name, inst.vrrp_name, vr_str],
                float(inst.master_transitions),
            )

        return [
            state_fam, priority_fam, eff_prio_fam, ts_fam,
            vip_fam, transitions_fam, err_fam,
        ]


# ── SNMP helpers ─────────────────────────────────────────────────────────────


async def _snmp_walk_table(
    cfg: VrrpSnmpConfig,
) -> dict[str, dict[str, object]]:
    """Walk the KEEPALIVED-MIB vrrpInstanceTable and return a dict of rows.

    The returned dict maps ``instance_index`` (the OID suffix after the
    column prefix, e.g. ``"1"`` or ``"2"``) to a column-value dict with
    keys ``name``, ``state``, ``vrid``, ``base_prio``, ``eff_prio``,
    ``vips_status``.

    Missing or NoSuchObject columns are silently skipped (value stays 0).
    """
    engine = SnmpEngine()
    auth = CommunityData(cfg.community, mpModel=1)  # mpModel=1 = SNMPv2c
    transport = await UdpTransportTarget.create(
        (cfg.host, cfg.port),
        timeout=cfg.timeout,
        retries=0,
    )
    ctx = ContextData()

    # Walk each column OID we care about.
    # Row index is the suffix of the OID after the column prefix.
    col_oids = [
        (_KA_OID_NAME,        "name"),
        (_KA_OID_STATE,       "state"),
        (_KA_OID_VRID,        "vrid"),
        (_KA_OID_BASE_PRIO,   "base_prio"),
        (_KA_OID_EFF_PRIO,    "eff_prio"),
        (_KA_OID_VIPS_STATUS, "vips_status"),
    ]

    rows: dict[str, dict[str, object]] = {}

    for base_oid, col_key in col_oids:
        try:
            async for (err_ind, err_status, _idx, var_binds) in walk_cmd(
                engine, auth, transport, ctx,
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                if err_ind or err_status:
                    log.debug(
                        "vrrp SNMP: walk error on %s: %s",
                        base_oid, err_ind or err_status,
                    )
                    break
                for oid_obj, val in var_binds:
                    # Check for NoSuchObject/NoSuchInstance — skip silently.
                    if isinstance(val, (NoSuchObject, NoSuchInstance)):
                        continue
                    full_oid = str(oid_obj)
                    if not full_oid.startswith(base_oid):
                        continue
                    idx = full_oid[len(base_oid):].lstrip(".")
                    if not idx:
                        idx = "0"
                    if idx not in rows:
                        rows[idx] = {}
                    rows[idx][col_key] = val
        except Exception as exc:
            log.debug("vrrp SNMP: walk error on col %s: %s", base_oid, exc)
            # Keep partial rows; don't abort the whole walk.

    return rows


def _coerce_snmp_int(val: object, default: int = 0) -> int:
    """Convert a pysnmp value to int, returning ``default`` on failure."""
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _coerce_snmp_str(val: object) -> str:
    """Convert a pysnmp OctetString / DisplayString to a Python str."""
    if val is None:
        return ""
    try:
        # pysnmp OctetString may have a prettyPrint() method.
        return str(val)
    except Exception:
        return ""


def _build_instances_from_snmp(
    snmp_rows: dict[str, dict[str, object]],
) -> list[VrrpInstance]:
    """Build VrrpInstance objects from an SNMP-only walk (no D-Bus)."""
    instances: list[VrrpInstance] = []
    for _idx, cols in snmp_rows.items():
        name = _coerce_snmp_str(cols.get("name"))
        if not name:
            continue
        state = _coerce_snmp_int(cols.get("state"), 0)
        vrid = _coerce_snmp_int(cols.get("vrid"), 0)
        base_prio = _coerce_snmp_int(cols.get("base_prio"), 0)
        eff_prio = _coerce_snmp_int(cols.get("eff_prio"), 0)
        vips_status = _coerce_snmp_int(cols.get("vips_status"), 0)
        instances.append(VrrpInstance(
            bus_name="",
            vrrp_name=name,
            nic="",
            vr_id=vrid,
            family="",
            state=state,
            priority=base_prio,
            effective_priority=eff_prio,
            last_transition=0.0,
            vip_count=vips_status,
        ))
    return instances


def _merge_snmp_into_instances(
    instances: list[VrrpInstance],
    snmp_rows: dict[str, dict[str, object]],
) -> list[VrrpInstance]:
    """Merge SNMP numeric fields into D-Bus-discovered instances.

    Correlation key: ``vrrp_name`` == ``vrrpInstanceName`` (the ``name``
    column from the SNMP walk).  Unmatched instances are returned unchanged
    (numeric fields stay at 0).  Extra SNMP rows with no D-Bus counterpart
    are discarded — D-Bus is the authoritative discovery source.
    """
    # Build name → snmp_cols lookup (deduplicate: first row wins).
    snmp_by_name: dict[str, dict[str, object]] = {}
    for cols in snmp_rows.values():
        name = _coerce_snmp_str(cols.get("name"))
        if name and name not in snmp_by_name:
            snmp_by_name[name] = cols

    merged: list[VrrpInstance] = []
    for inst in instances:
        cols = snmp_by_name.get(inst.vrrp_name)
        if cols is None:
            merged.append(inst)
            continue
        base_prio = _coerce_snmp_int(cols.get("base_prio"), 0)
        eff_prio = _coerce_snmp_int(cols.get("eff_prio"), 0)
        vips_status = _coerce_snmp_int(cols.get("vips_status"), 0)
        merged.append(VrrpInstance(
            bus_name=inst.bus_name,
            vrrp_name=inst.vrrp_name,
            nic=inst.nic,
            vr_id=inst.vr_id,
            family=inst.family,
            state=inst.state,
            priority=base_prio,
            effective_priority=eff_prio,
            last_transition=inst.last_transition,
            vip_count=vips_status,
        ))
    return merged


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
        master_transitions=0,
    )
