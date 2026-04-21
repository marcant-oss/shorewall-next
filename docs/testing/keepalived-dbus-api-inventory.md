# keepalived D-Bus API inventory (v2.3.4 vs 2.2.x)

Generated 2026-04-20 by reading `keepalived/dbus/*.xml`,
`keepalived/vrrp/vrrp_dbus.c`, `keepalived/include/vrrp_dbus.h`,
`keepalived/include/global_data.h`, and upstream release notes
for every 2.2.x–2.3.4 release.

Source commit: `cbc1dc6` (tag `v2.3.4`, shallow clone of
`https://github.com/acassen/keepalived`).

---

## Summary

| Interface | Object path | Consumed today | New since 2.2.x |
|-----------|-------------|----------------|-----------------|
| `org.keepalived.Vrrp1.Vrrp` | `/org/keepalived/Vrrp1[/<ns>[/<inst>]]/Vrrp` | NO (not touched by VrrpCollector) | `PrintStatsClear` method (2.2.7) |
| `org.keepalived.Vrrp1.Instance` | `/org/keepalived/Vrrp1[/<ns>[/<inst>]]/Instance/<nic>/<vrid>/<IPv4\|IPv6>` | PARTIAL — `Name` and `State` properties only | `VrrpStatusChange` signal (present since initial dbus, never subscribed); path now supports "no-interface" instances and configurable `dbus_no_interface_name` string (2.3.0) |
| `org.keepalived.Bfd` | N/A | NO | Does NOT exist — BFD (`--enable-bfd`) has no D-Bus interface in v2.3.4 |

---

## Per-interface details

### org.keepalived.Vrrp1.Vrrp

**Object path:**
```
/org/keepalived/Vrrp1[/<network_namespace>][/<instance_name>]/Vrrp
```
The optional `<network_namespace>` and `<instance_name>` path segments are
appended only when those global options are set in keepalived.conf.  The
baseline path used by our collector's Introspect walk is the plain
`/org/keepalived/Vrrp1/Vrrp` form.

**Interface definition:** `keepalived/dbus/org.keepalived.Vrrp1.Vrrp.xml_template`
(the `C`-prefixed lines are **compile-time gated** by `--enable-dbus-create-instance`
and are **not** part of the default binary; treated here as conditional/unimplemented).

#### Methods

| Method | Signature (in → out) | State-changing? | Consumed today | Notes |
|--------|---------------------|-----------------|----------------|-------|
| `PrintData` | `() → ()` | YES (writes `/tmp/keepalived.data`) | NO | Signals the VRRP process to dump internal data; side-effect only |
| `PrintStats` | `() → ()` | YES (writes `/tmp/keepalived.stats`) | NO | Dumps VRRP statistics file |
| `PrintStatsClear` | `() → ()` | YES (writes + clears stats) | NO | **NEW** added in 2.2.7 — atomically dumps and resets VRRP counters |
| `ReloadConfig` | `() → ()` | YES (sends `SIGHUP`) | NO | Triggers live config reload |
| `CreateInstance` *(conditional)* | `(s iname, s interface, u vrid, u family) → ()` | YES | NO | Only compiled when `--enable-dbus-create-instance`; **not** in default binary |
| `DestroyInstance` *(conditional)* | `(s iname) → ()` | YES | NO | Only compiled when `--enable-dbus-create-instance`; **not** in default binary |

All 4 unconditional methods are state-changing (writes to disk, reloads config).
None should be called from a passive observability collector.

#### Signals

| Signal | Signature | Consumed today | Notes |
|--------|-----------|----------------|-------|
| `VrrpStarted` | `()` | NO | Emitted from `on_bus_acquired` — fires once at startup after all instances are registered |
| `VrrpReloaded` | `()` | NO | Emitted after `dbus_reload()` completes — signals a config reload |
| `VrrpStopped` | `()` | NO | Emitted just before `dbus_stop()` disconnects — signals keepalived shutdown |

#### Properties

None defined on `org.keepalived.Vrrp1.Vrrp`.

---

### org.keepalived.Vrrp1.Instance

**Object path:**
```
/org/keepalived/Vrrp1[/<network_namespace>][/<instance_name>]/Instance/<nic>/<vrid>/<IPv4|IPv6>
```
One object per VRRP instance.  `<nic>` has non-alphanumeric characters replaced
with `_` (e.g. `bond0.20` → `bond0_20`).

When a VRRP instance has no configured interface (unicast-only), keepalived uses
the `dbus_no_interface_name` string in the path (default: `"none"`).  This is
configurable since 2.3.0 via the `dbus_no_interface_name` global option.

**Interface definition:** `keepalived/dbus/org.keepalived.Vrrp1.Instance.xml`

#### Properties

| Property | D-Bus type | Python/jeepney value | Consumed today | Notes |
|----------|-----------|---------------------|----------------|-------|
| `Name` | `(s)` | `str` (instance name, i.e. `vrrp->iname`) | YES | Correlation key |
| `State` | `(us)` | `(uint, str)` — state int + label string | YES (int only) | State encoding: `0`=Init, `1`=Backup, `2`=Master, `3`=Fault, `98`=Stop, `97`=Deleted (see note below) |

**State value note:** The D-Bus code returns `vrrp->state` directly, which can
take values `0` (Init), `1` (Backup), `2` (Master), `3` (Fault), `97`
(Deleted — internal), `98` (Stop — internal).  Our collector's docstring
documents only `1`/`2`/`3`; `0`, `97`, and `98` are reachable but undocumented
in `VrrpInstance.state`.  The string label in the `(us)` second element —
e.g. `"Init"`, `"Backup"`, `"Master"`, `"Fault"`, `"Stop"`, `"Deleted"`,
`"Unknown"` — is **not** consumed by the collector today.

#### Methods

| Method | Signature | State-changing? | Consumed today | Notes |
|--------|-----------|-----------------|----------------|-------|
| `SendGarp` | `() → ()` | YES (sends gratuitous ARP) | NO | Triggers a single GARP from the instance; must not be called from a passive collector |

#### Signals

| Signal | Signature | Consumed today | Notes |
|--------|-----------|----------------|-------|
| `VrrpStatusChange` | `(u status)` | NO | **Not subscribed.** Emitted on every state transition; `status` carries the new numeric state (same encoding as the `State` property uint). Also emitted at startup for each instance via `dbus_send_state_signal`. |

---

### org.freedesktop.DBus.Properties (standard interface, applied to Instance)

The collector calls `GetAll("org.keepalived.Vrrp1.Instance")` on each instance
path.  `Set` is not implemented server-side (`handle_set_property` is `NULL` in
the GDBus vtable).

---

### BFD D-Bus interface

**Does not exist.**  Keepalived v2.3.4 implements BFD (`--enable-bfd`) as a
separate internal daemon thread communicating with VRRP via sockets.  There is
no D-Bus interface for BFD state, session counts, or session transitions.
The `keepalived/bfd/` source tree contains no D-Bus code.  BFD state must be
monitored via SNMP (KEEPALIVED-MIB BFD subtable) or keepalived's status files.

---

## Object path variations (new since ~2.2.7 / 2.3.0)

The Vrrp and Instance object paths are extended with optional segments when
keepalived uses a named network namespace or instance name:

| Config option | Effect on path |
|---------------|---------------|
| `network_namespace <ns>` | `/org/keepalived/Vrrp1/<ns>/Vrrp` and `…/Instance/<ns>/<nic>/…` |
| `instance_name <name>` | `/org/keepalived/Vrrp1/<name>/Vrrp` (appended after namespace if both set) |
| Both set | `/org/keepalived/Vrrp1/<ns>/<name>/Vrrp` |
| Neither (default) | `/org/keepalived/Vrrp1/Vrrp` (what our collector assumes) |

Our `_parse_obj_path()` helper hard-codes a 3-component tail
(`<nic>/<vrid>/<family>`) after the `/Instance/` prefix and does not account
for the namespace/instance-name path segments.  This is safe for the reference
deployment (no `network_namespace` in use), but would silently drop all
instances on a multi-namespace keepalived node.

The `dbus_service_name` global option (present since at least 2.2.x) allows
overriding `org.keepalived.Vrrp1` — our collector's `bus_name_glob` already
handles this via wildcard `org.keepalived.*`.

---

## D-Bus policy (access control)

From `keepalived/dbus/org.keepalived.Vrrp1.conf`:

- `root` only may **own** the service name `org.keepalived.Vrrp1`.
- Any user may **send** to `org.keepalived.Vrrp1` on interfaces
  `Introspectable`, `Peer`, and `Properties`.
- All other sends (e.g. calling `SendGarp`, `PrintStats`, `ReloadConfig`)
  are restricted to `root` by the default `<policy context="default">`.

Our collector runs as a non-root Prometheus exporter.  It may call `Introspect`
and `Properties.GetAll` without root — consistent with current behavior.
Calling `SendGarp`, `PrintStats`, or `PrintStatsClear` from the collector would
require root or a custom policy file.

---

## Follow-up wiring opportunities (passive observability only)

Priority order — highest observability value first.

### 1. Subscribe to `VrrpStatusChange` on each Instance object

**Interface:** `org.keepalived.Vrrp1.Instance` signal `VrrpStatusChange(u status)`

**Value:** Eliminates poll latency on state transitions.  Today the collector
polls on a 5 s TTL; with a signal subscription the state change lands within a
single D-Bus round-trip of the actual failover.  Downtime computations in the
stagelab `HaFailoverDrillScenario` would become sub-second accurate instead of
±5 s.

**Implementation sketch:** Add a `jeepney` match rule
`type='signal',interface='org.keepalived.Vrrp1.Instance',member='VrrpStatusChange'`
on the blocking connection; run a background thread that processes signals and
updates an in-memory state cache; `collect()` reads from that cache.

**Caution:** The signal carries only `(u status)` — no instance identity.  The
collector must map the signal's originating object path to the `VrrpInstance` to
update the right record.

### 2. Subscribe to `VrrpStarted` / `VrrpStopped` / `VrrpReloaded` on the Vrrp object

**Interface:** `org.keepalived.Vrrp1.Vrrp` signals `VrrpStarted()`,
`VrrpStopped()`, `VrrpReloaded()`

**Value:** Allows the collector to invalidate its instance cache immediately when
keepalived restarts or reloads, rather than serving stale data for up to one TTL
cycle.  `VrrpStopped` in particular is the clean early-warning that all
instances are about to disappear.  `VrrpReloaded` should trigger a fresh
Introspect walk (instance set may have changed).

**Implementation sketch:** Subscribe to all three signals on the Vrrp object
path.  On `VrrpStopped` set a `_ka_running = False` flag so `collect()` returns
empty instead of stale data.  On `VrrpStarted` / `VrrpReloaded` clear the TTL
cache and force an immediate re-scrape.

### 3. Consume the `State` property string label (second element of `(us)`)

**Interface:** `org.keepalived.Vrrp1.Instance` property `State = (us)`

**Value:** The string label (`"Init"`, `"Backup"`, `"Master"`, `"Fault"`,
`"Stop"`, `"Deleted"`, `"Unknown"`) is already delivered in every `GetAll`
reply but silently discarded by `_parse_instance_reply`.  Surfacing it as a
Prometheus label on `shorewalld_vrrp_state` would allow alerting on the
`"Fault"` and `"Stop"` string values without needing to remember the numeric
encoding.  The numeric → string mapping is also useful as a validation check
(detect keepalived binary returning unexpected state integers).

**Implementation cost:** One-line change to `_parse_instance_reply` to extract
`raw_state[1]` and propagate it through `VrrpInstance` as a new `state_label`
field.

### 4. Handle namespace/instance-name object path segments

**Interface:** Path parsing in `_parse_obj_path` and `_list_instance_paths`

**Value:** If the reference deployment ever uses keepalived's
`network_namespace` or `instance_name` options (or a future upgrade to a
multi-namespace node), the current 3-component tail parser silently drops all
instances.  Adding a configurable `path_depth_offset` parameter (defaulting to
0, set to 1 or 2 when namespace/instance options are in use) future-proofs the
collector without any API change.

**Implementation cost:** Extend `_parse_obj_path` to strip the optional namespace
and/or instance-name prefix segments before splitting the tail.  The offset can
be auto-detected by counting path components rather than requiring operator
configuration.

### 5. Expose undocumented state values 97 (Deleted) and 98 (Stop)

**Interface:** `org.keepalived.Vrrp1.Instance` property `State` uint

**Value:** State `98` (Stop) appears briefly when an instance is being shut
down gracefully; state `97` (Deleted) is a transient internal value.  Neither
is documented in `VrrpInstance.state`'s docstring.  A Prometheus alert on
`shorewalld_vrrp_state == 98` could detect a keepalived shutdown before
`VrrpStopped` is processed, providing a safety net for the signal-subscription
path (item 2 above).

**Implementation cost:** Update `VrrpInstance` docstring and the
`shorewalld_vrrp_state` metric help-string to document all six valid values.
No code change required — the uint is already stored verbatim.

---

## What does NOT exist in v2.3.4 (anticipated but absent)

| Feature | Status |
|---------|--------|
| BFD D-Bus interface (`org.keepalived.Bfd`) | Not implemented |
| Per-instance packet counters / statistics properties | Not in D-Bus; only via `PrintStats` file dump or SNMP |
| Track-script status property | Not in D-Bus; only via keepalived status file / SNMP |
| GARP/advert counter properties | Not in D-Bus; only via SNMP or stats file |
| VIP list property | Not in D-Bus; only via SNMP `vrrpInstanceVipsStatus` (binary allSet/notAllSet) |
| State-transition timestamp | Not in D-Bus; `last_transition` remains 0 — SNMP `vrrpInstanceBecomeMaster` counter is the best proxy |
| Dynamic instance add/remove signals (CreateInstance / DestroyInstance) | Available only with `--enable-dbus-create-instance` compile flag; not in default binary; **`VrrpReloaded` signal is the correct hook for config changes** |
