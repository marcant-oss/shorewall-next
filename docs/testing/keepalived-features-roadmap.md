# keepalived v2.3.4 — feature-support roadmap

Generated 2026-04-20.  Evaluates every major keepalived feature in the 2.2.7–2.3.4
window against our current stack (VrrpCollector, snmp\_oids.py, HaFailoverDrillRunner,
reference HA firewall config).  Cross-references
[keepalived-dbus-api-inventory.md](keepalived-dbus-api-inventory.md) for D-Bus
specifics — that document is not duplicated here.

In-flight work by agent `abedfc8ffa33885b3` (VrrpStatusChange signal subscription,
VrrpStarted/Stopped/Reloaded lifecycle signals, State string label surfacing,
namespace path parsing, states 97/98 documentation) is marked **IN PROGRESS** and
not re-suggested.

---

## Executive summary

Top 3 highest-value features to wire in order:

1. **SNMP OID column-index audit and fix** — our `vrrp.py` collector queries the
   wrong column numbers for `vrrpInstanceEffectivePriority` (col .7 is BasePriority,
   effective is col .8) and `vrrpInstanceVipsStatus` (col .8, not .9); the
   `vrrpInstanceBecomeMaster` OID does not exist in the MIB at all.  Every
   effective\_priority and transitions-to-master metric we emit is silently wrong.
   Zero config changes; pure shorewalld fix.

2. **BFD integration via SNMP** — `track_bfd` lets keepalived degrade VRRP priority
   when a BFD session goes down (sub-50 ms link-failure detection).  The KEEPALIVED-MIB
   already exposes `vrrpBfdTable` (vrrp 18) and `vrrpTrackedBfdTable` (vrrp 17) with
   session state and per-instance weights.  Polling these two tables gives us
   millisecond-resolution link-failure events in Prometheus without any D-Bus work.

3. **SNMP traps for state changes** — the KEEPALIVED-MIB defines
   `vrrpInstanceStateChange` and `vrrpSyncGroupStateChange` traps.  Wiring an
   snmptrapd receiver (or a Prometheus alertmanager webhook) gives push-based failover
   notification as a fallback path independent of D-Bus and without the
   shorewalld polling cycle.

---

## Feature matrix

| Feature | Priority | Effort | Risk |
|---------|----------|--------|------|
| SNMP OID column-index audit + fix | High | Small | Low |
| BFD SNMP monitoring (vrrpBfdTable) | High | Small | Low |
| SNMP traps (vrrpInstanceStateChange) | High | Medium | Low |
| SNMP track\_script / track\_process / track\_file tables | Medium | Small | Low |
| SNMP track\_interface table | Medium | Small | Low |
| SNMP vrrpSyncGroupTable | Medium | Small | Low |
| BFD `track_bfd` on the reference FW config | Medium | Small | Medium |
| json\_version 2 output (--enable-json) | Medium | Medium | Low |
| notify\_deleted / notify\_stop scripts | Medium | Small | Low |
| HaFailoverDrill: D-Bus-based downtime timing | In Progress | — | — |
| Sub-second VRRP advertisement intervals | Low | Small | Medium |
| Custom multicast group (vrrp\_mcast\_group4/6) | Low | Small | Low |
| Unicast VRRP (vrrp\_unicast\_peer) | Low | Small | Low |
| VRRPv3 RFC 5798 (advert\_int 1 already defaults to v3) | Low | Skip | Low |
| Per-instance strict\_mode | Low | Small | Low |
| fifo\_write\_vrrp\_states\_on\_reload | Low | Small | Low |
| shutdown\_script / shutdown\_script\_timeout | Low | Small | Low |
| --enable-nftables (keepalived-owned nft rules) | **Skip** | Large | High |
| LVS / IPVS health-check integration | **Skip** | Large | High |
| --enable-dbus-create-instance (dynamic instances) | **Skip** | Medium | Medium |
| eBPF / XDP acceleration | **Skip** | — | — |

---

## Per-feature details

### SNMP OID column-index audit and fix

**Priority**: High
**Value**: Fixes silently wrong `vrrpInstanceEffectivePriority` and
`vrrpInstanceVipsStatus` metrics; removes a non-existent OID query.
**Effort**: Small (< 1 day)
**Dependencies**: None.
**Risk**: Low — purely additive correction; old metrics were at best wrong, at worst
zero (no-such-object).

**Current bugs (confirmed against KEEPALIVED-MIB.txt, v2.3.4):**

The `vrrpInstanceTable` column layout is:

| Column | OID suffix | Object |
|--------|-----------|--------|
| .7 | `…2.3.1.7` | `vrrpInstanceBasePriority` ← **we call this effective priority** |
| .8 | `…2.3.1.8` | `vrrpInstanceEffectivePriority` ← **we call this vipsStatus** |
| .9 | `…2.3.1.9` | `vrrpInstanceVipsStatus` ← **we call this becomeMaster** |

`vrrpInstanceBecomeMaster` does not exist anywhere in the KEEPALIVED-MIB.
Our `_KA_OID_BECOME_MASTER = "…2.3.1.9"` is actually VipsStatus (a one-bit
1=allSet / 2=notAllSet flag, not a counter).

The stagelab `vrrp_extended` bundle in `snmp_oids.py` is unaffected (it uses the
correct column .7 / .8 for effective priority and preempt), but the VrrpCollector's
SNMP walk in `vrrp.py` is wrong.

**Implementation sketch:**

In `packages/shorewalld/shorewalld/collectors/vrrp.py`:
- Rename `_KA_OID_EFF_PRIO` → target `"…2.3.1.8"` (was `.7`; that is base priority).
- Rename `_KA_OID_VIPS_STATUS` → target `"…2.3.1.9"` (was `.8`; that is effective priority).
- Remove `_KA_OID_BECOME_MASTER` and the `become_master` column from the walk —
  the OID does not exist.  Drop `master_transitions` from the SNMP walk path; it can
  only be read if keepalived exposes a stats file or via the `PrintStats` D-Bus call.

Also add `_KA_OID_BASE_PRIO = "…2.3.1.7"` so `priority` (base) and
`effective_priority` (base ± track adjustments) are both filled.

**Open questions for operator:**
- Do we want `master_transitions` at all?  If yes, it requires parsing keepalived's
  `/tmp/keepalived.stats` file (written by `PrintStats` D-Bus call, root-only) or
  keeping the `PrintStats` sidecar approach.  Alternatively, the Prometheus
  `shorewalld_vrrp_state` gauge can be RATE-queried to count transitions; less
  precise but zero extra code.

---

### BFD SNMP monitoring (vrrpBfdTable + vrrpTrackedBfdTable)

**Priority**: High
**Value**: Enables sub-50 ms link-failure detection results to surface in Prometheus
without D-Bus or kernel-probe work.  `vrrpBfdTable` (vrrp 18) exposes per-session
BFD state (up/down) and weight; `vrrpTrackedBfdTable` (vrrp 17) links BFD sessions
to VRRP instances.  Together they answer "is the BFD fast-path healthy, and which
VRRP instances does a down session affect?"
**Effort**: Small (< 1 day — two new bundle entries + two new scrape loops)
**Dependencies**: keepalived must be compiled with `--enable-bfd` (our RPM already
enables all optional features per CLAUDE.md) and a BFD peer must be configured
(`bfd_instance` block in keepalived.conf).  The reference FW currently does NOT
use `track_bfd` (see feature below).
**Risk**: Low — read-only SNMP walk; no config changes to keepalived.

**Implementation sketch:**

In `snmp_oids.py` add:
```python
VRRP_BFD_NAME   = "1.3.6.1.4.1.9586.100.5.2.18.1.2"   # vrrpBfdName
VRRP_BFD_RESULT = "1.3.6.1.4.1.9586.100.5.2.18.1.3"   # vrrpBfdResult (1=up, 2=down)
BUNDLE_VRRP_BFD = [VRRP_BFD_NAME, VRRP_BFD_RESULT]
```

In `metrics_ingest.py` (or a new `collectors/bfd.py` in shorewalld), walk
`vrrpBfdTable` and emit `shorewalld_vrrp_bfd_session_up{name=...}` = 1/0.

**Open questions for operator:**
- Is BFD actively in use on the reference HA firewall?  If the reference config has
  no `bfd_instance` block the table will be empty; still safe to scrape.
- Which interface / peer should be tracked?  BFD is usually configured between the
  two firewall nodes on the sync/heartbeat link.

---

### SNMP traps (vrrpInstanceStateChange / vrrpSyncGroupStateChange)

**Priority**: High
**Value**: Push-based failover notification via standard SNMP trap path, independent
of D-Bus polling.  With `enable_traps` in global\_defs, keepalived sends
`vrrpInstanceStateChange` on every MASTER↔BACKUP transition and
`vrrpSyncGroupStateChange` on sync-group transitions.  An snmptrapd receiver can
forward to alertmanager or write to a log that shorewalld tails.  This provides
a second independent failover-detection path alongside D-Bus signals.
**Effort**: Medium (1–3 days — snmptrapd config + trap-to-prometheus bridge or
alertmanager webhook; no shorewalld code change)
**Dependencies**: `enable_traps` added to keepalived.conf `global_defs`.  snmptrapd
running on each FW node.  Community string configured.
**Risk**: Low — traps are additive; they don't affect VRRP protocol behaviour.

**Implementation sketch:**

1. Add `enable_traps` to the reference keepalived.conf `global_defs`.
2. Configure snmptrapd on each FW node with a PERL or shell handler that writes to a
   log file.
3. Either: (a) point alertmanager at the log via a file\_sd scrape, or
   (b) add a `TrapReceiver` mode to shorewalld (a UDP listener that converts
   `vrrpInstanceStateChange` trap PDUs to Prometheus events).

Option (b) is the clean integration but requires new shorewalld code; option (a)
is operator-side and needs no code.

**Open questions for operator:**
- Is there already an snmptrapd receiver in the monitoring stack?  If yes, wiring
  the trap handler is a configuration-only change.

---

### SNMP track\_script / track\_process / track\_file / track\_interface tables

**Priority**: Medium
**Value**: Surfaces health-tracking context in Prometheus: which scripts are failing,
which processes are missing, which files have non-zero weight values — the exact
data that makes a VRRP priority drop explainable without logging into the FW.
Four tables available:
- `vrrpTrackedScriptTable` (vrrp 5): script name + weight + weight-reversal flag
- `vrrpTrackedProcessTable` (vrrp 20): process name + weight
- `vrrpTrackedFileTable` (vrrp 12): file name + weight
- `vrrpTrackedInterfaceTable` (vrrp 4): interface name + weight

Note: these tables expose *configuration* (what is being tracked and with what
weight), not the current result of the check.  The actual script exit code /
process count / file value is not directly visible — the impact is visible via
`vrrpInstanceEffectivePriority` dropping below `vrrpInstanceBasePriority`.
**Effort**: Small — four new bundle entries; can share one scrape loop.
**Dependencies**: Correct SNMP OID column fix (above) first, so effective priority
is read correctly and the priority-drop signal is trustworthy.
**Risk**: Low — read-only walk.

**Implementation sketch:**

Add `BUNDLE_VRRP_TRACKERS` to `snmp_oids.py` covering the four tracker tables.
In a new optional scrape loop emit:
- `shorewalld_vrrp_tracker_weight{instance_idx=..., tracker_type=script|process|file|interface, name=...}`

This allows a Prometheus rule: `vrrp_effective_priority < vrrp_base_priority` →
join with tracker metrics to identify the culprit without SSH.

**Open questions for operator:**
- The reference FW uses `track_interface { bond0; bond1 }` — the table should
  expose these.  Confirm that `vrrpTrackedInterfaceTable` actually populates on the
  live FW.

---

### SNMP vrrpSyncGroupTable

**Priority**: Medium
**Value**: The reference FW has three VRRP instances (VI\_fw, VI\_rns1, VI\_rns2)
which could be grouped in a `vrrp_sync_group`.  Even if they are not currently
grouped, `vrrpSyncGroupTable` (vrrp 1) and `vrrpSyncGroupMemberTable` (vrrp 2)
expose sync-group state independently — if all members of a group must be
MASTER/BACKUP together, a single sync-group state metric is cleaner to alert on
than three individual instance metrics.
**Effort**: Small.
**Dependencies**: None — safe to scrape even if no sync groups are configured.
**Risk**: Low.

**Implementation sketch:**

Add `VRRP_SYNC_GROUP_STATE = "1.3.6.1.4.1.9586.100.5.2.1.1.3"` to `snmp_oids.py`.
Add `BUNDLE_VRRP_SYNC_GROUP` = [name + state OIDs].

**Open questions for operator:**
- The reference keepalived.conf does not define a `vrrp_sync_group`.  Is there an
  operational reason not to group VI\_fw, VI\_rns1, VI\_rns2?  If they should always
  move together a sync group would simplify both config and monitoring.

---

### BFD `track_bfd` on the reference FW config

**Priority**: Medium
**Value**: keepalived can run BFD sessions to a peer (the other FW node, or upstream
router) and automatically drop VRRP priority when the BFD session goes down.  This
gives sub-50 ms link-failure detection compared to the current ~3 × advert\_int
(~3 s) VRRP dead-interval.  Particularly useful for the bond0 uplink failure
scenario.
**Effort**: Small (keepalived.conf change + BFD peer config on both nodes)
**Dependencies**: `--enable-bfd` in the keepalived binary (our RPM enables this).
BFD requires a peer — either the peer FW node or the upstream router.  The peer
must also speak BFD (bird2 / FRR support this natively).
**Risk**: Medium — config change on live FW.  A misconfigured BFD timer could
cause unnecessary VRRP failovers.  Recommend starting with `passive` mode and
conservative timers (min\_rx/min\_tx 300 ms, multiplier 5 → 1.5 s dead-interval)
before tuning down.

**Implementation sketch:**

In keepalived.conf, add a `bfd_instance` block per peer and add `track_bfd` to each
`vrrp_instance`.  Start with:
```
bfd_instance bfd_peer_fw {
    neighbor_ip 192.168.X.Y     # peer FW heartbeat IP
    source_ip   192.168.X.Z     # local heartbeat IP
    min_rx      300             # ms
    min_tx      300             # ms
    multiplier  5               # dead after 1.5 s
}

vrrp_instance VI_fw {
    ...
    track_bfd {
        bfd_peer_fw weight -50
    }
}
```

Once stable, tune timers down to min\_rx/min\_tx 50 ms for ~150 ms detection.

**Open questions for operator:**
- Does bird2 on the reference FW nodes speak BFD?  If yes this is trivial; if not
  you need a BFD daemon (bfdd from FRR, or openr) on the peer.
- What heartbeat / sync link connects the two FW nodes?  (conntrackd uses UDP/3780
  — likely a dedicated sync link exists.)

---

### json\_version 2 output (`--enable-json`)

**Priority**: Medium
**Value**: With `--enable-json` compiled in (our RPM enables this), keepalived
writes structured JSON to `/tmp/keepalived.json` on `SIGUSR1`.  Version 2
(`json_version 2` in global\_defs) includes VRRP instances in a named array and
adds tracking process details.  This could replace the slow `keepalived.data` text
parser and give shorewalld a fallback data path when D-Bus is down (JSON file has
no D-Bus dependency).  Also useful for `stagelab audit` to snapshot keepalived
state at a point in time.
**Effort**: Medium — need to parse JSON format, add a `FileCollector` path to
VrrpCollector that reads `/tmp/keepalived.json` when D-Bus is unavailable.
**Dependencies**: `json_version 2` directive in keepalived.conf `global_defs`.
**Risk**: Low — file is written on demand (SIGUSR1); no keepalived behaviour change.

**Implementation sketch:**

Add `json_version 2` to `global_defs`.  In `VrrpCollector` fallback path (when
D-Bus and SNMP both fail), `os.kill(ka_pid, signal.SIGUSR1)`, wait 100 ms, then
parse `/tmp/keepalived.json`.  This gives a third fallback without a network round-
trip.  The PID can be read from `/run/keepalived.pid`.

**Open questions for operator:**
- Is `--enable-json` actually compiled into the keepalived binary on the reference
  FW?  Run `keepalived --version` and look for `JSON output`.

---

### notify\_deleted / notify\_stop scripts

**Priority**: Medium
**Value**: keepalived 2.3.x exposes two additional notify hook points:
- `notify_deleted`: fires when a VRRP instance is removed during a config reload
  (previously the instance would silently exit).
- `notify_stop`: fires on graceful keepalived shutdown.

The reference FW already has `notify_master`, `notify_backup`, `notify_fault`
wired to `/etc/cluster/state-transition.sh`.  Adding `notify_stop` and
`notify_deleted` to that script allows the cluster state machine to react to
keepalived shutdown/reload without polling.
**Effort**: Small (keepalived.conf + shell script change).
**Dependencies**: None.
**Risk**: Low — additive; existing transitions are unaffected.

**Implementation sketch:**

In keepalived.conf for each `vrrp_instance`:
```
notify_stop   "/etc/cluster/state-transition.sh stop"
notify_deleted "/etc/cluster/state-transition.sh deleted"
```

Extend `state-transition.sh` to handle `stop` and `deleted` arguments.

**Open questions for operator:**
- What does the cluster state machine currently do when keepalived stops unexpectedly
  vs gracefully?  `notify_stop` lets the script distinguish the two cases.

---

### Sub-second VRRP advertisement intervals

**Priority**: Low
**Value**: keepalived supports `advert_int` with millisecond resolution (e.g.
`advert_int 0.5` for 500 ms advertisements).  The reference FW uses `advert_int 1`
(1 s).  Dropping to 200–500 ms would reduce the VRRP dead-interval from ~3 s to
~600 ms–1.5 s without requiring BFD.
**Effort**: Small (config change only).
**Dependencies**: Both keepalived nodes must be upgraded simultaneously.  The peer
must also accept sub-second intervals.  VRRPv3 is required (v2 does not support
sub-second; VRRPv3 is already the default for IPv4 in 2.2.x+ with `advert_int 1`).
**Risk**: Medium — more frequent advertisements increase CPU and network load on
the FW.  At 200 ms, 5 advert packets/s instead of 1.  Under heavy load the
scheduler may miss the deadline, triggering the `thread_timer_expired` failover.
The safer fix is BFD (above) which is out-of-band.

**Implementation sketch:**

Change `advert_int 1` → `advert_int 0.5` in both keepalived.conf instances.
Monitor `shorewalld_vrrp_master_transitions_total` for spurious failovers.

**Open questions for operator:**
- Is the current 3 s dead-interval causing observable downtime on failover that
  sub-second intervals would help?  If BFD (above) is in scope, prefer BFD —
  it's more reliable and doesn't require tuning advert timers.

---

### Custom multicast group (vrrp\_mcast\_group4/6)

**Priority**: Low
**Value**: Allows using a non-default VRRP multicast address to avoid conflicts
with other VRRP deployments on the same L2 segment.  The reference FW uses
standard `224.0.0.18`.  Only relevant if another VRRP-speaking device on the
same bond0.10 segment causes multicast collisions.
**Effort**: Small.
**Dependencies**: Both nodes + any L2 switches must forward the non-default group.
**Risk**: Low if the need exists; no need to change unless there is a conflict.

---

### Unicast VRRP (vrrp\_unicast\_peer)

**Priority**: Low
**Value**: In networks where VRRP multicast is filtered or unavailable, keepalived
can use unicast advertisements between a defined peer list.  The reference FW
operates on a controlled L2 segment where multicast is permitted, so unicast VRRP
adds complexity without benefit.  Useful if the deployment ever moves to a
multicast-filtered data-centre fabric.
**Effort**: Small (config change).
**Dependencies**: Both FW nodes and upstream L2 must permit direct unicast between
the VRRP source IPs.  2.3.3 added RFC 9568 compliance and duplicate unicast peer
detection.
**Risk**: Low in isolation; migration from multicast → unicast on a live HA pair
requires a maintenance window.

---

### VRRPv3 RFC 5798

**Priority**: Low / Skip
**Value**: keepalived 2.2.x+ already defaults to VRRPv3 for IPv4 when `advert_int`
is 1 second (VRRPv2 is limited to integer seconds but VRRPv3 is the same on the
wire at that resolution).  The reference FW config does not explicitly set
`vrrp_version`; the default is version 3.  Nothing to wire.
**Effort**: Small (verify `vrrp_version 3` in config if desired explicitness).
**Risk**: Low.

---

### Per-instance strict\_mode

**Priority**: Low
**Value**: `strict_mode` per vrrp\_instance overrides the global `vrrp_strict`
setting.  The reference FW does not use `vrrp_strict` globally; per-instance
override would only matter if some instances need RFC-strict behaviour (e.g. no
`virtual_ipaddress_excluded`) while others do not.
**Effort**: Small.
**Risk**: Low.

---

### fifo\_write\_vrrp\_states\_on\_reload

**Priority**: Low
**Value**: After a config reload keepalived re-sends all VRRP instance states to
any configured FIFO notify pipe.  This ensures that an external state machine
(e.g. `/etc/cluster/state-transition.sh` or a monitoring daemon) that missed
the reload gets a full state refresh.  Only useful if a FIFO pipe is configured
(`notify_fifo`).
**Effort**: Small — add `fifo_write_vrrp_states_on_reload` to `global_defs` and
add `notify_fifo /run/keepalived.notify` to `vrrp_instance`.
**Risk**: Low.

---

### shutdown\_script / shutdown\_script\_timeout

**Priority**: Low
**Value**: Runs a custom script on keepalived shutdown, with a configurable timeout.
Useful for draining connections before the service stops.  The reference FW already
handles this via VRRP transition to BACKUP (which triggers
`state-transition.sh backup`); `shutdown_script` is redundant unless the
transition script itself needs a longer execution window.
**Effort**: Small.
**Risk**: Low.

---

## Features we should NOT support + why

### `--enable-nftables` (keepalived-owned nft rules)

keepalived can emit its own nft rules for VRRP fwmark and LVS virtual servers via
`vrrp_nftables` in `global_defs`.  **Do not use this.**

Our shorewall-nft compiler owns the entire nft ruleset.  A parallel keepalived-
owned nft table would create a second table that may conflict with the shorewall-nft
`filter` table's jump chains.  The reference FW already handles all VRRP-related
rules (proto 112, multicast 224.0.0.18, conntrackd UDP/3780) via shorewall-nft
rules.  Keepalived's nft emission is redundant and would be a maintenance burden to
keep in sync.

The 2.3.0 release note mentions adding `nftables/iptables to stop neighbour
advertisements for link-local VMAC addresses in backup state` — this is an edge
case (IPVLAN/VMAC-based setups) that does not apply to the reference config.

### LVS / IPVS health-check integration

The reference HA firewall does not use LVS.  shorewalld has no LVS knowledge and
there is no current use case.  `--enable-lvs` is compiled in (it's the default),
but none of the health-check scenarios (`HTTP_GET`, `SMTP_CHECK`, `MISC_CHECK`,
`PING_CHECK`, `FILE_CHECK`, `BFD_CHECK`) should be consumed by shorewalld or
stagelab.  LVS virtual-server SNMP tables (`virtualServerTable` etc.) are present
in the MIB but provide no value without LVS configuration.

Skip entirely.  Revisit only if a new deployment introduces LVS.

### `--enable-dbus-create-instance` (dynamic D-Bus instance creation)

This compile-time flag enables `CreateInstance` and `DestroyInstance` D-Bus methods
for dynamically adding VRRP instances without a config reload.  It is not compiled
into the default binary and is explicitly documented in the D-Bus inventory as
out-of-scope.  Our use-case is static VRRP config; dynamic instance creation adds
complexity and security risk (root-only D-Bus method that mutates firewall state).

Skip.

### eBPF / XDP acceleration

**keepalived v2.3.4 has no eBPF support.**  The `configure.ac` has no
`--enable-ebpf` or `--enable-xdp` option, and a full source-tree search finds
zero BPF / XDP / libbpf references.  This feature was anticipated but not
implemented in this release.  The CLAUDE.md note about eBPF eligibility is
forward-looking speculation.  Nothing to evaluate today.

### RFC 9568 address-owner corner cases (2.3.3)

2.3.3 added handling for the address-owner duplicate priority corner case (RFC 9568
errata, collaboration with Orange Cyberdefense).  This only applies when two VRRP
routers both claim to be the address owner for the same VRID — a misconfiguration
the reference FW does not exhibit.  Log noise only.

---

## Suggested sequencing (dependency-ordered roadmap)

### Wave 1 — Q2 2026 (correctness fixes, no keepalived.conf changes)

1. **SNMP OID column-index fix** in `packages/shorewalld/shorewalld/collectors/vrrp.py`
   — fix `_KA_OID_EFF_PRIO` → col .8, `_KA_OID_VIPS_STATUS` → col .9, remove
   non-existent `_KA_OID_BECOME_MASTER`.  Add `_KA_OID_BASE_PRIO` (col .7).
   This is a bug fix, not a feature — should ship in the next shorewalld release.

2. **SNMP tracker tables** in `snmp_oids.py` — add bundle entries for
   `vrrpTrackedInterfaceTable`, `vrrpTrackedScriptTable`, `vrrpTrackedProcessTable`,
   `vrrpTrackedFileTable`.  Zero config changes on the FW.

3. **SNMP vrrpSyncGroupTable** — add bundle entry; scrape during next test run
   against the reference FW to confirm population.

### Wave 2 — Q3 2026 (FW config changes, requires maintenance window)

4. **notify\_stop + notify\_deleted** in keepalived.conf — additive; low risk.
   Extend `state-transition.sh` in the same maintenance window.

5. **BFD `track_bfd`** — add `bfd_instance` + `track_bfd` to keepalived.conf after
   confirming BFD peer availability (bird2 or FRR on the peer node).  Start with
   conservative timers (min\_rx/min\_tx 300 ms).

6. **BFD SNMP monitoring** in `snmp_oids.py` + `metrics_ingest.py` — depends on
   step 5 being live so there is data to validate against.

7. **SNMP traps** — add `enable_traps` to keepalived.conf, configure snmptrapd
   on both FW nodes, connect to alertmanager.

### Wave 3 — Q4 2026 / Deferred (operator decision required)

8. **json\_version 2 + JSON fallback path** in VrrpCollector — useful if BFD /
   SNMP traps uncover gaps, but low urgency once Waves 1–2 are in place.

9. **Sub-second advert\_int** — only if BFD is not meeting failover-time targets.
   Tune advert\_int to 0.5 s in a test window; monitor for spurious failovers.

10. **Unicast VRRP / custom multicast group** — deferred indefinitely unless
    network topology changes require it.

---

## Appendix: KEEPALIVED-MIB column corrections

The following OID mismatches between our `vrrp.py` comments/constants and the
actual KEEPALIVED-MIB (v2.3.4) were identified during this audit:

| Constant in vrrp.py | Comment says | Actual MIB column |
|---------------------|-------------|-------------------|
| `_KA_OID_EFF_PRIO` = `…2.3.1.7` | `vrrpInstanceEffectivePriority` | `vrrpInstanceBasePriority` (col .7) |
| `_KA_OID_VIPS_STATUS` = `…2.3.1.8` | `vrrpInstanceVipsStatus` | `vrrpInstanceEffectivePriority` (col .8) |
| `_KA_OID_BECOME_MASTER` = `…2.3.1.9` | `vrrpInstanceBecomeMaster (Counter32)` | `vrrpInstanceVipsStatus` (col .9); no BecomeMaster counter exists |

The `snmp_oids.py` stagelab file correctly maps `.7` as `VRRP_INSTANCE_EFFECTIVE_PRIO`
in its comment and `.8` as `VRRP_INSTANCE_VIPS_STATUS`, which actually matches
the wrong indices from vrrp.py — so both files have the same wrong mapping.
The root cause is that vrrp.py incorrectly documented column .7 as effective
priority, and snmp\_oids.py copied that mapping.  The fix is to shift all three
OIDs by one column as described in the feature detail above.
