# Live firewall test plan — operator playbook

Step-by-step procedure for executing the standards-driven security test plan
against the reference HA firewall pair (elgar-test + tropheus-test), producing
a signed-off audit report. Derived from real validation sessions; updated
iteratively as new scenarios are wired.

**Target audience**: operator with SSH access to the test-bed tester VMs +
network-level access to the firewall management plane. **Not** for production
firewalls — only the `-test` pair.

## Topology

```
       ┌──────────────────────────────────────────────────┐
       │  Test-bed VLAN trunk (Proxmox vmbr1, pvid 3999)  │
       └──────┬──────┬──────────────────────┬──────┬──────┘
              │ eth2 │ eth2             eth2│      │eth2
              ▼      ▼                      ▼      ▼
   ┌──────────────┐ ┌──────────────┐  ┌─────────┐ ┌──────────┐
   │ fw-tester01  │ │ fw-tester02  │  │  elgar  │ │ tropheus │
   │ 192.168.203. │ │ 192.168.203. │  │  -test  │ │  -test   │
   │     .93      │ │     .74      │  │  .70    │ │   .87    │
   │              │ │              │  │ mgmt    │ │ mgmt     │
   │ netns        │ │ netns (TODO) │  │  ┌───┐  │ │  ┌───┐   │
   │ sim-uplink   │ │ sim-uplink   │  │  │fw │  │ │  │fw │   │
   │ 217.14.160.77│ │ 217.14.160.78│  │  │ns │  │ │  │ns │   │
   │ OSPF area 0  │ │ OSPF area 0  │  │  └───┘  │ │  └───┘   │
   │ → 0.0.0.0/0  │ │ → 0.0.0.0/0  │  │ .75/27  │ │ .76/27   │
   │ via nft      │ │ via nft      │  │ bond1   │ │ bond1    │
   │ masquerade   │ │ masquerade   │  │ VRRP VI_│ │ VRRP VI_ │
   │ on eth0      │ │ on eth0      │  │  fw     │ │  fw      │
   └──────────────┘ └──────────────┘  │ master  │ │ backup   │
       mgmt 192.168.203/24             │ prio    │ │ prio     │
                                       │ 200     │ │ 150      │
                                       └─────────┘ └──────────┘
```

Both testers' `eth2` sit on Proxmox `vmbr1` untagged with pvid=3999, which is
the same L2 that elgar-test/tropheus-test `bond1` listens on for OSPF hellos
(217.14.160.64/27 backbone subnet).

## Prerequisites

- SSH key-based access from your workstation to:
  - `root@192.168.203.93` (fw-tester01)
  - `root@192.168.203.74` (fw-tester02)
  - `root@192.168.203.70` (elgar-test, prod — read-only operations preferred)
  - `root@192.168.203.87` (tropheus-test, prod — read-only operations preferred)
- Repo-root venv at `/path/to/marcant-fw/shorewall/.venv` (Python 3.13).
- `tools/setup-remote-test-host.sh` + one-off bootstrap per tester already
  applied (installs iperf3, nmap, ethtool, tcpdump, snmpd CLI + pysnmp, bird2,
  net-snmp-mibs).
- Community `public` for SNMP v2c on elgar/tropheus (not a secret in this
  test environment; treat as such in production).

## Phase 1 — sim-uplink on tester01 (OSPF uplink emulation)

**Purpose**: give elgar-test/tropheus-test an OSPF-peer on 217.14.160.64/27
that advertises a default route and NATs test-bed traffic to the real
Internet via the mgmt interface.

**Runtime reference**: `/home/avalentin/projects/marcant-fw/netns-routing/testing/sim-uplink/`:
- `sim-uplink-setup` (idempotent bash script)
- `bird.conf` (BIRD 2 OSPFv2 + v3 config, MD5 "Eb9haibe" id 10)
- `sim-uplink.service` (systemd oneshot to apply on boot)

### Deploy

```bash
SIMDIR=/home/avalentin/projects/marcant-fw/netns-routing/testing/sim-uplink
scp "$SIMDIR/sim-uplink-setup"    root@192.168.203.93:/usr/local/sbin/
scp "$SIMDIR/bird.conf"           root@192.168.203.93:/etc/bird.conf
scp "$SIMDIR/sim-uplink.service"  root@192.168.203.93:/etc/systemd/system/
ssh root@192.168.203.93 '
    chmod +x /usr/local/sbin/sim-uplink-setup
    dnf -y install bird2
    systemctl daemon-reload
    systemctl enable --now sim-uplink.service
'
```

### Verify

```bash
ssh root@192.168.203.93 '
    ip netns exec sim-uplink birdc -s /run/bird/bird.sim-uplink.ctl \
        show ospf neighbors
'
```

Expected: `217.14.160.75` (elgar bond1) state `Full/DR`, `217.14.160.76`
(tropheus bond1) state `Full/BDR`. IPv6 may take 30-60s to converge.

### Known behaviour

- **OSPFv2 converges in <5s**, IPv6 (OSPFv3) sometimes lingers in Waiting.
  Not blocking for any scenario below.
- sim-uplink announces `0.0.0.0/0` with `ospf_metric2=20`. elgar's
  `ip route show` will show `default via 217.14.160.77 dev bond1 proto
  bird metric 32` once installed.
- Outbound NAT via `nft table inet sim-uplink-nat` on tester01 eth0.
- Egress allowlist: ICMP / traceroute-UDP / DNS / HTTP / HTTPS. Everything
  else is LOG+reject to prevent accidental test traffic leakage.

## Phase 2 — simlab correctness (tester01)

**Purpose**: validate the compiled nft ruleset matches the iptables oracle
for zone-pair accept/drop behaviour. Runs fully in a netns on tester01; does
NOT hit elgar/tropheus live.

```bash
ssh root@192.168.203.93 '
    cd /root/shorewall-nft
    .venv/bin/python -m shorewall_nft_simlab.smoketest smoke \
        --output-json /tmp/simlab-smoke.json
'
scp root@192.168.203.93:/tmp/simlab-smoke.json /tmp/simlab-smoke.json
```

**Expected output**: `simlab-smoke.json` schema_version 1, 2 synthetic
scenarios:
- `simlab-fail-accept` ok=true (zero false-accept probes)
- `simlab-fail-drop` ok=true if count ≤ 2 (IPv6 NDP tolerance)

Known noise to discount: `net → adm ICMP (rossini)` + `adm → cdn tcp:443` are
two well-understood IPv6-side false-drops; both come from incomplete
`ip6add/ip6routes` reference dumps, not compiler bugs. See
`project_simlab_fail_drops_analysis` memory for the full explanation.

## Phase 3 — SNMP bundles live scrape

Bundles currently verified live:
- `node_traffic` — ifHCInOctets/OutOctets + discards (28 rows per FW)
- `system` — laLoad 1/5/15 + sysUpTime (4 rows per FW)
- `vrrp` — vrrpInstanceState + vrrpInstanceName (2 rows per FW)
- `vrrp_extended` — 6 extra keepalived-MIB OIDs (VRID, WantedState,
  EffectivePriority, VipsStatus, Preempt, PreemptDelay) (6 rows per FW)
- `pdns` — 0 rows (not configured on elgar/tropheus; operator TODO)

Quick check from tester01:

```bash
ssh root@192.168.203.93 'cd /root/shorewall-nft && .venv/bin/python <<PY
import asyncio, time
from shorewall_nft_stagelab.metrics_ingest import SNMPScraper, SNMPSource
async def main():
    for label, host in [("elgar","192.168.203.70"),("tropheus","192.168.203.87")]:
        src = SNMPSource(name=label, host=host, community="public",
                         port=161, timeout_s=5.0, oids=(),
                         bundles=("node_traffic","system","vrrp","vrrp_extended"))
        rows = await SNMPScraper(src).scrape(ts_unix=time.time())
        print(f"{label}: {len(rows)} rows")
asyncio.run(main())
PY'
```

Expected: `elgar: 40 rows`, `tropheus: 40 rows` (28+4+2+6).

## Phase 4 — HA-failover live drill (optional, riskant)

**Warning**: stops keepalived on the MASTER — causes a real VRRP failover.
Tropheus takes over; 180s later elgar preempts back. Confirm you have a
drill window + rollback path before executing.

```bash
# Background poller on tester01 captures VRRP-state transitions every 500ms
ssh root@192.168.203.93 "nohup bash -c '
    end=\$((\\$(date +%s)+240))
    while [ \\$(date +%s) -lt \\$end ]; do
        TS=\\$(date -u +%s.%N)
        E=\\$(snmpget -v2c -c public -t 1 -r 0 192.168.203.70 KEEPALIVED-MIB::vrrpInstanceState.1 2>/dev/null | grep -oE 'init|backup|master|fault' | head -1)
        T=\\$(snmpget -v2c -c public -t 1 -r 0 192.168.203.87 KEEPALIVED-MIB::vrrpInstanceState.1 2>/dev/null | grep -oE 'init|backup|master|fault' | head -1)
        echo \\\"\\$TS elgar=\\\${E:-?} tropheus=\\\${T:-?}\\\"
        sleep 0.5
    done' >/tmp/vrrp-drill.log 2>&1 &"

sleep 6  # baseline
ssh root@192.168.203.70 'systemctl stop  keepalived-netns@fw.service'
sleep 30 # failover observation
ssh root@192.168.203.70 'systemctl start keepalived-netns@fw.service'
sleep 200  # preempt-back settle
scp root@192.168.203.93:/tmp/vrrp-drill.log /tmp/vrrp-drill.log
```

Parse log for state transitions (example awk snippet in
`packages/shorewall-nft-stagelab/CLAUDE.md` HA section — TODO: package as
a reusable tool).

**Expected timings** (measured 2026-04-20):
- Failover master→backup: <1s (SNMP-poll-limited to 500ms resolution)
- Preempt-back: 184s (configured `preempt_delay 180s` + SNMP latency)
- No split-brain window, no dual-fault window.

## Phase 5 — Security-test-plan executor

Entry point: `tools/run-security-test-plan.sh`.

### Dry-run all standards (smoke)

```bash
./tools/run-security-test-plan.sh \
    --standards all \
    --config tools/stagelab-example-snmp.yaml \
    --dry-run \
    --out /tmp/sec-plan-dry
```

Should emit "would merge / would validate / would run" lines for all 7
standards (cc, nist, bsi, cis, owasp, iso27001, ipv6-perf).

### Real run with simlab merge (tester01-local)

```bash
# 1. simlab smoke → simlab.json
ssh root@192.168.203.93 'cd /root/shorewall-nft && \
    .venv/bin/python -m shorewall_nft_simlab.smoketest smoke \
        --output-json /tmp/simlab-smoke.json'

# 2. Minimal run.json as placeholder
mkdir -p /tmp/fake-run
cat > /tmp/fake-run/run.json <<EOF_RUN
{
  "run_id": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "config_path": "/tmp/minimal.yaml",
  "scenarios": []
}
EOF_RUN

# 3. Audit merge
.venv/bin/shorewall-nft-stagelab audit /tmp/fake-run \
    --simlab-report /tmp/simlab-smoke.json \
    --output /tmp/sec-audit --format html
```

Expected outputs:
- `/tmp/sec-audit/audit.html` — HTML report with "Correctness (simlab)"
  section showing 2 PASS scenarios with columns `Test-ID`, `Standard:
  cc-iso-15408`, `Control: FDP_IFF.1`.
- `/tmp/sec-audit/audit.json` — schema_version=1, scenarios[] with
  `source: simlab`.

### Full real run (WIP — blocked on tester02 setup)

End state we want:

```bash
./tools/run-security-test-plan.sh \
    --standards all \
    --config tools/stagelab-fw-test-live.yaml \
    --simlab \
    --out /tmp/sec-plan-live
```

where `stagelab-fw-test-live.yaml` wires tester01 (sim-uplink) as one
traffic endpoint and tester02 (downstream customer VLAN) as the other,
so `throughput`, `rule_scan`, `rule_coverage_matrix`, `dos_syn_flood`,
and other traffic-gen scenarios actually pass packets through elgar
and tropheus.

**Currently missing**: tester02 is not yet set up on a downstream VLAN.
Once it is, this section collapses to a single invocation.

## Phase 6 — Audit report collection

Artefacts from a complete run:
- `/tmp/sec-plan-<ts>/audit.html` — reviewable HTML report (grade + per-category tables + recommendations + scenario details)
- `/tmp/sec-plan-<ts>/audit.json` — machine-readable schema_version=1 payload for SIEM ingestion
- `/tmp/sec-plan-<ts>/runs/<std>/run.json` — per-standard stagelab run output
- `/tmp/sec-plan-<ts>/logs/<std>.log` — raw stagelab run logs
- `/tmp/sec-plan-<ts>/simlab.json` — simlab correctness report (if `--simlab`)

Archive the whole directory under a stable path for compliance evidence.

## Known limitations

1. **Traffic-gen scenarios require a downstream endpoint** — until tester02
   is configured on a bond0.X VLAN, `throughput`, `rule_scan`,
   `rule_coverage_matrix`, `dos_*`, `evasion_probes`, etc. are catalogued
   but not runnable end-to-end. Dry-run still validates the YAML/orchestrator.
2. **pdns advisor path is academic** — the `pdns` bundle requires NET-SNMP-EXTEND
   scripts on elgar/tropheus (`extend pdns-all-queries | cache-hits | answers-0-1`).
   Operator TODO on the firewall hosts.
3. **Prod-host read denials** — some diagnostic queries against elgar-test/
   tropheus-test via `ip netns exec fw ...` over SSH are policy-blocked
   from the dev workstation. Run them on the tester (via sim-uplink for ping
   tests) or use SNMP instead.
4. **keepalived-MIB column indices** — the `vrrp_extended` bundle pulls 6
   OIDs but the live VipsStatus column returns a value that looks like
   effective-priority (200) instead of `1/2` enum. Likely keepalived v2.2.8
   MIB-column-index deviation from upstream spec. Non-blocking for the drill
   but worth a separate cross-check.
5. **Catalogue endpoint-names vs. base-config names** — catalogue fragments
   hardcode strings like `v6-client`, `v6-server`, `wan-endpoint`. The base
   config MUST define endpoints with those exact names or validation fails.
   No remap-layer in the executor yet. Workaround: use
   `tools/stagelab-example-ipv6-throughput.yaml` as the base for
   ipv6-perf (names match). Cleaner: TODO-add an endpoint-alias layer to
   the executor, or standardise catalogue scenarios on a fixed naming
   convention (e.g. `src-endpoint` / `dst-endpoint`).
6. **sim-uplink netns owns eth2** on any tester running it — stagelab's
   `native` mode then can't claim eth2 for throughput/conn_storm scenarios
   on the same host. Consequence: on a tester that IS the sim-uplink, you
   can only run `probe`-mode scenarios (rule_scan, evasion_probes,
   rule_coverage_matrix). For native-mode traffic you need a second tester
   whose eth2 is NOT in the sim-uplink netns.
7. **Dev-workstation can't self-run simlab** — simlab needs
   `/root/simulate-data/ip4add` + `ip4routes` + `ip6add` + `ip6routes`
   reference dumps. On tester01/02 these ship with the package; on
   developer laptops they don't. Workaround: run simlab via SSH to tester01
   (`ssh root@192.168.203.93 '…smoketest smoke --output-json…'`) and scp
   the JSON back. The `--simlab` flag of `run-security-test-plan.sh`
   currently invokes simlab on the **local** host; runs from a laptop
   therefore fail that step. TODO: make `--simlab-host` configurable.

## Scenario compatibility matrix

| Scenario kind | Endpoint mode needed | Runnable today from tester01 |
|---------------|----------------------|-------------------------------|
| rule_scan, rule_coverage_matrix, evasion_probes | probe | ✓ (local netns+TAP) |
| throughput, conn_storm, tuning_sweep | native | ✗ (eth2 owned by sim-uplink) |
| throughput_dpdk, conn_storm_astf, dos_* | dpdk | ✗ (virtio-net, no DPDK-capable NIC) |
| ha_failover_drill | uses fw_host SSH only | ✓ (already validated live) |
| conntrack_overflow | native + fw_host SSH | ✗ (native blocked; fw_host SSH OK) |
| reload_atomicity, long_flow_survival | native + fw_host SSH | ✗ (native blocked) |
| stateful_helper_ftp | native + vsftpd | ✗ (native blocked) |

**Implication**: for a full live audit, the test-bed must include at least
one tester-NIC in root-ns (for native mode) in addition to the
sim-uplink-owning one. That's the point of Phase 2 (tester02 setup).

## Open items

- tester02 setup (Task #28 — decide: second sim-uplink for ECMP, OR downstream endpoint on bond0.X VLAN).
- `run-security-test-plan.sh --simlab` integration (currently simlab must be run manually; flag wiring in D1 but not exercised end-to-end).
- VRRP column-index cross-check on keepalived v2.2.8 MIB (follow-up).
- pdns-extend configuration on firewall hosts (operator TODO).
- Tagging and release of v1.10.0 once feature branch is merged.
