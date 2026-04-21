# Performance baseline — 2026-04-21

Throughput numbers from live perf reruns against the reference HA firewall
test-bed (tester01 + tester02, VLAN 20, L2-adjacent endpoints).

---

## Topology

Both `wan-native` (tester01 eth1.20) and `lan-downstream` (tester02 eth1.20)
are on the **same VLAN 20 L2 broadcast domain**.  These are **NOT through-FW
end-to-end** measurements.  Both hosts connect to the same customer-VLAN-
transparent trunk bridge; traffic does not traverse the reference HA firewall
forwarding path.

```
tester01 eth1.20 (wan-native)  ←— VLAN 20 L2 —→  tester02 eth1.20 (lan-downstream)
  203.0.113.253/24                                  203.0.113.254/24
  2001:db8:0:3168::253/64                            2001:db8:0:3168::254/64
```

Consequence: the numbers below represent **NIC-to-NIC kernel-stack
throughput** capped by the tester hardware, not through-firewall forwarding
performance.  For through-FW forwarding throughput, a second VLAN bridge
segment (or a zone-pair ACCEPT rule permitting iperf3) would be needed.

## Hardware caveat

Both testers are **Proxmox VMs with virtio-net NICs**.  virtio-net is
software-emulated and cannot deliver line-rate throughput.  The numbers below
represent the virtio-net ceiling on this hardware:

- TCP: ~35–39 Gbps (4 parallel streams, shared memory path on the Proxmox host)
- UDP: ~7–8 Gbps (2 parallel streams, after `-b 0` unlimited-bandwidth fix)

For DPDK line-rate (40–100 Gbps) testing see task #31 (physical NIC with
PCI passthrough to the test VMs).

---

## IPv4 TCP throughput

| Run | Date | Scenario | Gbps | Duration | Parallel streams | OK? |
|-----|------|----------|------|----------|------------------|-----|
| `udp-rerun` | 2026-04-21 | perf-conntrack-observe-throughput | 36.95 | 60 s | 4 | PASS |
| `ipv4-tcp-fix` | 2026-04-20 | perf-ipv4-tcp-throughput | **36.86** | 30 s | 4 | PASS |
| `ipv4-tcp-fix` | 2026-04-20 | perf-conntrack-observe-throughput | **35.37** | 60 s | 4 | PASS |

Source: `wan-native` → `lan-downstream`, IPv4, TCP, 4 parallel iperf3 streams.
SLO: ≥ 8.0 Gbps.  Passes at 35–37 Gbps (4× margin on virtio-net).

**Fix applied**: `perf-ipv4-tcp-throughput` catalogue entry previously targeted
`source_role: wan-uplink` (probe mode, no IPv4 stack — iperf3 binds to `""` and
exits immediately with "Name or service not known").  Retargeted to
`source_role: wan-native` (tester01 eth1.20, IPv4 `203.0.113.253/24`) in
commit `fix(catalogue): perf-ipv4-tcp-throughput → wan-native (was probe-mode)`.

**preexec_fn fix applied**: `_exec_in_netns` in `agent.py` previously called
`ctypes.CDLL("libc.so.6")` inside `preexec_fn`.  In a multithreaded asyncio
process, `fork()` preserves mutex lock state — if the dlopen lock is held by
another thread at fork time, the child inherits a permanently locked mutex and
any `ctypes.CDLL()` call in `preexec_fn` deadlocks, causing Python to raise
`SubprocessError: Exception occurred in preexec_fn`.  Fixed by loading libc
once at module import time (`_libc = ctypes.CDLL(...)` at module level).
`SubprocessError` is also now caught by the fallback path (`ip netns exec`)
alongside `OSError`, so any future preexec_fn failure degrades gracefully.

---

## IPv4 UDP throughput

| Run | Date | Scenario | Gbps | Duration | Parallel streams | OK? |
|-----|------|----------|------|----------|------------------|-----|
| `ipv4udp-baseline` | 2026-04-20 | perf-ipv4-udp-throughput | **6.48** | 20 s | 2 | PASS |

Source: `wan-native` → `lan-downstream`, IPv4, UDP, 2 parallel iperf3 streams,
`udp_bandwidth_mbps: 0` (unlimited).  SLO: ≥ 5.0 Gbps.

Fix: the entry previously used `source_role: wan-uplink` (probe mode, no IPv4
stack — iperf3 cannot run against probe endpoints).  Retargeted to
`source_role: wan-native` (tester01 eth1.20 with real IPv4 `203.0.113.253/24`)
in commit `fix(catalogue): IPv4 UDP throughput uses wan-native endpoint`.

---

## IPv6 TCP throughput

| Run | Date | Scenario | Gbps | Duration | Parallel streams | OK? |
|-----|------|----------|------|----------|------------------|-----|
| `full12` | 2026-04-21 | perf-ipv6-tcp-throughput | 34.67 | 30 s | 4 | PASS |
| `ipv6fix2` | 2026-04-20 | perf-ipv6-tcp-throughput | **34.58** | 30 s | 4 | PASS |
| `full17` | 2026-04-21 | perf-ipv6-tcp-throughput | 38.59 | 30 s | 4 | PASS |
| `udp-rerun` | 2026-04-21 | perf-ipv6-tcp-throughput | 36.23 | 30 s | 4 | PASS |

Source: `wan-native` → `lan-downstream`, IPv6, TCP, 4 parallel iperf3 streams.
SLO: ≥ 8.0 Gbps.  All runs pass comfortably (4× margin).

---

## IPv6 UDP throughput

| Run | Date | Gbps | Duration | Parallel streams | OK? | Notes |
|-----|------|------|----------|------------------|-----|-------|
| `ipv6fix2` | 2026-04-20 | 0.004 | 20 s | 2 | FAIL | **Before** `-b 0` fix; iperf3 default 1 Mbit/s cap per stream |
| `full12` | 2026-04-21 | 7.16 | 20 s | 2 | PASS | After fix |
| `full17` | 2026-04-21 | 7.53 | 20 s | 2 | PASS | After fix |
| `udp-rerun` | 2026-04-21 | **7.79** | 20 s | 2 | PASS | After fix, this run |

Source: `wan-native` → `lan-downstream`, IPv6, UDP, 2 parallel iperf3 streams,
`udp_bandwidth_mbps: 0` (unlimited).  SLO: ≥ 5.0 Gbps.

### `-b 0` fix

Prior to commit `102f4d830` (`feat(stagelab): … UDP unlimited …`), iperf3
UDP runs without an explicit `-b` flag were capped at iperf3's built-in
default of **1 Mbit/s per stream** (regardless of the configured
`udp_bandwidth_mbps: 0`).  The fix emits `-b 0` explicitly when
`udp_bandwidth_mbps == 0`, removing the cap.  This delivered the jump from
0.004 Gbps → 7+ Gbps shown above.

---

## Conntrack peak observed during TCP throughput

| Run | fw_host setting | conntrack_peak_observed | Notes |
|-----|-----------------|------------------------|-------|
| `udp-rerun` | `root@fw-primary` | **0** | Sidecar ran, 0 samples — hostname unresolvable |
| `full17` | `root@fw-primary` | **0** | Same — hostname unresolvable |
| `conntrack-chain` | `root@fw-primary` | **0** | SSH chain works (2026-04-20); scenario failed on IPv4 preexec_fn — see below |

### SSH agent-forwarding chain (2026-04-20)

The SSH agent-forwarding chain is now operational:

- `spawn_ssh` in `controller.py` passes `-A` to forward the local ssh-agent
  into the tester's shell.
- All fw_host ssh invocations in `agent.py` (`poll_conntrack`,
  `trigger_fw_reload`, `set_fw_sysctl`, `stop/start_fw_service`,
  `query_conntrack_count`, `_handle_conntrack_overflow_inspect`) pass `-A`
  so the agent is forwarded through to the reference HA firewall.
- `/etc/hosts` on both testers maps `fw-primary` and `fw-secondary` to their
  respective IPs (state-only entries, written 2026-04-20).

Pre-check confirmed: `ssh -A root@tester01 "ssh -A root@fw-primary 'conntrack -L 2>/dev/null | wc -l'"` returns `0` (idle firewall — no active conntrack entries; SSH succeeds).

**Blocker resolved**: the IPv4 iperf3 `preexec_fn` issue that prevented
`perf-conntrack-observe-throughput` from running has been fixed (see
"IPv4 TCP throughput" section above).  `perf-conntrack-observe-throughput`
now runs the full 60 s measurement window and the conntrack sidecar
(`poll_conntrack`) can return real counts from the reference HA firewall
once `fw_host` is set to a resolvable address (see follow-up item 1).

---

## conn-storm baseline

| Run | target_conns | established | failed | OK? | Notes |
|-----|-------------|-------------|--------|-----|-------|
| `udp-rerun` | 100 000 | 0 | 100 000 | FAIL | HTTP listener died before storm connected (pre-fix) |

### Root cause (fixed, commit ceff3a528)

`ConnStormRunner` emits `[start_http_listener(sink), run_tcpkali(source),
stop_http_listener(sink)]`.  The controller groups by host and runs groups
concurrently.  The sink group (tester02) ran start→stop sequentially, stopping
the HTTP listener immediately after starting it, before the source group
(tester01) even began connecting.

**Fix**: `stop_http_listener` now carries `delay_before_s = hold_s + 2` so the
listener stays alive for the entire storm duration.  The controller timeout for
`start/stop_http_listener` is now `delay_before_s + 30 s` (was fixed 120 s).

**Expected post-fix result**: ~100 000 connections established (L2-local
path, no FW forwarding involved; port 80 served by stdlib HTTP server in the
`lan-downstream` netns).

---

## Rerun recipe

```bash
# From repo root. Activates .venv automatically via the script.
# Sync latest code to testers first:
for h in 192.0.2.93 192.0.2.74; do
    rsync -a --delete \
        packages/shorewall-nft-stagelab/shorewall_nft_stagelab/ \
        root@$h:/root/shorewall-nft/packages/shorewall-nft-stagelab/shorewall_nft_stagelab/
done

# Run IPv6-perf standard (TCP + UDP throughput + conntrack-observe scenarios):
rm -rf /tmp/udp-rerun
STAGELAB_SNMP_COMMUNITY_MON=public \
    ./tools/run-security-test-plan.sh \
        --standards ipv6-perf \
        --config tools/stagelab-fw-test-live.yaml \
        --out /tmp/udp-rerun

# Expected wall-clock: ~3 min (30s TCP + 20s UDP + 60s conntrack-observe + setup + audit)
# Expected Gbps ranges (virtio-net on Proxmox):
#   IPv6 TCP: 34–40 Gbps (highly variable depending on Proxmox host load)
#   IPv6 UDP: 7–8 Gbps (2 parallel streams, -b 0 unlimited)
#   IPv4 TCP (conntrack-observe run): 35–40 Gbps

# Inspect results:
python3 -c "
import json
with open('/tmp/udp-rerun/audit.json') as f:
    data = json.load(f)
for sc in data['scenarios']:
    gbps = sc.get('raw', {}).get('throughput_gbps', 'N/A')
    print(f'{sc[\"test_id\"]}: ok={sc[\"ok\"]}, gbps={gbps}')
"
```

---

## Conntrack sidecar timing fix (commit 2c3ecc45)

Root-cause analysis of `conntrack_peak_observed = 0`:

**Two independent problems were found:**

### Problem 1: Sequential dispatch (fixed)

`poll_conntrack` was dispatched to the same host group as the iperf3 client
(both on tester01).  Within a host group, commands run sequentially
(`_run_host_group` iterates with `await`).  By the time `poll_conntrack`
started, the iperf3 run had finished and all TCP connections were gone.

**Fix** (commit `2c3ecc45`): Added `concurrent: bool = False` to `AgentCommand`.
The `poll_conntrack` sidecar is now emitted with `concurrent=True`.  The
controller's `_run_host_group` splits the group into sequential + concurrent
batches and runs them as concurrent asyncio tasks via `asyncio.gather`.
For `poll_conntrack`, the controller runs SSH **directly** (bypassing agent IPC)
rather than sending through the request-response channel, so the SSH poll
genuinely overlaps with the iperf3 run.

### Problem 2: L2-local traffic (topology limitation, NOT fixed by code)

Both `wan-native` (203.0.113.253) and `lan-downstream` (203.0.113.254) are
on the **same VLAN 20 L2 broadcast domain**.  iperf3 between them uses ARP to
find the MAC directly — traffic NEVER transits the FW forwarding path.  The
FW's netfilter/conntrack stack sees zero packets from this flow.

**Consequence**: `conntrack_peak_observed` will remain 0 for `wan-native →
lan-downstream` even with the timing fix.

**Required operator action**: For a real through-FW conntrack measurement:

Option A (recommended): Add a temporary ACCEPT rule on the FW permitting
iperf3 traffic between tester01's sim-uplink (203.0.113.74/27, net zone) and
tester02's downstream (203.0.113.128/25, host zone), then re-run with
`source_role: wan-uplink` and `sink_role: lan-downstream`.

Option B: Place tester01 and tester02 on different VLANs/subnets with the FW
as the only IP-layer path between them.

Until one of these is done, `perf-conntrack-observe-throughput` will always
report `conntrack_peak_observed = 0` even with the timing fix applied.

---

## DoS scenarios (Target 2)

All three live-DoS scenarios (`dos_syn_flood`, `dos_half_open`, `dos_dns_query`)
are hard-gated to `mode=dpdk` endpoints (TRex STL / ASTF).  They **cannot** run
on the current virtio-net test VMs without new kernel-stack scenario kinds.

| Scenario | Backend required | Virtio-net possible? |
|----------|-----------------|----------------------|
| `dos_syn_flood` | TRex STL (raw SYN packets) | No |
| `dos_half_open` | TRex ASTF (half-open TCP) | No |
| `dos_dns_query` | TRex STL (UDP/53 queries) | No |

A kernel-stack DoS proxy can be approximated with `conn_storm` at high rate
(e.g. `target_conns=5000, rate_per_s=5000, hold_s=10`).  This tests FW
resilience to connection bursts and fills conntrack — but only if through-FW
routing is set up (see Problem 2 above).

Tracking item: to enable kernel-stack DoS on virtio, add
`SynFloodNativeDosScenario` (pyconn backend) + `HalfOpenNativeDosScenario`
(pyconn with `hold_s` > 0 and no FIN).

---

## Flowtable offload (Target 3)

`nist-sc-7-flowtable-offload` is status `partial`.  The acceptance criterion
`flowtable_counter_nonzero: true` is not yet evaluated by `ThroughputRunner`.
The `advisor.py` `_h_flowtable_stagnant` heuristic fires on
`flowtable_*=0` in SNMP/nft-ssh MetricRows, which is a proxy signal.

To implement real flowtable counter tracking:
1. Add `observe_flowtable: bool` + `flowtable_fw_host: str | None` to
   `ThroughputScenario`.
2. In the controller, add `_run_flowtable_counter_poll_local` that SSHes to FW
   and runs `nft -j list ruleset` before and after the iperf3 run, extracts
   flowtable packet deltas, and stores them in `ScenarioResult.raw`.
3. In `ThroughputRunner.summarize()`, evaluate
   `acceptance_criteria["flowtable_counter_nonzero"]` against the packet delta.

This is tracked as a follow-up — the structural pattern (concurrent sidecar via
controller-local SSH) is identical to the conntrack sidecar fix already shipped.

---

---

## Through-FW conntrack probe (perf-through-fw-conntrack-probe)

**Status**: Designed; not yet executed.

**Rule piggybacked**: `SSH(ACCEPT) net:203.0.113.64/27 $FW`
(line 47, `/etc/shorewall/rules` on the reference HA firewall primary node)

**Traffic path**: tester01 eth2 (`203.0.113.74/27`) → FW `bond1`
(`203.0.113.75`) tcp/22 → SSHd on the FW itself.  Zone: `net → $FW` (INPUT
chain).  Conntrack sees the flow because it arrives on `bond1` (net zone
interface) and is directed at the FW itself.

**Scenario kind**: `conn_storm_direct` — targets a fixed IP:port directly
without requiring an HTTP listener on a sink endpoint.  The FW's SSHd
completes the TCP 3-way handshake; each connection contributes one
`ESTABLISHED` entry to conntrack.

**Source endpoint**: `net-backbone-native` — tester01, `mode: native`,
`nic: eth2` (untagged, no VLAN), `ipv4: 203.0.113.74/27`.  This requires
`topology_native.py` untagged-NIC support (NIC moved directly into netns,
`vlan=None`), added in this commit.

**Pre-run operator steps**:
1. `ssh root@192.0.2.93 "systemctl stop sim-uplink"` — sim-uplink uses
   eth2 (router ID `203.0.113.77`); must not conflict with the test endpoint.
2. `ssh root@192.0.2.93 "ip route"` — verify the default route still
   exists via the management NIC (eth0 or equivalent) so stagelab SSH stays up.
3. Run: `STAGELAB_SNMP_COMMUNITY_MON=public .venv/bin/shorewall-nft-stagelab run tools/stagelab-fw-test-live.yaml --output-dir /tmp/through-fw-test`
4. `ssh root@192.0.2.93 "systemctl start sim-uplink"` — restore.

**Expected results**:
| Metric | Expected range | Notes |
|--------|---------------|-------|
| `conntrack_peak_observed` | 10–1000 | SSH MaxStartups limits concurrent handshakes to ~128 by default; actual peak depends on FW sshd config |
| `established` | ≥ 10% of `target_conns` | SSH rate-limiting reduces success rate |
| `flowtable_packets_delta` | N/A | SSH flows are short-lived; flowtable offload unlikely to fire for tcp/22 |

**Flowtable note**: flowtable offload (`nft flowtable`) targets long-lived
throughput flows (http/https/iperf3), not short SSH handshakes.  For real
flowtable delta > 0, the scenario should target a long-lived TCP flow (e.g.
iperf3 on port 5201 against `host:$UPDATES` which has `ACCEPT all host:$UPDATES
tcp ... 5201` at rules line 616).  That requires tester01 in net zone +
tester02 in host zone as a through-FW iperf3 pair — a follow-up item.

---

## Follow-up items for operator

1. **Through-FW routing**: add a temporary ACCEPT rule on the FW for
   tester01 sim-uplink (net zone) → tester02 downstream (host zone) on
   tcp/5201 (iperf3), then re-run `perf-conntrack-observe-throughput` with
   `source_role: wan-uplink` to get real `conntrack_peak_observed` > 0.

2. **conn-storm HTTP listener**: add a `start_http_listener` sidecar command
   in `ConnStormRunner` (or in the catalogue entry) so port 80 on `lan-downstream`
   is served before the storm starts.

3. **IPv4 TCP native baseline**: ~~`perf-ipv4-tcp-throughput` targets
   `source_role: wan-uplink`~~ — **fixed**: retargeted to `wan-native` and
   preexec_fn dlopen issue resolved.  IPv4 TCP baseline now measurable via
   `wan-native` → `lan-downstream` (≈ 36–37 Gbps on virtio-net).

4. **DPDK line-rate** (task #31): provision physical NIC via Proxmox PCI
   passthrough for real 10–40 Gbps measurements.  The current virtio-net
   numbers are a software-emulation ceiling, not a firewall performance ceiling.

5. **Flowtable offload verification**: implement `observe_flowtable` in
   `ThroughputScenario` + controller sidecar (see flowtable section above).
   Prerequisite: through-FW routing must be set up so test traffic actually
   traverses the FW's flowtable rules.
