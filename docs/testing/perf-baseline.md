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
| `udp-rerun` | 2026-04-21 | perf-conntrack-observe-throughput | **36.95** | 60 s | 4 | PASS |

Source: `wan-native` → `lan-downstream`, IPv4, TCP, 4 parallel iperf3 streams.

*Note*: the `perf-ipv4-tcp-throughput` catalogue entry targets `wan-uplink`
(probe mode), which has no IPv4 address and therefore produces 0 Gbps.  The
IPv4 throughput number above comes from the `perf-conntrack-observe-throughput`
scenario, which uses `wan-native` (native mode with IPv4 `203.0.113.253/24`).

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

### Why conntrack_peak is 0

The `perf-conntrack-observe-throughput` catalogue entry uses
`fw_host: root@fw-primary`, a placeholder hostname.  The sidecar
(`_handle_poll_conntrack` in `agent.py`) SSHes to `fw_host` every second
during the 62 s measurement window.  Two failure modes combine:

1. `root@fw-primary` does not resolve (no DNS entry for this name in the
   test environment).  The correct address is `root@192.0.2.70`.
2. Even with the correct IP, **tester01 has no SSH private key authorised
   on the reference HA firewall**.  `BatchMode=yes` is enforced by the
   sidecar — it will not prompt for a password.

The sidecar soft-fails on all SSH errors (no exception propagation), so
the throughput scenario itself passes and records `conntrack_peak_observed: 0`.

**Required operator action** before the conntrack sidecar can produce real
data:
- Update the catalogue entry: `fw_host: root@192.0.2.70`
- Deploy tester01's SSH public key to `root@192.0.2.70:~/.ssh/authorized_keys`

This is flagged as an operator TODO; SSH key deployment is out of scope for
this task (see CLAUDE.md — no SSH key deployment by agents).

---

## conn-storm baseline

| Run | target_conns | established | failed | OK? | Notes |
|-----|-------------|-------------|--------|-----|-------|
| `udp-rerun` | 100 000 | 0 | 100 000 | FAIL | No HTTP listener on port 80 at `lan-downstream` |

The `perf-conntrack-observe-conn-storm` catalogue entry opens 100 000 TCP
connections to port 80 on `lan-downstream`.  There is no HTTP server running
at that endpoint, so all connections are refused immediately.  The scenario
needs an HTTP listener (e.g. `start_http_listener` sidecar) on the sink
endpoint, or a well-known open port.  This is a pre-existing catalogue gap,
not a code regression.

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

## Follow-up items for operator

1. **Conntrack sidecar**: update `fw_host: root@fw-primary` to
   `fw_host: root@192.0.2.70` in `docs/testing/security-test-plan.ipv6-perf.yaml`
   and deploy tester01's SSH key to the FW.

2. **conn-storm HTTP listener**: add a `start_http_listener` sidecar command
   in `ConnStormRunner` (or in the catalogue entry) so port 80 on `lan-downstream`
   is served before the storm starts.

3. **IPv4 TCP native baseline**: `perf-ipv4-tcp-throughput` still targets
   `source_role: wan-uplink` (probe mode, no IPv4 stack) and records 0 Gbps.
   Retargeting to `wan-native` is a separate follow-up (same fix pattern as
   this task).

4. **DPDK line-rate** (task #31): provision physical NIC via Proxmox PCI
   passthrough for real 10–40 Gbps measurements.  The current virtio-net
   numbers are a software-emulation ceiling, not a firewall performance ceiling.
