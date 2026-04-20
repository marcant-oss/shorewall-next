---
title: stagelab — distributed bridge-lab for FW performance and readiness testing
description: Performance, readiness and correctness testing of shorewall-nft against real firewall hardware via a VLAN-trunked bridge-lab.
---

# stagelab — distributed bridge-lab for FW performance and readiness testing

`shorewall-nft-stagelab` is a distributed test lab that drives synthetic
traffic from one or more high-throughput test hosts through a real firewall
appliance via a VLAN trunk, and measures throughput, connection-rate, and
correctness. It complements `shorewall-nft-simlab`, which validates compiled
ruleset correctness inside a local network namespace; stagelab validates
**performance and readiness against real firewall hardware under
production-grade load**.

Three endpoint modes cover the full range of test goals:

- **`probe`** — scapy-built frames injected via a TAP device inside a
  VLAN-filtering Linux bridge. Correct-verdict testing at ~1 Gbps, no
  physical NIC required on the test host. Used for correctness smoke runs.
- **`native`** — a physical NIC VLAN sub-interface moved into a dedicated
  network namespace. iperf3 and nmap run inside the namespace at 10–25 Gbps
  and up to ~1 M concurrent connections. Used for kernel-stack
  throughput/scan scenarios.
- **`dpdk`** — NIC detached from the kernel and bound to `vfio-pci`, driven
  by TRex in stateless (STL) or ASTF mode. Line-rate at 40–100 Gbps,
  10 M+ concurrent ASTF sessions. Used for stress-testing and capacity planning.

## When to use stagelab vs simlab

| Goal | Tool |
|------|------|
| Verify compiled ruleset emits correct verdicts | simlab |
| Correctness smoke run against real FW hardware (no line-rate NIC needed) | stagelab `probe` |
| Throughput / latency benchmarking at 10–25 Gbps | stagelab `native` |
| Port scan / vulnerability scan simulation | stagelab `native` (nmap) |
| Sweep kernel tuning knobs automatically | stagelab `native` + `tuning_sweep` |
| Line-rate / 40–100 Gbps UDP/TCP stateless flood | stagelab `dpdk` + `throughput_dpdk` |
| 10 M+ concurrent session storm (ASTF) | stagelab `dpdk` + `conn_storm_astf` |

---

## Installation and bootstrap

Bootstrap is handled by `tools/setup-remote-test-host.sh` using the `--role`
flag. The script is idempotent — safe to re-run after the test box is
re-imaged.

```
tools/setup-remote-test-host.sh root@<host> [--role ROLE]
```

### Roles

| `--role` | What it installs |
|----------|-----------------|
| `default` | simlab / simulate tooling only (iptables dump, venv, shorewall-nft, simlab) |
| `stagelab-agent` | `default` + iperf3, nmap, ethtool, bridge-utils, jq, tcpdump; high-pps sysctls (nf\_conntrack\_max=4 M, rmem/wmem\_max=128 MiB) |
| `stagelab-agent-dpdk` | `stagelab-agent` + DPDK tools, vfio-pci module, hugepages, TRex bundle staged at `/opt/trex/vX.YY`, `/var/lib/stagelab/` recovery dir |

Both `stagelab-agent` and `stagelab-agent-dpdk` support Debian/grml (apt) and
AlmaLinux 10 (dnf). The script detects the package manager automatically.

The venv install order is load-bearing — `shorewall-nft-netkit` must be
installed before `shorewall-nft-simlab` (which depends on it):

```bash
pip install -e 'packages/shorewall-nft-netkit[dev]' \
            -e 'packages/shorewall-nft[dev]' \
            -e 'packages/shorewalld[dev]' \
            -e 'packages/shorewall-nft-simlab[dev]' \
            -e 'packages/shorewall-nft-stagelab[dev]'
```

### DPDK bootstrap environment variables

These are honoured by `setup-remote-test-host.sh` with `--role stagelab-agent-dpdk`:

| Variable | Default | Effect |
|----------|---------|--------|
| `STAGELAB_HUGEPAGES` | `512` (1 GiB) | Number of 2 MiB hugepages to allocate |
| `STAGELAB_SKIP_SHA` | unset | Set to `1` to skip TRex tarball SHA-256 verification (dev/CI only) |
| `STAGELAB_DPDK_IFACES` | `eth1 eth2` | Space-separated list of NIC names to mark unmanaged in NetworkManager before DPDK binding |

Additional bootstrap behaviours (Phase 3):

- **EPEL + CRB**: the script enables EPEL and CRB on AlmaLinux before installing
  stagelab tools. It only runs `dnf install epel-release` when no enabled repo
  already matches `/epel/` — hosts with a vendor overlay that ships EPEL are
  handled gracefully.
- **Binary verification**: after each install phase the script calls
  `verify_binaries` (and `verify_sysctl` for tuning knobs) and fails fast with
  a clear error if any required binary is missing. Missing binaries on AlmaLinux
  are almost always caused by EPEL/CRB not being enabled.
- **NM unmanaged block**: when `IS_DPDK=1`, any NIC listed in
  `STAGELAB_DPDK_IFACES` that is currently managed by NetworkManager is
  detached and a drop-in config is written to
  `/etc/NetworkManager/conf.d/20-stagelab-unmanaged.conf`. Idempotent: if the
  NIC is already unmanaged (via a pre-existing conf or no NM at all) the step
  is skipped.

---

## YAML config reference

A stagelab run is described by a single YAML file passed to
`stagelab validate` / `stagelab run`. The top-level keys are:

```
hosts:       list[Host]
dut:         Dut
endpoints:   list[Endpoint]
scenarios:   list[Scenario]
metrics:     MetricsSpec        # optional, default: empty
report:      ReportSpec
```

### Host

```yaml
- name: tester-1          # logical label used in endpoint.host
  address: "root@192.0.2.73"   # SSH target; "local:" prefix = local subprocess
  work_dir: /root/shorewall-nft  # default
  isolate_cores: []              # CPUs to pin to (informational)
  hugepages_gib: 0               # total hugepages reserved on host (informational)
```

When `address` starts with `local:` the agent is spawned as a local
subprocess instead of over SSH.

### DUT (device under test)

```yaml
dut:
  kind: external    # "external" = real FW appliance wired by VLAN trunk
                    # "netns"    = shorewall-nft running in a local netns (dev/CI)
```

### Endpoint

```yaml
- name: ep-src
  host: tester-1
  mode: native        # "probe" | "native" | "dpdk"
  nic: ens5           # physical NIC
  vlan: 100           # VLAN sub-interface to create
  ipv4: 10.100.0.2/24
  ipv4_gw: 10.100.0.1
  ipv6: "2001:db8:1::2/64"      # optional
  ipv6_gw: "2001:db8:1::1"      # optional
  rss_queues: 4                  # RSS queue count (native only)
  irq_affinity: [2, 3, 4, 5]    # IRQ CPUs (native only)
```

For `probe` mode, replace `nic`/`vlan`/`ipv4` with:

```yaml
  mode: probe
  bridge: br-fw          # Linux bridge name that has the FW trunk port as a member
  vlan: 100
```

For `dpdk` mode:

```yaml
  mode: dpdk
  pci_addr: "0000:01:00.0"      # mandatory; must match ^[0-9a-f]{4}:…\.[0-7]$
  dpdk_cores: [2, 3]             # mandatory; CPU cores for DPDK poll-mode driver
  hugepages_gib: 4               # mandatory; must be >= 1
  trex_role: client              # "client" | "server"
```

Constraints enforced by `config.py`:

- The same (host, nic) cannot appear in both `probe` and `native` endpoints.
- `probe` endpoints must set `bridge`; `native` endpoints must not.
- A NIC cannot be used as both a kernel endpoint (native/probe) and a DPDK
  endpoint on the same host.
- `throughput_dpdk` and `conn_storm_astf` scenarios require `dpdk` endpoints.

### Scenarios

```yaml
scenarios:
  - id: my-throughput
    kind: throughput
    source: ep-src
    sink: ep-dst
    proto: tcp
    duration_s: 30
    parallel: 4
    expect_min_gbps: 5.0
```

Full scenario reference: see [Scenarios](#scenarios) section below.

### MetricsSpec

```yaml
metrics:
  poll_interval_s: 1
  collect:           # local metrics polled by the agent on each host
    - nft_counters       # nft list counters (requires loaded shorewall ruleset on FW)
    - conntrack_stats    # /proc/net/nf_conntrack_stat
    - nic_ethtool        # ethtool -S <iface>
    - cpu_softirq        # /proc/softirqs NET_RX per CPU
  sources:
    - kind: prometheus
      name: fw-prom
      url: http://192.168.1.1:9100/metrics
      timeout_s: 5.0
      metric_prefix_allow:
        - node_network_receive
        - node_cpu
    - kind: snmp
      name: fw-switch
      host: 192.168.1.254
      community: public
      port: 161
      timeout_s: 3.0
      oids:
        - "1.3.6.1.2.1.2.2.1.10"   # ifInOctets
        - "1.3.6.1.2.1.2.2.1.16"   # ifOutOctets
    - kind: nft_ssh
      name: fw-nft
      ssh_target: root@192.168.1.1
      timeout_s: 10.0
```

#### `nft_ssh` source (Phase 3)

The `nft_ssh` source kind SSHes into the firewall and runs
`nft list counters -j`, then ingests every named counter as `MetricRow`
entries. For each counter three rows are emitted: `<name>:packets`,
`<name>:bytes`, and `<name>:counter` (a duplicate of the packet count).

The `:counter`-suffixed rows are what feeds the `_h_rule_order_topN`
advisor heuristic: the controller aggregates all rows whose `source` ends
with `:counter` into a ranked mapping `{counter_name: max_packet_count}`,
which the advisor uses to detect when the top-3 counters account for
more than 70% of total traffic across 10+ counters (tier-C rule-order hint).

No Prometheus endpoint on the firewall is required for this source kind —
only SSH access and a loaded nftables ruleset with named counters.

### SNMP sources

SNMP sources poll firewall nodes and switches directly using SNMP v2c.
pysnmp runs on the **tester VM** (the stagelab agent), not on the firewall.

#### Install

```bash
pip install 'shorewall-nft-stagelab[snmp]'
```

Run this on the controller host and on every tester VM that will poll SNMP.
The `stagelab-agent` bootstrap role (`tools/setup-remote-test-host.sh --role stagelab-agent`)
is the target; the SNMP extra must be added manually until the bootstrap script
is updated.

#### Set the community

Store the community string in a secure location — never commit it:

```bash
# Secure options:
#   systemd credential file
#   sourced env file outside git (e.g. /etc/stagelab/env)
export STAGELAB_SNMP_COMMUNITY_MON=<your-read-only-community>
```

stagelab reads it at config-load time from the environment. The `${…}` placeholder
form is the only accepted syntax in YAML — a literal community string in YAML will
be treated as a validation error if it does not match the `${VAR}` pattern.

#### Bundle table

| Bundle | What it exposes | Typical use |
|--------|-----------------|-------------|
| `node_traffic` | ifHCInOctets / ifHCOutOctets + discard counters (IF-MIB 64-bit) | Replacement for ethtool polling; works across switches and remote FW nodes |
| `system` | UCD-SNMP load averages (1/5/15 min) + sysUpTime | CPU saturation signal during DoS scenarios |
| `vrrp` | keepalived VRRP instance state + name (KEEPALIVED-MIB) | Sub-second HA-failover drill real downtime measurement |
| `vrrp_extended` | vrrp_instance_vrid, vrrp_instance_wanted_state, vrrp_instance_effective_priority, vrrp_instance_vips_status, vrrp_instance_preempt, vrrp_instance_preempt_delay | Richer HA-observability: track-script priority drain, VIP assignment status, preempt config; use alongside `vrrp` during failover drills |
| `pdns` | PowerDNS-Recursor stats via NET-SNMP-EXTEND-MIB | DNS-DoS advisor signal: QPS increase ratio and cache-hit rate |

Use `bundles: [node_traffic, system, vrrp, vrrp_extended, pdns]` to collect all five.
The `oids` field must list the raw OIDs for the bundles you select — see
`tools/stagelab-example-snmp.yaml` for the full list.

#### Example config

See `tools/stagelab-example-snmp.yaml` for a complete runnable example with
two SNMP sources (one per HA node) alongside a Prometheus source.

Minimal metrics block:

```yaml
metrics:
  poll_interval_s: 5
  sources:
    - kind: snmp
      name: fw-primary-snmp
      host: 192.0.2.70
      community: "${STAGELAB_SNMP_COMMUNITY_MON}"
      oids:
        - "1.3.6.1.2.1.31.1.1.1.6"      # ifHCInOctets
        - "1.3.6.1.2.1.31.1.1.1.10"     # ifHCOutOctets
        - "1.3.6.1.4.1.9586.100.5.2.1.1.4"  # vrrpInstanceState
      bundles: [node_traffic, vrrp]
```

#### Security note

Communities are secrets. The `${VARNAME}` placeholder syntax is the **only** supported
form in YAML. Never paste a resolved community into the config file or commit it to git.
The `SNMPSourceSpec` validator raises an error if the env var referenced by `${…}` is
unset at config-load time — the original placeholder (not the secret) appears in that
error message.

---

### ReportSpec

```yaml
report:
  output_dir: /root/stagelab-reports
  keep_pcaps: failed_only    # "none" | "failed_only" | "all"
```

---

## Config snippets

### Minimal probe-only correctness smoke

```yaml
hosts:
  - name: tester
    address: "root@192.0.2.73"

dut:
  kind: external

endpoints:
  - name: probe-net
    host: tester
    mode: probe
    bridge: br-fw-trunk
    vlan: 200

scenarios:
  - id: smoke-scan
    kind: rule_scan
    source: probe-net
    target_subnet: "10.200.0.0/24"
    random_count: 200

report:
  output_dir: /root/stagelab-reports
```

### Native throughput + tuning sweep + Prometheus metrics

```yaml
hosts:
  - name: tester
    address: "root@192.0.2.73"

dut:
  kind: external

endpoints:
  - name: src
    host: tester
    mode: native
    nic: ens5
    vlan: 100
    ipv4: 10.100.0.2/24
    ipv4_gw: 10.100.0.1
  - name: dst
    host: tester
    mode: native
    nic: ens5
    vlan: 200
    ipv4: 10.200.0.2/24
    ipv4_gw: 10.200.0.1

scenarios:
  - id: tput-base
    kind: throughput
    source: src
    sink: dst
    proto: tcp
    duration_s: 30
    parallel: 4
    expect_min_gbps: 5.0

  - id: sweep-rss
    kind: tuning_sweep
    source: src
    sink: dst
    proto: tcp
    duration_per_point_s: 10
    rss_queues: [1, 2, 4, 8]
    rmem_max: [67108864, 134217728]
    wmem_max: [67108864, 134217728]

metrics:
  poll_interval_s: 1
  collect: [nft_counters, conntrack_stats, nic_ethtool]
  sources:
    - kind: prometheus
      name: fw
      url: http://192.168.1.1:9100/metrics

report:
  output_dir: /root/stagelab-reports
```

### DPDK throughput at line rate

```yaml
hosts:
  - name: dpdk-host
    address: "root@192.0.2.73"
    hugepages_gib: 8

dut:
  kind: external

endpoints:
  - name: dpdk-tx
    host: dpdk-host
    mode: dpdk
    pci_addr: "0000:01:00.0"
    dpdk_cores: [2, 3]
    hugepages_gib: 4
    trex_role: client
  - name: dpdk-rx
    host: dpdk-host
    mode: dpdk
    pci_addr: "0000:01:00.1"
    dpdk_cores: [4, 5]
    hugepages_gib: 4
    trex_role: server

scenarios:
  - id: line-rate-udp
    kind: throughput_dpdk
    source: dpdk-tx
    sink: dpdk-rx
    proto: udp
    duration_s: 20
    multiplier: "10gbps"
    packet_size_b: 1400

report:
  output_dir: /root/stagelab-reports
```

---

## Scenarios

| Kind | Mode | Tool | Description |
|------|------|------|-------------|
| `throughput` | native | iperf3 | TCP or UDP throughput between two native endpoints. Pass/fail against `expect_min_gbps`. |
| `conn_storm` | native | tcpkali | Ramp up to `target_conns` concurrent TCP connections at `rate_per_s` new connections per second. tcpkali subprocess wrapper shipped: spawns the binary in the source endpoint's netns, captures stdout, and parses the connections/bandwidth summary into a `TcpkaliResult`. |
| `rule_scan` | probe | scapy + oracle | Fire `random_count` probes at `target_subnet`, compare observed verdicts against the oracle. Reports false-drop / false-accept split. |
| `tuning_sweep` | native | iperf3 + ethtool/sysctl | Cartesian grid over `rss_queues`, `rmem_max`, `wmem_max`. Tier-A advisor signals applied automatically. Best-point CSV written to `sweep-<id>.csv`. |
| `throughput_dpdk` | dpdk | TRex STL | Stateless TRex stream at `multiplier` rate for `duration_s` seconds. Supports `pcap_file` replay or synthetic frames at `packet_size_b`. |
| `conn_storm_astf` | dpdk | TRex ASTF | Application-layer session storm driven by a Python ASTF profile. Measures concurrent sessions and new session rate. |

---

## CLI

### Example configs

Operator-ready YAML examples live under `tools/`:

| File | Purpose |
|------|---------|
| `tools/stagelab-example-ha.yaml` | Two-host HA-pair native throughput + Prometheus metrics from both FW nodes |
| `tools/stagelab-example-snmp.yaml` | HA-pair with SNMP sources (all four bundles) alongside a Prometheus source |
| `tools/stagelab-example-dpdk.yaml` | DPDK smoke on virtio eth1/eth2 — validates NIC bind/unbind lifecycle |
| `tools/stagelab-crash-test.yaml` | Crash-recovery test: SIGKILL controller mid-run, verify recovery on next start |
| `tools/stagelab-crash-agent.yaml` | Probe-mode rule scan from a single host (correctness smoke) |

### `stagelab validate`

Validate a config file; exit 0 on success, 1 on error.

```bash
stagelab validate stagelab.yaml
```

### `stagelab run`

Connect to agents, execute all scenarios, write the report.

```bash
stagelab run stagelab.yaml
# With output dir override:
stagelab run stagelab.yaml --output-dir /tmp/run-$(date -u +%Y%m%d)
```

Prints the run directory path to stdout on success.

### `stagelab inspect`

Print `summary.md` from an existing run directory to stdout.

```bash
stagelab inspect /root/stagelab-reports/2026-04-20T15:00:00Z
```

### `stagelab review`

Consolidate tier-B and tier-C recommendations plus rule-order hints from a
completed run into a human-readable review bundle. Optionally opens a PR on
the firewall config repository.

```bash
# Write review.md + review.yaml alongside the run:
stagelab review /root/stagelab-reports/2026-04-20T15:00:00Z

# Write to a separate directory:
stagelab review /root/stagelab-reports/2026-04-20T15:00:00Z \
    --output /root/stagelab-review/

# Open a PR on the FW config repo:
stagelab review /root/stagelab-reports/2026-04-20T15:00:00Z \
    --open-pr --repo owner/fw-config \
    --branch "stagelab/2026-04-20T15:00:00Z"
```

`--open-pr` requires the `gh` CLI to be authenticated. `--repo` is mandatory
when `--open-pr` is set. `--branch` defaults to `stagelab/<run_id>`.

---

## Reports

Every `stagelab run` writes files under `<output_dir>/<UTC-ISO>/`:

| File | Contents |
|------|----------|
| `run.json` | Machine-readable: run_id, config_path, per-scenario results with raw fields |
| `summary.md` | Human-readable: scenario status, throughput/conn numbers, tiered Recommendations section (A/B/C), false-drop/false-accept split for `rule_scan` |
| `recommendations.yaml` | All advisor recommendations (only when non-empty) |
| `sweep-<id>.csv` | Grid points + throughput for each `tuning_sweep` scenario |
| `review.md` | Tier-B + tier-C bundle (written by `stagelab review`) |
| `review.yaml` | Same data as review.md, machine-readable |

`summary.md` always includes a false-drop / false-accept breakdown for
`rule_scan` scenarios, with oracle rule attribution for each mismatch.
This follows the same reporting convention as simlab: never report a raw
mismatch count without identifying the triggering oracle rule.

---

## Advisor

The advisor runs after every `stagelab run` and emits tiered `Recommendation`
objects. Tiers:

- **A** — testhost-local, auto-applied by `tuning_sweep` (NIC ring size, IRQ
  affinity, TCP buffers). No operator review needed for the firewall.
- **B** — firewall-side changes that require operator review (conntrack table
  size, flowtable configuration).
- **C** — compiler hints (rule ordering); fed to `stagelab review` for a
  future T17b integration into the shorewall-nft optimizer.

All 8 heuristics are rule-based. Thresholds live at the top of
`shorewall_nft_stagelab/advisor.py` as module-level constants.

| Signal | Tier | Target | Trigger |
|--------|------|--------|---------|
| `rx_no_buffer` | A | testhost | `rx_no_buffer_count > 0` from ethtool NIC stats |
| `softirq_concentration` | A | testhost | max NET\_RX softirq per CPU > 3× median across CPUs |
| `tcp_retrans` | A | testhost | iperf3 retransmits > 0.5% of estimated sent packets |
| `flat_parallel_scaling` | A | testhost | parallel >= 4 streams but < 1 Gbps per stream |
| `conntrack_headroom` | B | fw | conntrack_count > 80% of conntrack_max |
| `conntrack_search_restart` | B | fw | `conntrack_search_restart > 0` from conntrack stats |
| `flowtable_stagnant` | B | fw | any `flowtable_*` metric equals 0 |
| `rule_order_topN` | C | compiler | top-3 nft counters account for > 70% of total packets across >= 10 counters |

### Reading `recommendations.yaml`

```yaml
recommendations:
  - tier: A
    signal: rx_no_buffer
    action: "ethtool -G <iface> rx 4096; ethtool -L <iface> combined $(nproc)"
    target: testhost
    confidence: high
    rationale: "rx_no_buffer_count=142 observed on source 'ep-src' — NIC ring is too small ..."
  - tier: B
    signal: conntrack_headroom
    action: "sysctl -w net.netfilter.nf_conntrack_max=8388608; ..."
    target: fw
    confidence: high
    rationale: "conntrack_count=3276800 / conntrack_max=4194304 (78.1% — headroom below 20%)"
```

Tier-A recommendations are auto-applied by `tuning_sweep` and need no further
action. Tier-B and tier-C recommendations go into the `stagelab review` bundle
for operator merge.

---

## DPDK notes

### Reversibility contract

Before binding a NIC to `vfio-pci` the agent reads the current kernel driver
from `/sys/bus/pci/devices/<pci_addr>/driver` and also snapshots the NIC's
current bond or bridge master (if any) via sysfs. The original driver name,
PCI address, bind timestamp, `orig_master`, and `orig_master_kind` are written
to `/var/lib/stagelab/dpdk-bindings.json` under an exclusive file lock before
the bind call returns.

On `teardown_dpdk_endpoint` the NIC is re-bound to the original driver and
then automatically re-enslaved to its bond or bridge master (if one was
snapshotted). No manual operator re-enslave step is needed after a DPDK run on
a bond- or bridge-enslaved NIC.

On agent startup (`run_agent`) the file is read and any recorded NICs are
re-bound to their original drivers (and masters restored) before the agent
enters its main loop. This means a controller crash, SIGKILL, or host reboot
leaves NICs recoverable on the next agent start.

**Corruption-tolerant recovery**: if a SIGKILL interrupts the JSON write,
the recovery file may contain partial JSON. `_read_recovery()` catches
`json.JSONDecodeError` and returns `[]` rather than refusing to start. The
principle is "better to lose the stale entry than to leave the agent stuck
unable to boot".

### Hardware requirements

| Driver | Status |
|--------|--------|
| `i40e` (Intel X710 / XL710) | fully supported |
| `ice` (Intel E810) | fully supported |
| `mlx5_core` (Mellanox ConnectX-4/5/6) | fully supported |
| `virtio-pci` / `virtio-net` | virtio-user PMD — development / correctness only; not line-rate |
| `r8169`, `r8125` (Realtek) | not compatible with DPDK |

`vfio-pci` requires either a real IOMMU or `enable_unsafe_noiommu_mode=1`.
The bootstrap script detects the IOMMU presence and sets the unsafe mode
automatically when no IOMMU is found (typical on VMs).

### Hugepages

Each DPDK endpoint requires `hugepages_gib >= 1`. The bootstrap script
allocates `STAGELAB_HUGEPAGES` × 2 MiB pages (default: 512 = 1 GiB) and
mounts `hugetlbfs` at `/dev/hugepages`. Sum hugepages across all DPDK
endpoints on a host; the total must fit in available RAM.

### TRex version pinning

TRex is not pip-installable. The bootstrap script downloads and stages the
tarball at `/opt/trex/<version>` (e.g. `/opt/trex/v3.04`). The version and
SHA-256 are pinned in `tools/setup-remote-test-host.sh`. Update both when
upgrading TRex. Use `STAGELAB_SKIP_SHA=1` in CI/dev only.

---

## Test hosts tested

Bootstrap supports:

- **Debian / grml (apt)** — the default simlab test host uses grml trixie/sid
  (RAM-only, reboots wipe everything).
- **AlmaLinux 10 (dnf)** — current stagelab smoke-test host. EPEL 10 + CRB
  enabled by bootstrap for `iperf3`, `python3-pyroute2`, and `python3-pytest`.

Current stagelab smoke-test host: **192.0.2.73** (AlmaLinux 10,
virtio-net NIC). virtio-net is supported for `probe` and `native` mode
correctness smoke; it is not suitable for DPDK line-rate testing.

---

## Known limitations and open items

- **T17b compiler integration** — the rule-order analyzer (`rule_order.py`)
  produces tier-C hints; feeding them back into the shorewall-nft compiler as
  ordering directives is a planned future item.
- **Full HA-pair scenario** — a second FW endpoint for VRRP failover simulation
  (conntrackd sync + keepalived handover) is not yet modelled. Use
  `verify --iptables` for rule coverage; manual failover drill for behavioural
  coverage.
- **Hardware-offload flow-steering** — no test yet verifies that flowtable
  `offload` actually moves flows to hardware. The `flowtable_stagnant` advisor
  heuristic fires if the counter stays at zero, which is a proxy signal only.
- **Simlab integration gate in CI** — stagelab unit tests run in CI; a
  minimal stagelab single-probe integration scenario is not yet a CI gate.
- **TRex tarball download** — cisco.com SSL certificate chain fails on some
  hosts. Operator workaround: vendor the tarball manually to `/opt/trex/v3.04`
  and set `STAGELAB_SKIP_SHA=1` to bypass the SHA-256 check.
- **nsstub bind-mount after agent SIGKILL** — if the agent is killed with
  SIGKILL while a netns stub is running, the `/run/netns/<name>` bind-mount
  may persist and block the next run. Manual `umount /run/netns/<name>` or a
  VM reboot clears it. Inherited from simlab; tester VMs are disposable.
- **Phase 4 enterprise validation** — DoS scenarios (D0–D4), extended HA
  scenarios (P4-1..P4-7), and an audit-report generator are planned in
  `~/.claude/plans/stagelab-phase-4-enterprise-validation.md`.
