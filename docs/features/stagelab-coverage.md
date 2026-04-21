# Stagelab Coverage Matrix

This document summarises the stagelab test coverage across all relevant
dimensions for the reference HA firewall: protocol family, traffic
protocol, performance vs correctness, firewall traversal direction, and
external dependencies (DPDK, conntrack, HA).

Cross-reference: [Security test plan](../testing/security-test-plan.md) |
[Stagelab operator guide](../testing/stagelab.md) |
[Point of truth](../testing/point-of-truth.md)

---

## Scenario × Dimension Matrix

| Scenario kind | Family | Proto | Dimension | FW traversal | Dep: DPDK | Dep: conntrack | Dep: HA |
|---|---|---|---|---|---|---|---|
| `throughput` | IPv4 | TCP | perf | yes | no | passive | no |
| `throughput` | IPv4 | UDP | perf | yes | no | passive | no |
| `throughput` | IPv6 | TCP | perf | yes | no | passive | no |
| `throughput` | IPv6 | UDP | perf | yes | no | passive | no |
| `throughput` + `observe_conntrack` | IPv4 | TCP | perf + observ. | yes | no | active sidecar | no |
| `throughput_dpdk` (TRex STL) | IPv4 | UDP/IMIX | perf line-rate | yes | **yes** | passive | no |
| `throughput_dpdk` (TRex STL) | IPv6 | UDP/IMIX | perf line-rate | yes | **yes** | passive | no |
| `conn_storm_astf` (TRex ASTF) | IPv4 | TCP/HTTP | perf + conntrack | yes | **yes** | active | no |
| `conn_storm` | IPv4 | TCP | perf + conntrack | yes | no | active | no |
| `conn_storm` + `observe_conntrack` | IPv4 | TCP | conntrack observ. | yes | no | active sidecar | no |
| `conntrack_overflow` | IPv4 | TCP | conntrack stress | yes | no | active | no |
| `rule_scan` | IPv4 | TCP/UDP/ICMP | correctness | yes | no | no | no |
| `rule_scan` | IPv6 | TCP/UDP/ICMP | correctness | yes | no | no | no |
| `rule_coverage_matrix` | IPv4 | TCP/UDP/ICMP | correctness | yes | no | no | no |
| `rule_coverage_matrix` | IPv6 | TCP/UDP/ICMP | correctness | yes | no | no | no |
| `evasion_probes` | IPv4 | TCP/UDP/ICMP | correctness | yes | no | no | no |
| `evasion_probes` | IPv6 | TCP/UDP/ICMP | correctness | yes | no | no | no |
| `dos_syn_flood` | IPv4 | TCP SYN | DoS | yes | **yes** | passive | no |
| `dos_dns_query` | IPv4 | UDP/DNS | DoS | yes | **yes** | no | no |
| `dos_half_open` | IPv4 | TCP half-open | DoS | yes | **yes** | active | no |
| `stateful_helper_ftp` | IPv4 | TCP/FTP | correctness | yes | no | active | no |
| `long_flow_survival` | IPv4 | TCP | correctness | yes | no | active | no |
| `reload_atomicity` | IPv4 | TCP | operational | yes | no | passive | no |
| `ha_failover_drill` | IPv4 | TCP | operational + HA | yes | no | passive | **yes** |
| `tuning_sweep` | IPv4 | TCP/UDP | perf tuning | yes | no | no | no |

**Legend:**
- `passive` — conntrack entries are created but the scenario does not measure or stress them
- `active` — scenario exercises the conntrack table (measures fill, creates/expires entries deliberately)
- `active sidecar` — `observe_conntrack: true` field enables a parallel `conntrack -L | wc -l` poll;
  peak count recorded in `ScenarioResult.metrics["conntrack_peak_observed"]`
  (**TODO for hang-fix agent**: wire sidecar in `ThroughputRunner` and `ConnStormRunner`)

---

## Coverage by Standard

Each row is one or more catalogue entries that satisfy the standard control.

| Standard | Control | Test IDs (IPv4) | Test IDs (IPv6) | Status |
|---|---|---|---|---|
| CC/ISO-15408 | FDP_IFF.1 basic flow | `cc-fdp-iff-1-basic-flow` | `cc-fdp-iff-1-basic-flow-ipv6` | covered |
| CC/ISO-15408 | FDP_IFF.1 default deny | `cc-fdp-iff-1-default-deny` | — | covered |
| CC/ISO-15408 | FDP_IFF.1 evasion | `cc-fdp-iff-1-evasion-reject` | `cc-fdp-iff-1-evasion-reject-ipv6` | covered |
| CC/ISO-15408 | FAU_GEN.1 audit | `cc-fau-gen-1-audit-record` | — | partial |
| CC/ISO-15408 | FRU_RSA.1 conn storm | `cc-fru-rsa-1-conn-storm` | `cc-fru-rsa-1-conn-storm-ipv6` | covered |
| CC/ISO-15408 | FRU_RSA.1 syn flood | `cc-fru-rsa-1-dos-syn-flood` | — | covered (DPDK) |
| CC/ISO-15408 | FRU_RSA.1 conntrack | `cc-fru-rsa-1-dos-conntrack` | — | covered (DPDK) |
| CC/ISO-15408 | FMT_MSA.3 default values | `cc-fmt-msa-3-default-values` | — | covered |
| CC/ISO-15408 | FPT_FLS.1 reload | `cc-fpt-fls-1-reload-atomicity` | — | covered |
| CC/ISO-15408 | FPT_RCV.3 HA | `cc-fpt-rcv-3-ha-failover` | — | covered |
| CC/ISO-15408 | FTA_SSL.3 long flow | `cc-fta-ssl-3-long-flow-survival` | — | covered |
| NIST 800-53 | AC-4 info flow | `nist-ac-4-info-flow` | `nist-ac-4-info-flow-ipv6` | covered |
| NIST 800-53 | AC-4 coverage matrix | `nist-ac-4-boundary-coverage` | — | covered |
| NIST 800-53 | SC-5 SYN flood | `nist-sc-5-dos-syn` | — | covered (DPDK) |
| NIST 800-53 | SC-5 conntrack DoS | `nist-sc-5-dos-conntrack` | — | covered |
| NIST 800-53 | SC-5 DNS flood | `nist-sc-5-dos-dns` | — | covered (DPDK) |
| NIST 800-53 | SC-5 half-open | `nist-sc-5-dos-half-open` | — | covered (DPDK) |
| NIST 800-53 | SC-5 conntrack overflow | `nist-sc-5-dos-conntrack-overflow` | — | covered |
| NIST 800-53 | SC-5 reload atomicity | `nist-sc-5-reload-atomicity` | — | covered |
| NIST 800-53 | SC-7 throughput | `nist-sc-7-boundary-throughput` | `nist-sc-7-boundary-throughput-ipv6` | covered |
| NIST 800-53 | SC-7 evasion | `nist-sc-7-boundary-evasion` | `nist-sc-7-boundary-evasion-ipv6` | covered |
| NIST 800-53 | SC-7 HA failover | `nist-sc-7-ha-failover` | — | covered |
| NIST 800-53 | SC-7 flowtable offload | `nist-sc-7-flowtable-offload` | — | partial |
| NIST 800-53 | AU-2 audit events | `nist-au-2-audit-events` | — | partial |
| NIST 800-53 | AU-12 audit generation | `nist-au-12-audit-generation` | — | partial |
| NIST 800-53 | SI-4 monitoring | `nist-si-4-monitoring` | — | covered |
| BSI IT-Grundschutz | NET.3.2.A2 zone sep | `bsi-net-3-2-a2-function-separation` | `bsi-net-3-2-a2-function-separation-ipv6` | covered |
| BSI IT-Grundschutz | NET.3.2.A4 rule doc | `bsi-net-3-2-a4-rule-documentation` | `bsi-net-3-2-a4-rule-documentation-ipv6` | partial |
| BSI IT-Grundschutz | NET.3.2.A5 DoS | `bsi-net-3-2-a5-dos-protection` | — | covered |
| BSI IT-Grundschutz | NET.3.2.A6 stateful | `bsi-net-3-2-a6-connection-state` | — | covered |
| BSI IT-Grundschutz | NET.3.2.A7 evasion | `bsi-net-3-2-a7-protocol-validation` | `bsi-net-3-2-a7-protocol-validation-ipv6` | covered |
| BSI IT-Grundschutz | NET.3.2.A10 logging | `bsi-net-3-2-a10-logging` | — | partial |
| BSI IT-Grundschutz | NET.3.2.A12 HA | `bsi-net-3-2-a12-redundancy-ha` | — | covered |
| CIS Benchmarks | 5.2.1 default deny in | `cis-5-2-1-firewall-default-deny-ingress` | `cis-5-2-1-firewall-default-deny-ingress-ipv6` | covered |
| CIS Benchmarks | 5.2.2 default deny out | `cis-5-2-2-firewall-default-deny-egress` | — | partial |
| CIS Benchmarks | 5.2.3 open ports | `cis-5-2-3-open-ports-inventory` | — | covered |
| CIS Benchmarks | 5.2.4 RFC-1918 block | `cis-5-2-4-ingress-rfc1918-from-wan` | — | covered |
| CIS Benchmarks | 5.2.5 bogon block | `cis-5-2-5-ingress-bogon-block` | `cis-5-2-5-ingress-bogon-block-ipv6` | covered |
| CIS Benchmarks | 5.4.1 established | `cis-5-4-1-established-traffic` | — | covered |
| CIS Benchmarks | 5.4.2 outbound coverage | `cis-5-4-2-outbound-rules-coverage` | — | covered |
| OWASP | FW-1 config review | `owasp-fw-1-config-review` | — | covered |
| OWASP | FW-2 rule-base audit | `owasp-fw-2-rulebase-audit` | — | covered |
| OWASP | FW-3 default deny | `owasp-fw-3-default-deny` | `owasp-fw-3-default-deny-ipv6` | covered |
| OWASP | FW-4 evasion | `owasp-fw-4-evasion-bypass` | `owasp-fw-4-evasion-bypass-ipv6` | covered |
| OWASP | FW-5 stateful inspection | `owasp-fw-5-stateful-inspection` | — | partial |
| OWASP | FW-6 HA failover | `owasp-fw-6-ha-failover` | — | covered |
| OWASP | FW-7 protocol stack | `owasp-fw-7-protocol-stack` | — | covered |
| OWASP | FW-8 operational hardening | `owasp-fw-8-operational-hardening` | — | covered |
| ISO-27001 | A.13.1.1 network controls | `iso27001-a-13-1-1-network-controls` | `iso27001-a-13-1-1-network-controls-ipv6` | covered |
| ISO-27001 | A.13.1.2 network svc security | `iso27001-a-13-1-2-network-service-security` | — | partial |
| ISO-27001 | A.13.1.3 network segregation | `iso27001-a-13-1-3-network-segregation` | — | covered |
| ISO-27001 | A.13.2.1 transfer controls | `iso27001-a-13-2-1-transfer-controls` | — | covered |
| ISO-27001 | A.12.4.1 event logging | `iso27001-a-12-4-1-event-logging` | — | partial |
| ISO-27001 | A.12.6.1 vuln management | `iso27001-a-12-6-1-vuln-management` | — | partial |
| ISO-27001 | A.18.2.1 security review | `iso27001-a-18-2-1-security-review` | — | covered |
| ISO-27001 | A.18.2.2 policy compliance | `iso27001-a-18-2-2-policy-compliance` | — | covered |
| Perf addendum | IPv4 TCP throughput | `perf-ipv4-tcp-throughput` | — | covered |
| Perf addendum | IPv4 UDP throughput | `perf-ipv4-udp-throughput` | — | covered |
| Perf addendum | IPv6 TCP throughput | — | `perf-ipv6-tcp-throughput` | covered |
| Perf addendum | IPv6 UDP throughput | — | `perf-ipv6-udp-throughput` | covered |
| Perf addendum | DPDK IPv4 STL | `perf-dpdk-ipv4-line-rate-stl` | — | deferred (#31) |
| Perf addendum | DPDK IPv6 STL | — | `perf-dpdk-ipv6-line-rate-stl` | deferred (#31) |
| Perf addendum | DPDK ASTF 1M sessions | `perf-dpdk-ipv4-astf-1m-sessions` | — | deferred (#31) |
| Perf addendum | Conntrack observe (throughput) | `perf-conntrack-observe-throughput` | — | covered* |
| Perf addendum | Conntrack observe (conn storm) | `perf-conntrack-observe-conn-storm` | — | covered* |

*covered* = config field + catalogue entry in place; handler sidecar is a TODO for the hang-fix agent.

---

## DPDK Status

DPDK scenarios are **deferred** pending task #31 (hardware NIC provisioning):

| Scenario | kind | Gate | Notes |
|---|---|---|---|
| `perf-dpdk-ipv4-line-rate-stl` | `throughput_dpdk` | task #31 | 10 Gbps IMIX IPv4 |
| `perf-dpdk-ipv6-line-rate-stl` | `throughput_dpdk` | task #31 | 10 Gbps IMIX IPv6 |
| `perf-dpdk-ipv4-astf-1m-sessions` | `conn_storm_astf` | task #31 | 1M concurrent sessions |
| `nist-sc-5-dos-syn` | `dos_syn_flood` | task #31 | 50 kpps SYN flood |
| `nist-sc-5-dos-dns` | `dos_dns_query` | task #31 | 20 kQPS DNS flood |
| `nist-sc-5-dos-half-open` | `dos_half_open` | task #31 | 500k half-open conns |
| `cc-fru-rsa-1-dos-syn-flood` | `dos_syn_flood` | task #31 | CC twin of NIST SYN |
| `cc-fru-rsa-1-dos-conntrack` | `dos_half_open` | task #31 | CC twin of NIST half-open |
| `bsi-net-3-2-a5-dos-protection` | `dos_syn_flood` | task #31 | BSI twin |
| `owasp-fw-7-protocol-stack` | `dos_syn_flood` | task #31 | OWASP twin |

Example config: `tools/stagelab-dpdk-example.yaml`

To gate-open task #31: provision physical NICs + run bootstrap with
`STAGELAB_HUGEPAGES=2048 tools/setup-remote-test-host.sh root@<host> --role stagelab-agent-dpdk`.

---

## Conntrack Observability

Two new config fields are available on `ThroughputScenario` and `ConnStormScenario`:

```yaml
observe_conntrack: true   # enable sidecar poller (default: false)
fw_host: "root@fw-primary"  # required when observe_conntrack=true
```

When `observe_conntrack=true`, the scenario runner polls `conntrack -L | wc -l`
on the firewall once per second throughout the run.  The peak count is written to
`ScenarioResult.metrics["conntrack_peak_observed"]`.

**Handler TODO for hang-fix agent:**
- `scenarios.py ThroughputRunner`: spawn sidecar task calling `metrics.poll_conntrack_list`
- `scenarios.py ConnStormRunner`: same
- The `poll_conntrack_list` function is implemented in `metrics.py`

---

## Parallel Execution

Stagelab does not yet have a `ParallelScenarioGroup` primitive.  Parallel
execution is automatic when two scenarios in the same config target
**disjoint endpoints on different hosts**: the controller groups per-host
`AgentCommand` objects and dispatches them via `asyncio.gather`.  This means
iperf3 `--one-off` server/client commands for different host-pairs run
concurrently without explicit grouping.

Scenarios sharing the same host are serialised to avoid resource contention.
No config-level override exists; if concurrent same-host execution is needed,
split into separate configs and run simultaneously from a shell script.

---

## Known Gaps

| Gap | Reason | Placeholder test-ID |
|---|---|---|
| DPDK line-rate tests (IPv4 + IPv6) | Requires hardware NICs — task #31 | `perf-dpdk-{ipv4,ipv6}-line-rate-stl` |
| `conntrack -L` sidecar wiring | Handler TODO in `ThroughputRunner`/`ConnStormRunner` | `perf-conntrack-observe-*` |
| Flowtable hardware-offload verification | Counter before/after comparison not implemented | `nist-sc-7-flowtable-offload` |
| Per-packet syslog/CEF audit records | shorewalld Prometheus counters only; no packet log | `cc-fau-gen-1-audit-record`, `nist-au-2-*` |
| Full HA-pair topology (conntrackd sync) | Only single-FW topology modelled; conntrackd rules not simlab-testable | — |
| IPv6 DoS scenarios (SYN flood, DNS) | DPDK required and DoS scenarios have IPv4-only packet generators | — |
| T17b compiler rule-order integration | `rule_order.py` hints not fed back to compiler optimiser | — |

See `CLAUDE.md` open items section and
[stagelab CLAUDE.md](../../packages/shorewall-nft-stagelab/CLAUDE.md) open items
for detailed tracking.
