# NIST SP 800-53 rev 5 — firewall coverage fragment

Merged by M1 into `security-test-plan.md`.

This fragment documents which NIST SP 800-53 rev 5 controls are covered by
the stagelab test suite, which are partially covered, and which are explicitly
out of scope for an nftables stateful packet-filter firewall.

## In scope

**Applicable control families**: AC (Access Control), SC (System and
Communications Protection), AU (Audit and Accountability), SI (System
and Information Integrity). These families contain the controls that
directly govern firewall behaviour at the boundary.

**Approach**: Each test maps to a specific control or control enhancement.
Controls that are organisational, personnel-focused, or require evaluation
of supporting infrastructure (PKI, SIEM) are explicitly called out as out of
scope.

## Test catalogue

### nist-ac-4-info-flow — Information flow enforcement

- **Control**: AC-4 (Information Flow Enforcement)
- **What we test**: Zone-pair accept/drop consistency versus the compiled nft
  ruleset, using `rule_scan` (random probes across a /8 target subnet).
  Every probe to a denied zone pair must be dropped; permitted flows must
  pass.
- **Acceptance**: `fail_accept_count == 0` AND `fail_drop_count <= 2` (small
  tolerance for IPv6 NDP edge cases in probe mode).
- **Evidence**: `audit.json scenarios[].test_id == nist-ac-4-info-flow`

### nist-ac-4-boundary-coverage — Information flow enforcement, boundary matrix

- **Control**: AC-4 (Information Flow Enforcement)
- **What we test**: `rule_coverage_matrix` exercises all configured zone
  pairs across TCP (22, 80, 443), UDP (53, 123), and ICMP. Confirms that the
  ruleset enforces the configured security policy across all boundary
  intersections.
- **Acceptance**: `uncovered_zone_pairs == 0` (every zone-pair tuple probed).
- **Evidence**: `audit.json scenarios[].test_id == nist-ac-4-boundary-coverage`

### nist-sc-5-dos-syn — Resistance to SYN-flood DoS

- **Control**: SC-5 (Denial-of-service Protection)
- **What we test**: `dos_syn_flood` at a controlled rate (capped by
  `STAGELAB_DOS_RATE_CAP_PPS`). At most 5% of SYN packets may reach the
  sink; the firewall must absorb or drop the remainder.
- **Acceptance**: `passed_ratio <= 0.05`.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-dos-syn`

### nist-sc-5-dos-conntrack — Resistance to conntrack saturation DoS

- **Control**: SC-5 (Denial-of-service Protection)
- **What we test**: `conn_storm` drives high connection-creation rate toward
  the conntrack table limit. The firewall must remain stable (no kernel OOM,
  no conntrack ENOMEM), and legitimate throughput must not drop below 80% of
  baseline.
- **Acceptance**: `throughput_ratio >= 0.8`; `kernel_error_count == 0`.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-dos-conntrack`

### nist-sc-5-dos-dns — Resistance to DNS query-rate DoS

- **Control**: SC-5 (Denial-of-service Protection)
- **What we test**: `dos_dns_query` floods the target resolver at a controlled
  QPS rate. The firewall must limit forwarded DNS queries to within the
  configured per-source rate limit; the resolver must remain reachable for
  legitimate clients.
- **Acceptance**: `resolver_reachable_during_flood == True`; flood QPS to
  resolver does not exceed configured rate limit.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-dos-dns`

### nist-sc-5-dos-half-open — Resistance to half-open TCP exhaustion

- **Control**: SC-5 (Denial-of-service Protection)
- **What we test**: `dos_half_open` builds a large population of half-open
  TCP connections toward the conntrack table. Tests that the firewall limits
  the impact and recovers after the flood stops.
- **Acceptance**: `conntrack_table_usage_peak_ratio <= 0.95` (table stays
  below 95% full); recovery confirmed within 30 seconds.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-dos-half-open`

### nist-sc-7-boundary-throughput — Boundary protection under sustained load

- **Control**: SC-7 (Boundary Protection)
- **What we test**: `throughput` scenario (iperf3) measures sustained TCP/UDP
  throughput through the firewall over a configurable duration. Verifies that
  the firewall does not become a bottleneck under expected production load.
- **Acceptance**: `throughput_gbps >= expect_min_gbps`.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-7-boundary-throughput`

### nist-sc-7-boundary-evasion — Boundary protection, evasion probe rejection

- **Control**: SC-7 (Boundary Protection)
- **What we test**: `evasion_probes` sends TCP NULL, TCP XMAS, TCP
  FIN-without-SYN, IP-spoofed, and malformed-checksum UDP frames across the
  boundary. All must be dropped.
- **Acceptance**: `pass_count == 0` across all probe types.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-7-boundary-evasion`

### nist-au-2-audit-events — Audit events (PARTIAL)

- **Control**: AU-2 (Event Logging)
- **What we test**: Per-rule packet/byte counters are exposed via the
  shorewalld Prometheus endpoint. The test verifies that counters increment
  for each rule exercised by a `rule_scan` run, confirming observable audit
  data is generated for accepted and denied flows.
- **Status**: PARTIAL — AU-2 also requires per-event records with timestamps.
  We produce only aggregate counters. A syslog/CEF exporter is a separate
  open task.
- **Evidence**: Prometheus counter diff in `audit.json scenarios[].metrics`

### nist-au-12-audit-generation — Audit record generation (PARTIAL)

- **Control**: AU-12 (Audit Record Generation)
- **What we test**: shorewalld Prometheus scrape endpoint is verified
  reachable and returns current nft counter values during and after a
  `rule_scan` run. Counter values must be monotonically increasing.
- **Status**: PARTIAL — per-packet structured audit records are not generated.
- **Evidence**: `audit.json scenarios[].test_id == nist-au-12-audit-generation`

### nist-si-4-monitoring — System monitoring via shorewalld

- **Control**: SI-4 (System Monitoring)
- **What we test**: shorewalld Prometheus exporter is operational, exposes
  per-rule counters (`nft_rule_packets_total`, `nft_rule_bytes_total`),
  conntrack table utilisation, and softirq stats. Test verifies scrape
  completes within 5 seconds and returns non-empty data.
- **Acceptance**: `scrape_duration_s <= 5.0`; `metric_count >= 1`.
- **Evidence**: `audit.json scenarios[].test_id == nist-si-4-monitoring`

### nist-sc-5-reload-atomicity — Service availability during ruleset reload

- **Control**: SC-5(3) (Denial-of-service Protection — Service Continuity)
- **What we test**: `reload_atomicity` drives a long TCP stream through the
  firewall, fires `shorewall-nft restart` mid-stream, and measures
  retransmissions. The reload must complete atomically (nft atomic replace)
  without interrupting established flows.
- **Acceptance**: `max_retrans_during_reload <= 100`.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-reload-atomicity`

### nist-sc-7-ha-failover — Boundary protection, HA failover continuity

- **Control**: SC-7(18) (Boundary Protection — Fail Secure)
- **What we test**: `ha_failover_drill` stops keepalived on the primary
  firewall node while a TCP stream is running, measures downtime until the
  secondary assumes the VRRP VIP, then restores the primary.
- **Acceptance**: `max_downtime_s <= 5.0`; flow resumes via secondary.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-7-ha-failover`

## Out of scope (NIST SP 800-53 rev 5)

- **SC-6 (Resource Availability)** — kernel-level resource partitioning
  (cgroups, CPU pinning) is a platform concern, not a firewall-compiler
  concern. Partially addressed by the advisor `tuning_sweep` heuristic.
- **IA-* (Identification and Authentication)** — management-plane
  authentication. The firewall does not authenticate forwarded flows.
- **CM-* (Configuration Management)** — configuration change control is an
  organisational process; no automated test applies.
- **AT-*, PS-* (Awareness and Training / Personnel Security)** — personnel
  controls; not testable by this framework.
- **PE-* (Physical and Environmental)** — data-centre physical access;
  outside scope.
- **SC-8 (Transmission Confidentiality / Integrity)** — TLS/MACsec; crypto
  stack testing is separate.
- **SC-28 (Protection of Information at Rest)** — disk encryption; outside
  scope.
- **AU-9 / AU-10 (Audit Protection / Non-repudiation)** — requires an
  independent audit store. Our Prometheus counters live on the firewall node
  itself; dedicated SIEM integration is a separate task.
- **CA-*, RA-* (Assessment and Risk Management)** — organisational risk
  processes; not automatable here.

## Gaps / partial coverage

- **AU-2 / AU-12** — Event logging is partial: only aggregate per-rule
  Prometheus counters are produced. Per-event records with timestamps,
  source/destination, and action fields are not emitted. Closing this gap
  requires a shorewalld-side CEF/syslog exporter.

- **SI-3 (Malicious Code Protection)** — deep packet inspection for malware
  signatures is outside the scope of a stateless/stateful firewall; this
  would require an IDS/IPS integration layer.

- **SC-5(1) (Restrict Internal Traffic)** — intra-zone traffic controls are
  currently not modelled in the test topology. A multi-zone test setup with
  explicit intra-zone probes would be needed to close this gap.
