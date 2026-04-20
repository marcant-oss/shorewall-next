# Firewall Security Test Plan

Auto-generated canonical document. Generated at 2026-04-20T16:59:22+00:00.
Do NOT edit by hand; update source fragments under
`docs/testing/security-test-plan.<std>.md` and re-run
`tools/merge-security-test-plan.py`.

## Table of contents

- [Common Criteria (ISO/IEC 15408)](#common-criteria)
- [NIST SP 800-53](#nist-sp-800-53)
- [BSI IT-Grundschutz](#bsi-it-grundschutz)
- [CIS Benchmarks](#cis-benchmarks)
- [OWASP](#owasp)
- [ISO/IEC 27001](#iso-27001)
- [Performance addendum (IPv6)](#performance-addendum-ipv6)
- [Consolidated out of scope](#consolidated-out-of-scope)
- [How to run](#how-to-run)

## Common Criteria (ISO/IEC 15408) {#common-criteria}

Merged by M1 into `security-test-plan.md`.

This fragment documents which Common Criteria (CC) Security Functional
Requirements (SFRs) are covered by the stagelab test suite, which are
partially covered, and which are explicitly out of scope.

### In scope

**Protection Profiles**: NDcPP v3.0 (Network Device Collaborative PP) and
the extended FWcPP (Firewall PP). Both profiles specify the minimum set of
SFRs a stateful packet-filter firewall must demonstrate to an evaluator.

**SFR families we touch**: FDP (User Data Protection), FAU (Security Audit),
FRU (Resource Utilisation), FMT (Security Management), FPT (Protection of
the TSF), FTA (TSF Access). We do not attempt to evaluate FCS (Cryptographic
Support) or the assurance families (ADV, ATE, AVA, AGD, ALC) — see Out of
scope below.

### Test catalogue

#### cc-fdp-iff-1-basic-flow — Basic information flow control

- **SFR**: FDP_IFF.1 (Subset information flow control)
- **What we test**: Zone-pair accept/drop consistency versus the compiled nft
  ruleset, using `rule_scan` (random probes across the target subnet) and
  `rule_coverage_matrix` (systematic per-zone-pair matrix).
- **Acceptance**: `fail_accept_count == 0` AND `fail_drop_count <= 2` (small
  tolerance for IPv6 NDP edge cases in probe mode).
- **Evidence**: `audit.json scenarios[].test_id == cc-fdp-iff-1-basic-flow`;
  human: this section.

#### cc-fdp-iff-1-default-deny — Default deny on undefined zone pairs

- **SFR**: FDP_IFF.1.5 (Deny information flow when no rule matches)
- **What we test**: Traffic to zone pairs with no explicit ACCEPT rule must
  be dropped. Verified by `rule_scan` probing IP addresses not covered by any
  policy; expected result is DROP for every probe.
- **Acceptance**: `fail_accept_count == 0` (zero packets passed on undefined
  zone pairs).
- **Evidence**: `audit.json scenarios[].test_id == cc-fdp-iff-1-default-deny`

#### cc-fdp-iff-1-evasion-reject — Reject evasion probes

- **SFR**: FDP_IFF.1 applied to malformed/crafted packets
- **What we test**: The `evasion_probes` scenario sends TCP NULL, TCP XMAS,
  TCP FIN-without-SYN, IP-spoofed, and malformed-checksum UDP frames. All
  must be silently dropped.
- **Acceptance**: `pass_count == 0` across all probe types.
- **Evidence**: `audit.json scenarios[].test_id == cc-fdp-iff-1-evasion-reject`

#### cc-fau-gen-1-audit-record — Audit record generation (PARTIAL)

- **SFR**: FAU_GEN.1 (Audit data generation)
- **What we test**: Per-rule packet/byte counters are exposed via the
  shorewalld Prometheus endpoint and scraped during a `rule_scan` run.
  The test verifies that counter values increase for rules that fire.
- **Acceptance**: All rules exercised by the scenario have non-zero Prometheus
  counter increments after the run.
- **Status**: PARTIAL — FAU_GEN.1 requires per-event audit records (ideally
  syslog/CEF). We emit only aggregate counters. A shorewalld syslog/CEF
  exporter is tracked as a separate open item.
- **Evidence**: Prometheus metrics scraped to `audit.json scenarios[].metrics`

#### cc-fru-rsa-1-conn-storm — Minimum resource allocation under conn-storm

- **SFR**: FRU_RSA.1 (Minimum quotas)
- **What we test**: `conn_storm` scenario drives high connection-creation rate
  through the firewall. The firewall must continue to handle legitimate traffic
  at minimum 80% of baseline throughput while under load.
- **Acceptance**: `throughput_ratio >= 0.8` (baseline vs under storm).
- **Evidence**: `audit.json scenarios[].test_id == cc-fru-rsa-1-conn-storm`

#### cc-fru-rsa-1-dos-syn-flood — Minimum resource allocation under SYN flood

- **SFR**: FRU_RSA.1 (Minimum quotas under DoS)
- **What we test**: `dos_syn_flood` at a controlled rate (capped by
  `STAGELAB_DOS_RATE_CAP_PPS`). At most 5% of SYN packets may reach the
  sink (i.e., 95%+ must be absorbed or dropped by the firewall).
- **Acceptance**: `passed_ratio <= 0.05`.
- **Evidence**: `audit.json scenarios[].test_id == cc-fru-rsa-1-dos-syn-flood`

#### cc-fru-rsa-1-dos-conntrack — Minimum resource allocation, conntrack saturation

- **SFR**: FRU_RSA.1 (Minimum quotas, conntrack table)
- **What we test**: `dos_half_open` drives half-open connections toward the
  conntrack table limit. The firewall must keep the established-connection
  table stable (no kernel OOM or conntrack ENOMEM error) and recover after
  the DoS stops.
- **Acceptance**: `kernel_error_count == 0` during drill; recovery confirmed.
- **Evidence**: `audit.json scenarios[].test_id == cc-fru-rsa-1-dos-conntrack`

#### cc-fmt-msa-3-default-values — Restrictive default attribute values

- **SFR**: FMT_MSA.3 (Static attribute initialisation)
- **What we test**: The compiled nft ruleset must enforce a default-DROP
  policy at the base chain level, and the `shorewall-nft check` configuration
  compile step must succeed without warnings.
- **Acceptance**: `compile_warnings == 0`; base chain policies are `drop`.
- **Evidence**: compile check output in `audit.json`; default-deny confirmed
  by cc-fdp-iff-1-default-deny.

#### cc-fpt-fls-1-reload-atomicity — Preserve secure state during reload

- **SFR**: FPT_FLS.1 (Failure with preservation of secure state)
- **What we test**: `reload_atomicity` scenario runs a long TCP stream through
  the firewall, triggers `shorewall-nft restart` mid-stream, and verifies
  that retransmissions during the reload window stay below threshold.
- **Acceptance**: `max_retrans_during_reload <= 100`.
- **Evidence**: `audit.json scenarios[].test_id == cc-fpt-fls-1-reload-atomicity`

#### cc-fpt-rcv-3-ha-failover — Automated recovery via HA failover

- **SFR**: FPT_RCV.3 (Automated recovery)
- **What we test**: `ha_failover_drill` stops keepalived on the primary FW,
  measures downtime until traffic flows via the secondary, then restores the
  primary. Downtime must not exceed 5 seconds.
- **Acceptance**: `max_downtime_s <= 5.0`.
- **Evidence**: `audit.json scenarios[].test_id == cc-fpt-rcv-3-ha-failover`

#### cc-fta-ssl-3-long-flow-survival — Established-flow survival

- **SFR**: FTA_SSL.3 (TSF-initiated termination)
- **What we test**: `long_flow_survival` scenario lowers the conntrack
  `tcp_timeout_established` sysctl below the stream duration, then confirms
  whether the flow survives (or dies, as configured). Default test: flow must
  survive the full duration (timeout not reached).
- **Acceptance**: `flow_survived == True` (or `flow_died == True` for the
  expect_flow_dies=True variant).
- **Evidence**: `audit.json scenarios[].test_id == cc-fta-ssl-3-long-flow-survival`

### Out of scope (CC)

- **FCS_* (Cryptographic support)** — the firewall is a stateless/stateful
  packet filter, not a crypto stack. TLS/IPsec testing belongs to a separate
  component evaluation.
- **ADV_* (Development)** — requires formal design documentation review,
  developer correspondence evidence. No test automation applies to this class.
- **ATE_* (Tests)** — meta-level; covered by the existence of this framework,
  not by individual scenarios.
- **FIA_* (Identification and authentication)** — management-plane concern.
  The firewall does not perform user authentication on forwarded flows.
- **FTP_ITC.1 (Inter-TSF channel)** — VPN/IPsec between trust domains; not
  part of the shorewall-nft packet-filter scope.
- **FPT_STM.1 (Reliable timestamps)** — NTP synchronisation is an OS/kernel
  concern, not tested here.
- **AGD_* (Guidance documents)** — documentation review, not automated.
- **ALC_* (Lifecycle support)** — supply-chain/process concerns, not testable
  with this framework.

### Gaps / partial coverage

- **FAU_GEN.1** — Audit record generation is PARTIAL. We expose per-rule
  Prometheus counters (packets/bytes) via shorewalld, but we do not emit
  per-packet syslog records in CEF or any other structured format. Closing
  this gap requires a shorewalld-side CEF/syslog exporter (tracked as a
  separate open task in the project backlog). Mark as `status: partial` in
  the catalogue.

- **FMT_SMF.1 / FMT_SMR.1** (Security management functions / roles) — the
  firewall configuration is file-based with no role separation enforced at
  the tool level. Out of scope for automated testing; requires procedural
  controls.

---

## NIST SP 800-53 {#nist-sp-800-53}

Merged by M1 into `security-test-plan.md`.

This fragment documents which NIST SP 800-53 rev 5 controls are covered by
the stagelab test suite, which are partially covered, and which are explicitly
out of scope for an nftables stateful packet-filter firewall.

### In scope

**Applicable control families**: AC (Access Control), SC (System and
Communications Protection), AU (Audit and Accountability), SI (System
and Information Integrity). These families contain the controls that
directly govern firewall behaviour at the boundary.

**Approach**: Each test maps to a specific control or control enhancement.
Controls that are organisational, personnel-focused, or require evaluation
of supporting infrastructure (PKI, SIEM) are explicitly called out as out of
scope.

### Test catalogue

#### nist-ac-4-info-flow — Information flow enforcement

- **Control**: AC-4 (Information Flow Enforcement)
- **What we test**: Zone-pair accept/drop consistency versus the compiled nft
  ruleset, using `rule_scan` (random probes across a /8 target subnet).
  Every probe to a denied zone pair must be dropped; permitted flows must
  pass.
- **Acceptance**: `fail_accept_count == 0` AND `fail_drop_count <= 2` (small
  tolerance for IPv6 NDP edge cases in probe mode).
- **Evidence**: `audit.json scenarios[].test_id == nist-ac-4-info-flow`

#### nist-ac-4-boundary-coverage — Information flow enforcement, boundary matrix

- **Control**: AC-4 (Information Flow Enforcement)
- **What we test**: `rule_coverage_matrix` exercises all configured zone
  pairs across TCP (22, 80, 443), UDP (53, 123), and ICMP. Confirms that the
  ruleset enforces the configured security policy across all boundary
  intersections.
- **Acceptance**: `uncovered_zone_pairs == 0` (every zone-pair tuple probed).
- **Evidence**: `audit.json scenarios[].test_id == nist-ac-4-boundary-coverage`

#### nist-sc-5-dos-syn — Resistance to SYN-flood DoS

- **Control**: SC-5 (Denial-of-service Protection)
- **What we test**: `dos_syn_flood` at a controlled rate (capped by
  `STAGELAB_DOS_RATE_CAP_PPS`). At most 5% of SYN packets may reach the
  sink; the firewall must absorb or drop the remainder.
- **Acceptance**: `passed_ratio <= 0.05`.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-dos-syn`

#### nist-sc-5-dos-conntrack — Resistance to conntrack saturation DoS

- **Control**: SC-5 (Denial-of-service Protection)
- **What we test**: `conn_storm` drives high connection-creation rate toward
  the conntrack table limit. The firewall must remain stable (no kernel OOM,
  no conntrack ENOMEM), and legitimate throughput must not drop below 80% of
  baseline.
- **Acceptance**: `throughput_ratio >= 0.8`; `kernel_error_count == 0`.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-dos-conntrack`

#### nist-sc-5-dos-dns — Resistance to DNS query-rate DoS

- **Control**: SC-5 (Denial-of-service Protection)
- **What we test**: `dos_dns_query` floods the target resolver at a controlled
  QPS rate. The firewall must limit forwarded DNS queries to within the
  configured per-source rate limit; the resolver must remain reachable for
  legitimate clients.
- **Acceptance**: `resolver_reachable_during_flood == True`; flood QPS to
  resolver does not exceed configured rate limit.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-dos-dns`

#### nist-sc-5-dos-half-open — Resistance to half-open TCP exhaustion

- **Control**: SC-5 (Denial-of-service Protection)
- **What we test**: `dos_half_open` builds a large population of half-open
  TCP connections toward the conntrack table. Tests that the firewall limits
  the impact and recovers after the flood stops.
- **Acceptance**: `conntrack_table_usage_peak_ratio <= 0.95` (table stays
  below 95% full); recovery confirmed within 30 seconds.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-dos-half-open`

#### nist-sc-7-boundary-throughput — Boundary protection under sustained load

- **Control**: SC-7 (Boundary Protection)
- **What we test**: `throughput` scenario (iperf3) measures sustained TCP/UDP
  throughput through the firewall over a configurable duration. Verifies that
  the firewall does not become a bottleneck under expected production load.
- **Acceptance**: `throughput_gbps >= expect_min_gbps`.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-7-boundary-throughput`

#### nist-sc-7-boundary-evasion — Boundary protection, evasion probe rejection

- **Control**: SC-7 (Boundary Protection)
- **What we test**: `evasion_probes` sends TCP NULL, TCP XMAS, TCP
  FIN-without-SYN, IP-spoofed, and malformed-checksum UDP frames across the
  boundary. All must be dropped.
- **Acceptance**: `pass_count == 0` across all probe types.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-7-boundary-evasion`

#### nist-au-2-audit-events — Audit events (PARTIAL)

- **Control**: AU-2 (Event Logging)
- **What we test**: Per-rule packet/byte counters are exposed via the
  shorewalld Prometheus endpoint. The test verifies that counters increment
  for each rule exercised by a `rule_scan` run, confirming observable audit
  data is generated for accepted and denied flows.
- **Status**: PARTIAL — AU-2 also requires per-event records with timestamps.
  We produce only aggregate counters. A syslog/CEF exporter is a separate
  open task.
- **Evidence**: Prometheus counter diff in `audit.json scenarios[].metrics`

#### nist-au-12-audit-generation — Audit record generation (PARTIAL)

- **Control**: AU-12 (Audit Record Generation)
- **What we test**: shorewalld Prometheus scrape endpoint is verified
  reachable and returns current nft counter values during and after a
  `rule_scan` run. Counter values must be monotonically increasing.
- **Status**: PARTIAL — per-packet structured audit records are not generated.
- **Evidence**: `audit.json scenarios[].test_id == nist-au-12-audit-generation`

#### nist-si-4-monitoring — System monitoring via shorewalld

- **Control**: SI-4 (System Monitoring)
- **What we test**: shorewalld Prometheus exporter is operational, exposes
  per-rule counters (`nft_rule_packets_total`, `nft_rule_bytes_total`),
  conntrack table utilisation, and softirq stats. Test verifies scrape
  completes within 5 seconds and returns non-empty data.
- **Acceptance**: `scrape_duration_s <= 5.0`; `metric_count >= 1`.
- **Evidence**: `audit.json scenarios[].test_id == nist-si-4-monitoring`

#### nist-sc-5-reload-atomicity — Service availability during ruleset reload

- **Control**: SC-5(3) (Denial-of-service Protection — Service Continuity)
- **What we test**: `reload_atomicity` drives a long TCP stream through the
  firewall, fires `shorewall-nft restart` mid-stream, and measures
  retransmissions. The reload must complete atomically (nft atomic replace)
  without interrupting established flows.
- **Acceptance**: `max_retrans_during_reload <= 100`.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-5-reload-atomicity`

#### nist-sc-7-ha-failover — Boundary protection, HA failover continuity

- **Control**: SC-7(18) (Boundary Protection — Fail Secure)
- **What we test**: `ha_failover_drill` stops keepalived on the primary
  firewall node while a TCP stream is running, measures downtime until the
  secondary assumes the VRRP VIP, then restores the primary.
- **Acceptance**: `max_downtime_s <= 5.0`; flow resumes via secondary.
- **Evidence**: `audit.json scenarios[].test_id == nist-sc-7-ha-failover`

### Out of scope (NIST SP 800-53 rev 5)

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

### Gaps / partial coverage

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

---

## BSI IT-Grundschutz {#bsi-it-grundschutz}

**Standard:** BSI IT-Grundschutz Kompendium 2023 Edition 1
**Controls in scope:** NET.3.2 Firewall, NET.1.1 Netzarchitektur, OPS.1.2.5 Protokollierung
**Fragment maintainer:** stream B2
**Last updated:** 2026-04-20

This document is a per-standard fragment.  The M1 merger agent consolidates
this file together with the CC/NIST (B1), OWASP/ISO-27001 (B3) fragments
into `docs/testing/security-test-plan.md`.

---

### Coverage summary

| Control | Title | Coverage |
|---------|-------|----------|
| NET.3.2.A2 | Separation of firewall functions | Strong — `rule_scan` |
| NET.3.2.A4 | Rule documentation and review | Partial — rule matrix only |
| NET.3.2.A5 | DoS protection | Strong — `dos_syn_flood`, `dos_dns_query`, `dos_half_open` |
| NET.3.2.A6 | Connection state tracking | Strong — `stateful_helper_ftp`, `long_flow_survival`, `conn_storm` |
| NET.3.2.A7 | Protocol validation | Strong — `evasion_probes` |
| NET.3.2.A9 | Time synchronisation | Out of scope — NTP is an OS concern |
| NET.3.2.A10 | Logging and audit trail | Partial — Prometheus counter only, no per-packet syslog |
| NET.3.2.A12 | Redundancy and HA | Strong — `ha_failover_drill`, `reload_atomicity` |
| NET.1.1.A1 | Network architecture documentation | Out of scope — governance artefact |
| OPS.1.2.5 | Log retention and integrity | Partial — retention policy not automated |

---

### Test catalogue

#### bsi-net-3-2-a2-function-separation {#bsi-net-3-2-a2-function-separation}

**Control:** NET.3.2.A2 — Separation of firewall functions
**Scenario kind:** `rule_scan`

The firewall must enforce zone boundaries and permit only explicitly authorised
traffic flows.  Intra-zone traffic that crosses a firewall interface must be
subject to the rule set.  This test probes all zone-pair combinations from the
WAN endpoint and verifies that packets whose source or destination do not match
any allow rule are silently dropped.

**Acceptance criteria:**
- `fail_accept_count == 0` — no unexpected packets forwarded
- `fail_drop_count <= 2` — operator override allowed per deployment (e.g. ICMP probe replies)

**Evidence:** `audit.json scenarios[].test_id == bsi-net-3-2-a2-function-separation`

---

#### bsi-net-3-2-a4-rule-documentation {#bsi-net-3-2-a4-rule-documentation}

**Control:** NET.3.2.A4 — Rule documentation and review
**Scenario kind:** `rule_coverage_matrix`
**Status:** Partial

Every firewall rule must be documented with its purpose.  The shorewall-nft
configuration files (`/etc/shorewall46/rules`, `/etc/shorewall46/policy`) are
the machine-readable rule list and serve as the documentation source.

The `rule_coverage_matrix` scenario probes all zone-pair combinations for a
set of expected services and verifies that allow rules exist for each.  It does
not verify the reverse: that every allow rule has a documented justification.
Manual review of the configuration files is required for full NET.3.2.A4
compliance.

**Gap:** No automated rule-to-documentation traceability checker.

**Acceptance criteria:**
- `undocumented_allow_count == 0` — all probed services match an explicit rule

---

#### bsi-net-3-2-a5-dos-protection {#bsi-net-3-2-a5-dos-protection}

**Control:** NET.3.2.A5 — DoS protection
**Scenario kind:** `dos_syn_flood`

The firewall must limit the impact of Denial-of-Service attacks.  Three
scenario kinds cover this control:

1. **`dos_syn_flood`** — generates a high-pps SYN flood from spoofed WAN
   sources; measures what fraction of SYNs reach the protected host.
2. **`dos_dns_query`** — generates a DNS query flood toward the resolver;
   measures query-pass-through ratio.
3. **`dos_half_open`** — establishes a large number of TCP half-open
   connections; verifies conntrack table does not saturate.

The primary catalogue entry uses `dos_syn_flood`.  The other two scenario
types are referenced in the machine-readable YAML under separate test_ids
within the DoS protection group.

**Acceptance criteria:**
- `passed_ratio_max <= 0.05` — at most 5% of DoS packets reach the sink
- `throughput_degradation_max_pct <= 10` — legitimate traffic must not degrade more than 10%

**Evidence:** `audit.json scenarios[].test_id == bsi-net-3-2-a5-dos-protection`

---

#### bsi-net-3-2-a6-connection-state {#bsi-net-3-2-a6-connection-state}

**Control:** NET.3.2.A6 — Connection state tracking
**Scenario kind:** `stateful_helper_ftp`

The firewall must be stateful: only packets belonging to established or related
connections may be forwarded after the initial handshake.  The FTP helper
scenario exercises this: it opens an FTP control channel, then verifies that
the data connection (opened on an ephemeral port by the server) is permitted
via the `ct helper ftp` / related-state path.

Additional coverage from `long_flow_survival` (confirms ct entries survive
full flow duration) and `conn_storm` (validates behaviour at high connection
rate).

**Acceptance criteria:**
- `data_connection_established == true` — FTP data channel opened successfully

---

#### bsi-net-3-2-a7-protocol-validation {#bsi-net-3-2-a7-protocol-validation}

**Control:** NET.3.2.A7 — Protocol validation and evasion resistance
**Scenario kind:** `evasion_probes`

The firewall must drop malformed or crafted packets that attempt to bypass rule
evaluation.  The `evasion_probes` scenario injects:

- TCP NULL scan (no flags set)
- TCP Xmas scan (FIN+PSH+URG)
- TCP FIN without prior SYN
- IP source-spoofed packets
- UDP with malformed checksum

All injected probes must be dropped; none should be accepted and forwarded.

**Acceptance criteria:**
- `evasion_accepted_count == 0`

---

#### bsi-net-3-2-a10-logging {#bsi-net-3-2-a10-logging}

**Control:** NET.3.2.A10 — Logging and audit trail
**Scenario kind:** `throughput` (with Prometheus counter validation)
**Status:** Partial

shorewalld exports nft counter values to Prometheus.  During a throughput
scenario run, the controller polls Prometheus metrics and verifies that the
per-rule byte/packet counters increment.  This demonstrates that the firewall
is counting traffic against rules (a prerequisite for meaningful logging).

**Gap:** Per-packet syslog export is not implemented.  Central SIEM ingestion,
syslog-integrity hashing, and log-archival retention policy are operational
concerns outside the automated test scope.  OPS.1.2.5 sub-controls B, C, D
cannot be fully automated.

**Acceptance criteria:**
- `prometheus_counter_increments == true` — at least one nft counter incremented during the run

---

#### bsi-net-3-2-a12-redundancy-ha {#bsi-net-3-2-a12-redundancy-ha}

**Control:** NET.3.2.A12 — Redundancy and high availability
**Scenario kind:** `ha_failover_drill`

The firewall must tolerate failure of the active node and restore traffic
forwarding within an acceptable window via VRRP failover.  The
`ha_failover_drill` scenario:

1. Establishes a long-running TCP stream through the active FW node.
2. Stops `keepalived` on the primary FW via SSH.
3. Measures the time until traffic flows again via the secondary (VRRP
   failover).
4. Restarts `keepalived` on the primary and verifies normal operation is
   restored.

**Acceptance criteria:**
- `failover_time_max_s <= 3.0`
- `traffic_gap_max_s <= 3.0`

---

#### bsi-ops-1-2-5-log-retention {#bsi-ops-1-2-5-log-retention}

**Control:** OPS.1.2.5 — Log retention and integrity
**Status:** Partial — no automated scenario

Log data must be retained for a defined period and protected against
modification.  The BSI baseline requires a minimum of 90 days retention and
tamper-evident log storage.

No automated stagelab scenario exists for this control.  shorewalld exports
counters to Prometheus (time-series retention is Prometheus-operator-level
configuration); per-packet logs would require syslog-ng or rsyslog integration.

**Gap:** Manual review required.  Operator must verify:
1. Prometheus retention setting >= 90 days (or external TSDB).
2. Any syslog export is configured and log files are append-only.

---

### Out of scope {#bsi-out-of-scope}

The following BSI IT-Grundschutz controls are **not covered** by the automated
test suite:

| Control | Reason |
|---------|--------|
| NET.3.2.A9 | NTP time synchronisation is an OS/chrony concern, not a firewall rule concern |
| NET.3.2.A3 | Physical network port security (switch hardening) — hardware concern |
| NET.3.2.A8 | VPN/PKI is handled by OpenVPN/WireGuard — FW rules permit VPN but do not test cryptography |
| NET.3.2.A11 | Remote administration channel hardening is an SSH-server configuration concern |
| NET.1.1.A1 | Network architecture documentation is a governance artefact; cannot be automated |
| All OPS.1.2.5 sub-controls except counter increment | Log retention/integrity are operational/infrastructure concerns |

---

*Generated by stream B2 of the security-test-plan feature.*
*See `docs/testing/security-test-plan.bsi.yaml` for the machine-readable catalogue.*

---

## CIS Benchmarks {#cis-benchmarks}

**Standard:** CIS Distribution Independent Linux Benchmark v2.0.0
**Relevant sections:** 5.2 (nftables/iptables), 5.3 (loopback), 5.4 (outbound)
**Fragment maintainer:** stream B2
**Last updated:** 2026-04-20

This document is a per-standard fragment.  The M1 merger agent consolidates
this file together with the CC/NIST (B1), BSI (B2), OWASP/ISO-27001 (B3)
fragments into `docs/testing/security-test-plan.md`.

**CIS context:** CIS does not publish a dedicated standalone "Firewall
Benchmark".  The firewall-relevant items appear within the CIS Distribution
Independent Linux Benchmark v2.0 under Section 5 "Access, Authentication and
Authorization".  Kernel-sysctl items (Section 3) and system-hardening items
(Section 6) are explicitly out of scope for firewall-rule testing.

---

### Coverage summary

| Control | Title | Coverage |
|---------|-------|----------|
| 5.2.1 | Default-deny ingress from WAN | Strong — `rule_scan` |
| 5.2.2 | Default-deny egress (outbound) | Partial — zone policy is deployment-specific |
| 5.2.3 | Open listening ports match expected rule set | Strong — `rule_scan` |
| 5.2.4 | RFC-1918 source addresses blocked from WAN | Strong — `rule_scan` |
| 5.2.5 | Bogon/martian source address block on WAN | Strong — `evasion_probes` |
| 5.3 | Loopback interface rules | Out of scope — system hardening |
| 5.4.1 | Accept established/related connections | Strong — `long_flow_survival` |
| 5.4.2 | Outbound rules coverage matrix | Strong — `rule_coverage_matrix` |
| 3.5 | Uncommon protocols disabled (DCCP/SCTP) | Out of scope — kernel module config |
| 3.x | Network kernel parameters | Out of scope — sysctl, not firewall rules |

---

### Test catalogue

#### cis-5-2-1-firewall-default-deny-ingress {#cis-5-2-1-firewall-default-deny-ingress}

**Control:** CIS 5.2.1 — Ensure default deny firewall policy (ingress)
**Scenario kind:** `rule_scan`

The default policy for inbound (ingress from WAN) traffic must be DROP.  Any
packet not matched by an explicit allow rule must be silently discarded.

This test generates 500 random destination probes from the WAN endpoint toward
the protected address space.  The random sample deliberately includes ports and
protocols not present in the allow rule set.  A zero `fail_accept_count`
demonstrates that the default-deny policy is effective.

**Acceptance criteria:**
- `fail_accept_count == 0` — no unexpected packet forwarded through the firewall
- `fail_drop_count <= 2` — small operator override per deployment (e.g. ICMP probe replies from the FW itself)

**Evidence:** `audit.json scenarios[].test_id == cis-5-2-1-firewall-default-deny-ingress`

---

#### cis-5-2-2-firewall-default-deny-egress {#cis-5-2-2-firewall-default-deny-egress}

**Control:** CIS 5.2.2 — Ensure default deny firewall policy (outbound)
**Scenario kind:** `rule_scan`
**Status:** Partial

The default policy for outbound traffic should also be DROP or REJECT.  Only
explicitly permitted egress flows are allowed.  This test scans from an
internal endpoint toward external destinations and verifies that unsolicited
outbound traffic is blocked.

**Note:** Whether egress default-deny is configured depends on zone policy in
the specific deployment.  Some deployments permit unrestricted outbound.
stagelab validates the observed behaviour; operators must verify the zone policy
configuration aligns with CIS intent.

**Acceptance criteria:**
- `fail_accept_count == 0` — no unexpected service reachable from LAN to arbitrary WAN ports

---

#### cis-5-2-3-open-ports-inventory {#cis-5-2-3-open-ports-inventory}

**Control:** CIS 5.2.3 — Ensure firewall rules exist for all open ports
**Scenario kind:** `rule_scan`

The set of ports reachable from outside must exactly match the set of ports
with explicit allow rules.  A rule scan with a wide random port sample probes
the expected-open ports and a random sample of unexpected ports; unexpected-open
ports fail the criterion.

**Acceptance criteria:**
- `unexpected_open_port_count == 0`

---

#### cis-5-2-4-ingress-rfc1918-from-wan {#cis-5-2-4-ingress-rfc1918-from-wan}

**Control:** CIS 5.2.4 — Block RFC-1918 source addresses from WAN ingress
**Scenario kind:** `rule_scan`

Packets arriving on the WAN interface with a RFC-1918 source address
(10/8, 172.16/12, 192.168/16) must be dropped.  shorewall-nft enforces this
via reverse-path filtering or explicit martian-block rules.

This test uses the `rule_scan` scenario with probes sourced from RFC-1918
ranges injected through the WAN endpoint, verifying that all such packets are
dropped.

**Acceptance criteria:**
- `fail_accept_count == 0` — no RFC-1918-sourced packet forwarded from WAN

---

#### cis-5-2-5-ingress-bogon-block {#cis-5-2-5-ingress-bogon-block}

**Control:** CIS 5.2.5 — Block bogon/martian source addresses on WAN ingress
**Scenario kind:** `evasion_probes`

Beyond RFC-1918, packets with loopback (127/8), link-local (169.254/16),
multicast source (224/4), or reserved-class-E (240/4) source addresses must be
dropped on the WAN ingress interface.

The `evasion_probes` scenario with `ip_spoof` probe type sends packets with a
link-local source (169.254.1.1) from the WAN endpoint and verifies they are
dropped.  Operators should extend the test with additional bogon ranges as
needed.

**Acceptance criteria:**
- `evasion_accepted_count == 0`

---

#### cis-5-4-1-established-traffic {#cis-5-4-1-established-traffic}

**Control:** CIS 5.4.1 — Ensure firewall accepts outbound connections and established/related return traffic
**Scenario kind:** `long_flow_survival`

The firewall must accept return traffic for outbound connections
(`ct state established,related accept`).  A long-running TCP stream from
internal to external validates that return packets are not dropped after the
initial connection is established and that conntrack entries are not prematurely
expired.

The `long_flow_survival` scenario temporarily lowers the conntrack TCP
established timeout (to confirm the actual configured value is above the
stream duration), then verifies the flow survives for the full test window.

**Acceptance criteria:**
- `flow_survived == true`
- `retransmit_count_max <= 50`

---

#### cis-5-4-2-outbound-rules-coverage {#cis-5-4-2-outbound-rules-coverage}

**Control:** CIS 5.4.2 — Ensure only authorised outbound services are permitted
**Scenario kind:** `rule_coverage_matrix`

All authorised outbound services must have explicit allow rules; no rule should
be a catch-all that opens broad egress.  The `rule_coverage_matrix` scenario
probes all zone-pair combinations with the known-permitted services and verifies
that:

1. All expected services (TCP 22, 25, 80, 443, 465, 587; UDP 53, 123) are
   reachable from LAN to WAN.
2. No unexpected service is reachable.

**Acceptance criteria:**
- `unexpected_accept_count == 0`
- `expected_services_reachable == true`

---

### Out of scope {#cis-out-of-scope}

The following CIS controls are **not covered** by the automated test suite:

| Control | Reason |
|---------|--------|
| 5.3 | Loopback interface rules are system-hardening (one-time config audit), not firewall-rule testing |
| 3.5 | Disabling DCCP/SCTP is a kernel module blacklist concern — not a firewall rule concern |
| 3.x (net.ipv4.ip_forward, net.ipv4.conf.all.send_redirects, etc.) | Kernel sysctl — applied at boot by sysctl.d; verified by a separate hardening audit tool |
| 6.x | CIS Section 6 (auditd, file integrity, PAM, etc.) — entirely out of scope for firewall testing |

---

*Generated by stream B2 of the security-test-plan feature.*
*See `docs/testing/security-test-plan.cis.yaml` for the machine-readable catalogue.*

---

## OWASP {#owasp}

**Standard:** OWASP Firewall Checklist (2021 Community Edition) /
OWASP Testing Guide v4, OTG-CONFIG-009  
**Fragment:** B3 (stream B3 of the security-test-plan feature)  
**Machine-readable catalogue:** `security-test-plan.owasp.yaml`

---

### Overview

This fragment maps OWASP firewall checklist controls to existing stagelab
scenario kinds.  Each entry records coverage status, the mapped scenario,
and acceptance criteria.  Out-of-scope items are gathered at the end with
explicit rationale.

The OWASP Firewall Checklist addresses eight control areas (FW-1 through
FW-8).  All eight are represented here: six are fully covered, one is
partial (FW-5 stateful inspection), and the two most commonly cited
out-of-scope items (TLS fingerprint evasion, fragment-reassembly DoS) are
explicitly excluded.

---

### Test catalogue

#### FW-1 — Firewall configuration review {#owasp-fw-1-config-review}

| Field | Value |
|-------|-------|
| test_id | `owasp-fw-1-config-review` |
| Status | **Covered** |
| Scenario | `rule_coverage_matrix` |
| Cross-ref | ISO/IEC 27001 A.18.2.1 |

Review the active ruleset for correctness, over-permission, shadowed rules,
and compliance with the deployment security policy.  Evidence is produced by
`stagelab review`, which collates tier-B (firewall-side) and tier-C
(compiler-hint) advisor recommendations backed by live Prometheus counter
data, and renders them in the HTML audit report.

**Acceptance criteria:**

- `advisor_tier_b_unresolved == 0` — all firewall-side recommendations
  addressed before sign-off.
- `advisor_tier_c_unresolved <= 5` — operator override permitted per
  deployment.

---

#### FW-2 — Rule-base audit {#owasp-fw-2-rulebase-audit}

| Field | Value |
|-------|-------|
| test_id | `owasp-fw-2-rulebase-audit` |
| Status | **Covered** |
| Scenario | `rule_coverage_matrix` |
| Cross-ref | — |

Enumerate all zone-pair combinations to detect rules that are never matched
(dead rules), rules that shadow more-specific entries, and zone pairs that
are inadvertently open.  `rule_coverage_matrix` emits per-zone-pair hit
counters; `rule_order.py` groups chains by packet volume and raises tier-C
hints for ordering optimisations.

**Acceptance criteria:**

- `unreachable_rule_count == 0`
- `over_permissive_zone_pairs == 0`

---

#### FW-3 — Default-deny policy verification {#owasp-fw-3-default-deny}

| Field | Value |
|-------|-------|
| test_id | `owasp-fw-3-default-deny` |
| Status | **Covered** |
| Scenario | `rule_scan` |
| Cross-ref | ISO/IEC 27001 A.13.1.1 |

Probe all unmapped zone pairs with random source/destination tuples and verify
that every packet is dropped.  No implicit accept path should exist for
traffic without an explicit ACCEPT rule.

**Acceptance criteria:**

- `fail_accept_count == 0`

---

#### FW-4 — Evasion and bypass probe suite {#owasp-fw-4-evasion-bypass}

| Field | Value |
|-------|-------|
| test_id | `owasp-fw-4-evasion-bypass` |
| Status | **Covered** |
| Scenario | `evasion_probes` |
| Cross-ref | — |

Send crafted packets designed to evade stateless ACLs: IP fragmentation,
overlapping fragment offsets, TCP RST-in-handshake, UDP bad checksum, and
IP-options stripping.  All probes must be dropped or normalised; none must
reach the protected zone.

**Acceptance criteria:**

- `evasion_success_count == 0`

---

#### FW-5 — Stateful inspection under load *(partial)* {#owasp-fw-5-stateful-inspection}

| Field | Value |
|-------|-------|
| test_id | `owasp-fw-5-stateful-inspection` |
| Status | **Partial** |
| Scenario | `conn_storm` |
| Cross-ref | — |

`conn_storm` and `long_flow_survival` exercise the conntrack code path under
high concurrency and over extended time, providing evidence that stateful
tracking functions under load.

**Gap:** The simlab correctness oracle is stateless (iptables-equivalent; no
conntrack model).  Out-of-state packet injection (spoofed RST, mid-session
SYN) is not validated at the oracle level.  A full FW-5 assessment requires
a stateful oracle.  This is tracked as the open item "simlab stateful oracle"
in `CLAUDE.md`.

**Acceptance criteria (proxy):**

- `established_flows_dropped == 0`
- `conntrack_table_fill_fraction <= 0.80`

---

#### FW-6 — HA failover drill {#owasp-fw-6-ha-failover}

| Field | Value |
|-------|-------|
| test_id | `owasp-fw-6-ha-failover` |
| Status | **Covered** |
| Scenario | `ha_failover_drill` |
| Cross-ref | — |

Trigger a VRRP failover while traffic is flowing.  Verify that established
TCP sessions survive the switchover (conntrackd state replication), that
VRRP/keepalived converges within the SLA window, and that Bird BGP
reconverges.

**Acceptance criteria:**

- `session_continuity == true`
- `failover_convergence_s <= 3`
- `bgp_reconvergence_s <= 10`

---

#### FW-7 — Protocol-stack attack resistance {#owasp-fw-7-protocol-stack}

| Field | Value |
|-------|-------|
| test_id | `owasp-fw-7-protocol-stack` |
| Status | **Covered** |
| Scenario | `dos_syn_flood` (+ `evasion_probes`) |
| Cross-ref | — |

Combine `evasion_probes` (layer-3/4 malformations) with `dos_syn_flood`
(TCP SYN exhaustion).  The firewall must absorb or drop all malformed frames
without degrading legitimate traffic.

**Acceptance criteria:**

- `legitimate_throughput_degradation_pct <= 5`
- `malformed_frame_accepted == 0`

---

#### FW-8 — Operational hardening {#owasp-fw-8-operational-hardening}

| Field | Value |
|-------|-------|
| test_id | `owasp-fw-8-operational-hardening` |
| Status | **Covered** |
| Scenario | `reload_atomicity` |
| Cross-ref | ISO/IEC 27001 A.18.2.2 |

Verify that ruleset reloads are atomic (no window where policy is absent),
that the shorewalld Prometheus exporter is reachable and returning
well-formed metrics, and that the management interface is not reachable from
non-management zones.

**Acceptance criteria:**

- `traffic_gap_during_reload_ms == 0`
- `prometheus_scrape_ok == true`

---

### Out of scope

#### TLS fingerprint / protocol-downgrade evasion

TLS fingerprint and protocol-downgrade attacks require a TLS-aware proxy or
DPI appliance operating above layer 4.  nftables operates below the TLS
layer; this control is out of scope for a stateless/stateful packet firewall.

#### Fragment-reassembly DoS (Teardrop / Rose)

Fragment-reassembly DoS is handled by the Linux kernel's IP reassembly
subsystem before nftables sees the resulting packet.  The effect is on the
host network stack, not the ruleset.  Tracked as a separate open item in
`CLAUDE.md`.

---

### Summary table

| test_id | Control | Status |
|---------|---------|--------|
| `owasp-fw-1-config-review` | FW-1 | Covered |
| `owasp-fw-2-rulebase-audit` | FW-2 | Covered |
| `owasp-fw-3-default-deny` | FW-3 | Covered |
| `owasp-fw-4-evasion-bypass` | FW-4 | Covered |
| `owasp-fw-5-stateful-inspection` | FW-5 | Partial |
| `owasp-fw-6-ha-failover` | FW-6 | Covered |
| `owasp-fw-7-protocol-stack` | FW-7 | Covered |
| `owasp-fw-8-operational-hardening` | FW-8 | Covered |
| `owasp-tls-fingerprint` | — | Out of scope |
| `owasp-fragment-reassembly-dos` | — | Out of scope |

---

## ISO/IEC 27001 {#iso-27001}

**Standard:** ISO/IEC 27001:2013 Annex A / ISO/IEC 27002:2013  
**Scope:** Firewall-relevant controls from A.12 (Operations), A.13
(Communications security), and A.18 (Compliance)  
**Fragment:** B3 (stream B3 of the security-test-plan feature)  
**Machine-readable catalogue:** `security-test-plan.iso27001.yaml`

---

### Overview

This fragment maps ISO/IEC 27001:2013 Annex A controls to existing stagelab
scenario kinds.  Only controls where the firewall is the primary or a
significant contributing technical control are included.  Controls relating
to personnel security (A.7), physical security (A.11), access management
(A.9), and asset management (A.8) are explicitly out of scope; the rationale
is recorded in the "Out of scope" section.

Eight controls are catalogued: three from A.13 (Communications security),
two from A.12 (Operations), and three from A.18 (Compliance).

---

### Test catalogue

#### A.13.1.1 — Network controls {#iso27001-a-13-1-1-network-controls}

| Field | Value |
|-------|-------|
| test_id | `iso27001-a-13-1-1-network-controls` |
| Status | **Covered** |
| Scenario | `rule_scan` |
| Cross-ref | OWASP FW-3 |

Verify that networks are segregated into security zones and that inter-zone
traffic is controlled by an explicit, default-deny policy.  The compiled
nftables ruleset enforces zone policies; `rule_scan` probes confirm that
every non-permitted zone pair is dropped.

**Acceptance criteria:**

- `fail_accept_count == 0`
- `zone_pair_coverage_pct == 100`

---

#### A.13.1.2 — Security of network services *(partial)* {#iso27001-a-13-1-2-network-service-security}

| Field | Value |
|-------|-------|
| test_id | `iso27001-a-13-1-2-network-service-security` |
| Status | **Partial** |
| Scenario | `throughput` |
| Cross-ref | — |

**Gap:** Service-level protocol SLA (guaranteed bandwidth or latency per
service class) is not separately validated.  Throughput and latency
scenarios provide proxy evidence that the firewall does not degrade service
quality beyond acceptable bounds, but formal SLA verification requires
per-service traffic shaping policy, which is not in scope.

**Acceptance criteria (proxy):**

- `throughput_degradation_pct <= 5`

---

#### A.13.1.3 — Segregation of networks {#iso27001-a-13-1-3-network-segregation}

| Field | Value |
|-------|-------|
| test_id | `iso27001-a-13-1-3-network-segregation` |
| Status | **Covered** |
| Scenario | `rule_coverage_matrix` |
| Cross-ref | OWASP FW-2 |

Exhaustively enumerate every zone-pair combination and confirm that each
pair is either explicitly permitted or explicitly blocked.  No implicit
reachability must exist between security zones.  `rule_coverage_matrix`
iterates all (src, dst) zone pairs, sends test traffic, and compares
observed nft counter increments against the expected policy.

**Acceptance criteria:**

- `implicit_accept_zone_pairs == 0`
- `uncovered_zone_pairs == 0`

---

#### A.13.2.1 — Information transfer controls {#iso27001-a-13-2-1-transfer-controls}

| Field | Value |
|-------|-------|
| test_id | `iso27001-a-13-2-1-transfer-controls` |
| Status | **Covered** |
| Scenario | `rule_scan` |
| Cross-ref | — |

Verify that zone-pair rules restrict data flows to those explicitly permitted
by the security policy, preventing unauthorised lateral movement or data
exfiltration paths.  Validated by `rule_scan` (random probes on
non-permitted paths) and `rule_coverage_matrix` (systematic enumeration of
all flow directions).

**Acceptance criteria:**

- `fail_accept_count == 0`

---

#### A.12.4.1 — Event logging *(partial)* {#iso27001-a-12-4-1-event-logging}

| Field | Value |
|-------|-------|
| test_id | `iso27001-a-12-4-1-event-logging` |
| Status | **Partial** |
| Scenario | `rule_coverage_matrix` (Prometheus scrape) |
| Cross-ref | — |

Prometheus counters (via shorewalld) provide near-real-time aggregate
metrics: packets, bytes, connection rate, drop count.  However, there is no
per-packet drop log, no central SIEM integration, and no CEF/syslog export.

**Gap:** Full compliance with A.12.4.1 requires a per-packet logging
pipeline so that every security event (drop, reject, new connection) is
recorded with timestamp, source/destination, and rule reference.  This is
tracked as a separate shorewalld task in `CLAUDE.md`.

**Acceptance criteria (proxy):**

- `prometheus_scrape_ok == true`
- `nft_counter_gap_s <= 30`

---

#### A.12.6.1 — Technical vulnerability management *(partial)* {#iso27001-a-12-6-1-vuln-management}

| Field | Value |
|-------|-------|
| test_id | `iso27001-a-12-6-1-vuln-management` |
| Status | **Partial** |
| Scenario | `rule_coverage_matrix` |
| Cross-ref | — |

Advisor tier-B/C recommendations are automatically opened as PRs via
`stagelab review`, providing a structured workflow for addressing
firewall-configuration vulnerabilities.

**Gap:** No automated CVE feed or package-vulnerability scanner is
integrated.  This covers the configuration-drift aspect of A.12.6.1 but
not the software-CVE aspect.

**Acceptance criteria:**

- `advisor_tier_b_pr_created == true`

---

#### A.18.2.1 — Independent review of information security {#iso27001-a-18-2-1-security-review}

| Field | Value |
|-------|-------|
| test_id | `iso27001-a-18-2-1-security-review` |
| Status | **Covered** |
| Scenario | `rule_coverage_matrix` (+ `stagelab audit`) |
| Cross-ref | — |

`stagelab audit` aggregates evidence from all scenario runs (run.json
files), renders a signed HTML/PDF audit report with per-scenario pass/fail
verdicts, advisor recommendations, and rule-coverage heat-map.  The report
is suitable for submission to an independent reviewer or compliance auditor.

**Acceptance criteria:**

- `audit_html_generated == true`
- `audit_json_generated == true`
- `overall_pass == true`

---

#### A.18.2.2 — Compliance with security policies {#iso27001-a-18-2-2-policy-compliance}

| Field | Value |
|-------|-------|
| test_id | `iso27001-a-18-2-2-policy-compliance` |
| Status | **Covered** |
| Scenario | `reload_atomicity` |
| Cross-ref | OWASP FW-8 |

This test plan is the policy instrument: running
`tools/run-security-test-plan.sh` executes all catalogue entries, enforces
acceptance criteria, and exits non-zero on any failure.  Regular execution
(scheduled or on every ruleset change) implements continuous compliance
checking against the documented security policy.

**Acceptance criteria:**

- `run_exit_code == 0`
- `acceptance_criteria_failures == 0`

---

### Out of scope

#### A.12.4.3 — Administrator and operator activity logs

OS-level audit control (auditd, sshd logs).  Not a firewall ruleset test.

#### A.18.1.3 — Records protection

Data-retention and organisational policy control.  Outside firewall scope.

#### A.7 — Human resource security

Vetting, contracts, and disciplinary processes are HR/organisational
controls, not firewall tests.

#### A.8 — Asset management

Inventory and classification is a governance control, not a firewall test.

#### A.9 — Access control (identity layer)

IAM, MFA, and privilege review are not directly tested by firewall scenarios.
The firewall enforces network-layer access policy only.

#### A.11 — Physical and environmental security

Data-centre access, cabling, and power are not firewall tests.

---

### Summary table

| test_id | Control | Status |
|---------|---------|--------|
| `iso27001-a-13-1-1-network-controls` | A.13.1.1 | Covered |
| `iso27001-a-13-1-2-network-service-security` | A.13.1.2 | Partial |
| `iso27001-a-13-1-3-network-segregation` | A.13.1.3 | Covered |
| `iso27001-a-13-2-1-transfer-controls` | A.13.2.1 | Covered |
| `iso27001-a-12-4-1-event-logging` | A.12.4.1 | Partial |
| `iso27001-a-12-6-1-vuln-management` | A.12.6.1 | Partial |
| `iso27001-a-18-2-1-security-review` | A.18.2.1 | Covered |
| `iso27001-a-18-2-2-policy-compliance` | A.18.2.2 | Covered |
| `iso27001-a-12-4-3-admin-activity` | A.12.4.3 | Out of scope |
| `iso27001-a-18-1-3-records-protection` | A.18.1.3 | Out of scope |
| `iso27001-a-7-personnel` | A.7 | Out of scope |
| `iso27001-a-8-asset-management` | A.8 | Out of scope |
| `iso27001-a-9-access-control` | A.9 | Out of scope |
| `iso27001-a-11-physical` | A.11 | Out of scope |

---

## Performance addendum (IPv6) {#performance-addendum-ipv6}

Merged by M1 into security-test-plan.md.

### In scope

- TCP throughput parity with IPv4 over a native IPv6 endpoint pair.
- UDP throughput parity over a native IPv6 endpoint pair.

### Test catalogue

#### perf-ipv6-tcp-throughput — IPv6 TCP throughput meets SLO

- **Scenario**: `throughput` with `proto: tcp` and IPv6-native endpoints (`fd00:10:0:13::100/64` and `fd00:10:0:13::200/64`).
- **Acceptance**: `min_gbps >= 8.0` AND `max_retrans_ratio <= 0.005`.
- **Standard refs**: NIST SP 800-53 SC-7 (boundary protection).
- **Evidence**: `audit.json scenarios[].test_id == perf-ipv6-tcp-throughput`.
- **Rationale**: SC-7 boundary protection applies to IPv6 as much as IPv4; throughput parity must be demonstrated to confirm the firewall does not introduce IPv6-specific performance degradation.

#### perf-ipv6-udp-throughput — IPv6 UDP throughput meets SLO

- **Scenario**: `throughput` with `proto: udp` and IPv6-native endpoints.
- **Acceptance**: `min_gbps >= 5.0`.
- **Standard refs**: NIST SP 800-53 SC-7 (boundary protection).
- **Evidence**: `audit.json scenarios[].test_id == perf-ipv6-udp-throughput`.
- **Rationale**: UDP-based protocols (DNS, NTP, syslog, media) traverse the firewall over IPv6 in dual-stack deployments.  Throughput parity reduces the risk of a performance cliff when clients migrate to IPv6.

### Running these tests

Use the example config `tools/stagelab-example-ipv6-throughput.yaml`:

```bash
.venv/bin/stagelab validate tools/stagelab-example-ipv6-throughput.yaml
.venv/bin/stagelab run tools/stagelab-example-ipv6-throughput.yaml
```

The example config requires physical interfaces on the two tester hosts.  Adjust
`nic`, `vlan`, and the ULA prefix (`fd00:10:0:13::/64`) to match the deployment.

### Out of scope

- **IPv6-only transition / NAT64** — the reference firewall is dual-stack; the NAT64 appliance is a separate component.
- **IPv6 flow-label QoS** — not a firewall-level concern; deferred to the network-layer QoS test plan.
- **MLD (Multicast Listener Discovery)** — handled by CIS/OWASP protocol-stack test items; out of scope for throughput parity.

---

## Consolidated out of scope {#consolidated-out-of-scope}

Every fragment's out-of-scope items unified:

| Standard | Item | Reason |
|---|---|---|
| CC | FCS_* (Cryptographic support) | Firewall is a stateless/stateful packet filter. TLS/IPsec crypto stack testing belongs to a separate component evaluation. |
| CC | ADV_* (Development) | Requires formal design documentation review and developer correspondence evidence. No test automation applies. |
| CC | ATE_* (Tests) | Meta-level; covered by the existence of this framework, not by individual scenarios. |
| CC | FIA_* (Identification and authentication) | Management-plane concern. The firewall does not authenticate forwarded flows. |
| CC | FTP_ITC.1 (Inter-TSF channel) | VPN/IPsec between trust domains is not in scope for the packet-filter test plan. |
| CC | FPT_STM.1 (Reliable timestamps) | NTP synchronisation is an OS/kernel concern; not tested here. |
| CC | AGD_* (Guidance documents) | Documentation review; not automated. |
| CC | ALC_* (Lifecycle support) | Supply-chain and process concerns; not testable with this framework. |
| NIST | SC-6 (Resource Availability) | Kernel-level resource partitioning (cgroups, CPU pinning) is a platform concern. Partially addressed by the advisor tuning_sweep heuristic. |
| NIST | IA-* (Identification and Authentication) | Management-plane authentication; firewall does not authenticate forwarded flows. |
| NIST | CM-* (Configuration Management) | Organisational configuration change control process; not automatable. |
| NIST | AT-*, PS-* (Awareness and Training / Personnel Security) | Personnel controls; not testable by this framework. |
| NIST | PE-* (Physical and Environmental Protection) | Data-centre physical access controls; outside scope. |
| NIST | SC-8 (Transmission Confidentiality and Integrity) | TLS/MACsec crypto stack testing is a separate component concern. |
| NIST | SC-28 (Protection of Information at Rest) | Disk encryption; outside scope of packet-filter testing. |
| NIST | AU-9 / AU-10 (Audit Protection / Non-repudiation) | Requires an independent audit store. Prometheus counters live on the firewall node itself; dedicated SIEM integration is a separate task. |
| NIST | CA-*, RA-* (Assessment and Risk Management) | Organisational risk processes; not automatable here. |
| BSI | NET.3.2.A9 | NTP time synchronisation is a system-level concern handled by the OS (chrony/ntpd). shorewall-nft does not configure or test NTP; the control is out of scope for firewall rule testing. |
| BSI | NET.1.1.A1 | Network architecture documentation is a governance/design artefact. Automated testing cannot verify completeness of documentation. The shorewall-nft configuration files are the machine-readable architecture record; human review is required for NET.1.1.A1. |
| BSI | NET.3.2.A3 | Physical network port security (switch port hardening) is out of scope for a software firewall test suite. |
| BSI | NET.3.2.A8 | VPN termination and PKI are handled by external components (OpenVPN, WireGuard). Firewall rules permit VPN traffic but do not perform cryptographic validation — out of scope. |
| BSI | NET.3.2.A11 | Remote administration channel hardening is an SSH server configuration concern, not a firewall rule concern. Out of scope. |
| CIS | 5.3 | CIS 5.3 requires loopback interface rules (accept all lo traffic, drop lo-source from non-lo). These are system-hardening rules that belong in the OS firewall configuration, not in the shorewall-nft firewall-rule test suite. Verified as a one-time configuration audit item, not by repeated stagelab runs. |
| CIS | 3.5 | Disabling uncommon protocols (DCCP/SCTP) is a kernel module configuration task (modprobe.d blacklist). Not a firewall rule concern; out of scope for shorewall-nft testing. |
| CIS | 3.x | CIS Section 3 network parameters (ip_forward, send_redirects, accept_source_route, etc.) are kernel sysctl settings. Applied at boot by sysctl.d; verified by a separate hardening audit tool. Out of scope for the firewall-rule test suite. |
| CIS | 6.x | CIS Section 6 (system hardening — auditd, file integrity, PAM, etc.) is entirely out of scope for firewall testing. |
| OWASP | owasp-tls-fingerprint | TLS fingerprint / protocol-downgrade evasion requires a TLS-aware proxy or DPI appliance. nftables operates below the TLS layer; this control is out of scope for a stateless/stateful packet firewall. |
| OWASP | owasp-fragment-reassembly-dos | Fragment-reassembly DoS (Teardrop / Rose) is handled by the Linux kernel before nftables sees the packet. Effect is on the host stack, not the ruleset. Tracked as a separate open item in CLAUDE.md. |
| ISO-27001 | A.12.4.3 | Administrator and operator activity logs are OS-level controls (auditd, sshd AuthorizedKeysFile logs). Not a firewall ruleset test. |
| ISO-27001 | A.18.1.3 | Records protection is a data-retention and organisational policy control. Outside firewall scope. |
| ISO-27001 | A.7 | Human resource security (vetting, contracts, disciplinary process) is an HR/organisational control, not a firewall test. |
| ISO-27001 | A.8 | Asset management and classification is an inventory/governance control, not a firewall test. |
| ISO-27001 | A.9 | Identity and authentication management (IAM, MFA, privilege review) is not directly tested by firewall scenarios; the firewall enforces network-layer access policy only. |
| ISO-27001 | A.11 | Physical and environmental security (data-centre access, cabling, power) is not a firewall test. |
| Perf-IPv6 | IPv6-only transition / NAT64 | The reference firewall is dual-stack; NAT64 is a separate appliance and not in scope for throughput parity tests. |
| Perf-IPv6 | IPv6 flow-label QoS | Flow-label based QoS is not a firewall-level concern and is deferred to the network-layer QoS test plan. |
| Perf-IPv6 | MLD (Multicast Listener Discovery) | MLD is handled by the CIS/OWASP protocol-stack test items; out of scope for throughput parity. |

---

## How to run {#how-to-run}

End-to-end executor:

```bash
tools/run-security-test-plan.sh --standards all --config <base-config.yaml>
```

Filter to a subset of standards:

```bash
tools/run-security-test-plan.sh --standards cis,owasp --config <base-config.yaml>
```

Dry-run (print planned invocations without executing):

```bash
tools/run-security-test-plan.sh --standards all --config <base-config.yaml> --dry-run
```

See `tools/run-security-test-plan.sh --help` for full options.

The machine-readable catalogue is at `docs/testing/security-test-plan.yaml`.
Regenerate this document and the YAML catalogue:

```bash
tools/merge-security-test-plan-yaml.py
tools/merge-security-test-plan.py
```
