# Common Criteria (ISO/IEC 15408) — firewall coverage fragment

Merged by M1 into `security-test-plan.md`.

This fragment documents which Common Criteria (CC) Security Functional
Requirements (SFRs) are covered by the stagelab test suite, which are
partially covered, and which are explicitly out of scope.

## In scope

**Protection Profiles**: NDcPP v3.0 (Network Device Collaborative PP) and
the extended FWcPP (Firewall PP). Both profiles specify the minimum set of
SFRs a stateful packet-filter firewall must demonstrate to an evaluator.

**SFR families we touch**: FDP (User Data Protection), FAU (Security Audit),
FRU (Resource Utilisation), FMT (Security Management), FPT (Protection of
the TSF), FTA (TSF Access). We do not attempt to evaluate FCS (Cryptographic
Support) or the assurance families (ADV, ATE, AVA, AGD, ALC) — see Out of
scope below.

## Test catalogue

### cc-fdp-iff-1-basic-flow — Basic information flow control

- **SFR**: FDP_IFF.1 (Subset information flow control)
- **What we test**: Zone-pair accept/drop consistency versus the compiled nft
  ruleset, using `rule_scan` (random probes across the target subnet) and
  `rule_coverage_matrix` (systematic per-zone-pair matrix).
- **Acceptance**: `fail_accept_count == 0` AND `fail_drop_count <= 2` (small
  tolerance for IPv6 NDP edge cases in probe mode).
- **Evidence**: `audit.json scenarios[].test_id == cc-fdp-iff-1-basic-flow`;
  human: this section.

### cc-fdp-iff-1-default-deny — Default deny on undefined zone pairs

- **SFR**: FDP_IFF.1.5 (Deny information flow when no rule matches)
- **What we test**: Traffic to zone pairs with no explicit ACCEPT rule must
  be dropped. Verified by `rule_scan` probing IP addresses not covered by any
  policy; expected result is DROP for every probe.
- **Acceptance**: `fail_accept_count == 0` (zero packets passed on undefined
  zone pairs).
- **Evidence**: `audit.json scenarios[].test_id == cc-fdp-iff-1-default-deny`

### cc-fdp-iff-1-evasion-reject — Reject evasion probes

- **SFR**: FDP_IFF.1 applied to malformed/crafted packets
- **What we test**: The `evasion_probes` scenario sends TCP NULL, TCP XMAS,
  TCP FIN-without-SYN, IP-spoofed, and malformed-checksum UDP frames. All
  must be silently dropped.
- **Acceptance**: `pass_count == 0` across all probe types.
- **Evidence**: `audit.json scenarios[].test_id == cc-fdp-iff-1-evasion-reject`

### cc-fau-gen-1-audit-record — Audit record generation (PARTIAL)

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

### cc-fru-rsa-1-conn-storm — Minimum resource allocation under conn-storm

- **SFR**: FRU_RSA.1 (Minimum quotas)
- **What we test**: `conn_storm` scenario drives high connection-creation rate
  through the firewall. The firewall must continue to handle legitimate traffic
  at minimum 80% of baseline throughput while under load.
- **Acceptance**: `throughput_ratio >= 0.8` (baseline vs under storm).
- **Evidence**: `audit.json scenarios[].test_id == cc-fru-rsa-1-conn-storm`

### cc-fru-rsa-1-dos-syn-flood — Minimum resource allocation under SYN flood

- **SFR**: FRU_RSA.1 (Minimum quotas under DoS)
- **What we test**: `dos_syn_flood` at a controlled rate (capped by
  `STAGELAB_DOS_RATE_CAP_PPS`). At most 5% of SYN packets may reach the
  sink (i.e., 95%+ must be absorbed or dropped by the firewall).
- **Acceptance**: `passed_ratio <= 0.05`.
- **Evidence**: `audit.json scenarios[].test_id == cc-fru-rsa-1-dos-syn-flood`

### cc-fru-rsa-1-dos-conntrack — Minimum resource allocation, conntrack saturation

- **SFR**: FRU_RSA.1 (Minimum quotas, conntrack table)
- **What we test**: `dos_half_open` drives half-open connections toward the
  conntrack table limit. The firewall must keep the established-connection
  table stable (no kernel OOM or conntrack ENOMEM error) and recover after
  the DoS stops.
- **Acceptance**: `kernel_error_count == 0` during drill; recovery confirmed.
- **Evidence**: `audit.json scenarios[].test_id == cc-fru-rsa-1-dos-conntrack`

### cc-fmt-msa-3-default-values — Restrictive default attribute values

- **SFR**: FMT_MSA.3 (Static attribute initialisation)
- **What we test**: The compiled nft ruleset must enforce a default-DROP
  policy at the base chain level, and the `shorewall-nft check` configuration
  compile step must succeed without warnings.
- **Acceptance**: `compile_warnings == 0`; base chain policies are `drop`.
- **Evidence**: compile check output in `audit.json`; default-deny confirmed
  by cc-fdp-iff-1-default-deny.

### cc-fpt-fls-1-reload-atomicity — Preserve secure state during reload

- **SFR**: FPT_FLS.1 (Failure with preservation of secure state)
- **What we test**: `reload_atomicity` scenario runs a long TCP stream through
  the firewall, triggers `shorewall-nft restart` mid-stream, and verifies
  that retransmissions during the reload window stay below threshold.
- **Acceptance**: `max_retrans_during_reload <= 100`.
- **Evidence**: `audit.json scenarios[].test_id == cc-fpt-fls-1-reload-atomicity`

### cc-fpt-rcv-3-ha-failover — Automated recovery via HA failover

- **SFR**: FPT_RCV.3 (Automated recovery)
- **What we test**: `ha_failover_drill` stops keepalived on the primary FW,
  measures downtime until traffic flows via the secondary, then restores the
  primary. Downtime must not exceed 5 seconds.
- **Acceptance**: `max_downtime_s <= 5.0`.
- **Evidence**: `audit.json scenarios[].test_id == cc-fpt-rcv-3-ha-failover`

### cc-fta-ssl-3-long-flow-survival — Established-flow survival

- **SFR**: FTA_SSL.3 (TSF-initiated termination)
- **What we test**: `long_flow_survival` scenario lowers the conntrack
  `tcp_timeout_established` sysctl below the stream duration, then confirms
  whether the flow survives (or dies, as configured). Default test: flow must
  survive the full duration (timeout not reached).
- **Acceptance**: `flow_survived == True` (or `flow_died == True` for the
  expect_flow_dies=True variant).
- **Evidence**: `audit.json scenarios[].test_id == cc-fta-ssl-3-long-flow-survival`

## Out of scope (CC)

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

## Gaps / partial coverage

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
