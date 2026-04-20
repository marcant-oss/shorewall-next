# Security test plan — BSI IT-Grundschutz fragment

**Standard:** BSI IT-Grundschutz Kompendium 2023 Edition 1
**Controls in scope:** NET.3.2 Firewall, NET.1.1 Netzarchitektur, OPS.1.2.5 Protokollierung
**Fragment maintainer:** stream B2
**Last updated:** 2026-04-20

This document is a per-standard fragment.  The M1 merger agent consolidates
this file together with the CC/NIST (B1), OWASP/ISO-27001 (B3) fragments
into `docs/testing/security-test-plan.md`.

---

## Coverage summary

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

## Test catalogue

### bsi-net-3-2-a2-function-separation {#bsi-net-3-2-a2-function-separation}

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

### bsi-net-3-2-a4-rule-documentation {#bsi-net-3-2-a4-rule-documentation}

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

### bsi-net-3-2-a5-dos-protection {#bsi-net-3-2-a5-dos-protection}

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

### bsi-net-3-2-a6-connection-state {#bsi-net-3-2-a6-connection-state}

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

### bsi-net-3-2-a7-protocol-validation {#bsi-net-3-2-a7-protocol-validation}

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

### bsi-net-3-2-a10-logging {#bsi-net-3-2-a10-logging}

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

### bsi-net-3-2-a12-redundancy-ha {#bsi-net-3-2-a12-redundancy-ha}

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

### bsi-ops-1-2-5-log-retention {#bsi-ops-1-2-5-log-retention}

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

## Out of scope {#bsi-out-of-scope}

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
