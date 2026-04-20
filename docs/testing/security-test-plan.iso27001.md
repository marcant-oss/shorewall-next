# ISO/IEC 27001:2013 Annex A — Security Test Plan Fragment

**Standard:** ISO/IEC 27001:2013 Annex A / ISO/IEC 27002:2013  
**Scope:** Firewall-relevant controls from A.12 (Operations), A.13
(Communications security), and A.18 (Compliance)  
**Fragment:** B3 (stream B3 of the security-test-plan feature)  
**Machine-readable catalogue:** `security-test-plan.iso27001.yaml`

---

## Overview

This fragment maps ISO/IEC 27001:2013 Annex A controls to existing stagelab
scenario kinds.  Only controls where the firewall is the primary or a
significant contributing technical control are included.  Controls relating
to personnel security (A.7), physical security (A.11), access management
(A.9), and asset management (A.8) are explicitly out of scope; the rationale
is recorded in the "Out of scope" section.

Eight controls are catalogued: three from A.13 (Communications security),
two from A.12 (Operations), and three from A.18 (Compliance).

---

## Test catalogue

### A.13.1.1 — Network controls {#iso27001-a-13-1-1-network-controls}

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

### A.13.1.2 — Security of network services *(partial)* {#iso27001-a-13-1-2-network-service-security}

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

### A.13.1.3 — Segregation of networks {#iso27001-a-13-1-3-network-segregation}

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

### A.13.2.1 — Information transfer controls {#iso27001-a-13-2-1-transfer-controls}

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

### A.12.4.1 — Event logging *(partial)* {#iso27001-a-12-4-1-event-logging}

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

### A.12.6.1 — Technical vulnerability management *(partial)* {#iso27001-a-12-6-1-vuln-management}

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

### A.18.2.1 — Independent review of information security {#iso27001-a-18-2-1-security-review}

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

### A.18.2.2 — Compliance with security policies {#iso27001-a-18-2-2-policy-compliance}

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

## Out of scope

### A.12.4.3 — Administrator and operator activity logs

OS-level audit control (auditd, sshd logs).  Not a firewall ruleset test.

### A.18.1.3 — Records protection

Data-retention and organisational policy control.  Outside firewall scope.

### A.7 — Human resource security

Vetting, contracts, and disciplinary processes are HR/organisational
controls, not firewall tests.

### A.8 — Asset management

Inventory and classification is a governance control, not a firewall test.

### A.9 — Access control (identity layer)

IAM, MFA, and privilege review are not directly tested by firewall scenarios.
The firewall enforces network-layer access policy only.

### A.11 — Physical and environmental security

Data-centre access, cabling, and power are not firewall tests.

---

## Summary table

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
