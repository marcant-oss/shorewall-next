# OWASP Firewall Checklist — Security Test Plan Fragment

**Standard:** OWASP Firewall Checklist (2021 Community Edition) /
OWASP Testing Guide v4, OTG-CONFIG-009  
**Fragment:** B3 (stream B3 of the security-test-plan feature)  
**Machine-readable catalogue:** `security-test-plan.owasp.yaml`

---

## Overview

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

## Test catalogue

### FW-1 — Firewall configuration review {#owasp-fw-1-config-review}

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

### FW-2 — Rule-base audit {#owasp-fw-2-rulebase-audit}

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

### FW-3 — Default-deny policy verification {#owasp-fw-3-default-deny}

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

### FW-4 — Evasion and bypass probe suite {#owasp-fw-4-evasion-bypass}

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

### FW-5 — Stateful inspection under load *(partial)* {#owasp-fw-5-stateful-inspection}

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

### FW-6 — HA failover drill {#owasp-fw-6-ha-failover}

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

### FW-7 — Protocol-stack attack resistance {#owasp-fw-7-protocol-stack}

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

### FW-8 — Operational hardening {#owasp-fw-8-operational-hardening}

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

## Out of scope

### TLS fingerprint / protocol-downgrade evasion

TLS fingerprint and protocol-downgrade attacks require a TLS-aware proxy or
DPI appliance operating above layer 4.  nftables operates below the TLS
layer; this control is out of scope for a stateless/stateful packet firewall.

### Fragment-reassembly DoS (Teardrop / Rose)

Fragment-reassembly DoS is handled by the Linux kernel's IP reassembly
subsystem before nftables sees the resulting packet.  The effect is on the
host network stack, not the ruleset.  Tracked as a separate open item in
`CLAUDE.md`.

---

## Summary table

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
