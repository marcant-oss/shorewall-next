# Security test plan — CIS Benchmarks fragment

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

## Coverage summary

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

## Test catalogue

### cis-5-2-1-firewall-default-deny-ingress {#cis-5-2-1-firewall-default-deny-ingress}

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

### cis-5-2-2-firewall-default-deny-egress {#cis-5-2-2-firewall-default-deny-egress}

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

### cis-5-2-3-open-ports-inventory {#cis-5-2-3-open-ports-inventory}

**Control:** CIS 5.2.3 — Ensure firewall rules exist for all open ports
**Scenario kind:** `rule_scan`

The set of ports reachable from outside must exactly match the set of ports
with explicit allow rules.  A rule scan with a wide random port sample probes
the expected-open ports and a random sample of unexpected ports; unexpected-open
ports fail the criterion.

**Acceptance criteria:**
- `unexpected_open_port_count == 0`

---

### cis-5-2-4-ingress-rfc1918-from-wan {#cis-5-2-4-ingress-rfc1918-from-wan}

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

### cis-5-2-5-ingress-bogon-block {#cis-5-2-5-ingress-bogon-block}

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

### cis-5-4-1-established-traffic {#cis-5-4-1-established-traffic}

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

### cis-5-4-2-outbound-rules-coverage {#cis-5-4-2-outbound-rules-coverage}

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

## Out of scope {#cis-out-of-scope}

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
