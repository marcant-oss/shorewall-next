"""TEST_ID fragment for OWASP firewall checklist + ISO/IEC 27001 Annex A.

Each entry maps a stable test_id slug to a 3-tuple:
    (standard, control_id, title)

Consumed by standards.py (merged at import time) and the M1 merger agent.

OWASP references:
    OWASP Testing Guide v4 — OTG-CONFIG-009 "Test Network/Infrastructure Configuration"
    OWASP Firewall Checklist (2021 Community Edition)

ISO/IEC 27001 references:
    ISO/IEC 27001:2013 Annex A
    ISO/IEC 27002:2013 implementation guidance
"""
from __future__ import annotations

TEST_ID_FRAGMENT: dict[str, tuple[str, str, str]] = {
    # ------------------------------------------------------------------ #
    # OWASP Firewall Checklist (~8 entries)                               #
    # ------------------------------------------------------------------ #

    # FW-1: Review the firewall configuration and rule base.
    # Covered by `stagelab review` (tier-B/C recommendations) +
    # Prometheus-backed advisor heuristics.
    "owasp-fw-1-config-review": (
        "owasp",
        "FW-1",
        "Firewall configuration review",
    ),

    # FW-2: Audit the rule base — identify shadowed, redundant, and overly
    # permissive rules.  Covered by `rule_coverage_matrix` (exhaustive
    # zone-pair enumeration) + tier-C rule-order hints from rule_order.py.
    "owasp-fw-2-rulebase-audit": (
        "owasp",
        "FW-2",
        "Rule-base audit (shadow / redundancy / over-permission)",
    ),

    # FW-3: Verify default-deny policy — all traffic not explicitly
    # permitted must be dropped.  Covered by `rule_scan` probing
    # unmapped zone pairs and expecting DROP.
    "owasp-fw-3-default-deny": (
        "owasp",
        "FW-3",
        "Default-deny policy verification",
    ),
    "owasp-fw-3-default-deny-ipv6": (
        "owasp",
        "FW-3",
        "Default-deny policy verification — IPv6",
    ),

    # FW-4: Evasion / bypass — packet-level techniques that bypass stateless
    # ACLs (fragmentation, overlapping offsets, TTL tricks).
    # Covered by `evasion_probes` (TCP RST-in-handshake, bad checksum,
    # overlapping fragments, IP-option-strip).
    "owasp-fw-4-evasion-bypass": (
        "owasp",
        "FW-4",
        "Evasion and bypass probe suite",
    ),
    "owasp-fw-4-evasion-bypass-ipv6": (
        "owasp",
        "FW-4",
        "Evasion and bypass probe suite — IPv6 (extension headers, fragmentation)",
    ),

    # FW-5: Stateful inspection — verify that the firewall correctly
    # tracks connection state and rejects out-of-state packets.
    # PARTIAL: `conn_storm` + `long_flow_survival` exercise stateful code
    # paths under load, but the simlab correctness oracle is stateless
    # (iptables-equivalent; no conntrack model).  Documented as a gap.
    "owasp-fw-5-stateful-inspection": (
        "owasp",
        "FW-5",
        "Stateful inspection under load (partial — oracle is stateless)",
    ),

    # FW-6: HA failover — firewall survives active/passive VRRP switchover
    # without connection loss.  Covered by `ha_failover_drill`.
    "owasp-fw-6-ha-failover": (
        "owasp",
        "FW-6",
        "HA failover drill (VRRP + conntrackd)",
    ),

    # FW-7: Protocol-stack attacks — malformed frames, bad checksums,
    # oversized packets, SYN floods.  Covered by `evasion_probes` (layer-3/4
    # malformations) and `dos_syn_flood`.
    "owasp-fw-7-protocol-stack": (
        "owasp",
        "FW-7",
        "Protocol-stack attack resistance",
    ),

    # FW-8: Operational hardening — atomic reloads, no service gap during
    # rule updates, shorewalld exporter health.
    # Covered by `reload_atomicity` + shorewalld Prometheus endpoint.
    "owasp-fw-8-operational-hardening": (
        "owasp",
        "FW-8",
        "Operational hardening (reload atomicity + exporter health)",
    ),

    # ------------------------------------------------------------------ #
    # ISO/IEC 27001:2013 Annex A — firewall-relevant controls (~8 entries) #
    # ------------------------------------------------------------------ #

    # A.13.1.1: Network controls — segregate, manage, and control networks
    # to protect information and information-processing facilities.
    # Covered by zone policies (compiled ruleset) + `rule_scan`.
    "iso27001-a-13-1-1-network-controls": (
        "iso-27001",
        "A.13.1.1",
        "Network controls (segmentation and access policy)",
    ),
    "iso27001-a-13-1-1-network-controls-ipv6": (
        "iso-27001",
        "A.13.1.1",
        "Network controls — IPv6 (dual-stack segmentation and access policy)",
    ),

    # A.13.1.2: Security of network services — identify and include security
    # mechanisms, service levels, and management requirements.
    # PARTIAL: service-level protocol SLA is not separately validated;
    # throughput + latency scenarios provide proxy evidence only.
    "iso27001-a-13-1-2-network-service-security": (
        "iso-27001",
        "A.13.1.2",
        "Security of network services (partial — SLA proxy via throughput)",
    ),

    # A.13.1.3: Segregation in networks — segregate groups of information
    # services, users, and information systems.
    # Covered by `rule_coverage_matrix` exhaustive zone-pair enumeration.
    "iso27001-a-13-1-3-network-segregation": (
        "iso-27001",
        "A.13.1.3",
        "Segregation of networks (zone-pair exhaustion via rule_coverage_matrix)",
    ),

    # A.12.4.1: Event logging — produce, keep, and regularly review event
    # logs recording user activities, exceptions, and information security
    # events.
    # PARTIAL: Prometheus counters provide near-real-time metrics but there
    # is no central SIEM / syslog integration.  Per-packet drop logging is
    # not implemented.
    "iso27001-a-12-4-1-event-logging": (
        "iso-27001",
        "A.12.4.1",
        "Event logging (partial — Prometheus counters; no per-packet syslog)",
    ),

    # A.12.6.1: Management of technical vulnerabilities — obtain timely
    # information about technical vulnerabilities, evaluate exposure, and
    # take action.
    # PARTIAL: advisor tier-B/C recommendations are tracked in PRs via
    # `stagelab review`; no automated CVE / package-vulnerability feed.
    "iso27001-a-12-6-1-vuln-management": (
        "iso-27001",
        "A.12.6.1",
        "Technical vulnerability management (partial — advisor tier-B/C in review PRs)",
    ),

    # A.18.2.1: Independent review of information security — review the
    # organisation's approach to managing information security at planned
    # intervals.
    # Covered by `stagelab audit` which aggregates evidence from all
    # scenario runs into a signed HTML/PDF audit report.
    "iso27001-a-18-2-1-security-review": (
        "iso-27001",
        "A.18.2.1",
        "Independent review of information security (stagelab audit report)",
    ),

    # A.18.2.2: Compliance with security policies and standards — regularly
    # review compliance of information processing and procedures.
    # Covered by this test plan itself as the policy instrument, executed
    # end-to-end via `tools/run-security-test-plan.sh`.
    "iso27001-a-18-2-2-policy-compliance": (
        "iso-27001",
        "A.18.2.2",
        "Compliance with security policies (this test plan as the policy instrument)",
    ),

    # A.13.2.1: Information transfer policies — formal transfer policies,
    # procedures, and controls to protect the transfer of information.
    # Covered by zone-pair rules restricting inter-zone data flows;
    # validated by `rule_scan` and `rule_coverage_matrix`.
    "iso27001-a-13-2-1-transfer-controls": (
        "iso-27001",
        "A.13.2.1",
        "Information transfer controls (zone-pair data-flow policy enforcement)",
    ),
}

# Explicit out-of-scope items (documented here for the M1 merger):
OUT_OF_SCOPE: dict[str, str] = {
    "iso27001-a-12-4-3-admin-activity": (
        "A.12.4.3 Administrator and operator activity logs — OS-level audit "
        "(auditd/sshd logs); not a firewall test."
    ),
    "iso27001-a-18-1-3-records-protection": (
        "A.18.1.3 Records protection — data-retention policy; organisational "
        "control outside firewall scope."
    ),
    "iso27001-a-7-personnel": (
        "A.7 Human resource security — personnel vetting and HR; not a "
        "firewall test."
    ),
    "iso27001-a-8-asset-mgmt": (
        "A.8 Asset management — inventory classification; not a firewall test."
    ),
    "iso27001-a-9-access-control": (
        "A.9 Access control — identity and authentication management; not "
        "directly tested by firewall scenarios."
    ),
    "iso27001-a-11-physical": (
        "A.11 Physical and environmental security — data-centre controls; "
        "not a firewall test."
    ),
    "owasp-tls-fingerprint": (
        "TLS fingerprint / protocol-downgrade evasion — requires a TLS-aware "
        "proxy; out of scope for a stateless/stateful packet firewall."
    ),
    "owasp-fragment-reassembly-dos": (
        "Fragment-reassembly DoS (Teardrop / Rose) — kernel handles "
        "reassembly before nftables; effect is on the host stack, not the "
        "ruleset.  Tracked as a separate open item."
    ),
}

__all__ = ["TEST_ID_FRAGMENT", "OUT_OF_SCOPE"]
