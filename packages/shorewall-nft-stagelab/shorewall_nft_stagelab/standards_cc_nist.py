"""TEST_ID fragment for Common Criteria (ISO 15408) + NIST SP 800-53.

Merged into standards.TEST_ID by the M1 merger. Each entry is a 3-tuple
(standard, control, title) matching the StandardRef shape in standards.py.
"""
from __future__ import annotations

TEST_ID_FRAGMENT: dict[str, tuple[str, str, str]] = {
    # -----------------------------------------------------------------------
    # Common Criteria (ISO/IEC 15408) — Network Device / Firewall PP (NDcPP
    # v3.0 / FWcPP) relevant Security Functional Requirements (SFRs)
    # -----------------------------------------------------------------------

    # FDP_IFF.1 — Subset information flow control
    "cc-fdp-iff-1-basic-flow": (
        "cc-iso-15408",
        "FDP_IFF.1",
        "Basic information flow control (zone-pair policies)",
    ),
    "cc-fdp-iff-1-basic-flow-ipv6": (
        "cc-iso-15408",
        "FDP_IFF.1",
        "Basic information flow control — IPv6 (zone-pair policies, dual-stack)",
    ),
    "cc-fdp-iff-1-default-deny": (
        "cc-iso-15408",
        "FDP_IFF.1.5",
        "Default deny on undefined zone pairs",
    ),
    "cc-fdp-iff-1-evasion-reject": (
        "cc-iso-15408",
        "FDP_IFF.1",
        "Reject evasion probes (malformed TCP flags, spoofed IPs, fragmentation)",
    ),
    "cc-fdp-iff-1-evasion-reject-ipv6": (
        "cc-iso-15408",
        "FDP_IFF.1",
        "Reject evasion probes — IPv6 (extension headers, fragmentation, malformed ICMPv6)",
    ),

    # FAU_GEN.1 — Audit data generation (PARTIAL — Prometheus counters only)
    "cc-fau-gen-1-audit-record": (
        "cc-iso-15408",
        "FAU_GEN.1",
        "Audit record generation (per-rule Prometheus counters — partial, no per-packet syslog)",
    ),

    # FRU_RSA.1 — Minimum resource allocation under load
    "cc-fru-rsa-1-conn-storm": (
        "cc-iso-15408",
        "FRU_RSA.1",
        "Minimum resource allocation under high connection-rate load",
    ),
    "cc-fru-rsa-1-conn-storm-ipv6": (
        "cc-iso-15408",
        "FRU_RSA.1",
        "Minimum resource allocation under high IPv6 connection-rate load",
    ),
    "cc-fru-rsa-1-dos-syn-flood": (
        "cc-iso-15408",
        "FRU_RSA.1",
        "Minimum resource allocation under SYN-flood DoS",
    ),
    "cc-fru-rsa-1-dos-conntrack": (
        "cc-iso-15408",
        "FRU_RSA.1",
        "Minimum resource allocation under conntrack saturation DoS",
    ),

    # FMT_MSA.3 — Static attribute initialisation
    "cc-fmt-msa-3-default-values": (
        "cc-iso-15408",
        "FMT_MSA.3",
        "Restrictive default attribute values (default-deny, compile-time config check)",
    ),

    # FPT_FLS.1 — Failure with preservation of secure state
    "cc-fpt-fls-1-reload-atomicity": (
        "cc-iso-15408",
        "FPT_FLS.1",
        "Preserve secure state during ruleset reload (atomic reload, no connection disruption)",
    ),

    # FPT_RCV.3 — Automated recovery
    "cc-fpt-rcv-3-ha-failover": (
        "cc-iso-15408",
        "FPT_RCV.3",
        "Automated recovery via HA failover drill (VRRP)",
    ),

    # FTA_SSL.3 — TSF-initiated termination (long-flow conntrack timeout)
    "cc-fta-ssl-3-long-flow-survival": (
        "cc-iso-15408",
        "FTA_SSL.3",
        "Established-flow survival under conntrack timeout constraints",
    ),

    # FCS_* are explicitly out of scope — no entries.

    # -----------------------------------------------------------------------
    # NIST SP 800-53 rev 5 — Information System Security Controls
    # -----------------------------------------------------------------------

    # AC-4 — Information flow enforcement
    "nist-ac-4-info-flow": (
        "nist-800-53",
        "AC-4",
        "Information flow enforcement (zone-pair policy scan)",
    ),
    "nist-ac-4-info-flow-ipv6": (
        "nist-800-53",
        "AC-4",
        "Information flow enforcement — IPv6 (dual-stack zone-pair policy scan)",
    ),
    "nist-ac-4-boundary-coverage": (
        "nist-800-53",
        "AC-4",
        "Information flow enforcement — boundary coverage matrix",
    ),

    # SC-5 — Denial-of-service protection
    "nist-sc-5-dos-syn": (
        "nist-800-53",
        "SC-5",
        "Resistance to SYN-flood DoS",
    ),
    "nist-sc-5-dos-conntrack": (
        "nist-800-53",
        "SC-5",
        "Resistance to conntrack saturation DoS (conn_storm)",
    ),
    "nist-sc-5-dos-conntrack-overflow": (
        "nist-800-53",
        "SC-5",
        "Resistance to conntrack table overflow (conntrack_overflow scenario)",
    ),
    "nist-sc-5-dos-dns": (
        "nist-800-53",
        "SC-5",
        "Resistance to DNS query-rate DoS",
    ),
    "nist-sc-5-dos-half-open": (
        "nist-800-53",
        "SC-5",
        "Resistance to half-open TCP connection exhaustion",
    ),

    # SC-7 — Boundary protection
    "nist-sc-7-boundary-throughput": (
        "nist-800-53",
        "SC-7",
        "Boundary protection — sustained throughput under load",
    ),
    "nist-sc-7-boundary-throughput-ipv6": (
        "nist-800-53",
        "SC-7",
        "Boundary protection — sustained IPv6 throughput under load",
    ),
    "nist-sc-7-boundary-evasion": (
        "nist-800-53",
        "SC-7",
        "Boundary protection — evasion probe rejection",
    ),
    "nist-sc-7-boundary-evasion-ipv6": (
        "nist-800-53",
        "SC-7",
        "Boundary protection — IPv6 evasion probe rejection",
    ),
    "nist-sc-7-flowtable-offload": (
        "nist-800-53",
        "SC-7",
        "Boundary protection — nft flowtable hardware offload verification",
    ),

    # AU-2 / AU-12 — Audit events (PARTIAL — Prometheus counters only)
    "nist-au-2-audit-events": (
        "nist-800-53",
        "AU-2",
        "Audit events (per-rule counters via Prometheus — partial, no per-packet syslog)",
    ),
    "nist-au-12-audit-generation": (
        "nist-800-53",
        "AU-12",
        "Audit record generation (shorewalld Prometheus scrape — partial)",
    ),

    # SI-4 — System monitoring
    "nist-si-4-monitoring": (
        "nist-800-53",
        "SI-4",
        "System monitoring via shorewalld Prometheus exporter (nft counters, conntrack)",
    ),

    # SC-5(3) — Reload continuity (FW service availability)
    "nist-sc-5-reload-atomicity": (
        "nist-800-53",
        "SC-5(3)",
        "Service availability during ruleset reload (atomic reload drill)",
    ),

    # SC-7(18) — HA failover continuity
    "nist-sc-7-ha-failover": (
        "nist-800-53",
        "SC-7(18)",
        "Boundary protection — HA failover continuity (VRRP drill)",
    ),
}

__all__ = ["TEST_ID_FRAGMENT"]
