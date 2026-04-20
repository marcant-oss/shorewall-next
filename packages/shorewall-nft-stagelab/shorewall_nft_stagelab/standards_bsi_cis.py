"""TEST_ID fragment for BSI IT-Grundschutz + CIS Benchmarks.

BSI IT-Grundschutz controls referenced here:
  NET.3.2  Firewall (A2, A4, A5, A6, A7, A9, A10, A12)
  NET.1.1  Netzarchitektur (A1)
  OPS.1.2.5 Protokollierung

CIS controls referenced here are from the CIS Distribution Independent Linux
Benchmark v2.0 (https://www.cisecurity.org/benchmark/distribution_independent_linux).
The firewall-relevant items are in Section 5 (Access, Authentication and
Authorization -> Firewall Configuration).  CIS does not publish a dedicated
standalone "Firewall Benchmark"; all firewall items appear within the
Linux benchmark under Section 5.2, 5.3, and 5.4.

Import this module and merge TEST_ID_FRAGMENT into the central standards.TEST_ID
dict (done by standards_loader.py, assembled by the M1 merger agent).
"""
from __future__ import annotations

# Each entry: test_id -> (standard, control, title)
# standard must be one of: "bsi-grundschutz", "cis-benchmarks"
TEST_ID_FRAGMENT: dict[str, tuple[str, str, str]] = {
    # -------------------------------------------------------------------------
    # BSI IT-Grundschutz
    # -------------------------------------------------------------------------
    "bsi-net-3-2-a2-function-separation": (
        "bsi-grundschutz",
        "NET.3.2.A2",
        "Separation of firewall functions",
    ),
    "bsi-net-3-2-a4-rule-documentation": (
        "bsi-grundschutz",
        "NET.3.2.A4",
        "Rule documentation and review",
    ),
    "bsi-net-3-2-a5-dos-protection": (
        "bsi-grundschutz",
        "NET.3.2.A5",
        "DoS protection",
    ),
    "bsi-net-3-2-a6-connection-state": (
        "bsi-grundschutz",
        "NET.3.2.A6",
        "Connection state tracking",
    ),
    "bsi-net-3-2-a7-protocol-validation": (
        "bsi-grundschutz",
        "NET.3.2.A7",
        "Protocol validation and evasion resistance",
    ),
    "bsi-net-3-2-a9-time-sync": (
        "bsi-grundschutz",
        "NET.3.2.A9",
        "Time synchronization (NTP) — out of scope",
    ),
    "bsi-net-3-2-a10-logging": (
        "bsi-grundschutz",
        "NET.3.2.A10",
        "Logging and audit trail",
    ),
    "bsi-net-3-2-a12-redundancy-ha": (
        "bsi-grundschutz",
        "NET.3.2.A12",
        "Redundancy and high availability",
    ),
    "bsi-net-1-1-a1-arch-doc": (
        "bsi-grundschutz",
        "NET.1.1.A1",
        "Network architecture documentation — out of scope",
    ),
    "bsi-ops-1-2-5-log-retention": (
        "bsi-grundschutz",
        "OPS.1.2.5",
        "Log retention and integrity",
    ),
    # -------------------------------------------------------------------------
    # CIS Distribution Independent Linux v2.0 — Section 5
    # -------------------------------------------------------------------------
    "cis-5-2-1-firewall-default-deny-ingress": (
        "cis-benchmarks",
        "5.2.1",
        "Default-deny ingress from WAN",
    ),
    "cis-5-2-2-firewall-default-deny-egress": (
        "cis-benchmarks",
        "5.2.2",
        "Default-deny egress (outbound) policy",
    ),
    "cis-5-3-loopback-rules": (
        "cis-benchmarks",
        "5.3",
        "Loopback interface rules — out of scope (system hardening, not firewall-config testing)",
    ),
    "cis-5-4-1-established-traffic": (
        "cis-benchmarks",
        "5.4.1",
        "Accept outbound and established/related connections",
    ),
    "cis-5-4-2-outbound-rules-coverage": (
        "cis-benchmarks",
        "5.4.2",
        "Outbound rules coverage matrix",
    ),
    "cis-3-5-uncommon-protocols": (
        "cis-benchmarks",
        "3.5",
        "Uncommon network protocols disabled (DCCP/SCTP) — out of scope (kernel config)",
    ),
    "cis-3-x-network-params": (
        "cis-benchmarks",
        "3.x",
        "Network kernel parameters (ip_forward, send_redirects) — out of scope (sysctl)",
    ),
    "cis-5-2-3-open-ports-inventory": (
        "cis-benchmarks",
        "5.2.3",
        "Open listening ports match expected rule set",
    ),
    "cis-5-2-4-ingress-rfc1918-from-wan": (
        "cis-benchmarks",
        "5.2.4",
        "RFC-1918 source addresses blocked from WAN ingress",
    ),
    "cis-5-2-5-ingress-bogon-block": (
        "cis-benchmarks",
        "5.2.5",
        "Bogon/martian source address block on WAN ingress",
    ),
}

__all__ = ["TEST_ID_FRAGMENT"]
