# SNMP OID constants and bundle tables for stagelab metrics collection.
from __future__ import annotations

# Core IF-MIB (RFC 2863)
IF_HC_IN_OCTETS  = "1.3.6.1.2.1.31.1.1.1.6"    # 64-bit RX bytes
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"   # 64-bit TX bytes
IF_IN_DISCARDS   = "1.3.6.1.2.1.2.2.1.13"
IF_OUT_DISCARDS  = "1.3.6.1.2.1.2.2.1.19"
IF_ALIAS         = "1.3.6.1.2.1.31.1.1.1.18"

# UCD-SNMP load (.1/.2/.3 = 1/5/15 min)
LA_LOAD          = "1.3.6.1.4.1.2021.10.1.3"

# System uptime (walk node; instance .0 is the only leaf — using the node OID
# because walk_cmd with a scalar .0 suffix returns no rows).
SYS_UPTIME       = "1.3.6.1.2.1.1.3"

# Keepalived VRRP (KEEPALIVED-MIB root .1.3.6.1.4.1.9586.100.5)
# int: 0=init 1=backup 2=master 3=fault
VRRP_INSTANCE_STATE = "1.3.6.1.4.1.9586.100.5.2.3.1.4"
VRRP_INSTANCE_NAME  = "1.3.6.1.4.1.9586.100.5.2.3.1.2"

# PowerDNS-Recursor via NET-SNMP-EXTEND-MIB
# Operator's pdns_recursor_stats.sh output under
# .1.3.6.1.4.1.8072.1.3.2.3.1.2.<extend-name>
PDNS_EXTEND_OUTPUT = "1.3.6.1.4.1.8072.1.3.2.3.1.2"

# Individual bundle lists (imported by name in S2+)
BUNDLE_NODE_TRAFFIC = [IF_HC_IN_OCTETS, IF_HC_OUT_OCTETS, IF_IN_DISCARDS, IF_OUT_DISCARDS]
BUNDLE_SYSTEM       = [LA_LOAD, SYS_UPTIME]
BUNDLE_VRRP         = [VRRP_INSTANCE_STATE, VRRP_INSTANCE_NAME]
BUNDLE_PDNS         = [PDNS_EXTEND_OUTPUT]

BUNDLES: dict[str, list[str]] = {
    "node_traffic": BUNDLE_NODE_TRAFFIC,
    "system":       BUNDLE_SYSTEM,
    "vrrp":         BUNDLE_VRRP,
    "pdns":         BUNDLE_PDNS,
}


def resolve_bundle(name: str) -> list[str]:
    """Return the OID list for bundle *name*; raise KeyError on unknown names."""
    try:
        return BUNDLES[name]
    except KeyError:
        valid = ", ".join(sorted(BUNDLES))
        raise KeyError(f"Unknown bundle {name!r}. Valid names: {valid}") from None
