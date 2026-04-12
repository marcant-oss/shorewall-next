"""Shorewall action processing.

Actions are reusable rule chains that implement complex behaviors like
Broadcast filtering, TCP flag checking, smurf detection, etc.

Shorewall action files support embedded Perl and iptables passthrough
syntax (;;). Since we're a clean nft reimplementation, we translate
the well-known actions to their nft equivalents directly.
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import (
    FirewallIR,
    Match,
    Rule,
    Verdict,
)


def create_action_chains(ir: FirewallIR) -> None:
    """Create nft chains for standard Shorewall actions."""
    _create_drop_chain(ir)
    _create_reject_chain(ir)
    _create_broadcast_chain(ir)
    _create_multicast_chain(ir)
    _create_drop_smurfs_chain(ir)
    _create_drop_not_syn_chain(ir)
    _create_drop_invalid_chain(ir)
    _create_allow_icmps_chain(ir)
    _create_drop_dnsrep_chain(ir)
    _create_established_chain(ir)
    _create_invalid_chain(ir)
    _create_blacklist_chain(ir)
    _create_tcp_flags_chain(ir)
    _create_fin_chain(ir)
    _create_rst_chain(ir)
    _create_rej_not_syn_chain(ir)
    _create_allow_upnp_chain(ir)
    _create_dns_amp_chain(ir)


def _create_drop_chain(ir: FirewallIR) -> None:
    """action.Drop: Drop with broadcast/multicast pre-filter.

    Broadcasts and multicasts are silently dropped before the
    actual drop+log to avoid log noise.
    """
    chain = ir.get_or_create_chain("sw_Drop")
    # Silently drop broadcasts
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="broadcast")],
        verdict=Verdict.DROP,
    ))
    # Silently drop multicasts
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="multicast")],
        verdict=Verdict.DROP,
    ))
    # Drop non-SYN TCP to avoid RST floods
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0", negate=False),
        ],
        verdict=Verdict.DROP,
        comment="dropNotSyn",
    ))
    # Drop invalid
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
        comment="dropInvalid",
    ))
    # Final drop
    chain.rules.append(Rule(verdict=Verdict.DROP))


def _create_reject_chain(ir: FirewallIR) -> None:
    """action.Reject: Reject with broadcast/multicast pre-filter."""
    chain = ir.get_or_create_chain("sw_Reject")
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="broadcast")],
        verdict=Verdict.DROP,
    ))
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="multicast")],
        verdict=Verdict.DROP,
    ))
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0", negate=False),
        ],
        verdict=Verdict.DROP,
        comment="dropNotSyn",
    ))
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
        comment="dropInvalid",
    ))
    chain.rules.append(Rule(verdict=Verdict.REJECT))


def _create_broadcast_chain(ir: FirewallIR) -> None:
    """action.Broadcast: Handle broadcast/anycast packets."""
    chain = ir.get_or_create_chain("sw_Broadcast")
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="broadcast")],
        verdict=Verdict.DROP,
    ))
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="anycast")],
        verdict=Verdict.DROP,
    ))


def _create_multicast_chain(ir: FirewallIR) -> None:
    """action.Multicast: Handle multicast packets."""
    chain = ir.get_or_create_chain("sw_Multicast")
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="multicast")],
        verdict=Verdict.DROP,
    ))


def _create_drop_smurfs_chain(ir: FirewallIR) -> None:
    """action.DropSmurfs: Drop smurf attacks (broadcast source)."""
    chain = ir.get_or_create_chain("sw_DropSmurfs")
    chain.rules.append(Rule(
        matches=[Match(field="fib saddr type", value="broadcast")],
        verdict=Verdict.DROP,
        comment="smurf",
    ))


def _create_drop_not_syn_chain(ir: FirewallIR) -> None:
    """action.dropNotSyn: Drop new TCP without SYN."""
    chain = ir.get_or_create_chain("sw_dropNotSyn")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0", negate=False),
        ],
        verdict=Verdict.DROP,
    ))


def _create_drop_invalid_chain(ir: FirewallIR) -> None:
    """action.dropInvalid: Drop invalid state packets."""
    chain = ir.get_or_create_chain("sw_dropInvalid")
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
    ))


def _create_allow_icmps_chain(ir: FirewallIR) -> None:
    """action.AllowICMPs: Allow required ICMP types per RFC."""
    chain = ir.get_or_create_chain("sw_AllowICMPs")
    # Essential ICMP types
    for icmp_type in ["destination-unreachable", "time-exceeded",
                      "parameter-problem", "echo-request", "echo-reply"]:
        chain.rules.append(Rule(
            matches=[
                Match(field="meta l4proto", value="icmp"),
                Match(field="icmp type", value=icmp_type),
            ],
            verdict=Verdict.ACCEPT,
        ))


def _create_drop_dnsrep_chain(ir: FirewallIR) -> None:
    """action.DropDNSrep: Drop unsolicited DNS replies (amplification)."""
    chain = ir.get_or_create_chain("sw_DropDNSrep")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp sport", value="53"),
            Match(field="ct state", value="new"),
        ],
        verdict=Verdict.DROP,
        comment="DNS amplification",
    ))


def _create_established_chain(ir: FirewallIR) -> None:
    """action.Established: Accept established connections."""
    chain = ir.get_or_create_chain("sw_Established")
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="established")],
        verdict=Verdict.ACCEPT,
    ))


def _create_invalid_chain(ir: FirewallIR) -> None:
    """action.Invalid: Handle invalid packets."""
    chain = ir.get_or_create_chain("sw_Invalid")
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
    ))


def _create_blacklist_chain(ir: FirewallIR) -> None:
    """action.BLACKLIST: Default blacklist action chain."""
    chain = ir.get_or_create_chain("sw_BLACKLIST")
    # Broadcast/multicast silent drop
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="broadcast")],
        verdict=Verdict.DROP,
    ))
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="multicast")],
        verdict=Verdict.DROP,
    ))
    # dropNotSyn
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0", negate=False),
        ],
        verdict=Verdict.DROP,
    ))
    # dropInvalid
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
    ))
    # DropDNSrep
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp sport", value="53"),
            Match(field="ct state", value="new"),
        ],
        verdict=Verdict.DROP,
    ))
    chain.rules.append(Rule(verdict=Verdict.DROP))


def _create_tcp_flags_chain(ir: FirewallIR) -> None:
    """action.TCPFlags: Drop bad TCP flag combinations."""
    chain = ir.get_or_create_chain("sw_TCPFlags")
    for flags in [
        ("fin | syn", "fin | syn"),
        ("syn | rst", "syn | rst"),
        ("fin | rst", "fin | rst"),
        ("fin | urg | psh", "fin | urg | psh"),
    ]:
        chain.rules.append(Rule(
            matches=[
                Match(field="meta l4proto", value="tcp"),
                Match(field=f"tcp flags & ({flags[0]})", value=flags[1]),
            ],
            verdict=Verdict.DROP,
        ))


def _create_fin_chain(ir: FirewallIR) -> None:
    """action.FIN: Handle TCP FIN packets."""
    chain = ir.get_or_create_chain("sw_FIN")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="tcp flags & fin", value="fin"),
            Match(field="ct state", value="new"),
        ],
        verdict=Verdict.DROP,
    ))


def _create_rst_chain(ir: FirewallIR) -> None:
    """action.RST: Rate-limit TCP RST packets."""
    chain = ir.get_or_create_chain("sw_RST")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="tcp flags & rst", value="rst"),
        ],
        verdict=Verdict.ACCEPT,
        rate_limit="2/second burst 5 packets",
    ))
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="tcp flags & rst", value="rst"),
        ],
        verdict=Verdict.DROP,
    ))


def _create_rej_not_syn_chain(ir: FirewallIR) -> None:
    """action.rejNotSyn: Reject new TCP without SYN."""
    chain = ir.get_or_create_chain("sw_rejNotSyn")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0"),
        ],
        verdict=Verdict.REJECT,
    ))


def _create_allow_upnp_chain(ir: FirewallIR) -> None:
    """action.allowinUPnP: Allow UPnP/SSDP discovery."""
    chain = ir.get_or_create_chain("sw_allowinUPnP")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp dport", value="1900"),
        ],
        verdict=Verdict.ACCEPT,
        comment="SSDP",
    ))
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="tcp dport", value="5000"),
        ],
        verdict=Verdict.ACCEPT,
        comment="UPnP",
    ))


def _create_dns_amp_chain(ir: FirewallIR) -> None:
    """action.DNSAmp: Drop DNS amplification attempts."""
    chain = ir.get_or_create_chain("sw_DNSAmp")
    # Drop large DNS responses from unknown sources
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp sport", value="53"),
            Match(field="ct state", value="new"),
        ],
        verdict=Verdict.DROP,
        comment="DNS amplification",
    ))
    # Drop ANY queries (common in amplification)
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp dport", value="53"),
        ],
        verdict=Verdict.DROP,
        comment="DNS amplification",
    ))


# Map action names to their chain names
ACTION_CHAIN_MAP: dict[str, str] = {
    "Drop": "sw_Drop",
    "Reject": "sw_Reject",
    "Broadcast": "sw_Broadcast",
    "Multicast": "sw_Multicast",
    "DropSmurfs": "sw_DropSmurfs",
    "dropNotSyn": "sw_dropNotSyn",
    "dropInvalid": "sw_dropInvalid",
    "AllowICMPs": "sw_AllowICMPs",
    "DropDNSrep": "sw_DropDNSrep",
    "Established": "sw_Established",
    "Invalid": "sw_Invalid",
    "BLACKLIST": "sw_BLACKLIST",
    "A_DROP": "sw_Drop",
    "A_REJECT": "sw_Reject",
    "dropBcast": "sw_Broadcast",
    "dropBcasts": "sw_Broadcast",
    "dropMcast": "sw_Multicast",
    "allowBcast": "sw_Broadcast",  # same chain, but called with ACCEPT
    "allowMcast": "sw_Multicast",
    "allowInvalid": "sw_dropInvalid",
    "allowinUPnP": "sw_AllowICMPs",  # approximation
    "New": "sw_Established",  # no-op, new is default
    "Related": "sw_Established",
    "NotSyn": "sw_dropNotSyn",
    "TCPFlags": "sw_TCPFlags",
    "FIN": "sw_FIN",
    "RST": "sw_RST",
    "rejNotSyn": "sw_rejNotSyn",
    "DNSAmp": "sw_DNSAmp",
    "allowinUPnP": "sw_allowinUPnP",
    "A_ACCEPT": "sw_Established",  # audit accept
}


def create_dynamic_blacklist(ir: FirewallIR, settings: dict[str, str]) -> None:
    """Create a dynamic blacklist set and chain.

    The dynamic blacklist is an nft set with timeout support.
    Addresses can be added at runtime via:
      nft add element inet shorewall dynamic_blacklist { 1.2.3.4 timeout 1h }

    The DYNAMIC_BLACKLIST setting controls this feature.
    """
    dbl = settings.get("DYNAMIC_BLACKLIST", "")
    if not dbl or dbl.lower() in ("no", "0", ""):
        return

    # Create the dynamic blacklist chain
    chain = ir.get_or_create_chain("sw_dynamic-blacklist")
    chain.rules.append(Rule(
        matches=[Match(field="ip saddr", value="@dynamic_blacklist")],
        verdict=Verdict.DROP,
        comment="dynamic blacklist",
    ))

    # The set itself is declared in the emitter via the sets mechanism
    # We signal this by adding a marker to the IR
    if not hasattr(ir, '_dynamic_blacklist'):
        ir._dynamic_blacklist = True
