"""MAC address filtering.

Implements Shorewall's maclist feature — allows/denies traffic
based on source MAC address per interface.

Config: maclist file with FORMAT: DISPOSITION INTERFACE MAC [IP_ADDRESSES]
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import (
    FirewallIR,
    Match,
    Rule,
    Verdict,
)
from shorewall_nft.config.parser import ConfigLine


def process_maclist(ir: FirewallIR, maclist_lines: list[ConfigLine],
                    disposition: str = "REJECT") -> None:
    """Process MAC filter rules.

    Format: DISPOSITION INTERFACE MAC [IP_ADDRESSES]
    """
    if not maclist_lines:
        return

    for line in maclist_lines:
        cols = line.columns
        if len(cols) < 3:
            continue

        action = cols[0].upper()
        iface = cols[1]
        mac = cols[2]
        ip_addrs = cols[3] if len(cols) > 3 and cols[3] != "-" else None

        verdict = Verdict.ACCEPT if action == "ACCEPT" else Verdict.DROP

        # Add to input chain
        input_chain = ir.chains.get("input")
        if input_chain:
            rule = Rule(
                verdict=verdict,
                comment=f"maclist:{iface}",
            )
            rule.matches.append(Match(field="iifname", value=iface))
            rule.matches.append(Match(field="ether saddr", value=mac))
            if ip_addrs:
                rule.matches.append(Match(field="ip saddr", value=ip_addrs))
            input_chain.rules.append(rule)
