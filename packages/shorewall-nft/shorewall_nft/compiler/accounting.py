"""Accounting rule processing.

Handles the Shorewall accounting config file which creates
packet/byte counters per rule for traffic analysis.

Accounting config format:
  ACTION CHAIN SOURCE DEST PROTO DPORT SPORT USER MARK IPSEC

Sections: ?SECTION INPUT/OUTPUT/FORWARD (or PREROUTING/POSTROUTING)

Actions:
  COUNT        - Count packets/bytes (nft: counter)
  DONE         - Stop processing accounting chain
  ACCOUNT(t,n) - Per-IP accounting (nft: counter per element)
  NFACCT(obj)  - Named kernel counter (nft: named counter object)
  chain_name   - Jump to custom accounting chain
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
    Match,
    Rule,
    Verdict,
)
from shorewall_nft.config.parser import ConfigLine


def process_accounting(ir: FirewallIR, acct_lines: list[ConfigLine]) -> None:
    """Process accounting rules into nft counter chains."""
    if not acct_lines:
        return

    # Default accounting chains per section
    section_chains = {
        "INPUT": "acct-input",
        "OUTPUT": "acct-output",
        "FORWARD": "acct-forward",
        "PREROUTING": "acct-prerouting",
        "POSTROUTING": "acct-postrouting",
    }

    # Create base accounting chains
    section_hooks = {
        "INPUT": (Hook.INPUT, 1),
        "OUTPUT": (Hook.OUTPUT, 1),
        "FORWARD": (Hook.FORWARD, 1),
        "PREROUTING": (Hook.PREROUTING, 1),
        "POSTROUTING": (Hook.POSTROUTING, 1),
    }

    current_section = "INPUT"

    for line in acct_lines:
        cols = line.columns
        if not cols:
            continue

        # Track section
        if line.section:
            current_section = line.section.upper()

        action = cols[0]
        chain_name_col = cols[1] if len(cols) > 1 and cols[1] != "-" else None
        source = cols[2] if len(cols) > 2 and cols[2] != "-" else None
        dest = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        proto = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        dport = cols[5] if len(cols) > 5 and cols[5] != "-" else None
        sport = cols[6] if len(cols) > 6 and cols[6] != "-" else None

        # Determine target chain
        target_chain_name = chain_name_col or section_chains.get(
            current_section, "acct-forward")

        # Create chain if needed
        if target_chain_name not in ir.chains:
            hook_info = section_hooks.get(current_section)
            if hook_info and target_chain_name == section_chains.get(current_section):
                hook, prio = hook_info
                ir.add_chain(Chain(
                    name=target_chain_name,
                    chain_type=ChainType.FILTER,
                    hook=hook,
                    priority=prio,  # After main filter chains
                ))
            else:
                ir.add_chain(Chain(name=target_chain_name))

        chain = ir.chains[target_chain_name]

        # Build rule
        rule = Rule(
            source_file=line.file,
            source_line=line.lineno,
            counter=True,  # All accounting rules have counters
        )

        # Matches
        if source:
            rule.matches.append(Match(field="ip saddr", value=source))
        if dest:
            rule.matches.append(Match(field="ip daddr", value=dest))
        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if dport:
                rule.matches.append(Match(field=f"{proto} dport", value=dport))
            if sport:
                rule.matches.append(Match(field=f"{proto} sport", value=sport))

        # Action
        if action == "COUNT":
            rule.verdict = Verdict.ACCEPT
            rule.verdict_args = "counter:"
        elif action == "DONE":
            rule.verdict = Verdict.RETURN
        elif action.startswith("NFACCT("):
            obj_name = action[7:].rstrip(")")
            rule.verdict = Verdict.ACCEPT
            rule.verdict_args = f"named_counter:{obj_name}"
        elif action.startswith("ACCOUNT("):
            params = action[8:].rstrip(")")
            rule.verdict = Verdict.ACCEPT
            rule.verdict_args = f"account:{params}"
        elif action == "NFLOG":
            rule.verdict = Verdict.ACCEPT
            rule.verdict_args = "nflog:"
        else:
            # Jump to named chain
            rule.verdict = Verdict.JUMP
            rule.verdict_args = action

        chain.rules.append(rule)
