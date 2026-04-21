"""NAT rule processing: SNAT (masq), DNAT, Masquerade.

Translates Shorewall masq config and DNAT rules into
nft nat chain rules.
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
    _expand_line_for_tokens,
    _has_set_token,
)
from shorewall_nft.config.parser import ConfigLine


def process_nat(ir: FirewallIR, masq_lines: list[ConfigLine],
                dnat_rules: list[ConfigLine]) -> None:
    """Process NAT rules into the IR."""
    # Create nat base chains if we have any NAT rules
    if masq_lines or dnat_rules:
        _ensure_nat_chains(ir)

    # Process masq (SNAT) rules
    for line in masq_lines:
        _process_masq_line(ir, line)

    # Process DNAT rules (extracted from rules file)
    for line in dnat_rules:
        _process_dnat_line(ir, line)


def _ensure_nat_chains(ir: FirewallIR) -> None:
    """Create nat base chains if they don't exist."""
    if "prerouting" not in ir.chains:
        ir.add_chain(Chain(
            name="prerouting",
            chain_type=ChainType.NAT,
            hook=Hook.PREROUTING,
            priority=-100,
        ))
    if "postrouting" not in ir.chains:
        ir.add_chain(Chain(
            name="postrouting",
            chain_type=ChainType.NAT,
            hook=Hook.POSTROUTING,
            priority=100,
        ))


def _process_masq_line(ir: FirewallIR, line: ConfigLine) -> None:
    """Process a masq (SNAT/Masquerade) line.

    Format: INTERFACE[:dest_addr] SOURCE ADDRESS [PROTO] [PORT(S)]
    Examples:
        bond1            192.0.2.35  198.51.100.34
        bond1::198.51.100.21,198.51.100.193  192.0.2.35  198.51.100.34
        bond1::198.51.100.107  192.0.2.200  203.0.113.100  tcp  443

    SOURCE (col 1) accepts nfset:/dns:/dnsr: tokens.
    ADDRESS (col 2) is a single SNAT target IP/range and MUST NOT carry
    set tokens — raise ValueError if one is found.
    """
    cols = line.columns
    if len(cols) < 3:
        return

    # Reject set tokens in the ADDRESS column (SNAT target).
    snat_addr_raw = cols[2]
    if _has_set_token(snat_addr_raw):
        raise ValueError(
            f"masq {line.file}:{line.lineno}: ADDRESS column (SNAT target) "
            f"does not accept nfset:/dns:/dnsr: tokens — got {snat_addr_raw!r}. "
            f"Use a literal IP address or CIDR instead."
        )

    # nfset/dns/dnsr token pre-pass on SOURCE (col 1) only.
    found, expanded = _expand_line_for_tokens(line, 1, None, ir)
    if found:
        for exp_line in expanded:
            _process_masq_line(ir, exp_line)
        return

    iface_spec = cols[0]
    source = cols[1]
    snat_addr = cols[2]
    proto = cols[3] if len(cols) > 3 else None
    ports = cols[4] if len(cols) > 4 else None

    if proto == "-":
        proto = None
    if ports == "-":
        ports = None

    # Parse interface spec: IFACE or IFACE::DEST_ADDRS
    iface = iface_spec
    orig_dest = None
    if "::" in iface_spec:
        iface, orig_dest = iface_spec.split("::", 1)
    elif ":" in iface_spec:
        parts = iface_spec.split(":", 1)
        iface = parts[0]
        if parts[1]:
            orig_dest = parts[1]

    chain = ir.chains["postrouting"]
    rule = Rule(
        verdict=Verdict.ACCEPT,  # placeholder, emitter handles snat specially
        verdict_args=f"snat:{snat_addr}",
        source_file=line.file,
        source_line=line.lineno,
        comment=line.comment_tag,
    )

    # Output interface match
    if iface and iface != "-":
        rule.matches.append(Match(field="oifname", value=iface))

    # Source address match
    if source and source != "-":
        rule.matches.append(Match(field="ip saddr", value=source))

    # Original destination (for selective SNAT)
    if orig_dest and orig_dest != "-":
        rule.matches.append(Match(field="ip daddr", value=orig_dest))

    # Protocol and port
    if proto:
        rule.matches.append(Match(field="meta l4proto", value=proto))
        if ports:
            rule.matches.append(Match(field=f"{proto} dport", value=ports))

    chain.rules.append(rule)


def _process_dnat_line(ir: FirewallIR, line: ConfigLine) -> None:
    """Process a DNAT rule from the rules file.

    Format: DNAT SOURCE DEST:IP[:PORT] PROTO DPORT [SPORT] [ORIG_DEST]
    Examples:
        DNAT  net  host:203.0.113.38:3389  tcp  13389  -  203.0.113.38
        DNAT  all  loc:192.0.2.201          tcp  80,443 -  203.0.113.100

    SOURCE (col 1) accepts nfset:/dns:/dnsr: tokens.
    DEST (col 2) is a zone:ip[:port] DNAT target and MUST NOT carry set
    tokens — raise ValueError if one is found.
    """
    cols = line.columns
    if len(cols) < 4:
        return

    # Reject set tokens in the DEST column (DNAT target).
    dest_spec_raw = cols[2] if len(cols) > 2 else "-"
    if _has_set_token(dest_spec_raw):
        raise ValueError(
            f"dnat {line.file}:{line.lineno}: DEST column (DNAT target) "
            f"does not accept nfset:/dns:/dnsr: tokens — got {dest_spec_raw!r}. "
            f"Use a literal zone:ip[:port] target instead."
        )

    # nfset/dns/dnsr token pre-pass on SOURCE (col 1) only.
    found, expanded = _expand_line_for_tokens(line, 1, None, ir)
    if found:
        for exp_line in expanded:
            _process_dnat_line(ir, exp_line)
        return

    source_spec = cols[1] if len(cols) > 1 else "all"
    dest_spec = cols[2] if len(cols) > 2 else "-"
    proto = cols[3] if len(cols) > 3 else None
    dport = cols[4] if len(cols) > 4 else None
    sport = cols[5] if len(cols) > 5 else None
    orig_dest = cols[6] if len(cols) > 6 else None

    if proto == "-":
        proto = None
    if dport == "-":
        dport = None
    if sport == "-":
        sport = None
    if orig_dest == "-":
        orig_dest = None

    # Parse destination: zone:ip or zone:ip:port
    dest_zone = None
    dest_ip = None
    dest_port = None
    if dest_spec and dest_spec != "-":
        parts = dest_spec.split(":")
        dest_zone = parts[0]
        if len(parts) > 1:
            dest_ip = parts[1]
        if len(parts) > 2:
            dest_port = parts[2]

    # Parse source zone.  A rewritten set-reference sentinel starts with
    # '+' (e.g. ``+nfset_allowed_v4``) and contains no zone prefix — use
    # it directly as the saddr match value.
    src_zone = None
    src_addr = None
    if source_spec and source_spec != "-":
        if source_spec.startswith("+") or source_spec.startswith("!+"):
            # Pre-rewritten set sentinel — use as address directly.
            src_addr = source_spec
        elif ":" in source_spec:
            src_zone, src_addr = source_spec.split(":", 1)
        else:
            src_zone = source_spec

    chain = ir.chains["prerouting"]
    dnat_target = dest_ip or ""
    if dest_port:
        dnat_target += f":{dest_port}"

    rule = Rule(
        verdict=Verdict.ACCEPT,  # placeholder
        verdict_args=f"dnat:{dnat_target}",
        source_file=line.file,
        source_line=line.lineno,
        comment=line.comment_tag,
    )

    # Source address
    if src_addr:
        rule.matches.append(Match(field="ip saddr", value=src_addr))

    # Original destination (the external IP being accessed)
    if orig_dest:
        rule.matches.append(Match(field="ip daddr", value=orig_dest))

    # Protocol and port
    if proto:
        rule.matches.append(Match(field="meta l4proto", value=proto))
        if dport:
            rule.matches.append(Match(field=f"{proto} dport", value=dport))

    chain.rules.append(rule)


def process_netmap(ir: FirewallIR, netmap_lines: list[ConfigLine]) -> None:
    """Process netmap (bidirectional NAT) rules.

    Format: TYPE NET1 INTERFACE NET2 [PROTO] [DEST PORT]
    """
    if not netmap_lines:
        return

    _ensure_nat_chains(ir)

    for line in netmap_lines:
        cols = line.columns
        if len(cols) < 4:
            continue

        map_type = cols[0].upper()  # DNAT, SNAT, or MAP
        net1 = cols[1]
        iface = cols[2]
        net2 = cols[3]
        proto = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        dport = cols[5] if len(cols) > 5 and cols[5] != "-" else None

        if map_type in ("DNAT", "MAP"):
            chain = ir.chains["prerouting"]
            rule = Rule(
                verdict=Verdict.ACCEPT,
                verdict_args=f"dnat:{net2}",
                source_file=line.file,
                source_line=line.lineno,
            )
            rule.matches.append(Match(field="ip daddr", value=net1))
            if iface != "-":
                rule.matches.append(Match(field="iifname", value=iface))
            if proto:
                rule.matches.append(Match(field="meta l4proto", value=proto))
                if dport:
                    rule.matches.append(Match(field=f"{proto} dport", value=dport))
            chain.rules.append(rule)

        if map_type in ("SNAT", "MAP"):
            chain = ir.chains["postrouting"]
            rule = Rule(
                verdict=Verdict.ACCEPT,
                verdict_args=f"snat:{net1}",
                source_file=line.file,
                source_line=line.lineno,
            )
            rule.matches.append(Match(field="ip saddr", value=net2))
            if iface != "-":
                rule.matches.append(Match(field="oifname", value=iface))
            if proto:
                rule.matches.append(Match(field="meta l4proto", value=proto))
            chain.rules.append(rule)


def extract_nat_rules(rules: list[ConfigLine]) -> tuple[list[ConfigLine], list[ConfigLine]]:
    """Separate DNAT/REDIRECT rules from regular rules.

    Returns (nat_rules, remaining_rules).
    """
    nat_rules = []
    remaining = []

    for line in rules:
        if not line.columns:
            remaining.append(line)
            continue

        action = line.columns[0].upper()
        # Strip log level: DNAT:info -> DNAT
        base_action = action.split(":")[0]

        if base_action in ("DNAT", "REDIRECT"):
            nat_rules.append(line)
        else:
            remaining.append(line)

    return nat_rules, remaining
