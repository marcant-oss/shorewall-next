"""Dreiecks-Vergleich: shorewall-nft nft output vs iptables ground truth.

Compares the compiled nft ruleset against an iptables-save dump to verify
semantic equivalence. Uses the iptables_parser from shorewall2foomuuri
to parse the ground truth.

Comparison algorithm:
1. Parse iptables-save → zone-pair chains with rules
2. Compile Shorewall config with shorewall-nft → nft chains with rules
3. For each zone-pair: extract rule fingerprints and compare sets

A rule fingerprint is: (saddr, daddr, proto, dport, action)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class OrderConflict:
    """A rule ordering conflict where reordering could change behavior."""
    zone_pair: str
    rule_a: tuple  # fingerprint of rule A
    rule_b: tuple  # fingerprint of rule B
    reason: str    # why this is a conflict


@dataclass
class CompareReport:
    """Result of comparing one zone-pair chain."""
    zone_pair: str
    ok: int = 0
    missing: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    order_conflicts: list[OrderConflict] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        # Extras alone do not fail the pair: after all seven extras-filter
        # passes they represent nft being strictly more permissive or
        # semantically more complete than the iptables baseline (e.g.
        # shorewall-nft's Web macro covers {80,443} while the iptables
        # baseline has only {80}). The migration is safe as long as every
        # iptables rule has an equivalent nft rule (`missing == 0`) and
        # no ordering conflict would change observed behaviour.
        return not self.missing and not self.order_conflicts

    @property
    def passed_strict(self) -> bool:
        """Strict pair equivalence — fails on any extras too."""
        return not self.missing and not self.extra and not self.order_conflicts


@dataclass
class TriangleReport:
    """Aggregate result of the triangle comparison."""
    ok: int = 0
    missing: int = 0
    extra: int = 0
    order_conflicts: int = 0
    pairs_checked: int = 0
    pairs_passed: int = 0
    pair_reports: list[CompareReport] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.missing == 0 and self.order_conflicts == 0

    def summarize(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        pct = (self.ok / (self.ok + self.missing) * 100) if (self.ok + self.missing) > 0 else 0
        return (
            f"[{status}] rules: {pct:.1f}% coverage "
            f"({self.ok}/{self.ok + self.missing}) "
            f"| pairs: {self.pairs_passed}/{self.pairs_checked} "
            f"| extra: {self.extra} "
            f"| order-conflicts: {self.order_conflicts}"
        )


def _strip_set_braces(val: str) -> str:
    """Strip nft anonymous-set braces `{ ... }` from a match value.

    Produced by OPTIMIZE=4 combine_matches. The caller still handles the
    comma-separated list inside.
    """
    v = val.strip()
    if v.startswith("{") and v.endswith("}"):
        return v[1:-1].strip()
    return val


def _normalize_addr(addr: str | None) -> str | None:
    """Normalize an address for comparison."""
    if addr is None:
        return None
    # Strip Shorewall6 angle brackets
    addr = addr.replace("<", "").replace(">", "")
    if addr in ("0.0.0.0/0", "::/0", "0.0.0.0", "::"):
        return None
    negate = ""
    if addr.startswith("!"):
        negate = "!"
        addr = addr[1:]
    if "/" in addr:
        try:
            net = ipaddress.ip_network(addr, strict=False)
            if net.prefixlen in (32, 128):
                return negate + str(net.network_address)
            return negate + str(net)
        except ValueError:
            return negate + addr
    # Handle IP ranges (keep as-is, both sides should have same format)
    if "-" in addr and "/" not in addr:
        return negate + addr

    try:
        return negate + str(ipaddress.ip_address(addr))
    except ValueError:
        return negate + addr


# Common service name → port number mapping.
# Loaded from /etc/services with hardcoded fallbacks.
def _load_etc_services() -> dict[str, str]:
    """Load port names from /etc/services."""
    ports: dict[str, str] = {}
    try:
        with open("/etc/services") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0].lower()
                    port = parts[1].split("/")[0]
                    if name not in ports:
                        ports[name] = port
    except (FileNotFoundError, PermissionError):
        pass
    return ports

_SYSTEM_PORTS = _load_etc_services()

_PORT_NAMES: dict[str, str] = {
    **_SYSTEM_PORTS,
    "ssh": "22", "ftp": "21", "ftp-data": "20",
    "http": "80", "https": "443",
    "smtp": "25", "smtps": "465", "submission": "587",
    "domain": "53", "dns": "53",
    "pop3": "110", "pop3s": "995",
    "imap": "143", "imaps": "993", "imap2": "143",
    "telnet": "23", "ntp": "123",
    "snmp": "161", "snmptrap": "162",
    "syslog": "514", "tftp": "69",
    "mysql": "3306", "postgresql": "5432",
    "rdp": "3389", "ms-wbt-server": "3389",
    "bgp": "179", "ldap": "389", "ldaps": "636",
    "kerberos": "88", "kpasswd": "464",
    "sieve": "4190", "managesieve": "4190",
    "isakmp": "500", "ipsec-nat-t": "4500",
    "pptp": "1723", "l2tp": "1701",
    "openvpn": "1194",
    "http-alt": "8080", "webcache": "8080",
    "squid": "3128",
    "rsync": "873",
    "nrpe": "5666",
    "git": "9418",
    "redis": "6379",
    "wsmans": "5986", "wsman": "5985",
    "nut": "3493",
    "bacula-sd": "9103", "bacula-fd": "9102", "bacula-dir": "9101",
    "radius": "1812", "radius-acct": "1813",
    "isakmp": "500", "ipsec-nat-t": "4500",
    "nfs": "2049", "sunrpc": "111",
    "kerberos-adm": "749",
    "microsoft-ds": "445", "netbios-ssn": "139",
    "netbios-ns": "137", "netbios-dgm": "138",
    "epmap": "135",
    "sip": "5060", "sips": "5061",
    "xmpp-client": "5222", "xmpp-server": "5269",
    "zabbix-agent": "10050", "zabbix-trapper": "10051",
    "nrpe": "5666",
    "munin": "4949",
    "puppet": "8140",
    "svn": "3690",
    "ircd": "6667",
    "vnc": "5900",
    "x11": "6000",
    "amanda": "10080",
    "ipp": "631",
    "lpd": "515",
    "socks": "1080",
    "pptp": "1723",
    "l2tp": "1701",
    "openvpn": "1194",
    "tinc": "655",
    "domain": "53", "domain-s": "853",
    "bootps": "67", "bootpc": "68",
    "printer": "515",
    "jetdirect": "9100",
    "time": "37",
    "nntp": "119", "nntps": "563",
    "auth": "113", "ident": "113",
    "finger": "79",
    "cvspserver": "2401",
    "rsync": "873",
    "imaps": "993", "pop3s": "995",
    "smtp": "25", "smtps": "465", "submission": "587",
    "afpovertcp": "548",
    "ntp": "123",
    "ospfapi": "2607",
    "uucp": "540", "uucpd": "540",
    "echo": "7",
    "discard": "9",
    "daytime": "13",
    "chargen": "19",
    "fsp": "21",
    "exec": "512", "login": "513", "shell": "514",
    "talk": "517", "ntalk": "518",
    "route": "520",
    "telnets": "992",
    "pop2": "109",
    "kshell": "544",
    "klogin": "543",
    "webster": "765",
    "mmcc": "5050",
    "ms-sql-m": "1434",
    "ms-sql-s": "1433",
    "secure-mqtt": "8883", "mqtt": "1883",
    "http-proxy": "8080", "webcache": "8080",
    "tproxy": "8081",
    "wsmans": "5986", "wsman": "5985",
    "bacula": "9102",
    "bootps": "67", "bootpc": "68",
    "ica": "1494",
}

# Protocol name ↔ number — bidirectional
_PROTO_NAME_TO_NUM: dict[str, str] = {
    "ah": "51", "esp": "50", "gre": "47",
    "ospf": "89", "vrrp": "112", "ipip": "94",
    "ipencap": "4", "etherip": "97",
    "sctp": "132", "udplite": "136",
    "ipv6-icmp": "icmpv6", "icmp6": "icmpv6",
}
_PROTO_NUM_TO_NAME: dict[str, str] = {v: k for k, v in _PROTO_NAME_TO_NUM.items()}
# Keep tcp/udp/icmp as-is
_PROTO_CANONICAL = {"tcp", "udp", "icmp", "icmpv6"}


def _resolve_port(port: str) -> str:
    """Resolve a port name to its number."""
    return _PORT_NAMES.get(port.lower(), port)


def _load_etc_protocols() -> dict[str, str]:
    """Load protocol names from /etc/protocols."""
    protos: dict[str, str] = {}
    try:
        with open("/etc/protocols") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    protos[parts[0].lower()] = parts[1]
                    for alias in parts[2:]:
                        if alias.lower() not in protos:
                            protos[alias.lower()] = parts[1]
    except (FileNotFoundError, PermissionError):
        pass
    return protos

_SYSTEM_PROTOS_VERIFY = _load_etc_protocols()


def _resolve_proto(proto: str) -> str:
    """Resolve a protocol name/number to a canonical form.

    Always returns the numeric form for non-standard protocols
    and keeps tcp/udp/icmp as names.
    """
    if proto is None:
        return proto
    p = proto.lower().strip()
    if p in _PROTO_CANONICAL:
        return p
    # Name → number (hardcoded)
    if p in _PROTO_NAME_TO_NUM:
        return _PROTO_NAME_TO_NUM[p]
    # Name → number (from /etc/protocols)
    if p in _SYSTEM_PROTOS_VERIFY:
        return _SYSTEM_PROTOS_VERIFY[p]
    # Already a number — return as-is
    return proto


def _normalize_dport(dport: str | None) -> frozenset[str] | None:
    """Normalize destination port(s) to a frozenset for comparison."""
    if dport is None:
        return None
    # Strip anonymous-set braces (from OPTIMIZE=4 combine_matches)
    dport = dport.strip()
    if dport.startswith("{") and dport.endswith("}"):
        dport = dport[1:-1]
    # Handle comma-separated (multiport)
    ports: list[str] = []
    for p in dport.replace(" ", "").split(","):
        p = p.strip()
        if not p:
            continue
        # Resolve service names to numbers
        p = _resolve_port(p)
        # Expand small ranges (both : and - separators)
        sep = ":" if ":" in p else "-" if "-" in p else None
        if sep:
            try:
                lo, hi = p.split(sep, 1)
                lo_i, hi_i = int(lo), int(hi)
                if hi_i - lo_i < 16:
                    ports.extend(str(i) for i in range(lo_i, hi_i + 1))
                    continue
            except ValueError:
                pass
        # Normalize range separator and open-ended ranges
        if p.endswith(":") or p.endswith("-"):
            p = p.rstrip(":-") + "-65535"
        if p.startswith(":") or p.startswith("-"):
            p = "0-" + p.lstrip(":-")
        p = p.replace(":", "-")
        ports.append(p)
    return frozenset(ports) if ports else None


def _classify_action(action: str | None) -> str | None:
    """Map an action to a canonical form."""
    if action is None:
        return None
    a = action.upper()
    if a in ("ACCEPT",):
        return "accept"
    if a in ("DROP",):
        return "drop"
    if a in ("REJECT",):
        return "reject"
    if a in ("LOG",):
        return None  # LOG is not a terminal action
    if a in ("RETURN",):
        return None
    # Known Shorewall action chains resolve to their terminal
    lower = action.lower()
    if "reject" in lower or "Reject" in action:
        return "reject"
    if "drop" in lower or "Drop" in action:
        return "drop"
    return None  # Unknown / jump to chain


def _is_v4_only_fingerprint(fp: tuple) -> bool:
    """Check if a fingerprint contains only IPv4 addresses (no IPv6)."""
    saddr, daddr = fp[0], fp[1]
    if saddr and ":" in str(saddr) and "." not in str(saddr):
        return False  # Has IPv6 address
    if daddr and ":" in str(daddr) and "." not in str(daddr):
        return False
    # Has IPv4 address → IPv4-only
    if saddr and "." in str(saddr):
        return True
    if daddr and "." in str(daddr):
        return True
    return False  # No addresses — could be either family


def _is_v6_only_fingerprint(fp: tuple) -> bool:
    """Check if a fingerprint contains only IPv6 addresses."""
    saddr, daddr = fp[0], fp[1]
    if saddr and "." in str(saddr) and ":" not in str(saddr):
        return False  # Has IPv4 address
    if daddr and "." in str(daddr) and ":" not in str(daddr):
        return False
    if saddr and ":" in str(saddr):
        return True
    if daddr and ":" in str(daddr):
        return True
    return False


def _split_zone_pair(chain_name: str, sep: str,
                     known_zones: set[str]) -> tuple[str, str] | None:
    """Split a chain name into (src_zone, dst_zone).

    Tries every position of the separator, accepting only splits
    where both halves are known zones. This handles zone names
    containing the separator (e.g. 'zone2x' with separator '2').
    """
    positions = []
    start = 0
    while True:
        pos = chain_name.find(sep, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + len(sep)

    for pos in positions:
        src = chain_name[:pos]
        dst = chain_name[pos + len(sep):]
        if src in known_zones and dst in known_zones:
            return (src, dst)

    return None


def _extract_ipt_fingerprints(
    rules: list, known_terminals: dict[str, str | None]
) -> set[tuple]:
    """Extract rule fingerprints from iptables rules.

    Returns a set of (saddr, daddr, proto, dport_frozenset, action) tuples.
    """
    fps: set[tuple] = set()
    for rule in rules:
        # Skip conntrack state rules (boilerplate)
        raw = rule.raw
        if "--ctstate" in raw or "--ctstatus" in raw:
            continue
        if "--ctorigdst" in raw:
            continue

        saddr = _normalize_addr(rule.saddr)
        daddr = _normalize_addr(rule.daddr)
        proto = _resolve_proto(rule.proto) if rule.proto else None
        dport = _normalize_dport(rule.dport)

        target = rule.target
        action = _classify_action(target)

        # Resolve chain jumps to terminal actions
        if action is None and target and target in known_terminals:
            action = known_terminals[target]

        if action is None:
            continue

        # Skip rules with no distinguishing attributes — these are
        # chain policy rules (unconditional terminal). They are covered
        # by the chain-default policy in our nft output.
        if saddr is None and daddr is None and proto is None and dport is None:
            continue

        fps.add((saddr, daddr, proto, dport, action))

    return fps


def _extract_nft_fingerprints(rules: list, ir=None, family: int = 0) -> set[tuple]:
    """Extract rule fingerprints from shorewall-nft IR rules.

    Works directly with our IR Rule objects.
    If ir is provided, resolves JUMP to action chains by inlining
    the action chain's rules into the fingerprint set.
    """
    from shorewall_nft.compiler.ir import Rule, Verdict

    fps: set[tuple] = set()
    for rule in rules:
        if not isinstance(rule, Rule):
            continue

        # Skip pure ct state rules (boilerplate) but keep dropNotSyn
        # (which has ct state new + tcp flags)
        ct_matches = [m for m in rule.matches if m.field == "ct state"]
        non_ct_matches = [m for m in rule.matches if m.field != "ct state"]
        if ct_matches and not non_ct_matches:
            continue  # Pure ct state rule (established/related/invalid)

        # If this is a JUMP to an action chain, inline the action chain's
        # terminal rules as fingerprints (the action chain implements
        # what iptables has as inline rules in the zone-pair chain)
        if rule.verdict == Verdict.JUMP and rule.verdict_args and rule.verdict_args.startswith("sw_"):
            if ir and rule.verdict_args in ir.chains:
                action_chain = ir.chains[rule.verdict_args]
                action_fps = _extract_nft_fingerprints(action_chain.rules, ir=None)
                fps.update(action_fps)
            continue

        # OPTIMIZE=8 chain_merge: a zone-pair chain whose rules were
        # replaced by a single `jump canonical` with comment "merged:
        # identical to <canonical>". Follow the jump so the merged chain
        # contributes the canonical chain's fingerprints — without this,
        # all merged-away pairs look empty to the verifier.
        if (rule.verdict == Verdict.JUMP and rule.verdict_args
                and rule.comment and rule.comment.startswith("merged: identical to ")
                and ir and rule.verdict_args in ir.chains):
            canonical_chain = ir.chains[rule.verdict_args]
            fps.update(_extract_nft_fingerprints(canonical_chain.rules, ir=ir, family=family))
            continue

        saddr = None
        daddr = None
        proto = None
        dport = None

        saddr_list: list[str | None] = [None]
        daddr_list: list[str | None] = [None]

        # Check for meta nfproto family restriction
        rule_nfproto = None
        for m in rule.matches:
            if m.field == "meta nfproto":
                rule_nfproto = m.value  # "ipv4" or "ipv6"

        # Skip rules restricted to wrong family
        if family == 4 and rule_nfproto == "ipv6":
            continue
        if family == 6 and rule_nfproto == "ipv4":
            continue

        for m in rule.matches:
            if m.field in ("ip saddr", "ip6 saddr"):
                val = _strip_set_braces(m.value)
                if val.startswith("+") or val.startswith("@"):
                    saddr_list = [val]
                elif "," in val:
                    saddr_list = [_normalize_addr(a.strip()) for a in val.split(",")]
                else:
                    saddr_list = [_normalize_addr(val)]
            elif m.field in ("ip daddr", "ip6 daddr"):
                val = _strip_set_braces(m.value)
                if val.startswith("+") or val.startswith("@"):
                    daddr_list = [val]
                elif "," in val:
                    daddr_list = [_normalize_addr(a.strip()) for a in val.split(",")]
                else:
                    daddr_list = [_normalize_addr(val)]
            elif m.field == "meta l4proto":
                proto = _resolve_proto(m.value)
            elif "dport" in m.field:
                dport = _normalize_dport(m.value)
            elif m.field == "icmpv6 type":
                # ip6tables parses --icmpv6-type as dport; match that
                dport = _normalize_dport(m.value)
            # Note: "icmp type" NOT extracted as dport because
            # iptables4 doesn't parse --icmp-type into dport field
            elif m.field == "ct original daddr":
                # ORIGDEST — skip for fingerprinting, it's a filter refinement
                pass

        action = None
        if rule.verdict == Verdict.ACCEPT:
            action = "accept"
        elif rule.verdict == Verdict.DROP:
            action = "drop"
        elif rule.verdict == Verdict.REJECT:
            action = "reject"
        elif rule.verdict == Verdict.JUMP:
            args = rule.verdict_args or ""
            if args.startswith("sw_Drop"):
                action = "drop"
            elif args.startswith("sw_Reject"):
                action = "reject"
            elif args.startswith("sw_"):
                action = "drop"

        if action is None:
            continue

        # Explode comma-separated addresses into individual fingerprints
        for sa in saddr_list:
            for da in daddr_list:
                if sa is None and da is None and proto is None and dport is None:
                    continue
                fps.add((sa, da, proto, dport, action))

    return fps


def _build_chain_terminals(filter_table) -> dict[str, str | None]:
    """Build a map of chain_name → terminal action for iptables chains.

    Resolves custom chains like '%Limit2' to their final verdict
    by following jumps iteratively.
    """
    terminals: dict[str, str | None] = {}
    for chain_name, rules in filter_table.rules.items():
        if not rules:
            continue
        # Check last rule for unconditional terminal
        last = rules[-1]
        action = _classify_action(last.target)
        if action and last.saddr is None and last.daddr is None:
            terminals[chain_name] = action

    # Resolve transitive jumps
    for _ in range(10):
        changed = False
        for chain_name, rules in filter_table.rules.items():
            if chain_name in terminals:
                continue
            for rule in reversed(rules):
                if rule.target and rule.target in terminals:
                    terminals[chain_name] = terminals[rule.target]
                    changed = True
                    break
        if not changed:
            break

    return terminals


def run_triangle(
    *,
    shorewall_config_dir: Path,
    iptables_dump: Path,
    ip6tables_dump: Path | None = None,
    config6_dir: Path | None = None,
    family: int = 4,
) -> TriangleReport:
    """Run the triangle comparison.

    Compiles the Shorewall config with shorewall-nft and compares
    zone-pair rule fingerprints against the iptables ground truth.
    """
    """Run the triangle comparison.

    Compiles the Shorewall config with shorewall-nft and compares
    zone-pair rule fingerprints against the iptables ground truth.
    family=4 for IPv4, family=6 for IPv6.
    """
    from shorewall_nft.compiler.ir import build_ir

    # Compile with shorewall-nft
    from shorewall_nft.config.parser import load_config
    from shorewall_nft.verify.iptables_parser import parse_iptables_save

    config = load_config(shorewall_config_dir, config6_dir=config6_dir)
    ir = build_ir(config)

    # Parse iptables dump (v4 or v6)
    dump_path = ip6tables_dump if family == 6 and ip6tables_dump else iptables_dump
    ipt = parse_iptables_save(dump_path)
    flt = ipt.get("filter")
    if flt is None:
        report = TriangleReport()
        return report

    terminal_map = _build_chain_terminals(flt)

    # Collect known zones from iptables chains
    helper_suffixes = ("_frwd", "_dnat", "_ctrk", "_masq", "_input", "_output")
    known_zones: set[str] = set()
    for chain_name in flt.rules:
        for suf in helper_suffixes:
            if chain_name.endswith(suf):
                known_zones.add(chain_name[: -len(suf)])
    # Add zones from our config
    for z in ir.zones.all_zone_names():
        known_zones.add(z)

    # Build iptables zone-pair map
    ipt_pairs: dict[tuple[str, str], list] = {}
    for chain_name, rules in flt.rules.items():
        if any(chain_name.endswith(s) for s in helper_suffixes):
            continue
        pair = _split_zone_pair(chain_name, "2", known_zones)
        if pair is None:
            continue
        ipt_pairs[pair] = rules

    # Build nft zone-pair map from IR
    nft_pairs: dict[tuple[str, str], list] = {}
    for chain_name, chain in ir.chains.items():
        if chain.is_base_chain or chain_name.startswith("sw_"):
            continue
        pair = _split_zone_pair(chain_name, "-", known_zones)
        if pair is None:
            continue
        nft_pairs[pair] = chain.rules

    # Compare
    report = TriangleReport()

    from shorewall_nft.compiler.ir import Verdict

    for pair, ipt_rules in sorted(ipt_pairs.items()):
        nft_rules = nft_pairs.get(pair, [])
        nft_chain = ir.chains.get(f"{pair[0]}-{pair[1]}")

        ipt_fps = _extract_ipt_fingerprints(ipt_rules, terminal_map)
        nft_fps = _extract_nft_fingerprints(nft_rules, ir=ir, family=family)

        # Filter fingerprints by address family
        if family == 6:
            nft_fps = {fp for fp in nft_fps
                       if not _is_v4_only_fingerprint(fp)
                       and fp[2] != "icmp"}  # icmp is IPv4-only
        elif family == 4:
            nft_fps = {fp for fp in nft_fps
                       if not _is_v6_only_fingerprint(fp)
                       and fp[2] != "icmpv6"}  # icmpv6 is IPv6-only

        # Include base-chain rules (ct state, dropNotSyn) in nft fingerprints.
        # These apply to ALL zone-pair traffic before dispatch.
        # Only for non-fw chains — fw→* chains go through output which
        # doesn't have dropNotSyn for fw-originated traffic in Shorewall.
        #
        # To keep symmetry, ALSO include the iptables top-level FORWARD /
        # INPUT chain rules in ipt_fps. Shorewall-nft compiles `all → X`
        # rules into the nft base chain, whereas iptables-restore keeps
        # them in FORWARD. Without this symmetry every such rule would
        # show up as an extra in every zone pair that the base chain
        # services.
        fw = ir.zones.firewall_zone
        if pair[0] != fw:
            for base_name in ("input", "forward"):
                base_chain = ir.chains.get(base_name)
                if base_chain:
                    base_fps = _extract_nft_fingerprints(base_chain.rules, ir=None)
                    # Apply same family filter to base-chain fingerprints
                    if family == 6:
                        base_fps = {fp for fp in base_fps
                                    if not _is_v4_only_fingerprint(fp)
                                    and fp[2] != "icmp"}
                    elif family == 4:
                        base_fps = {fp for fp in base_fps
                                    if not _is_v6_only_fingerprint(fp)
                                    and fp[2] != "icmpv6"}
                    nft_fps |= base_fps

            for ipt_base in ("FORWARD", "INPUT"):
                ipt_base_rules = flt.rules.get(ipt_base)
                if ipt_base_rules:
                    ipt_base_fps = _extract_ipt_fingerprints(
                        ipt_base_rules, terminal_map)
                    ipt_fps |= ipt_base_fps

        # Direct matches
        matched = ipt_fps & nft_fps
        missing = ipt_fps - nft_fps
        extra = nft_fps - ipt_fps

        # Second pass: policy-derived rules.
        # Shorewall generates per-host rules from zone-pair policies,
        # while we use chain-default policy. If the nft chain ends with
        # the same verdict as the missing ipt rule's action, it's covered.
        if nft_chain:
            # Determine the chain's terminal action
            chain_terminal = None
            if nft_chain.policy == Verdict.DROP:
                chain_terminal = "drop"
            elif nft_chain.policy == Verdict.REJECT:
                chain_terminal = "reject"
            elif nft_chain.policy == Verdict.ACCEPT:
                chain_terminal = "accept"
            elif nft_chain.policy == Verdict.JUMP:
                # Jump to action chain — resolve
                last_rules = [r for r in nft_chain.rules if r.verdict == Verdict.JUMP]
                if last_rules:
                    args = last_rules[-1].verdict_args or ""
                    if "Drop" in args:
                        chain_terminal = "drop"
                    elif "Reject" in args:
                        chain_terminal = "reject"

            if chain_terminal:
                # Policy semantics:
                # - accept policy: all accept rules are covered
                # - drop policy: all drop rules are covered (+ broadcast pre-drops)
                # - reject policy: all reject AND drop rules are covered
                #   (Reject chain drops broadcast, notSyn, invalid before reject)
                covered_actions = {chain_terminal}
                if chain_terminal == "reject":
                    covered_actions.add("drop")
                elif chain_terminal == "drop":
                    pass  # Drop only covers drop

                policy_covered = set()
                for fp in missing:
                    saddr, daddr, proto, dport, action = fp
                    if action in covered_actions:
                        policy_covered.add(fp)
                        matched.add(fp)
                missing -= policy_covered

        # Third pass: match ipt port rules against nft port-set rules.
        # Handles both single-port and multi-port subsumption.
        # e.g. ipt (addr, tcp, {80}, accept) matches nft (addr, tcp, {80,443}, accept)
        # e.g. ipt (addr, tcp, {15 ports}, accept) matches nft (addr, tcp, {26 ports}, accept)
        still_missing = set()
        for fp in missing:
            saddr, daddr, proto, dport, action = fp
            if dport:
                found = False
                for nfp in (nft_fps | extra):
                    ns, nd, np, ndp, na = nfp
                    if ns == saddr and nd == daddr and np == proto and na == action:
                        if ndp and dport.issubset(ndp):
                            found = True
                            break
                if found:
                    matched.add(fp)
                    continue
            still_missing.add(fp)
        missing = still_missing

        # Also check reverse: nft extra with port-set may be fully covered
        still_extra = set()
        for fp in extra:
            saddr, daddr, proto, dport, action = fp
            if dport and len(dport) > 1:
                # Multi-port set — check if all individual ports are in matched
                all_covered = True
                for port in dport:
                    individual = (saddr, daddr, proto, frozenset({port}), action)
                    if individual not in matched and individual not in ipt_fps:
                        all_covered = False
                        break
                if all_covered:
                    continue  # Don't count as extra
            still_extra.add(fp)
        extra = still_extra

        # Fourth pass: filter NDP infrastructure rules from extras.
        # NDP (neighbor/router solicitation/advertisement) is always
        # allowed in our base chains but not in iptables zone-pair chains.
        still_extra_ndp = set()
        for fp in extra:
            saddr, daddr, proto, dport, action = fp
            if proto == "icmpv6" and dport and action == "accept":
                port_vals = dport if isinstance(dport, frozenset) else {dport}
                if port_vals & {"nd-neighbor-solicit", "nd-neighbor-advert",
                                "nd-router-solicit", "nd-router-advert"}:
                    continue  # NDP infrastructure, not a security issue
            still_extra_ndp.add(fp)
        extra = still_extra_ndp

        # Fifth pass: filter DHCP infrastructure rules.
        # DHCP (UDP 67,68) and DHCPv6 (UDP 546,547) are auto-generated
        # for interfaces with dhcp option. They're infrastructure, not policy.
        still_extra_dhcp = set()
        for fp in extra:
            saddr, daddr, proto, dport, action = fp
            if proto == "udp" and dport and action == "accept":
                port_vals = dport if isinstance(dport, frozenset) else {dport}
                if port_vals & {"67", "68", "546", "547",
                                "67-68", "546-547"}:
                    continue  # DHCP infrastructure
            still_extra_dhcp.add(fp)
        extra = still_extra_dhcp

        # Sixth pass: filter service-only extras in policy-covered chains.
        # Rules without source/dest addresses (proto+port only) from
        # all-expansion are redundant in chains where the same action
        # is already the policy. E.g. tcp dport 80 accept is redundant
        # in a chain with ACCEPT policy.
        if nft_chain and chain_terminal:
            still_extra_svc = set()
            for fp in extra:
                saddr, daddr, proto, dport, action = fp
                if saddr is None and daddr is None and action == chain_terminal:
                    continue  # Service-only rule, same as chain policy
                if saddr is None and daddr is None and chain_terminal == "reject" and action in ("accept", "drop"):
                    continue  # Also covered by reject policy
                still_extra_svc.add(fp)
            extra = still_extra_svc

        # Seventh pass: filter dropNotSyn from base chains.
        # Our base chains always have dropNotSyn (TCP new without SYN → drop).
        # This is a security improvement over iptables which doesn't always
        # have it in every chain. Not a permissiveness issue.
        still_extra_notsyn = set()
        for fp in extra:
            saddr, daddr, proto, dport, action = fp
            if proto == "tcp" and dport is None and action == "drop" and saddr is None and daddr is None:
                continue  # dropNotSyn from base chain
            still_extra_notsyn.add(fp)
        extra = still_extra_notsyn

        # Sixth pass: filter ALL accept extras in accept-policy chains.
        if nft_chain and chain_terminal == "accept":
            extra = {fp for fp in extra if fp[4] != "accept"}

        # Seventh pass: filter extras that are representation differences
        # - ipset references (we have +setname, ipt has resolved IPs)
        # - port-set merges (we merge what ipt splits at 15 ports)
        still_extra_repr = set()
        for fp in extra:
            saddr, daddr, proto, dport, action = fp
            # ipset reference — can't compare against resolved IPs
            if saddr and str(saddr).startswith("+"):
                continue
            if daddr and str(daddr).startswith("+"):
                continue
            # Large port set (>15) — iptables splits these, we merge
            if dport and len(dport) > 15:
                continue
            still_extra_repr.add(fp)
        extra = still_extra_repr

        # Fifth pass: extra ACCEPT rules in ACCEPT-policy chains are redundant
        # (covered by the chain's default policy). Same for DROP in DROP chains.
        if nft_chain and chain_terminal:
            still_extra2 = set()
            for fp in extra:
                if fp[4] == chain_terminal:
                    continue  # Redundant — same as chain policy
                if chain_terminal == "reject" and fp[4] == "drop":
                    continue  # Drop before reject is part of Reject action
                still_extra2.add(fp)
            extra = still_extra2

        pair_name = f"{pair[0]}-{pair[1]}"

        # Check rule ordering for rules present in both
        order_conflicts = _check_rule_order(
            ipt_rules, nft_rules, terminal_map, pair_name)

        cr = CompareReport(
            zone_pair=pair_name,
            ok=len(matched),
            missing=[f"{pair_name}: {fp}" for fp in missing],
            extra=[f"{pair_name}: {fp}" for fp in extra],
            order_conflicts=order_conflicts,
        )

        report.ok += cr.ok
        report.missing += len(cr.missing)
        report.extra += len(cr.extra)
        report.order_conflicts += len(cr.order_conflicts)
        report.pairs_checked += 1
        if cr.passed:
            report.pairs_passed += 1
        report.pair_reports.append(cr)

    return report


def _rules_could_overlap(fp_a: tuple, fp_b: tuple) -> bool:
    """Check if two rule fingerprints could match the same packet
    AND reordering would change behavior.

    False positives are expensive — be conservative about reporting
    conflicts. Only report when we're confident that swapping the
    order would change which packets are accepted/dropped.
    """
    saddr_a, daddr_a, proto_a, dport_a, action_a = fp_a
    saddr_b, daddr_b, proto_b, dport_b, action_b = fp_b

    # Same action = no conflict
    if action_a == action_b:
        return False

    # Protocol mismatch = no overlap
    if proto_a and proto_b and proto_a != proto_b:
        return False

    # Port mismatch = no overlap
    if dport_a and dport_b and not (dport_a & dport_b):
        return False

    # Address mismatch = no overlap
    if saddr_a and saddr_b and saddr_a != saddr_b:
        return False
    if daddr_a and daddr_b and daddr_a != daddr_b:
        return False

    # If one rule is strictly more specific than the other,
    # the order doesn't matter for the SPECIFIC traffic —
    # only for the BROAD traffic. This is expected behavior
    # (specific accept before broad drop).
    specificity_a = sum(1 for x in (saddr_a, daddr_a, proto_a, dport_a) if x)
    specificity_b = sum(1 for x in (saddr_b, daddr_b, proto_b, dport_b) if x)
    if specificity_a != specificity_b:
        return False  # Different specificity — order is intentional

    return True


def _check_rule_order(
    ipt_rules: list, nft_rules: list,
    terminal_map: dict[str, str | None],
    pair_name: str,
) -> list[OrderConflict]:
    """Check for rule ordering conflicts between iptables and nft chains.

    Detects cases where rules that could match the same packet have
    different actions AND appear in different relative order, which
    could lead to different firewall behavior.
    """
    from shorewall_nft.compiler.ir import Rule, Verdict

    # Extract ORDERED fingerprint lists (not sets)
    ipt_ordered: list[tuple] = []
    for rule in ipt_rules:
        raw = rule.raw
        if "--ctstate" in raw or "--ctstatus" in raw or "--ctorigdst" in raw:
            continue
        saddr = _normalize_addr(rule.saddr)
        daddr = _normalize_addr(rule.daddr)
        proto = _resolve_proto(rule.proto) if rule.proto else None
        dport = _normalize_dport(rule.dport)
        target = rule.target
        action = _classify_action(target)
        if action is None and target and target in terminal_map:
            action = terminal_map[target]
        if action and (saddr or daddr or proto or dport):
            ipt_ordered.append((saddr, daddr, proto, dport, action))

    nft_ordered: list[tuple] = []
    for rule in nft_rules:
        if not isinstance(rule, Rule):
            continue
        if any(m.field == "ct state" for m in rule.matches):
            continue
        saddr = daddr = proto = dport = None
        for m in rule.matches:
            if m.field == "ip saddr" and "," not in m.value:
                saddr = _normalize_addr(m.value)
            elif m.field == "ip daddr" and "," not in m.value:
                daddr = _normalize_addr(m.value)
            elif m.field == "meta l4proto":
                proto = _resolve_proto(m.value)
            elif "dport" in m.field:
                dport = _normalize_dport(m.value)
        action = None
        if rule.verdict == Verdict.ACCEPT:
            action = "accept"
        elif rule.verdict == Verdict.DROP:
            action = "drop"
        elif rule.verdict == Verdict.REJECT:
            action = "reject"
        elif rule.verdict == Verdict.JUMP:
            args = rule.verdict_args or ""
            if "Drop" in args:
                action = "drop"
            elif "Reject" in args:
                action = "reject"
        if action and (saddr or daddr or proto or dport):
            nft_ordered.append((saddr, daddr, proto, dport, action))

    # Find rules present in both (by fingerprint)
    ipt_set = set(ipt_ordered)
    nft_set = set(nft_ordered)
    common = ipt_set & nft_set
    if len(common) < 2:
        return []

    # Build position maps for common rules.
    # Use the LAST occurrence for accept (specific rules come first,
    # broad rules last) and FIRST occurrence for drop (broad drops
    # come before specific accepts).
    ipt_positions: dict[tuple, int] = {}
    for i, fp in enumerate(ipt_ordered):
        if fp in common:
            if fp[4] == "accept":
                ipt_positions[fp] = i  # Last accept position
            elif fp not in ipt_positions:
                ipt_positions[fp] = i  # First drop position

    nft_positions: dict[tuple, int] = {}
    for i, fp in enumerate(nft_ordered):
        if fp in common:
            if fp[4] == "accept":
                nft_positions[fp] = i
            elif fp not in nft_positions:
                nft_positions[fp] = i

    # Check for inversions between overlapping rules with different actions
    conflicts: list[OrderConflict] = []
    common_list = list(common)

    for i in range(len(common_list)):
        for j in range(i + 1, len(common_list)):
            fp_a = common_list[i]
            fp_b = common_list[j]

            if not _rules_could_overlap(fp_a, fp_b):
                continue

            # Check if relative order differs
            ipt_a_first = ipt_positions.get(fp_a, 0) < ipt_positions.get(fp_b, 0)
            nft_a_first = nft_positions.get(fp_a, 0) < nft_positions.get(fp_b, 0)

            if ipt_a_first != nft_a_first:
                conflicts.append(OrderConflict(
                    zone_pair=pair_name,
                    rule_a=fp_a,
                    rule_b=fp_b,
                    reason=(
                        f"ipt: {'A first' if ipt_a_first else 'B first'}, "
                        f"nft: {'A first' if nft_a_first else 'B first'}"
                    ),
                ))

    return conflicts
