"""Internal Representation (IR) for the firewall ruleset.

Transforms parsed Shorewall config into a backend-agnostic IR that
the nft emitter consumes to produce nft -f scripts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewall_nft.config.zones import ZoneModel, build_zone_model


class Verdict(Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"
    JUMP = "jump"
    GOTO = "goto"
    RETURN = "return"


class ChainType(Enum):
    FILTER = "filter"
    NAT = "nat"
    ROUTE = "route"


class Hook(Enum):
    INPUT = "input"
    FORWARD = "forward"
    OUTPUT = "output"
    PREROUTING = "prerouting"
    POSTROUTING = "postrouting"


@dataclass
class Match:
    """A single match condition in a rule."""
    field: str      # e.g. "iifname", "ip saddr", "tcp dport", "ct state"
    value: str      # e.g. "eth0", "10.0.0.0/8", "80", "established"
    negate: bool = False


@dataclass
class Rule:
    """A single firewall rule."""
    matches: list[Match] = field(default_factory=list)
    verdict: Verdict = Verdict.ACCEPT
    verdict_args: str | None = None  # e.g. chain name for JUMP, log prefix for LOG
    comment: str | None = None
    counter: bool = False
    log_prefix: str | None = None
    rate_limit: str | None = None  # e.g. "30/minute burst 100"
    connlimit: str | None = None   # e.g. "s:1:2"
    time_match: str | None = None  # e.g. "utc&timestart=8:00&timestop=17:00"
    user_match: str | None = None  # e.g. "nobody"
    mark_match: str | None = None  # e.g. "0x1/0xff"
    source_file: str = ""
    source_line: int = 0
    source_raw: str = ""  # Trimmed raw source line for debug comments


@dataclass
class Chain:
    """A chain containing rules."""
    name: str
    chain_type: ChainType | None = None  # None for non-base chains
    hook: Hook | None = None             # None for non-base chains
    priority: int = 0
    policy: Verdict | None = None
    rules: list[Rule] = field(default_factory=list)

    @property
    def is_base_chain(self) -> bool:
        return self.hook is not None


@dataclass
class FirewallIR:
    """Complete intermediate representation of the firewall."""
    zones: ZoneModel = field(default_factory=ZoneModel)
    chains: dict[str, Chain] = field(default_factory=dict)
    settings: dict[str, str] = field(default_factory=dict)

    def add_chain(self, chain: Chain) -> None:
        self.chains[chain.name] = chain

    def get_or_create_chain(self, name: str) -> Chain:
        if name not in self.chains:
            self.chains[name] = Chain(name=name)
        return self.chains[name]


# Macro pattern: NAME(VERDICT) e.g. SSH(ACCEPT), DNS(DROP):$LOG
# Name can contain hyphens (e.g. OrgAdmin(ACCEPT))
_MACRO_RE = re.compile(r'^([\w-]+)\((\w+)\)(?::(.+))?$')

# Slash macro pattern: NAME/VERDICT e.g. Ping/ACCEPT, Rfc1918/DROP:$LOG
# Name can contain hyphens (e.g. OrgAdmin/ACCEPT)
_SLASH_MACRO_RE = re.compile(r'^([\w-]+)/(\w+)(?::(.+))?$')

# Builtin macros are loaded dynamically from Shorewall/Macros/ at build time.
# This dict is populated by _load_standard_macros().
_BUILTIN_MACROS: dict[str, list[tuple[str, str]]] = {}

# Shorewall actions loaded from Shorewall/Actions/
# Actions are chains that implement complex multi-rule behaviors.
# They are loaded dynamically like macros.
_ACTION_MACROS: dict[str, str] = {}

# RFC1918 private address ranges
_RFC1918_RANGES = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

# Custom macros loaded from macros/ directory
# Each entry is a list of (action, source, dest, proto, dport, sport) tuples
# where "PARAM" means "use the calling action", "SOURCE"/"DEST" mean "use caller's"
_CUSTOM_MACROS: dict[str, list[tuple[str, ...]]] = {}


def _load_standard_macros(shorewall_dir: Path | None = None) -> None:
    """Load standard Shorewall macros.

    Loads from the bundled macros directory (shipped inside the package)
    by default, with fallbacks to system-installed Shorewall locations
    if the bundled copy is missing. Entries are merged into _CUSTOM_MACROS
    so user macros can override them.
    """
    if shorewall_dir is None:
        # Try bundled macros first (shipped with the package), then
        # fall back to a system Shorewall installation if present.
        candidates = [
            Path(__file__).parent.parent / "data" / "macros",
            Path("/usr/share/shorewall/Macros"),
            Path("/usr/share/shorewall/macro"),
        ]
        for c in candidates:
            if c.is_dir():
                shorewall_dir = c
                break

    if shorewall_dir is None or not shorewall_dir.is_dir():
        return

    from shorewall_nft.config.parser import ConfigParser
    parser = ConfigParser(shorewall_dir)

    for macro_file in sorted(shorewall_dir.iterdir()):
        if not macro_file.is_file() or not macro_file.name.startswith("macro."):
            continue
        macro_name = macro_file.name[6:]
        if macro_name in _CUSTOM_MACROS:
            continue  # User macros take precedence
        if macro_name in _NATIVE_HANDLED_MACROS:
            continue  # Handled natively by the compiler

        try:
            lines = parser._parse_columnar(macro_file)
        except Exception:
            continue

        entries = []
        for line in lines:
            cols = line.columns
            if not cols:
                continue
            while len(cols) < 6:
                cols.append("-")
            entries.append(tuple(cols[:6]))

        if entries:
            _CUSTOM_MACROS[macro_name] = entries


# Macros that we handle natively (better than the standard macro files)
_NATIVE_HANDLED_MACROS = {"Rfc1918"}


def _load_custom_macros(macros: dict[str, list]) -> None:
    """Load custom macros from parsed macro files into _CUSTOM_MACROS."""
    _CUSTOM_MACROS.clear()
    for name, lines in macros.items():
        entries = []
        for line in lines:
            cols = line.columns
            if not cols:
                continue
            # Pad to 6 columns
            while len(cols) < 6:
                cols.append("-")
            entries.append(tuple(cols[:6]))
        if entries:
            _CUSTOM_MACROS[name] = entries


def build_ir(config: ShorewalConfig) -> FirewallIR:
    """Build the complete IR from a parsed config."""
    zones = build_zone_model(config)
    ir = FirewallIR(zones=zones, settings=config.settings)
    ir._fastaccept = config.settings.get("FASTACCEPT", "Yes").lower() in ("yes", "1")

    # Load custom macros (user-defined take precedence)
    _load_custom_macros(config.macros)

    # Load standard Shorewall macros (from Shorewall/Macros/)
    _load_standard_macros()

    # Create base chains
    _create_base_chains(ir)

    # Process policies (default actions per zone-pair)
    _process_policies(ir, config.policy, zones)

    # Process NAT (DNAT from rules, SNAT from masq, netmap)
    from shorewall_nft.compiler.nat import extract_nat_rules, process_nat, process_netmap
    dnat_rules, filter_rules = extract_nat_rules(config.rules)
    process_nat(ir, config.masq, dnat_rules)
    if config.netmap:
        process_netmap(ir, config.netmap)

    # Process filter rules (excluding DNAT)
    _process_rules(ir, filter_rules, zones)

    # Process notrack rules
    if config.notrack:
        _process_notrack(ir, config.notrack, zones)

    # Process conntrack helpers
    if config.conntrack:
        _process_conntrack(ir, config.conntrack)

    # Process mangle/tcrules
    if config.tcrules or config.mangle:
        from shorewall_nft.compiler.tc import process_mangle
        process_mangle(ir, config.tcrules, config.mangle, zones)

    # Add interface-level protections (tcpflags, nosmurfs) and DHCP
    _process_interface_options(ir, zones)

    # DHCP: interfaces with 'dhcp' option get automatic UDP 67,68 ACCEPT
    _process_dhcp_interfaces(ir, zones)

    # Process blrules (blacklist rules)
    if config.blrules:
        _process_blrules(ir, config.blrules, zones)

    # Process routestopped
    if config.routestopped:
        _process_routestopped(ir, config.routestopped)

    # Set self-zone ACCEPT for multi-interface zones and routeback zones
    _set_self_zone_policies(ir, zones)

    # Apply default actions (DROP_DEFAULT, REJECT_DEFAULT)
    _apply_default_actions(ir, config.settings)

    # Process accounting rules
    if config.accounting:
        from shorewall_nft.compiler.accounting import process_accounting
        process_accounting(ir, config.accounting)

    # Process providers (multi-ISP routing)
    if config.providers:
        from shorewall_nft.compiler.providers import parse_providers
        providers = parse_providers(config.providers)
        # Provider marks → mangle rules for policy routing
        if providers:
            if "mangle-prerouting" not in ir.chains:
                ir.add_chain(Chain(
                    name="mangle-prerouting",
                    chain_type=ChainType.ROUTE,
                    hook=Hook.PREROUTING,
                    priority=-150,
                ))
            for prov in providers:
                if prov.mark:
                    mangle = ir.chains["mangle-prerouting"]
                    mangle.rules.append(Rule(
                        matches=[Match(field="iifname", value=prov.interface)],
                        verdict=Verdict.ACCEPT,
                        verdict_args=f"mark:{prov.mark}",
                        comment=f"provider:{prov.name}",
                    ))

    # Process tunnels
    if config.tunnels:
        from shorewall_nft.compiler.tunnels import process_tunnels
        process_tunnels(ir, config.tunnels, zones)

    # Process MAC filtering
    if config.maclist:
        from shorewall_nft.compiler.macfilter import process_maclist
        process_maclist(ir, config.maclist,
                        config.settings.get("MACLIST_DISPOSITION", "REJECT"))

    # Docker integration
    from shorewall_nft.compiler.docker import setup_docker
    setup_docker(ir, config.settings)

    # Create action chains (Drop, Reject, Broadcast, etc.)
    from shorewall_nft.compiler.actions import create_action_chains, create_dynamic_blacklist
    create_action_chains(ir)
    create_dynamic_blacklist(ir, config.settings)

    # Optimize: run all applicable optimizations
    optimize_level = int(config.settings.get("OPTIMIZE", "0"))
    if optimize_level >= 1:
        from shorewall_nft.compiler.optimize import run_optimizations
        run_optimizations(ir, optimize_level)

    return ir


def _create_base_chains(ir: FirewallIR) -> None:
    """Create the base filter chains with hooks.

    Each base chain gets ct state established,related accept as first rule
    (standard Shorewall FASTACCEPT semantik).
    """
    for hook, name in [
        (Hook.INPUT, "input"),
        (Hook.FORWARD, "forward"),
        (Hook.OUTPUT, "output"),
    ]:
        chain = Chain(
            name=name,
            chain_type=ChainType.FILTER,
            hook=hook,
            priority=0,
        )
        # FASTACCEPT: if Yes (default), established/related traffic is
        # accepted in base chains before dispatch. If No, it flows through
        # zone-pair chains for accounting/logging purposes.
        # We always add ct state invalid drop and dropNotSyn regardless.
        fastaccept = getattr(ir, '_fastaccept', True)
        if fastaccept:
            chain.rules.append(Rule(
                matches=[Match(field="ct state", value="established,related")],
                verdict=Verdict.ACCEPT,
            ))
        # Drop invalid packets (always)
        chain.rules.append(Rule(
            matches=[Match(field="ct state", value="invalid")],
            verdict=Verdict.DROP,
        ))
        # dropNotSyn: drop new TCP connections without SYN flag
        # (prevents ACK scans, RST floods, and other TCP anomalies)
        chain.rules.append(Rule(
            matches=[
                Match(field="meta l4proto", value="tcp"),
                Match(field="ct state", value="new"),
                Match(field="tcp flags & syn", value="0"),
            ],
            verdict=Verdict.DROP,
            comment="dropNotSyn",
        ))
        # ICMPv6 NDP essentials — MUST always be allowed for IPv6 to work
        # (Neighbor Solicitation, Neighbor Advertisement,
        #  Router Solicitation, Router Advertisement)
        if hook in (Hook.INPUT, Hook.OUTPUT):
            for icmpv6_type in [
                "nd-neighbor-solicit",
                "nd-neighbor-advert",
                "nd-router-solicit",
                "nd-router-advert",
            ]:
                chain.rules.append(Rule(
                    matches=[
                        Match(field="meta l4proto", value="icmpv6"),
                        Match(field="icmpv6 type", value=icmpv6_type),
                    ],
                    verdict=Verdict.ACCEPT,
                    comment="NDP essential",
                ))
        ir.add_chain(chain)


def _process_policies(ir: FirewallIR, policy_lines: list[ConfigLine],
                      zones: ZoneModel) -> None:
    """Process policy definitions into default chain rules."""
    for line in policy_lines:
        cols = line.columns
        if len(cols) < 3:
            continue

        source = cols[0]
        dest = cols[1]
        policy_str = cols[2].upper()
        log_level = cols[3] if len(cols) > 3 else None

        verdict = _parse_verdict(policy_str)
        if verdict is None:
            continue

        # Resolve $FW
        if source == "$FW":
            source = zones.firewall_zone
        if dest == "$FW":
            dest = zones.firewall_zone

        # "all" means all zones
        sources = zones.all_zone_names() if source in ("all", "any") else [source]
        dests = zones.all_zone_names() if dest in ("all", "any") else [dest]

        for src in sources:
            for dst in dests:
                # Skip self-zone pairs unless explicitly configured
                # (e.g. "loc loc ACCEPT" is explicit)
                if src == dst:
                    if source in ("all", "any") or dest in ("all", "any"):
                        continue  # Don't create self-zone from "all" expansion
                    # Explicit self-zone policy (e.g. "loc loc ACCEPT")
                chain_name = _zone_pair_chain_name(src, dst, zones)
                chain = ir.get_or_create_chain(chain_name)
                if chain.policy is None:
                    chain.policy = verdict


def _expand_zone_list(spec: str, zones: ZoneModel) -> list[str]:
    """Expand a comma-separated zone list in a source/dest spec.

    Shorewall rules allow comma-separated zone names in the SOURCE and
    DEST columns: `linux,vpn  voice` means "from either linux OR vpn
    to voice". We expand this into N individual specs so each gets its
    own chain name (otherwise we'd emit `linux,vpn-voice` which is an
    invalid nft chain identifier).

    Handles:
        'linux,vpn'         → ['linux', 'vpn']
        'linux,vpn:1.2.3.4' → ['linux:1.2.3.4', 'vpn:1.2.3.4']
        'net'               → ['net']
        'all'               → ['all']             (not a zone list)
        '$FW'               → ['$FW']             (firewall variable)
        'net:<2a00::1>'     → ['net:<2a00::1>']   (angle-bracket v6 not split)
    """
    # Don't split inside angle brackets (IPv6 literals in shorewall6 syntax)
    if "<" in spec or ">" in spec:
        return [spec]

    # Split zone part (before first colon) from address part
    if ":" in spec:
        zone_part, addr_part = spec.split(":", 1)
    else:
        zone_part, addr_part = spec, None

    if "," not in zone_part:
        return [spec]

    # Only split if every comma-separated piece is a known zone name.
    # This avoids accidentally splitting things like port lists.
    pieces = [z.strip() for z in zone_part.split(",")]
    valid_names = set(zones.zones.keys()) | {"all", "any", "$FW"}
    if not all(p in valid_names for p in pieces):
        return [spec]

    if addr_part is not None:
        return [f"{p}:{addr_part}" for p in pieces]
    return pieces


def _process_rules(ir: FirewallIR, rule_lines: list[ConfigLine],
                   zones: ZoneModel) -> None:
    """Process firewall rules into chain rules."""
    for line in rule_lines:
        cols = line.columns
        if not cols:
            continue

        action_str = cols[0]
        source_spec_raw = cols[1] if len(cols) > 1 else "all"
        dest_spec_raw = cols[2] if len(cols) > 2 else "all"

        # Expand comma-separated zone lists in SOURCE and DEST.
        # One rule line may become N×M processed rules.
        src_specs = _expand_zone_list(source_spec_raw, zones)
        dst_specs = _expand_zone_list(dest_spec_raw, zones)

        # Recursively process each expanded combination by rewriting the
        # ConfigLine's columns for a single-zone rule. This keeps the
        # existing rule processing logic unchanged.
        if len(src_specs) > 1 or len(dst_specs) > 1:
            for src in src_specs:
                for dst in dst_specs:
                    new_cols = list(cols)
                    new_cols[1] = src
                    if len(new_cols) > 2:
                        new_cols[2] = dst
                    else:
                        new_cols.append(dst)
                    expanded_line = ConfigLine(
                        columns=new_cols,
                        file=line.file,
                        lineno=line.lineno,
                        comment_tag=line.comment_tag,
                        section=line.section,
                        raw=line.raw,
                        format_version=line.format_version,
                    )
                    _process_rules(ir, [expanded_line], zones)
            continue

        source_spec = source_spec_raw
        dest_spec = dest_spec_raw
        proto = cols[3] if len(cols) > 3 else None
        dport = cols[4] if len(cols) > 4 else None
        sport = cols[5] if len(cols) > 5 else None
        origdest = cols[6] if len(cols) > 6 else None
        rate = cols[7] if len(cols) > 7 else None
        user = cols[8] if len(cols) > 8 else None
        mark = cols[9] if len(cols) > 9 else None
        connlimit = cols[10] if len(cols) > 10 else None
        time_col = cols[11] if len(cols) > 11 else None
        headers = cols[12] if len(cols) > 12 else None
        switch = cols[13] if len(cols) > 13 else None
        helper = cols[14] if len(cols) > 14 else None

        # Handle defaults
        for v in (proto, dport, sport, origdest, rate, user, mark,
                  connlimit, time_col, headers, switch, helper):
            pass  # Can't use locals() trick, handle individually
        if proto == "-": proto = None
        if dport == "-": dport = None
        if sport == "-": sport = None
        if origdest == "-": origdest = None
        if rate == "-": rate = None
        if user == "-": user = None
        if mark == "-": mark = None
        if connlimit == "-": connlimit = None
        if time_col == "-": time_col = None
        if headers == "-": headers = None
        if switch == "-": switch = None
        if helper == "-": helper = None

        # Normalize protocol name to lowercase so that `TCP`/`tcp`/`Tcp`
        # all produce the same nft field name (e.g. `tcp dport 80`).
        # nft rejects uppercase protocol identifiers.
        if proto:
            proto = proto.lower()

        # Parse action — may be macro like SSH(ACCEPT), Ping/ACCEPT, or plain ACCEPT
        macro_match = _MACRO_RE.match(action_str) or _SLASH_MACRO_RE.match(action_str)
        if macro_match:
            macro_name = macro_match.group(1)
            verdict_str = macro_match.group(2)
            log_tag = macro_match.group(3)
            _expand_macro(ir, zones, macro_name, verdict_str, log_tag,
                          source_spec, dest_spec, proto, dport, sport, line)
        else:
            # Check for action:loglevel pattern
            log_prefix = None
            if ":" in action_str:
                action_str, log_tag = action_str.split(":", 1)
                log_prefix = log_tag if log_tag and log_tag != "-" else None

            # Rfc1918: drop RFC1918 source addresses — one rule per range
            if action_str == "Rfc1918":
                verdict = _parse_verdict("DROP")
                src_zone = source_spec.split(":")[0]
                for rfc_range in _RFC1918_RANGES.split(","):
                    _add_rule(ir, zones, verdict, log_prefix,
                              f"{src_zone}:{rfc_range}",
                              dest_spec, proto, dport, sport, line)
                continue

            # Limit:TAG — rate-limited action
            if action_str.startswith("Limit"):
                _add_rule(ir, zones, Verdict.ACCEPT, log_prefix,
                          source_spec, dest_spec, proto, dport, sport, line)
                continue

            # AUDIT actions: A_ACCEPT, A_DROP, A_REJECT
            # These log to the kernel audit subsystem then apply the verdict
            if action_str.startswith("A_"):
                base_action = action_str[2:]  # Strip A_ prefix
                verdict = _parse_verdict(base_action)
                if verdict:
                    _add_rule(ir, zones, verdict, log_prefix,
                              source_spec, dest_spec, proto, dport, sport, line,
                              verdict_args=f"audit:{base_action}")
                    continue

            # Check if it's a known action → jump to action chain
            from shorewall_nft.compiler.actions import ACTION_CHAIN_MAP
            if action_str in ACTION_CHAIN_MAP:
                chain_name = ACTION_CHAIN_MAP[action_str]
                _add_rule(ir, zones, Verdict.JUMP, log_prefix,
                          source_spec, dest_spec, proto, dport, sport, line,
                          verdict_args=chain_name, origdest=origdest,
                          rate=rate, user=user, mark=mark,
                          connlimit=connlimit, time_match=time_col,
                          headers=headers, switch=switch, helper=helper)
                continue

            verdict = _parse_verdict(action_str)
            if verdict is None:
                continue

            _add_rule(ir, zones, verdict, log_prefix,
                      source_spec, dest_spec, proto, dport, sport, line,
                      origdest=origdest, rate=rate, user=user, mark=mark,
                      connlimit=connlimit, time_match=time_col,
                      headers=headers, switch=switch, helper=helper)


def _expand_macro(ir: FirewallIR, zones: ZoneModel,
                  macro_name: str, verdict_str: str, log_tag: str | None,
                  source_spec: str, dest_spec: str,
                  proto: str | None, dport: str | None, sport: str | None,
                  line: ConfigLine) -> None:
    """Expand a macro into individual rules."""
    verdict = _parse_verdict(verdict_str)
    if verdict is None:
        return

    log_prefix = None
    if log_tag and log_tag != "-":
        log_prefix = log_tag

    # Native-handled macros
    if macro_name == "Rfc1918":
        src_zone = source_spec.split(":")[0]
        for rfc_range in _RFC1918_RANGES.split(","):
            _add_rule(ir, zones, verdict, log_prefix,
                      f"{src_zone}:{rfc_range}",
                      dest_spec, proto, dport, sport, line)
        return

    # Check builtin macros first
    expansions = _BUILTIN_MACROS.get(macro_name)
    if expansions:
        for exp_proto, exp_port in expansions:
            actual_proto = proto or exp_proto
            actual_dport = dport or exp_port
            _add_rule(ir, zones, verdict, log_prefix,
                      source_spec, dest_spec, actual_proto, actual_dport, sport, line)
        return

    # Check custom macros
    custom = _CUSTOM_MACROS.get(macro_name)
    if custom:
        # Detect if calling context is IPv6:
        # - Source/dest has IPv6 addresses
        # - Source/dest zones are ipv6 type
        # - The rule comes from a shorewall6 config
        ctx_is_v6 = (_is_ipv6(source_spec) or _is_ipv6(dest_spec))
        if not ctx_is_v6:
            # Check zone types
            src_z = source_spec.split(":<")[0].split(":")[0]
            dst_z = dest_spec.split(":<")[0].split(":")[0]
            if src_z == "$FW":
                src_z = zones.firewall_zone
            if dst_z == "$FW":
                dst_z = zones.firewall_zone
            for z in (src_z, dst_z):
                if z in zones.zones and zones.zones[z].zone_type == "ipv6":
                    ctx_is_v6 = True
                    break
        # Also check if the config line comes from a shorewall6 directory
        if not ctx_is_v6 and line.file and "shorewall6" in line.file:
            ctx_is_v6 = True
        ctx_is_v4 = not ctx_is_v6

        for entry in custom:
            m_action, m_source, m_dest, m_proto, m_dport, m_sport = entry

            # Filter entries by address family — skip v4 entries in v6
            # context and vice versa
            entry_has_v6 = any(_is_ipv6(str(f)) for f in (m_source, m_dest)
                               if f not in ("SOURCE", "DEST", "-", "PARAM"))
            entry_has_v4 = any(
                f not in ("SOURCE", "DEST", "-", "PARAM") and f[0:1].isdigit()
                for f in (m_source, m_dest)
            )
            if entry_has_v6 and ctx_is_v4:
                continue  # Skip IPv6 entry in IPv4 context
            if entry_has_v4 and ctx_is_v6:
                continue  # Skip IPv4 entry in IPv6 context

            # Resolve PARAM -> calling verdict
            if m_action == "PARAM":
                m_verdict = verdict
            else:
                m_verdict = _parse_verdict(m_action)
                if m_verdict is None:
                    # m_action might be a sub-macro (e.g. Web → HTTP, HTTPS)
                    # Recursively expand it
                    sub_source = source_spec if m_source in ("SOURCE", "-") else m_source
                    sub_dest = dest_spec if m_dest in ("DEST", "-") else m_dest
                    sub_proto = m_proto if m_proto != "-" else proto
                    sub_dport = m_dport if m_dport != "-" else dport
                    sub_sport = m_sport if m_sport != "-" else sport
                    _expand_macro(ir, zones, m_action, verdict_str, log_tag,
                                  sub_source, sub_dest,
                                  sub_proto, sub_dport, sub_sport, line)
                    continue

            # Resolve SOURCE/DEST placeholders
            # SOURCE → calling rule's source, DEST → calling rule's dest
            # Reverse rules use DEST as source and SOURCE as dest
            if m_source == "SOURCE":
                actual_source = source_spec
            elif m_source == "DEST":
                actual_source = dest_spec
            elif m_source == "-":
                actual_source = source_spec
            else:
                actual_source = m_source

            if m_dest == "DEST":
                actual_dest = dest_spec
            elif m_dest == "SOURCE":
                actual_dest = source_spec
            elif m_dest == "-":
                actual_dest = dest_spec
            else:
                actual_dest = m_dest

            # If macro provides raw IP addresses (not SOURCE/DEST/zone),
            # combine them with the calling rule's zone context.
            # Only for values that are NOT already zone-prefixed.
            # IPv4 raw: starts with digit, no colon
            if actual_source and actual_source[0].isdigit() and ":" not in actual_source:
                src_zone_ctx = source_spec.split(":")[0] if ":" in source_spec else source_spec
                if src_zone_ctx not in ("all", "any"):
                    actual_source = f"{src_zone_ctx}:{actual_source}"
            if actual_dest and actual_dest[0].isdigit() and ":" not in actual_dest:
                dst_zone_ctx = dest_spec.split(":")[0] if ":" in dest_spec else dest_spec
                if dst_zone_ctx not in ("all", "any"):
                    actual_dest = f"{dst_zone_ctx}:{actual_dest}"

            # IPv6 raw: starts with < (angle-bracket from shorewall6 macro)
            # These ONLY come from merged v6 macros with literal addresses
            if actual_source and actual_source.startswith("<"):
                src_zone_ctx = source_spec.split(":<")[0].split(":")[0]
                if src_zone_ctx == "$FW":
                    src_zone_ctx = zones.firewall_zone
                if src_zone_ctx in zones.zones and src_zone_ctx not in ("all", "any"):
                    actual_source = f"{src_zone_ctx}:<{actual_source.strip('<>')}>"
            if actual_dest and actual_dest.startswith("<"):
                dst_zone_ctx = dest_spec.split(":<")[0].split(":")[0]
                if dst_zone_ctx == "$FW":
                    dst_zone_ctx = zones.firewall_zone
                if dst_zone_ctx in zones.zones and dst_zone_ctx not in ("all", "any"):
                    actual_dest = f"{dst_zone_ctx}:<{actual_dest.strip('<>')}>"

            # Resolve proto/port: calling rule overrides macro defaults
            actual_proto = proto if proto else (m_proto if m_proto != "-" else None)
            actual_dport = dport if dport else (m_dport if m_dport != "-" else None)
            actual_sport = sport if sport else (m_sport if m_sport != "-" else None)

            _add_rule(ir, zones, m_verdict, log_prefix,
                      actual_source, actual_dest, actual_proto, actual_dport,
                      actual_sport, line)
        return

    # Unknown macro — treat as simple action with given proto/port
    _add_rule(ir, zones, verdict, log_prefix,
              source_spec, dest_spec, proto, dport, sport, line)


def _add_rule(ir: FirewallIR, zones: ZoneModel,
              verdict: Verdict, log_prefix: str | None,
              source_spec: str, dest_spec: str,
              proto: str | None, dport: str | None, sport: str | None,
              line: ConfigLine, verdict_args: str | None = None,
              origdest: str | None = None,
              rate: str | None = None,
              user: str | None = None,
              mark: str | None = None,
              connlimit: str | None = None,
              time_match: str | None = None,
              headers: str | None = None,
              switch: str | None = None,
              helper: str | None = None) -> None:
    """Add a rule to the appropriate chain(s)."""
    src_zone, src_addrs = _parse_zone_spec(source_spec, zones)
    dst_zone, dst_addrs = _parse_zone_spec(dest_spec, zones)

    # Determine source/dest zones ("any" is a Shorewall synonym for "all")
    src_zones = zones.all_zone_names() if src_zone in ("all", "any") else [src_zone]
    dst_zones = zones.all_zone_names() if dst_zone in ("all", "any") else [dst_zone]

    is_all_expansion = src_zone in ("all", "any") or dst_zone in ("all", "any")

    for sz in src_zones:
        for dz in dst_zones:
            # Skip self-zone pairs from "all" expansion
            if sz == dz and is_all_expansion:
                continue

            chain_name = _zone_pair_chain_name(sz, dz, zones)
            chain = ir.get_or_create_chain(chain_name)

            # Shorewall optimization: don't add ACCEPT rules to chains
            # that already have ACCEPT policy (redundant).
            # Only applies to "all" expansion — explicit rules always go in.
            # Exception: FASTACCEPT=No means established traffic goes through
            # all chains, so ACCEPT rules ARE needed for accounting.
            fastaccept = getattr(ir, '_fastaccept', True)
            if (is_all_expansion and verdict == Verdict.ACCEPT
                    and chain.policy == Verdict.ACCEPT
                    and not verdict_args
                    and fastaccept):
                continue

            rule = Rule(
                verdict=verdict,
                verdict_args=verdict_args,
                comment=line.comment_tag,
                source_file=line.file,
                source_line=line.lineno,
            source_raw=line.raw,
            )

            # Add matches — detect IPv4 vs IPv6 addresses
            has_v4_addr = False
            has_v6_addr = False

            if src_addrs:
                negate = src_addrs.startswith("!")
                clean_addr = src_addrs.lstrip("!")
                # Shorewall MAC syntax: ~XX-XX-XX-XX-XX-XX (dash-separated).
                # Convert to nft ether-addr match with colon separators.
                if clean_addr.startswith("~") and _is_mac_addr(clean_addr[1:]):
                    mac = clean_addr[1:].replace("-", ":").lower()
                    rule.matches.append(
                        Match(field="ether saddr", value=mac, negate=negate))
                elif _is_ipv6(clean_addr):
                    rule.matches.append(Match(field="ip6 saddr", value=clean_addr, negate=negate))
                    has_v6_addr = True
                else:
                    rule.matches.append(Match(field="ip saddr", value=clean_addr, negate=negate))
                    has_v4_addr = True

            if dst_addrs:
                negate = dst_addrs.startswith("!")
                clean_addr = dst_addrs.lstrip("!")
                if _is_ipv6(clean_addr):
                    rule.matches.append(Match(field="ip6 daddr", value=clean_addr, negate=negate))
                    has_v6_addr = True
                else:
                    rule.matches.append(Match(field="ip daddr", value=clean_addr, negate=negate))
                    has_v4_addr = True

            # ORIGDEST: match on original destination (before DNAT)
            if origdest:
                rule.matches.append(Match(field="ct original daddr", value=origdest))

            # Family restriction for dual-stack:
            # In a merged inet table, rules without address matches
            # apply to BOTH families. We must restrict them to the
            # correct family to avoid cross-family leaks.
            if not has_v4_addr and not has_v6_addr:
                is_from_v6 = line.file and "shorewall6" in line.file
                is_from_v4 = line.file and "shorewall6" not in line.file
                if is_from_v6:
                    rule.matches.insert(0, Match(
                        field="meta nfproto", value="ipv6"))
                elif is_from_v4:
                    rule.matches.insert(0, Match(
                        field="meta nfproto", value="ipv4"))

            # No interface matches here — dispatch in base chains handles that

            # Detect if this rule is in IPv6 context
            is_v6 = any(m.field.startswith("ip6 ") or
                        (m.field == "meta nfproto" and m.value == "ipv6")
                        for m in rule.matches)

            # ICMP type code mapping: IPv4 ↔ IPv6
            _ICMP4_TO_6: dict[str, str] = {
                "8": "128", "echo-request": "echo-request",
                "0": "129", "echo-reply": "echo-reply",
                "3": "1",   # destination-unreachable
                "11": "3",  # time-exceeded
                "12": "4",  # parameter-problem
            }
            _ICMP6_TO_4: dict[str, str] = {v: k for k, v in _ICMP4_TO_6.items()}

            if proto:
                # Auto-translate icmp ↔ icmpv6 based on address family
                actual_proto = proto
                actual_dport_icmp = dport
                if proto == "icmp" and is_v6:
                    actual_proto = "icmpv6"
                    if dport and dport in _ICMP4_TO_6:
                        actual_dport_icmp = _ICMP4_TO_6[dport]
                elif proto == "icmpv6" and not is_v6 and not any(
                    m.field.startswith("ip6 ") for m in rule.matches):
                    actual_proto = "icmp"
                    if dport and dport in _ICMP6_TO_4:
                        actual_dport_icmp = _ICMP6_TO_4[dport]

                if actual_proto in ("icmp", "icmpv6"):
                    rule.matches.append(Match(field="meta l4proto", value=actual_proto))
                    if actual_dport_icmp:
                        rule.matches.append(Match(field=f"{actual_proto} type", value=actual_dport_icmp))
                elif proto == "icmpv6":
                    rule.matches.append(Match(field="meta l4proto", value="icmpv6"))
                    if dport:
                        rule.matches.append(Match(field="icmpv6 type", value=dport))
                else:
                    rule.matches.append(Match(field="meta l4proto", value=proto))
                    if dport:
                        rule.matches.append(Match(field=f"{proto} dport", value=dport))
                    if sport:
                        rule.matches.append(Match(field=f"{proto} sport", value=sport))

            if log_prefix:
                # Generate Shorewall-style log prefix: "Shorewall:chain:action:"
                nft_log_prefix = f"Shorewall:{chain_name}:{verdict.value.upper()}:"
                log_level = log_prefix  # The original value is the syslog level
                log_rule = Rule(
                    matches=list(rule.matches),
                    verdict=Verdict.LOG,
                    log_prefix=nft_log_prefix,
                    verdict_args=f"log_level:{log_level}",
                    source_file=line.file,
                    source_line=line.lineno,
                source_raw=line.raw,
                )
                chain.rules.append(log_rule)

            # HEADERS (col 13): IPv6 extension header matching
            if headers:
                _HEADER_MAP = {
                    "hop": "hbh", "dst": "dst", "route": "rt",
                    "frag": "frag", "auth": "ah", "esp": "esp",
                    "none": "none", "protocol": "proto",
                }
                for hdr in headers.replace("any:", "").replace("exactly:", "").split(","):
                    hdr = hdr.strip().lstrip("!")
                    nft_hdr = _HEADER_MAP.get(hdr, hdr)
                    rule.matches.append(Match(
                        field="exthdr", value=nft_hdr,
                        negate=headers.startswith("!")))

            # SWITCH (col 14): conditional rule via conntrack mark
            if switch:
                rule.matches.append(Match(field="ct mark", value=switch))

            # HELPER (col 15): match by ct helper
            if helper:
                rule.matches.append(Match(field="ct helper", value=f'"{helper}"'))

            # Inline matches (;; passthrough from config columns)
            for col in line.columns:
                if col.startswith(";;"):
                    inline_text = col[2:].strip()
                    if inline_text:
                        # Convert iptables inline to nft equivalent where possible
                        # Common patterns: -m set --match-set, -m recent, etc.
                        rule.matches.append(Match(field="inline", value=inline_text))

            # Rate limit: s:name:rate/unit:burst → nft limit
            if rate:
                rule.rate_limit = _parse_rate_limit(rate)
            if user:
                rule.user_match = user
            if mark:
                rule.mark_match = mark
            if connlimit:
                rule.connlimit = connlimit
            if time_match:
                rule.time_match = time_match

            chain.rules.append(rule)


def _parse_rate_limit(rate_str: str) -> str:
    """Parse Shorewall rate limit format to nft format.

    Shorewall: s:name:rate/unit:burst  or  rate/unit:burst
    nft:       limit rate N/unit burst M
    """
    import re
    # s:name:30/min:100 → limit rate 30/minute burst 100
    m = re.match(r'^(?:s:\w+:)?(\d+)/(\w+)(?::(\d+))?$', rate_str)
    if m:
        count = m.group(1)
        unit = m.group(2)
        burst = m.group(3)
        # Normalize unit names
        unit_map = {"sec": "second", "min": "minute", "hour": "hour", "day": "day",
                    "second": "second", "minute": "minute"}
        nft_unit = unit_map.get(unit, unit)
        result = f"{count}/{nft_unit}"
        if burst:
            result += f" burst {burst} packets"
        return result
    return rate_str


def _is_ipv6(addr: str) -> bool:
    """Check if an address string contains IPv6 addresses."""
    # Strip set braces and check individual addresses
    clean = addr.strip("{ }")
    for part in clean.split(","):
        part = part.strip().lstrip("!")
        if part.startswith("+"):
            continue  # ipset reference
        if ":" in part and not part.startswith("/"):
            return True
    return False


_MAC_RE = re.compile(r'^[0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}\1'
                     r'[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}$')


def _is_mac_addr(s: str) -> bool:
    """Check if a string is an Ethernet MAC address.

    Accepts both colon-separated (00:22:61:be:37:7a) and Shorewall's
    dash-separated (00-22-61-BE-37-7A) forms.
    """
    return bool(_MAC_RE.match(s))


def _parse_zone_spec(spec: str, zones: ZoneModel) -> tuple[str, str | None]:
    """Parse a zone:address or zone:<address> specification.

    Shorewall uses zone:addr for IPv4, zone:<addr> for IPv6
    (angle brackets avoid ambiguity with IPv6 colons).

    Returns (zone_name, address_or_None).
    Examples:
        "net"                    -> ("net", None)
        "net:10.0.0.1"           -> ("net", "10.0.0.1")
        "net:<2001:db8::1>"      -> ("net", "2001:db8::1")
        "net:<$ORG_PFX>"     -> ("net", "$ORG_PFX")
        "$FW"                    -> ("fw", None)
        "all"                    -> ("all", None)
        "all:<2001:db8::/32>"    -> ("all", "2001:db8::/32")
    """
    if spec == "$FW":
        return zones.firewall_zone, None

    # Handle negation prefix: !zone or !zone:addr
    if spec.startswith("!"):
        zone, addr = _parse_zone_spec(spec[1:], zones)
        # Negation is handled at the rule level, not zone level
        # Return the zone with a negation marker in the address
        if addr:
            return zone, f"!{addr}"
        return zone, None

    # IPv6 angle-bracket syntax: zone:<addr> or zone:<addr,addr>
    if ":<" in spec:
        zone, rest = spec.split(":<", 1)
        # Strip trailing > and any nested <> from addresses
        addr = rest.rstrip(">").replace("<", "").replace(">", "")
        if zone == "$FW":
            zone = zones.firewall_zone
        return zone, addr

    # Standard colon syntax (IPv4 or zone without address)
    if ":" in spec:
        # Check if it looks like zone:addr or just an IPv6 address
        parts = spec.split(":", 1)
        # If the first part is a known zone or special name, split there
        if parts[0] in zones.zones or parts[0] in ("$FW", "all", "any"):
            zone = parts[0]
            addr = parts[1]
            if zone == "$FW":
                zone = zones.firewall_zone
            return zone, addr
        # Bare IPv6 address (from macro expansion) — treat as address
        # without zone. The _add_rule caller will get zone "all" which
        # expands to all zones. For proper zone context, the calling
        # macro should prepend the zone.
        if "::" in spec or spec.count(":") >= 3:
            # Strip angle brackets if present
            clean = spec.replace("<", "").replace(">", "")
            return "all", clean

    return spec, None


def _add_interface_matches(rule: Rule, src_zone: str, dst_zone: str,
                           zones: ZoneModel) -> None:
    """Add interface matches based on zone definitions."""
    if src_zone in zones.zones and not zones.zones[src_zone].is_firewall:
        ifaces = zones.zones[src_zone].interfaces
        if len(ifaces) == 1:
            rule.matches.insert(0, Match(field="iifname", value=ifaces[0].name))
        elif len(ifaces) > 1:
            names = ", ".join(f'"{i.name}"' for i in ifaces)
            rule.matches.insert(0, Match(field="iifname", value=f"{{ {names} }}"))

    if dst_zone in zones.zones and not zones.zones[dst_zone].is_firewall:
        ifaces = zones.zones[dst_zone].interfaces
        if len(ifaces) == 1:
            rule.matches.insert(
                1 if rule.matches else 0,
                Match(field="oifname", value=ifaces[0].name))
        elif len(ifaces) > 1:
            names = ", ".join(f'"{i.name}"' for i in ifaces)
            rule.matches.insert(
                1 if rule.matches else 0,
                Match(field="oifname", value=f"{{ {names} }}"))


def _zone_pair_chain_name(src: str, dst: str, zones: ZoneModel) -> str:
    """Generate chain name for a zone pair.

    Traffic direction determines which base chain dispatches:
    - src=fw -> output chain
    - dst=fw -> input chain
    - else   -> forward chain
    """
    fw = zones.firewall_zone
    if src == fw and dst == fw:
        return "output"  # fw->fw goes through output
    if src == fw:
        return f"{src}-{dst}"
    if dst == fw:
        return f"{src}-{dst}"
    return f"{src}-{dst}"


def _parse_verdict(action: str) -> Verdict | None:
    """Parse an action string into a Verdict."""
    mapping = {
        "ACCEPT": Verdict.ACCEPT,
        "DROP": Verdict.DROP,
        "REJECT": Verdict.REJECT,
        "LOG": Verdict.LOG,
        "RETURN": Verdict.RETURN,
    }
    return mapping.get(action.upper())


def _process_notrack(ir: FirewallIR, notrack_lines: list[ConfigLine],
                     zones: ZoneModel) -> None:
    """Process notrack rules into raw-priority chains.

    Format: SOURCE DESTINATION PROTO DEST_PORT SOURCE_PORT
    """
    # Create raw chain if needed
    if "raw-prerouting" not in ir.chains:
        ir.add_chain(Chain(
            name="raw-prerouting",
            chain_type=ChainType.FILTER,
            hook=Hook.PREROUTING,
            priority=-300,
        ))
    if "raw-output" not in ir.chains:
        ir.add_chain(Chain(
            name="raw-output",
            chain_type=ChainType.FILTER,
            hook=Hook.OUTPUT,
            priority=-300,
        ))

    for line in notrack_lines:
        cols = line.columns
        if len(cols) < 3:
            continue

        source_spec = cols[0]
        dest_spec = cols[1]
        proto = cols[2] if len(cols) > 2 else None
        dport = cols[3] if len(cols) > 3 else None
        sport = cols[4] if len(cols) > 4 else None

        if proto == "-":
            proto = None
        if dport == "-":
            dport = None
        if sport == "-":
            sport = None

        src_zone, src_addr = _parse_zone_spec(source_spec, zones)

        # Determine chain: $FW source -> output, else -> prerouting
        fw = zones.firewall_zone
        if src_zone == fw:
            chain = ir.chains["raw-output"]
        else:
            chain = ir.chains["raw-prerouting"]

        rule = Rule(
            verdict=Verdict.ACCEPT,
            verdict_args="notrack:",
            source_file=line.file,
            source_line=line.lineno,
        source_raw=line.raw,
        )

        if src_addr:
            rule.matches.append(Match(field="ip saddr", value=src_addr))

        _, dst_addr = _parse_zone_spec(dest_spec, zones)
        if dst_addr and dst_addr != "0.0.0.0/0":
            rule.matches.append(Match(field="ip daddr", value=dst_addr))

        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if dport:
                rule.matches.append(Match(field=f"{proto} dport", value=dport))
            if sport:
                rule.matches.append(Match(field=f"{proto} sport", value=sport))

        chain.rules.append(rule)


def _process_conntrack(ir: FirewallIR, conntrack_lines: list[ConfigLine]) -> None:
    """Process conntrack helper rules.

    Format: CT:helper:NAME:POLICY SOURCE DESTINATION PROTO DEST_PORT
    """
    # Create ct helper chain if needed
    if "ct-helpers" not in ir.chains:
        ir.add_chain(Chain(
            name="ct-helpers",
            chain_type=ChainType.FILTER,
            hook=Hook.PREROUTING,
            priority=-200,  # Between raw and conntrack
        ))

    for line in conntrack_lines:
        cols = line.columns
        if not cols:
            continue

        action = cols[0]
        if not action.startswith("CT:helper:"):
            continue

        # Parse CT:helper:NAME:POLICY
        parts = action.split(":")
        helper_name = parts[2] if len(parts) > 2 else ""
        # policy = parts[3] if len(parts) > 3 else ""

        proto = cols[3] if len(cols) > 3 else None
        dport = cols[4] if len(cols) > 4 else None

        if proto == "-":
            proto = None
        if dport == "-":
            dport = None

        chain = ir.chains["ct-helpers"]
        rule = Rule(
            verdict=Verdict.ACCEPT,
            verdict_args=f"ct_helper:{helper_name}",
            source_file=line.file,
            source_line=line.lineno,
        source_raw=line.raw,
        )

        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if dport:
                rule.matches.append(Match(field=f"{proto} dport", value=dport))

        chain.rules.append(rule)  # conntrack helper


def _process_interface_options(ir: FirewallIR, zones: ZoneModel) -> None:
    """Generate nft rules for interface-level protections.

    Handles tcpflags and nosmurfs interface options.
    Inserted into the input chain after ct state rules.
    """
    input_chain = ir.chains.get("input")
    if not input_chain:
        return

    protection_rules: list[Rule] = []

    for zone in zones.zones.values():
        for iface in zone.interfaces:
            opts = set(iface.options)

            if "tcpflags" in opts:
                # SYN+FIN
                protection_rules.append(Rule(
                    matches=[
                        Match(field="iifname", value=iface.name),
                        Match(field="tcp flags & (syn|fin)", value="syn|fin"),
                    ],
                    verdict=Verdict.DROP,
                    comment=f"tcpflags:{iface.name}",
                ))
                # SYN+RST
                protection_rules.append(Rule(
                    matches=[
                        Match(field="iifname", value=iface.name),
                        Match(field="tcp flags & (syn|rst)", value="syn|rst"),
                    ],
                    verdict=Verdict.DROP,
                    comment=f"tcpflags:{iface.name}",
                ))

            if "nosmurfs" in opts:
                protection_rules.append(Rule(
                    matches=[
                        Match(field="iifname", value=iface.name),
                        Match(field="fib saddr type", value="broadcast"),
                    ],
                    verdict=Verdict.DROP,
                    comment=f"nosmurfs:{iface.name}",
                ))

    # Insert after ct state rules (positions 0-1) but before dispatch
    insert_pos = 2
    for rule in protection_rules:
        input_chain.rules.insert(insert_pos, rule)
        insert_pos += 1


def _process_dhcp_interfaces(ir: FirewallIR, zones: ZoneModel) -> None:
    """Generate DHCP allow rules for interfaces with 'dhcp' option.

    Shorewall automatically allows UDP 67,68 (DHCP) on interfaces
    configured with the dhcp option. This creates rules in both
    the input chain (for DHCP to the firewall) and in all zone-pair
    chains involving this zone (for DHCP forwarding).
    """
    for zone in zones.zones.values():
        for iface in zone.interfaces:
            if "dhcp" not in iface.options:
                continue

            fw = zones.firewall_zone

            def _add_dhcp_to_chain(chain_name: str) -> None:
                chain = ir.get_or_create_chain(chain_name)
                has_dhcp = any(
                    any(m.value in ("67,68", "67", "68") for m in r.matches if "dport" in m.field)
                    for r in chain.rules
                )
                if not has_dhcp:
                    chain.rules.append(Rule(
                        matches=[
                            Match(field="meta l4proto", value="udp"),
                            Match(field="udp dport", value="67,68"),
                        ],
                        verdict=Verdict.ACCEPT,
                        comment=f"dhcp:{iface.name}",
                    ))
                    chain.rules.append(Rule(
                        matches=[
                            Match(field="meta l4proto", value="udp"),
                            Match(field="udp dport", value="546,547"),
                        ],
                        verdict=Verdict.ACCEPT,
                        comment=f"dhcpv6:{iface.name}",
                    ))

            # DHCP to/from firewall (INPUT/OUTPUT chains)
            _add_dhcp_to_chain(f"{zone.name}-{fw}")
            _add_dhcp_to_chain(f"{fw}-{zone.name}")

            # Self-zone DHCP (bridge interfaces)
            _add_dhcp_to_chain(f"{zone.name}-{zone.name}")

            # DHCP forwarding from this zone to ALL other zones
            # (Shorewall generates DHCP allow in all zone-pair chains
            # where the dhcp-enabled zone is the source)
            for other_zone in zones.zones.values():
                if other_zone.name == zone.name or other_zone.is_firewall:
                    continue
                _add_dhcp_to_chain(f"{zone.name}-{other_zone.name}")
                _add_dhcp_to_chain(f"{other_zone.name}-{zone.name}")


def _process_blrules(ir: FirewallIR, blrules: list[ConfigLine],
                     zones: ZoneModel) -> None:
    """Process blacklist rules into a blacklist chain.

    blrules format: ACTION SOURCE DEST PROTO DPORT SPORT ORIGDEST ...
    """
    if not blrules:
        return

    # Create blacklist chain, called from input/forward before zone dispatch
    if "blacklist" not in ir.chains:
        ir.add_chain(Chain(name="blacklist"))

    chain = ir.chains["blacklist"]

    for line in blrules:
        cols = line.columns
        if not cols:
            continue

        action_str = cols[0]
        source_spec = cols[1] if len(cols) > 1 else "-"
        dest_spec = cols[2] if len(cols) > 2 else "-"
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else None

        # Map blacklist actions
        if action_str.lower() in ("blacklog", "blacklist"):
            verdict = Verdict.DROP
        elif action_str.upper() == "DROP":
            verdict = Verdict.DROP
        elif action_str.upper() == "REJECT":
            verdict = Verdict.REJECT
        else:
            verdict = Verdict.DROP

        rule = Rule(
            verdict=verdict,
            source_file=line.file,
            source_line=line.lineno,
        source_raw=line.raw,
        )

        if source_spec and source_spec != "-":
            _, addr = _parse_zone_spec(source_spec, zones)
            if addr:
                rule.matches.append(Match(field="ip saddr", value=addr))

        if dest_spec and dest_spec != "-":
            _, addr = _parse_zone_spec(dest_spec, zones)
            if addr:
                rule.matches.append(Match(field="ip daddr", value=addr))

        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if dport:
                rule.matches.append(Match(field=f"{proto} dport", value=dport))

        chain.rules.append(rule)


def _process_routestopped(ir: FirewallIR, routestopped: list[ConfigLine]) -> None:
    """Process routestopped rules.

    These define traffic allowed when the firewall is stopped.
    In nft: we create a separate table 'inet shorewall_stopped' that
    can be loaded when the main table is removed.

    Format: INTERFACE HOST(S) OPTIONS PROTO DPORT SPORT
    """
    if "stopped-input" not in ir.chains:
        ir.add_chain(Chain(name="stopped-input"))
    if "stopped-output" not in ir.chains:
        ir.add_chain(Chain(name="stopped-output"))

    for line in routestopped:
        cols = line.columns
        if not cols:
            continue

        iface = cols[0]
        hosts = cols[1] if len(cols) > 1 and cols[1] != "-" else None
        options = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else None

        # Input rule: allow traffic from this interface
        rule_in = Rule(verdict=Verdict.ACCEPT)
        rule_in.matches.append(Match(field="iifname", value=iface))
        if hosts:
            for host in hosts.split(","):
                h = host.strip()
                if h:
                    r = Rule(verdict=Verdict.ACCEPT)
                    r.matches.append(Match(field="iifname", value=iface))
                    r.matches.append(Match(field="ip saddr", value=h))
                    if proto:
                        r.matches.append(Match(field="meta l4proto", value=proto))
                        if dport:
                            r.matches.append(Match(field=f"{proto} dport", value=dport))
                    ir.chains["stopped-input"].rules.append(r)

                    # Corresponding output rule
                    r_out = Rule(verdict=Verdict.ACCEPT)
                    r_out.matches.append(Match(field="oifname", value=iface))
                    r_out.matches.append(Match(field="ip daddr", value=h))
                    if proto:
                        r_out.matches.append(Match(field="meta l4proto", value=proto))
                    ir.chains["stopped-output"].rules.append(r_out)
        else:
            if proto:
                rule_in.matches.append(Match(field="meta l4proto", value=proto))
                if dport:
                    rule_in.matches.append(Match(field=f"{proto} dport", value=dport))
            ir.chains["stopped-input"].rules.append(rule_in)

            rule_out = Rule(verdict=Verdict.ACCEPT)
            rule_out.matches.append(Match(field="oifname", value=iface))
            if proto:
                rule_out.matches.append(Match(field="meta l4proto", value=proto))
            ir.chains["stopped-output"].rules.append(rule_out)


def _set_self_zone_policies(ir: FirewallIR, zones: ZoneModel) -> None:
    """Set ACCEPT policy for self-zone chains.

    Shorewall behavior: traffic within the same zone (between multiple
    interfaces) is ACCEPT by default. This applies to:
    - Zones with multiple interfaces (inter-interface routing)
    - Zones with routeback option on any interface
    """
    for zone_name, zone in zones.zones.items():
        if zone.is_firewall:
            continue

        # Check if zone has routeback or multiple interfaces
        has_routeback = any(
            "routeback" in opt or opt.startswith("routeback=")
            for iface in zone.interfaces
            for opt in iface.options
        )
        has_multi_iface = len(zone.interfaces) > 1

        if has_routeback or has_multi_iface:
            chain_name = f"{zone_name}-{zone_name}"
            chain = ir.get_or_create_chain(chain_name)
            if chain.policy is None:
                chain.policy = Verdict.ACCEPT


def _apply_default_actions(ir: FirewallIR, settings: dict[str, str]) -> None:
    """Apply DROP_DEFAULT and REJECT_DEFAULT action chains.

    In Shorewall, these prepend Broadcast/Multicast filtering before
    the actual DROP/REJECT policy in zone-pair chains.

    DROP_DEFAULT=Drop means: before dropping, silently discard broadcasts.
    REJECT_DEFAULT=Reject means: before rejecting, silently discard broadcasts.
    """
    drop_default = settings.get("DROP_DEFAULT", "Drop")
    reject_default = settings.get("REJECT_DEFAULT", "Reject")

    from shorewall_nft.compiler.actions import ACTION_CHAIN_MAP

    for chain in ir.chains.values():
        if chain.is_base_chain or chain.name.startswith("sw_"):
            continue

        if chain.policy == Verdict.DROP and drop_default in ACTION_CHAIN_MAP:
            # Replace simple drop policy with jump to action chain
            chain.policy = Verdict.JUMP
            chain.rules.append(Rule(
                verdict=Verdict.JUMP,
                verdict_args=ACTION_CHAIN_MAP[drop_default],
            ))
        elif chain.policy == Verdict.REJECT and reject_default in ACTION_CHAIN_MAP:
            chain.policy = Verdict.JUMP
            chain.rules.append(Rule(
                verdict=Verdict.JUMP,
                verdict_args=ACTION_CHAIN_MAP[reject_default],
            ))
