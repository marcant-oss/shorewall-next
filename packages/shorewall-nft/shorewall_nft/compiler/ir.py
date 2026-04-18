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
from shorewall_nft.nft.dns_sets import (
    DEFAULT_SET_SIZE,
    DEFAULT_TTL_CEIL,
    DEFAULT_TTL_FLOOR,
    DnsSetRegistry,
    DnsrRegistry,
    canonical_qname,
    is_valid_hostname,
    parse_dnsnames_file,
    qname_to_set_name,
)


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
    # Chains for the separate `inet shorewall_stopped` table — populated
    # from routestopped. Kept apart from `chains` so the main emitter
    # never mixes them into the running ruleset.
    stopped_chains: dict[str, Chain] = field(default_factory=dict)
    # Chains for the separate `arp filter` table — populated from
    # arprules. The arp family is its own table type so we keep it
    # apart from the inet chains, which only see L3 IPv4/IPv6 traffic.
    arp_chains: dict[str, Chain] = field(default_factory=dict)
    # Named counter objects from the nfacct file. Each entry maps a
    # name to its (packets, bytes) initial values. Emitted as
    # `counter <name> { packets N bytes M }` declarations at the
    # top of the inet shorewall table.
    nfacct_counters: dict[str, tuple[int, int]] = field(default_factory=dict)
    # DNS-backed nft set registry — populated from rules that use
    # ``dns:hostname`` tokens and from the optional ``dnsnames`` file.
    # The emitter reads this to declare one ``dns_<name>_v4`` /
    # ``dns_<name>_v6`` pair per hostname, and the start command writes
    # a compiled allowlist for shorewalld to consume at runtime.
    dns_registry: DnsSetRegistry = field(default_factory=DnsSetRegistry)
    # Pull-resolver groups — populated from ``dnsr:hostname[,hostname…]``
    # tokens. Uses the same dns_* nft sets as the tap pipeline; the
    # registry carries the extra metadata (secondary qnames) needed by
    # shorewalld's PullResolver to actively maintain those sets.
    dnsr_registry: DnsrRegistry = field(default_factory=DnsrRegistry)

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

    # Seed DNS set registry with global defaults from shorewall.conf;
    # per-name overrides from the ``dnsnames`` config file win over
    # these defaults, and rule-discovered hostnames fall back to them.
    try:
        ir.dns_registry.default_ttl_floor = int(
            config.settings.get("DNS_SET_TTL_FLOOR", DEFAULT_TTL_FLOOR))
    except (TypeError, ValueError):
        ir.dns_registry.default_ttl_floor = DEFAULT_TTL_FLOOR
    try:
        ir.dns_registry.default_ttl_ceil = int(
            config.settings.get("DNS_SET_TTL_CEIL", DEFAULT_TTL_CEIL))
    except (TypeError, ValueError):
        ir.dns_registry.default_ttl_ceil = DEFAULT_TTL_CEIL
    try:
        ir.dns_registry.default_size = int(
            config.settings.get("DNS_SET_SIZE", DEFAULT_SET_SIZE))
    except (TypeError, ValueError):
        ir.dns_registry.default_size = DEFAULT_SET_SIZE

    # Per-name overrides from the ``dnsnames`` config file, if present.
    if getattr(config, "dnsnames", None):
        for spec in parse_dnsnames_file(
            config.dnsnames,
            default_ttl_floor=ir.dns_registry.default_ttl_floor,
            default_ttl_ceil=ir.dns_registry.default_ttl_ceil,
            default_size=ir.dns_registry.default_size,
        ):
            ir.dns_registry.add_spec(spec)

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

    # Process rawnat rules (raw-table actions, runs pre-conntrack)
    if getattr(config, "rawnat", None):
        _process_rawnat(ir, config.rawnat, zones)

    # Process arprules (arp family — separate table)
    if getattr(config, "arprules", None):
        _process_arprules(ir, config.arprules)

    # Process nfacct (named counter objects in the inet table)
    if getattr(config, "nfacct", None):
        _process_nfacct(ir, config.nfacct)

    # Process scfilter (source CIDR sanity filter)
    if getattr(config, "scfilter", None):
        _process_scfilter(ir, config.scfilter)

    # Process ecn (clear ECN bits per iface/host)
    if getattr(config, "ecn", None):
        _process_ecn(ir, config.ecn)

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

    # Process routestopped (legacy)
    if config.routestopped:
        _process_routestopped(ir, config.routestopped, config.settings)

    # Process stoppedrules (modern routestopped successor)
    if getattr(config, "stoppedrules", None):
        _process_stoppedrules(ir, config.stoppedrules, zones)

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

    # FASTACCEPT=No: classic shorewall puts `ctstate RELATED,ESTABLISHED
    # -j ACCEPT` + `ctstate INVALID -j DROP` inside every zone-pair chain
    # instead of at the top of the FORWARD base chain. shorewall-nft's
    # base-chain pass already handles the FASTACCEPT=Yes case; mirror
    # the classic behaviour here for FASTACCEPT=No so return traffic
    # through zone-pair chains still gets accepted.
    fastaccept = getattr(ir, "_fastaccept", True)
    _prepend_ct_state_to_zone_pair_chains(
        ir, include_established=not fastaccept)

    # Optimize: run all applicable optimizations
    optimize_level = int(config.settings.get("OPTIMIZE", "8"))
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
            policy=Verdict.DROP,
        )
        # Base chains mirror Shorewall's iptables architecture:
        # policy DROP, no ct state rules, only dispatch jumps (emitted
        # later by the emitter).  ct state established/related accept
        # and invalid drop live in the zone-pair chains (prepended by
        # _prepend_ct_state_to_zone_pair_chains).
        #
        # FASTACCEPT: if Yes (default), established/related accept is
        # added here so it fires before dispatch — a fast path that
        # skips the per-chain walk for return traffic.
        fastaccept = getattr(ir, '_fastaccept', True)
        if fastaccept:
            chain.rules.append(Rule(
                matches=[Match(field="ct state", value="established,related")],
                verdict=Verdict.ACCEPT,
            ))
        # ICMPv6 NDP essentials — MUST be accepted in input/output
        # base chains before dispatch so the kernel can resolve
        # neighbors and receive router advertisements.
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


def _prepend_ct_state_to_zone_pair_chains(ir: FirewallIR,
                                          include_established: bool = True,
                                          ) -> None:
    """Prepend ct state rules to every zone-pair chain.

    Always prepends ``ct state invalid drop``.  When
    *include_established* is True (FASTACCEPT=No), also prepends
    ``ct state established,related accept`` so return traffic is
    accepted inside the zone-pair chain instead of in the base chain.

    Zone-pair chains are identified as non-base chains whose names
    contain a dash matching a known zone pair (emitter convention:
    "<src>-<dst>"). Chains starting with "sw_" are action chains —
    skipped.
    """
    all_zones = set(ir.zones.all_zone_names())
    for name, chain in ir.chains.items():
        if chain.is_base_chain:
            continue
        if name.startswith("sw_"):
            continue
        if "-" not in name:
            continue
        src, _, dst = name.partition("-")
        if src not in all_zones or dst not in all_zones:
            continue
        ct_rules: list[Rule] = []
        if include_established:
            ct_rules.append(Rule(
                matches=[Match(field="ct state", value="established,related")],
                verdict=Verdict.ACCEPT,
            ))
        ct_rules.append(Rule(
            matches=[Match(field="ct state", value="invalid")],
            verdict=Verdict.DROP,
        ))
        chain.rules = ct_rules + list(chain.rules)


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


def _spec_contains_dns_token(spec: str) -> bool:
    """Cheap test for ``dns:HOSTNAME`` embedded in a raw spec column.

    Covers every shape the compiler's rule parser accepts for a
    DNS-managed address: bare ``dns:host``, zone-prefixed
    ``net:dns:host``, leading negation ``!dns:host``, and
    zone-prefixed inner negation ``net:!dns:host``. We only need to
    know *whether* to run the DNS pre-pass — the rewriter below
    reconstructs the exact form.
    """
    return (
        spec.startswith("dns:")
        or spec.startswith("!dns:")
        or ":dns:" in spec
        or ":!dns:" in spec
    )


def _rewrite_dns_spec(
    spec: str,
    registry: DnsSetRegistry,
    family: str,
    dnsr_registry: DnsrRegistry | None = None,
) -> str:
    """Replace any ``dns:hostname[,hostname…]`` token in ``spec`` with
    the compiled set-reference sentinel ``+dns_<sanitised>_<family>``.

    Supports every negation shape Shorewall accepts:

    * ``dns:host``                — bare
    * ``!dns:host``               — whole-spec negation
    * ``net:dns:host``            — zone-prefixed
    * ``net:!dns:host``           — zone-prefixed with inner negation
    * ``<dns:host>`` / ``net:<dns:host>`` — ipv6 angle brackets (rare
      but grammatically valid)

    Multi-host ``dns:host1,host2,…`` is supported: the first hostname
    is the primary (its set is what the rule references); the rest
    are registered as tap-alias secondaries so shorewalld's tap
    pipeline routes their DNS answers into the primary's set.  This
    mirrors ``dnsr:`` multi-host semantics but without active pull
    resolution — ``dnsr_registry`` records the group with
    ``pull_enabled=False``.

    The zone prefix (if any) and negation marker (wherever it sat)
    are preserved verbatim on the rewritten sentinel so
    ``_parse_zone_spec`` and ``_add_rule`` downstream handle it
    with their existing codepaths.

    Side-effect: registers the canonicalised hostname(s) with
    ``registry`` so the emitter later produces matching set
    declarations.  Invalid hostnames are left untouched — the
    caller's existing parser will reject them with a syntactic
    error further down the line.
    """
    prefix = ""
    body = spec
    sentinel_negate = ""

    if body.startswith("dns:"):
        host_str = body[4:]
    elif body.startswith("!dns:"):
        sentinel_negate = "!"
        host_str = body[5:]
    else:
        # ``zone:[!]dns:hostname`` — split off the zone prefix at the
        # first colon. What follows is either ``dns:host`` or
        # ``!dns:host``.
        colon = body.find(":")
        if colon < 0:
            return spec
        prefix = body[: colon + 1]
        rest = body[colon + 1:]
        if rest.startswith("dns:"):
            host_str = rest[4:]
        elif rest.startswith("!dns:"):
            sentinel_negate = "!"
            host_str = rest[5:]
        else:
            return spec

    # Strip any ipv6 angle brackets — grammatically legal for DNS
    # tokens even though they're nonsensical.
    host_str = host_str.rstrip(">").lstrip("<")
    raw_hosts = [h.strip() for h in host_str.split(",") if h.strip()]
    if not raw_hosts:
        return spec
    for h in raw_hosts:
        if not is_valid_hostname(h):
            return spec

    qnames = [canonical_qname(h) for h in raw_hosts]
    primary = qnames[0]

    # Primary always materialises the nft set; secondaries only enter
    # the allowlist so the tap filter forwards them through a tracker
    # alias into the primary's set.
    registry.add_from_rule(primary, declare_set=True)
    for qn in qnames[1:]:
        registry.add_from_rule(qn, declare_set=False)

    # Multi-host dns: needs the same tap-alias plumbing as dnsr: so
    # the daemon installs add_qname_alias for the secondaries. Record
    # the group in dnsr_registry with pull_enabled=False — same data
    # shape, no active resolution. Single-host dns: is a pure set
    # reference and doesn't need an alias entry.
    if len(qnames) > 1 and dnsr_registry is not None:
        dnsr_registry.add_from_rule(primary, qnames, pull_enabled=False)

    set_name = qname_to_set_name(primary, family)
    return f"{prefix}{sentinel_negate}+{set_name}"


def _spec_contains_dnsr_token(spec: str) -> bool:
    """Cheap test for ``dnsr:HOSTNAME[,HOSTNAME…]`` embedded in a spec column.

    Mirrors :func:`_spec_contains_dns_token` but for the pull-resolver
    variant.  Covers bare, negated, zone-prefixed, and zone+negation forms.
    """
    return (
        spec.startswith("dnsr:")
        or spec.startswith("!dnsr:")
        or ":dnsr:" in spec
        or ":!dnsr:" in spec
    )


def _rewrite_dnsr_spec(
    spec: str,
    dns_registry: DnsSetRegistry,
    dnsr_registry: DnsrRegistry,
    family: str,
) -> str:
    """Replace a ``dnsr:host[,host…]`` token with the same sentinel as ``dns:``.

    The primary hostname (first in the comma list) is registered in
    ``dns_registry`` so the emitter declares the ``dns_<primary>_v4/v6``
    sets.  The full hostname list is recorded in ``dnsr_registry`` so the
    daemon's PullResolver knows which hostnames to actively resolve into
    that set.

    Secondary hostnames are also registered individually in ``dns_registry``
    so the tap pipeline's qname-filter accepts their DNS answers and
    routes them to the same set via tracker aliases.

    The returned sentinel is identical to a ``dns:primary`` rewrite
    (``+dns_<primary>_<family>``), so the downstream IR and emitter need
    no changes.
    """
    prefix = ""
    body = spec
    sentinel_negate = ""

    if body.startswith("dnsr:"):
        host_str = body[5:]
    elif body.startswith("!dnsr:"):
        sentinel_negate = "!"
        host_str = body[6:]
    else:
        colon = body.find(":")
        if colon < 0:
            return spec
        prefix = body[: colon + 1]
        rest = body[colon + 1:]
        if rest.startswith("dnsr:"):
            host_str = rest[5:]
        elif rest.startswith("!dnsr:"):
            sentinel_negate = "!"
            host_str = rest[6:]
        else:
            return spec

    host_str = host_str.rstrip(">").lstrip("<")
    raw_hosts = [h.strip() for h in host_str.split(",") if h.strip()]
    if not raw_hosts:
        return spec
    for h in raw_hosts:
        if not is_valid_hostname(h):
            return spec

    qnames = [canonical_qname(h) for h in raw_hosts]
    primary = qnames[0]

    # Primary materialises the nft set; secondaries only enter the
    # allowlist so the tap filter passes their answers through the
    # tracker alias into the primary's set.
    dns_registry.add_from_rule(primary, declare_set=True)
    for qn in qnames[1:]:
        dns_registry.add_from_rule(qn, declare_set=False)

    # Record the full pull-resolver group (primary + secondaries).
    dnsr_registry.add_from_rule(primary, qnames)

    set_name = qname_to_set_name(primary, family)
    return f"{prefix}{sentinel_negate}+{set_name}"


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

        # DNS-token pre-pass: if SOURCE or DEST carries a ``dns:HOST`` or
        # ``dnsr:HOST[,HOST…]`` token, clone the rule into two
        # family-specific variants.  Each clone gets rewritten sentinels
        # (``+dns_*_v4`` / ``+dns_*_v6``) so the downstream pipeline never
        # sees raw hostnames.  Both rewriters are applied sequentially; each
        # is a no-op when its token type is absent.
        _src_has_dns = _spec_contains_dns_token(source_spec_raw)
        _dst_has_dns = _spec_contains_dns_token(dest_spec_raw)
        _src_has_dnsr = _spec_contains_dnsr_token(source_spec_raw)
        _dst_has_dnsr = _spec_contains_dnsr_token(dest_spec_raw)
        if _src_has_dns or _dst_has_dns or _src_has_dnsr or _dst_has_dnsr:
            for family in ("v4", "v6"):
                new_cols = list(cols)
                src = _rewrite_dns_spec(
                    source_spec_raw, ir.dns_registry, family,
                    ir.dnsr_registry)
                src = _rewrite_dnsr_spec(
                    src, ir.dns_registry, ir.dnsr_registry, family)
                new_cols[1] = src
                if len(new_cols) > 2:
                    dst = _rewrite_dns_spec(
                        dest_spec_raw, ir.dns_registry, family,
                        ir.dnsr_registry)
                    dst = _rewrite_dnsr_spec(
                        dst, ir.dns_registry, ir.dnsr_registry, family)
                    new_cols[2] = dst
                elif _dst_has_dns or _dst_has_dnsr:
                    dst = _rewrite_dns_spec(
                        dest_spec_raw, ir.dns_registry, family,
                        ir.dnsr_registry)
                    dst = _rewrite_dnsr_spec(
                        dst, ir.dns_registry, ir.dnsr_registry, family)
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

            # Symmetric optimisation for DROP/REJECT: a rule like
            # `DROP:$LOG customer-a any` expands into every customer-a→X chain.
            # If the chain's policy is *also* drop-class, the inline
            # rule is redundant — and worse, when it lands mid-chain
            # (because file order has it BEFORE later `all → adm:host`
            # accept rules) it shadows everything that follows. The
            # iptables backend simply omits these rules; we mirror
            # that behaviour. Only triggers for catch-all expansions
            # without any host/proto/port narrowing — explicit
            # `customer-a→adm DROP` stays in the chain.
            drop_like = (Verdict.DROP, Verdict.REJECT)
            chain_drops = chain.policy in drop_like
            rule_is_drop_like = verdict in drop_like
            if (is_all_expansion and rule_is_drop_like and chain_drops
                    and not verdict_args
                    and not src_addrs and not dst_addrs
                    and not proto and not dport and not sport
                    and not origdest and not headers
                    and not mark and not connlimit and not user
                    and not time_match and not switch and not helper):
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
                elif clean_addr.startswith("+dns_") and clean_addr.endswith("_v6"):
                    # DNS-backed set sentinel produced by the pre-pass
                    # in _process_rules. Force ip6 family; bare name
                    # has no colons, so _is_ipv6 would misclassify.
                    rule.matches.append(Match(
                        field="ip6 saddr", value=clean_addr, negate=negate))
                    has_v6_addr = True
                elif clean_addr.startswith("+dns_") and clean_addr.endswith("_v4"):
                    rule.matches.append(Match(
                        field="ip saddr", value=clean_addr, negate=negate))
                    has_v4_addr = True
                elif _is_ipv6(clean_addr):
                    rule.matches.append(Match(field="ip6 saddr", value=clean_addr, negate=negate))
                    has_v6_addr = True
                else:
                    rule.matches.append(Match(field="ip saddr", value=clean_addr, negate=negate))
                    has_v4_addr = True

            if dst_addrs:
                negate = dst_addrs.startswith("!")
                clean_addr = dst_addrs.lstrip("!")
                if clean_addr.startswith("+dns_") and clean_addr.endswith("_v6"):
                    rule.matches.append(Match(
                        field="ip6 daddr", value=clean_addr, negate=negate))
                    has_v6_addr = True
                elif clean_addr.startswith("+dns_") and clean_addr.endswith("_v4"):
                    rule.matches.append(Match(
                        field="ip daddr", value=clean_addr, negate=negate))
                    has_v4_addr = True
                elif _is_ipv6(clean_addr):
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


_ROUTESTOPPED_VALID_OPTIONS = {
    "routeback", "source", "dest", "critical", "notrack",
}


def _is_ipv6_addr(host: str) -> bool:
    """Heuristic: does this host token look like an IPv6 literal/CIDR?"""
    h = host.strip()
    if not h:
        return False
    addr = h.split("/", 1)[0]
    return ":" in addr


def _process_routestopped(ir: FirewallIR, routestopped: list[ConfigLine],
                          settings: dict[str, str] | None = None) -> None:
    """Process routestopped rules.

    Renders Shorewall's full ``routestopped`` semantics into the
    standalone ``inet shorewall_stopped`` table (built by
    :func:`shorewall_nft.nft.emitter.emit_stopped_nft`). Loaded by
    ``shorewall-nft stop`` after deleting the running ruleset.

    Format::

        INTERFACE  HOST(S)  OPTIONS  PROTO  DPORT  SPORT

    Supported OPTIONS (comma-separated):
      * ``routeback`` — also forward between hosts on the same iface
      * ``source``    — only ingress (no matching output rule)
      * ``dest``      — only egress  (no matching input rule)
      * ``critical``  — recorded but currently a no-op (we don't ship
        a ``clear`` command yet)
      * ``notrack``   — disables conntrack for this iface/host via a
        ``stopped-raw-prerouting`` chain at priority raw

    Global setting ``ROUTESTOPPED_OPEN=Yes`` opens every interface
    listed in routestopped wide (no host/proto filtering) — matching
    Shorewall's "panic but keep the network up" mode.

    Base chain layout:
      * stopped-input    — policy DROP, ACCEPT for matching traffic
      * stopped-output   — policy DROP, ACCEPT for matching traffic
      * stopped-forward  — policy DROP, ACCEPT for routeback pairs
      * stopped-raw-prerouting — only present if any rule sets notrack

    Loopback ACCEPT and ``ct state established,related`` are added
    unconditionally so local services and active mgmt sessions
    survive a stop window.
    """
    settings = settings or {}
    open_mode = settings.get("ROUTESTOPPED_OPEN", "No").lower() in (
        "yes", "1", "true")

    stopped_input = Chain(
        name="stopped-input",
        chain_type=ChainType.FILTER,
        hook=Hook.INPUT,
        priority=0,
        policy=Verdict.DROP,
    )
    stopped_output = Chain(
        name="stopped-output",
        chain_type=ChainType.FILTER,
        hook=Hook.OUTPUT,
        priority=0,
        policy=Verdict.DROP,
    )
    stopped_forward = Chain(
        name="stopped-forward",
        chain_type=ChainType.FILTER,
        hook=Hook.FORWARD,
        priority=0,
        policy=Verdict.DROP,
    )

    # Loopback always passes — otherwise local services break.
    lo_in = Rule(verdict=Verdict.ACCEPT)
    lo_in.matches.append(Match(field="iifname", value="lo"))
    stopped_input.rules.append(lo_in)
    lo_out = Rule(verdict=Verdict.ACCEPT)
    lo_out.matches.append(Match(field="oifname", value="lo"))
    stopped_output.rules.append(lo_out)

    # Established/related survive — otherwise short-lived stop windows
    # would tear down every active mgmt session.
    est_in = Rule(verdict=Verdict.ACCEPT)
    est_in.matches.append(Match(field="ct state", value="established,related"))
    stopped_input.rules.append(est_in)
    est_out = Rule(verdict=Verdict.ACCEPT)
    est_out.matches.append(Match(field="ct state", value="established,related"))
    stopped_output.rules.append(est_out)

    ir.stopped_chains[stopped_input.name] = stopped_input
    ir.stopped_chains[stopped_output.name] = stopped_output
    ir.stopped_chains[stopped_forward.name] = stopped_forward

    # notrack chain is added lazily — only if any rule needs it.
    stopped_raw: Chain | None = None

    def _saddr_field(host: str) -> str:
        return "ip6 saddr" if _is_ipv6_addr(host) else "ip saddr"

    def _daddr_field(host: str) -> str:
        return "ip6 daddr" if _is_ipv6_addr(host) else "ip daddr"

    def _add_proto(rule: Rule, proto: str | None,
                   dport: str | None, sport: str | None) -> None:
        if not proto:
            return
        rule.matches.append(Match(field="meta l4proto", value=proto))
        if dport:
            rule.matches.append(Match(field=f"{proto} dport", value=dport))
        if sport:
            rule.matches.append(Match(field=f"{proto} sport", value=sport))

    for line in routestopped:
        cols = line.columns
        if not cols:
            continue

        iface = cols[0]
        hosts = cols[1] if len(cols) > 1 and cols[1] != "-" else None
        options_raw = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        sport = cols[5] if len(cols) > 5 and cols[5] != "-" else None

        opts = {o.strip() for o in options_raw.split(",") if o.strip()}
        unknown = opts - _ROUTESTOPPED_VALID_OPTIONS
        if unknown:
            # Best effort: keep going, but warn — matches Shorewall's
            # behaviour of accepting and ignoring unknown options.
            import warnings
            warnings.warn(
                f"routestopped {line.file}:{line.lineno}: unknown "
                f"option(s) {sorted(unknown)} — ignored",
                stacklevel=2)

        emit_in = "dest" not in opts
        emit_out = "source" not in opts
        do_routeback = "routeback" in opts
        do_notrack = "notrack" in opts

        # ROUTESTOPPED_OPEN: collapse to wildcard accept on this
        # interface, ignoring host/proto filtering. The single rule
        # per direction supersedes everything else for this iface.
        if open_mode:
            if emit_in:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="iifname", value=iface))
                stopped_input.rules.append(r)
            if emit_out:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="oifname", value=iface))
                stopped_output.rules.append(r)
            if do_routeback:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="iifname", value=iface))
                r.matches.append(Match(field="oifname", value=iface))
                stopped_forward.rules.append(r)
            if do_notrack:
                if stopped_raw is None:
                    stopped_raw = Chain(
                        name="stopped-raw-prerouting",
                        chain_type=ChainType.FILTER,
                        hook=Hook.PREROUTING,
                        priority=-300,  # raw
                        policy=None,
                    )
                    ir.stopped_chains[stopped_raw.name] = stopped_raw
                r = Rule(verdict=Verdict.ACCEPT, verdict_args="notrack:")
                r.matches.append(Match(field="iifname", value=iface))
                stopped_raw.rules.append(r)
            continue

        host_list: list[str | None]
        if hosts:
            host_list = [h.strip() for h in hosts.split(",") if h.strip()]
        else:
            host_list = [None]  # iface-wide

        for h in host_list:
            if emit_in:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="iifname", value=iface))
                if h:
                    r.matches.append(Match(field=_saddr_field(h), value=h))
                _add_proto(r, proto, dport, sport)
                stopped_input.rules.append(r)

            if emit_out:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="oifname", value=iface))
                if h:
                    r.matches.append(Match(field=_daddr_field(h), value=h))
                # Output direction swaps src/dst port semantics —
                # keep dport on dport (it's the listening port on
                # the host we're talking to) and sport on sport.
                _add_proto(r, proto, dport, sport)
                stopped_output.rules.append(r)

            if do_routeback:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="iifname", value=iface))
                r.matches.append(Match(field="oifname", value=iface))
                if h:
                    # transit between two hosts on the same iface —
                    # the listed host can be either side, so we emit
                    # one rule per side instead of constraining both.
                    r.matches.append(Match(field=_daddr_field(h), value=h))
                _add_proto(r, proto, dport, sport)
                stopped_forward.rules.append(r)

            if do_notrack:
                if stopped_raw is None:
                    stopped_raw = Chain(
                        name="stopped-raw-prerouting",
                        chain_type=ChainType.FILTER,
                        hook=Hook.PREROUTING,
                        priority=-300,  # raw
                        policy=None,
                    )
                    ir.stopped_chains[stopped_raw.name] = stopped_raw
                r = Rule(verdict=Verdict.ACCEPT, verdict_args="notrack:")
                r.matches.append(Match(field="iifname", value=iface))
                if h:
                    r.matches.append(Match(field=_saddr_field(h), value=h))
                _add_proto(r, proto, dport, sport)
                stopped_raw.rules.append(r)


def _process_scfilter(ir: FirewallIR, scfilter_lines: list[ConfigLine]) -> None:
    """Process the ``scfilter`` config file (source CIDR sanity filter).

    scfilter declares per-interface allow-lists for source IPs:
    any packet whose source address does NOT fall in the listed
    CIDRs gets dropped at ingress. Useful as an anti-spoof gate
    on uplinks where you know the legitimate source ranges.

    We emit drop rules at the top of the forward + input base
    chains (so they fire before any zone dispatch). The simpler
    form is one rule per (iface, !cidr-list) tuple:

        iifname X ip saddr != { allowed cidrs } drop

    Format::

        INTERFACE  HOST(S)  OPTIONS
    """
    if not scfilter_lines:
        return

    # Insert at the top of the forward + input chains. Both base
    # chains exist by now (created in _create_base_chains).
    forward = ir.chains.get("forward")
    inp = ir.chains.get("input")

    inserts: list[Rule] = []
    for line in scfilter_lines:
        cols = line.columns
        if not cols:
            continue
        iface = cols[0]
        hosts_raw = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        if not hosts_raw:
            continue
        hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]
        v4 = [h for h in hosts if not _is_ipv6(h)]
        v6 = [h for h in hosts if _is_ipv6(h)]

        if v4:
            r = Rule(verdict=Verdict.DROP)
            r.matches.append(Match(field="iifname", value=iface))
            r.matches.append(Match(
                field="ip saddr",
                value="{ " + ", ".join(v4) + " }",
                negate=True))
            inserts.append(r)
        if v6:
            r = Rule(verdict=Verdict.DROP)
            r.matches.append(Match(field="iifname", value=iface))
            r.matches.append(Match(
                field="ip6 saddr",
                value="{ " + ", ".join(v6) + " }",
                negate=True))
            inserts.append(r)

    # Prepend so the sanity drop fires before zone dispatch.
    if forward:
        forward.rules = inserts + list(forward.rules)
    if inp:
        inp.rules = inserts + list(inp.rules)


def _process_ecn(ir: FirewallIR, ecn_lines: list[ConfigLine]) -> None:
    """Process the ``ecn`` config file (clear ECN bits per iface/host).

    Shorewall's ``ecn`` file lists (interface, host) tuples whose
    TCP traffic should have ECN bits cleared — historically used
    when a buggy peer rejects ECN-marked packets. The original
    implementation used iptables' ``-j ECN --ecn-tcp-remove``
    target. nftables expresses the same with::

        ip dscp set ip dscp and 0xfc

    on the matching tcp flow (DSCP field is 6 bits, ECN is the
    low 2 bits — masking with 0xfc clears them). The rule lands
    in the mangle-postrouting chain so the change applies just
    before the packet leaves the box.

    Format::

        INTERFACE  HOST(S)
    """
    if not ecn_lines:
        return

    # Lazily create the mangle-postrouting chain.
    chain_name = "mangle-postrouting"
    if chain_name not in ir.chains:
        ir.add_chain(Chain(
            name=chain_name,
            chain_type=ChainType.ROUTE,
            hook=Hook.POSTROUTING,
            priority=-150,  # mangle
        ))
    chain = ir.chains[chain_name]

    for line in ecn_lines:
        cols = line.columns
        if not cols:
            continue
        iface = cols[0]
        hosts_raw = cols[1] if len(cols) > 1 and cols[1] != "-" else None

        hosts: list[str | None]
        if hosts_raw:
            hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]
        else:
            hosts = [None]

        for h in hosts:
            r = Rule(
                verdict=Verdict.ACCEPT,
                verdict_args="ecn_clear:",
            )
            r.matches.append(Match(field="oifname", value=iface))
            r.matches.append(Match(field="meta l4proto", value="tcp"))
            if h:
                field = "ip6 daddr" if _is_ipv6(h) else "ip daddr"
                r.matches.append(Match(field=field, value=h))
            chain.rules.append(r)


def _process_nfacct(ir: FirewallIR, nfacct_lines: list[ConfigLine]) -> None:
    """Process the ``nfacct`` config file into named counter objects.

    Shorewall's ``nfacct`` file declares named accounting objects
    that the kernel maintains via the ``nfnetlink_acct`` module.
    The closest nft equivalent is a named counter object —
    ``counter <name> { packets N bytes M }`` — which can be
    referenced from rules with ``counter name "<name>"``.

    We map nfacct rows onto nft named counters and store them in
    ``ir.nfacct_counters`` for the emitter to declare at the top
    of the inet shorewall table. Initial values from the file
    survive the table flush so reload-and-keep-counts is at
    least theoretically possible (in practice nft resets named
    counters on table flush; the field is here to capture intent
    if/when we wire a counter snapshot/restore path through
    libnftables).

    Format::

        NAME  [PACKETS  [BYTES]]
    """
    for line in nfacct_lines:
        cols = line.columns
        if not cols:
            continue
        name = cols[0]
        try:
            packets = int(cols[1]) if len(cols) > 1 and cols[1] != "-" else 0
        except ValueError:
            packets = 0
        try:
            byte_count = int(cols[2]) if len(cols) > 2 and cols[2] != "-" else 0
        except ValueError:
            byte_count = 0
        ir.nfacct_counters[name] = (packets, byte_count)


def _process_arprules(ir: FirewallIR, arprules: list[ConfigLine]) -> None:
    """Process the ``arprules`` config file into the arp filter table.

    arprules sit at OSI layer 2.5 — they match on ARP packets, not
    IP traffic. nftables exposes them via a separate table family
    (``table arp filter``) with its own input/output base chains
    that hook the kernel's ARP path.

    Format::

        ACTION  SOURCE  DEST  INTERFACE  MAC

    where SOURCE is the ARP sender IP, DEST is the ARP target IP,
    INTERFACE is the iface, and MAC is the sender Ethernet
    address (optional). The chains live in ``ir.arp_chains`` and
    are emitted as a standalone ``table arp filter`` block by
    :func:`shorewall_nft.nft.emitter.emit_arp_nft`, included by
    the main script when present.

    Supported actions: ACCEPT, DROP, REJECT (mapped onto an arp
    drop with ICMP-host-unreachable analogue is not possible —
    REJECT in the arp family just becomes a drop).
    """
    arp_input = Chain(
        name="arp-input",
        chain_type=ChainType.FILTER,
        hook=Hook.INPUT,
        priority=0,
        policy=Verdict.ACCEPT,
    )
    arp_output = Chain(
        name="arp-output",
        chain_type=ChainType.FILTER,
        hook=Hook.OUTPUT,
        priority=0,
        policy=Verdict.ACCEPT,
    )
    ir.arp_chains[arp_input.name] = arp_input
    ir.arp_chains[arp_output.name] = arp_output

    for line in arprules:
        cols = line.columns
        if not cols:
            continue
        action_raw = cols[0]
        source = cols[1] if len(cols) > 1 and cols[1] != "-" else None
        dest = cols[2] if len(cols) > 2 and cols[2] != "-" else None
        iface = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        mac = cols[4] if len(cols) > 4 and cols[4] != "-" else None

        action = action_raw.upper().split("(")[0].rstrip("+")
        if action in ("ACCEPT", "ACCEPT_LOG"):
            verdict = Verdict.ACCEPT
        elif action in ("DROP", "DROP_LOG", "REJECT", "DROP_DEFAULT"):
            verdict = Verdict.DROP
        else:
            import warnings
            warnings.warn(
                f"arprules {line.file}:{line.lineno}: unsupported "
                f"action {action_raw!r} — skipped", stacklevel=2)
            continue

        # Direction inference: a rule whose only constraint is the
        # ARP sender IP defaults to input (we received an ARP from
        # someone). A rule with a target IP (dest) and no other
        # qualifier is also input — the kernel saw a who-has for
        # that IP. Output rules are rare and we treat any rule
        # with explicit `out:` prefix in the action as output.
        # Most arprules deployments only need input, so default
        # there.
        chain = arp_input

        rule = Rule(verdict=verdict)
        if iface:
            rule.matches.append(Match(field="meta iifname", value=iface))
        if source:
            # ARP sender IP
            rule.matches.append(Match(field="arp saddr ip", value=source))
        if dest:
            # ARP target IP
            rule.matches.append(Match(field="arp daddr ip", value=dest))
        if mac:
            mac_norm = mac.lstrip("~").replace("-", ":").lower()
            rule.matches.append(
                Match(field="arp saddr ether", value=mac_norm))
        chain.rules.append(rule)


def _process_rawnat(ir: FirewallIR, rawnat_lines: list[ConfigLine],
                    zones: ZoneModel) -> None:
    """Process the ``rawnat`` config file.

    Shorewall's ``rawnat`` lets you put rules in the iptables raw
    PREROUTING chain — i.e. they fire **before** conntrack and any
    DNAT/SNAT in the regular nat table. The supported actions are
    things like ``NOTRACK`` and ``ACCEPT`` plus the rare early-DNAT
    ``DNAT`` form (only useful with conntrack zones / notrack
    follow-up rules).

    For us this slots cleanly onto the existing
    ``raw-prerouting`` / ``raw-output`` chains created by the
    ``notrack`` processor — we re-create them lazily here so a
    config that uses ONLY ``rawnat`` (no notrack file) still gets
    the chains.

    Format::

        ACTION  SOURCE  DEST  PROTO  DPORT  SPORT  USER

    SOURCE / DEST are zone:host specs. ``$FW`` source routes the
    rule into ``raw-output``; everything else into
    ``raw-prerouting``.
    """
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

    fw = zones.firewall_zone

    for line in rawnat_lines:
        cols = line.columns
        if not cols:
            continue
        action_raw = cols[0]
        source_spec = cols[1] if len(cols) > 1 and cols[1] != "-" else "all"
        dest_spec = cols[2] if len(cols) > 2 and cols[2] != "-" else "all"
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        sport = cols[5] if len(cols) > 5 and cols[5] != "-" else None

        action = action_raw.upper().split("(")[0].rstrip("+")

        # Map the action onto a (verdict, verdict_args) pair. We
        # support NOTRACK, ACCEPT, DROP — the only ones that make
        # any sense in the raw table. Everything else gets a
        # warning and is skipped.
        if action == "NOTRACK":
            verdict = Verdict.ACCEPT
            verdict_args: str | None = "notrack:"
        elif action == "ACCEPT":
            verdict = Verdict.ACCEPT
            verdict_args = None
        elif action == "DROP":
            verdict = Verdict.DROP
            verdict_args = None
        else:
            import warnings
            warnings.warn(
                f"rawnat {line.file}:{line.lineno}: unsupported "
                f"action {action_raw!r} — skipped", stacklevel=2)
            continue

        src_zone, src_addr = _parse_zone_spec(source_spec, zones)
        dst_zone, dst_addr = _parse_zone_spec(dest_spec, zones)

        chain = (ir.chains["raw-output"] if src_zone == fw
                 else ir.chains["raw-prerouting"])

        rule = Rule(
            verdict=verdict,
            verdict_args=verdict_args,
            source_file=line.file,
            source_line=line.lineno,
            source_raw=line.raw,
        )

        # iif/oif from zone interfaces (skip $FW + the all/any
        # catchalls — those leave the chain unrestricted).
        def _zone_iface_match(zone_name: str | None, field: str) -> None:
            if not zone_name or zone_name == fw:
                return
            if zone_name in ("all", "any"):
                return
            z = zones.zones.get(zone_name)
            if not z:
                return
            iface_names = [i.name for i in z.interfaces]
            if not iface_names:
                return
            if len(iface_names) == 1:
                rule.matches.append(Match(
                    field=field, value=iface_names[0]))
            else:
                rule.matches.append(Match(
                    field=field,
                    value="{ " + ", ".join(
                        f'"{i}"' for i in sorted(iface_names)) + " }"))

        _zone_iface_match(src_zone, "iifname")
        _zone_iface_match(dst_zone, "oifname")

        if src_addr:
            field = "ip6 saddr" if _is_ipv6(src_addr) else "ip saddr"
            rule.matches.append(Match(field=field, value=src_addr))
        if dst_addr:
            field = "ip6 daddr" if _is_ipv6(dst_addr) else "ip daddr"
            rule.matches.append(Match(field=field, value=dst_addr))
        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if dport:
                rule.matches.append(Match(field=f"{proto} dport", value=dport))
            if sport:
                rule.matches.append(Match(field=f"{proto} sport", value=sport))

        chain.rules.append(rule)


def _process_stoppedrules(ir: FirewallIR, stoppedrules: list[ConfigLine],
                          zones: ZoneModel) -> None:
    """Process the modern ``stoppedrules`` file (Shorewall ≥ 5.x).

    The legacy ``routestopped`` file (handled by
    :func:`_process_routestopped`) only knew interface + host
    tuples. ``stoppedrules`` is a full rule format::

        ACTION  SOURCE  DEST  PROTO  DPORT  SPORT  ORIGDEST

    where ACTION is one of ``ACCEPT``, ``DROP``, ``NOTRACK``,
    ``ACCEPT+`` (an alias). SOURCE / DEST are zone:host specs
    just like the regular ``rules`` file. The rules are emitted
    into the same standalone ``inet shorewall_stopped`` table that
    routestopped uses, so a config can mix both files.

    Routing rules into base chains:

    * SOURCE = ``$FW`` → output (the firewall sending traffic)
    * DEST   = ``$FW`` → input (traffic destined for the firewall)
    * neither $FW       → forward (transit traffic)

    NOTRACK lands in ``stopped-raw-prerouting`` regardless of the
    src/dst direction (it's a raw-table affair).

    The base chains are created lazily — if neither routestopped
    nor stoppedrules is configured, no stopped table is emitted.
    """
    # Make sure the standard input/output/forward base chains
    # exist (routestopped may not have run).
    def _ensure(name: str, hook: Hook) -> Chain:
        ch = ir.stopped_chains.get(name)
        if ch is None:
            ch = Chain(
                name=name,
                chain_type=ChainType.FILTER,
                hook=hook,
                priority=0,
                policy=Verdict.DROP,
            )
            ir.stopped_chains[name] = ch
            # Loopback + ct established/related survive — same
            # baseline as routestopped.
            if name == "stopped-input":
                lo = Rule(verdict=Verdict.ACCEPT)
                lo.matches.append(Match(field="iifname", value="lo"))
                ch.rules.append(lo)
                est = Rule(verdict=Verdict.ACCEPT)
                est.matches.append(
                    Match(field="ct state", value="established,related"))
                ch.rules.append(est)
            elif name == "stopped-output":
                lo = Rule(verdict=Verdict.ACCEPT)
                lo.matches.append(Match(field="oifname", value="lo"))
                ch.rules.append(lo)
                est = Rule(verdict=Verdict.ACCEPT)
                est.matches.append(
                    Match(field="ct state", value="established,related"))
                ch.rules.append(est)
        return ch

    stopped_raw: Chain | None = ir.stopped_chains.get("stopped-raw-prerouting")

    fw = zones.firewall_zone

    for line in stoppedrules:
        cols = line.columns
        if not cols:
            continue
        target_raw = cols[0]
        source_spec = cols[1] if len(cols) > 1 and cols[1] != "-" else "all"
        dest_spec = cols[2] if len(cols) > 2 and cols[2] != "-" else "all"
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        sport = cols[5] if len(cols) > 5 and cols[5] != "-" else None

        target = target_raw.upper().split("(")[0].rstrip("+")
        if target == "ACCEPT":
            verdict = Verdict.ACCEPT
            verdict_args: str | None = None
        elif target == "DROP":
            verdict = Verdict.DROP
            verdict_args = None
        elif target == "REJECT":
            verdict = Verdict.REJECT
            verdict_args = None
        elif target == "NOTRACK":
            verdict = Verdict.ACCEPT
            verdict_args = "notrack:"
        else:
            import warnings
            warnings.warn(
                f"stoppedrules {line.file}:{line.lineno}: unsupported "
                f"target {target_raw!r} — skipped", stacklevel=2)
            continue

        src_zone, src_addr = _parse_zone_spec(source_spec, zones)
        dst_zone, dst_addr = _parse_zone_spec(dest_spec, zones)

        is_v6_src = src_addr is not None and _is_ipv6(src_addr)
        is_v6_dst = dst_addr is not None and _is_ipv6(dst_addr)

        def _make_match(field: str, val: str) -> Match:
            return Match(field=field, value=val)

        def _add_proto_to(rule: Rule) -> None:
            if proto:
                rule.matches.append(Match(field="meta l4proto", value=proto))
                if dport:
                    rule.matches.append(
                        Match(field=f"{proto} dport", value=dport))
                if sport:
                    rule.matches.append(
                        Match(field=f"{proto} sport", value=sport))

        # NOTRACK always lands in the raw-prerouting chain
        if verdict_args == "notrack:":
            if stopped_raw is None:
                stopped_raw = Chain(
                    name="stopped-raw-prerouting",
                    chain_type=ChainType.FILTER,
                    hook=Hook.PREROUTING,
                    priority=-300,
                    policy=None,
                )
                ir.stopped_chains[stopped_raw.name] = stopped_raw
            r = Rule(verdict=Verdict.ACCEPT, verdict_args="notrack:")
            if src_addr:
                r.matches.append(_make_match(
                    "ip6 saddr" if is_v6_src else "ip saddr", src_addr))
            if dst_addr:
                r.matches.append(_make_match(
                    "ip6 daddr" if is_v6_dst else "ip daddr", dst_addr))
            _add_proto_to(r)
            stopped_raw.rules.append(r)
            continue

        # Pick base chain by direction
        if src_zone == fw and dst_zone == fw:
            chains = [_ensure("stopped-output", Hook.OUTPUT)]
        elif src_zone == fw:
            chains = [_ensure("stopped-output", Hook.OUTPUT)]
        elif dst_zone == fw:
            chains = [_ensure("stopped-input", Hook.INPUT)]
        else:
            chains = [_ensure("stopped-forward", Hook.FORWARD)]

        for ch in chains:
            r = Rule(verdict=verdict, verdict_args=verdict_args)
            # Translate zone → iifname/oifname when the zone has
            # interfaces. Skip the firewall zone (no iface match).
            if src_zone and src_zone != fw and src_zone in zones.zones:
                z = zones.zones[src_zone]
                iface_names = [i.name for i in z.interfaces]
                if iface_names:
                    if len(iface_names) == 1:
                        r.matches.append(Match(
                            field="iifname", value=iface_names[0]))
                    else:
                        r.matches.append(Match(
                            field="iifname",
                            value="{ " + ", ".join(
                                f'"{i}"' for i in sorted(iface_names))
                            + " }"))
            if dst_zone and dst_zone != fw and dst_zone in zones.zones:
                z = zones.zones[dst_zone]
                iface_names = [i.name for i in z.interfaces]
                if iface_names:
                    if len(iface_names) == 1:
                        r.matches.append(Match(
                            field="oifname", value=iface_names[0]))
                    else:
                        r.matches.append(Match(
                            field="oifname",
                            value="{ " + ", ".join(
                                f'"{i}"' for i in sorted(iface_names))
                            + " }"))
            if src_addr:
                r.matches.append(_make_match(
                    "ip6 saddr" if is_v6_src else "ip saddr", src_addr))
            if dst_addr:
                r.matches.append(_make_match(
                    "ip6 daddr" if is_v6_dst else "ip daddr", dst_addr))
            _add_proto_to(r)
            ch.rules.append(r)


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
