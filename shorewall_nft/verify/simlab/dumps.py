"""Parse `ip addr show` / `ip route show` output into structured state.

The simlab controller (re-)reads these dumps each time it builds the
test topology so the FW namespace mirrors the real marcant-fw box as
faithfully as possible: same interface list, same MTUs, same
addresses (primary + secondary), same routing table. No hand-rolled
/30s.

Input files are the plain-text dumps taken from the running firewall:

    ip4add     ← `ip addr show`          (v4 addresses + link meta)
    ip4routes  ← `ip route show`         (v4 main table, plus any
                                           alternative tables seen)
    ip6add     ← `ip -6 addr show`
    ip6routes  ← `ip -6 route show table all`

Everything here is pure parsing — no side effects, no pyroute2 calls.
The topology builder in :mod:`simlab.topology` consumes these
dataclasses and applies them to NS_FW.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────
#  Data model
# ─────────────────────────────────────────────────────────────────────


@dataclass
class Address:
    """One inet/inet6 address on an interface."""
    family: int            # 4 or 6
    addr: str              # "217.14.160.75"
    prefixlen: int         # 27
    scope: str = "global"
    secondary: bool = False
    broadcast: str | None = None


@dataclass
class Interface:
    """Parsed interface header + address list."""
    name: str
    index: int
    mtu: int
    flags: frozenset[str]  # e.g. {"BROADCAST","MULTICAST","UP","LOWER_UP"}
    state: str             # "UP" / "DOWN" / "UNKNOWN"
    kind: str              # guessed: "ethernet" / "vlan" / "loopback" / "tun"
    parent: str | None     # for "bond0.10@bond0" → "bond0"
    addrs4: list[Address] = field(default_factory=list)
    addrs6: list[Address] = field(default_factory=list)

    @property
    def is_ether_like(self) -> bool:
        """True if the iface carries Ethernet frames (→ needs TAP in sim)."""
        return self.kind in ("ethernet", "vlan", "bond", "bridge")

    @property
    def is_ptp(self) -> bool:
        """True if L3 point-to-point (tun, ppp, gre, sit) → TUN in sim."""
        return self.kind in ("tun", "ppp", "gre", "sit", "ipip")


@dataclass
class Route:
    """One route entry."""
    family: int             # 4 or 6
    dst: str                # "default" or "10.0.0.0/8" or "1.2.3.4"
    via: str | None = None
    dev: str | None = None
    src: str | None = None
    scope: str | None = None
    proto: str | None = None
    metric: int | None = None
    table: int = 254        # main
    # Unusual types (unreachable/blackhole/prohibit/throw)
    rtype: str = "unicast"


@dataclass
class FwState:
    """Full parsed firewall network state."""
    interfaces: dict[str, Interface] = field(default_factory=dict)
    routes4: list[Route] = field(default_factory=list)
    routes6: list[Route] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────
#  Interface-kind heuristics
# ─────────────────────────────────────────────────────────────────────


def _guess_kind(name: str, flags: frozenset[str]) -> str:
    if "LOOPBACK" in flags:
        return "loopback"
    if name.startswith("lo"):
        return "loopback"
    if name.startswith(("tun", "tap")):
        return "tun"
    if name.startswith("ppp"):
        return "ppp"
    if name.startswith(("gre", "gretap")):
        return "gre"
    if name.startswith("sit"):
        return "sit"
    if name.startswith("ipip"):
        return "ipip"
    if "." in name:                       # bond0.10, eth0.200 → vlan
        return "vlan"
    if name.startswith("br"):
        return "bridge"
    if name.startswith("bond"):
        return "bond"
    if name.startswith("dummy"):
        return "ethernet"  # treat as ether-like for the sim
    return "ethernet"


# ─────────────────────────────────────────────────────────────────────
#  Parsers
# ─────────────────────────────────────────────────────────────────────


_IF_HEADER_RE = re.compile(
    r"^(?P<idx>\d+):\s+"
    r"(?P<name>[\w.\-@]+):\s+"
    r"<(?P<flags>[^>]*)>"
    r".*?mtu\s+(?P<mtu>\d+)"
    r".*?state\s+(?P<state>\w+)"
)
_INET_RE = re.compile(
    r"^\s+inet\s+(?P<addr>\d{1,3}(?:\.\d{1,3}){3})/(?P<plen>\d+)"
    r"(?:\s+brd\s+(?P<brd>\S+))?"
    r"(?:\s+scope\s+(?P<scope>\w+))?"
    r"(?P<secondary>\s+secondary)?"
)
_INET6_RE = re.compile(
    r"^\s+inet6\s+(?P<addr>[0-9a-fA-F:]+)/(?P<plen>\d+)"
    r"(?:\s+scope\s+(?P<scope>\w+))?"
)


def parse_addr_dump(text: str, family: int) -> dict[str, Interface]:
    """Parse `ip addr show` (v4 or v6) into an iface → Interface map."""
    ifaces: dict[str, Interface] = {}
    cur: Interface | None = None
    for line in text.splitlines():
        hm = _IF_HEADER_RE.match(line)
        if hm:
            name = hm.group("name")
            # "bond0.10@bond0" → name=bond0.10, parent=bond0
            parent = None
            if "@" in name:
                name, parent = name.split("@", 1)
            flags = frozenset(hm.group("flags").split(","))
            cur = Interface(
                name=name,
                index=int(hm.group("idx")),
                mtu=int(hm.group("mtu")),
                flags=flags,
                state=hm.group("state"),
                kind=_guess_kind(name, flags),
                parent=parent,
            )
            # Preserve existing interface if we're parsing v6 after v4
            if name in ifaces:
                cur = ifaces[name]
            else:
                ifaces[name] = cur
            continue
        if cur is None:
            continue
        if family == 4:
            m4 = _INET_RE.match(line)
            if m4:
                cur.addrs4.append(Address(
                    family=4,
                    addr=m4.group("addr"),
                    prefixlen=int(m4.group("plen")),
                    scope=m4.group("scope") or "global",
                    secondary=bool(m4.group("secondary")),
                    broadcast=m4.group("brd"),
                ))
                continue
        if family == 6:
            m6 = _INET6_RE.match(line)
            if m6:
                cur.addrs6.append(Address(
                    family=6,
                    addr=m6.group("addr"),
                    prefixlen=int(m6.group("plen")),
                    scope=m6.group("scope") or "global",
                ))
                continue
    return ifaces


_RTYPE_WORDS = {"unreachable", "blackhole", "prohibit", "throw", "local", "broadcast"}


def parse_route_dump(text: str, family: int) -> list[Route]:
    """Parse `ip route show` or `ip -6 route show table all` output."""
    out: list[Route] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("Failed", "#")):
            continue
        tokens = line.split()
        rtype = "unicast"
        if tokens[0] in _RTYPE_WORDS:
            rtype = tokens.pop(0)
        if not tokens:
            continue
        dst = tokens.pop(0)
        route = Route(family=family, dst=dst, rtype=rtype)
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "via" and i + 1 < len(tokens):
                route.via = tokens[i + 1]
                i += 2
            elif tok == "dev" and i + 1 < len(tokens):
                route.dev = tokens[i + 1]
                i += 2
            elif tok == "src" and i + 1 < len(tokens):
                route.src = tokens[i + 1]
                i += 2
            elif tok == "scope" and i + 1 < len(tokens):
                route.scope = tokens[i + 1]
                i += 2
            elif tok == "proto" and i + 1 < len(tokens):
                route.proto = tokens[i + 1]
                i += 2
            elif tok == "metric" and i + 1 < len(tokens):
                try:
                    route.metric = int(tokens[i + 1])
                except ValueError:
                    pass
                i += 2
            elif tok == "table" and i + 1 < len(tokens):
                try:
                    route.table = int(tokens[i + 1])
                except ValueError:
                    # keywords main/local/default
                    route.table = {"main": 254, "local": 255, "default": 253}.get(
                        tokens[i + 1], 254)
                i += 2
            else:
                i += 1
        out.append(route)
    return out


# ─────────────────────────────────────────────────────────────────────
#  Top-level loader
# ─────────────────────────────────────────────────────────────────────


def load_fw_state(
    ip4add: Path,
    ip4routes: Path,
    ip6add: Path | None = None,
    ip6routes: Path | None = None,
) -> FwState:
    """Load the firewall's real network state from the dump files.

    Always re-reads from disk — callers may call this repeatedly to
    pick up fresh dumps. Missing v6 files are tolerated.
    """
    state = FwState()
    ifaces4 = parse_addr_dump(ip4add.read_text(), family=4)
    state.interfaces.update(ifaces4)
    state.routes4 = parse_route_dump(ip4routes.read_text(), family=4)

    if ip6add and ip6add.exists():
        ifaces6 = parse_addr_dump(ip6add.read_text(), family=6)
        for name, iface in ifaces6.items():
            if name in state.interfaces:
                state.interfaces[name].addrs6 = iface.addrs6
            else:
                state.interfaces[name] = iface
    if ip6routes and ip6routes.exists():
        state.routes6 = parse_route_dump(ip6routes.read_text(), family=6)

    return state


def iface_needs_tap(iface: Interface) -> bool:
    """Simulation device type selector.

    Ethernet-like interfaces need a TAP so the FW kernel sees full
    Ethernet frames (ARP, MAC, ethertype). PTP-like interfaces get
    a TUN (L3 only, no link layer).
    """
    return iface.is_ether_like or iface.kind == "loopback"
