"""Ruleset oracle for the simlab random-test plausibility check.

Given a parsed iptables-save dump and a zone-pair chain naming
convention (``<src>2<dst>``), classify an arbitrary test tuple
``(src_zone, dst_zone, src_ip, dst_ip, proto, port)`` into the
verdict the chain-level rules would produce:

    ACCEPT, DROP, REJECT (normalised to DROP),
    UNKNOWN (no rule matched and no default policy we can read)

This is intentionally conservative — we match on the same fields
the triangle verifier uses (saddr, daddr, proto, dport) plus
explicit subnet containment. Rules we don't understand (ipsets,
complex matches) are treated as "not a match" so classify()
falls through to the next rule.

The oracle does NOT handle connection state or chain jumps to
sw_* action chains — for simlab random probes we only care about
"would the direct chain walk permit this packet?". Any more
nuanced check is out of scope (use triangle for full fidelity).
"""

from __future__ import annotations

import ipaddress as _ipaddr
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class OracleVerdict:
    verdict: str                # "ACCEPT" / "DROP" / "UNKNOWN"
    matched_rule_raw: str | None = None
    reason: str = ""


class RulesetOracle:
    """Parses an iptables-save dump once and answers tuple queries.

    Accepts both an iptables-save (IPv4) and an optional ip6tables-save
    (IPv6) dump. :meth:`classify` dispatches to the right table based
    on the ``family`` parameter (4 or 6, default 4).
    """

    def __init__(self, ipt_dump: Path, ip6t_dump: Path | None = None):
        from shorewall_nft.verify.iptables_parser import parse_iptables_save
        self._ipt = parse_iptables_save(ipt_dump)
        self._ip6t = parse_iptables_save(ip6t_dump) if ip6t_dump else None

    # ── oracle ────────────────────────────────────────────────────

    def classify(
        self,
        *,
        src_zone: str,
        dst_zone: str,
        src_ip: str,
        dst_ip: str,
        proto: str,
        port: int | None = None,
        family: int = 4,
    ) -> OracleVerdict:
        """Return the verdict the <src>2<dst> chain would produce.

        ``family`` selects which parsed dump is consulted:
        4 → iptables-save, 6 → ip6tables-save. When the requested
        family's dump was not loaded, returns UNKNOWN.
        """
        tables = self._ip6t if family == 6 else self._ipt
        if tables is None:
            return OracleVerdict("UNKNOWN", None,
                                  f"no dump loaded for family {family}")
        flt = tables.get("filter")
        if flt is None:
            return OracleVerdict("UNKNOWN", None, "no filter table in dump")
        chain_name = f"{src_zone}2{dst_zone}"
        rules = flt.rules.get(chain_name)
        if not rules:
            return OracleVerdict("UNKNOWN", None,
                                  f"no {chain_name} chain")

        for rule in rules:
            # Skip rules whose match predicate we can't evaluate
            # from the parsed fields alone. Without these skips,
            # ``_rule_matches`` treats absent fields as "no check"
            # and the rule short-circuits on every probe, silently
            # wiping out every ACCEPT / DROP expectation below
            # the rule in question.
            #
            # - ``--ctstate`` / ``--ctstatus``: pure conntrack
            #   state rules (est,related accept / invalid drop)
            #   sitting at the top of every zone-pair chain under
            #   FASTACCEPT=No.
            # - ``--match-set`` / ``-m set``: ipset membership
            #   checks. The parser stores the ipset name in
            #   ``rule.raw`` but not in any field ``_rule_matches``
            #   can read, so the rule *looks* unconstrained even
            #   though it really is constrained by set membership.
            #   Skipping is the conservative choice; we don't
            #   have the ipset contents loaded at classify time.
            # - ``-m conntrack --ctorigdst``: original-destination
            #   match (used for pre-DNAT filters). Same reason —
            #   the parser doesn't surface ctorigdst as a field.
            # - ``-m multiport``: parsed, but the parser stores a
            #   comma list in ``rule.dport`` which
            #   ``_port_in_spec`` handles correctly, so multiport
            #   DOES work — no skip needed.
            if "--ctstate" in rule.raw or "--ctstatus" in rule.raw:
                continue
            if "--match-set" in rule.raw or " -m set " in rule.raw:
                continue
            if "--ctorigdst" in rule.raw:
                continue
            if not self._rule_matches(rule, src_ip, dst_ip, proto, port):
                continue
            target = rule.target
            if target == "ACCEPT":
                return OracleVerdict("ACCEPT", rule.raw, "direct accept")
            if target in ("DROP", "REJECT"):
                return OracleVerdict("DROP", rule.raw, f"direct {target}")
            # Jumps to action chains (sw_Reject etc.)
            if target and target.startswith(("sw_Reject", "Reject")):
                return OracleVerdict("DROP", rule.raw, "sw_Reject jump")
            if target and target.startswith(("sw_Drop", "Drop")):
                return OracleVerdict("DROP", rule.raw, "sw_Drop jump")
            # Unknown jump → keep walking
            continue

        # Fall-through: every Shorewall zone-pair chain ends with a
        # ``-g`` to a policy chain (~log108 / Reject / Drop). The
        # policy file effectively guarantees DROP/REJECT for any
        # cross-zone pair that doesn't explicitly accept earlier.
        # Self-zone (e.g. mgmt→mgmt) chains are normally ACCEPT-
        # policy and have an early explicit accept rule, so a
        # fall-through here means we hit nothing matchable —
        # safest default is DROP, matching reality.
        return OracleVerdict("DROP", None,
                              f"{chain_name} fell through to end (policy)")

    # ── matching ──────────────────────────────────────────────────

    def _rule_matches(self, rule, src_ip: str, dst_ip: str,
                      proto: str, port: int | None) -> bool:
        # Protocol check — rules without -p match any protocol.
        # Normalise ICMPv6 aliases: ip6tables stores it as "ipv6-icmp"
        # while our probe generators use "icmpv6". Treat as identical.
        _ICMPV6 = frozenset({"icmpv6", "ipv6-icmp"})
        rule_proto = rule.proto
        if rule_proto in _ICMPV6:
            rule_proto = "icmpv6"
        probe_proto = proto
        if probe_proto in _ICMPV6:
            probe_proto = "icmpv6"
        if rule_proto and rule_proto != probe_proto:
            return False

        # Source address check
        if rule.saddr:
            if not self._ip_in_spec(src_ip, rule.saddr):
                return False

        # Destination address check
        if rule.daddr:
            if not self._ip_in_spec(dst_ip, rule.daddr):
                return False

        # Destination port check (TCP/UDP) or ICMP type check.
        # The iptables parser maps --icmpv6-type / --icmp-type into
        # rule.dport.  Our probes carry port=None for ICMP traffic,
        # so we substitute the well-known echo-request type number
        # (ICMPv4=8, ICMPv6=128) for the comparison.
        effective_port = port
        if effective_port is None and probe_proto in ("icmpv6", "ipv6-icmp"):
            effective_port = 128
        elif effective_port is None and probe_proto == "icmp":
            effective_port = 8
        if effective_port is not None and rule.dport:
            if not self._port_in_spec(effective_port, rule.dport):
                return False
        elif rule.dport and effective_port is None:
            # Rule requires a port, packet has none
            return False

        return True

    @staticmethod
    def _ip_in_spec(ip: str, spec: str) -> bool:
        """True if ``ip`` falls within ``spec`` (address or CIDR)."""
        try:
            addr = _ipaddr.ip_address(ip)
        except ValueError:
            return False
        if spec.startswith(("+", "@")):
            return False  # ipset reference — we don't expand
        # ``ip_network(..., strict=False)`` already accepts both
        # bare addresses and CIDRs. No pre-stripping needed.
        #
        # The old code did ``spec.rstrip("/32").rstrip("/128")`` —
        # that's subtly wrong because ``rstrip`` strips a **set**
        # of characters, not a suffix: ``"46.231.232.0/21".rstrip
        # ("/128")`` peels ``/`` + ``2`` + ``1`` from the right and
        # yields ``"46.231.232.0"``, turning the /21 into a /32.
        # Every rule with a /21 / /20 / /24 / … source or dest in
        # iptables.txt silently stopped matching. Use
        # ``removesuffix`` if a cleanup is ever needed again.
        try:
            net = _ipaddr.ip_network(spec, strict=False)
        except ValueError:
            return False
        try:
            return addr in net
        except TypeError:  # family mismatch
            return False

    @staticmethod
    def _port_in_spec(port: int, spec: str) -> bool:
        """True if ``port`` is listed in ``spec`` (single, comma, range)."""
        spec = spec.strip().strip("{}").strip()
        for tok in spec.replace(" ", "").split(","):
            if not tok:
                continue
            if ":" in tok or "-" in tok:
                sep = ":" if ":" in tok else "-"
                try:
                    lo, hi = tok.split(sep, 1)
                    if int(lo) <= port <= int(hi):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if int(tok) == port:
                        return True
                except ValueError:
                    continue
        return False


# ── random probe generator ────────────────────────────────────────


@dataclass
class RandomProbe:
    src_zone: str
    dst_zone: str
    src_iface: str
    dst_iface: str
    src_ip: str
    dst_ip: str
    proto: str
    port: int | None
    family: int = 4   # IP version: 4 or 6


class RandomProbeGenerator:
    """Pick routable, chain-consistent random probes from FwState + config.

    Every probe is guaranteed to have:
      * src_ip belonging to one of the FW's interface subnets → so
        the FW will forward it instead of dropping it on rp_filter.
      * dst_ip belonging to a (different) FW interface subnet → so
        the forwarding path is non-trivial and the ruleset decides.
      * proto + port picked from a realistic distribution.

    The ``iface_to_zone`` map is needed to classify the picked
    interfaces into zones for the oracle lookup.
    """

    TCP_PORTS = [22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                 1194, 1812, 3128, 3306, 5432, 5900, 8080, 8443]
    UDP_PORTS = [53, 67, 68, 123, 161, 500, 514, 1194, 1812, 1813, 4500]

    def __init__(
        self,
        fw_state,
        iface_to_zone: dict[str, str],
        *,
        seed: int | None = None,
    ):
        self.state = fw_state
        self.iface_to_zone = iface_to_zone
        self.rng = random.Random(seed)
        # Collect every IP the firewall owns (v4 + v6) so _pick_host
        # can avoid them — picking a fw-local IP as src/dst means the
        # kernel treats the packet as a martian source / a packet for
        # itself and short-circuits the forwarding path before the
        # ruleset ever evaluates.
        self._fw_local_ips: set[str] = set()
        for iface in fw_state.interfaces.values():
            for a in getattr(iface, "addrs4", []) or []:
                self._fw_local_ips.add(a.addr)
            for a in getattr(iface, "addrs6", []) or []:
                self._fw_local_ips.add(a.addr)
        # Pre-compute list of (iface, subnet, family) candidates so we
        # only walk parsed state once. Family 4 and 6 candidates are
        # mixed; next() ensures src and dst are always the same family.
        self._candidates: list[tuple[str, Any, int]] = []
        for name, iface in fw_state.interfaces.items():
            if iface.kind == "loopback":
                continue
            if name not in iface_to_zone:
                continue
            # IPv4 subnets
            for a in iface.addrs4:
                if a.scope != "global":
                    continue
                try:
                    net = _ipaddr.ip_network(
                        f"{a.addr}/{a.prefixlen}", strict=False)
                except ValueError:
                    continue
                if net.num_addresses < 4:
                    continue
                self._candidates.append((name, net, 4))
            # IPv6 subnets — global scope only, skip link-local and
            # /128 host routes (no room to pick neighbours from them).
            for a in getattr(iface, "addrs6", []) or []:
                if a.scope != "global":
                    continue
                if a.addr.startswith("fe80::"):
                    continue
                try:
                    net6 = _ipaddr.ip_network(
                        f"{a.addr}/{a.prefixlen}", strict=False)
                except ValueError:
                    continue
                if net6.prefixlen > 120:
                    continue  # subnet too small to pick hosts from
                self._candidates.append((name, net6, 6))

    def next(self) -> RandomProbe | None:
        """Return a fresh random probe, or None if we can't pick one.

        src and dst are always the same IP family so the packet
        builder (v4 vs v6) stays consistent. Each call may produce
        either a v4 or v6 probe depending on which candidates happen
        to be available on the randomly chosen interfaces.
        """
        if len(self._candidates) < 2:
            return None
        src_pick = self.rng.choice(self._candidates)
        src_iface, src_net, family = src_pick
        # Pick a dst from a DIFFERENT interface with the SAME family.
        for _ in range(32):
            dst_pick = self.rng.choice(self._candidates)
            if dst_pick[0] != src_iface and dst_pick[2] == family:
                break
        else:
            return None
        dst_iface, dst_net, _ = dst_pick
        src_ip = str(self._pick_host(src_net))
        dst_ip = str(self._pick_host(dst_net))
        # ICMPv6 for IPv6 probes, plain ICMP for IPv4.
        if family == 6:
            proto = self.rng.choice(["tcp", "udp", "icmpv6"])
        else:
            proto = self.rng.choice(["tcp", "udp", "icmp"])
        port: int | None = None
        if proto == "tcp":
            port = self.rng.choice(self.TCP_PORTS)
        elif proto == "udp":
            port = self.rng.choice(self.UDP_PORTS)
        return RandomProbe(
            src_zone=self.iface_to_zone[src_iface],
            dst_zone=self.iface_to_zone[dst_iface],
            src_iface=src_iface,
            dst_iface=dst_iface,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
            port=port,
            family=family,
        )

    def _pick_host(self, net: _ipaddr.IPv4Network | _ipaddr.IPv6Network
                   ) -> _ipaddr.IPv4Address | _ipaddr.IPv6Address:
        """Return a usable host IP that is NOT the network / broadcast
        and NOT one of the firewall's own interface addresses.

        Uses random integer sampling instead of ``list(net.hosts())``
        so that large subnets (IPv4 /8, IPv6 /64) don't materialise
        millions of objects.
        """
        n_total = net.num_addresses
        if n_total <= 2:
            # /31 or /32 — no real host range; return network address
            return net.network_address
        n_hosts = n_total - 2  # exclude network + broadcast
        base = int(net.network_address)
        # Try up to 64 random offsets before falling back to the
        # first non-fw address in the subnet.
        for _ in range(64):
            offset = self.rng.randint(1, int(n_hosts))
            addr = net.network_address.__class__(base + offset)
            if str(addr) not in self._fw_local_ips:
                return addr
        # All 64 random picks were fw-local — subnet is densely owned.
        # Walk forward from offset 1 to find the first free address.
        for offset in range(1, min(int(n_hosts) + 1, 256)):
            addr = net.network_address.__class__(base + offset)
            if str(addr) not in self._fw_local_ips:
                return addr
        return net.network_address
