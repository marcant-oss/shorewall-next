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


@dataclass
class OracleVerdict:
    verdict: str                # "ACCEPT" / "DROP" / "UNKNOWN"
    matched_rule_raw: str | None = None
    reason: str = ""


class RulesetOracle:
    """Parses an iptables-save dump once and answers tuple queries."""

    def __init__(self, ipt_dump: Path):
        from shorewall_nft.verify.iptables_parser import parse_iptables_save
        self._ipt = parse_iptables_save(ipt_dump)

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
    ) -> OracleVerdict:
        """Return the verdict the <src>2<dst> chain would produce."""
        flt = self._ipt.get("filter")
        if flt is None:
            return OracleVerdict("UNKNOWN", None, "no filter table in dump")
        chain_name = f"{src_zone}2{dst_zone}"
        rules = flt.rules.get(chain_name)
        if not rules:
            return OracleVerdict("UNKNOWN", None,
                                  f"no {chain_name} chain")

        for rule in rules:
            # Skip pure conntrack-state rules (``ct state
            # established,related accept`` etc.). They have no
            # address/proto/port fields, so _rule_matches() would
            # return True for every tuple and classify would
            # short-circuit on the very first such rule in the
            # chain — wiping out every DROP expectation. Matches
            # the same filter that derive_tests_all_zones applies
            # on the generator side.
            if "--ctstate" in rule.raw or "--ctstatus" in rule.raw:
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

        return OracleVerdict("UNKNOWN", None,
                              f"{chain_name} fell through to end")

    # ── matching ──────────────────────────────────────────────────

    def _rule_matches(self, rule, src_ip: str, dst_ip: str,
                      proto: str, port: int | None) -> bool:
        # Protocol check — rules without -p match any protocol
        if rule.proto and rule.proto != proto:
            return False

        # Source address check
        if rule.saddr:
            if not self._ip_in_spec(src_ip, rule.saddr):
                return False

        # Destination address check
        if rule.daddr:
            if not self._ip_in_spec(dst_ip, rule.daddr):
                return False

        # Destination port check (TCP/UDP)
        if port is not None and rule.dport:
            if not self._port_in_spec(port, rule.dport):
                return False
        elif rule.dport and port is None:
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
        # Pre-compute list of (iface, subnet) candidates so we only
        # walk parsed state once.
        self._candidates: list[tuple[str, _ipaddr.IPv4Network]] = []
        for name, iface in fw_state.interfaces.items():
            if iface.kind == "loopback":
                continue
            if name not in iface_to_zone:
                continue
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
                self._candidates.append((name, net))

    def next(self) -> RandomProbe | None:
        """Return a fresh random probe, or None if we can't pick one."""
        if len(self._candidates) < 2:
            return None
        src_pick = self.rng.choice(self._candidates)
        # Pick a dst from a DIFFERENT interface
        for _ in range(16):
            dst_pick = self.rng.choice(self._candidates)
            if dst_pick[0] != src_pick[0]:
                break
        else:
            return None
        src_iface, src_net = src_pick
        dst_iface, dst_net = dst_pick
        src_ip = str(self._pick_host(src_net))
        dst_ip = str(self._pick_host(dst_net))
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
        )

    def _pick_host(self, net: _ipaddr.IPv4Network) -> _ipaddr.IPv4Address:
        """Return a usable host IP that is NOT the network / broadcast."""
        hosts = list(net.hosts())
        if not hosts:
            return net.network_address
        return self.rng.choice(hosts)
