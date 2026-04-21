"""Tests for nfset:/dns:/dnsr: token support in per-table ir.py processors.

Covers: notrack, conntrack, blrules, stoppedrules, ecn, arprules, rawnat.
(nfacct has no address columns; scfilter uses a literal CIDR allowlist.)

All addresses use RFC 5737 / RFC 3849 ranges.  Hostnames use example.com.
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
    _process_arprules,
    _process_blrules,
    _process_conntrack,
    _process_ecn,
    _process_notrack,
    _process_rawnat,
    _process_stoppedrules,
)
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.config.zones import ZoneModel
from shorewall_nft.nft.nfsets import NfSetEntry, NfSetRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _registry(*names: str) -> NfSetRegistry:
    reg = NfSetRegistry()
    for name in names:
        reg.entries.append(NfSetEntry(name=name, hosts=["example.com"], backend="dnstap"))
        reg.set_names.add(name)
    return reg


def _ir(*nfset_names: str) -> FirewallIR:
    ir = FirewallIR()
    if nfset_names:
        ir.nfset_registry = _registry(*nfset_names)
    return ir


def _zones() -> ZoneModel:
    """Minimal zone model: fw + net (eth0) + loc (eth1)."""
    from shorewall_nft.config.zones import Zone, Interface
    fw_zone = Zone(name="fw", zone_type="firewall", interfaces=[])
    net_zone = Zone(
        name="net",
        zone_type="ipv4",
        interfaces=[Interface(name="eth0", zone="net")],
    )
    loc_zone = Zone(
        name="loc",
        zone_type="ipv4",
        interfaces=[Interface(name="eth1", zone="loc")],
    )
    return ZoneModel(
        zones={"fw": fw_zone, "net": net_zone, "loc": loc_zone},
        firewall_zone="fw",
    )


def _line(*cols: str, file: str = "test", lineno: int = 1) -> ConfigLine:
    return ConfigLine(columns=list(cols), file=file, lineno=lineno)


def _saddr_values(chain: Chain) -> set[str]:
    return {m.value for r in chain.rules for m in r.matches if "saddr" in m.field}


def _daddr_values(chain: Chain) -> set[str]:
    return {m.value for r in chain.rules for m in r.matches if "daddr" in m.field}


# ---------------------------------------------------------------------------
# _process_notrack
# ---------------------------------------------------------------------------


class TestNottrackNfset:
    def test_nfset_source_clones_for_v4_v6(self):
        """nfset: in SOURCE → two notrack rules."""
        ir = _ir("scanner")
        _process_notrack(ir, [_line("nfset:scanner", "all", "-")], _zones())

        chain = ir.chains["raw-prerouting"]
        assert len(chain.rules) == 2
        vals = _saddr_values(chain)
        assert "+nfset_scanner_v4" in vals
        assert "+nfset_scanner_v6" in vals

    def test_nfset_dest_clones_for_v4_v6(self):
        """nfset: in DEST → two notrack rules."""
        ir = _ir("peering")
        _process_notrack(ir, [_line("all", "nfset:peering", "-")], _zones())

        chain = ir.chains["raw-prerouting"]
        assert len(chain.rules) == 2
        vals = _daddr_values(chain)
        assert "+nfset_peering_v4" in vals
        assert "+nfset_peering_v6" in vals

    def test_plain_source_single_rule(self):
        ir = _ir()
        _process_notrack(ir, [_line("all", "all", "-")], _zones())
        chain = ir.chains["raw-prerouting"]
        assert len(chain.rules) == 1


# ---------------------------------------------------------------------------
# _process_conntrack
# ---------------------------------------------------------------------------


class TestConntrackNfset:
    def test_nfset_source_clones_for_v4_v6(self):
        """nfset: in SOURCE (col 1) → two ct-helper rules."""
        ir = _ir("vpn_peers")
        ir.add_chain(Chain(
            name="ct-helpers",
            chain_type=ChainType.FILTER,
            hook=Hook.PREROUTING,
            priority=-200,
        ))
        line = _line("CT:helper:ftp:", "nfset:vpn_peers", "all", "tcp", "21")
        _process_conntrack(ir, [line])

        chain = ir.chains["ct-helpers"]
        assert len(chain.rules) == 2

    def test_plain_source_single_rule(self):
        ir = _ir()
        ir.add_chain(Chain(
            name="ct-helpers",
            chain_type=ChainType.FILTER,
            hook=Hook.PREROUTING,
            priority=-200,
        ))
        line = _line("CT:helper:ftp:", "net", "fw", "tcp", "21")
        _process_conntrack(ir, [line])

        chain = ir.chains["ct-helpers"]
        assert len(chain.rules) == 1


# ---------------------------------------------------------------------------
# _process_blrules
# ---------------------------------------------------------------------------


class TestBlrulesNfset:
    def test_nfset_source_clones(self):
        """nfset: in SOURCE → two blacklist rules."""
        ir = _ir("badguys")
        ir.add_chain(Chain(name="blacklist"))
        _process_blrules(
            ir,
            [_line("DROP", "nfset:badguys", "all")],
            _zones(),
        )

        chain = ir.chains["blacklist"]
        assert len(chain.rules) == 2
        vals = _saddr_values(chain)
        assert "+nfset_badguys_v4" in vals
        assert "+nfset_badguys_v6" in vals

    def test_nfset_dest_clones(self):
        """nfset: in DEST → two blacklist rules."""
        ir = _ir("honeypot")
        ir.add_chain(Chain(name="blacklist"))
        _process_blrules(
            ir,
            [_line("DROP", "all", "nfset:honeypot")],
            _zones(),
        )

        chain = ir.chains["blacklist"]
        assert len(chain.rules) == 2
        vals = _daddr_values(chain)
        assert "+nfset_honeypot_v4" in vals
        assert "+nfset_honeypot_v6" in vals

    def test_plain_source_single_rule(self):
        ir = _ir()
        ir.add_chain(Chain(name="blacklist"))
        _process_blrules(
            ir,
            [_line("DROP", "net:198.51.100.0/24", "all")],
            _zones(),
        )
        chain = ir.chains["blacklist"]
        assert len(chain.rules) == 1


# ---------------------------------------------------------------------------
# _process_stoppedrules
# ---------------------------------------------------------------------------


class TestStoppedrules:
    def test_nfset_source_clones(self):
        """nfset: in SOURCE → two stopped-* rules."""
        ir = _ir("mgmt")
        _process_stoppedrules(
            ir,
            [_line("ACCEPT", "nfset:mgmt", "fw")],
            _zones(),
        )

        # SOURCE=nfset:mgmt, DEST=fw → stopped-input chain
        chain = ir.stopped_chains.get("stopped-input")
        assert chain is not None
        # 2 baseline rules (lo + established) + 2 cloned
        nfset_rules = [
            r for r in chain.rules
            if any("nfset" in (m.value or "") for m in r.matches)
        ]
        assert len(nfset_rules) == 2
        vals = {m.value for r in nfset_rules for m in r.matches if "saddr" in m.field}
        assert "+nfset_mgmt_v4" in vals
        assert "+nfset_mgmt_v6" in vals

    def test_plain_source_single_rule(self):
        ir = _ir()
        _process_stoppedrules(
            ir,
            [_line("ACCEPT", "net", "fw")],
            _zones(),
        )
        chain = ir.stopped_chains.get("stopped-input")
        assert chain is not None
        # baseline: lo-accept + established-accept; plus 1 user rule
        assert len(chain.rules) >= 3


# ---------------------------------------------------------------------------
# _process_ecn
# ---------------------------------------------------------------------------


class TestEcnNfset:
    def test_nfset_host_clones(self):
        """nfset: in HOST col → two ECN rules."""
        ir = _ir("legacy_peers")
        ir.add_chain(Chain(
            name="mangle-postrouting",
            chain_type=ChainType.ROUTE,
            hook=Hook.POSTROUTING,
            priority=-150,
        ))
        _process_ecn(ir, [_line("eth0", "nfset:legacy_peers")])

        chain = ir.chains["mangle-postrouting"]
        assert len(chain.rules) == 2
        daddr_vals = _daddr_values(chain)
        assert "+nfset_legacy_peers_v4" in daddr_vals
        assert "+nfset_legacy_peers_v6" in daddr_vals

    def test_plain_host_single_rule(self):
        ir = _ir()
        ir.add_chain(Chain(
            name="mangle-postrouting",
            chain_type=ChainType.ROUTE,
            hook=Hook.POSTROUTING,
            priority=-150,
        ))
        _process_ecn(ir, [_line("eth0", "203.0.113.5")])

        chain = ir.chains["mangle-postrouting"]
        assert len(chain.rules) == 1


# ---------------------------------------------------------------------------
# _process_arprules
# ---------------------------------------------------------------------------


class TestArprulesNfset:
    def test_nfset_source_clones(self):
        """nfset: in SOURCE col → two arp rules (v4 + v6 sentinels)."""
        ir = _ir("arp_allowed")
        _process_arprules(ir, [_line("ACCEPT", "nfset:arp_allowed", "-")])

        chain = ir.arp_chains.get("arp-input")
        assert chain is not None
        assert len(chain.rules) == 2
        vals = {
            m.value
            for r in chain.rules
            for m in r.matches
            if "saddr" in m.field
        }
        assert "+nfset_arp_allowed_v4" in vals
        assert "+nfset_arp_allowed_v6" in vals

    def test_plain_source_single_rule(self):
        ir = _ir()
        _process_arprules(ir, [_line("ACCEPT", "192.168.1.0/24", "-")])
        chain = ir.arp_chains["arp-input"]
        assert len(chain.rules) == 1


# ---------------------------------------------------------------------------
# _process_rawnat
# ---------------------------------------------------------------------------


class TestRawnatNfset:
    def test_nfset_source_clones(self):
        """nfset: in SOURCE → two rawnat rules."""
        ir = _ir("bypass")
        _process_rawnat(ir, [_line("NOTRACK", "nfset:bypass", "all")], _zones())

        chain = ir.chains["raw-prerouting"]
        assert len(chain.rules) == 2
        vals = _saddr_values(chain)
        assert "+nfset_bypass_v4" in vals
        assert "+nfset_bypass_v6" in vals

    def test_nfset_dest_clones(self):
        """nfset: in DEST → two rawnat rules."""
        ir = _ir("servers")
        _process_rawnat(ir, [_line("NOTRACK", "all", "nfset:servers")], _zones())

        chain = ir.chains["raw-prerouting"]
        assert len(chain.rules) == 2
        vals = _daddr_values(chain)
        assert "+nfset_servers_v4" in vals
        assert "+nfset_servers_v6" in vals

    def test_plain_source_single_rule(self):
        ir = _ir()
        _process_rawnat(ir, [_line("NOTRACK", "all", "all")], _zones())
        chain = ir.chains["raw-prerouting"]
        assert len(chain.rules) == 1
