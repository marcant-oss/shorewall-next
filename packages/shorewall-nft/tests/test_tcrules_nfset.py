"""Tests for nfset:/dns:/dnsr: token support in tcrules/mangle mark rules.

All addresses use RFC 5737 (198.51.100.x, 203.0.113.x) ranges.
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
)

from shorewall_nft.compiler.tc import _process_mark_rule
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
    ir.add_chain(Chain(
        name="mangle-prerouting",
        chain_type=ChainType.ROUTE,
        hook=Hook.PREROUTING,
        priority=-150,
    ))
    return ir


def _zones() -> ZoneModel:
    return ZoneModel(zones={}, firewall_zone="fw")


def _line(*cols: str) -> ConfigLine:
    return ConfigLine(columns=list(cols), file="tcrules", lineno=1)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTcrulesNfset:
    def test_nfset_in_source_emits_v4_and_v6(self):
        """nfset: in SOURCE col → two mark rules (v4 + v6)."""
        ir = _ir("bulk")
        line = _line("1", "nfset:bulk", "all")
        _process_mark_rule(ir, line, _zones())

        chain = ir.chains["mangle-prerouting"]
        assert len(chain.rules) == 2
        saddr_vals = {
            m.value
            for r in chain.rules
            for m in r.matches
            if "saddr" in m.field
        }
        assert "+nfset_bulk_v4" in saddr_vals
        assert "+nfset_bulk_v6" in saddr_vals

    def test_nfset_in_dest_emits_v4_and_v6(self):
        """nfset: in DEST col → two mark rules (v4 + v6)."""
        ir = _ir("servers")
        line = _line("2", "all", "nfset:servers")
        _process_mark_rule(ir, line, _zones())

        chain = ir.chains["mangle-prerouting"]
        assert len(chain.rules) == 2
        daddr_vals = {
            m.value
            for r in chain.rules
            for m in r.matches
            if "daddr" in m.field
        }
        assert "+nfset_servers_v4" in daddr_vals
        assert "+nfset_servers_v6" in daddr_vals

    def test_nfset_in_source_and_dest(self):
        """nfset: in both SOURCE and DEST → two rules with both set refs."""
        ir = _ir("srcs", "dsts")
        line = _line("3", "nfset:srcs", "nfset:dsts")
        _process_mark_rule(ir, line, _zones())

        chain = ir.chains["mangle-prerouting"]
        assert len(chain.rules) == 2
        for rule in chain.rules:
            fields = {m.field: m.value for m in rule.matches}
            assert any("saddr" in f for f in fields)
            assert any("daddr" in f for f in fields)

    def test_no_token_plain_source(self):
        """Plain address source → single mark rule."""
        ir = _ir()
        line = _line("1", "198.51.100.0/24", "all")
        _process_mark_rule(ir, line, _zones())

        chain = ir.chains["mangle-prerouting"]
        assert len(chain.rules) == 1
