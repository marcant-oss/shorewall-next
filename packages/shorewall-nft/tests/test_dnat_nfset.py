"""Tests for nfset:/dns:/dnsr: token support in DNAT rules.

All addresses use RFC 5737 (198.51.100.x, 203.0.113.x) ranges.
"""

from __future__ import annotations

import pytest

from shorewall_nft.compiler.ir import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
)
from shorewall_nft.compiler.nat import _process_dnat_line
from shorewall_nft.config.parser import ConfigLine
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
        name="prerouting",
        chain_type=ChainType.NAT,
        hook=Hook.PREROUTING,
        priority=-100,
    ))
    return ir


def _line(*cols: str) -> ConfigLine:
    return ConfigLine(columns=list(cols), file="rules", lineno=1)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDnatNfsetSource:
    def test_nfset_source_emits_v4_and_v6_rules(self):
        """nfset: in SOURCE → two DNAT rules (v4 + v6)."""
        ir = _ir("allowed")
        # DNAT ACTION SOURCE DEST PROTO DPORT
        line = _line("DNAT", "nfset:allowed", "loc:203.0.113.38:8080", "tcp", "80")
        _process_dnat_line(ir, line)

        chain = ir.chains["prerouting"]
        assert len(chain.rules) == 2
        saddr_vals = {
            m.value
            for r in chain.rules
            for m in r.matches
            if "saddr" in m.field
        }
        assert "+nfset_allowed_v4" in saddr_vals
        assert "+nfset_allowed_v6" in saddr_vals

    def test_nfset_in_dest_column_raises(self):
        """nfset: in DEST (DNAT target) column must raise ValueError."""
        ir = _ir("targets")
        line = _line("DNAT", "net", "nfset:targets", "tcp", "80")
        with pytest.raises(ValueError, match="DEST column"):
            _process_dnat_line(ir, line)

    def test_dns_in_dest_column_raises(self):
        """dns: in DEST column must raise ValueError."""
        ir = _ir()
        line = _line("DNAT", "net", "dns:example.com", "tcp", "80")
        with pytest.raises(ValueError, match="DEST column"):
            _process_dnat_line(ir, line)

    def test_no_token_plain_source(self):
        """Plain source zone → single DNAT rule."""
        ir = _ir()
        line = _line("DNAT", "net", "loc:203.0.113.38:8080", "tcp", "80")
        _process_dnat_line(ir, line)

        chain = ir.chains["prerouting"]
        assert len(chain.rules) == 1
