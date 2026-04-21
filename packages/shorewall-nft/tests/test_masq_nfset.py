"""Tests for nfset:/dns:/dnsr: token support in masq (SNAT) rules.

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
from shorewall_nft.compiler.nat import _process_masq_line
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
    # Masq needs the postrouting chain to exist.
    ir.add_chain(Chain(
        name="postrouting",
        chain_type=ChainType.NAT,
        hook=Hook.POSTROUTING,
        priority=100,
    ))
    return ir


def _line(*cols: str) -> ConfigLine:
    return ConfigLine(columns=list(cols), file="masq", lineno=1)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMasqNfsetSource:
    def test_nfset_source_emits_v4_and_v6_rules(self):
        """nfset: in SOURCE col → two rules emitted, one per family."""
        ir = _ir("blocklist")
        line = _line("eth0", "nfset:blocklist", "203.0.113.5")
        _process_masq_line(ir, line)

        chain = ir.chains["postrouting"]
        assert len(chain.rules) == 2
        set_values = {
            m.value
            for r in chain.rules
            for m in r.matches
            if "saddr" in m.field
        }
        assert "+nfset_blocklist_v4" in set_values
        assert "+nfset_blocklist_v6" in set_values

    def test_nfset_source_snat_addr_preserved(self):
        """SNAT target address is preserved unchanged in both cloned rules."""
        ir = _ir("blocklist")
        line = _line("eth0", "nfset:blocklist", "203.0.113.5")
        _process_masq_line(ir, line)

        chain = ir.chains["postrouting"]
        snat_targets = [r.verdict_args for r in chain.rules]
        assert all(a == "snat:203.0.113.5" for a in snat_targets)

    def test_nfset_in_address_column_raises(self):
        """nfset: in ADDRESS (SNAT target) column must raise ValueError."""
        ir = _ir("snat_pool")
        line = _line("eth0", "198.51.100.0/24", "nfset:snat_pool")
        with pytest.raises(ValueError, match="ADDRESS column"):
            _process_masq_line(ir, line)

    def test_dns_in_address_column_raises(self):
        """dns: in ADDRESS column must raise ValueError."""
        ir = _ir()
        line = _line("eth0", "198.51.100.0/24", "dns:example.com")
        with pytest.raises(ValueError, match="ADDRESS column"):
            _process_masq_line(ir, line)

    def test_no_token_plain_source(self):
        """Plain CIDR source → single rule, no cloning."""
        ir = _ir()
        line = _line("eth0", "198.51.100.0/24", "203.0.113.5")
        _process_masq_line(ir, line)

        chain = ir.chains["postrouting"]
        assert len(chain.rules) == 1
