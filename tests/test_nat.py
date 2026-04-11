import os

"""Tests for Phase 2: NAT, Conntrack, Notrack, Custom Macros."""

from pathlib import Path

import pytest

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

NAT_DIR = Path(__file__).parent / "configs" / "nat"
PROD_DIR = Path(os.environ.get("SHOREWALL_NFT_PROD_DIR", "/etc/shorewall"))


class TestNAT:
    def setup_method(self):
        config = load_config(NAT_DIR)
        self.ir = build_ir(config)
        self.output = emit_nft(self.ir)

    def test_prerouting_chain_exists(self):
        assert "prerouting" in self.ir.chains
        chain = self.ir.chains["prerouting"]
        assert chain.hook.value == "prerouting"
        assert chain.chain_type.value == "nat"

    def test_postrouting_chain_exists(self):
        assert "postrouting" in self.ir.chains
        chain = self.ir.chains["postrouting"]
        assert chain.hook.value == "postrouting"
        assert chain.chain_type.value == "nat"

    def test_dnat_rule(self):
        chain = self.ir.chains["prerouting"]
        dnat_rules = [r for r in chain.rules if r.verdict_args and "dnat:" in r.verdict_args]
        assert len(dnat_rules) >= 1
        # DNAT to webserver:80 on port 8080
        r = dnat_rules[0]
        assert "192.168.1.10:80" in r.verdict_args

    def test_snat_rule(self):
        chain = self.ir.chains["postrouting"]
        snat_rules = [r for r in chain.rules if r.verdict_args and "snat:" in r.verdict_args]
        assert len(snat_rules) >= 1
        assert "203.0.113.1" in snat_rules[0].verdict_args

    def test_dnat_nft_output(self):
        assert "dnat to 192.168.1.10:80" in self.output

    def test_snat_nft_output(self):
        assert "snat to 203.0.113.1" in self.output

    def test_nat_chain_hooks(self):
        assert "type nat hook prerouting priority -100;" in self.output
        assert "type nat hook postrouting priority 100;" in self.output


class TestNotrack:
    def setup_method(self):
        config = load_config(NAT_DIR)
        self.ir = build_ir(config)
        self.output = emit_nft(self.ir)

    def test_raw_chain_exists(self):
        assert "raw-prerouting" in self.ir.chains
        chain = self.ir.chains["raw-prerouting"]
        assert chain.priority == -300

    def test_notrack_rules(self):
        chain = self.ir.chains["raw-prerouting"]
        notrack_rules = [r for r in chain.rules if r.verdict_args and "notrack" in r.verdict_args]
        assert len(notrack_rules) >= 1

    def test_notrack_nft_output(self):
        assert "notrack" in self.output

    def test_raw_output_chain(self):
        assert "raw-output" in self.ir.chains
        chain = self.ir.chains["raw-output"]
        assert len(chain.rules) >= 1


class TestConntrack:
    def setup_method(self):
        config = load_config(NAT_DIR)
        self.ir = build_ir(config)
        self.output = emit_nft(self.ir)

    def test_ct_helper_chain(self):
        assert "ct-helpers" in self.ir.chains

    def test_ftp_helper(self):
        chain = self.ir.chains["ct-helpers"]
        ftp = [r for r in chain.rules if r.verdict_args and "ftp" in r.verdict_args]
        assert len(ftp) == 1

    def test_ct_helper_nft_output(self):
        assert 'ct helper set "ftp"' in self.output


class TestProductionConfig:
    """Test against the real production config."""

    @pytest.fixture(autouse=True)
    def skip_if_missing(self):
        if not PROD_DIR.exists():
            pytest.skip("Production config not available")

    def setup_method(self):
        if PROD_DIR.exists():
            config = load_config(PROD_DIR)
            self.ir = build_ir(config)
            self.output = emit_nft(self.ir)

    def test_zones(self):
        assert len(self.ir.zones.zones) >= 16

    def test_chain_count(self):
        assert len(self.ir.chains) > 250

    def test_rule_count(self):
        total = sum(len(c.rules) for c in self.ir.chains.values())
        assert total > 5000

    def test_nat_chains(self):
        assert "prerouting" in self.ir.chains
        assert "postrouting" in self.ir.chains

    def test_raw_chains(self):
        assert "raw-prerouting" in self.ir.chains
        assert "raw-output" in self.ir.chains

    def test_ct_helpers(self):
        assert "ct-helpers" in self.ir.chains
        chain = self.ir.chains["ct-helpers"]
        assert len(chain.rules) >= 4  # ftp, snmp, tftp, pptp

    def test_output_line_count(self):
        lines = self.output.split("\n")
        assert len(lines) > 9000

    def test_nft_syntax_basics(self):
        assert "table inet shorewall {" in self.output
        assert "type filter hook input" in self.output
        assert "type nat hook prerouting" in self.output
        assert "snat to" in self.output
        assert "dnat to" in self.output
        assert "notrack" in self.output
