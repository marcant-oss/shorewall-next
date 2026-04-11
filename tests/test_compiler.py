"""Tests for the IR compiler."""

from pathlib import Path

from shorewall_nft.compiler.ir import Verdict, build_ir
from shorewall_nft.config.parser import load_config

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


class TestBuildIR:
    def setup_method(self):
        config = load_config(MINIMAL_DIR)
        self.ir = build_ir(config)

    def test_firewall_zone(self):
        assert self.ir.zones.firewall_zone == "fw"

    def test_zones(self):
        names = self.ir.zones.all_zone_names()
        assert "fw" in names
        assert "net" in names
        assert "loc" in names

    def test_base_chains(self):
        assert "input" in self.ir.chains
        assert "forward" in self.ir.chains
        assert "output" in self.ir.chains
        assert self.ir.chains["input"].is_base_chain
        assert self.ir.chains["forward"].is_base_chain
        assert self.ir.chains["output"].is_base_chain

    def test_zone_pair_chains(self):
        # From policy: loc->net ACCEPT, net->all DROP
        assert "loc-net" in self.ir.chains
        assert "net-fw" in self.ir.chains
        assert "net-loc" in self.ir.chains

    def test_policy_defaults(self):
        assert self.ir.chains["fw-net"].policy == Verdict.ACCEPT
        assert self.ir.chains["fw-loc"].policy == Verdict.ACCEPT
        assert self.ir.chains["loc-net"].policy == Verdict.ACCEPT
        # DROP/REJECT policies become JUMP to action chains (Drop/Reject)
        # when DROP_DEFAULT/REJECT_DEFAULT are set
        assert self.ir.chains["net-fw"].policy in (Verdict.DROP, Verdict.JUMP)
        assert self.ir.chains["net-loc"].policy in (Verdict.DROP, Verdict.JUMP)

    def test_ssh_rule_in_loc_fw(self):
        chain = self.ir.chains["loc-fw"]
        # SSH(ACCEPT) should expand to tcp dport 22
        ssh_rules = [r for r in chain.rules if
                     any(m.field == "tcp dport" and m.value == "22"
                         for m in r.matches)]
        assert len(ssh_rules) >= 1
        assert ssh_rules[0].verdict == Verdict.ACCEPT

    def test_dns_rule_in_loc_net(self):
        chain = self.ir.chains["loc-net"]
        # DNS(ACCEPT) should expand to tcp+udp dport 53
        dns_rules = [r for r in chain.rules if
                     any(m.value == "53" for m in r.matches)]
        assert len(dns_rules) == 2  # tcp and udp

    def test_ping_rule(self):
        chain = self.ir.chains["net-fw"]
        ping_rules = [r for r in chain.rules if
                      any("icmp" in m.field and "type" in m.field for m in r.matches)]
        assert len(ping_rules) >= 1

    def test_admin_ssh_comment(self):
        chain = self.ir.chains["net-fw"]
        commented = [r for r in chain.rules if r.comment == "Admin SSH"]
        assert len(commented) >= 1

    def test_http_anonymous_set(self):
        chain = self.ir.chains["net-loc"]
        http_rules = [r for r in chain.rules if
                      any("80" in m.value for m in r.matches)]
        assert len(http_rules) >= 1
