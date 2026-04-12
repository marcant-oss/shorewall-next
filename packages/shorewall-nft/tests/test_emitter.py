"""Tests for the nft emitter."""

from pathlib import Path

import pytest

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


class TestEmitNft:
    def setup_method(self):
        config = load_config(MINIMAL_DIR)
        ir = build_ir(config)
        self.output = emit_nft(ir)

    def test_shebang(self):
        assert self.output.startswith("#!/usr/sbin/nft -f")

    def test_table_declaration(self):
        assert "table inet shorewall {" in self.output

    def test_table_cleanup(self):
        assert "delete table inet shorewall" in self.output

    def test_base_chains(self):
        assert "chain input {" in self.output
        assert "chain forward {" in self.output
        assert "chain output {" in self.output

    def test_filter_hook(self):
        assert "type filter hook input priority 0;" in self.output
        assert "type filter hook forward priority 0;" in self.output
        assert "type filter hook output priority 0;" in self.output

    def test_zone_pair_chains(self):
        assert "chain loc-fw {" in self.output
        assert "chain net-fw {" in self.output
        assert "chain loc-net {" in self.output

    def test_dispatch_jumps(self):
        assert 'iifname "eth1" jump loc-fw' in self.output
        assert 'iifname "eth0" jump net-fw' in self.output

    def test_ssh_rule(self):
        assert "tcp dport 22 accept" in self.output

    def test_dns_rules(self):
        assert "tcp dport 53 accept" in self.output
        assert "udp dport 53 accept" in self.output

    def test_ping_rule(self):
        # Ping macro expands to icmp type 8 (or echo-request)
        assert "icmp type 8" in self.output or "icmp type echo-request" in self.output

    def test_http_set(self):
        assert "tcp dport { 80, 443 } accept" in self.output

    def test_admin_comment(self):
        assert "# Admin SSH" in self.output

    def test_admin_saddr(self):
        assert "ip saddr 192.168.1.100" in self.output

    def test_policy_verdicts(self):
        assert "drop" in self.output  # net->* policy (via ~Drop action chain)
        assert "reject" in self.output  # loc->fw policy (via ~Reject action chain)
        # fw->* policy: ACCEPT chains have accept policy on output base chain
        assert "type filter hook output" in self.output

    def test_no_duplicate_iifname(self):
        # Inside zone-pair chains, there should be no interface matches
        # (dispatch handles that)
        lines = self.output.split("\n")
        in_loc_fw = False
        for line in lines:
            if "chain loc-fw" in line:
                in_loc_fw = True
            elif in_loc_fw and line.strip().startswith("}"):
                break
            elif in_loc_fw and "iifname" in line:
                pytest.fail(f"Unexpected iifname in loc-fw chain: {line}")
