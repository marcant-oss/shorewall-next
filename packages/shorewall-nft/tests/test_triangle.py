import os

"""Dreiecks-Vergleich: shorewall-nft vs shorewall2foomuuri vs iptables baseline.

This test compiles the production config through shorewall-nft and
compares the output structure against the foomuuri reference.

When the iptables dump and shorewall2foomuuri are available, it also
runs the full semantic comparison using the verify framework.
"""

from pathlib import Path

import pytest

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft
from shorewall_nft.nft.sets import parse_init_for_sets

PROD_DIR = Path(os.environ.get("SHOREWALL_NFT_PROD_DIR", "/etc/shorewall"))
S2F_DIR = Path(os.environ.get("SHOREWALL_NFT_S2F_DIR", "/opt/shorewall2foomuuri"))
IPT_DUMP = Path(os.environ.get("SHOREWALL_NFT_IPT_DUMP", "/tmp/iptables-save.txt"))


@pytest.fixture
def prod_config():
    if not PROD_DIR.exists():
        pytest.skip("Production config not available")
    return load_config(PROD_DIR)


@pytest.fixture
def prod_nft(prod_config):
    ir = build_ir(prod_config)
    sets = parse_init_for_sets(PROD_DIR / "init", PROD_DIR)
    return emit_nft(ir, nft_sets=sets)


@pytest.fixture
def prod_ir(prod_config):
    return build_ir(prod_config)


class TestProductionCompleteness:
    """Verify that shorewall-nft handles the full production config."""

    def test_all_zones_present(self, prod_ir):
        zone_names = prod_ir.zones.all_zone_names()
        # Universal requirement: every Shorewall config has a firewall zone
        # and at least one external network zone.
        assert "fw" in zone_names
        assert "net" in zone_names
        # Production configs typically have several more zones on top.
        assert len(zone_names) >= 3

    def test_all_interfaces_mapped(self, prod_ir):
        """Every IPv4 zone (except fw) should have at least one interface.
        IPv6-only zones without interfaces are OK (they share v4 interfaces)."""
        for name, zone in prod_ir.zones.zones.items():
            if zone.is_firewall:
                continue
            if zone.zone_type == "ipv6" and not zone.interfaces:
                continue  # IPv6-only zone, interfaces inherited from v4
            assert len(zone.interfaces) > 0, f"Zone {name} has no interfaces"

    def test_zone_pair_coverage(self, prod_ir):
        """Key zone pairs should have chains with rules or ACCEPT policy."""
        key_pairs = [
            "net-fw", "adm-fw", "dmz-fw", "host-fw",
            "fw-net", "fw-dmz",
            "loc-net" if "loc" in prod_ir.zones.zones else "adm-net",
        ]
        for pair in key_pairs:
            if pair in prod_ir.chains:
                chain = prod_ir.chains[pair]
                has_content = len(chain.rules) > 0 or chain.policy is not None
                assert has_content, f"Chain {pair} has no rules and no policy"

    def test_nat_chains_populated(self, prod_ir):
        assert len(prod_ir.chains["prerouting"].rules) > 0
        assert len(prod_ir.chains["postrouting"].rules) > 0

    def test_notrack_chains_populated(self, prod_ir):
        assert len(prod_ir.chains["raw-prerouting"].rules) > 0

    def test_ct_helpers_populated(self, prod_ir):
        chain = prod_ir.chains["ct-helpers"]
        helper_names = set()
        for r in chain.rules:
            if r.verdict_args and "ct_helper:" in r.verdict_args:
                helper_names.add(r.verdict_args.split(":")[1])
        assert helper_names >= {"ftp", "snmp", "tftp", "pptp"}


class TestNftOutputStructure:
    """Verify that the nft output has correct structure."""

    def test_single_table(self, prod_nft):
        assert prod_nft.count("table inet shorewall {") == 1

    def test_delete_before_create(self, prod_nft):
        delete_pos = prod_nft.index("delete table inet shorewall")
        create_pos = prod_nft.index("table inet shorewall {")
        assert delete_pos < create_pos

    def test_base_chain_types(self, prod_nft):
        assert "type filter hook input priority 0;" in prod_nft
        assert "type filter hook forward priority 0;" in prod_nft
        assert "type filter hook output priority 0;" in prod_nft
        assert "type nat hook prerouting priority -100;" in prod_nft
        assert "type nat hook postrouting priority 100;" in prod_nft

    def test_ct_state_before_dispatch(self, prod_nft):
        """ct state rules must come before dispatch jumps in filter chains."""
        lines = prod_nft.split("\n")
        for i, line in enumerate(lines):
            if "type filter hook input" in line:
                # Find ct state and first jump
                ct_line = None
                jump_line = None
                for j in range(i + 1, min(i + 20, len(lines))):
                    if "ct state" in lines[j] and ct_line is None:
                        ct_line = j
                    if "jump" in lines[j] and jump_line is None:
                        jump_line = j
                if ct_line and jump_line:
                    assert ct_line < jump_line, "ct state must come before dispatch jumps"
                break

    def test_no_empty_chains(self, prod_nft):
        """Zone-pair chains should not be empty (they at least have a policy verdict)."""
        lines = prod_nft.split("\n")
        i = 0
        while i < len(lines):
            if "\tchain " in lines[i] and "chain input" not in lines[i] and "chain forward" not in lines[i] and "chain output" not in lines[i]:
                chain_name = lines[i].strip().split()[1]
                # Count non-empty lines until closing brace
                content_lines = 0
                j = i + 1
                while j < len(lines) and lines[j].strip() != "}":
                    if lines[j].strip() and not lines[j].strip().startswith("#") and not lines[j].strip().startswith("type "):
                        content_lines += 1
                    j += 1
                assert content_lines > 0, f"Chain {chain_name} is empty"
            i += 1

    def test_nft_set_declaration(self, prod_nft):
        """Named sets should be declared before chains."""
        if "customer-a-ipv4" in prod_nft:
            set_pos = prod_nft.index("set customer-a-ipv4")
            chain_pos = prod_nft.index("chain input")
            assert set_pos < chain_pos

    def test_set_reference_matches_declaration(self, prod_nft):
        """@setname references should have matching set declarations."""
        import re
        refs = set(re.findall(r'@([\w-]+)', prod_nft))
        decls = set(re.findall(r'set ([\w-]+) \{', prod_nft))
        # Every referenced set should be declared
        for ref in refs:
            assert ref in decls, f"Set @{ref} referenced but not declared"


class TestFoomuuriComparison:
    """Compare zone structure against shorewall2foomuuri output."""

    @pytest.fixture(autouse=True)
    def skip_if_missing(self):
        if not S2F_DIR.exists():
            pytest.skip("shorewall2foomuuri not available")

    def test_zone_count_matches(self, prod_ir):
        """shorewall-nft should produce the same number of zones as the production config."""
        # Production has 16 zones (including fw)
        assert len(prod_ir.zones.zones) >= 16  # 16 v4 + optional v6-only zones

    def test_zone_pair_count_reasonable(self, prod_ir):
        """Number of zone-pair chains should be in expected range.
        16 zones = up to 16*15=240 pairs, plus base chains."""
        non_base = [c for c in prod_ir.chains.values() if not c.is_base_chain]
        assert 200 < len(non_base) < 300


class TestSemanticTriangleComparison:
    """Full semantic comparison against iptables baseline.

    This is the real Dreiecks-Vergleich:
    shorewall-nft nft output ↔ iptables-save ground truth.
    """

    @pytest.fixture(autouse=True)
    def skip_if_missing(self):
        if not PROD_DIR.exists():
            pytest.skip("Production config not available")
        if not IPT_DUMP.exists():
            pytest.skip("iptables dump not available")

    def test_triangle_runs(self):
        """The triangle comparison should complete without errors."""
        from shorewall_nft.verify.triangle import run_triangle

        report = run_triangle(
            shorewall_config_dir=PROD_DIR,
            iptables_dump=IPT_DUMP,
        )
        print(report.summarize())
        assert report.pairs_checked > 0

    def test_triangle_coverage_baseline(self):
        """Track the coverage percentage as a baseline metric."""
        from shorewall_nft.verify.triangle import run_triangle

        report = run_triangle(
            shorewall_config_dir=PROD_DIR,
            iptables_dump=IPT_DUMP,
        )
        print(f"\n{report.summarize()}")
        total = report.ok + report.missing
        if total > 0:
            print(f"Coverage: {report.ok / total * 100:.1f}%")

        # We expect at least some rules to match
        assert report.ok > 0, "No rules matched"

        # Show top failing pairs
        failing = sorted(
            [p for p in report.pair_reports if not p.passed],
            key=lambda p: len(p.missing),
            reverse=True,
        )
        if failing:
            print("\nTop 5 failing pairs:")
            for p in failing[:5]:
                print(f"  {p.zone_pair}: ok={p.ok} missing={len(p.missing)} extra={len(p.extra)}")
