"""Tests for the plugin system: base classes, manager, built-in plugins."""

from __future__ import annotations

import pytest

from shorewall_nft.plugins import (
    EnrichResult,
    ParamEnrichResult,
    Plugin,
    PluginManager,
)
from shorewall_nft.plugins.builtin.ip_info import IpInfoPlugin
from shorewall_nft.plugins.utils import (
    extract_ipv4,
    extract_ipv6,
    ip_in_subnet,
    is_ipv4,
    is_ipv6,
)

# ── utils ─────────────────────────────────────────────────────────

class TestUtils:
    def test_extract_ipv4(self):
        assert extract_ipv4("ACCEPT host:203.0.113.65 net") == ["203.0.113.65"]
        assert extract_ipv4("net:10.0.0.1,10.0.0.2") == ["10.0.0.1", "10.0.0.2"]
        assert extract_ipv4("net:203.0.113.0/24") == ["203.0.113.0"]
        assert extract_ipv4("no ips here") == []

    def test_extract_ipv4_invalid(self):
        assert extract_ipv4("999.999.999.999") == []
        assert extract_ipv4("300.1.1.1") == []

    def test_extract_ipv6(self):
        assert "2001:db8:0:100:203:0:113:65" in extract_ipv6(
            "host:<2001:db8:0:100:203:0:113:65>")
        assert "2001:db8::1" in extract_ipv6("host:<2001:db8::1>")
        assert extract_ipv6("no ips here") == []

    def test_ip_in_subnet(self):
        assert ip_in_subnet("203.0.113.65", "203.0.113.0/24")
        assert not ip_in_subnet("203.0.114.1", "203.0.113.0/24")
        assert ip_in_subnet("2001:db8::1", "2001:db8::/32")

    def test_is_ipv4_ipv6(self):
        assert is_ipv4("1.2.3.4")
        assert not is_ipv4("2a00::1")
        assert is_ipv6("::1")
        assert not is_ipv6("1.2.3.4")


# ── base ──────────────────────────────────────────────────────────

class TestBase:
    def test_plugin_defaults(self, tmp_path):
        p = Plugin({}, tmp_path)
        assert p.lookup_ip("1.2.3.4") is None
        assert p.map_v4_to_v6("1.2.3.4") is None
        assert p.enrich_comment_block("x", [], []).is_empty()

    def test_enrich_result_empty(self):
        assert EnrichResult().is_empty()
        assert not EnrichResult(tag="new").is_empty()
        assert not EnrichResult(prepend_comments=["# foo"]).is_empty()

    def test_param_enrich_result(self):
        pe = ParamEnrichResult()
        pe.pairs["MAIL5"] = ("MAIL5=1.1.1.1", "MAIL5=::1")
        assert "MAIL5" in pe.pairs


# ── IpInfoPlugin ──────────────────────────────────────────────────

@pytest.fixture
def ip_info_plugin(tmp_path):
    config = {
        "mappings": [
            {"v4_subnet": "203.0.113.0/24",
             "v6_prefix": "2001:db8:0:100::/64"},
            {"v4_subnet": "198.51.100.0/24",
             "v6_prefix": "2001:db8:0:200::/64"},
            {"v4_subnet": "192.0.2.0/24",
             "v6_prefix": "2001:db8:0:300::/64"},
        ],
    }
    p = IpInfoPlugin(config, tmp_path)
    p.load()
    return p


class TestIpInfo:
    def test_v4_to_v6_basic(self, ip_info_plugin):
        assert (ip_info_plugin.map_v4_to_v6("203.0.113.65")
                == "2001:db8:0:100:203:0:113:65")

    def test_v4_to_v6_multiple_subnets(self, ip_info_plugin):
        assert (ip_info_plugin.map_v4_to_v6("198.51.100.162")
                == "2001:db8:0:200:198:51:100:162")
        assert (ip_info_plugin.map_v4_to_v6("192.0.2.35")
                == "2001:db8:0:300:192:0:2:35")

    def test_v4_to_v6_unknown_subnet(self, ip_info_plugin):
        assert ip_info_plugin.map_v4_to_v6("8.8.8.8") is None
        assert ip_info_plugin.map_v4_to_v6("10.0.0.1") is None

    def test_v6_to_v4_roundtrip(self, ip_info_plugin):
        for v4 in ["203.0.113.65", "198.51.100.162", "192.0.2.130"]:
            v6 = ip_info_plugin.map_v4_to_v6(v4)
            assert v6 is not None
            assert ip_info_plugin.map_v6_to_v4(v6) == v4

    def test_v6_to_v4_unknown_prefix(self, ip_info_plugin):
        assert ip_info_plugin.map_v6_to_v4("2a00:db8::1") is None

    def test_v4_to_v6_invalid(self, ip_info_plugin):
        assert ip_info_plugin.map_v4_to_v6("not.an.ip") is None
        assert ip_info_plugin.map_v4_to_v6("2a00::1") is None  # v6 input

    def test_lookup_ip(self, ip_info_plugin):
        info = ip_info_plugin.lookup_ip("203.0.113.65")
        assert info is not None
        assert info["v4"] == "203.0.113.65"
        assert info["v6"] == "2001:db8:0:100:203:0:113:65"
        assert info["source"] == "ip-info (pattern)"

    def test_enrich_params_pair(self, ip_info_plugin):
        v4 = {"MAIL5": "MAIL5=203.0.113.86"}
        v6 = {"MAIL5": "MAIL5=2001:db8:0:100:203:0:113:86"}
        result = ip_info_plugin.enrich_params(v4, v6)
        assert "MAIL5" in result.pairs

    def test_enrich_params_non_pair(self, ip_info_plugin):
        # Same varname but v6 doesn't match v4 pattern — not a pair
        v4 = {"NS2": "NS2=198.51.100.36"}
        v6 = {"NS2": "NS2=2001:db8::53:2"}
        result = ip_info_plugin.enrich_params(v4, v6)
        assert "NS2" not in result.pairs

    def test_enrich_comment_block_detects_pairs(self, ip_info_plugin):
        v4_rules = ["ACCEPT\thost:203.0.113.121\tnet"]
        v6_rules = ["ACCEPT\thost:<2001:db8:0:100:203:0:113:121>\tnet"]
        result = ip_info_plugin.enrich_comment_block("mandant-b", v4_rules, v6_rules)
        assert any("v4/v6 host pair" in c for c in result.prepend_comments)

    def test_enrich_comment_block_v4_only(self, ip_info_plugin):
        v4_rules = ["ACCEPT\thost:203.0.113.203\tnet"]
        v6_rules = []
        result = ip_info_plugin.enrich_comment_block("x", v4_rules, v6_rules)
        assert any("v4-only" in c for c in result.prepend_comments)
        assert any("203.0.113.203" in c for c in result.prepend_comments)

    def test_enrich_comment_block_empty(self, ip_info_plugin):
        # No mapped IPs in block
        result = ip_info_plugin.enrich_comment_block(
            "x", ["ACCEPT all net"], [])
        assert result.is_empty()


# ── PluginManager ─────────────────────────────────────────────────

@pytest.fixture
def plugin_config_dir(tmp_path):
    """Create a tmp dir with plugins.conf + ip-info.toml."""
    (tmp_path / "plugins").mkdir()
    (tmp_path / "plugins.conf").write_text("""
[[plugins]]
name = "ip-info"
enabled = true
""")
    (tmp_path / "plugins" / "ip-info.toml").write_text("""
[[mappings]]
v4_subnet = "203.0.113.0/24"
v6_prefix = "2001:db8:0:100::/64"
""")
    return tmp_path


class TestPluginManager:
    def test_load_from_config(self, plugin_config_dir):
        pm = PluginManager(plugin_config_dir)
        assert len(pm.plugins) == 1
        assert pm.plugins[0].name == "ip-info"

    def test_empty_config(self, tmp_path):
        pm = PluginManager(tmp_path)
        assert pm.plugins == []

    def test_disabled_plugin(self, tmp_path):
        (tmp_path / "plugins.conf").write_text("""
[[plugins]]
name = "ip-info"
enabled = false
""")
        pm = PluginManager(tmp_path)
        assert pm.plugins == []

    def test_unknown_plugin_skipped(self, tmp_path):
        (tmp_path / "plugins.conf").write_text("""
[[plugins]]
name = "does-not-exist"
enabled = true
""")
        pm = PluginManager(tmp_path)
        assert pm.plugins == []

    def test_map_v4_to_v6(self, plugin_config_dir):
        pm = PluginManager(plugin_config_dir)
        assert (pm.map_v4_to_v6("203.0.113.65")
                == "2001:db8:0:100:203:0:113:65")
        assert pm.map_v4_to_v6("8.8.8.8") is None

    def test_lookup_ip_aggregates(self, plugin_config_dir):
        pm = PluginManager(plugin_config_dir)
        info = pm.lookup_ip("203.0.113.65")
        assert info["v4"] == "203.0.113.65"
        assert "_sources" in info
        assert "ip-info" in info["_sources"]

    def test_priority_ordering(self, tmp_path):
        """Higher priority plugins are asked first for map_v4_to_v6."""
        # Create two ip-info plugins with different priorities via subclass
        class HighPrio(IpInfoPlugin):
            name = "high"
            priority = 100

            def map_v4_to_v6(self, ip):
                return "HIGH" if ip == "1.1.1.1" else None

        class LowPrio(IpInfoPlugin):
            name = "low"
            priority = 10

            def map_v4_to_v6(self, ip):
                return "LOW" if ip == "1.1.1.1" else None

        pm = PluginManager(tmp_path)
        pm.plugins = [LowPrio({"mappings": []}, tmp_path),
                      HighPrio({"mappings": []}, tmp_path)]
        pm.plugins.sort(key=lambda p: -p.priority)
        assert pm.map_v4_to_v6("1.1.1.1") == "HIGH"
