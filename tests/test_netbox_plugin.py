"""Tests for the netbox plugin with mocked API."""

from __future__ import annotations

import json
import time
from unittest.mock import patch

import pytest

from shorewall_nft.plugins.builtin.netbox import NetboxPlugin


@pytest.fixture
def netbox_plugin(tmp_path):
    (tmp_path / "plugins").mkdir()
    config = {
        "url": "https://netbox.example.com",
        "token": "test-token",
        "cache_ttl": 3600,
        "bulk_subnets": ["203.0.113.0/24"],
        "priority": 100,
    }
    return NetboxPlugin(config, tmp_path)


@pytest.fixture
def netbox_with_cache(netbox_plugin):
    """Netbox plugin with a pre-populated cache (dns_name-based linking)."""
    netbox_plugin._cache = {
        "_meta": {
            "refreshed_at": int(time.time()),
            "bulk_subnets": ["203.0.113.0/24"],
        },
        "by_ip": {
            "203.0.113.86": {
                "dns_name": "mail.example.com",
                "tenant": "Example Inc",
                "customer": "12345",
                "status": "active",
                "tags": ["production", "mail"],
                "description": "VW OTLG",
                "role": None,
            },
            "2001:db8:0:100:203:0:113:86": {
                "dns_name": "mail.example.com",
                "tenant": "InternalOrg",
                "customer": None,
                "status": "active",
                "tags": ["production", "mail"],
                "description": "",
                "role": None,
            },
            "203.0.113.121": {
                "dns_name": "test.example.com",
                "tenant": "Another Customer Inc",
                "customer": "67890",
                "status": "active",
                "tags": ["test"],
                "description": "",
                "role": None,
            },
            "203.0.113.200": {
                "dns_name": "legacy.example.com",
                "tenant": "Legacy Customer",
                "customer": "999999",
                "status": "deprecated",
                "tags": [],
                "description": "",
                "role": None,
            },
            # Pattern mismatch: v4 .183 but v6 :46 (same dns_name)
            "203.0.113.183": {
                "dns_name": "h00137.host-up.de",
                "tenant": "Some Customer",
                "customer": "200001",
                "status": "active",
                "tags": [],
                "description": "",
                "role": None,
            },
            "2001:db8:0:100:203:0:113:46": {
                "dns_name": "h00137.host-up.de",
                "tenant": "Some Customer",
                "customer": "200001",
                "status": "active",
                "tags": [],
                "description": "",
                "role": None,
            },
        },
        "by_dns_name": {
            "mail.example.com": [
                "203.0.113.86", "2001:db8:0:100:203:0:113:86"],
            "test.example.com": ["203.0.113.121"],
            "legacy.example.com": ["203.0.113.200"],
            "h00137.host-up.de": [
                "203.0.113.183", "2001:db8:0:100:203:0:113:46"],
        },
    }
    return netbox_plugin


class TestNetboxCache:
    def test_load_missing_cache(self, netbox_plugin):
        netbox_plugin.load()
        assert netbox_plugin._cache["by_ip"] == {}

    def test_load_existing_cache(self, netbox_plugin, tmp_path):
        cache_data = {
            "_meta": {"refreshed_at": 1000, "bulk_subnets": []},
            "by_ip": {"1.2.3.4": {"hostname": "test"}},
            "by_device": {},
        }
        (tmp_path / "plugins" / "netbox-cache.json").write_text(
            json.dumps(cache_data))
        netbox_plugin.load()
        assert netbox_plugin._cache["by_ip"]["1.2.3.4"]["hostname"] == "test"

    def test_cache_stale_check(self, netbox_plugin):
        netbox_plugin._cache["_meta"]["refreshed_at"] = 0
        assert netbox_plugin._is_cache_stale()
        netbox_plugin._cache["_meta"]["refreshed_at"] = int(time.time())
        assert not netbox_plugin._is_cache_stale()

    def test_save_cache(self, netbox_plugin, tmp_path):
        netbox_plugin._cache["by_ip"] = {"1.1.1.1": {"hostname": "x"}}
        netbox_plugin._save_cache()
        saved = json.loads((tmp_path / "plugins" / "netbox-cache.json").read_text())
        assert saved["by_ip"]["1.1.1.1"]["hostname"] == "x"


class TestNetboxLookups:
    def test_lookup_ip(self, netbox_with_cache):
        info = netbox_with_cache.lookup_ip("203.0.113.86")
        assert info["dns_name"] == "mail.example.com"
        assert info["customer"] == "12345"
        assert info["status"] == "active"

    def test_lookup_unknown(self, netbox_with_cache):
        with patch.object(netbox_with_cache, "_fetch_on_demand", return_value=None):
            assert netbox_with_cache.lookup_ip("8.8.8.8") is None

    def test_map_v4_to_v6(self, netbox_with_cache):
        assert (netbox_with_cache.map_v4_to_v6("203.0.113.86")
                == "2001:db8:0:100:203:0:113:86")

    def test_map_v4_to_v6_pattern_mismatch(self, netbox_with_cache):
        """Critical: v4 .183 and v6 :46 linked via dns_name, not pattern."""
        assert (netbox_with_cache.map_v4_to_v6("203.0.113.183")
                == "2001:db8:0:100:203:0:113:46")

    def test_map_v4_to_v6_no_v6_for_dns(self, netbox_with_cache):
        # test.example.com has only v4, no v6
        assert netbox_with_cache.map_v4_to_v6("203.0.113.121") is None

    def test_map_v6_to_v4(self, netbox_with_cache):
        assert (netbox_with_cache.map_v6_to_v4(
                "2001:db8:0:100:203:0:113:86") == "203.0.113.86")

    def test_map_v6_to_v4_pattern_mismatch(self, netbox_with_cache):
        assert (netbox_with_cache.map_v6_to_v4(
                "2001:db8:0:100:203:0:113:46") == "203.0.113.183")


class TestNetboxEnrichment:
    def test_enrich_comment_block(self, netbox_with_cache):
        v4_rules = [
            "ACCEPT\thost:203.0.113.86\tnet",
            "ACCEPT\thost:203.0.113.121\tnet",
        ]
        result = netbox_with_cache.enrich_comment_block("test", v4_rules, [])
        comments = "\n".join(result.prepend_comments)
        assert "2 customer" in comments
        assert "mail.example.com" in comments
        assert "test.example.com" in comments

    def test_enrich_comment_block_single_customer(self, netbox_with_cache):
        v4_rules = ["ACCEPT\thost:203.0.113.86\tnet"]
        result = netbox_with_cache.enrich_comment_block("mail", v4_rules, [])
        # Customer 12345 is the only one → tag renamed
        assert result.tag is not None
        assert "12345" in result.tag

    def test_enrich_comment_block_stale_warning(self, netbox_with_cache):
        v4_rules = ["ACCEPT\thost:203.0.113.200\tnet"]
        result = netbox_with_cache.enrich_comment_block("legacy", v4_rules, [])
        comments = "\n".join(result.prepend_comments)
        assert "WARNING" in comments
        assert "stale" in comments

    def test_enrich_params_pair_same_dns_name(self, netbox_with_cache):
        v4 = {"MAIL5": "MAIL5=203.0.113.86"}
        v6 = {"MAIL5": "MAIL5=2001:db8:0:100:203:0:113:86"}
        result = netbox_with_cache.enrich_params(v4, v6)
        assert "MAIL5" in result.pairs
        assert "MAIL5" in result.annotations
        assert "mail.example.com" in result.annotations["MAIL5"]

    def test_enrich_params_pair_pattern_mismatch(self, netbox_with_cache):
        """v4 .183 and v6 :46 should be paired via dns_name."""
        v4 = {"H137": "H137=203.0.113.183"}
        v6 = {"H137": "H137=2001:db8:0:100:203:0:113:46"}
        result = netbox_with_cache.enrich_params(v4, v6)
        assert "H137" in result.pairs


class TestNetboxIndexing:
    def test_index_real_netbox_format(self, netbox_plugin):
        """Real Netbox 4.5+ API format (as returned by live deployments)."""
        ip_obj = {
            "id": 6097,
            "family": {"value": 4, "label": "IPv4"},
            "address": "203.0.113.86/24",
            "vrf": None,
            "tenant": {
                "id": 566,
                "display": "12345 - Example Inc",
                "name": "12345 - Example Inc",
                "slug": "example-corp",
                "description": ""
            },
            "status": {"value": "active", "label": "Active"},
            "role": None,
            "assigned_object_type": None,
            "assigned_object_id": None,
            "assigned_object": None,
            "dns_name": "mail.example.com",
            "description": "VW OTLG",
            "tags": [],
            "custom_fields": {},
            "last_updated": "2023-03-03T11:21:40.421550Z",
        }
        by_ip: dict = {}
        by_dns: dict = {}
        netbox_plugin._index_ip(ip_obj, by_ip, by_dns)
        assert "203.0.113.86" in by_ip
        entry = by_ip["203.0.113.86"]
        # Customer number extracted from tenant name
        assert entry["customer"] == "12345"
        assert entry["tenant"] == "Example Inc"
        assert entry["dns_name"] == "mail.example.com"
        assert entry["status"] == "active"
        # Indexed by dns_name
        assert "mail.example.com" in by_dns
        assert "203.0.113.86" in by_dns["mail.example.com"]

    def test_index_internal_tenant(self, netbox_plugin):
        """Tenant without customer number (internal host)."""
        ip_obj = {
            "address": "203.0.113.2/24",
            "tenant": {"name": "InternalOrg", "slug": "internal-org"},
            "status": {"value": "active"},
            "dns_name": "",
            "tags": [],
        }
        by_ip: dict = {}
        by_dns: dict = {}
        netbox_plugin._index_ip(ip_obj, by_ip, by_dns)
        entry = by_ip["203.0.113.2"]
        assert entry["customer"] is None
        assert entry["tenant"] == "InternalOrg"
        # No dns_name → not in by_dns
        assert by_dns == {}

    def test_index_ip_deprecated_status(self, netbox_plugin):
        ip_obj = {
            "address": "5.5.5.5/32",
            "status": {"value": "deprecated"},
            "tenant": None,
            "tags": [],
            "dns_name": "",
        }
        by_ip: dict = {}
        by_dns: dict = {}
        netbox_plugin._index_ip(ip_obj, by_ip, by_dns)
        assert by_ip["5.5.5.5"]["status"] == "deprecated"

    def test_parse_tenant(self):
        """Parsing tenant names with/without customer number."""
        from shorewall_nft.plugins.builtin.netbox import _parse_tenant
        assert _parse_tenant("12345 - Example Inc") == (
            "12345", "Example Inc")
        assert _parse_tenant("InternalOrg") == (None, "InternalOrg")
        assert _parse_tenant("") == (None, "")
        assert _parse_tenant("12345-Foo") == ("12345", "Foo")


class TestNetboxSnapshot:
    """Test snapshot-mode loading (compatible with shorewall2foomuuri format)."""

    def test_load_snapshot(self, tmp_path):
        (tmp_path / "plugins").mkdir()
        snapshot = tmp_path / "plugins" / "snapshot.json"
        snapshot.write_text(json.dumps({
            "ip_addresses": {
                "203.0.113.86": {
                    "address": "203.0.113.86/32",
                    "dns_name": "mail.example.com",
                    "tenant": "12345 - Example Inc",
                    "tags": ["production", "mail"],
                    "status": "active",
                },
                "2001:db8:0:100:203:0:113:86": {
                    "address": "2001:db8:0:100:203:0:113:86/128",
                    "dns_name": "mail.example.com",
                    "tenant": "InternalOrg",
                    "tags": ["production", "mail"],
                    "status": "active",
                },
            },
        }))
        config = {
            "snapshot": "plugins/snapshot.json",
            "bulk_subnets": [],
        }
        p = NetboxPlugin(config, tmp_path)
        p.load()
        info = p.lookup_ip("203.0.113.86")
        assert info["customer"] == "12345"
        assert info["tenant"] == "Example Inc"
        # v4 → v6 via dns_name
        assert p.map_v4_to_v6("203.0.113.86") == "2001:db8:0:100:203:0:113:86"
