"""Unit tests for shorewall_nft_stagelab.fw_rules."""

from __future__ import annotations

import asyncio
import json

import pytest

from shorewall_nft_stagelab.fw_rules import (
    AcceptRule,
    _extract_zones_from_chain,
    discover_accept_rules,
    find_best_rule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


# Sample nft JSON output with ACCEPT rules in zone-pair chains
_SAMPLE_NFT_JSON = {
    "nftables": [
        {"metainfo": {"json_schema_version": 1}},
        {
            "rule": {
                "family": "inet",
                "table": "filter",
                "chain": "net2$FW",
                "handle": 10,
                "expr": [
                    {"match": {"op": "==", "right": "tcp"}},
                    {"match": {"op": "==", "right": 22}},
                    {"accept": None}
                ],
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "filter",
                "chain": "net2$FW",
                "handle": 11,
                "expr": [
                    {"match": {"op": "==", "right": "udp"}},
                    {"match": {"op": "==", "right": 53}},
                    {"accept": None}
                ],
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "filter",
                "chain": "lan2net",
                "handle": 20,
                "expr": [
                    {"match": {"op": "==", "right": "icmp"}},
                    {"accept": None}
                ],
            }
        },
    ]
}


# ---------------------------------------------------------------------------
# Tests for _extract_zones_from_chain
# ---------------------------------------------------------------------------

def test_extract_zones_standard_chain():
    """Standard chain names like 'net2$FW' extract zones correctly."""
    assert _extract_zones_from_chain("net2$FW") == ("net", "$FW")
    assert _extract_zones_from_chain("lan2net") == ("lan", "net")
    assert _extract_zones_from_chain("dmz2$FW-foo") == ("dmz", "$FW")


def test_extract_zones_malformed_chain():
    """Chain names that don't match the pattern return None."""
    assert _extract_zones_from_chain("INPUT") is None
    assert _extract_zones_from_chain("FORWARD") is None
    assert _extract_zones_from_chain("OUTPUT") is None
    assert _extract_zones_from_chain("foo") is None


# ---------------------------------------------------------------------------
# Tests for discover_accept_rules
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_discover_accept_rules_json(monkeypatch):
    """Mock SSH subprocess with canned nft JSON; parse returns AcceptRules."""

    async def _fake_create_subprocess(*args, **kwargs):
        # Return a fake process with pre-canned JSON output
        class FakeProc:
            returncode = 0

            async def communicate(self):
                json_bytes = json.dumps(_SAMPLE_NFT_JSON).encode("utf-8")
                return json_bytes, b""

        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create_subprocess)

    rules = await discover_accept_rules("root@192.168.1.1")

    # Should extract 3 rules (tcp/22, udp/53, icmp)
    assert len(rules) == 3

    # Check first rule (SSH)
    ssh_rule = rules[0]
    assert ssh_rule.zone_src == "net"
    assert ssh_rule.zone_dst == "$FW"
    assert ssh_rule.proto == "tcp"
    assert ssh_rule.port == 22

    # Check second rule (DNS)
    dns_rule = rules[1]
    assert dns_rule.zone_src == "net"
    assert dns_rule.zone_dst == "$FW"
    assert dns_rule.proto == "udp"
    assert dns_rule.port == 53

    # Check third rule (ICMP)
    icmp_rule = rules[2]
    assert icmp_rule.zone_src == "lan"
    assert icmp_rule.zone_dst == "net"
    assert icmp_rule.proto == "icmp"
    assert icmp_rule.port is None


@pytest.mark.asyncio
async def test_discover_soft_fail_ssh_error(monkeypatch):
    """SSH failure (OSError) logs warning and returns empty list."""

    async def _fake_subprocess_fail(*args, **kwargs):
        raise OSError("Connection refused")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_subprocess_fail)

    rules = await discover_accept_rules("root@bad-host")
    assert rules == []


@pytest.mark.asyncio
async def test_discover_soft_fail_nft_error(monkeypatch):
    """nft command returns non-zero exit code; log warning and return []."""

    async def _fake_subprocess_nft_fail(*args, **kwargs):
        class FakeProc:
            returncode = 1

            async def communicate(self):
                return b"", b"nft command failed"

        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_subprocess_nft_fail)

    rules = await discover_accept_rules("root@192.168.1.1")
    assert rules == []


@pytest.mark.asyncio
async def test_discover_soft_fail_json_error(monkeypatch):
    """nft outputs invalid JSON; log warning and return []."""

    async def _fake_subprocess_bad_json(*args, **kwargs):
        class FakeProc:
            returncode = 0

            async def communicate(self):
                return b"not valid json", b""

        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_subprocess_bad_json)

    rules = await discover_accept_rules("root@192.168.1.1")
    assert rules == []


# ---------------------------------------------------------------------------
# Tests for find_best_rule
# ---------------------------------------------------------------------------

def test_find_best_rule_exact_match():
    """Perfect match (proto + port + zones) returns the rule."""
    rules = [
        AcceptRule(zone_src="net", zone_dst="$FW", proto="tcp", port=22, rule_index=1),
        AcceptRule(zone_src="net", zone_dst="$FW", proto="tcp", port=80, rule_index=2),
        AcceptRule(zone_src="lan", zone_dst="$FW", proto="tcp", port=22, rule_index=3),
    ]

    best = find_best_rule(rules, proto="tcp", port=22, zone_src="net", zone_dst="$FW")
    assert best is not None
    assert best.port == 22
    assert best.zone_src == "net"
    assert best.zone_dst == "$FW"


def test_find_best_rule_partial_match():
    """Proto match without port match still returns a rule."""
    rules = [
        AcceptRule(zone_src="net", zone_dst="$FW", proto="tcp", port=80, rule_index=1),
        AcceptRule(zone_src="net", zone_dst="$FW", proto="tcp", port=443, rule_index=2),
    ]

    # Looking for port 22, but only 80 and 443 exist
    # Should still return a rule because proto matches
    best = find_best_rule(rules, proto="tcp", port=22, zone_src="net", zone_dst="$FW")
    assert best is not None
    assert best.proto == "tcp"


def test_find_best_rule_zone_mismatch():
    """Zone mismatch reduces score; best zone match wins."""
    rules = [
        AcceptRule(zone_src="net", zone_dst="$FW", proto="tcp", port=22, rule_index=1),
        AcceptRule(zone_src="lan", zone_dst="$FW", proto="tcp", port=22, rule_index=2),
    ]

    # Looking for lan → $FW
    best = find_best_rule(rules, proto="tcp", port=22, zone_src="lan", zone_dst="$FW")
    assert best is not None
    assert best.zone_src == "lan"


def test_find_best_rule_icmp_no_port():
    """ICMP rules have port=None; matching works correctly."""
    rules = [
        AcceptRule(zone_src="net", zone_dst="$FW", proto="icmp", port=None, rule_index=1),
        AcceptRule(zone_src="net", zone_dst="$FW", proto="tcp", port=22, rule_index=2),
    ]

    best = find_best_rule(rules, proto="icmp", port=None, zone_src="net", zone_dst="$FW")
    assert best is not None
    assert best.proto == "icmp"
    assert best.port is None


def test_find_best_rule_empty():
    """Empty rules list returns None."""
    rules: list[AcceptRule] = []

    best = find_best_rule(rules, proto="tcp", port=22, zone_src="net", zone_dst="$FW")
    assert best is None


def test_find_best_rule_proto_mismatch():
    """Protocol mismatch returns None (no rule matches)."""
    rules = [
        AcceptRule(zone_src="net", zone_dst="$FW", proto="tcp", port=22, rule_index=1),
        AcceptRule(zone_src="net", zone_dst="$FW", proto="udp", port=53, rule_index=2),
    ]

    # Looking for ICMP, but only TCP/UDP exist
    best = find_best_rule(rules, proto="icmp", port=None, zone_src="net", zone_dst="$FW")
    assert best is None
