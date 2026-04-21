"""Tests for shorewalld.seed.SeedCoordinator.

Coverage:
* tracker-only collection — fast, < 50 ms
* dnstap_active + wait_for_passive=True → always waits full timeout
* data arriving during tracker polling is captured in the response
* wait_for_passive=False with dnstap active → returns early
* pull resolver contribution
* max-TTL merge rule: duplicate (qname, ip) keeps highest TTL
* iplist snapshot
* control-socket AF_UNIX roundtrip
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import MagicMock


from shorewalld.dns_set_tracker import FAMILY_V4, FAMILY_V6, DnsSetTracker
from shorewalld.seed import SeedCoordinator, _merge, _merged_to_response
from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsSetSpec


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

IP_A = ipaddress.IPv4Address("1.2.3.4").packed
IP_B = ipaddress.IPv4Address("5.6.7.8").packed
IP_C = ipaddress.IPv6Address("2001:db8::1").packed


def _loaded_tracker(*qnames: str) -> DnsSetTracker:
    reg = DnsSetRegistry()
    for qn in qnames:
        reg.add_spec(DnsSetSpec(qn, 300, 86400, 512))
    tracker = DnsSetTracker()
    tracker.load_registry(reg)
    return tracker


def _populate_tracker(
    tracker: DnsSetTracker,
    qname: str,
    family: int,
    ip_bytes: bytes,
    ttl: int,
) -> None:
    set_id = tracker.set_id_for(qname, family)
    assert set_id is not None
    now = time.monotonic()
    with tracker._lock:  # type: ignore[attr-defined]
        state = tracker._states[set_id]  # type: ignore[attr-defined]
        # elements dict keys are big-endian int after the ip-key refactor.
        ip_int = int.from_bytes(ip_bytes, "big")
        state.elements[ip_int] = now + ttl
        state.metrics.elements = len(state.elements)


# ---------------------------------------------------------------------------
# test_seed_tracker_only
# ---------------------------------------------------------------------------


def test_seed_tracker_only():
    """Tracker has data; should return < 500 ms (no passive wait)."""
    tracker = _loaded_tracker("github.com")
    _populate_tracker(tracker, "github.com", FAMILY_V4, IP_A, 60)
    coord = SeedCoordinator(tracker=tracker, dnstap_active=False)

    req = {
        "cmd": "request-seed",
        "netns": "",
        "name": "test",
        "timeout_ms": 5000,
        "qnames": ["github.com"],
        "iplist_sets": [],
        "wait_for_passive": False,
    }

    async def _run():
        t0 = time.monotonic()
        resp = await coord.handle(req)
        return resp, time.monotonic() - t0

    resp, elapsed = asyncio.run(_run())
    assert resp["ok"] is True
    assert elapsed < 0.5, f"Should return quickly, took {elapsed:.3f}s"
    dns = resp["seeds"]["dns"]
    assert "github.com" in dns
    assert any(e["ip"] == "1.2.3.4" for e in dns["github.com"]["v4"])
    assert resp["timeout_hit"] is False
    assert "tracker" in resp["sources_contributed"]


# ---------------------------------------------------------------------------
# test_seed_dnstap_waits_full_timeout
# ---------------------------------------------------------------------------


def test_seed_dnstap_waits_full_timeout():
    """dnstap active + wait_for_passive=True → waits full timeout even with no data."""
    tracker = _loaded_tracker("github.com")
    coord = SeedCoordinator(tracker=tracker, dnstap_active=True, pbdns_active=False)

    timeout_ms = 250
    req = {
        "cmd": "request-seed",
        "netns": "",
        "name": "test",
        "timeout_ms": timeout_ms,
        "qnames": ["github.com"],
        "iplist_sets": [],
        "wait_for_passive": True,
    }

    async def _run():
        t0 = time.monotonic()
        resp = await coord.handle(req)
        return resp, (time.monotonic() - t0) * 1000

    resp, elapsed_ms = asyncio.run(_run())
    assert resp["ok"] is True
    assert resp["timeout_hit"] is True
    assert resp["dnstap_waited"] is True
    assert elapsed_ms >= timeout_ms - 50, (
        f"Should have waited ~{timeout_ms}ms, waited {elapsed_ms:.0f}ms")


# ---------------------------------------------------------------------------
# test_seed_dnstap_new_data_during_wait
# ---------------------------------------------------------------------------


def test_seed_dnstap_new_data_during_wait():
    """Data injected into tracker mid-wait appears in the final response."""
    tracker = _loaded_tracker("github.com")
    coord = SeedCoordinator(tracker=tracker, dnstap_active=True)

    timeout_ms = 500

    async def _run():
        async def _inject_after_delay():
            await asyncio.sleep(0.1)
            _populate_tracker(tracker, "github.com", FAMILY_V4, IP_A, 60)

        asyncio.create_task(_inject_after_delay())
        req = {
            "cmd": "request-seed",
            "netns": "",
            "name": "test",
            "timeout_ms": timeout_ms,
            "qnames": ["github.com"],
            "iplist_sets": [],
            "wait_for_passive": True,
        }
        return await coord.handle(req)

    resp = asyncio.run(_run())
    assert resp["ok"] is True
    # Data arrived mid-wait before the deadline → not a timeout.
    assert resp["timeout_hit"] is False
    dns = resp["seeds"]["dns"]
    assert "github.com" in dns
    assert any(e["ip"] == "1.2.3.4" for e in dns["github.com"]["v4"])


# ---------------------------------------------------------------------------
# test_seed_no_passive_wait
# ---------------------------------------------------------------------------


def test_seed_no_passive_wait():
    """wait_for_passive=False with dnstap active → returns early without full wait."""
    tracker = _loaded_tracker("github.com")
    _populate_tracker(tracker, "github.com", FAMILY_V4, IP_A, 60)
    coord = SeedCoordinator(tracker=tracker, dnstap_active=True)

    req = {
        "cmd": "request-seed",
        "netns": "",
        "name": "test",
        "timeout_ms": 5000,
        "qnames": ["github.com"],
        "iplist_sets": [],
        "wait_for_passive": False,
    }

    async def _run():
        t0 = time.monotonic()
        resp = await coord.handle(req)
        return resp, time.monotonic() - t0

    resp, elapsed = asyncio.run(_run())
    assert resp["ok"] is True
    assert resp["dnstap_waited"] is False
    assert resp["timeout_hit"] is False
    assert elapsed < 0.5, f"Should return quickly, took {elapsed:.3f}s"


# ---------------------------------------------------------------------------
# test_seed_merges_max_ttl
# ---------------------------------------------------------------------------


def test_seed_merges_max_ttl():
    """When tracker and pull return the same IP, max TTL is kept."""
    tracker = _loaded_tracker("github.com")
    _populate_tracker(tracker, "github.com", FAMILY_V4, IP_A, 30)

    mock_pull = MagicMock()
    mock_pull._primaries = {"github.com": True}

    async def _resolve_now(qname):
        return [(FAMILY_V4, IP_A, 3600)]

    mock_pull.resolve_now = _resolve_now

    coord = SeedCoordinator(
        tracker=tracker,
        pull_resolver=mock_pull,
        dnstap_active=False,
    )
    req = {
        "cmd": "request-seed",
        "netns": "",
        "name": "test",
        "timeout_ms": 5000,
        "qnames": ["github.com"],
        "iplist_sets": [],
        "wait_for_passive": False,
    }

    resp = asyncio.run(coord.handle(req))

    assert resp["ok"] is True
    dns = resp["seeds"]["dns"]
    v4 = dns["github.com"]["v4"]
    ip_entry = next((e for e in v4 if e["ip"] == "1.2.3.4"), None)
    assert ip_entry is not None
    assert ip_entry["ttl"] == 3600, f"Expected max TTL 3600, got {ip_entry['ttl']}"
    assert "pull" in resp["sources_contributed"]


# ---------------------------------------------------------------------------
# test_seed_iplist_snapshot
# ---------------------------------------------------------------------------


def test_seed_iplist_snapshot():
    """IP-list prefixes are included in the seed response when requested."""
    tracker = _loaded_tracker("github.com")

    mock_state = SimpleNamespace(
        cfg=SimpleNamespace(
            set_v4="aws_ec2_v4",
            set_v6="aws_ec2_v6",
        ),
        current_v4={"52.0.0.0/11", "54.0.0.0/8"},
        current_v6=set(),
    )
    mock_iplist = MagicMock()
    mock_iplist._states = {"aws_ec2": mock_state}

    coord = SeedCoordinator(
        tracker=tracker,
        iplist_tracker=mock_iplist,
        dnstap_active=False,
    )
    req = {
        "cmd": "request-seed",
        "netns": "",
        "name": "test",
        "timeout_ms": 1000,
        "qnames": [],
        "iplist_sets": ["aws_ec2_v4"],
        "wait_for_passive": False,
    }

    resp = asyncio.run(coord.handle(req))

    assert resp["ok"] is True
    iplist = resp["seeds"]["iplist"]
    assert "aws_ec2_v4" in iplist
    assert "52.0.0.0/11" in iplist["aws_ec2_v4"]
    assert "iplist" in resp["sources_contributed"]


# ---------------------------------------------------------------------------
# test_seed_too_many_in_flight
# ---------------------------------------------------------------------------


def test_seed_too_many_in_flight():
    """Requests beyond _MAX_IN_FLIGHT return an error immediately."""
    from shorewalld.seed import _MAX_IN_FLIGHT

    coord = SeedCoordinator()
    coord._in_flight = _MAX_IN_FLIGHT

    req = {
        "cmd": "request-seed",
        "netns": "",
        "name": "test",
        "timeout_ms": 1000,
        "qnames": [],
        "iplist_sets": [],
        "wait_for_passive": False,
    }

    resp = asyncio.run(coord.handle(req))
    assert resp["ok"] is False
    assert "too many" in resp["error"]


# ---------------------------------------------------------------------------
# test_merge_* helpers
# ---------------------------------------------------------------------------


def test_merge_keeps_max_ttl():
    """_merge helper keeps highest TTL on collision."""
    target: dict = {("github.com", FAMILY_V4): {IP_A: 30}}
    source: dict = {("github.com", FAMILY_V4): {IP_A: 3600, IP_B: 60}}
    _merge(target, source)
    assert target[("github.com", FAMILY_V4)][IP_A] == 3600
    assert target[("github.com", FAMILY_V4)][IP_B] == 60


def test_merged_to_response_format():
    """_merged_to_response produces correct wire format."""
    data = {
        ("github.com", FAMILY_V4): {IP_A: 60},
        ("github.com", FAMILY_V6): {IP_C: 300},
    }
    out = _merged_to_response(data)
    assert "github.com" in out
    assert any(e["ip"] == "1.2.3.4" for e in out["github.com"]["v4"])
    assert any(e["ip"] == "2001:db8::1" for e in out["github.com"]["v6"])


# ---------------------------------------------------------------------------
# test_control_request_seed_roundtrip
# ---------------------------------------------------------------------------


def test_control_request_seed_roundtrip():
    """Full AF_UNIX + JSON roundtrip through the control server."""
    from shorewalld.control import ControlServer

    tracker = _loaded_tracker("github.com")
    _populate_tracker(tracker, "github.com", FAMILY_V4, IP_A, 120)

    coord = SeedCoordinator(tracker=tracker, dnstap_active=False)

    async def _run():
        with tempfile.TemporaryDirectory() as tmpdir:
            sock_path = os.path.join(tmpdir, "control.sock")
            server = ControlServer(socket_path=sock_path)
            server.register_handler("request-seed", coord.handle)
            await server.start()
            try:
                req = json.dumps({
                    "cmd": "request-seed",
                    "netns": "",
                    "name": "fw",
                    "timeout_ms": 1000,
                    "qnames": ["github.com"],
                    "iplist_sets": [],
                    "wait_for_passive": False,
                }).encode() + b"\n"

                reader, writer = await asyncio.open_unix_connection(sock_path)
                try:
                    writer.write(req)
                    await writer.drain()
                    line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                finally:
                    writer.close()
                    await writer.wait_closed()
                return json.loads(line)
            finally:
                await server.shutdown()

    resp = asyncio.run(_run())
    assert resp["ok"] is True
    assert "github.com" in resp["seeds"]["dns"]
    v4 = resp["seeds"]["dns"]["github.com"]["v4"]
    assert any(e["ip"] == "1.2.3.4" for e in v4)
