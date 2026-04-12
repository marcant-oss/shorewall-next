"""Tests for the DNS-wire fast-path qname extractor and the
Phase 2 TrackerBridge adapter.
"""

from __future__ import annotations

import asyncio

import pytest

from shorewalld.dns_set_tracker import (
    DnsSetTracker,
)
from shorewalld.dns_wire import (
    DNS_HEADER_LEN,
    extract_qname,
    extract_rcode,
    is_response,
)
from shorewalld.dnstap_bridge import TrackerBridge
from shorewalld.setwriter import SetWriter
from shorewalld.worker_router import (
    WorkerRouter,
    inproc_worker_pair,
)
from shorewall_nft.nft.dns_sets import (
    DnsSetRegistry,
    DnsSetSpec,
    qname_to_set_name,
)

# ---------------------------------------------------------------------------
# DNS wire synthesiser — build minimal legal DNS responses for tests.
# Shorter than importing dnspython and gives precise control over bad inputs.
# ---------------------------------------------------------------------------


def make_dns_query_wire(qname: str, qtype: int = 1) -> bytes:
    """Build a DNS query header+question; no answer section."""
    header = bytearray(12)
    header[0] = 0x12  # ID high
    header[1] = 0x34  # ID low
    header[2] = 0x01  # flags: RD
    header[3] = 0x00
    header[4] = 0x00  # qdcount high
    header[5] = 0x01  # qdcount low = 1
    # no answers/auth/additional
    wire = bytearray(header)
    for label in qname.rstrip(".").split("."):
        wire.append(len(label))
        wire.extend(label.encode("ascii"))
    wire.append(0)
    wire.extend(qtype.to_bytes(2, "big"))  # QTYPE
    wire.extend((1).to_bytes(2, "big"))    # QCLASS=IN
    return bytes(wire)


def make_dns_response_wire(qname: str, rcode: int = 0) -> bytes:
    """Same as a query but with QR bit set and rcode."""
    wire = bytearray(make_dns_query_wire(qname))
    wire[2] = 0x81           # QR=1, RD=1
    wire[3] = rcode & 0x0F
    return bytes(wire)


class TestExtractQname:
    def test_simple_query(self):
        wire = make_dns_query_wire("github.com")
        result = extract_qname(wire)
        assert result is not None
        qname, pos = result
        assert qname == "github.com"
        # pos should point at QTYPE (after the 0x00 terminator)
        # header(12) + len(1) + "github"(6) + len(1) + "com"(3) + term(1) = 24
        assert pos == DNS_HEADER_LEN + 12

    def test_canonicalises_case(self):
        # Our qname matching is case-insensitive, but the wire
        # format is as-sent. Verify lower-casing happens.
        wire = make_dns_query_wire("GitHub.Com")
        qname, _ = extract_qname(wire)
        assert qname == "github.com"

    def test_returns_none_on_truncated_header(self):
        assert extract_qname(b"\x00" * 10) is None

    def test_returns_none_on_zero_qdcount(self):
        # QDCOUNT=0 — not a useful frame.
        wire = bytearray(make_dns_query_wire("github.com"))
        wire[4] = 0
        wire[5] = 0
        assert extract_qname(bytes(wire)) is None

    def test_returns_none_on_compression_pointer(self):
        # Question section with compression pointer is illegal per
        # RFC 1035 — 0xC0+offset in the label-length slot.
        wire = bytearray(12)
        wire[5] = 1   # qdcount=1
        wire.extend(b"\xc0\x0c")  # pointer to header start
        assert extract_qname(bytes(wire)) is None

    def test_returns_none_on_label_too_long(self):
        wire = bytearray(12)
        wire[5] = 1
        wire.append(64)   # label length > 63
        wire.extend(b"x" * 64)
        wire.append(0)
        assert extract_qname(bytes(wire)) is None

    def test_returns_none_on_unterminated_labels(self):
        wire = bytearray(12)
        wire[5] = 1
        # Never terminate — fill with labels until we blow past
        # MAX_QNAME_LEN.
        for _ in range(8):
            wire.append(63)
            wire.extend(b"x" * 63)
        assert extract_qname(bytes(wire)) is None

    def test_memoryview_input(self):
        wire = make_dns_query_wire("api.stripe.com")
        qname, _ = extract_qname(memoryview(wire))
        assert qname == "api.stripe.com"


class TestExtractRcode:
    def test_noerror_returns_zero(self):
        wire = make_dns_response_wire("github.com", rcode=0)
        assert extract_rcode(wire) == 0

    def test_nxdomain(self):
        wire = make_dns_response_wire("nonesuch.example", rcode=3)
        assert extract_rcode(wire) == 3

    def test_truncated(self):
        assert extract_rcode(b"\x00") is None


class TestIsResponse:
    def test_query_has_qr_clear(self):
        wire = make_dns_query_wire("github.com")
        assert is_response(wire) is False

    def test_response_has_qr_set(self):
        wire = make_dns_response_wire("github.com")
        assert is_response(wire) is True


# ---------------------------------------------------------------------------
# TrackerBridge tests — full pipeline including Phase 2 SetWriter.
# ---------------------------------------------------------------------------


@pytest.fixture
def tracker():
    reg = DnsSetRegistry()
    reg.add_spec(DnsSetSpec(
        qname="github.com", ttl_floor=300, ttl_ceil=3600, size=256))
    reg.add_spec(DnsSetSpec(
        qname="api.stripe.com", ttl_floor=60, ttl_ceil=3600, size=64))
    t = DnsSetTracker()
    t.load_registry(reg)
    return t


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def bridge_setup(tracker, event_loop):
    """Wire TrackerBridge → SetWriter → inproc WorkerRouter."""
    scripts: list[str] = []

    def lookup(key):
        entry = tracker.name_for(key[0])
        if entry is None:
            return None
        qname, family = entry
        return qname_to_set_name(
            qname, "v4" if family == 4 else "v6")

    pw, _ = inproc_worker_pair(
        tracker, event_loop, lookup, apply_cb=scripts.append)
    router = WorkerRouter(tracker=tracker, loop=event_loop)
    router._workers["inproc"] = pw
    writer = SetWriter(
        tracker, router,
        batch_window_sec=0.02, loop=event_loop)
    bridge = TrackerBridge(tracker, writer, default_netns="inproc")

    async def prime():
        await writer.start()

    event_loop.run_until_complete(prime())
    yield bridge, writer, router, scripts
    event_loop.run_until_complete(writer.shutdown())
    event_loop.run_until_complete(router.shutdown())


class TestTrackerBridgeApply:
    def test_v4_update_reaches_worker(
        self, tracker, event_loop, bridge_setup
    ):
        bridge, writer, router, scripts = bridge_setup
        bridge.apply(
            qname="github.com",
            a_rrs=[b"\x01\x02\x03\x04"],
            aaaa_rrs=[],
            ttl=600,
        )
        event_loop.run_until_complete(asyncio.sleep(0.1))
        assert len(scripts) >= 1
        assert "dns_github_com_v4" in scripts[0]
        assert "1.2.3.4" in scripts[0]
        assert bridge.metrics.proposals_total == 1

    def test_v6_update(self, tracker, event_loop, bridge_setup):
        bridge, writer, router, scripts = bridge_setup
        v6 = bytes([0xAA] * 16)
        bridge.apply(
            qname="github.com", a_rrs=[], aaaa_rrs=[v6], ttl=600)
        event_loop.run_until_complete(asyncio.sleep(0.1))
        assert "dns_github_com_v6" in "\n".join(scripts)

    def test_unknown_qname_drops_without_submit(
        self, tracker, event_loop, bridge_setup
    ):
        bridge, writer, router, scripts = bridge_setup
        bridge.apply(
            qname="unknown.example",
            a_rrs=[b"\x01\x02\x03\x04"],
            aaaa_rrs=[],
            ttl=600,
        )
        event_loop.run_until_complete(asyncio.sleep(0.1))
        assert scripts == []
        assert bridge.metrics.proposals_total == 0

    def test_empty_update_counted(
        self, tracker, event_loop, bridge_setup
    ):
        bridge, writer, router, scripts = bridge_setup
        bridge.apply(
            qname="github.com", a_rrs=[], aaaa_rrs=[], ttl=600)
        assert bridge.metrics.updates_empty_total == 1
        assert bridge.metrics.proposals_total == 0

    def test_string_ip_gets_converted(
        self, tracker, event_loop, bridge_setup
    ):
        # Legacy dnstap decoder emits string IPs via dnspython;
        # the bridge must coerce them to bytes without error.
        bridge, writer, router, scripts = bridge_setup
        bridge.apply(
            qname="github.com",
            a_rrs=["8.8.8.8"],
            aaaa_rrs=["2001:db8::1"],
            ttl=600,
        )
        event_loop.run_until_complete(asyncio.sleep(0.1))
        text = "\n".join(scripts)
        assert "8.8.8.8" in text
        assert "2001:db8::1" in text

    def test_proposals_counter(
        self, tracker, event_loop, bridge_setup
    ):
        bridge, writer, router, scripts = bridge_setup
        bridge.apply(
            qname="github.com",
            a_rrs=[b"\x01\x01\x01\x01", b"\x02\x02\x02\x02"],
            aaaa_rrs=[bytes([0xAA] * 16)],
            ttl=600,
        )
        assert bridge.metrics.proposals_total == 3


class TestEarlyFilterFromWire:
    def test_allowlisted_qname_passes(self, tracker, bridge_setup):
        bridge, *_ = bridge_setup
        wire = make_dns_response_wire("github.com")
        qn = bridge.early_filter_from_wire(wire)
        assert qn == "github.com"
        assert bridge.metrics.early_filter_pass_total == 1

    def test_non_allowlisted_rejected(self, tracker, bridge_setup):
        bridge, *_ = bridge_setup
        wire = make_dns_response_wire("unknown.example")
        qn = bridge.early_filter_from_wire(wire)
        assert qn is None
        assert bridge.metrics.early_filter_miss_total == 1
        # Also bumps the tracker's unknown-qname counter.
        snap = tracker.snapshot()
        assert snap.unknown_qname_total == 1

    def test_malformed_wire_returns_none(self, tracker, bridge_setup):
        bridge, *_ = bridge_setup
        qn = bridge.early_filter_from_wire(b"\x00" * 8)  # too short
        assert qn is None
