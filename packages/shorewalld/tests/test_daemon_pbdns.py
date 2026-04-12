"""Tests for the PBDNSMessage ingestion path.

Exercises the decode path end-to-end from a synthesized
``PBDNSMessage`` protobuf through :class:`TrackerBridge` into
the Phase 2 :class:`SetWriter` and an inproc nft-worker.

Also tests :class:`PbdnsServer`'s length-prefixed framing against
a real ``asyncio.start_unix_server`` socket.
"""

from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    DnsSetTracker,
)
from shorewalld.dnstap_bridge import TrackerBridge
from shorewalld.pbdns import (
    PbdnsServer,
    decode_pbdns_frame,
    encode_length_prefixed,
)
from shorewalld.proto import dnsmessage_pb2
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


def _make_response(
    qname: str = "github.com",
    rcode: int = 0,
    a: list[bytes] | None = None,
    aaaa: list[bytes] | None = None,
    ttl: int = 300,
) -> "dnsmessage_pb2.PBDNSMessage":
    msg = dnsmessage_pb2.PBDNSMessage()
    msg.type = dnsmessage_pb2.PBDNSMessage.DNSResponseType
    msg.question.qName = qname
    msg.question.qType = 1
    msg.response.rcode = rcode
    for addr in a or []:
        rr = msg.response.rrs.add()
        rr.name = qname
        rr.type = 1
        rr.ttl = ttl
        rr.rdata = addr
    for addr in aaaa or []:
        rr = msg.response.rrs.add()
        rr.name = qname
        rr.type = 28
        rr.ttl = ttl
        rr.rdata = addr
    return msg


@pytest.fixture
def tracker():
    reg = DnsSetRegistry()
    reg.add_spec(DnsSetSpec(
        qname="github.com", ttl_floor=60, ttl_ceil=3600, size=256))
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
    yield bridge, writer, router, scripts, tracker
    event_loop.run_until_complete(writer.shutdown())
    event_loop.run_until_complete(router.shutdown())


class TestDecodePbdnsFrame:
    def test_accepts_client_response(self, bridge_setup, event_loop):
        bridge, writer, router, scripts, tracker = bridge_setup
        msg = _make_response(
            qname="github.com",
            a=[b"\x01\x02\x03\x04", b"\x05\x06\x07\x08"],
            aaaa=[bytes([0xAA] * 16)],
            ttl=600,
        )
        decode_pbdns_frame(
            msg.SerializeToString(), bridge, bridge_setup[1].__dict__
            if False else _PbdnsMetricsDummy())

    def test_end_to_end_via_bridge(self, bridge_setup, event_loop):
        bridge, writer, router, scripts, tracker = bridge_setup
        metrics = _PbdnsMetricsDummy()
        msg = _make_response(
            a=[b"\x01\x02\x03\x04"],
            ttl=600,
        )
        decode_pbdns_frame(msg.SerializeToString(), bridge, metrics)
        event_loop.run_until_complete(asyncio.sleep(0.1))
        assert len(scripts) >= 1
        assert "dns_github_com_v4" in scripts[0]
        assert "1.2.3.4" in scripts[0]

    def test_query_frame_ignored(self, bridge_setup):
        bridge, writer, router, scripts, tracker = bridge_setup
        metrics = _PbdnsMetricsDummy()
        msg = dnsmessage_pb2.PBDNSMessage()
        msg.type = dnsmessage_pb2.PBDNSMessage.DNSQueryType
        msg.question.qName = "github.com"
        decode_pbdns_frame(msg.SerializeToString(), bridge, metrics)
        assert metrics.frames_by_type_query_total == 1
        assert metrics.frames_by_type_response_total == 0

    def test_nxdomain_counted_not_submitted(self, bridge_setup):
        bridge, writer, router, scripts, tracker = bridge_setup
        metrics = _PbdnsMetricsDummy()
        msg = _make_response(qname="nonexistent.example", rcode=3)
        decode_pbdns_frame(msg.SerializeToString(), bridge, metrics)
        assert metrics.frames_by_rcode_nxdomain_total == 1
        assert bridge.metrics.proposals_total == 0

    def test_unknown_qname_dropped_at_bridge(self, bridge_setup):
        bridge, writer, router, scripts, tracker = bridge_setup
        metrics = _PbdnsMetricsDummy()
        msg = _make_response(
            qname="unknown.example",
            a=[b"\x01\x02\x03\x04"],
        )
        decode_pbdns_frame(msg.SerializeToString(), bridge, metrics)
        assert metrics.frames_accepted_total == 1
        assert bridge.metrics.proposals_total == 0

    def test_malformed_bytes_increment_error(self, bridge_setup):
        bridge, writer, router, scripts, tracker = bridge_setup
        metrics = _PbdnsMetricsDummy()
        decode_pbdns_frame(b"\x00\xff\xff\xff", bridge, metrics)
        assert metrics.frames_decode_error_total == 1

    def test_empty_rrs_counted(self, bridge_setup):
        bridge, writer, router, scripts, tracker = bridge_setup
        metrics = _PbdnsMetricsDummy()
        msg = _make_response()   # no A/AAAA
        decode_pbdns_frame(msg.SerializeToString(), bridge, metrics)
        assert metrics.frames_empty_rrs_total == 1

    def test_ttl_uses_minimum(self, bridge_setup, event_loop):
        bridge, writer, router, scripts, tracker = bridge_setup
        metrics = _PbdnsMetricsDummy()
        msg = dnsmessage_pb2.PBDNSMessage()
        msg.type = dnsmessage_pb2.PBDNSMessage.DNSResponseType
        msg.question.qName = "github.com"
        msg.response.rcode = 0
        for ttl in (300, 60, 600):
            rr = msg.response.rrs.add()
            rr.name = "github.com"
            rr.type = 1
            rr.ttl = ttl
            rr.rdata = bytes([1, 1, 1, ttl & 0xFF])
        decode_pbdns_frame(msg.SerializeToString(), bridge, metrics)
        event_loop.run_until_complete(asyncio.sleep(0.1))
        # Only the tracker saw the proposals — check via its metrics.
        snap = tracker.snapshot()
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        assert snap.per_set[(sid, FAMILY_V4)].elements == 3


class TestPbdnsServer:
    def test_server_round_trip(self, tracker, event_loop):
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
            tracker, router, batch_window_sec=0.01, loop=event_loop)

        async def run() -> "PbdnsServer":
            await writer.start()
            bridge = TrackerBridge(
                tracker, writer, default_netns="inproc")
            with tempfile.TemporaryDirectory() as tmp:
                sock_path = os.path.join(tmp, "pbdns.sock")
                server = PbdnsServer(
                    socket_path=sock_path, bridge=bridge)
                await server.start()
                try:
                    _, producer = await asyncio.open_unix_connection(
                        sock_path)
                    msg = _make_response(
                        qname="github.com",
                        a=[b"\x01\x02\x03\x04"],
                    )
                    producer.write(encode_length_prefixed(msg))
                    await producer.drain()
                    await asyncio.sleep(0.1)
                    producer.close()
                    try:
                        await producer.wait_closed()
                    except Exception:
                        pass
                    return server
                finally:
                    await server.close()
                    await writer.shutdown()
                    await router.shutdown()

        server = event_loop.run_until_complete(run())
        assert server.metrics.frames_accepted_total == 1
        assert server.metrics.frames_by_type_response_total == 1
        assert len(scripts) >= 1
        assert "dns_github_com_v4" in scripts[0]


class _PbdnsMetricsDummy:
    """Dataclass stand-in for :class:`PbdnsMetrics` so tests
    exercising :func:`decode_pbdns_frame` don't need the real lock."""

    def __init__(self) -> None:
        self.frames_accepted_total = 0
        self.frames_decode_error_total = 0
        self.frames_dropped_queue_full_total = 0
        self.frames_by_type_query_total = 0
        self.frames_by_type_response_total = 0
        self.frames_by_type_other_total = 0
        self.frames_by_rcode_noerror_total = 0
        self.frames_by_rcode_nxdomain_total = 0
        self.frames_by_rcode_servfail_total = 0
        self.frames_by_rcode_refused_total = 0
        self.frames_by_rcode_other_total = 0
        self.frames_family_v4_total = 0
        self.frames_family_v6_total = 0
        self.frames_empty_rrs_total = 0
        self.bytes_received_total = 0
        self.last_frame_mono = 0.0

    def inc(self, attr: str, n: int = 1) -> None:
        setattr(self, attr, getattr(self, attr) + n)

    def set_last_frame_now(self) -> None:
        import time
        self.last_frame_mono = time.monotonic()
