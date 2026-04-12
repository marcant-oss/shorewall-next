"""Tests for HA peer replication (Phase 8).

Uses real UDP sockets bound to the loopback interface so the
FrameStream auth, sequence tracking, loop prevention, and dns
batch application all exercise the true asyncio datagram
transport.
"""

from __future__ import annotations

import asyncio

import pytest

from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    DnsSetTracker,
)
from shorewalld.peer import (
    PROTO_VERSION,
    HmacSha256Auth,
    PeerLink,
    _parse_envelope,
    _serialise_envelope,
    peer_is_up,
)
from shorewalld.proto import peer_pb2
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

# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def tracker():
    reg = DnsSetRegistry()
    reg.add_spec(DnsSetSpec(
        qname="github.com", ttl_floor=60, ttl_ceil=3600, size=256))
    t = DnsSetTracker()
    t.load_registry(reg)
    return t


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def auth():
    return HmacSha256Auth(b"supersecret_supersecret_32_bytes")


@pytest.fixture
def inproc_writer(tracker, event_loop):
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
        tracker, router, batch_window_sec=0.02, loop=event_loop)

    async def prime():
        await writer.start()

    event_loop.run_until_complete(prime())
    yield writer, router, scripts
    event_loop.run_until_complete(writer.shutdown())
    event_loop.run_until_complete(router.shutdown())


# ── Auth ──────────────────────────────────────────────────────────────


class TestHmacAuth:
    def test_sign_and_verify_round_trip(self, auth):
        body = b"hello world"
        signed = auth.sign(body)
        recovered = auth.verify(signed)
        assert recovered == body

    def test_tampered_body_rejected(self, auth):
        signed = auth.sign(b"hello world")
        tampered = bytearray(signed)
        tampered[0] ^= 0xFF
        assert auth.verify(bytes(tampered)) is None

    def test_wrong_key_rejected(self, auth):
        wrong = HmacSha256Auth(b"wrongwrongwrongwrongwrongwrong")
        signed = auth.sign(b"data")
        assert wrong.verify(signed) is None

    def test_short_body_rejected(self, auth):
        assert auth.verify(b"shorter than 32 bytes") is None

    def test_short_secret_rejected(self):
        from shorewalld.peer import HmacSha256Auth
        with pytest.raises(ValueError):
            HmacSha256Auth(b"tooshort")


class TestEnvelopeSerialisation:
    def test_round_trip_envelope(self, auth):
        env = peer_pb2.PeerEnvelope()
        env.seq = 42
        env.ts_unix_ns = 1234567890000000000
        env.origin_node = "fw-a"
        env.proto_version = PROTO_VERSION
        env.heartbeat.frames_accepted_total = 1000
        env.heartbeat.frames_dropped_total = 0
        env.heartbeat.queue_depth = 0
        env.heartbeat.nft_set_elements_total = 250
        env.heartbeat.uptime_seconds = 3600
        env.heartbeat.version = "1.1.0"
        data = _serialise_envelope(env, auth)
        env2 = _parse_envelope(data, auth)
        assert env2 is not None
        assert env2.seq == 42
        assert env2.origin_node == "fw-a"
        assert env2.heartbeat.nft_set_elements_total == 250

    def test_oversize_raises(self, auth):
        env = peer_pb2.PeerEnvelope()
        env.seq = 1
        env.ts_unix_ns = 0
        env.origin_node = "fw-a"
        env.proto_version = PROTO_VERSION
        # Stuff the dns_batch until we're certain to exceed the cap.
        for i in range(200):
            upd = env.dns_batch.updates.add()
            upd.qname = f"pad{i}.example.com"
            upd.ttl = 300
            upd.a_rrs.append(b"\x01\x02\x03\x04")
        with pytest.raises(ValueError):
            _serialise_envelope(env, auth)

    def test_tampered_envelope_returns_none(self, auth):
        env = peer_pb2.PeerEnvelope()
        env.seq = 1
        env.ts_unix_ns = 0
        env.origin_node = "fw-a"
        env.proto_version = PROTO_VERSION
        env.heartbeat.frames_accepted_total = 1
        env.heartbeat.frames_dropped_total = 0
        env.heartbeat.queue_depth = 0
        env.heartbeat.nft_set_elements_total = 0
        env.heartbeat.uptime_seconds = 0
        env.heartbeat.version = ""
        signed = _serialise_envelope(env, auth)
        tampered = bytearray(signed)
        tampered[10] ^= 0x01
        assert _parse_envelope(bytes(tampered), auth) is None


# ── End-to-end link ──────────────────────────────────────────────────


class TestPeerLinkE2E:
    def _make_link(
        self,
        tracker,
        writer,
        auth,
        *,
        bind_port: int,
        peer_port: int,
        origin: str,
    ) -> PeerLink:
        return PeerLink(
            tracker=tracker,
            writer=writer,
            auth=auth,
            bind_host="127.0.0.1",
            bind_port=bind_port,
            peer_host="127.0.0.1",
            peer_port=peer_port,
            origin_node=origin,
            heartbeat_interval=10.0,     # out of test timeframe
            local_netns="inproc",
        )

    def test_heartbeat_round_trip(
        self, tracker, auth, event_loop, inproc_writer
    ):
        writer, _router, _scripts = inproc_writer
        # Two links, swapped bind/peer ports. Both share the
        # tracker/writer for simplicity — in production they'd
        # be on two hosts, but the wire format is the same.
        link_a = self._make_link(
            tracker, writer, auth,
            bind_port=19750, peer_port=19751, origin="fw-a")
        link_b = self._make_link(
            tracker, writer, auth,
            bind_port=19751, peer_port=19750, origin="fw-b")

        async def run():
            await link_a.start(event_loop)
            await link_b.start(event_loop)
            # Startup heartbeat fires immediately.
            await asyncio.sleep(0.1)
            await link_a.stop()
            await link_b.stop()

        event_loop.run_until_complete(run())

        # Each side sent one heartbeat, each side received one.
        assert link_a.metrics.heartbeats_sent_total >= 1
        assert link_b.metrics.heartbeats_sent_total >= 1
        assert link_a.metrics.heartbeats_received_total >= 1
        assert link_b.metrics.heartbeats_received_total >= 1
        assert link_a.metrics.up == 1
        assert link_b.metrics.up == 1

    def test_loop_prevention(
        self, tracker, auth, event_loop, inproc_writer
    ):
        writer, _router, _scripts = inproc_writer
        # Point a link at itself — same origin_node, same bind+peer
        # ports. Any frame it sends should be dropped on receipt.
        link = self._make_link(
            tracker, writer, auth,
            bind_port=19760, peer_port=19760, origin="self")

        async def run():
            await link.start(event_loop)
            await asyncio.sleep(0.1)
            await link.stop()

        event_loop.run_until_complete(run())
        assert link.metrics.loop_drops_total >= 1

    def test_dns_batch_application(
        self, tracker, auth, event_loop, inproc_writer
    ):
        writer, _router, scripts = inproc_writer
        link_a = self._make_link(
            tracker, writer, auth,
            bind_port=19770, peer_port=19771, origin="fw-a")
        link_b = self._make_link(
            tracker, writer, auth,
            bind_port=19771, peer_port=19770, origin="fw-b")

        async def run():
            await link_a.start(event_loop)
            await link_b.start(event_loop)
            await asyncio.sleep(0.05)
            # fw-a sends a DNS batch to fw-b.
            link_a.send_dns_batch([
                ("github.com", [b"\x01\x02\x03\x04"], [], 600),
            ])
            # Give fw-b time to receive and apply.
            await asyncio.sleep(0.2)
            await link_a.stop()
            await link_b.stop()

        event_loop.run_until_complete(run())
        # fw-b received the batch and applied it through its writer.
        assert link_b.metrics.dns_updates_applied_total >= 1
        # The applied update produced a real script via the inproc
        # worker (shared writer/router for test simplicity).
        assert any("1.2.3.4" in s for s in scripts)

    def test_hmac_failure_counts(
        self, tracker, event_loop, inproc_writer
    ):
        writer, _router, _scripts = inproc_writer
        auth_a = HmacSha256Auth(b"a" * 32)
        auth_b = HmacSha256Auth(b"b" * 32)  # different!
        link_a = self._make_link(
            tracker, writer, auth_a,
            bind_port=19780, peer_port=19781, origin="fw-a")
        link_b = self._make_link(
            tracker, writer, auth_b,
            bind_port=19781, peer_port=19780, origin="fw-b")

        async def run():
            await link_a.start(event_loop)
            await link_b.start(event_loop)
            await asyncio.sleep(0.1)
            await link_a.stop()
            await link_b.stop()

        event_loop.run_until_complete(run())
        # The startup heartbeats fail HMAC on both ends.
        assert link_a.metrics.hmac_failures_total >= 1
        assert link_b.metrics.hmac_failures_total >= 1
        assert link_a.metrics.heartbeats_received_total == 0
        assert link_b.metrics.heartbeats_received_total == 0


class TestSnapshotRequestResponse:
    def _make_link(
        self, tracker, writer, auth,
        *, bind_port, peer_port, origin,
    ):
        return PeerLink(
            tracker=tracker, writer=writer, auth=auth,
            bind_host="127.0.0.1", bind_port=bind_port,
            peer_host="127.0.0.1", peer_port=peer_port,
            origin_node=origin,
            heartbeat_interval=60.0,      # out of test timeframe
            local_netns="inproc",
        )

    def test_snapshot_round_trip_applies_entries(
        self, tracker, auth, event_loop, inproc_writer
    ):
        """fw-a has tracker entries; fw-b asks for a snapshot and
        applies them into its own tracker."""
        from shorewalld.dns_set_tracker import Proposal, Verdict

        # Populate source-of-truth tracker (fw-a's view).
        writer, _router, _scripts = inproc_writer
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        tracker.commit([
            Proposal(set_id=sid, ip_bytes=b"\x01\x01\x01\x01", ttl=600),
            Proposal(set_id=sid, ip_bytes=b"\x02\x02\x02\x02", ttl=600),
            Proposal(set_id=sid, ip_bytes=b"\x03\x03\x03\x03", ttl=600),
        ], [Verdict.ADD] * 3)

        link_a = self._make_link(
            tracker, writer, auth,
            bind_port=19790, peer_port=19791, origin="fw-a")
        link_b = self._make_link(
            tracker, writer, auth,
            bind_port=19791, peer_port=19790, origin="fw-b")

        async def run():
            await link_a.start(event_loop)
            await link_b.start(event_loop)
            await asyncio.sleep(0.05)
            # fw-b requests a snapshot from fw-a.
            link_b.request_snapshot()
            await asyncio.sleep(0.3)
            await link_a.stop()
            await link_b.stop()

        event_loop.run_until_complete(run())

        assert link_b.metrics.snapshot_requests_sent_total == 1
        assert link_a.metrics.snapshot_requests_received_total == 1
        assert link_a.metrics.snapshot_responses_sent_total == 1
        assert link_a.metrics.snapshot_chunks_sent_total >= 1
        assert link_b.metrics.snapshot_chunks_received_total >= 1
        assert link_b.metrics.snapshot_entries_applied_total == 3
        assert link_b.metrics.snapshot_complete_total == 1

    def test_snapshot_chunking_across_many_entries(
        self, tracker, auth, event_loop, inproc_writer
    ):
        """More than SNAPSHOT_CHUNK_SIZE entries → multi-chunk
        response, all chunks delivered and applied."""
        from shorewalld.dns_set_tracker import Proposal, Verdict
        from shorewalld.peer import SNAPSHOT_CHUNK_SIZE

        writer, _router, _scripts = inproc_writer
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        n_entries = SNAPSHOT_CHUNK_SIZE * 2 + 3    # 43 entries
        props = [
            Proposal(
                set_id=sid,
                ip_bytes=bytes([10, i >> 8 & 0xFF, i & 0xFF, 1]),
                ttl=600,
            )
            for i in range(n_entries)
        ]
        tracker.commit(props, [Verdict.ADD] * n_entries)

        link_a = self._make_link(
            tracker, writer, auth,
            bind_port=19800, peer_port=19801, origin="fw-a")
        link_b = self._make_link(
            tracker, writer, auth,
            bind_port=19801, peer_port=19800, origin="fw-b")

        async def run():
            await link_a.start(event_loop)
            await link_b.start(event_loop)
            await asyncio.sleep(0.05)
            link_b.request_snapshot()
            await asyncio.sleep(0.5)
            await link_a.stop()
            await link_b.stop()

        event_loop.run_until_complete(run())
        assert link_a.metrics.snapshot_chunks_sent_total == 3
        assert link_b.metrics.snapshot_chunks_received_total == 3
        assert link_b.metrics.snapshot_entries_applied_total == n_entries
        assert link_b.metrics.snapshot_complete_total == 1

    def test_qname_filter_limits_entries(
        self, tracker, auth, event_loop, inproc_writer
    ):
        """SnapshotRequest with a qname_filter returns only
        entries for the listed qnames."""
        from shorewalld.dns_set_tracker import Proposal, Verdict

        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec(
            qname="github.com", ttl_floor=60, ttl_ceil=3600, size=256))
        reg.add_spec(DnsSetSpec(
            qname="api.stripe.com", ttl_floor=60, ttl_ceil=3600, size=64))
        tr = DnsSetTracker()
        tr.load_registry(reg)
        gh = tr.set_id_for("github.com", FAMILY_V4)
        api = tr.set_id_for("api.stripe.com", FAMILY_V4)
        tr.commit([
            Proposal(set_id=gh, ip_bytes=b"\x01\x01\x01\x01", ttl=600),
            Proposal(set_id=api, ip_bytes=b"\x02\x02\x02\x02", ttl=600),
        ], [Verdict.ADD, Verdict.ADD])

        writer, _router, _scripts = inproc_writer
        link_a = self._make_link(
            tr, writer, auth,
            bind_port=19810, peer_port=19811, origin="fw-a")
        link_b = self._make_link(
            tr, writer, auth,
            bind_port=19811, peer_port=19810, origin="fw-b")

        async def run():
            await link_a.start(event_loop)
            await link_b.start(event_loop)
            await asyncio.sleep(0.05)
            link_b.request_snapshot(qname_filter=["github.com"])
            await asyncio.sleep(0.3)
            await link_a.stop()
            await link_b.stop()

        event_loop.run_until_complete(run())
        # Only one entry was shipped — the stripe one is filtered out.
        assert link_b.metrics.snapshot_entries_applied_total == 1


class TestPeerIsUp:
    def test_fresh_heartbeat_is_up(self):
        import time

        from shorewalld.peer import PeerMetrics
        m = PeerMetrics()
        m.last_heartbeat_recv_mono = time.monotonic()
        assert peer_is_up(m, interval=5.0) is True

    def test_stale_heartbeat_is_down(self):
        import time

        from shorewalld.peer import PeerMetrics
        m = PeerMetrics()
        m.last_heartbeat_recv_mono = time.monotonic() - 60.0
        assert peer_is_up(m, interval=5.0) is False

    def test_never_seen_is_down(self):
        from shorewalld.peer import PeerMetrics
        assert peer_is_up(PeerMetrics(), interval=5.0) is False
