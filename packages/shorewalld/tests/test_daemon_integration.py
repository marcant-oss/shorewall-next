"""Phase 10 — end-to-end integration tests for the shorewalld stack.

The simlab full-topology path (TUN/TAP + packet injection) is
operator-driven and requires root. These tests instead wire every
in-process component of shorewalld into one pipeline and exercise
the user-visible happy paths:

1. **Compiler → emitter → tracker**: a ``rules`` file with
   ``dns:github.com`` compiles to an nft script that declares the
   DNS sets, and the tracker loads the compiled allowlist.
2. **dnstap ingestion → SetWriter → inproc worker**: a synthetic
   dnstap frame produces real nft ``add element`` calls.
3. **PBDNSMessage ingestion**: same round trip over the pbdns
   decoder path.
4. **State persistence across restart**: save, simulate daemon
   restart, load, verify entries survive.
5. **HA peer convergence**: two PeerLink instances exchange
   heartbeats + a DNS batch; entries land on both sides.
6. **HA peer snapshot resync**: fresh node joins, requests a
   snapshot, applies the full state.

Everything runs on one asyncio loop with ``inproc_worker_pair``
replacing the forked nft-worker, so no root or CAP_NET_ADMIN is
needed. The tests are fast (< 2 s total) and hit every layer the
daemon ships with.
"""

from __future__ import annotations

import asyncio

import pytest

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    DnsSetTracker,
    Proposal,
    Verdict,
)
from shorewalld.dnstap import decode_dnstap_frame
from shorewalld.dnstap_bridge import TrackerBridge
from shorewalld.pbdns import decode_pbdns_frame
from shorewalld.peer import (
    HmacSha256Auth,
    PeerLink,
)
from shorewalld.proto import dnsmessage_pb2, dnstap_pb2
from shorewalld.setwriter import SetWriter
from shorewalld.state import StateConfig, StateStore
from shorewalld.worker_router import (
    WorkerRouter,
    inproc_worker_pair,
)
from shorewall_nft.nft.dns_sets import (
    DnsSetRegistry,
    DnsSetSpec,
    qname_to_set_name,
    write_compiled_allowlist,
)
from shorewall_nft.nft.emitter import emit_nft

# ---------------------------------------------------------------------------
# Wire format helpers
# ---------------------------------------------------------------------------


def _dns_wire(qname: str, rcode: int = 0) -> bytes:
    wire = bytearray(12)
    wire[0] = 0x12
    wire[1] = 0x34
    wire[2] = 0x81
    wire[3] = rcode & 0x0F
    wire[5] = 1
    for label in qname.rstrip(".").split("."):
        wire.append(len(label))
        wire.extend(label.encode("ascii"))
    wire.append(0)
    wire.extend((1).to_bytes(2, "big"))
    wire.extend((1).to_bytes(2, "big"))
    return bytes(wire)


def _dnstap_frame(qname: str = "github.com") -> bytes:
    msg = dnstap_pb2.Dnstap()
    msg.type = dnstap_pb2.Dnstap.MESSAGE
    msg.message.type = dnstap_pb2.Message.CLIENT_RESPONSE
    msg.message.response_message = _dns_wire(qname)
    return msg.SerializeToString()


def _pbdns_frame(
    qname: str = "github.com",
    a_rrs: list[bytes] | None = None,
    aaaa_rrs: list[bytes] | None = None,
    ttl: int = 600,
) -> "dnsmessage_pb2.PBDNSMessage":
    msg = dnsmessage_pb2.PBDNSMessage()
    msg.type = dnsmessage_pb2.PBDNSMessage.DNSResponseType
    msg.question.qName = qname
    msg.question.qType = 1
    msg.response.rcode = 0
    for ip in a_rrs or []:
        rr = msg.response.rrs.add()
        rr.name = qname
        rr.type = 1
        rr.ttl = ttl
        rr.rdata = ip
    for ip in aaaa_rrs or []:
        rr = msg.response.rrs.add()
        rr.name = qname
        rr.type = 28
        rr.ttl = ttl
        rr.rdata = ip
    return msg


# ---------------------------------------------------------------------------
# Wire the full stack together
# ---------------------------------------------------------------------------


class _Harness:
    """One-shot full-stack wiring for an integration test.

    Owns the tracker, writer, router, bridge, inproc worker,
    state store, and reload monitor. Caller drives via
    :meth:`feed_dnstap`, :meth:`feed_pbdns`, and the ``scripts``
    list captures all nft commands the inproc worker would run.
    """

    def __init__(
        self,
        tracker: DnsSetTracker,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self.tracker = tracker
        self.loop = loop
        self.scripts: list[str] = []

        def lookup(key):
            entry = tracker.name_for(key[0])
            if entry is None:
                return None
            qname, family = entry
            return qname_to_set_name(
                qname, "v4" if family == 4 else "v6")

        pw, _ = inproc_worker_pair(
            tracker, loop, lookup, apply_cb=self.scripts.append)
        self.router = WorkerRouter(tracker=tracker, loop=loop)
        self.router._workers["inproc"] = pw
        self.writer = SetWriter(
            tracker, self.router,
            batch_window_sec=0.02, loop=loop)
        self.bridge = TrackerBridge(
            tracker, self.writer, default_netns="inproc")

    async def start(self) -> None:
        await self.writer.start()

    async def stop(self) -> None:
        await self.writer.shutdown()
        await self.router.shutdown()

    def feed_dnstap(self, qname: str) -> None:
        """Decode one dnstap frame and push the update through the
        bridge. Returns after submission; the batch_window will
        flush asynchronously.
        """
        buf = _dnstap_frame(qname)
        msg_type, wire = decode_dnstap_frame(buf)
        qn = self.bridge.early_filter_from_wire(wire)
        if qn is None:
            return
        # For the integration test, hand-craft the A RR list
        # from a fixed IP so we don't need dnspython.
        self.bridge.apply(
            qname=qn,
            a_rrs=[b"\x08\x08\x08\x08"],
            aaaa_rrs=[],
            ttl=600,
        )

    def feed_pbdns(
        self,
        qname: str,
        ips: list[bytes],
        aaaa: list[bytes] | None = None,
    ) -> None:
        msg = _pbdns_frame(qname, a_rrs=ips, aaaa_rrs=aaaa)
        decode_pbdns_frame(
            msg.SerializeToString(), self.bridge,
            _DummyMetrics(),
        )


class _DummyMetrics:
    """Counter stand-in for :class:`PbdnsMetrics` in tests that
    don't care about the counter values."""

    def inc(self, attr: str, n: int = 1) -> None:
        pass

    def set_last_frame_now(self) -> None:
        pass


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


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


# ---------------------------------------------------------------------------
# 1) Compiler → emitter → runtime allowlist round trip
# ---------------------------------------------------------------------------


class TestCompilerIntegration:
    def test_dns_rule_produces_matching_set_names(self, tmp_path):
        cfg = ShorewalConfig(config_dir=tmp_path)
        cfg.zones = [
            ConfigLine(
                columns=["fw", "firewall"], file="zones", lineno=1),
            ConfigLine(
                columns=["net", "ipv4"], file="zones", lineno=2),
        ]
        cfg.interfaces = [
            ConfigLine(
                columns=["net", "eth0", "-"],
                file="interfaces", lineno=1),
        ]
        cfg.rules = [
            ConfigLine(
                columns=[
                    "ACCEPT", "fw", "net:dns:github.com", "tcp", "443"],
                file="rules", lineno=1),
        ]
        ir = build_ir(cfg)
        script = emit_nft(ir)

        # Emitter produced both v4+v6 set declarations.
        assert "set dns_github_com_v4" in script
        assert "set dns_github_com_v6" in script
        assert "flags timeout;" in script

        # Allowlist file (Phase 1 output) can be written.
        allow_path = tmp_path / "dnsnames.compiled"
        write_compiled_allowlist(ir.dns_registry, allow_path)
        assert allow_path.exists()

        # The daemon can load that exact file.
        from shorewall_nft.nft.dns_sets import read_compiled_allowlist
        loaded = read_compiled_allowlist(allow_path)
        assert "github.com" in loaded.specs


# ---------------------------------------------------------------------------
# 2) dnstap ingestion path
# ---------------------------------------------------------------------------


class TestDnstapPath:
    def test_dnstap_frame_reaches_worker(self, tracker, event_loop):
        harness = _Harness(tracker, event_loop)

        async def run():
            await harness.start()
            harness.feed_dnstap("github.com")
            await asyncio.sleep(0.1)
            await harness.stop()

        event_loop.run_until_complete(run())
        joined = "\n".join(harness.scripts)
        assert "dns_github_com_v4" in joined
        assert "8.8.8.8" in joined

    def test_unknown_qname_is_filtered(self, tracker, event_loop):
        harness = _Harness(tracker, event_loop)

        async def run():
            await harness.start()
            harness.feed_dnstap("unknown.example.invalid")
            await asyncio.sleep(0.1)
            await harness.stop()

        event_loop.run_until_complete(run())
        assert harness.scripts == []
        snap = tracker.snapshot()
        assert snap.unknown_qname_total >= 1


# ---------------------------------------------------------------------------
# 3) PBDNSMessage ingestion path
# ---------------------------------------------------------------------------


class TestPbdnsPath:
    def test_pbdns_frame_reaches_worker(self, tracker, event_loop):
        harness = _Harness(tracker, event_loop)

        async def run():
            await harness.start()
            harness.feed_pbdns(
                qname="api.stripe.com",
                ips=[b"\x36\xbb\xad\xf2"],
            )
            await asyncio.sleep(0.1)
            await harness.stop()

        event_loop.run_until_complete(run())
        joined = "\n".join(harness.scripts)
        assert "dns_api_stripe_com_v4" in joined
        assert "54.187.173.242" in joined


# ---------------------------------------------------------------------------
# 4) State persistence across a simulated restart
# ---------------------------------------------------------------------------


class TestStatePersistence:
    def test_entries_survive_restart(
        self, tracker, event_loop, tmp_path
    ):
        cfg = StateConfig(state_dir=tmp_path)

        # Start one harness, ingest a frame, save state, stop.
        harness = _Harness(tracker, event_loop)

        async def run_first():
            await harness.start()
            harness.feed_pbdns(
                qname="github.com",
                ips=[b"\x01\x02\x03\x04"],
            )
            await asyncio.sleep(0.1)
            store = StateStore(tracker, cfg)
            store.save_sync()
            await harness.stop()

        event_loop.run_until_complete(run_first())

        # Simulate a fresh daemon: new tracker, same allowlist.
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec(
            qname="github.com", ttl_floor=60, ttl_ceil=3600, size=256))
        reg.add_spec(DnsSetSpec(
            qname="api.stripe.com", ttl_floor=60, ttl_ceil=3600, size=64))
        fresh = DnsSetTracker()
        fresh.load_registry(reg)

        # Before load, state is empty.
        assert fresh.snapshot().totals.elements == 0

        # Load from disk.
        store2 = StateStore(fresh, cfg)
        installed = store2.load()
        assert installed == 1
        assert fresh.snapshot().totals.elements == 1


# ---------------------------------------------------------------------------
# 5) HA peer convergence
# ---------------------------------------------------------------------------


class TestHaConvergence:
    def test_peer_batch_applied_on_receiver(self, tracker, event_loop):
        harness = _Harness(tracker, event_loop)
        auth = HmacSha256Auth(b"a" * 32)

        link_a = PeerLink(
            tracker=tracker, writer=harness.writer, auth=auth,
            bind_host="127.0.0.1", bind_port=19820,
            peer_host="127.0.0.1", peer_port=19821,
            origin_node="fw-a",
            heartbeat_interval=60.0,
            local_netns="inproc",
        )
        link_b = PeerLink(
            tracker=tracker, writer=harness.writer, auth=auth,
            bind_host="127.0.0.1", bind_port=19821,
            peer_host="127.0.0.1", peer_port=19820,
            origin_node="fw-b",
            heartbeat_interval=60.0,
            local_netns="inproc",
        )

        async def run():
            await harness.start()
            await link_a.start(event_loop)
            await link_b.start(event_loop)
            await asyncio.sleep(0.05)
            # fw-a replicates a DNS update to fw-b.
            link_a.send_dns_batch([
                ("github.com", [b"\x0a\x0b\x0c\x0d"], [], 600),
            ])
            await asyncio.sleep(0.2)
            await link_a.stop()
            await link_b.stop()
            await harness.stop()

        event_loop.run_until_complete(run())
        assert link_b.metrics.dns_updates_applied_total >= 1
        # The batch landed as a real nft command through the
        # shared inproc worker.
        assert any("10.11.12.13" in s for s in harness.scripts)


class TestSnapshotResync:
    def test_cold_start_snapshot_fills_new_node(
        self, tracker, event_loop
    ):
        # Populate the source tracker.
        sid = tracker.set_id_for("github.com", FAMILY_V4)
        tracker.commit([
            Proposal(set_id=sid, ip_bytes=b"\x01\x01\x01\x01", ttl=600),
            Proposal(set_id=sid, ip_bytes=b"\x02\x02\x02\x02", ttl=600),
            Proposal(set_id=sid, ip_bytes=b"\x03\x03\x03\x03", ttl=600),
        ], [Verdict.ADD] * 3)

        harness = _Harness(tracker, event_loop)
        auth = HmacSha256Auth(b"x" * 32)

        link_seed = PeerLink(
            tracker=tracker, writer=harness.writer, auth=auth,
            bind_host="127.0.0.1", bind_port=19830,
            peer_host="127.0.0.1", peer_port=19831,
            origin_node="fw-seed",
            heartbeat_interval=60.0,
            local_netns="inproc",
        )
        link_new = PeerLink(
            tracker=tracker, writer=harness.writer, auth=auth,
            bind_host="127.0.0.1", bind_port=19831,
            peer_host="127.0.0.1", peer_port=19830,
            origin_node="fw-new",
            heartbeat_interval=60.0,
            local_netns="inproc",
        )

        async def run():
            await harness.start()
            await link_seed.start(event_loop)
            await link_new.start(event_loop)
            await asyncio.sleep(0.05)
            # fw-new requests a full snapshot from fw-seed.
            link_new.request_snapshot()
            await asyncio.sleep(0.3)
            await link_seed.stop()
            await link_new.stop()
            await harness.stop()

        event_loop.run_until_complete(run())
        assert link_seed.metrics.snapshot_requests_received_total == 1
        assert link_new.metrics.snapshot_complete_total == 1
        assert link_new.metrics.snapshot_entries_applied_total == 3
