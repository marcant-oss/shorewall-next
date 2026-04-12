"""Tests for the SetWriter asyncio coroutine.

Uses the in-process router helper so we exercise the whole
propose→batch→dispatch→ack→commit pipeline without fork()/setns().
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    FAMILY_V6,
    DnsSetTracker,
    Proposal,
)
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


def _name_lookup(tracker):
    def lookup(key: tuple[int, int]) -> str | None:
        entry = tracker.name_for(key[0])
        if entry is None:
            return None
        qname, family = entry
        return qname_to_set_name(
            qname, "v4" if family == 4 else "v6")
    return lookup


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def router_with_inproc(tracker, event_loop):
    scripts: list[str] = []
    pw, _ = inproc_worker_pair(
        tracker, event_loop, _name_lookup(tracker),
        apply_cb=scripts.append)
    router = WorkerRouter(tracker=tracker, loop=event_loop)
    router._workers["inproc"] = pw
    yield router, scripts
    # Teardown: clean up the inproc worker's pending asyncio tasks.
    event_loop.run_until_complete(router.shutdown())


class TestSubmitFlushCycle:
    def test_single_submit_flushes_in_window(
        self, tracker, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        writer = SetWriter(
            tracker, router, batch_window_sec=0.02, loop=event_loop)

        async def run():
            await writer.start()
            sid = tracker.set_id_for("github.com", FAMILY_V4)
            ok = writer.submit(
                netns="inproc", family=FAMILY_V4,
                proposal=Proposal(
                    set_id=sid, ip_bytes=b"\x01\x02\x03\x04", ttl=600),
            )
            assert ok is True
            # Wait longer than window → drain loop must flush.
            await asyncio.sleep(0.1)
            assert writer.metrics.batches_flushed_total == 1
            assert writer.metrics.commits_total == 1
            await writer.shutdown()

        event_loop.run_until_complete(run())
        assert len(scripts) == 1
        assert "dns_github_com_v4" in scripts[0]
        assert "1.2.3.4" in scripts[0]

    def test_batch_fills_flushes_immediately(
        self, tracker, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        writer = SetWriter(
            tracker, router,
            batch_window_sec=60.0,   # unreachable → only "full" triggers
            batch_max_ops=3,
            loop=event_loop,
        )

        async def run():
            await writer.start()
            sid = tracker.set_id_for("api.stripe.com", FAMILY_V4)
            for i in range(3):
                writer.submit(
                    netns="inproc", family=FAMILY_V4,
                    proposal=Proposal(
                        set_id=sid,
                        ip_bytes=bytes([10, 0, 0, i]),
                        ttl=600,
                    ),
                )
            await asyncio.sleep(0.05)
            assert writer.metrics.flush_reason_full_total == 1
            await writer.shutdown()

        event_loop.run_until_complete(run())
        script = scripts[0]
        assert script.count("dns_api_stripe_com_v4") == 3

    def test_v4_and_v6_stay_on_separate_batches(
        self, tracker, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        writer = SetWriter(
            tracker, router, batch_window_sec=0.02, loop=event_loop)

        async def run():
            await writer.start()
            sid4 = tracker.set_id_for("github.com", FAMILY_V4)
            sid6 = tracker.set_id_for("github.com", FAMILY_V6)
            writer.submit(
                netns="inproc", family=FAMILY_V4,
                proposal=Proposal(
                    set_id=sid4, ip_bytes=b"\x01\x02\x03\x04", ttl=600))
            writer.submit(
                netns="inproc", family=FAMILY_V6,
                proposal=Proposal(
                    set_id=sid6, ip_bytes=bytes([0xAA] * 16), ttl=600))
            await asyncio.sleep(0.1)
            assert writer.metrics.batches_flushed_total == 2
            await writer.shutdown()

        event_loop.run_until_complete(run())
        assert len(scripts) == 2
        all_text = "\n".join(scripts)
        assert "dns_github_com_v4" in all_text
        assert "dns_github_com_v6" in all_text

    def test_dedup_entries_never_hit_worker(
        self, tracker, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        writer = SetWriter(
            tracker, router, batch_window_sec=0.02, loop=event_loop)

        async def run():
            await writer.start()
            sid = tracker.set_id_for("github.com", FAMILY_V4)
            prop = Proposal(
                set_id=sid, ip_bytes=b"\x01\x02\x03\x04", ttl=600)
            writer.submit(netns="inproc", family=FAMILY_V4, proposal=prop)
            await asyncio.sleep(0.05)
            # Same proposal again — tracker should dedup before queue.
            for _ in range(5):
                writer.submit(
                    netns="inproc", family=FAMILY_V4, proposal=prop)
            await asyncio.sleep(0.1)
            await writer.shutdown()

        event_loop.run_until_complete(run())
        # First write was committed once, rest were deduped.
        snap = tracker.snapshot()
        m = snap.per_set[
            (tracker.set_id_for("github.com", FAMILY_V4), FAMILY_V4)]
        assert m.adds_total == 1
        assert m.dedup_hits_total == 5
        # Only one script emitted to the worker.
        assert len(scripts) == 1

    def test_submit_from_decoder_thread(
        self, tracker, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        writer = SetWriter(
            tracker, router, batch_window_sec=0.02, loop=event_loop)

        async def run():
            await writer.start()

            def worker():
                sid = tracker.set_id_for("github.com", FAMILY_V4)
                for i in range(10):
                    writer.submit(
                        netns="inproc", family=FAMILY_V4,
                        proposal=Proposal(
                            set_id=sid,
                            ip_bytes=bytes([1, 2, 3, i]),
                            ttl=600,
                        ),
                    )
                    time.sleep(0.001)

            t = threading.Thread(target=worker)
            t.start()
            await asyncio.sleep(0.2)
            t.join()
            await writer.shutdown()

        event_loop.run_until_complete(run())
        snap = tracker.snapshot()
        m = snap.per_set[
            (tracker.set_id_for("github.com", FAMILY_V4), FAMILY_V4)]
        # All 10 distinct IPs committed.
        assert m.elements == 10
        assert m.adds_total == 10

    def test_queue_full_drops_with_counter(self, tracker, event_loop):
        # Fabricate a router whose dispatch never returns so the
        # queue fills up.
        class SlowRouter:
            def __init__(self):
                self._held = asyncio.Event()

            async def dispatch(self, netns, builder):
                await self._held.wait()
                return 0

        router = SlowRouter()
        writer = SetWriter(
            tracker, router,   # type: ignore[arg-type]
            batch_window_sec=1.0,
            batch_max_ops=2,
            queue_size=4,
            loop=event_loop,
        )

        async def run():
            await writer.start()
            sid = tracker.set_id_for("github.com", FAMILY_V4)
            # Push 20 distinct proposals; the tiny queue
            # overflows and we count drops.
            for i in range(20):
                writer.submit(
                    netns="inproc", family=FAMILY_V4,
                    proposal=Proposal(
                        set_id=sid,
                        ip_bytes=bytes([10, 0, i >> 8, i & 0xFF]),
                        ttl=600,
                    ),
                )
                # Tiny yield so the drain loop gets a chance, but
                # dispatch is blocked so pending batches accumulate.
                await asyncio.sleep(0.0)
            router._held.set()
            await asyncio.sleep(0.05)
            assert writer.metrics.dropped_queue_full_total > 0
            await writer.shutdown()

        event_loop.run_until_complete(run())


class TestShutdownFlush:
    def test_shutdown_flushes_pending_ops(
        self, tracker, event_loop, router_with_inproc
    ):
        router, scripts = router_with_inproc
        writer = SetWriter(
            tracker, router,
            batch_window_sec=60.0,   # Window won't fire during test
            loop=event_loop,
        )

        async def run():
            await writer.start()
            sid = tracker.set_id_for("github.com", FAMILY_V4)
            writer.submit(
                netns="inproc", family=FAMILY_V4,
                proposal=Proposal(
                    set_id=sid,
                    ip_bytes=b"\x01\x02\x03\x04",
                    ttl=600,
                ),
            )
            # Immediately shut down — no window flush had a chance.
            await asyncio.sleep(0.01)
            await writer.shutdown()
            assert writer.metrics.flush_reason_shutdown_total >= 1

        event_loop.run_until_complete(run())
        assert len(scripts) == 1
