"""Tests for nft-worker router dispatch + ack machinery.

Uses ``inproc_worker_pair`` which runs :func:`worker_main_loop` in
a background thread connected to a real SEQPACKET pair. This
exercises the full parent↔worker protocol without needing fork +
setns + CAP_SYS_ADMIN, but with the real wire codec and asyncio
reply pump.
"""

from __future__ import annotations

import asyncio

import pytest

from shorewalld.batch_codec import (
    BATCH_OP_ADD,
    BATCH_OP_DEL,
    BatchBuilder,
)
from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    FAMILY_V6,
    DnsSetTracker,
)
from shorewalld.worker_router import (
    WorkerBatchError,
    inproc_worker_pair,
)
from shorewall_nft.nft.dns_sets import (
    DnsSetRegistry,
    DnsSetSpec,
    qname_to_set_name,
)


@pytest.fixture
def tracker_with_allowlist():
    reg = DnsSetRegistry()
    reg.add_spec(DnsSetSpec(
        qname="github.com", ttl_floor=300, ttl_ceil=3600, size=256))
    reg.add_spec(DnsSetSpec(
        qname="api.stripe.com", ttl_floor=60, ttl_ceil=3600, size=64))
    t = DnsSetTracker()
    t.load_registry(reg)
    return t


def _name_lookup_for(tracker):
    def lookup(key: tuple[int, int]) -> str | None:
        entry = tracker.name_for(key[0])
        if entry is None:
            return None
        qname, family = entry
        return qname_to_set_name(
            qname, "v4" if family == 4 else "v6")
    return lookup


def _single_op_batch(set_id: int, family: int) -> BatchBuilder:
    b = BatchBuilder()
    ip = b"\x01\x02\x03\x04" if family == 4 else bytes([0xAA] * 16)
    b.append(
        set_id=set_id,
        family=family,
        op_kind=BATCH_OP_ADD,
        ttl=300,
        ip_bytes=ip,
    )
    return b


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


class TestParentWorkerInproc:
    def test_dispatch_returns_applied_count(
        self, tracker_with_allowlist, event_loop
    ):
        applied_scripts: list[str] = []
        pw, _worker_t = inproc_worker_pair(
            tracker_with_allowlist,
            event_loop,
            _name_lookup_for(tracker_with_allowlist),
            apply_cb=applied_scripts.append,
        )
        try:
            sid = tracker_with_allowlist.set_id_for(
                "github.com", FAMILY_V4)
            batch = _single_op_batch(sid, FAMILY_V4)
            result = event_loop.run_until_complete(pw.dispatch(batch))
            assert result == 1
            assert len(applied_scripts) == 1
            assert "dns_github_com_v4" in applied_scripts[0]
            assert "1.2.3.4" in applied_scripts[0]
            assert "timeout 300s" in applied_scripts[0]
            # Both timeout AND expires must be on the line so the kernel
            # actually resets the deadline on a refresh — without
            # ``expires`` the kernel silently keeps the original
            # countdown when the same timeout is re-added.
            assert "expires 300s" in applied_scripts[0]
        finally:
            event_loop.run_until_complete(pw.shutdown())

    def test_v6_op_emits_ip6_formatted_element(
        self, tracker_with_allowlist, event_loop
    ):
        applied_scripts: list[str] = []
        pw, _w = inproc_worker_pair(
            tracker_with_allowlist, event_loop,
            _name_lookup_for(tracker_with_allowlist),
            apply_cb=applied_scripts.append,
        )
        try:
            sid = tracker_with_allowlist.set_id_for(
                "github.com", FAMILY_V6)
            batch = _single_op_batch(sid, FAMILY_V6)
            result = event_loop.run_until_complete(pw.dispatch(batch))
            assert result == 1
            script = applied_scripts[0]
            assert "dns_github_com_v6" in script
            assert "aaaa:aaaa:aaaa:aaaa" in script.lower()
        finally:
            event_loop.run_until_complete(pw.shutdown())

    def test_multiple_ops_one_batch(
        self, tracker_with_allowlist, event_loop
    ):
        applied_scripts: list[str] = []
        pw, _w = inproc_worker_pair(
            tracker_with_allowlist, event_loop,
            _name_lookup_for(tracker_with_allowlist),
            apply_cb=applied_scripts.append,
        )
        try:
            sid = tracker_with_allowlist.set_id_for(
                "api.stripe.com", FAMILY_V4)
            b = BatchBuilder()
            for i in range(5):
                b.append(
                    set_id=sid,
                    family=FAMILY_V4,
                    op_kind=BATCH_OP_ADD,
                    ttl=600,
                    ip_bytes=bytes([10, 0, 0, i]),
                )
            result = event_loop.run_until_complete(pw.dispatch(b))
            assert result == 5
            script = applied_scripts[0]
            assert script.count("add element") == 5
            assert script.count("dns_api_stripe_com_v4") == 5
        finally:
            event_loop.run_until_complete(pw.shutdown())

    def test_delete_op(self, tracker_with_allowlist, event_loop):
        applied_scripts: list[str] = []
        pw, _w = inproc_worker_pair(
            tracker_with_allowlist, event_loop,
            _name_lookup_for(tracker_with_allowlist),
            apply_cb=applied_scripts.append,
        )
        try:
            sid = tracker_with_allowlist.set_id_for(
                "github.com", FAMILY_V4)
            b = BatchBuilder()
            b.append(
                set_id=sid, family=FAMILY_V4, op_kind=BATCH_OP_DEL,
                ttl=0, ip_bytes=b"\x05\x06\x07\x08")
            event_loop.run_until_complete(pw.dispatch(b))
            assert "delete element" in applied_scripts[0]
        finally:
            event_loop.run_until_complete(pw.shutdown())

    def test_worker_error_raises_in_parent(
        self, tracker_with_allowlist, event_loop
    ):
        def boom(_script):
            raise RuntimeError("netlink: something went wrong")

        pw, _w = inproc_worker_pair(
            tracker_with_allowlist, event_loop,
            _name_lookup_for(tracker_with_allowlist),
            apply_cb=boom,
        )
        try:
            sid = tracker_with_allowlist.set_id_for(
                "github.com", FAMILY_V4)
            with pytest.raises(WorkerBatchError, match="netlink"):
                event_loop.run_until_complete(
                    pw.dispatch(_single_op_batch(sid, FAMILY_V4)))
            assert pw.metrics.batches_failed_total == 1
        finally:
            event_loop.run_until_complete(pw.shutdown())

    def test_unknown_set_id_drops_op_silently(
        self, tracker_with_allowlist, event_loop
    ):
        applied_scripts: list[str] = []
        pw, _w = inproc_worker_pair(
            tracker_with_allowlist, event_loop,
            _name_lookup_for(tracker_with_allowlist),
            apply_cb=applied_scripts.append,
        )
        try:
            b = BatchBuilder()
            b.append(
                set_id=9999, family=FAMILY_V4, op_kind=BATCH_OP_ADD,
                ttl=300, ip_bytes=b"\x01\x02\x03\x04")
            result = event_loop.run_until_complete(pw.dispatch(b))
            # Worker reports op_count=1 applied even though the
            # translator dropped it — that's the contract, the
            # SetWriter does the tracker.commit() using its own
            # records and doesn't trust the worker's count.
            assert result == 1
            # No script actually sent because the lookup returned None.
            assert applied_scripts == []
        finally:
            event_loop.run_until_complete(pw.shutdown())

    def test_dispatch_metrics_counted(
        self, tracker_with_allowlist, event_loop
    ):
        pw, _w = inproc_worker_pair(
            tracker_with_allowlist, event_loop,
            _name_lookup_for(tracker_with_allowlist),
        )
        try:
            sid = tracker_with_allowlist.set_id_for(
                "github.com", FAMILY_V4)
            for _ in range(3):
                event_loop.run_until_complete(
                    pw.dispatch(_single_op_batch(sid, FAMILY_V4)))
            assert pw.metrics.batches_sent_total == 3
            assert pw.metrics.batches_applied_total == 3
            assert pw.metrics.batches_failed_total == 0
            assert pw.metrics.alive == 1
        finally:
            event_loop.run_until_complete(pw.shutdown())

    def test_dispatch_records_latency_and_size_histograms(
        self, tracker_with_allowlist, event_loop
    ):
        pw, _w = inproc_worker_pair(
            tracker_with_allowlist, event_loop,
            _name_lookup_for(tracker_with_allowlist),
        )
        try:
            sid = tracker_with_allowlist.set_id_for(
                "github.com", FAMILY_V4)
            for _ in range(3):
                event_loop.run_until_complete(
                    pw.dispatch(_single_op_batch(sid, FAMILY_V4)))
            # Both histograms observed once per dispatch.
            assert pw.metrics.batch_latency_hist.count == 3
            assert pw.metrics.batch_size_hist.count == 3
            # Every batch had one op — all observations land in the
            # "<=1" bucket and propagate upwards cumulatively.
            size_by_bound = dict(
                pw.metrics.batch_size_hist.bucket_samples())
            assert size_by_bound["1"] == 3.0
            assert size_by_bound["+Inf"] == 3.0
            # Latency is always positive and finite; round-trip through
            # the inproc thread is well under one second.
            assert pw.metrics.batch_latency_hist.sum_value > 0.0
            lat_by_bound = dict(
                pw.metrics.batch_latency_hist.bucket_samples())
            assert lat_by_bound["+Inf"] == 3.0
        finally:
            event_loop.run_until_complete(pw.shutdown())


class TestShutdown:
    def test_shutdown_stops_dispatch(
        self, tracker_with_allowlist, event_loop
    ):
        pw, _w = inproc_worker_pair(
            tracker_with_allowlist, event_loop,
            _name_lookup_for(tracker_with_allowlist),
        )
        event_loop.run_until_complete(pw.shutdown())
        assert pw.metrics.alive == 0
        sid = tracker_with_allowlist.set_id_for(
            "github.com", FAMILY_V4)
        with pytest.raises(RuntimeError):
            event_loop.run_until_complete(
                pw.dispatch(_single_op_batch(sid, FAMILY_V4)))
