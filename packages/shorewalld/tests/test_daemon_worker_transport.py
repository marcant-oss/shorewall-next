"""Tests for the parent↔worker SEQPACKET transport.

Uses in-process ``socketpair()`` endpoints so we can verify the
wire semantics without fork()/setns() complications. Those live
in the ``nft_worker`` integration tests later in Phase 2.
"""

from __future__ import annotations

import threading

import pytest

from shorewalld.batch_codec import (
    BATCH_OP_ADD,
    REPLY_OK,
    BatchBuilder,
    decode_header,
    decode_reply,
    encode_reply_into,
    iter_ops,
)
from shorewalld.worker_transport import (
    WorkerTransport,
    echo_worker_loop,
)


@pytest.fixture
def pair():
    parent, worker = WorkerTransport.pair(recv_buf_size=4096)
    yield parent, worker
    parent.close()
    worker.close()


def test_pair_yields_connected_transports(pair):
    parent, worker = pair
    parent.send(b"ping")
    view = worker.recv_into()
    assert bytes(view) == b"ping"
    worker.send(b"pong")
    view = parent.recv_into()
    assert bytes(view) == b"pong"


def test_batch_builder_round_trip_through_transport(pair):
    parent, worker = pair
    b = BatchBuilder()
    b.append(
        set_id=1, family=4, op_kind=BATCH_OP_ADD,
        ttl=300, ip_bytes=b"\x0a\x00\x00\x01",
    )
    b.append(
        set_id=1, family=4, op_kind=BATCH_OP_ADD,
        ttl=300, ip_bytes=b"\x0a\x00\x00\x02",
    )
    parent.send(b.finish(batch_id=42))

    view = worker.recv_into()
    header = decode_header(view)
    assert header.batch_id == 42
    assert header.op_count == 2
    ops = list(iter_ops(view, header))
    assert ops[0].ip_bytes == b"\x0a\x00\x00\x01"
    assert ops[1].ip_bytes == b"\x0a\x00\x00\x02"


def test_reply_round_trip(pair):
    parent, worker = pair
    ack_buf = bytearray(128)
    reply_view = encode_reply_into(
        ack_buf, status=REPLY_OK, batch_id=42, applied=2)
    worker.send(reply_view)

    view = parent.recv_into()
    r = decode_reply(view)
    assert r.status == REPLY_OK
    assert r.batch_id == 42
    assert r.applied == 2


def test_echo_worker_loop(pair):
    parent, worker = pair

    def run_worker():
        echo_worker_loop(worker, max_iterations=3)

    t = threading.Thread(target=run_worker)
    t.start()
    try:
        for i in range(3):
            parent.send(bytes([i]) * 16)
            view = parent.recv_into()
            assert bytes(view) == bytes([i]) * 16
    finally:
        worker.close()
        t.join(timeout=2.0)


def test_transport_stats_counters(pair):
    parent, worker = pair
    parent.send(b"a" * 20)
    worker.recv_into()
    worker.send(b"b" * 30)
    parent.recv_into()

    assert parent.stats.sends_total == 1
    assert parent.stats.send_bytes_total == 20
    assert parent.stats.recvs_total == 1
    assert parent.stats.recv_bytes_total == 30
    assert worker.stats.sends_total == 1
    assert worker.stats.recvs_total == 1


def test_truncation_raises(pair):
    # A SEQPACKET datagram bigger than the peer's recv buffer is
    # marked MSG_TRUNC on recvmsg; we translate that to OSError.
    parent = pair[0]
    worker = pair[1]
    # Tiny recv buffer on the worker side — send something bigger.
    worker._recv_buf = bytearray(8)
    worker._recv_view = memoryview(worker._recv_buf)
    parent.send(b"x" * 64)
    with pytest.raises(OSError):
        worker.recv_into()


def test_send_error_counts_on_closed_peer(pair):
    parent, worker = pair
    worker.close()
    # EPIPE / ECONNRESET — the exact errno varies; what we assert
    # is that the stats counter advances and the error surfaces.
    with pytest.raises(OSError):
        parent.send(b"dropped")
    assert parent.stats.send_errors_total == 1
