"""Phase 4 shorewalld dnstap consumer unit tests.

Covers the hand-rolled FrameStream reader, the 3-field dnstap
protobuf decoder, DNS wire parse (opt-in on dnspython availability),
qname → set-name sanitisation, and the bounded-queue overflow path.

No real unix socket, no real nftables socket, no real pdns. The
``SetWriter``-level integration is exercised with a fake
``NftInterface`` stub and the decode worker pool is fed from a
synchronous ``queue.Queue`` so the test never races an event loop.
"""
from __future__ import annotations

import asyncio
import io
import queue
import struct
from typing import Any

import pytest

from shorewalld.dnstap import (
    CLIENT_RESPONSE,
    DecodeWorkerPool,
    DnstapMetrics,
    DnsUpdate,
    QnameFilter,
    SetWriter,
    _decode_fields,
    _read_varint,
    decode_dnstap_frame,
    parse_dns_response,
    qname_to_set_name,
)
from shorewalld.framestream import (
    CONTROL_ACCEPT,
    CONTROL_READY,
    CONTROL_START,
    DNSTAP_CONTENT_TYPE,
    FrameStreamError,
    accept_handshake,
    decode_control,
    encode_control,
    read_frame,
)

try:
    import dns.message  # type: ignore[import-untyped]
    import dns.name  # type: ignore[import-untyped]
    import dns.rrset  # type: ignore[import-untyped]
    _HAVE_DNSPYTHON = True
except ImportError:
    _HAVE_DNSPYTHON = False


# ── protobuf varint / field decoder ─────────────────────────────────


def _enc_varint(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _enc_field(fnum: int, wire_type: int, body: bytes) -> bytes:
    return _enc_varint((fnum << 3) | wire_type) + body


def test_varint_roundtrip_small():
    v, i = _read_varint(_enc_varint(150), 0)
    assert v == 150
    assert i == 2


def test_varint_roundtrip_large():
    v, _ = _read_varint(_enc_varint(123_456_789), 0)
    assert v == 123_456_789


def test_decode_fields_varint_and_length_delimited():
    # Two fields: #1 varint=7, #2 length-delimited "hello"
    buf = (
        _enc_field(1, 0, _enc_varint(7))
        + _enc_field(2, 2, _enc_varint(5) + b"hello")
    )
    out = _decode_fields(buf)
    assert out == {1: 7, 2: b"hello"}


def test_decode_fields_truncated_raises():
    with pytest.raises(ValueError):
        _decode_fields(_enc_field(1, 2, _enc_varint(10) + b"short"))


# ── dnstap Dnstap framing ──────────────────────────────────────────


def _make_dnstap_frame(msg_type: int, wire: bytes) -> bytes:
    """Build a dnstap.Dnstap protobuf frame wrapping a DNS wire blob.

    Structure (only the fields we read):
      Dnstap.message (field 14, length-delimited) = Dnstap.Message {
        type (field 1, varint) = msg_type
        response_message (field 14, length-delimited) = wire
      }
    """
    inner = (
        _enc_field(1, 0, _enc_varint(msg_type))
        + _enc_field(14, 2, _enc_varint(len(wire)) + wire)
    )
    outer = _enc_field(14, 2, _enc_varint(len(inner)) + inner)
    return outer


def test_decode_dnstap_frame_extracts_wire_and_type():
    wire_bytes = b"\x00\x01\x02\x03"
    frame = _make_dnstap_frame(CLIENT_RESPONSE, wire_bytes)
    decoded = decode_dnstap_frame(frame)
    assert decoded is not None
    msg_type, payload = decoded
    assert msg_type == CLIENT_RESPONSE
    assert payload == wire_bytes


def test_decode_dnstap_frame_none_when_missing_message():
    assert decode_dnstap_frame(b"") is None


# ── DNS wire parse ─────────────────────────────────────────────────


def _build_dns_a_response(qname: str,
                          addrs: list[str], ttl: int = 300) -> bytes:
    msg = dns.message.make_response(
        dns.message.make_query(qname, "A"))
    rrset = dns.rrset.from_text_list(
        dns.name.from_text(qname), ttl, "IN", "A", addrs)
    msg.answer.append(rrset)
    return msg.to_wire()


def _build_dns_aaaa_response(qname: str,
                             addrs: list[str], ttl: int = 120) -> bytes:
    msg = dns.message.make_response(
        dns.message.make_query(qname, "AAAA"))
    rrset = dns.rrset.from_text_list(
        dns.name.from_text(qname), ttl, "IN", "AAAA", addrs)
    msg.answer.append(rrset)
    return msg.to_wire()


@pytest.mark.skipif(not _HAVE_DNSPYTHON, reason="dnspython not installed")
def test_parse_dns_response_a_record():
    wire = _build_dns_a_response(
        "github.com.", ["140.82.121.3", "140.82.121.4"], ttl=500)
    upd = parse_dns_response(wire)
    assert upd is not None
    assert upd.qname == "github.com"
    assert sorted(upd.a_rrs) == ["140.82.121.3", "140.82.121.4"]
    assert upd.aaaa_rrs == []
    assert upd.ttl == 500


@pytest.mark.skipif(not _HAVE_DNSPYTHON, reason="dnspython not installed")
def test_parse_dns_response_aaaa_record():
    wire = _build_dns_aaaa_response(
        "example.com.", ["2606:2800:220:1::248:1893"], ttl=60)
    upd = parse_dns_response(wire)
    assert upd is not None
    assert upd.aaaa_rrs == ["2606:2800:220:1::248:1893"]
    assert upd.ttl == 60


@pytest.mark.skipif(not _HAVE_DNSPYTHON, reason="dnspython not installed")
def test_parse_dns_response_returns_none_for_nxdomain():
    q = dns.message.make_query("nonexistent.invalid.", "A")
    msg = dns.message.make_response(q)
    msg.set_rcode(dns.rcode.NXDOMAIN)
    upd = parse_dns_response(msg.to_wire())
    assert upd is None


def test_parse_dns_response_returns_none_on_garbage():
    assert parse_dns_response(b"\x00\x01") is None


# ── qname → set name sanitisation ──────────────────────────────────


def test_qname_to_set_name_basic():
    assert qname_to_set_name("github.com", "A") == "dns_github_com_v4"


def test_qname_to_set_name_aaaa_suffix():
    assert qname_to_set_name("example.com", "AAAA") == "dns_example_com_v6"


def test_qname_to_set_name_sanitises_specials():
    name = qname_to_set_name("foo-bar.baz.example.com", "A")
    assert name.startswith("dns_foo_bar_baz_example_")
    assert name.endswith("_v4") or len(name) == 31


def test_qname_to_set_name_truncates_to_31_chars():
    long = "a" * 60 + ".com"
    assert len(qname_to_set_name(long, "A")) == 31


def test_qname_to_set_name_strips_trailing_dot():
    assert qname_to_set_name("github.com.", "A") == "dns_github_com_v4"


# ── QnameFilter ────────────────────────────────────────────────────


def test_qname_filter_default_allows_everything():
    f = QnameFilter()
    assert f.allows("github.com")
    assert f.allows("any.random.thing")


def test_qname_filter_allowlist():
    f = QnameFilter(allowlist={"github.com"})
    assert f.allows("github.com")
    assert f.allows("GITHUB.COM")
    assert not f.allows("example.com")


# ── FrameStream read_frame + handshake ─────────────────────────────


def _encode_length_prefixed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


async def _read_from_bytes(buf: bytes) -> Any:
    """Run read_frame against a StreamReader pre-fed with ``buf``."""
    reader = asyncio.StreamReader()
    reader.feed_data(buf)
    reader.feed_eof()
    return await read_frame(reader)


def test_read_frame_data():
    payload = b"\x01\x02\x03\x04"
    buf = _encode_length_prefixed(payload)
    is_ctrl, body = asyncio.run(_read_from_bytes(buf))
    assert is_ctrl is False
    assert body == payload


def test_read_frame_control_roundtrips_encode_control():
    ctrl_bytes = encode_control(CONTROL_ACCEPT, [DNSTAP_CONTENT_TYPE])
    is_ctrl, body = asyncio.run(_read_from_bytes(ctrl_bytes))
    assert is_ctrl is True
    parsed = decode_control(body)
    assert parsed.ctype == CONTROL_ACCEPT
    assert DNSTAP_CONTENT_TYPE in parsed.content_types


def test_decode_control_rejects_truncated():
    with pytest.raises(FrameStreamError):
        decode_control(b"\x00\x01")


# Simulated server/client handshake over an in-process pair.


class _MockStreamWriter:
    """Captures writes for assertions."""
    def __init__(self) -> None:
        self.buf = io.BytesIO()

    def write(self, data: bytes) -> None:
        self.buf.write(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, _name: str) -> Any:
        return None


def test_accept_handshake_roundtrip():
    # Writer (recursor side) sends READY + START
    incoming = (
        encode_control(CONTROL_READY, [DNSTAP_CONTENT_TYPE])
        + encode_control(CONTROL_START, [DNSTAP_CONTENT_TYPE])
    )

    async def driver() -> bytes:
        reader = asyncio.StreamReader()
        reader.feed_data(incoming)
        reader.feed_eof()
        writer = _MockStreamWriter()
        await accept_handshake(reader, writer)  # type: ignore[arg-type]
        return writer.buf.getvalue()

    sent = asyncio.run(driver())
    # Expect exactly one ACCEPT with the correct content type.
    parsed = decode_control(sent[8:])
    assert parsed.ctype == CONTROL_ACCEPT
    assert DNSTAP_CONTENT_TYPE in parsed.content_types


def test_accept_handshake_rejects_wrong_content_type():
    bad = encode_control(CONTROL_READY, [b"protobuf:wrong.Type"])

    async def driver() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(bad)
        reader.feed_eof()
        writer = _MockStreamWriter()
        await accept_handshake(reader, writer)  # type: ignore[arg-type]

    with pytest.raises(FrameStreamError):
        asyncio.run(driver())


# ── DecodeWorkerPool ───────────────────────────────────────────────


@pytest.mark.skipif(not _HAVE_DNSPYTHON, reason="dnspython not installed")
def test_worker_pool_accepts_client_response_and_pushes_update():
    metrics = DnstapMetrics()
    frame_q: queue.Queue[bytes] = queue.Queue(maxsize=16)

    wire = _build_dns_a_response("github.com.", ["140.82.121.3"], ttl=300)
    frame = _make_dnstap_frame(CLIENT_RESPONSE, wire)

    received: list[DnsUpdate] = []

    async def driver() -> None:
        loop = asyncio.get_running_loop()

        def on_update(upd: DnsUpdate) -> None:
            received.append(upd)

        pool = DecodeWorkerPool(
            frame_q, metrics, on_update=on_update, loop=loop,
            qname_filter=QnameFilter(), n_workers=2)
        pool.start()
        try:
            frame_q.put(frame)
            # Give workers time to decode + dispatch + loop.call_soon_threadsafe.
            for _ in range(50):
                await asyncio.sleep(0.02)
                if received:
                    break
        finally:
            pool.stop()

    asyncio.run(driver())
    assert len(received) == 1
    assert received[0].qname == "github.com"
    assert received[0].a_rrs == ["140.82.121.3"]
    assert metrics.frames_accepted == 1


def test_worker_pool_counts_non_client_response_drops():
    metrics = DnstapMetrics()
    frame_q: queue.Queue[bytes] = queue.Queue(maxsize=4)

    # CLIENT_QUERY (type=5) is a query event, not a response — the
    # decoder drops it and increments the non-response counter.
    frame = _make_dnstap_frame(5, b"\x00")

    async def driver() -> None:
        loop = asyncio.get_running_loop()
        pool = DecodeWorkerPool(
            frame_q, metrics,
            on_update=lambda _u: None,
            loop=loop, qname_filter=QnameFilter(), n_workers=1)
        pool.start()
        try:
            frame_q.put(frame)
            for _ in range(50):
                await asyncio.sleep(0.02)
                if metrics.frames_dropped_not_client_response:
                    break
        finally:
            pool.stop()

    asyncio.run(driver())
    assert metrics.frames_dropped_not_client_response == 1


@pytest.mark.skipif(not _HAVE_DNSPYTHON, reason="dnspython not installed")
def test_worker_pool_two_pass_filter_skips_dnspython_on_reject(monkeypatch):
    """When an allowlist is set and the qname is not in it, the
    expensive dnspython parse must not run. This is the whole point
    of the two-pass filter (CLAUDE.md §Performance doctrine)."""
    import shorewalld.dnstap as dnstap_mod

    metrics = DnstapMetrics()
    frame_q: queue.Queue[bytes] = queue.Queue(maxsize=4)

    wire = _build_dns_a_response("blocked.example.", ["10.0.0.1"])
    frame = _make_dnstap_frame(CLIENT_RESPONSE, wire)

    parse_calls: list[bytes] = []
    real_parse = dnstap_mod.parse_dns_response

    def tracking_parse(w: bytes):
        parse_calls.append(w)
        return real_parse(w)

    monkeypatch.setattr(dnstap_mod, "parse_dns_response", tracking_parse)

    async def driver() -> None:
        loop = asyncio.get_running_loop()
        pool = DecodeWorkerPool(
            frame_q, metrics,
            on_update=lambda _u: None,
            loop=loop,
            qname_filter=QnameFilter(allowlist={"allowed.example"}),
            n_workers=1)
        pool.start()
        try:
            frame_q.put(frame)
            for _ in range(50):
                await asyncio.sleep(0.02)
                if metrics.frames_dropped_not_allowlisted:
                    break
        finally:
            pool.stop()

    asyncio.run(driver())
    assert metrics.frames_dropped_not_allowlisted == 1
    assert metrics.frames_accepted == 0
    assert parse_calls == []


@pytest.mark.skipif(not _HAVE_DNSPYTHON, reason="dnspython not installed")
def test_worker_pool_two_pass_filter_accepts_allowlisted(monkeypatch):
    """When the qname is in the allowlist, parse_dns_response runs
    and the update propagates normally."""
    import shorewalld.dnstap as dnstap_mod

    metrics = DnstapMetrics()
    frame_q: queue.Queue[bytes] = queue.Queue(maxsize=4)

    wire = _build_dns_a_response("allowed.example.", ["10.0.0.1"])
    frame = _make_dnstap_frame(CLIENT_RESPONSE, wire)

    parse_calls: list[bytes] = []
    real_parse = dnstap_mod.parse_dns_response

    def tracking_parse(w: bytes):
        parse_calls.append(w)
        return real_parse(w)

    monkeypatch.setattr(dnstap_mod, "parse_dns_response", tracking_parse)

    received: list[DnsUpdate] = []

    async def driver() -> None:
        loop = asyncio.get_running_loop()
        pool = DecodeWorkerPool(
            frame_q, metrics,
            on_update=received.append,
            loop=loop,
            qname_filter=QnameFilter(allowlist={"allowed.example"}),
            n_workers=1)
        pool.start()
        try:
            frame_q.put(frame)
            for _ in range(50):
                await asyncio.sleep(0.02)
                if received:
                    break
        finally:
            pool.stop()

    asyncio.run(driver())
    assert len(received) == 1
    assert received[0].qname == "allowed.example"
    assert metrics.frames_accepted == 1
    assert metrics.frames_dropped_not_allowlisted == 0
    assert len(parse_calls) == 1


def test_worker_pool_counts_decode_errors():
    metrics = DnstapMetrics()
    frame_q: queue.Queue[bytes] = queue.Queue(maxsize=4)

    async def driver() -> None:
        loop = asyncio.get_running_loop()
        pool = DecodeWorkerPool(
            frame_q, metrics,
            on_update=lambda _u: None,
            loop=loop, qname_filter=QnameFilter(), n_workers=1)
        pool.start()
        try:
            frame_q.put(b"\xff\xff\xff\xff\xff\xff\xff\xff")  # garbage
            for _ in range(50):
                await asyncio.sleep(0.02)
                if metrics.frames_decode_error:
                    break
        finally:
            pool.stop()

    asyncio.run(driver())
    assert metrics.frames_decode_error == 1


# ── Queue overflow bookkeeping (server side) ──────────────────────


def test_metrics_inc_is_thread_safe():
    m = DnstapMetrics()
    import threading

    def hammer() -> None:
        for _ in range(1000):
            m.inc("frames_accepted")

    threads = [threading.Thread(target=hammer) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m.frames_accepted == 4000


# ── SetWriter (with a fake NftInterface) ──────────────────────────


class _FakeNft:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def add_set_element(self, set_name: str, element: str,
                        timeout: str | None = None,
                        family: str = "inet", table: str = "shorewall",
                        *, netns: str | None = None) -> None:
        self.calls.append((set_name, element, timeout or "", netns or ""))


def test_set_writer_applies_both_families_across_netns():
    fake = _FakeNft()
    metrics = DnstapMetrics()
    sw = SetWriter(fake, ["fw", "rns1"], metrics)  # type: ignore[arg-type]
    upd = DnsUpdate(
        qname="github.com",
        a_rrs=["140.82.121.3"],
        aaaa_rrs=["2606:50c0:8000::154"],
        ttl=200)
    sw.apply(upd)
    # 2 netns × (1 A + 1 AAAA) = 4 calls
    assert len(fake.calls) == 4
    sets = {c[0] for c in fake.calls}
    assert sets == {"dns_github_com_v4", "dns_github_com_v6"}
    netns = {c[3] for c in fake.calls}
    assert netns == {"fw", "rns1"}
    timeouts = {c[2] for c in fake.calls}
    assert timeouts == {"200s"}
