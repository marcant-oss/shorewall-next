"""TCP dnstap listener tests.

pdns_recursor can emit dnstap over TCP via
``dnstapFrameStreamServer({"tcp://host:port"}, ...)``. These tests
verify that shorewalld's DnstapServer accepts a
``(tcp_host, tcp_port)`` pair, binds the listener, runs the real
FrameStream handshake over TCP, and pipes decoded frames through
the same downstream path as the unix socket variant.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from shorewalld.dnstap import DnstapServer
from shorewalld.framestream import (
    read_frame,
)
from shorewalld.proto import dnstap_pb2


def _dns_response_wire(qname: str = "github.com") -> bytes:
    wire = bytearray(12)
    wire[0] = 0x12
    wire[1] = 0x34
    wire[2] = 0x81
    wire[5] = 1
    for label in qname.rstrip(".").split("."):
        wire.append(len(label))
        wire.extend(label.encode("ascii"))
    wire.append(0)
    wire.extend((1).to_bytes(2, "big"))   # QTYPE=A
    wire.extend((1).to_bytes(2, "big"))   # QCLASS=IN
    # Answer section (one A RR for 1.2.3.4, ttl 300)
    # NAME (pointer to 12), TYPE=1, CLASS=1, TTL=300, RDLENGTH=4, RDATA
    wire[7] = 1  # ANCOUNT=1
    wire.extend(b"\xc0\x0c")               # compression pointer
    wire.extend((1).to_bytes(2, "big"))     # TYPE
    wire.extend((1).to_bytes(2, "big"))     # CLASS
    wire.extend((300).to_bytes(4, "big"))   # TTL
    wire.extend((4).to_bytes(2, "big"))     # RDLENGTH
    wire.extend(bytes([1, 2, 3, 4]))         # RDATA
    return bytes(wire)


def _dnstap_frame() -> bytes:
    msg = dnstap_pb2.Dnstap()
    msg.type = dnstap_pb2.Dnstap.MESSAGE
    msg.message.type = dnstap_pb2.Message.CLIENT_RESPONSE
    msg.message.response_message = _dns_response_wire("github.com")
    return msg.SerializeToString()


class TestDnstapServerTcpConstruction:
    def test_requires_at_least_one_listener(self):
        nft = MagicMock()
        with pytest.raises(ValueError):
            DnstapServer(socket_path=None, nft=nft, netns_list=[""])

    def test_accepts_tcp_only(self, tmp_path):
        nft = MagicMock()
        server = DnstapServer(
            socket_path=None,
            nft=nft,
            netns_list=[""],
            tcp_host="127.0.0.1",
            tcp_port=0,
        )
        assert server.tcp_host == "127.0.0.1"
        assert server.socket_path is None

    def test_accepts_both(self, tmp_path):
        nft = MagicMock()
        server = DnstapServer(
            socket_path=str(tmp_path / "dnstap.sock"),
            nft=nft,
            netns_list=[""],
            tcp_host="127.0.0.1",
            tcp_port=0,
        )
        assert server.socket_path is not None
        assert server.tcp_host == "127.0.0.1"


class TestDnstapTcpListener:
    def test_tcp_handshake_and_frame_delivery(self):
        """End-to-end: bind TCP listener, connect a fake pdns
        client, run the FrameStream handshake, push one data
        frame, verify it lands in the decoder queue."""
        nft = MagicMock()
        nft.add_set_element = MagicMock()
        loop = asyncio.new_event_loop()
        updates: list = []

        async def run():
            server = DnstapServer(
                socket_path=None,
                nft=nft,
                netns_list=[""],
                queue_size=64,
                n_workers=1,
                tcp_host="127.0.0.1",
                tcp_port=0,
            )
            # Patch the update sink so we can observe frames
            # arriving without touching libnftables.
            got_update = asyncio.Event()

            def _capture(upd):
                updates.append(upd)
                got_update.set()

            server._on_update = _capture
            await server.start()
            try:
                # Pick up the ephemeral port we just bound.
                assert server._tcp_server is not None
                sockets = server._tcp_server.sockets or []
                host, port = sockets[0].getsockname()[:2]

                # Fake pdns client — opens TCP, runs the producer
                # side of the handshake, pushes one data frame.
                reader, writer = await asyncio.open_connection(
                    host, port)
                try:
                    # Server runs accept_handshake; we run the
                    # producer side by sending READY → ACCEPT →
                    # START → data → STOP.
                    from shorewalld.framestream import (
                        CONTROL_READY,
                        CONTROL_START,
                        CONTROL_STOP,
                        DNSTAP_CONTENT_TYPE,
                        encode_control,
                    )
                    writer.write(encode_control(
                        CONTROL_READY, [DNSTAP_CONTENT_TYPE]))
                    await writer.drain()
                    # Server replies with ACCEPT.
                    is_ctrl, body = await read_frame(reader)
                    assert is_ctrl
                    # Send START.
                    writer.write(encode_control(
                        CONTROL_START, [DNSTAP_CONTENT_TYPE]))
                    # Send one data frame.
                    frame = _dnstap_frame()
                    header = len(frame).to_bytes(4, "big")
                    writer.write(header + frame)
                    # Send STOP.
                    writer.write(encode_control(CONTROL_STOP))
                    await writer.drain()
                    # Wait for the decoder worker to call _on_update.
                    # Using an Event means we return the instant the
                    # update lands — no polling, no fixed sleep, no
                    # sensitivity to CI host speed.
                    await asyncio.wait_for(got_update.wait(), timeout=8.0)
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            finally:
                server.close()

        try:
            loop.run_until_complete(asyncio.wait_for(run(), timeout=12.0))
        finally:
            loop.close()

        # The decoder pipeline accepted the frame.
        assert any(
            getattr(u, "qname", "") == "github.com" for u in updates)


class TestListenerConcurrent:
    def test_both_listeners_up_concurrently(self, tmp_path):
        """Start unix + tcp together, verify serve_forever doesn't
        immediately exit and close() tears everything down cleanly."""
        nft = MagicMock()
        loop = asyncio.new_event_loop()

        async def run():
            server = DnstapServer(
                socket_path=str(tmp_path / "dnstap.sock"),
                nft=nft,
                netns_list=[""],
                tcp_host="127.0.0.1",
                tcp_port=0,
                n_workers=1,
            )
            await server.start()
            assert server._server is not None
            assert server._tcp_server is not None
            server.close()
            # After close, both should be None.
            assert server._server is None
            assert server._tcp_server is None

        try:
            loop.run_until_complete(run())
        finally:
            loop.close()
