"""Unit tests for shorewall_nft_stagelab.ipc (transport + message dataclasses)."""

from __future__ import annotations

import asyncio
import json

from shorewall_nft_stagelab.ipc import (
    AckMessage,
    ConnectionClosedError,
    ErrorMessage,
    JsonLineChannel,
    PingMessage,
    PollMetricsMessage,
    RunScenarioMessage,
    SetupEndpointMessage,
    ShutdownMessage,
    TeardownEndpointMessage,
    decode,
    new_id,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


async def _make_channel_pair() -> tuple[JsonLineChannel, JsonLineChannel]:
    """Return two connected JsonLineChannels backed by a Unix socket pair."""
    import socket

    sock_a, sock_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    reader_a, writer_a = await asyncio.open_unix_connection(sock=sock_a)
    reader_b, writer_b = await asyncio.open_unix_connection(sock=sock_b)
    return JsonLineChannel(reader_a, writer_a), JsonLineChannel(reader_b, writer_b)


async def _feed_lines(lines: list[bytes]) -> JsonLineChannel:
    """Return a JsonLineChannel whose reader is pre-loaded with *lines*.

    Uses a loopback socket pair: channel A's writer sends bytes that are
    immediately available on channel B's reader.  We pre-write the lines
    before returning so recv() sees them without needing a second coroutine.
    """
    import socket

    sock_a, sock_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    _reader_a, writer_a = await asyncio.open_unix_connection(sock=sock_a)
    reader_b, writer_b = await asyncio.open_unix_connection(sock=sock_b)
    # Write all lines through writer_a so reader_b sees them, then close
    # writer_a to signal EOF.
    for line in lines:
        writer_a.write(line)
    await writer_a.drain()
    writer_a.close()
    try:
        await writer_a.wait_closed()
    except Exception:  # noqa: BLE001
        pass
    return JsonLineChannel(reader_b, writer_b)


# ── Test 1: roundtrip all message types (encode → dict → decode) ──────────────


def test_roundtrip_all_message_types() -> None:
    """Encode each message type to dict and decode back; assert structural equality."""
    mid = new_id()

    ping = PingMessage(id=mid)
    assert decode(ping.to_dict()) == ping

    setup = SetupEndpointMessage(id=mid, endpoint_spec={"name": "ep1", "port": 9000})
    assert decode(setup.to_dict()) == setup

    teardown = TeardownEndpointMessage(id=mid, endpoint_name="ep1")
    assert decode(teardown.to_dict()) == teardown

    run = RunScenarioMessage(id=mid, scenario_spec={"name": "s1", "steps": []})
    assert decode(run.to_dict()) == run

    poll = PollMetricsMessage(id=mid, source="agent0", kind="counters")
    assert decode(poll.to_dict()) == poll

    shutdown = ShutdownMessage(id=mid)
    assert decode(shutdown.to_dict()) == shutdown

    ack = AckMessage(id=mid, reply_to="other-id", result={"status": "ok"})
    assert decode(ack.to_dict()) == ack

    err = ErrorMessage(
        id=mid, reply_to="other-id", error_type="NotFound", message="missing ep"
    )
    assert decode(err.to_dict()) == err


# ── Test 2: send/recv over a real channel pair ────────────────────────────────


def test_channel_send_recv() -> None:
    """Send a PING from channel A; receive and verify it on channel B."""

    async def _body() -> None:
        ch_a, ch_b = await _make_channel_pair()

        msg = PingMessage(id=new_id())
        await ch_a.send(msg)
        received = await ch_b.recv()
        assert received == msg
        assert isinstance(received, PingMessage)

    asyncio.run(_body())


# ── Test 3: EOF raises ConnectionClosedError ──────────────────────────────────


def test_eof_raises_connection_closed() -> None:
    """Reading after EOF raises ConnectionClosedError."""

    async def _body() -> None:
        import socket

        sock_a, sock_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        _reader_a, writer_a = await asyncio.open_unix_connection(sock=sock_a)
        reader_b, writer_b = await asyncio.open_unix_connection(sock=sock_b)
        # Close the write side immediately — reader_b will see EOF.
        writer_a.close()
        try:
            await writer_a.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        ch = JsonLineChannel(reader_b, writer_b)
        try:
            await ch.recv()
            raise AssertionError("expected ConnectionClosedError")
        except ConnectionClosedError:
            pass

    asyncio.run(_body())


# ── Test 4: malformed JSON raises ValueError ──────────────────────────────────


def test_malformed_json_raises_valueerror() -> None:
    """Writing non-JSON bytes; recv must raise ValueError."""

    async def _body() -> None:
        ch = await _feed_lines([b"not-json\n"])
        try:
            await ch.recv()
            raise AssertionError("expected ValueError")
        except ValueError:
            pass

    asyncio.run(_body())


# ── Test 5: unknown message type raises ValueError ────────────────────────────


def test_unknown_message_type_raises() -> None:
    """A valid JSON object with an unknown 'type' must raise ValueError."""

    async def _body() -> None:
        payload = json.dumps({"type": "BOGUS", "id": new_id(), "version": "1"}).encode() + b"\n"
        ch = await _feed_lines([payload])
        try:
            await ch.recv()
            raise AssertionError("expected ValueError")
        except ValueError as exc:
            assert "BOGUS" in str(exc)

    asyncio.run(_body())
