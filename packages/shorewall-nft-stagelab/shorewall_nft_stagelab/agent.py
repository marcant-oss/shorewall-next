"""Subprocess agent running on the test host: netns setup, traffic-gen lifecycle."""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from shorewall_nft_stagelab.ipc import (
    AckMessage,
    ErrorMessage,
    JsonLineChannel,
    Message,
    PollMetricsMessage,
    RunScenarioMessage,
    SetupEndpointMessage,
    ShutdownMessage,
    TeardownEndpointMessage,
    decode,
    new_id,
)

# ── State type ────────────────────────────────────────────────────────────────

# state dict keys:
#   "host_name": str
#   "stubs": dict[str, int]  — name → pid


# ── Handler stubs ─────────────────────────────────────────────────────────────


async def handle_ping(msg: Message, state: dict[str, Any]) -> dict[str, Any]:
    """Return empty ACK body."""
    return {}


async def handle_setup_endpoint(
    msg: SetupEndpointMessage, state: dict[str, Any]
) -> dict[str, Any]:
    """Create a netns stub for the endpoint and record its pid."""
    import shorewall_nft_netkit.nsstub as nsstub

    spec = msg.endpoint_spec
    name: str = spec["name"]
    ns_name = f"NS_TEST_{name}"
    pid = nsstub.spawn_nsstub(ns_name)
    state["stubs"][name] = pid
    return {"netns": ns_name, "pid": pid}


async def handle_teardown_endpoint(
    msg: TeardownEndpointMessage, state: dict[str, Any]
) -> dict[str, Any]:
    """Stop and remove the named netns stub."""
    import shorewall_nft_netkit.nsstub as nsstub

    name = msg.endpoint_name
    if name not in state["stubs"]:
        raise ValueError(f"unknown endpoint: {name!r}")
    pid = state["stubs"].pop(name)
    nsstub.stop_nsstub(f"NS_TEST_{name}", pid)
    return {"ok": True}


async def handle_run_scenario(
    msg: RunScenarioMessage, state: dict[str, Any]
) -> dict[str, Any]:
    raise NotImplementedError("agent scenario/metrics stubs — T9/T10/T11 will fill in")


async def handle_poll_metrics(
    msg: PollMetricsMessage, state: dict[str, Any]
) -> dict[str, Any]:
    raise NotImplementedError("agent scenario/metrics stubs — T9/T10/T11 will fill in")


# ── Dispatch table ────────────────────────────────────────────────────────────

_HANDLERS = {
    "PING": handle_ping,
    "SETUP_ENDPOINT": handle_setup_endpoint,
    "TEARDOWN_ENDPOINT": handle_teardown_endpoint,
    "RUN_SCENARIO": handle_run_scenario,
    "POLL_METRICS": handle_poll_metrics,
}


# ── Cleanup helper ────────────────────────────────────────────────────────────


def _cleanup_stubs(state: dict[str, Any]) -> None:
    """Stop all remaining nsstub processes."""
    import shorewall_nft_netkit.nsstub as nsstub

    for name, pid in list(state["stubs"].items()):
        try:
            nsstub.stop_nsstub(f"NS_TEST_{name}", pid)
        except Exception:  # noqa: BLE001
            pass
    state["stubs"].clear()


# ── Async streams helper ──────────────────────────────────────────────────────


async def _make_stdio_channel() -> JsonLineChannel:
    """Attach asyncio streams to stdin/stdout and return a JsonLineChannel."""
    loop = asyncio.get_event_loop()

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    write_transport, write_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(write_transport, write_protocol, None, loop)

    return JsonLineChannel(reader, writer)


# ── Main loop ─────────────────────────────────────────────────────────────────


async def run_agent(host_name: str) -> int:
    """Main async loop.

    Attach to stdin/stdout asyncio streams, dispatch messages until SHUTDOWN
    (respond with ACK then exit 0) or EOF (exit 0) or fatal error (exit 1).
    Returns exit code for sys.exit.

    Tracks a registry of active netns stubs (name → pid) so
    TEARDOWN_ENDPOINT can stop them; SHUTDOWN cleans up all remaining stubs
    before ACK.
    """
    state: dict[str, Any] = {"host_name": host_name, "stubs": {}}

    try:
        channel = await _make_stdio_channel()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"agent: failed to attach stdio streams: {exc}\n")
        return 1

    while True:
        # Read next message
        try:
            raw_line = await channel._reader.readline()
        except Exception:  # noqa: BLE001
            _cleanup_stubs(state)
            return 0

        if not raw_line:
            # EOF
            _cleanup_stubs(state)
            return 0

        # Decode
        import json

        msg_id: str | None = None
        try:
            data = json.loads(raw_line.rstrip(b"\n"))
            if not isinstance(data, dict):
                raise ValueError("message must be a JSON object")
            msg_id = data.get("id")
            msg = decode(data)
        except Exception as exc:  # noqa: BLE001
            error = ErrorMessage(
                id=new_id(),
                reply_to=msg_id or "unknown",
                error_type=type(exc).__name__,
                message=str(exc),
            )
            await channel.send(error)
            continue

        # SHUTDOWN — clean up and ack
        if isinstance(msg, ShutdownMessage):
            _cleanup_stubs(state)
            ack = AckMessage(id=new_id(), reply_to=msg.id, result={})
            await channel.send(ack)
            return 0

        # Dispatch
        handler = _HANDLERS.get(msg.type)  # type: ignore[attr-defined]
        if handler is None:
            error = ErrorMessage(
                id=new_id(),
                reply_to=msg.id,  # type: ignore[attr-defined]
                error_type="ValueError",
                message=f"no handler for message type {msg.type!r}",  # type: ignore[attr-defined]
            )
            await channel.send(error)
            continue

        try:
            result = await handler(msg, state)
        except Exception as exc:  # noqa: BLE001
            error = ErrorMessage(
                id=new_id(),
                reply_to=msg.id,  # type: ignore[attr-defined]
                error_type=type(exc).__name__,
                message=str(exc),
            )
            await channel.send(error)
            continue

        ack = AckMessage(id=new_id(), reply_to=msg.id, result=result)  # type: ignore[attr-defined]
        await channel.send(ack)


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """CLI entry: argparse --host-name, asyncio.run(run_agent(...)), sys.exit(code)."""
    parser = argparse.ArgumentParser(description="shorewall-nft-stagelab agent")
    parser.add_argument(
        "--host-name",
        required=True,
        help="Logical name for this test host (used in log/metrics labels)",
    )
    args = parser.parse_args()
    code = asyncio.run(run_agent(args.host_name))
    sys.exit(code)


if __name__ == "__main__":
    main()
