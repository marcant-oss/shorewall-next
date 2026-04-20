"""Integration tests for agent runtime — requires root + CAP_NET_ADMIN.

These tests spawn the agent as a subprocess (via asyncio stdin/stdout IPC),
send real SETUP_ENDPOINT / TEARDOWN_ENDPOINT / SHUTDOWN messages, and verify
that actual netns + topology objects are created and torn down.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys

import pytest

from shorewall_nft_stagelab.ipc import (
    AckMessage,
    SetupEndpointMessage,
    ShutdownMessage,
    TeardownEndpointMessage,
    decode,
    new_id,
)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="requires root and CAP_NET_ADMIN",
)

_AGENT_CMD = [sys.executable, "-m", "shorewall_nft_stagelab.agent", "--host-name", "test-host"]
_TIMEOUT = 15.0


def _dummy_nic(name: str) -> None:
    subprocess.run(["ip", "link", "add", name, "type", "dummy"],
                   check=True, text=True, capture_output=True)


def _del_nic(name: str) -> None:
    subprocess.run(["ip", "link", "delete", name],
                   check=False, text=True, capture_output=True)


def _encode(msg) -> bytes:
    return (json.dumps(msg.to_dict(), separators=(",", ":")) + "\n").encode()


async def _recv_ack(reader: asyncio.StreamReader) -> dict:
    line = await asyncio.wait_for(reader.readline(), timeout=_TIMEOUT)
    data = json.loads(line.rstrip(b"\n"))
    msg = decode(data)
    assert isinstance(msg, AckMessage), f"expected ACK, got {data}"
    return msg.result


@pytest.mark.asyncio
async def test_setup_native_endpoint_end_to_end():
    """Spawn agent, SETUP_ENDPOINT native, check ACK fields, TEARDOWN, SHUTDOWN."""
    dummy = "agnt_dummy0"
    _dummy_nic(dummy)
    try:
        proc = await asyncio.create_subprocess_exec(
            *_AGENT_CMD,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        assert proc.stdin and proc.stdout

        # SETUP
        setup_msg = SetupEndpointMessage(
            id=new_id(),
            endpoint_spec={
                "name": "agntnat1", "mode": "native",
                "nic": dummy, "vlan": 111,
                "ipv4": "10.99.111.5/24", "ipv4_gw": "10.99.111.1",
            },
        )
        proc.stdin.write(_encode(setup_msg))
        await proc.stdin.drain()
        result = await asyncio.wait_for(_recv_ack(proc.stdout), timeout=_TIMEOUT)
        assert result["mode"] == "native"
        assert result["netns"] == "NS_TEST_agntnat1"
        assert "nsstub_pid" in result
        assert result["vlan_iface"] == f"{dummy}.111"

        # TEARDOWN
        teardown_msg = TeardownEndpointMessage(id=new_id(), endpoint_name="agntnat1")
        proc.stdin.write(_encode(teardown_msg))
        await proc.stdin.drain()
        td_result = await asyncio.wait_for(_recv_ack(proc.stdout), timeout=_TIMEOUT)
        assert td_result == {"ok": True}

        # SHUTDOWN
        shutdown_msg = ShutdownMessage(id=new_id())
        proc.stdin.write(_encode(shutdown_msg))
        await proc.stdin.drain()
        await asyncio.wait_for(_recv_ack(proc.stdout), timeout=_TIMEOUT)

        await asyncio.wait_for(proc.wait(), timeout=5.0)
        assert proc.returncode == 0
    finally:
        _del_nic(dummy)
        try:
            proc.stdin.close()  # type: ignore[union-attr]
        except Exception:
            pass


@pytest.mark.asyncio
async def test_setup_probe_endpoint_end_to_end():
    """Spawn agent, SETUP_ENDPOINT probe, check ACK fields, TEARDOWN, SHUTDOWN."""
    proc = await asyncio.create_subprocess_exec(
        *_AGENT_CMD,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    assert proc.stdin and proc.stdout

    try:
        # SETUP
        setup_msg = SetupEndpointMessage(
            id=new_id(),
            endpoint_spec={
                "name": "agntprobe1", "mode": "probe",
                "vlan": 200, "bridge": "br-agnt",
            },
        )
        proc.stdin.write(_encode(setup_msg))
        await proc.stdin.drain()
        result = await asyncio.wait_for(_recv_ack(proc.stdout), timeout=_TIMEOUT)
        assert result["mode"] == "probe"
        assert result["netns"] == "NS_TEST_agntprobe1"
        assert "nsstub_pid" in result
        assert result["bridge"] == "br-agnt"
        assert result["tap_count"] == 1

        # TEARDOWN
        teardown_msg = TeardownEndpointMessage(id=new_id(), endpoint_name="agntprobe1")
        proc.stdin.write(_encode(teardown_msg))
        await proc.stdin.drain()
        td_result = await asyncio.wait_for(_recv_ack(proc.stdout), timeout=_TIMEOUT)
        assert td_result == {"ok": True}

        # SHUTDOWN
        shutdown_msg = ShutdownMessage(id=new_id())
        proc.stdin.write(_encode(shutdown_msg))
        await proc.stdin.drain()
        await asyncio.wait_for(_recv_ack(proc.stdout), timeout=_TIMEOUT)

        await asyncio.wait_for(proc.wait(), timeout=5.0)
        assert proc.returncode == 0
    finally:
        try:
            proc.stdin.close()  # type: ignore[union-attr]
        except Exception:
            pass
