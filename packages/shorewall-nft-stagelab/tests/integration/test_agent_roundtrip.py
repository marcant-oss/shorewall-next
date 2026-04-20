"""Integration tests for the agent roundtrip (stdin/stdout pipes, no root needed).

These tests spawn the agent as a plain subprocess and exercise PING and
SHUTDOWN only — handlers that require no root privileges.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time

# ── Helpers ───────────────────────────────────────────────────────────────────


def _send(proc: subprocess.Popen, msg: dict) -> None:
    """Write one JSON line to the subprocess stdin."""
    line = json.dumps(msg) + "\n"
    proc.stdin.write(line.encode())
    proc.stdin.flush()


def _recv(proc: subprocess.Popen, timeout: float = 5.0) -> dict:
    """Read one JSON line from the subprocess stdout, with timeout."""
    # Use a deadline loop so we don't block indefinitely.
    deadline = time.monotonic() + timeout
    buf = b""
    while time.monotonic() < deadline:
        proc.stdout.fileno()  # ensure non-blocking FD
        ch = proc.stdout.read(1)
        if not ch:
            raise EOFError("agent closed stdout before sending a response")
        buf += ch
        if buf.endswith(b"\n"):
            return json.loads(buf.strip())
    raise TimeoutError("no response within timeout")


def _spawn_agent() -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "shorewall_nft_stagelab.agent", "--host-name", "t1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_agent_ping_ack() -> None:
    """Agent responds with ACK(reply_to=ping_id) to a PING, then exits on SHUTDOWN."""
    proc = _spawn_agent()
    try:
        ping_id = "test-ping-001"
        _send(proc, {"type": "PING", "id": ping_id, "version": "1"})
        ack = _recv(proc, timeout=5.0)
        assert ack["type"] == "ACK", f"expected ACK, got {ack!r}"
        assert ack["reply_to"] == ping_id, f"reply_to mismatch: {ack!r}"

        shutdown_id = "test-shutdown-001"
        _send(proc, {"type": "SHUTDOWN", "id": shutdown_id, "version": "1"})
        shutdown_ack = _recv(proc, timeout=5.0)
        assert shutdown_ack["type"] == "ACK"
        assert shutdown_ack["reply_to"] == shutdown_id

        proc.stdin.close()
        rc = proc.wait(timeout=5.0)
        assert rc == 0, f"agent exited with code {rc}"
    finally:
        proc.kill()
        proc.wait()


def test_agent_unknown_type_errors() -> None:
    """Agent sends ERROR for an unknown message type, then exits cleanly on SHUTDOWN."""
    proc = _spawn_agent()
    try:
        _send(proc, {"type": "NOTHING", "id": "x", "version": "1"})
        resp = _recv(proc, timeout=5.0)
        assert resp["type"] == "ERROR", f"expected ERROR, got {resp!r}"
        assert resp["reply_to"] == "x", f"reply_to mismatch: {resp!r}"

        _send(proc, {"type": "SHUTDOWN", "id": "s1", "version": "1"})
        ack = _recv(proc, timeout=5.0)
        assert ack["type"] == "ACK"

        proc.stdin.close()
        rc = proc.wait(timeout=5.0)
        assert rc == 0, f"agent exited with code {rc}"
    finally:
        proc.kill()
        proc.wait()


def test_agent_exits_on_eof() -> None:
    """Agent exits 0 when stdin is closed immediately (clean EOF)."""
    proc = _spawn_agent()
    try:
        proc.stdin.close()
        rc = proc.wait(timeout=3.0)
        assert rc == 0, f"agent exited with code {rc}"
    finally:
        proc.kill()
        proc.wait()
