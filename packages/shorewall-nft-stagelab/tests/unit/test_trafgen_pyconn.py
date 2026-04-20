"""Unit tests for trafgen_pyconn — pure-Python asyncio TCP burst generator."""

from __future__ import annotations

import asyncio
import time

import pytest

from shorewall_nft_stagelab.trafgen_pyconn import PyConnResult, PyConnSpec, run_pyconn

# ---------------------------------------------------------------------------
# Test 1 — dataclass smoke
# ---------------------------------------------------------------------------


def test_pyconnspec_defaults() -> None:
    """PyConnSpec can be constructed with only the required fields."""
    spec = PyConnSpec(
        target="127.0.0.1:8080",
        connections=100,
        connect_rate=50,
        duration_s=2.0,
    )
    assert spec.target == "127.0.0.1:8080"
    assert spec.connections == 100
    assert spec.connect_rate == 50
    assert spec.duration_s == 2.0
    # Optional fields have sensible defaults
    assert spec.message_rate == 0
    assert spec.message_size_b == 0
    assert spec.bind is None


def test_pyconnresult_defaults() -> None:
    """PyConnResult stores all fields and is frozen."""
    r = PyConnResult(
        ok=True,
        established_conns=90,
        failed_conns=10,
        elapsed_s=3.0,
        connect_rate_observed=30.0,
        bytes_sent=0,
    )
    assert r.ok is True
    assert r.established_conns == 90
    assert r.failed_conns == 10
    assert r.elapsed_s == pytest.approx(3.0)
    assert r.connect_rate_observed == pytest.approx(30.0)
    assert r.bytes_sent == 0
    assert r.error is None


# ---------------------------------------------------------------------------
# Test 2 — happy path: real local server, 10 connections
# ---------------------------------------------------------------------------


@pytest.fixture
def local_tcp_server():
    """Start a real asyncio TCP server on a random localhost port, yield port, stop."""
    conns: list[asyncio.StreamWriter] = []

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conns.append(writer)
        try:
            await reader.read(4096)
        except Exception:
            pass
        writer.close()

    async def _start():
        srv = await asyncio.start_server(_handle, "127.0.0.1", 0)
        return srv, srv.sockets[0].getsockname()[1]

    srv, port = asyncio.run(_start())

    async def _stop():
        srv.close()
        await srv.wait_closed()

    yield port

    asyncio.run(_stop())


def test_run_pyconn_happy_path(local_tcp_server: int) -> None:
    """10 connections against a local server all establish successfully."""
    port = local_tcp_server
    spec = PyConnSpec(
        target=f"127.0.0.1:{port}",
        connections=10,
        connect_rate=100,   # fast — no artificial throttle for a 10-conn test
        duration_s=0.1,
    )
    result = run_pyconn(spec)

    assert result.ok is True
    assert result.established_conns == 10
    assert result.failed_conns == 0
    assert result.elapsed_s > 0
    assert result.connect_rate_observed > 0


# ---------------------------------------------------------------------------
# Test 3 — unreachable target: most/all connections fail
# ---------------------------------------------------------------------------


def test_run_pyconn_unreachable_target() -> None:
    """Connections to a port with no listener mostly fail (established < 5)."""
    spec = PyConnSpec(
        target="127.0.0.1:1",   # port 1 — effectively unreachable without root
        connections=5,
        connect_rate=50,
        duration_s=0.1,
    )
    result = run_pyconn(spec)

    # Some or all connections fail; established must be strictly less than 5.
    assert result.established_conns < 5


# ---------------------------------------------------------------------------
# Test 4 — rate limiter: connect_rate=5, connections=10 → elapsed >= 1.5s
# ---------------------------------------------------------------------------


def test_run_pyconn_rate_limiter(local_tcp_server: int) -> None:
    """Rate limiter: 10 connections at 5/s must take at least 1.5 s."""
    port = local_tcp_server
    spec = PyConnSpec(
        target=f"127.0.0.1:{port}",
        connections=10,
        connect_rate=5,    # 5 conn/s → 2 s nominal for 10 conns
        duration_s=0.05,   # short hold; we care about the launch spacing
    )
    t0 = time.monotonic()
    result = run_pyconn(spec)
    elapsed = time.monotonic() - t0

    # At 5 conn/s the 10th launch should fire at t=1.8s; allow 1.5s as floor.
    assert elapsed >= 1.5, f"elapsed={elapsed:.2f}s — rate limiter not working"
    # Also verify connections went through
    assert result.established_conns > 0
