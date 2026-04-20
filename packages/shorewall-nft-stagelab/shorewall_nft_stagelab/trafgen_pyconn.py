"""Pure-Python asyncio-based TCP connection-burst generator.

Replaces the external tcpkali dependency. Uses asyncio.open_connection for
real TCP 3WHS (so conntrack sees ESTABLISHED entries). Designed for
kernel-mode testhosts (virtio-net realistic cap: ~80-120k new-conn/s).
For line-rate / >1M concurrent sessions, use the DPDK + TRex ASTF path
(conn_storm_astf) instead.

Note on probe-mode endpoints: pyconn opens real TCP connections from the
process network namespace. If the endpoint lives inside a dedicated netns
(native mode), run_pyconn must be executed inside that netns (via
_exec_in_netns or equivalent). For probe-mode TAP endpoints, pyconn does not
inject frames through a TAP — use trafgen_scapy SYN-burst for that path.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class PyConnSpec:
    target: str                   # "host:port"
    connections: int              # total new connections to open
    connect_rate: int             # connections-per-second target
    duration_s: float             # total session duration (hold after connect)
    message_rate: int = 0         # per-conn msg/s after connect (0 = none)
    message_size_b: int = 0       # bytes per message (0 = none)
    bind: str | None = None       # source IP to bind(), optional


@dataclass(frozen=True)
class PyConnResult:
    ok: bool
    established_conns: int
    failed_conns: int
    elapsed_s: float
    connect_rate_observed: float  # established / elapsed
    bytes_sent: int
    error: str | None = None


async def _one_conn(
    host: str,
    port: int,
    hold_s: float,
    msg_rate: int,
    msg_size: int,
    bind: str | None,
) -> tuple[int, int]:
    """Open one TCP connection, optionally send data, return (established, bytes_sent)."""
    try:
        local_addr = (bind, 0) if bind else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, local_addr=local_addr),
            timeout=5.0,
        )
    except (OSError, asyncio.TimeoutError):
        return 0, 0

    bytes_sent = 0
    if msg_rate > 0 and msg_size > 0:
        interval = 1.0 / msg_rate
        deadline = time.monotonic() + hold_s
        buf = b"\x00" * msg_size
        while time.monotonic() < deadline:
            writer.write(buf)
            bytes_sent += msg_size
            try:
                await writer.drain()
            except (OSError, ConnectionResetError):
                break
            await asyncio.sleep(interval)
    else:
        try:
            await asyncio.sleep(hold_s)
        except asyncio.CancelledError:
            pass

    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ConnectionResetError):
        pass
    return 1, bytes_sent


async def run_pyconn_async(spec: PyConnSpec) -> PyConnResult:
    """Async implementation: open spec.connections TCP connections at spec.connect_rate/s."""
    host, port_str = spec.target.rsplit(":", 1)
    port = int(port_str)
    total = spec.connections
    rate = max(1, spec.connect_rate)
    interval = 1.0 / rate

    established = 0
    failed = 0
    bytes_sent_total = 0
    started = time.monotonic()
    tasks: list[asyncio.Task[tuple[int, int]]] = []

    for i in range(total):
        tasks.append(
            asyncio.create_task(
                _one_conn(
                    host,
                    port,
                    spec.duration_s,
                    spec.message_rate,
                    spec.message_size_b,
                    spec.bind,
                )
            )
        )
        # Throttle start-rate to spec.connect_rate conn/s
        target_t = started + (i + 1) * interval
        sleep_s = target_t - time.monotonic()
        if sleep_s > 0:
            await asyncio.sleep(sleep_s)

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            failed += 1
        else:
            est, bs = r
            established += est
            failed += 1 - est
            bytes_sent_total += bs

    elapsed = time.monotonic() - started
    return PyConnResult(
        ok=established > 0,
        established_conns=established,
        failed_conns=failed,
        elapsed_s=elapsed,
        connect_rate_observed=established / elapsed if elapsed > 0 else 0.0,
        bytes_sent=bytes_sent_total,
    )


def run_pyconn(spec: PyConnSpec) -> PyConnResult:
    """Sync wrapper for run_pyconn_async (convenience in tests and agent handlers)."""
    return asyncio.run(run_pyconn_async(spec))
