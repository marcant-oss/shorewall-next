"""DEPRECATED — tcpkali wrapper kept for back-compat only.

New code should use `trafgen_pyconn` (pure-Python asyncio). tcpkali is
no longer a required external dependency. If tcpkali is present on the
testhost, this module still works — but no scenario handler selects it
by default.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TcpkaliSpec:
    target: str                    # "host:port" — server to connect to
    bind: str = ""                 # optional source IP
    connections: int = 1000        # -c
    connect_rate: int = 100        # -r, new connections per second
    duration_s: int = 30           # -T
    message_rate: int = 0          # -m per-connection msg/s (0 = default)
    message_size_b: int = 0        # -s (0 = default)


@dataclass(frozen=True)
class TcpkaliResult:
    tool: str                      # "tcpkali"
    ok: bool
    duration_s: float
    connections_established: int
    connections_failed: int
    traffic_bits_per_sec: float    # aggregate throughput
    raw: dict = field(compare=False)  # parsed stdout summary


# ── Bandwidth unit conversion ─────────────────────────────────────────────────

_BW_UNITS: dict[str, float] = {
    "gbps": 1e9,
    "mbps": 1e6,
    "kbps": 1e3,
    "bps": 1.0,
}

_RE_BANDWIDTH = re.compile(
    r"Bandwidth:\s*([\d.]+)\s*(Gbps|Mbps|Kbps|bps)"
    r".*?([\d.]+)\s*(Gbps|Mbps|Kbps|bps)",
    re.IGNORECASE,
)
_RE_CONNECTIONS = re.compile(
    r"Connections:\s*(\d+)/\d+\s+established,\s*(\d+)\s+failed",
    re.IGNORECASE,
)
_RE_DURATION = re.compile(
    r"Test duration:\s*([\d.]+)\s*s",
    re.IGNORECASE,
)


def _to_bps(value: float, unit: str) -> float:
    return value * _BW_UNITS.get(unit.lower(), 1.0)


# ── Public API ────────────────────────────────────────────────────────────────


def build_argv(spec: TcpkaliSpec) -> list[str]:
    """Translate spec → tcpkali argv."""
    argv = [
        "tcpkali",
        "-c", str(spec.connections),
        "-r", str(spec.connect_rate),
        "-T", str(spec.duration_s),
    ]
    if spec.bind:
        argv += ["--source-ip", spec.bind]
    if spec.message_rate:
        argv += ["-m", str(spec.message_rate)]
    if spec.message_size_b:
        argv += ["-s", str(spec.message_size_b)]
    argv.append(spec.target)
    return argv


def parse_stdout(stdout: str) -> TcpkaliResult:
    """Pure parser — extract connections, bandwidth, duration from tcpkali stdout."""
    raw: dict = {}

    # Connections line is required for ok=True
    conn_match = _RE_CONNECTIONS.search(stdout)
    if not conn_match:
        return TcpkaliResult(
            tool="tcpkali",
            ok=False,
            duration_s=0.0,
            connections_established=0,
            connections_failed=0,
            traffic_bits_per_sec=0.0,
            raw=raw,
        )

    connections_established = int(conn_match.group(1))
    connections_failed = int(conn_match.group(2))
    raw["connections_established"] = connections_established
    raw["connections_failed"] = connections_failed

    # Bandwidth
    traffic_bps = 0.0
    bw_match = _RE_BANDWIDTH.search(stdout)
    if bw_match:
        up_val = float(bw_match.group(1))
        up_unit = bw_match.group(2)
        down_val = float(bw_match.group(3))
        down_unit = bw_match.group(4)
        traffic_bps = _to_bps(up_val, up_unit) + _to_bps(down_val, down_unit)
        raw["bandwidth_up"] = f"{up_val} {up_unit}"
        raw["bandwidth_down"] = f"{down_val} {down_unit}"

    # Duration
    duration_s = 0.0
    dur_match = _RE_DURATION.search(stdout)
    if dur_match:
        duration_s = float(dur_match.group(1))
        raw["duration_s"] = duration_s

    return TcpkaliResult(
        tool="tcpkali",
        ok=True,
        duration_s=duration_s,
        connections_established=connections_established,
        connections_failed=connections_failed,
        traffic_bits_per_sec=traffic_bps,
        raw=raw,
    )


def run_tcpkali(spec: TcpkaliSpec, timeout_s: int | None = None) -> TcpkaliResult:
    """Execute tcpkali, capture stdout, parse, return TcpkaliResult.

    Raises RuntimeError if rc != 0 and stdout has no parseable summary.
    """
    argv = build_argv(spec)

    try:
        proc = subprocess.run(
            argv,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"tcpkali timed out after {timeout_s}s") from exc

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    rc = proc.returncode

    result = parse_stdout(stdout)
    if rc != 0 and not result.ok:
        raise RuntimeError(stderr[:500] or f"tcpkali exited with rc={rc}")
    return result
