"""iperf3 wrapper: launch, monitor, parse JSON output for throughput measurements."""

from __future__ import annotations

import json
import statistics
import subprocess
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Iperf3Spec:
    mode: str              # "client" | "server"
    bind: str              # IP to bind (server) or connect-from (client)
    # Client-only fields (ignored for server):
    server_ip: str = ""    # where to connect
    duration_s: int = 10
    parallel: int = 1
    proto: str = "tcp"     # "tcp" | "udp"
    family: str = "ipv4"   # "ipv4" | "ipv6"
    udp_bandwidth_mbps: int = 0  # only for udp; 0 = unlimited
    port: int = 5201


@dataclass(frozen=True)
class TrafGenResult:
    tool: str              # "iperf3"
    ok: bool
    throughput_gbps: float  # 0.0 for servers / on failure
    retransmits: int
    duration_s: float
    raw: dict = field(compare=False)  # full parsed JSON — trimmed to .end if present
    # Smoothed TCP RTT percentiles (from getsockopt(TCP_INFO) per interval).
    # Not per-packet latency — true per-packet needs tcpdump + correlation.
    # None when measure_latency=False or when RTT samples are absent (UDP, error).
    latency_p50_ms: float | None = None
    latency_p95_ms: float | None = None
    latency_p99_ms: float | None = None


def build_argv(spec: Iperf3Spec) -> list[str]:
    """Translate spec into iperf3 argv. Always include --json."""
    argv = ["iperf3", "--json", "-p", str(spec.port), "-B", spec.bind]
    if spec.family == "ipv6":
        argv.insert(1, "-6")

    if spec.mode == "server":
        argv += ["-s", "--one-off"]
    else:
        argv += [
            "-c", spec.server_ip,
            "-t", str(spec.duration_s),
            "-P", str(spec.parallel),
        ]
        if spec.proto == "udp":
            argv.append("-u")
            if spec.udp_bandwidth_mbps:
                argv += ["-b", f"{spec.udp_bandwidth_mbps}M"]
            else:
                # udp_bandwidth_mbps=0 means unlimited; emit -b 0 explicitly
                # so iperf3 doesn't silently cap at its built-in 1 Mbps default.
                argv += ["-b", "0"]

    return argv


def _compute_rtt_percentiles(
    raw: dict,
) -> tuple[float | None, float | None, float | None]:
    """Extract per-interval RTT samples from iperf3 JSON and compute p50/p95/p99.

    iperf3 reports rtt (smoothed TCP RTT from TCP_INFO) in microseconds under
    intervals[].streams[].rtt.  Returns (p50_ms, p95_ms, p99_ms) or
    (None, None, None) when samples are absent or too few to compute.

    Uses stdlib statistics.quantiles to avoid adding numpy as a dependency.
    """
    samples_us: list[float] = []
    for interval in raw.get("intervals", []):
        for stream in interval.get("streams", []):
            rtt = stream.get("rtt")
            if rtt is not None:
                try:
                    samples_us.append(float(rtt))
                except (TypeError, ValueError):
                    pass

    if len(samples_us) < 2:
        # statistics.quantiles requires at least 2 data points
        return None, None, None

    # statistics.quantiles(data, n=100) returns 99 cut points (the 1st through 99th
    # percentile boundaries).  Index 49 = p50, 94 = p95, 98 = p99.
    qs = statistics.quantiles(samples_us, n=100, method="exclusive")
    p50_ms = qs[49] / 1000.0
    p95_ms = qs[94] / 1000.0
    p99_ms = qs[98] / 1000.0
    return p50_ms, p95_ms, p99_ms


def parse_result(raw_json: str, measure_latency: bool = False) -> TrafGenResult:
    """Pure parser — takes iperf3's JSON stdout, returns TrafGenResult.

    Key extraction:
      raw["end"]["sum_received"]["bits_per_second"] → throughput_gbps (/1e9)
      raw["end"]["sum_sent"]["retransmits"] (tcp only, missing for udp → 0)
      raw["end"]["sum_received"]["seconds"] → duration_s
      If "error" field is present at root → ok=False, throughput 0.0.

    When measure_latency=True, per-interval TCP RTT samples
    (intervals[].streams[].rtt, microseconds) are collected and used to
    compute latency_p50_ms / latency_p95_ms / latency_p99_ms.
    """
    raw = json.loads(raw_json)

    if "error" in raw:
        return TrafGenResult(
            tool="iperf3",
            ok=False,
            throughput_gbps=0.0,
            retransmits=0,
            duration_s=0.0,
            raw=raw,
        )

    end = raw.get("end", {})
    sum_received = end.get("sum_received", {})
    sum_sent = end.get("sum_sent", {})

    throughput_gbps = sum_received.get("bits_per_second", 0.0) / 1e9
    retransmits = sum_sent.get("retransmits", 0)
    duration_s = sum_received.get("seconds", 0.0)

    p50_ms: float | None = None
    p95_ms: float | None = None
    p99_ms: float | None = None
    if measure_latency:
        p50_ms, p95_ms, p99_ms = _compute_rtt_percentiles(raw)

    return TrafGenResult(
        tool="iperf3",
        ok=True,
        throughput_gbps=throughput_gbps,
        retransmits=retransmits,
        duration_s=duration_s,
        raw=end if end else raw,
        latency_p50_ms=p50_ms,
        latency_p95_ms=p95_ms,
        latency_p99_ms=p99_ms,
    )


def run_iperf3(
    spec: Iperf3Spec,
    timeout_s: int | None = None,
    measure_latency: bool = False,
) -> TrafGenResult:
    """Execute iperf3, capture JSON stdout, parse, return TrafGenResult.

    Server mode: Run one-shot (`-s --one-off --json`) for `duration_s` if
    given, else until the first client finishes.  (Iperf3 JSON output for
    server side is generated by --one-off + --json.)

    When measure_latency=True, per-interval TCP RTT samples are extracted and
    latency_p50_ms / latency_p95_ms / latency_p99_ms are populated.

    Raises RuntimeError on subprocess failure (non-zero exit AND no parseable
    JSON). If subprocess exits non-zero but emits a valid JSON error block,
    returns TrafGenResult(ok=False, raw=<json>).
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
        raise RuntimeError(f"iperf3 timed out after {timeout_s}s") from exc

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    rc = proc.returncode

    try:
        return parse_result(stdout, measure_latency=measure_latency)
    except (json.JSONDecodeError, KeyError, TypeError):
        raise RuntimeError(
            f"iperf3 did not emit JSON (exit={rc}): {stderr[:200]}"
        ) from None
