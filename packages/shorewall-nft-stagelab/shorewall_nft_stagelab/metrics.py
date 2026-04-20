"""Conntrack, nft-counter, and NIC-stats polling for live metric collection."""

from __future__ import annotations

import csv
import re
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MetricRow:
    source: str       # e.g. "fw-nft-counters-packets", "thx1-enp1s0f0-ethtool"
    ts_unix: float
    key: str          # metric name, e.g. "bytes", "tx_drops", "NET_RX"
    value: float


def poll_nft_counters(ssh_runner: callable) -> list[MetricRow]:
    """Poll `nft list counters` via ssh_runner; return two MetricRows per counter.

    ssh_runner(argv: list[str]) -> str returns stdout.
    Emits one row with source suffix "-packets" and one with "-bytes".
    Expects lines of the form:
        counter <name> { packets N bytes M }
    """
    stdout = ssh_runner(["nft", "list", "counters"])
    rows: list[MetricRow] = []
    ts = time.time()
    # Pattern: counter <name> { packets N bytes M }
    pattern = re.compile(
        r"counter\s+(\S+)\s*\{[^}]*packets\s+(\d+)\s+bytes\s+(\d+)"
    )
    for m in pattern.finditer(stdout):
        name, pkts, byts = m.group(1), int(m.group(2)), int(m.group(3))
        rows.append(MetricRow(
            source="nft-counters-packets",
            ts_unix=ts,
            key=name,
            value=float(pkts),
        ))
        rows.append(MetricRow(
            source="nft-counters-bytes",
            ts_unix=ts,
            key=name,
            value=float(byts),
        ))
    return rows


def poll_conntrack(ssh_runner: callable) -> list[MetricRow]:
    """`conntrack -S` lines like "cpu=0 found=N invalid=M ..."; sum across CPUs.

    Returns one MetricRow per summed key.
    """
    stdout = ssh_runner(["conntrack", "-S"])
    ts = time.time()
    totals: dict[str, int] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Each token is "key=value"; skip "cpu=N" prefix
        for token in line.split():
            if "=" not in token:
                continue
            k, v = token.split("=", 1)
            if k == "cpu":
                continue
            totals[k] = totals.get(k, 0) + int(v)
    return [
        MetricRow(source="conntrack", ts_unix=ts, key=k, value=float(v))
        for k, v in sorted(totals.items())
    ]


def poll_ethtool(ssh_runner: callable, iface: str) -> list[MetricRow]:
    """`ethtool -S <iface>` — one MetricRow per "     key: N" line."""
    stdout = ssh_runner(["ethtool", "-S", iface])
    ts = time.time()
    rows: list[MetricRow] = []
    source = f"{iface}-ethtool"
    # Lines look like "     rx_packets: 12345"
    kv_re = re.compile(r"^\s+(\S+):\s+(\d+)\s*$")
    for line in stdout.splitlines():
        m = kv_re.match(line)
        if m:
            rows.append(MetricRow(
                source=source,
                ts_unix=ts,
                key=m.group(1),
                value=float(m.group(2)),
            ))
    return rows


def poll_softirq(ssh_runner: callable) -> list[MetricRow]:
    """`/proc/softirqs` — emit NET_RX and NET_TX totals across all CPUs."""
    stdout = ssh_runner(["cat", "/proc/softirqs"])
    ts = time.time()
    rows: list[MetricRow] = []
    for line in stdout.splitlines():
        line = line.strip()
        # Header line starts with "CPU"
        if line.startswith("CPU"):
            continue
        parts = line.split()
        if not parts:
            continue
        label = parts[0].rstrip(":")
        if label not in ("NET_RX", "NET_TX"):
            continue
        total = sum(int(x) for x in parts[1:])
        rows.append(MetricRow(
            source="softirq",
            ts_unix=ts,
            key=label,
            value=float(total),
        ))
    return rows


def rows_to_csv(rows: list[MetricRow], path: Path) -> None:
    """Write CSV with header: ts_unix,source,key,value."""
    with path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ts_unix", "source", "key", "value"])
        for r in rows:
            writer.writerow([r.ts_unix, r.source, r.key, r.value])
