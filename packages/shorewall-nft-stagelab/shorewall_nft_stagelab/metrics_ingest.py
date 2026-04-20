"""External-metrics ingestion: Prometheus scrape + optional SNMP poll.

Used by T15b advisor to correlate DUT-side signals with run windows.
Public API: PrometheusScraper, SNMPScraper, NftSSHScraper, scrape_all,
parse_prometheus_exposition, build_source, PrometheusSource, SNMPSource,
NftSSHSource, MetricSource.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable

from .metrics import MetricRow

if TYPE_CHECKING:
    from .config import SourceSpec

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Source descriptors (lightweight, frozen dataclasses)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrometheusSource:
    name: str
    url: str
    timeout_s: float = 5.0
    metric_prefix_allow: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SNMPSource:
    name: str
    host: str
    community: str
    oids: tuple[str, ...]
    port: int = 161
    timeout_s: float = 3.0


@dataclass(frozen=True)
class NftSSHSource:
    name: str                  # logical tag, e.g. "fw-nft"
    ssh_target: str            # "root@10.0.0.1" — what ssh expects
    timeout_s: float = 10.0
    ssh_opts: tuple[str, ...] = ("-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no")


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class MetricSource(ABC):
    @abstractmethod
    async def scrape(self, ts_unix: float) -> list[MetricRow]:
        """Single-shot scrape; returns rows stamped with ts_unix.

        Implementations may raise on network errors — callers decide
        whether to tolerate failures (log+continue) or abort.
        """


# ---------------------------------------------------------------------------
# Prometheus text-format parser (pure, no I/O)
# ---------------------------------------------------------------------------

# Matches:  name{k="v",...} value [timestamp]
#      or:  name value [timestamp]
_SAMPLE_RE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?P<labels>\{[^}]*\})?\s+'
    r'(?P<value>[^\s]+)(?:\s+\d+)?\s*$'
)
_LABEL_RE = re.compile(r'(\w+)="([^"]*)"')


def parse_prometheus_exposition(
    body: str,
    source_name: str,
    ts_unix: float,
    prefix_allow: tuple[str, ...] = (),
) -> list[MetricRow]:
    """Parse Prometheus text exposition (v0.0.4) into MetricRows.

    For a sample:
        shorewalld_set_size{set="blocked_ips"} 42.0
    emits:
        MetricRow(source="{source_name}:set=blocked_ips",
                  ts_unix=ts_unix, key="shorewalld_set_size", value=42.0)

    Unlabelled samples use source=source_name unchanged.
    If prefix_allow is non-empty, samples whose metric name does not start
    with one of the prefixes are dropped.
    """
    rows: list[MetricRow] = []
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _SAMPLE_RE.match(line)
        if m is None:
            log.debug("metrics_ingest: skipping malformed line: %r", line)
            continue
        name = m.group("name")
        if prefix_allow and not any(name.startswith(p) for p in prefix_allow):
            continue
        raw_value = m.group("value")
        try:
            value = float(raw_value)
        except ValueError:
            log.debug("metrics_ingest: non-numeric value %r on line: %r", raw_value, line)
            continue
        labels_str = m.group("labels") or ""
        if labels_str:
            label_pairs = _LABEL_RE.findall(labels_str)
            label_suffix = ",".join(f"{k}={v}" for k, v in label_pairs)
            source = f"{source_name}:{label_suffix}"
        else:
            source = source_name
        rows.append(MetricRow(source=source, ts_unix=ts_unix, key=name, value=value))
    return rows


# ---------------------------------------------------------------------------
# PrometheusScraper
# ---------------------------------------------------------------------------


class PrometheusScraper(MetricSource):
    def __init__(self, source: PrometheusSource) -> None:
        self._source = source

    async def scrape(self, ts_unix: float) -> list[MetricRow]:
        src = self._source

        def _fetch() -> str:
            import urllib.request  # stdlib only
            with urllib.request.urlopen(src.url, timeout=src.timeout_s) as resp:
                return resp.read().decode("utf-8", errors="replace")

        body = await asyncio.to_thread(_fetch)
        return parse_prometheus_exposition(
            body,
            source_name=src.name,
            ts_unix=ts_unix,
            prefix_allow=src.metric_prefix_allow,
        )


# ---------------------------------------------------------------------------
# NftSSHScraper
# ---------------------------------------------------------------------------


class NftSSHScraper(MetricSource):
    """SSH into fw host, run `nft list counters -j`, emit 3 MetricRows per counter.

    Sources: <name>:packets, <name>:bytes, <name>:counter (duplicate of packets
    for the controller's advisor-aggregation `:counter` filter).
    """

    def __init__(self, source: NftSSHSource) -> None:
        self._source = source

    async def scrape(self, ts_unix: float) -> list[MetricRow]:
        src = self._source

        def _run() -> str:
            return subprocess.run(
                ["ssh", *src.ssh_opts, src.ssh_target, "nft", "list", "counters", "-j"],
                check=True, text=True, capture_output=True, timeout=src.timeout_s,
            ).stdout

        stdout = await asyncio.to_thread(_run)
        rows: list[MetricRow] = []
        for entry in json.loads(stdout).get("nftables", []):
            c = entry.get("counter")
            if c is None:
                continue
            name, pkts, byt = c["name"], float(c["packets"]), float(c["bytes"])
            rows.append(MetricRow(source=f"{src.name}:packets", ts_unix=ts_unix, key=name, value=pkts))
            rows.append(MetricRow(source=f"{src.name}:bytes",   ts_unix=ts_unix, key=name, value=byt))
            rows.append(MetricRow(source=f"{src.name}:counter", ts_unix=ts_unix, key=name, value=pkts))
        return rows


# ---------------------------------------------------------------------------
# SNMPScraper (lazy import of pysnmp — may be absent)
# ---------------------------------------------------------------------------

_PYSNMP_MISSING_MSG = (
    "pysnmp is not installed; install it to enable SNMP scraping. "
    "Run: pip install pysnmp"
)


class SNMPScraper(MetricSource):
    """Best-effort. If pysnmp is not importable, every scrape raises ImportError."""

    def __init__(self, source: SNMPSource) -> None:
        self._source = source

    async def scrape(self, ts_unix: float) -> list[MetricRow]:
        try:
            import importlib
            pysnmp = importlib.import_module("pysnmp")  # noqa: F841
        except ImportError as exc:
            raise ImportError(_PYSNMP_MISSING_MSG) from exc

        # Real implementation would use pysnmp's hlapi here.
        # Deferred to T15b when a live SNMP target exists.
        src = self._source
        log.warning("SNMPScraper: pysnmp available but live polling not yet implemented")
        return []


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_source(spec: "SourceSpec") -> MetricSource:
    """Dispatch on spec.kind → PrometheusScraper / SNMPScraper / NftSSHScraper."""
    if spec.kind == "prometheus":
        return PrometheusScraper(
            PrometheusSource(
                name=spec.name,
                url=spec.url,
                timeout_s=spec.timeout_s,
                metric_prefix_allow=tuple(spec.metric_prefix_allow),
            )
        )
    if spec.kind == "snmp":
        return SNMPScraper(
            SNMPSource(
                name=spec.name,
                host=spec.host,
                community=spec.community,
                oids=tuple(spec.oids),
                port=spec.port,
                timeout_s=spec.timeout_s,
            )
        )
    if spec.kind == "nft_ssh":
        return NftSSHScraper(
            NftSSHSource(
                name=spec.name,
                ssh_target=spec.ssh_target,
                timeout_s=spec.timeout_s,
            )
        )
    raise ValueError(f"Unknown source kind: {spec.kind!r}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Fan-out scrape
# ---------------------------------------------------------------------------


async def scrape_all(
    sources: Iterable[MetricSource],
    ts_unix: float,
    on_error: str = "log",
) -> list[MetricRow]:
    """Fan-out scrape across all sources concurrently.

    on_error in {"log", "raise"}:
      "log"   — a failing source is logged and skipped; others still run.
      "raise" — first exception is re-raised after cancelling remaining tasks.
    """
    source_list = list(sources)
    tasks = [asyncio.create_task(s.scrape(ts_unix)) for s in source_list]
    results: list[MetricRow] = []
    errors: list[BaseException] = []

    for task in asyncio.as_completed(tasks):
        try:
            rows = await task
            results.extend(rows)
        except Exception as exc:  # noqa: BLE001
            if on_error == "raise":
                # Cancel remaining tasks before re-raising
                for t in tasks:
                    t.cancel()
                raise
            log.warning("metrics_ingest: scrape error (on_error=log): %s", exc)
            errors.append(exc)

    return results


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

__all__ = [
    "MetricSource",
    "MetricRow",
    "PrometheusSource",
    "SNMPSource",
    "NftSSHSource",
    "PrometheusScraper",
    "SNMPScraper",
    "NftSSHScraper",
    "build_source",
    "parse_prometheus_exposition",
    "scrape_all",
]
