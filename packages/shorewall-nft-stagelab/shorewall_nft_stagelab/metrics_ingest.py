"""External-metrics ingestion: Prometheus scrape + optional SNMP poll."""
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
from .snmp_oids import resolve_bundle

if TYPE_CHECKING:
    from .config import SourceSpec

log = logging.getLogger(__name__)

try:
    from pysnmp.hlapi.asyncio import (  # type: ignore[import-untyped]
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        walk_cmd,
    )
    _HAS_PYSNMP = True
except ImportError:
    _HAS_PYSNMP = False


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
    bundles: tuple[str, ...] = ("node_traffic",)


@dataclass(frozen=True)
class NftSSHSource:
    name: str
    ssh_target: str
    timeout_s: float = 10.0
    ssh_opts: tuple[str, ...] = ("-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no")


class MetricSource(ABC):
    @abstractmethod
    async def scrape(self, ts_unix: float) -> list[MetricRow]: ...


_SAMPLE_RE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?P<labels>\{[^}]*\})?\s+'
    r'(?P<value>[^\s]+)(?:\s+\d+)?\s*$'
)
_LABEL_RE = re.compile(r'(\w+)="([^"]*)"')


def parse_prometheus_exposition(
    body: str, source_name: str, ts_unix: float, prefix_allow: tuple[str, ...] = (),
) -> list[MetricRow]:
    """Parse Prometheus text exposition (v0.0.4) into MetricRows."""
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
            source = f"{source_name}:{','.join(f'{k}={v}' for k, v in _LABEL_RE.findall(labels_str))}"
        else:
            source = source_name
        rows.append(MetricRow(source=source, ts_unix=ts_unix, key=name, value=value))
    return rows


class PrometheusScraper(MetricSource):
    def __init__(self, source: PrometheusSource) -> None:
        self._source = source

    async def scrape(self, ts_unix: float) -> list[MetricRow]:
        src = self._source

        def _fetch() -> str:
            import urllib.request
            with urllib.request.urlopen(src.url, timeout=src.timeout_s) as resp:
                return resp.read().decode("utf-8", errors="replace")

        body = await asyncio.to_thread(_fetch)
        return parse_prometheus_exposition(body, source_name=src.name, ts_unix=ts_unix,
                                           prefix_allow=src.metric_prefix_allow)


class NftSSHScraper(MetricSource):
    """SSH into fw host, run `nft list counters -j`, emit 3 MetricRows per counter."""

    def __init__(self, source: NftSSHSource) -> None:
        self._source = source

    async def scrape(self, ts_unix: float) -> list[MetricRow]:
        src = self._source
        stdout = await asyncio.to_thread(lambda: subprocess.run(
            ["ssh", *src.ssh_opts, src.ssh_target, "nft", "list", "counters", "-j"],
            check=True, text=True, capture_output=True, timeout=src.timeout_s,
        ).stdout)
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


_PYSNMP_MISSING_MSG = "pysnmp not installed — `pip install 'shorewall-nft-stagelab[snmp]'`"
_OID_NAMES: dict[str, str] = {
    "1.3.6.1.2.1.31.1.1.1.6": "if_hc_in_octets", "1.3.6.1.2.1.31.1.1.1.10": "if_hc_out_octets",
    "1.3.6.1.2.1.2.2.1.13": "if_in_discards",    "1.3.6.1.2.1.2.2.1.19": "if_out_discards",
    "1.3.6.1.4.1.2021.10.1.3": "la_load",         "1.3.6.1.2.1.1.3": "sys_uptime",
    "1.3.6.1.4.1.9586.100.5.2.3.1.4": "vrrp_instance_state",
    "1.3.6.1.4.1.9586.100.5.2.3.1.2": "vrrp_instance_name",
    "1.3.6.1.4.1.8072.1.3.2.3.1.2": "pdns_extend_output",
}


def _oid_key(base_oid: str, full_oid: str) -> str:
    lbl = _OID_NAMES.get(base_oid, base_oid.replace(".", "_"))
    sfx = full_oid[len(base_oid):].lstrip(".")
    return f"{lbl}.{sfx}" if sfx else lbl


def _coerce_value(val: object) -> float:
    """SNMP values arrive as pysnmp-typed objects: Counter32/64/Integer (int-castable),
    or DisplayString/OctetString (string-castable, e.g. UCD-SNMP laLoad returns "0.02").
    Try int() first for counters, then float(str()) for string-encoded numerics, then -1.0.
    """
    try:
        return float(int(val))
    except (TypeError, ValueError):
        pass
    try:
        return float(str(val))
    except (TypeError, ValueError):
        return -1.0


class SNMPScraper(MetricSource):
    """Async SNMP walk per bundle OID using pysnmp hlapi.asyncio.walk_cmd."""

    def __init__(self, source: SNMPSource) -> None:
        self._source = source

    async def scrape(self, ts_unix: float) -> list[MetricRow]:
        if not _HAS_PYSNMP:
            raise ImportError(_PYSNMP_MISSING_MSG)
        src = self._source
        rows: list[MetricRow] = []
        engine = SnmpEngine()
        # mpModel=1 = SNMPv2c — required for Counter64 (ifHCInOctets etc.).
        auth = CommunityData(src.community, mpModel=1)
        transport = await UdpTransportTarget.create(
            (src.host, src.port), timeout=src.timeout_s, retries=0,
        )
        ctx = ContextData()
        for bundle_name in src.bundles:
            try:
                oids = resolve_bundle(bundle_name)
            except KeyError:
                log.warning("SNMPScraper: unknown bundle %r — skipping", bundle_name)
                rows.append(MetricRow(source=f"{src.name}:error", ts_unix=ts_unix,
                                      key=bundle_name, value=-1.0))
                continue
            for base_oid in oids:
                try:
                    async for (err_ind, err_status, _idx, var_binds) in walk_cmd(
                        engine, auth, transport, ctx,
                        ObjectType(ObjectIdentity(base_oid)),
                        lexicographicMode=False,
                    ):
                        if err_ind or err_status:
                            log.debug("SNMP err %s: %s", base_oid, err_ind or err_status)
                            rows.append(MetricRow(source=f"{src.name}:error", ts_unix=ts_unix,
                                                  key=bundle_name, value=-1.0))
                            break
                        for oid_obj, val in var_binds:
                            value = _coerce_value(val)
                            rows.append(MetricRow(source=f"{src.name}:{bundle_name}",
                                                  ts_unix=ts_unix,
                                                  key=_oid_key(base_oid, str(oid_obj)),
                                                  value=value))
                except asyncio.TimeoutError:
                    log.debug("SNMP timeout bundle=%s oid=%s", bundle_name, base_oid)
                    rows.append(MetricRow(source=f"{src.name}:error", ts_unix=ts_unix,
                                         key=bundle_name, value=-1.0))
        return rows


def build_source(spec: "SourceSpec") -> MetricSource:
    """Dispatch on spec.kind → PrometheusScraper / SNMPScraper / NftSSHScraper."""
    if spec.kind == "prometheus":
        return PrometheusScraper(PrometheusSource(
            name=spec.name, url=spec.url, timeout_s=spec.timeout_s,
            metric_prefix_allow=tuple(spec.metric_prefix_allow),
        ))
    if spec.kind == "snmp":
        bundles = tuple(getattr(spec, "bundles", None) or ["node_traffic"])
        return SNMPScraper(SNMPSource(
            name=spec.name, host=spec.host, community=spec.community,
            oids=tuple(spec.oids), port=spec.port, timeout_s=spec.timeout_s, bundles=bundles,
        ))
    if spec.kind == "nft_ssh":
        return NftSSHScraper(NftSSHSource(
            name=spec.name, ssh_target=spec.ssh_target, timeout_s=spec.timeout_s,
        ))
    raise ValueError(f"Unknown source kind: {spec.kind!r}")  # pragma: no cover


async def scrape_all(
    sources: Iterable[MetricSource], ts_unix: float, on_error: str = "log",
) -> list[MetricRow]:
    """Fan-out scrape concurrently. on_error in {"log","raise"}."""
    source_list = list(sources)
    tasks = [asyncio.create_task(s.scrape(ts_unix)) for s in source_list]
    results: list[MetricRow] = []
    for task in asyncio.as_completed(tasks):
        try:
            results.extend(await task)
        except Exception as exc:  # noqa: BLE001
            if on_error == "raise":
                for t in tasks:
                    t.cancel()
                raise
            log.warning("metrics_ingest: scrape error (on_error=log): %s", exc)
    return results


__all__ = [
    "MetricSource", "MetricRow",
    "PrometheusSource", "SNMPSource", "NftSSHSource",
    "PrometheusScraper", "SNMPScraper", "NftSSHScraper",
    "build_source", "parse_prometheus_exposition", "scrape_all",
]
