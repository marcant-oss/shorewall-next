"""Prometheus scraper + registry for shorewalld.

This module is the shared infrastructure every collector is built on
top of:

* :class:`NftScraper` — one ``list table`` per scrape per netns,
  cached for ``ttl_s`` seconds so faster scrapes amortise to zero
  netlink round-trips.
* :class:`Histogram`, :class:`_MetricFamily` — tiny stand-ins for
  prometheus_client types so collectors + unit tests never require
  the optional ``[daemon]`` dep.
* :class:`CollectorBase` — mixin every collector inherits.
* :class:`ShorewalldRegistry` — merges per-family samples from all
  registered collectors + renders to real prometheus_client types
  when the server subclass calls :meth:`to_prom_families`.

The concrete collectors live under :mod:`shorewalld.collectors` (see
``collectors/__init__.py`` for the full list). This module re-exports
every collector name so existing ``from shorewalld.exporter import
FooCollector`` imports keep working after the split.

Data-source split, at a glance:

* **nft / libnftables** — ``NftCollector`` and ``FlowtableCollector``
  share one :class:`NftScraper` snapshot per scrape.
* **pyroute2** — ``LinkCollector``, ``QdiscCollector``,
  ``NeighbourCollector``, ``AddressCollector`` open an
  ``IPRoute(netns=…)`` per scrape; pyroute2 forks internally to bind
  the socket to the target netns.
* **``/proc`` + ``/sys`` readers** — ``CtCollector``,
  ``SnmpCollector``, ``NetstatCollector``, ``SockstatCollector``,
  ``SoftnetCollector`` route their reads through the nft-worker
  already pinned to the target netns
  (:meth:`WorkerRouter.read_file_sync` / ``count_lines_sync``). No
  ``setns(2)`` on the scrape thread.
* **CTNETLINK** — ``ConntrackStatsCollector`` is the lone exception:
  it keeps a direct ``_in_netns()`` hop because the read RPC doesn't
  proxy ``NFCTSocket`` yet.

prometheus_client is an optional dep (``pip install .[daemon]``); its
imports are deferred so importing this file without the package still
works for hand-written unit tests.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from shorewall_nft.nft.netlink import NftError, NftInterface

log = logging.getLogger("shorewalld.exporter")


class _FileReader(Protocol):
    """Minimal duck type for the router surface the collectors need.

    Accepts either a real :class:`~shorewalld.worker_router.WorkerRouter`
    or any test double that implements ``read_file_sync`` /
    ``count_lines_sync`` with matching signatures. Keeps the collectors
    unit-testable without dragging the whole worker stack into the
    test fixture.
    """

    def read_file_sync(
        self, netns: str, path: str, *, timeout: float = ...,
    ) -> bytes | None: ...

    def count_lines_sync(
        self, netns: str, path: str, *, timeout: float = ...,
    ) -> int | None: ...


# ── Scraper cache ────────────────────────────────────────────────────


@dataclass
class _NftScrapeSnapshot:
    """One netns's most recent ruleset scrape."""
    taken_at: float = 0.0
    rule_counters: list[dict[str, Any]] = field(default_factory=list)
    named_counters: dict[str, dict[str, int]] = field(default_factory=dict)
    sets: dict[str, int] = field(default_factory=dict)
    flowtables: list[dict[str, Any]] = field(default_factory=list)
    has_table: bool = False


class NftScraper:
    """Cached scraper for ``inet shorewall`` per netns.

    A fresh scrape is taken only when the cached snapshot is older
    than ``ttl_s``. Multiple scrape callers within the TTL window
    share the same snapshot without triggering additional netlink
    round-trips.
    """

    def __init__(self, nft: NftInterface, ttl_s: float = 30.0) -> None:
        self._nft = nft
        self._ttl_s = ttl_s
        self._snapshots: dict[str, _NftScrapeSnapshot] = {}

    def snapshot(self, netns: str) -> _NftScrapeSnapshot:
        """Return a recent-enough snapshot for ``netns``.

        ``netns=""`` means the daemon's own namespace.
        """
        now = time.monotonic()
        snap = self._snapshots.get(netns)
        if snap is not None and (now - snap.taken_at) < self._ttl_s:
            return snap

        fresh = self._scrape(netns)
        fresh.taken_at = now
        self._snapshots[netns] = fresh
        return fresh

    def invalidate(self, netns: str | None = None) -> None:
        """Drop the cached snapshot for ``netns`` (or all)."""
        if netns is None:
            self._snapshots.clear()
        else:
            self._snapshots.pop(netns, None)

    def _scrape(self, netns: str) -> _NftScrapeSnapshot:
        """Perform a real scrape. Never raises — returns empty snapshot
        if the table doesn't exist or the netns is gone.

        Single ``list table`` call drives both the rule-counter walk
        and the set-element gauge; that's one netlink round-trip per
        netns per scrape.
        """
        ns = netns or None
        snap = _NftScrapeSnapshot()
        try:
            data = self._nft.list_table(netns=ns)
        except (NftError, OSError):
            return snap
        snap.has_table = True

        # Rule counter walk — same extraction logic as
        # NftInterface.list_rule_counters, but operating on the dict
        # we already have in hand instead of re-issuing the nft call.
        rules: list[dict[str, Any]] = []
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            packets = bytes_ = 0
            found = False
            for expr in rule.get("expr", []):
                c = expr.get("counter") if isinstance(expr, dict) else None
                if isinstance(c, dict):
                    packets += int(c.get("packets", 0))
                    bytes_ += int(c.get("bytes", 0))
                    found = True
            if not found:
                continue
            rules.append({
                "table": rule.get("table", "shorewall"),
                "chain": rule.get("chain", ""),
                "handle": rule.get("handle", 0),
                "comment": rule.get("comment", ""),
                "packets": packets,
                "bytes": bytes_,
            })
        snap.rule_counters = rules

        # Set element gauge + flowtable walks — reuse the same ``data``.
        for item in data.get("nftables", []):
            s = item.get("set")
            if isinstance(s, dict):
                name = s.get("name", "")
                elem = s.get("elem") or []
                snap.sets[name] = len(elem)
                continue
            ft = item.get("flowtable")
            if isinstance(ft, dict):
                # libnftables does not expose the live flow count for a
                # flowtable — only its definition. We record name / hook
                # / prio / attached devices so operators can alert on
                # "no devices attached" or "flowtable disappeared".
                snap.flowtables.append({
                    "name": ft.get("name", ""),
                    "hook": ft.get("hook", ""),
                    "prio": ft.get("prio", ""),
                    "devices": list(ft.get("devices") or []),
                    "flags": list(ft.get("flags") or []),
                })

        # Named counter objects — separate nft call (one round-trip).
        try:
            snap.named_counters = self._nft.list_counters(netns=ns)
        except (NftError, OSError):
            pass

        return snap


# ── Collector interface ──────────────────────────────────────────────


class Histogram:
    """Tiny lock-free histogram for observe-once-per-event hot paths.

    Not a ``prometheus_client.Histogram`` — those carry per-bucket
    Counter objects and thread-locks we don't need inside the single-
    threaded dispatch path. Buckets are cumulative (Prometheus convention):
    ``bucket_counts[i]`` counts every observation ``<= buckets[i]``;
    the final entry is the ``+Inf`` bucket and equals :attr:`count`.

    ``buckets`` must be sorted ascending and NOT include ``+Inf``;
    the class appends its own implicit ``+Inf`` slot.
    """

    __slots__ = ("buckets", "bucket_counts", "sum_value", "count")

    def __init__(self, buckets: list[float]) -> None:
        self.buckets = list(buckets)
        # One extra slot for the implicit +Inf bucket — saves a
        # conditional in observe() at the cost of one int per histogram.
        self.bucket_counts: list[int] = [0] * (len(self.buckets) + 1)
        self.sum_value: float = 0.0
        self.count: int = 0

    def observe(self, value: float) -> None:
        self.sum_value += value
        self.count += 1
        buckets = self.buckets
        counts = self.bucket_counts
        for i, ub in enumerate(buckets):
            if value <= ub:
                counts[i] += 1
        counts[-1] += 1  # +Inf always

    def bucket_samples(self) -> list[tuple[str, float]]:
        """Cumulative ``(upper_bound, count)`` pairs for Prom export.

        Upper bounds are rendered with ``repr`` for fractional values
        (so ``0.005`` stays ``"0.005"``, not ``"5e-3"``) and ``+Inf``
        as the final entry.
        """
        out: list[tuple[str, float]] = []
        for ub, cnt in zip(self.buckets, self.bucket_counts):
            out.append((_fmt_bucket_bound(ub), float(cnt)))
        out.append(("+Inf", float(self.bucket_counts[-1])))
        return out


def _fmt_bucket_bound(ub: float) -> str:
    """Render an upper bound so Prometheus matches human-typed le=…

    ``0.005`` → ``"0.005"`` (not ``"5e-3"``), ``1`` → ``"1"``,
    ``2.5`` → ``"2.5"``. Matches prometheus_client's own formatter.
    """
    if ub == int(ub):
        return f"{int(ub)}"
    return f"{ub!r}"


class _MetricFamily:
    """Minimal stand-in for prometheus_client.MetricFamily.

    Kept lightweight so unit tests can exercise ``CollectorBase``
    subclasses without needing prometheus_client installed. The real
    server wraps these in ``GaugeMetricFamily`` /
    ``CounterMetricFamily`` / ``HistogramMetricFamily`` at
    registration time.

    ``mtype="histogram"`` samples carry a :class:`Histogram` object
    as their value instead of a float, populated via :meth:`add_histogram`.
    """

    __slots__ = ("name", "help_text", "labels", "samples", "mtype")

    def __init__(self, name: str, help_text: str, labels: list[str],
                 mtype: str = "gauge") -> None:
        self.name = name
        self.help_text = help_text
        self.labels = labels
        self.mtype = mtype
        # Values are floats for counter/gauge and Histogram for
        # mtype="histogram". Mixed in one list to keep the merge logic
        # in ShorewalldRegistry.collect() uniform.
        self.samples: list[tuple[list[str], Any]] = []

    def add(self, label_values: list[str], value: float) -> None:
        self.samples.append((label_values, value))

    def add_histogram(
        self, label_values: list[str], hist: "Histogram",
    ) -> None:
        self.samples.append((label_values, hist))


class CollectorBase:
    """Base class: every collector takes a ``netns`` label for routing."""

    def __init__(self, netns: str) -> None:
        self.netns = netns

    def collect(self) -> list[_MetricFamily]:
        raise NotImplementedError


# ── Registry + prometheus_client adapter ─────────────────────────────


class ShorewalldRegistry:
    """Collects from a heterogeneous list of ``CollectorBase`` and
    presents a single ``collect()`` that the prometheus_client server
    subclasses can call.

    One Registry serves N netns profiles. Each profile brings its own
    ``(LinkCollector, CtCollector, [NftCollector])`` triple.
    """

    def __init__(self) -> None:
        self._collectors: list[CollectorBase] = []

    def add(self, collector: CollectorBase) -> None:
        self._collectors.append(collector)

    def remove(self, collector: CollectorBase) -> None:
        try:
            self._collectors.remove(collector)
        except ValueError:
            pass

    def __len__(self) -> int:
        return len(self._collectors)

    def collect(self) -> list[_MetricFamily]:
        """Merge samples from every collector, keyed by metric name."""
        merged: dict[str, _MetricFamily] = {}
        for c in self._collectors:
            try:
                for fam in c.collect():
                    existing = merged.get(fam.name)
                    if existing is None:
                        merged[fam.name] = fam
                    else:
                        existing.samples.extend(fam.samples)
            except Exception:
                log.exception(
                    "collector %s.collect() failed",
                    type(c).__name__)
        return list(merged.values())

    def to_prom_families(self) -> list[Any]:
        """Convert internal families to prometheus_client MetricFamily.

        Deferred import so tests can run without prometheus_client.
        """
        from prometheus_client.core import (  # type: ignore[import-untyped]
            CounterMetricFamily,
            GaugeMetricFamily,
            HistogramMetricFamily,
        )

        out = []
        for fam in self.collect():
            if fam.mtype == "counter":
                mf = CounterMetricFamily(
                    fam.name, fam.help_text, labels=fam.labels)
                for label_values, value in fam.samples:
                    mf.add_metric(label_values, value)
            elif fam.mtype == "histogram":
                mf = HistogramMetricFamily(
                    fam.name, fam.help_text, labels=fam.labels)
                for label_values, hist in fam.samples:
                    mf.add_metric(
                        label_values,
                        hist.bucket_samples(),
                        hist.sum_value,
                    )
            else:
                mf = GaugeMetricFamily(
                    fam.name, fam.help_text, labels=fam.labels)
                for label_values, value in fam.samples:
                    mf.add_metric(label_values, value)
            out.append(mf)
        return out


# ── Back-compat re-exports ──────────────────────────────────────────
#
# Every concrete collector moved to ``shorewalld/collectors/`` in the
# 2026-04 refactor. Existing callers (`from shorewalld.exporter import
# FooCollector`, including tests and ``discover.py``) keep working
# because the names below re-export from the subpackage. New code
# should import from ``shorewalld.collectors`` directly.

from shorewalld.collectors import (  # noqa: E402,F401
    _CT_STAT_FIELDS,
    _LINK_STAT_FIELDS,
    _QDISC_FIELDS,
    _QDISC_LABELS,
    _SNMP_ICMP_FIELDS,
    _SNMP_IP_FIELDS,
    _SNMP_TCP_FIELDS,
    _SNMP_UDP_FIELDS,
    _SOCKSTAT_FIELDS,
    _SOFTNET_FIELDS,
    _TCPEXT_FIELDS,
    AddressCollector,
    ConntrackStatsCollector,
    CtCollector,
    FlowtableCollector,
    LinkCollector,
    NeighbourCollector,
    NetstatCollector,
    NfsetsCollector,
    NftCollector,
    QdiscCollector,
    SnmpCollector,
    SockstatCollector,
    SoftnetCollector,
    VrrpCollector,
    VrrpInstance,
    VrrpSnmpConfig,
    _extract_qdisc_row,
    _format_tc_handle,
    _neigh_state_name,
    _parse_proc_net_snmp,
    _parse_proc_net_snmp6,
    _parse_proc_net_sockstat,
    _parse_proc_net_softnet_stat,
    _sum_ct_stats_cpu,
)
