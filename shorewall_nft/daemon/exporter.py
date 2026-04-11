"""Prometheus collectors for shorewalld.

Three collectors that share a per-netns label:

* ``NftCollector`` — walks the ``inet shorewall`` ruleset with a single
  libnftables ``list table`` round-trip and emits per-rule packet/byte
  counters + named counter objects + set-element gauges.
* ``LinkCollector`` — pyroute2 ``IPRoute(netns=...).get_links()`` dump
  for per-interface RX/TX and oper state.
* ``CtCollector`` — reads ``/proc/sys/net/netfilter/nf_conntrack_count``
  from inside the target netns (via ``_in_netns`` setns hop) for the
  connection-tracking table size.

Each collector caches its last scrape for ``ttl_s`` seconds so that
Prometheus scraping faster than the cache TTL is amortised to zero
netlink round-trips. The cache is per-netns and per-collector.

prometheus_client is an optional dep (``pip install .[daemon]``); the
module level imports are deferred so importing this file without the
package still works for hand-written unit tests that only need the
``CounterScraper`` logic.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from shorewall_nft.nft.netlink import NftError, NftInterface, _in_netns

log = logging.getLogger("shorewalld.exporter")


# ── Scraper cache ────────────────────────────────────────────────────


@dataclass
class _NftScrapeSnapshot:
    """One netns's most recent ruleset scrape."""
    taken_at: float = 0.0
    rule_counters: list[dict[str, Any]] = field(default_factory=list)
    named_counters: dict[str, dict[str, int]] = field(default_factory=dict)
    sets: dict[str, int] = field(default_factory=dict)
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

        # Set element gauge walk — reuse the same ``data``.
        for item in data.get("nftables", []):
            s = item.get("set")
            if not isinstance(s, dict):
                continue
            name = s.get("name", "")
            elem = s.get("elem") or []
            snap.sets[name] = len(elem)

        # Named counter objects — separate nft call (one round-trip).
        try:
            snap.named_counters = self._nft.list_counters(netns=ns)
        except (NftError, OSError):
            pass

        return snap


# ── Collector interface ──────────────────────────────────────────────


class _MetricFamily:
    """Minimal stand-in for prometheus_client.MetricFamily.

    Kept lightweight so unit tests can exercise ``CollectorBase``
    subclasses without needing prometheus_client installed. The real
    server wraps these in ``GaugeMetricFamily``/``CounterMetricFamily``
    at registration time.
    """

    __slots__ = ("name", "help_text", "labels", "samples", "mtype")

    def __init__(self, name: str, help_text: str, labels: list[str],
                 mtype: str = "gauge") -> None:
        self.name = name
        self.help_text = help_text
        self.labels = labels
        self.mtype = mtype
        self.samples: list[tuple[list[str], float]] = []

    def add(self, label_values: list[str], value: float) -> None:
        self.samples.append((label_values, value))


class CollectorBase:
    """Base class: every collector takes a ``netns`` label for routing."""

    def __init__(self, netns: str) -> None:
        self.netns = netns

    def collect(self) -> list[_MetricFamily]:
        raise NotImplementedError


class NftCollector(CollectorBase):
    """Per-rule + named-counter + set-element metrics for one netns."""

    def __init__(self, netns: str, scraper: NftScraper) -> None:
        super().__init__(netns)
        self._scraper = scraper

    def collect(self) -> list[_MetricFamily]:
        snap = self._scraper.snapshot(self.netns)

        packets = _MetricFamily(
            "shorewall_nft_packets_total",
            "Per-rule packet count in the inet shorewall table",
            ["netns", "table", "chain", "rule_handle", "comment"],
            mtype="counter")
        bytes_ = _MetricFamily(
            "shorewall_nft_bytes_total",
            "Per-rule byte count in the inet shorewall table",
            ["netns", "table", "chain", "rule_handle", "comment"],
            mtype="counter")
        named_pk = _MetricFamily(
            "shorewall_nft_named_counter_packets_total",
            "Named counter object packet count",
            ["netns", "name"],
            mtype="counter")
        named_by = _MetricFamily(
            "shorewall_nft_named_counter_bytes_total",
            "Named counter object byte count",
            ["netns", "name"],
            mtype="counter")
        set_el = _MetricFamily(
            "shorewall_nft_set_elements",
            "Element count of named sets in the inet shorewall table",
            ["netns", "set"])

        if not snap.has_table:
            return [packets, bytes_, named_pk, named_by, set_el]

        for rc in snap.rule_counters:
            labels = [
                self.netns,
                str(rc.get("table", "")),
                str(rc.get("chain", "")),
                str(rc.get("handle", 0)),
                str(rc.get("comment", "")),
            ]
            packets.add(labels, float(rc.get("packets", 0)))
            bytes_.add(labels, float(rc.get("bytes", 0)))

        for name, vals in snap.named_counters.items():
            named_pk.add([self.netns, name], float(vals.get("packets", 0)))
            named_by.add([self.netns, name], float(vals.get("bytes", 0)))

        for name, n in snap.sets.items():
            set_el.add([self.netns, name], float(n))

        return [packets, bytes_, named_pk, named_by, set_el]


class LinkCollector(CollectorBase):
    """Per-interface RX/TX + oper state via pyroute2.

    Opens a fresh ``IPRoute(netns=…)`` per scrape because the socket
    must live in the target netns. For ``netns=""`` we use the
    daemon's own netns (no argument).
    """

    def collect(self) -> list[_MetricFamily]:
        rx_p = _MetricFamily(
            "shorewall_nft_iface_rx_packets_total",
            "Interface RX packets",
            ["netns", "iface"], mtype="counter")
        rx_b = _MetricFamily(
            "shorewall_nft_iface_rx_bytes_total",
            "Interface RX bytes",
            ["netns", "iface"], mtype="counter")
        tx_p = _MetricFamily(
            "shorewall_nft_iface_tx_packets_total",
            "Interface TX packets",
            ["netns", "iface"], mtype="counter")
        tx_b = _MetricFamily(
            "shorewall_nft_iface_tx_bytes_total",
            "Interface TX bytes",
            ["netns", "iface"], mtype="counter")
        oper = _MetricFamily(
            "shorewall_nft_iface_oper_state",
            "Interface operational state (1=UP, 0=DOWN, 0.5=UNKNOWN)",
            ["netns", "iface"])

        try:
            from pyroute2 import IPRoute  # type: ignore[import-untyped]
        except ImportError:
            return [rx_p, rx_b, tx_p, tx_b, oper]

        kwargs = {"netns": self.netns} if self.netns else {}
        try:
            ipr = IPRoute(**kwargs)
        except Exception:
            return [rx_p, rx_b, tx_p, tx_b, oper]
        try:
            links = ipr.get_links()
        except Exception:
            return [rx_p, rx_b, tx_p, tx_b, oper]
        finally:
            try:
                ipr.close()
            except Exception:
                pass

        oper_map = {"UP": 1.0, "DOWN": 0.0}

        for link in links:
            name = link.get_attr("IFLA_IFNAME") or ""
            stats = link.get_attr("IFLA_STATS64") or link.get_attr("IFLA_STATS")
            if stats:
                rx_p.add([self.netns, name], float(stats.get("rx_packets", 0)))
                rx_b.add([self.netns, name], float(stats.get("rx_bytes", 0)))
                tx_p.add([self.netns, name], float(stats.get("tx_packets", 0)))
                tx_b.add([self.netns, name], float(stats.get("tx_bytes", 0)))
            state = link.get_attr("IFLA_OPERSTATE") or ""
            oper.add([self.netns, name], oper_map.get(state, 0.5))

        return [rx_p, rx_b, tx_p, tx_b, oper]


class CtCollector(CollectorBase):
    """Conntrack table size gauge per netns.

    Reads ``/proc/sys/net/netfilter/nf_conntrack_count`` and
    ``nf_conntrack_max`` from inside the target netns via the
    ``_in_netns`` setns hop. Cheap — two small reads per scrape.
    """

    def collect(self) -> list[_MetricFamily]:
        count = _MetricFamily(
            "shorewall_nft_ct_count",
            "Current conntrack table size",
            ["netns"])
        max_ = _MetricFamily(
            "shorewall_nft_ct_max",
            "Conntrack table maximum (sysctl nf_conntrack_max)",
            ["netns"])
        try:
            with _in_netns(self.netns or None):
                cur = self._read_int(
                    "/proc/sys/net/netfilter/nf_conntrack_count")
                mx = self._read_int(
                    "/proc/sys/net/netfilter/nf_conntrack_max")
        except OSError:
            return [count, max_]
        if cur is not None:
            count.add([self.netns], float(cur))
        if mx is not None:
            max_.add([self.netns], float(mx))
        return [count, max_]

    @staticmethod
    def _read_int(path: str) -> int | None:
        try:
            with open(path) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None


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
        )

        out = []
        for fam in self.collect():
            if fam.mtype == "counter":
                mf = CounterMetricFamily(
                    fam.name, fam.help_text, labels=fam.labels)
            else:
                mf = GaugeMetricFamily(
                    fam.name, fam.help_text, labels=fam.labels)
            for label_values, value in fam.samples:
                mf.add_metric(label_values, value)
            out.append(mf)
        return out
