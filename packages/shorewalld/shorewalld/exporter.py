"""Prometheus collectors for shorewalld.

Four collectors that share a per-netns label:

* ``NftCollector`` — walks the ``inet shorewall`` ruleset with a single
  libnftables ``list table`` round-trip and emits per-rule packet/byte
  counters + named counter objects + set-element gauges.
* ``LinkCollector`` — pyroute2 ``IPRoute(netns=...).get_links()`` dump
  for the full ``IFLA_STATS64`` surface (RX/TX packets/bytes/errors/
  dropped, multicast, collisions, and the detailed RX/TX sub-counters)
  plus oper state.
* ``QdiscCollector`` — pyroute2 ``get_qdiscs()`` dump for per-qdisc
  bytes/packets/drops/requeues/overlimits + qlen/backlog gauges, plus
  the rate-estimator bps/pps (populated only for qdiscs configured
  with ``est``).
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


# Every field kernel ``rtnl_link_stats64`` exposes that we surface as
# its own prometheus metric. Order is the kernel struct order so the
# scraped output reads naturally top-to-bottom.
#
# ``rx_nohandler`` was added in kernel 4.6 and is not decoded by every
# pyroute2 version — ``dict.get(key)`` returns ``None`` when absent
# and we skip the sample instead of emitting a misleading zero.
_LINK_STAT_FIELDS: list[tuple[str, str, str]] = [
    # (kernel_key, metric_name, help_text)
    ("rx_packets", "shorewall_nft_iface_rx_packets_total",
     "Interface RX packets"),
    ("rx_bytes", "shorewall_nft_iface_rx_bytes_total",
     "Interface RX bytes"),
    ("tx_packets", "shorewall_nft_iface_tx_packets_total",
     "Interface TX packets"),
    ("tx_bytes", "shorewall_nft_iface_tx_bytes_total",
     "Interface TX bytes"),
    ("rx_errors", "shorewall_nft_iface_rx_errors_total",
     "Interface RX errors (generic total)"),
    ("tx_errors", "shorewall_nft_iface_tx_errors_total",
     "Interface TX errors (generic total)"),
    ("rx_dropped", "shorewall_nft_iface_rx_dropped_total",
     "Interface RX dropped packets"),
    ("tx_dropped", "shorewall_nft_iface_tx_dropped_total",
     "Interface TX dropped packets"),
    ("multicast", "shorewall_nft_iface_multicast_total",
     "Interface multicast packets received"),
    ("collisions", "shorewall_nft_iface_collisions_total",
     "Interface collisions"),
    ("rx_length_errors", "shorewall_nft_iface_rx_length_errors_total",
     "RX length errors"),
    ("rx_over_errors", "shorewall_nft_iface_rx_over_errors_total",
     "RX over errors (frame larger than the NIC buffer)"),
    ("rx_crc_errors", "shorewall_nft_iface_rx_crc_errors_total",
     "RX CRC errors (cable/SFP integrity)"),
    ("rx_frame_errors", "shorewall_nft_iface_rx_frame_errors_total",
     "RX frame alignment errors"),
    ("rx_fifo_errors", "shorewall_nft_iface_rx_fifo_errors_total",
     "RX FIFO errors"),
    ("rx_missed_errors", "shorewall_nft_iface_rx_missed_errors_total",
     "RX NIC ring-buffer overruns (packets the driver never saw)"),
    ("tx_aborted_errors", "shorewall_nft_iface_tx_aborted_errors_total",
     "TX aborted errors"),
    ("tx_carrier_errors", "shorewall_nft_iface_tx_carrier_errors_total",
     "TX carrier-lost errors"),
    ("tx_fifo_errors", "shorewall_nft_iface_tx_fifo_errors_total",
     "TX FIFO errors"),
    ("tx_heartbeat_errors", "shorewall_nft_iface_tx_heartbeat_errors_total",
     "TX heartbeat errors"),
    ("tx_window_errors", "shorewall_nft_iface_tx_window_errors_total",
     "TX window errors"),
    ("rx_compressed", "shorewall_nft_iface_rx_compressed_total",
     "RX compressed packets"),
    ("tx_compressed", "shorewall_nft_iface_tx_compressed_total",
     "TX compressed packets"),
    ("rx_nohandler", "shorewall_nft_iface_rx_nohandler_total",
     "RX packets dropped because no protocol handler was registered"),
]


class LinkCollector(CollectorBase):
    """Per-interface ``IFLA_STATS64`` + oper state via pyroute2.

    Opens a fresh ``IPRoute(netns=…)`` per scrape because the socket
    must live in the target netns. For ``netns=""`` we use the
    daemon's own netns (no argument).

    One ``get_links()`` dump per scrape feeds every metric in
    :data:`_LINK_STAT_FIELDS` — no extra netlink round-trips for the
    expanded counter surface.
    """

    def collect(self) -> list[_MetricFamily]:
        families: dict[str, _MetricFamily] = {
            name: _MetricFamily(name, help_text, ["netns", "iface"],
                                mtype="counter")
            for _, name, help_text in _LINK_STAT_FIELDS
        }
        oper = _MetricFamily(
            "shorewall_nft_iface_oper_state",
            "Interface operational state (1=UP, 0=DOWN, 0.5=UNKNOWN)",
            ["netns", "iface"])

        def _all() -> list[_MetricFamily]:
            return [*families.values(), oper]

        try:
            from pyroute2 import IPRoute  # type: ignore[import-untyped]
        except ImportError:
            return _all()

        kwargs = {"netns": self.netns} if self.netns else {}
        try:
            ipr = IPRoute(**kwargs)
        except Exception:
            return _all()
        try:
            links = ipr.get_links()
        except Exception:
            return _all()
        finally:
            try:
                ipr.close()
            except Exception:
                pass

        oper_map = {"UP": 1.0, "DOWN": 0.0}

        for link in links:
            name = link.get_attr("IFLA_IFNAME") or ""
            stats = link.get_attr("IFLA_STATS64") or link.get_attr("IFLA_STATS")
            if isinstance(stats, dict):
                for kernel_key, metric_name, _help in _LINK_STAT_FIELDS:
                    val = stats.get(kernel_key)
                    if val is None:
                        continue
                    families[metric_name].add(
                        [self.netns, name], float(val))
            state = link.get_attr("IFLA_OPERSTATE") or ""
            oper.add([self.netns, name], oper_map.get(state, 0.5))

        return _all()


# ── Qdisc collector ──────────────────────────────────────────────────


def _format_tc_handle(raw: int) -> str:
    """Render a u32 tc handle as ``major:minor`` hex, or a reserved name.

    ``0xffffffff`` is ``TC_H_ROOT`` (used as the parent of a root
    qdisc). ``0`` means unspecified — typically the ingress/clsact
    root. Both get a human-readable placeholder instead of an opaque
    hex blob that would bloat Prometheus labels.
    """
    if raw == 0xFFFFFFFF:
        return "root"
    if raw == 0:
        return "none"
    major = (raw >> 16) & 0xFFFF
    minor = raw & 0xFFFF
    return f"{major:x}:{minor:x}"


# Qdisc metric families: one per semantic counter/gauge. Counter-typed
# unless the kernel value is inherently a current depth (qlen/backlog)
# or an instantaneous rate (bps/pps from the rate estimator).
_QDISC_LABELS = ["netns", "iface", "kind", "handle", "parent"]
_QDISC_FIELDS: list[tuple[str, str, str, str]] = [
    # (bucket_key, metric_name, mtype, help_text)
    ("bytes", "shorewall_nft_qdisc_bytes_total", "counter",
     "Qdisc TX bytes"),
    ("packets", "shorewall_nft_qdisc_packets_total", "counter",
     "Qdisc TX packets"),
    ("drops", "shorewall_nft_qdisc_drops_total", "counter",
     "Qdisc dropped packets (overflow + policing)"),
    ("requeues", "shorewall_nft_qdisc_requeues_total", "counter",
     "Qdisc requeued packets (driver pushback)"),
    ("overlimits", "shorewall_nft_qdisc_overlimits_total", "counter",
     "Qdisc overlimit events (rate/class ceiling hits)"),
    ("qlen", "shorewall_nft_qdisc_qlen", "gauge",
     "Current qdisc queue length in packets"),
    ("backlog", "shorewall_nft_qdisc_backlog_bytes", "gauge",
     "Current qdisc backlog in bytes"),
    ("bps", "shorewall_nft_qdisc_rate_bps", "gauge",
     "Qdisc rate estimator bytes/s (0 if no estimator configured)"),
    ("pps", "shorewall_nft_qdisc_rate_pps", "gauge",
     "Qdisc rate estimator packets/s (0 if no estimator configured)"),
]


def _extract_qdisc_row(qdisc: Any,
                       idx_to_name: dict[int, str]) -> tuple[list[str],
                                                             dict[str, int]]:
    """Parse one pyroute2 qdisc message into (labels, stats-dict).

    Prefers the nested ``TCA_STATS2`` (modern kernels, carries
    ``requeues``) and fills in ``bps``/``pps`` from legacy
    ``TCA_STATS`` since the rate estimator only shows up there.
    Every missing field defaults to ``0`` — callers decide whether
    to emit it.

    Pure function — no netlink I/O — so the test suite can exercise
    the attribute shapes without a live socket.
    """
    ifindex = qdisc.get("index", 0) if isinstance(qdisc, dict) else \
        getattr(qdisc, "get", lambda *_a, **_k: 0)("index", 0)
    # pyroute2's tcmsg supports both ``.get(key)`` and dict subscript.
    try:
        handle_raw = qdisc.get("handle", 0)
        parent_raw = qdisc.get("parent", 0)
    except AttributeError:
        handle_raw = parent_raw = 0

    kind = qdisc.get_attr("TCA_KIND") or "unknown"
    iface = idx_to_name.get(ifindex, f"ifindex{ifindex}")
    labels_suffix = [
        iface,
        kind,
        _format_tc_handle(int(handle_raw)),
        _format_tc_handle(int(parent_raw)),
    ]

    stats: dict[str, int] = {
        "bytes": 0, "packets": 0, "drops": 0, "requeues": 0,
        "overlimits": 0, "qlen": 0, "backlog": 0, "bps": 0, "pps": 0,
    }

    s2 = qdisc.get_attr("TCA_STATS2")
    if s2 is not None and hasattr(s2, "get_attr"):
        basic = s2.get_attr("TCA_STATS_BASIC")
        queue = s2.get_attr("TCA_STATS_QUEUE")
        if isinstance(basic, dict):
            stats["bytes"] = int(basic.get("bytes", 0))
            stats["packets"] = int(basic.get("packets", 0))
        if isinstance(queue, dict):
            stats["drops"] = int(queue.get("drops", 0))
            stats["requeues"] = int(queue.get("requeues", 0))
            stats["overlimits"] = int(queue.get("overlimits", 0))
            stats["qlen"] = int(queue.get("qlen", 0))
            stats["backlog"] = int(queue.get("backlog", 0))

    s1 = qdisc.get_attr("TCA_STATS")
    if isinstance(s1, dict):
        if stats["bytes"] == 0:
            stats["bytes"] = int(s1.get("bytes", 0))
        if stats["packets"] == 0:
            stats["packets"] = int(s1.get("packets", 0))
        # TCA_STATS uses the singular key ``drop``.
        if stats["drops"] == 0:
            stats["drops"] = int(s1.get("drop", 0))
        if stats["overlimits"] == 0:
            stats["overlimits"] = int(s1.get("overlimits", 0))
        if stats["qlen"] == 0:
            stats["qlen"] = int(s1.get("qlen", 0))
        if stats["backlog"] == 0:
            stats["backlog"] = int(s1.get("backlog", 0))
        # bps/pps live only in the legacy flat stats.
        stats["bps"] = int(s1.get("bps", 0))
        stats["pps"] = int(s1.get("pps", 0))

    return labels_suffix, stats


class QdiscCollector(CollectorBase):
    """Per-qdisc stats via ``RTM_GETQDISC`` netlink dump.

    Two dumps per scrape per netns: ``get_links()`` to build
    ``ifindex → ifname``, then ``get_qdiscs()``. Both are cheap (the
    same pair ``tc -s qdisc`` issues). No forks, no shell-outs.
    """

    def collect(self) -> list[_MetricFamily]:
        families: dict[str, _MetricFamily] = {
            name: _MetricFamily(name, help_text, _QDISC_LABELS, mtype=mtype)
            for _, name, mtype, help_text in _QDISC_FIELDS
        }

        def _all() -> list[_MetricFamily]:
            return list(families.values())

        try:
            from pyroute2 import IPRoute  # type: ignore[import-untyped]
        except ImportError:
            return _all()

        kwargs = {"netns": self.netns} if self.netns else {}
        try:
            ipr = IPRoute(**kwargs)
        except Exception:
            return _all()
        try:
            links = ipr.get_links()
            qdiscs = ipr.get_qdiscs()
        except Exception:
            return _all()
        finally:
            try:
                ipr.close()
            except Exception:
                pass

        idx_to_name: dict[int, str] = {}
        for link in links:
            ifname = link.get_attr("IFLA_IFNAME")
            if ifname is not None:
                idx_to_name[int(link.get("index", 0))] = ifname

        for q in qdiscs:
            suffix, stats = _extract_qdisc_row(q, idx_to_name)
            labels = [self.netns, *suffix]
            for bucket_key, metric_name, _mtype, _help in _QDISC_FIELDS:
                families[metric_name].add(labels, float(stats[bucket_key]))

        return _all()


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
