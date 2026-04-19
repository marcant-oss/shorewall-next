"""Prometheus collectors for shorewalld.

The collectors split into three families by how they gather data:

* **nft / libnftables** — :class:`NftCollector` walks the
  ``inet shorewall`` ruleset with one ``list table`` round-trip via the
  shared :class:`NftScraper`, emitting per-rule packet/byte counters,
  named counter objects, set-element gauges and flowtable descriptors.
  :class:`FlowtableCollector` reuses the same scraper.
* **pyroute2** — :class:`LinkCollector` (IFLA_STATS64, oper state,
  carrier transitions, MTU), :class:`QdiscCollector` (tc stats),
  :class:`NeighbourCollector` (ARP/ND cache) and
  :class:`AddressCollector` (configured addresses). These open an
  ``IPRoute(netns=…)`` per scrape — pyroute2 forks internally to bind
  the netlink socket to the target netns.
* **``/proc`` / ``/sys`` readers** — :class:`CtCollector`,
  :class:`SnmpCollector`, :class:`NetstatCollector`,
  :class:`SockstatCollector` and :class:`SoftnetCollector` delegate
  their reads to the nft-worker pinned to the target netns via
  :meth:`WorkerRouter.read_file_sync` /
  :meth:`WorkerRouter.count_lines_sync`. This keeps the scrape thread
  out of ``setns(2)`` and the file read inside the worker that already
  owns the namespace.
  :class:`ConntrackStatsCollector` is the exception: it opens a
  ``NFCTSocket`` via an ``_in_netns`` hop because the netlink socket
  must be bound to the target netns and we don't ship netlink over
  the worker IPC.

Each collector caches its last scrape for ``ttl_s`` seconds (where
applicable) so that Prometheus scraping faster than the cache TTL is
amortised to zero netlink round-trips. The cache is per-netns and
per-collector.

prometheus_client is an optional dep (``pip install .[daemon]``); the
module level imports are deferred so importing this file without the
package still works for hand-written unit tests that only need the
``CounterScraper`` logic.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from shorewall_nft.nft.netlink import NftError, NftInterface, _in_netns

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
    """Per-interface ``IFLA_STATS64`` + oper state + carrier churn + MTU
    via pyroute2.

    Opens a fresh ``IPRoute(netns=…)`` per scrape because the socket
    must live in the target netns. For ``netns=""`` we use the
    daemon's own netns (no argument).

    One ``get_links()`` dump per scrape feeds every metric in
    :data:`_LINK_STAT_FIELDS` plus ``IFLA_CARRIER_CHANGES`` (link
    up/down event count) and ``IFLA_MTU`` (current MTU) — no extra
    netlink round-trips for the expanded counter surface.
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
        carrier_changes = _MetricFamily(
            "shorewall_nft_iface_carrier_changes_total",
            "Interface carrier transitions (link up/down events)",
            ["netns", "iface"], mtype="counter")
        mtu = _MetricFamily(
            "shorewall_nft_iface_mtu",
            "Interface MTU in bytes",
            ["netns", "iface"])

        def _all() -> list[_MetricFamily]:
            return [*families.values(), oper, carrier_changes, mtu]

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

            cc = link.get_attr("IFLA_CARRIER_CHANGES")
            if cc is not None:
                carrier_changes.add([self.netns, name], float(cc))
            mtu_val = link.get_attr("IFLA_MTU")
            if mtu_val is not None:
                mtu.add([self.netns, name], float(mtu_val))

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


# ── Conntrack stats collector ────────────────────────────────────────


# Per-netns conntrack counters summed from the per-CPU CTNETLINK rows.
# Legacy fields (SEARCHED / NEW / DELETE / DELETE_LIST / INSERT) are
# skipped — modern kernels never increment them and surfacing them
# would only confuse alerting rules.
_CT_STAT_FIELDS: list[tuple[str, str, str]] = [
    # (pyroute2 attr, metric name, help text)
    ("CTA_STATS_FOUND", "shorewall_nft_ct_found_total",
     "Conntrack lookups that matched an existing entry"),
    ("CTA_STATS_INVALID", "shorewall_nft_ct_invalid_total",
     "Packets whose state could not be tracked (malformed, bad sequence)"),
    ("CTA_STATS_IGNORE", "shorewall_nft_ct_ignore_total",
     "Packets not subjected to connection tracking"),
    ("CTA_STATS_INSERT_FAILED", "shorewall_nft_ct_insert_failed_total",
     "Conntrack insertions that lost the race with a concurrent flow"),
    ("CTA_STATS_DROP", "shorewall_nft_ct_drop_total",
     "Packets dropped because conntrack table was full"),
    ("CTA_STATS_EARLY_DROP", "shorewall_nft_ct_early_drop_total",
     "Entries evicted early to make room in a full conntrack table"),
    ("CTA_STATS_ERROR", "shorewall_nft_ct_error_total",
     "ICMP errors referring to flows conntrack did not know about"),
    ("CTA_STATS_SEARCH_RESTART", "shorewall_nft_ct_search_restart_total",
     "Hash-chain search restarts (table resize or bucket churn)"),
]


def _sum_ct_stats_cpu(rows: list[Any]) -> dict[str, int]:
    """Sum the per-CPU ``nfct_stats_cpu`` rows into one dict per netns.

    Each row exposes its CTA_STATS_* fields via ``get_attr``. Missing
    fields contribute ``0``. Pure function — no netlink I/O — so the
    test suite can feed it synthetic rows directly.
    """
    totals = {attr: 0 for attr, _name, _help in _CT_STAT_FIELDS}
    for row in rows:
        get = getattr(row, "get_attr", None)
        if get is None:
            continue
        for attr in totals:
            val = get(attr)
            if val is not None:
                totals[attr] += int(val)
    return totals


class ConntrackStatsCollector(CollectorBase):
    """Per-netns conntrack engine counters via ``CTNETLINK``.

    Opens ``NFCTSocket`` *inside* the target netns (setns hop via
    :func:`_in_netns`) because netfilter sockets bind to the calling
    netns at open time — same pattern as :class:`CtCollector`. The
    kernel returns one row per CPU; we sum across CPUs since the
    per-CPU identity is never a stable label for Prometheus.

    Requires ``CAP_NET_ADMIN``. On EPERM / missing pyroute2 / netns
    gone the collector emits the metric families with zero samples
    rather than raising — the registry isolates exceptions anyway,
    but a silent empty is friendlier for unprivileged dev runs.
    """

    def collect(self) -> list[_MetricFamily]:
        families = {
            name: _MetricFamily(name, help_text, ["netns"], mtype="counter")
            for _attr, name, help_text in _CT_STAT_FIELDS
        }

        def _all() -> list[_MetricFamily]:
            return list(families.values())

        try:
            from pyroute2 import NFCTSocket  # type: ignore[import-untyped]
        except ImportError:
            return _all()

        try:
            with _in_netns(self.netns or None):
                sock = NFCTSocket()
                try:
                    rows = sock.stat()
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
        except Exception:
            # EPERM (no CAP_NET_ADMIN), netns gone, pyroute2 NetlinkError
            # — all non-fatal. Return the declared families empty so
            # Prometheus still sees them rather than the metric names
            # disappearing under dropped privileges.
            return _all()

        totals = _sum_ct_stats_cpu(rows)
        for attr, name, _help in _CT_STAT_FIELDS:
            families[name].add([self.netns], float(totals[attr]))
        return _all()


class CtCollector(CollectorBase):
    """Conntrack table gauges + FIB (main) route counts per netns.

    All reads delegate to the nft-worker pinned to the target netns
    (``router.read_file_sync`` / ``count_lines_sync``) so the scrape
    thread never does a ``setns(2)`` hop itself:

    * ``nf_conntrack_count`` / ``nf_conntrack_max`` /
      ``nf_conntrack_buckets`` — table occupancy, ceiling and hash
      bucket count. ``count / buckets`` directly expresses mean
      hash-chain length; a runaway ratio predicts CT lookup cost.
    * ``/proc/net/route`` (IPv4 main) and ``/proc/net/ipv6_route``
      (IPv6 main) — line counts approximate FIB size. A sudden drop
      on ``family="ipv4"`` on a firewall running a BGP session is
      usually the first signal that the session went down. Both files
      go through :meth:`count_lines_sync` because a full-BGP v6 table
      is ~150 MB of text — streaming the line count in the worker
      keeps the payload at 8 bytes regardless of file size.
    """

    def __init__(self, netns: str, router: "_FileReader") -> None:
        super().__init__(netns)
        self._router = router

    def collect(self) -> list[_MetricFamily]:
        count = _MetricFamily(
            "shorewall_nft_ct_count",
            "Current conntrack table size",
            ["netns"])
        max_ = _MetricFamily(
            "shorewall_nft_ct_max",
            "Conntrack table maximum (sysctl nf_conntrack_max)",
            ["netns"])
        buckets = _MetricFamily(
            "shorewall_nft_ct_buckets",
            "Conntrack hash bucket count (sysctl nf_conntrack_buckets)",
            ["netns"])
        fib = _MetricFamily(
            "shorewall_nft_fib_routes",
            "FIB routes in the main routing table (line count of "
            "/proc/net/route resp. /proc/net/ipv6_route)",
            ["netns", "family"])

        cur = _read_int_via_router(
            self._router, self.netns,
            "/proc/sys/net/netfilter/nf_conntrack_count")
        mx = _read_int_via_router(
            self._router, self.netns,
            "/proc/sys/net/netfilter/nf_conntrack_max")
        bk = _read_int_via_router(
            self._router, self.netns,
            "/proc/sys/net/netfilter/nf_conntrack_buckets")
        # /proc/net/route has a one-line header; ipv6_route has none.
        v4 = self._router.count_lines_sync(self.netns, "/proc/net/route")
        if v4 is not None and v4 > 0:
            v4 -= 1
        v6 = self._router.count_lines_sync(
            self.netns, "/proc/net/ipv6_route")

        if cur is not None:
            count.add([self.netns], float(cur))
        if mx is not None:
            max_.add([self.netns], float(mx))
        if bk is not None:
            buckets.add([self.netns], float(bk))
        if v4 is not None:
            fib.add([self.netns, "ipv4"], float(v4))
        if v6 is not None:
            fib.add([self.netns, "ipv6"], float(v6))
        return [count, max_, buckets, fib]


def _read_int_via_router(
    router: "_FileReader", netns: str, path: str,
) -> int | None:
    """Decode a single-integer ``/proc``/``/sys`` file via the router.

    Returns ``None`` when the file is missing, the worker is down or
    the content isn't a valid integer — callers simply skip the
    sample in that case. Shared across the ``/proc``-reading
    collectors to keep the pattern uniform.
    """
    data = router.read_file_sync(netns, path)
    if data is None:
        return None
    try:
        return int(data.strip())
    except ValueError:
        return None


# ── /proc/net/snmp + /proc/net/netstat parser ────────────────────────


def _parse_proc_net_snmp(text: str) -> dict[str, dict[str, int]]:
    """Parse ``/proc/net/snmp`` or ``/proc/net/netstat`` into
    ``{proto: {field: int}}``.

    Both files share the same format: pairs of lines, the first is the
    header with field names, the second carries the values, both
    prefixed by ``Proto:``. Example::

        Ip: Forwarding DefaultTTL InReceives ...
        Ip: 1 64 1234 ...
        Tcp: RtoAlgorithm RtoMin ActiveOpens ...
        Tcp: 1 200 123 ...

    Malformed pairs are skipped silently — the kernel occasionally adds
    new fields between releases, but since header and value lines are
    generated together the number of columns always matches. Pure
    function — no I/O — so unit tests feed it synthetic text.
    """
    out: dict[str, dict[str, int]] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        header = lines[i]
        if ":" not in header:
            # Stray lines (blank, junk, kernel comment) don't tear the
            # stream — just skip one and retry; paired lines always
            # live two apart in a well-formed file.
            i += 1
            continue
        if i + 1 >= len(lines):
            break
        value = lines[i + 1]
        if ":" not in value:
            i += 1
            continue
        i += 2
        h_proto, h_cols = header.split(":", 1)
        v_proto, v_vals = value.split(":", 1)
        if h_proto.strip() != v_proto.strip():
            continue
        cols = h_cols.split()
        vals = v_vals.split()
        block: dict[str, int] = {}
        for key, raw in zip(cols, vals):
            try:
                block[key] = int(raw)
            except ValueError:
                pass
        out[h_proto.strip()] = block
    return out


def _parse_proc_net_snmp6(text: str) -> dict[str, int]:
    """Parse ``/proc/net/snmp6`` (single ``key value`` per line)."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            out[parts[0]] = int(parts[1])
        except ValueError:
            pass
    return out


# Field curation — we intentionally *don't* expose every SNMP counter
# the kernel emits: operators alert on the subset below. Each entry is
# ``(v4_key, v6_key, metric_suffix, mtype, help)`` where ``v6_key`` is
# the corresponding key in ``/proc/net/snmp6`` (prefixed ``Ip6``/``Icmp6``/
# ``Udp6``). The family=ipv4|ipv6 split goes into a Prometheus label.
_SNMP_IP_FIELDS: list[tuple[str, str, str, str, str]] = [
    ("ForwDatagrams", "Ip6OutForwDatagrams", "ip_forwarded_total",
     "counter", "IP packets forwarded to another interface"),
    ("OutNoRoutes", "Ip6OutNoRoutes", "ip_out_no_routes_total",
     "counter", "IP packets dropped: no route to destination"),
    ("InDiscards", "Ip6InDiscards", "ip_in_discards_total",
     "counter", "IP input packets discarded (buffer full etc.)"),
    ("InHdrErrors", "Ip6InHdrErrors", "ip_in_hdr_errors_total",
     "counter", "IP input packets with header errors"),
    ("InAddrErrors", "Ip6InAddrErrors", "ip_in_addr_errors_total",
     "counter", "IP input packets with invalid destination address"),
    ("InDelivers", "Ip6InDelivers", "ip_in_delivers_total",
     "counter", "IP packets delivered to upper layers"),
    ("OutRequests", "Ip6OutRequests", "ip_out_requests_total",
     "counter", "IP output packets requested by upper layers"),
    ("ReasmFails", "Ip6ReasmFails", "ip_reasm_fails_total",
     "counter", "IP reassembly failures"),
]

_SNMP_ICMP_FIELDS: list[tuple[str, str, str, str, str]] = [
    ("InMsgs", "Icmp6InMsgs", "icmp_in_msgs_total",
     "counter", "ICMP messages received"),
    ("OutMsgs", "Icmp6OutMsgs", "icmp_out_msgs_total",
     "counter", "ICMP messages sent"),
    ("InDestUnreachs", "Icmp6InDestUnreachs",
     "icmp_in_dest_unreachs_total", "counter",
     "ICMP destination-unreachable received"),
    ("OutDestUnreachs", "Icmp6OutDestUnreachs",
     "icmp_out_dest_unreachs_total", "counter",
     "ICMP destination-unreachable sent"),
    ("InTimeExcds", "Icmp6InTimeExcds", "icmp_in_time_excds_total",
     "counter", "ICMP time-exceeded received"),
    ("OutTimeExcds", "Icmp6OutTimeExcds", "icmp_out_time_excds_total",
     "counter", "ICMP time-exceeded sent"),
    ("InRedirects", "Icmp6InRedirects", "icmp_in_redirects_total",
     "counter", "ICMP redirects received"),
    ("InEchos", "Icmp6InEchos", "icmp_in_echos_total",
     "counter", "ICMP echo requests received"),
    ("InEchoReps", "Icmp6InEchoReplies", "icmp_in_echo_reps_total",
     "counter", "ICMP echo replies received"),
]

_SNMP_UDP_FIELDS: list[tuple[str, str, str, str, str]] = [
    ("InDatagrams", "Udp6InDatagrams", "udp_in_datagrams_total",
     "counter", "UDP datagrams received"),
    ("NoPorts", "Udp6NoPorts", "udp_no_ports_total",
     "counter", "UDP datagrams to closed port"),
    ("InErrors", "Udp6InErrors", "udp_in_errors_total",
     "counter", "UDP datagrams received with errors"),
    ("OutDatagrams", "Udp6OutDatagrams", "udp_out_datagrams_total",
     "counter", "UDP datagrams sent"),
    ("RcvbufErrors", "Udp6RcvbufErrors", "udp_rcvbuf_errors_total",
     "counter", "UDP dropped: receive buffer full"),
    ("SndbufErrors", "Udp6SndbufErrors", "udp_sndbuf_errors_total",
     "counter", "UDP dropped: send buffer full"),
    ("InCsumErrors", "Udp6InCsumErrors", "udp_in_csum_errors_total",
     "counter", "UDP datagrams with bad checksum"),
]

# TCP lives only in /proc/net/snmp (one counter covers both v4 + v6
# sockets, because the kernel shares the TCP MIB across families).
# No family label.
_SNMP_TCP_FIELDS: list[tuple[str, str, str, str]] = [
    ("CurrEstab", "tcp_curr_estab", "gauge",
     "Current TCP connections in ESTABLISHED or CLOSE_WAIT"),
    ("ActiveOpens", "tcp_active_opens_total", "counter",
     "TCP active connection opens"),
    ("PassiveOpens", "tcp_passive_opens_total", "counter",
     "TCP passive connection opens"),
    ("AttemptFails", "tcp_attempt_fails_total", "counter",
     "TCP connection attempts that failed"),
    ("EstabResets", "tcp_estab_resets_total", "counter",
     "TCP connections reset from ESTABLISHED or CLOSE_WAIT"),
    ("RetransSegs", "tcp_retrans_segs_total", "counter",
     "TCP retransmitted segments"),
    ("InSegs", "tcp_in_segs_total", "counter",
     "TCP segments received"),
    ("OutSegs", "tcp_out_segs_total", "counter",
     "TCP segments sent"),
    ("InErrs", "tcp_in_errs_total", "counter",
     "TCP segments received with errors"),
    ("OutRsts", "tcp_out_rsts_total", "counter",
     "TCP segments sent with RST"),
    ("InCsumErrors", "tcp_in_csum_errors_total", "counter",
     "TCP segments with bad checksum"),
]


class SnmpCollector(CollectorBase):
    """IP/TCP/UDP/ICMP counters from ``/proc/net/snmp`` + ``/proc/net/snmp6``.

    Per scrape: two small file reads delegated to the nft-worker
    pinned to the target netns. The per-protocol SNMP counters are a
    first-class SRE signal on a firewall — ``OutNoRoutes`` and
    ``ForwDatagrams`` summarise forwarding quality, TCP ``RetransSegs``
    and ``InErrs`` catch wire-level trouble ahead of any application
    alarm.

    Every metric family is pre-declared in :meth:`collect` (even when
    the underlying scrape fails) so ``absent()``-based Prometheus
    alerts stay stable across daemon restarts and permission glitches.
    """

    def __init__(self, netns: str, router: "_FileReader") -> None:
        super().__init__(netns)
        self._router = router

    def collect(self) -> list[_MetricFamily]:
        fams: dict[str, _MetricFamily] = {}

        for _v4, _v6, suffix, mtype, help_text in _SNMP_IP_FIELDS:
            name = f"shorewall_nft_{suffix}"
            fams[name] = _MetricFamily(
                name, help_text, ["netns", "family"], mtype=mtype)
        for _v4, _v6, suffix, mtype, help_text in _SNMP_ICMP_FIELDS:
            name = f"shorewall_nft_{suffix}"
            fams[name] = _MetricFamily(
                name, help_text, ["netns", "family"], mtype=mtype)
        for _v4, _v6, suffix, mtype, help_text in _SNMP_UDP_FIELDS:
            name = f"shorewall_nft_{suffix}"
            fams[name] = _MetricFamily(
                name, help_text, ["netns", "family"], mtype=mtype)
        for _v4, suffix, mtype, help_text in _SNMP_TCP_FIELDS:
            name = f"shorewall_nft_{suffix}"
            fams[name] = _MetricFamily(
                name, help_text, ["netns"], mtype=mtype)

        snmp = self._router.read_file_sync(self.netns, "/proc/net/snmp")
        snmp6 = self._router.read_file_sync(
            self.netns, "/proc/net/snmp6")
        v4 = _parse_proc_net_snmp(snmp.decode(
            "utf-8", errors="replace")) if snmp else {}
        v6 = _parse_proc_net_snmp6(snmp6.decode(
            "utf-8", errors="replace")) if snmp6 else {}

        ip4 = v4.get("Ip", {})
        icmp4 = v4.get("Icmp", {})
        udp4 = v4.get("Udp", {})
        tcp4 = v4.get("Tcp", {})

        def _emit(fields, source4, dict_key_suffix, families_with_family):
            for v4_key, v6_key, suffix, _mt, _h in fields:
                fam = fams[f"shorewall_nft_{suffix}"]
                val = source4.get(v4_key)
                if val is not None:
                    fam.add([self.netns, "ipv4"], float(val))
                val6 = v6.get(v6_key)
                if val6 is not None:
                    fam.add([self.netns, "ipv6"], float(val6))

        _emit(_SNMP_IP_FIELDS, ip4, "Ip", True)
        _emit(_SNMP_ICMP_FIELDS, icmp4, "Icmp", True)
        _emit(_SNMP_UDP_FIELDS, udp4, "Udp", True)

        for v4_key, suffix, _mt, _h in _SNMP_TCP_FIELDS:
            val = tcp4.get(v4_key)
            if val is not None:
                fams[f"shorewall_nft_{suffix}"].add(
                    [self.netns], float(val))

        return list(fams.values())


# ── /proc/net/netstat (TcpExt) collector ─────────────────────────────


# Curated TcpExt fields — the subset operators alert on. Full list is
# in linux/include/uapi/linux/snmp.h; adding new ones is a one-line
# change. Every field is a counter.
_TCPEXT_FIELDS: list[tuple[str, str, str]] = [
    # (kernel key, metric suffix, help)
    ("ListenOverflows", "tcpext_listen_overflows_total",
     "TCP SYNs arrived with a full accept queue"),
    ("ListenDrops", "tcpext_listen_drops_total",
     "TCP SYNs dropped (all resource shortages)"),
    ("TCPBacklogDrop", "tcpext_backlog_drop_total",
     "TCP packets dropped because the socket backlog was full"),
    ("TCPTimeouts", "tcpext_timeouts_total",
     "TCP retransmission timeouts fired"),
    ("TCPSynRetrans", "tcpext_syn_retrans_total",
     "TCP SYN retransmissions"),
    ("PruneCalled", "tcpext_prune_called_total",
     "TCP socket memory pruning invocations"),
    ("TCPOFODrop", "tcpext_ofo_drop_total",
     "TCP out-of-order packets dropped"),
    ("TCPAbortOnData", "tcpext_abort_on_data_total",
     "TCP connections aborted while data was pending"),
    ("TCPAbortOnMemory", "tcpext_abort_on_memory_total",
     "TCP connections aborted due to memory pressure"),
    ("TCPRetransFail", "tcpext_retrans_fail_total",
     "TCP retransmission attempts that failed at send time"),
]


class NetstatCollector(CollectorBase):
    """Selected ``TcpExt`` counters from ``/proc/net/netstat``.

    One read per scrape, delegated to the worker. ``ListenOverflows``
    + ``ListenDrops`` directly indicate SYN-flood / accept-queue
    exhaustion; ``TCPBacklogDrop`` catches socket backpressure;
    ``TCPTimeouts`` + ``TCPSynRetrans`` track wire-level packet loss.
    """

    def __init__(self, netns: str, router: "_FileReader") -> None:
        super().__init__(netns)
        self._router = router

    def collect(self) -> list[_MetricFamily]:
        fams: dict[str, _MetricFamily] = {}
        for _k, suffix, help_text in _TCPEXT_FIELDS:
            name = f"shorewall_nft_{suffix}"
            fams[name] = _MetricFamily(
                name, help_text, ["netns"], mtype="counter")

        data = self._router.read_file_sync(
            self.netns, "/proc/net/netstat")
        if not data:
            return list(fams.values())

        blocks = _parse_proc_net_snmp(data.decode(
            "utf-8", errors="replace"))
        tcp_ext = blocks.get("TcpExt", {})
        for key, suffix, _h in _TCPEXT_FIELDS:
            val = tcp_ext.get(key)
            if val is not None:
                fams[f"shorewall_nft_{suffix}"].add(
                    [self.netns], float(val))

        return list(fams.values())


# ── /proc/net/sockstat{,6} parser + collector ────────────────────────


def _parse_proc_net_sockstat(text: str) -> dict[str, dict[str, int]]:
    """Parse ``/proc/net/sockstat`` (or sockstat6) into ``{label: {k: int}}``.

    Line format is ``LABEL: k1 v1 k2 v2 …``. Example::

        TCP: inuse 42 orphan 0 tw 7 alloc 55 mem 23
        UDP: inuse 5 mem 3
    """
    out: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, rest = line.split(":", 1)
        parts = rest.split()
        kv: dict[str, int] = {}
        for i in range(0, len(parts) - 1, 2):
            try:
                kv[parts[i]] = int(parts[i + 1])
            except ValueError:
                pass
        out[label.strip()] = kv
    return out


# Sockstat field table. Each entry maps a (v4-label, v6-label,
# in-file key) to the emitted metric. ``has_family=True`` means the
# same counter exists in both sockstat and sockstat6 — emitted with a
# ``family`` label so Prometheus rules can sum across. ``False`` means
# v4-only (TCP orphan/tw/alloc/mem + the kernel-wide ``sockets_used``
# bucket); no family label for those.
_SOCKSTAT_FIELDS: list[tuple[str, str, str, str, str, bool]] = [
    # (label_v4, label_v6, source key, metric suffix, help, has_family)
    ("TCP", "TCP6", "inuse", "sockstat_tcp_inuse",
     "TCP sockets currently in use", True),
    ("TCP", "", "orphan", "sockstat_tcp_orphan",
     "TCP orphan sockets (no user-space handle)", False),
    ("TCP", "", "tw", "sockstat_tcp_tw",
     "TCP sockets in TIME_WAIT", False),
    ("TCP", "", "alloc", "sockstat_tcp_alloc",
     "TCP sockets allocated", False),
    ("TCP", "", "mem", "sockstat_tcp_mem_pages",
     "TCP memory usage in kernel pages", False),
    ("UDP", "UDP6", "inuse", "sockstat_udp_inuse",
     "UDP sockets currently in use", True),
    ("UDP", "", "mem", "sockstat_udp_mem_pages",
     "UDP memory usage in kernel pages", False),
    ("UDPLITE", "UDPLITE6", "inuse", "sockstat_udplite_inuse",
     "UDP-Lite sockets currently in use", True),
    ("RAW", "RAW6", "inuse", "sockstat_raw_inuse",
     "RAW sockets currently in use", True),
    ("FRAG", "FRAG6", "inuse", "sockstat_frag_inuse",
     "IP fragment reassembly queues", True),
    ("FRAG", "FRAG6", "memory", "sockstat_frag_memory_bytes",
     "IP fragment reassembly memory in bytes", True),
    ("sockets", "", "used", "sockstat_sockets_used",
     "Total sockets used (kernel-wide)", False),
]


class SockstatCollector(CollectorBase):
    """Socket-count gauges from ``/proc/net/sockstat`` +
    ``/proc/net/sockstat6``.

    Two small reads per scrape delegated to the worker. ``tcp_inuse``
    tracks active connection count; ``tcp_tw`` surfaces churn;
    ``tcp_mem_pages`` feeds the kernel ``tcp_mem`` pressure check;
    ``frag_*`` reports reassembly load.
    """

    def __init__(self, netns: str, router: "_FileReader") -> None:
        super().__init__(netns)
        self._router = router

    def collect(self) -> list[_MetricFamily]:
        fams: dict[str, _MetricFamily] = {}
        for _v4, _v6, _key, suffix, help_text, has_family in _SOCKSTAT_FIELDS:
            name = f"shorewall_nft_{suffix}"
            labels = ["netns", "family"] if has_family else ["netns"]
            fams[name] = _MetricFamily(name, help_text, labels)

        s4 = self._router.read_file_sync(
            self.netns, "/proc/net/sockstat")
        s6 = self._router.read_file_sync(
            self.netns, "/proc/net/sockstat6")
        v4 = _parse_proc_net_sockstat(s4.decode(
            "utf-8", errors="replace")) if s4 else {}
        v6 = _parse_proc_net_sockstat(s6.decode(
            "utf-8", errors="replace")) if s6 else {}

        for label_v4, label_v6, key, suffix, _h, has_family in _SOCKSTAT_FIELDS:
            fam = fams[f"shorewall_nft_{suffix}"]
            if label_v4:
                val = v4.get(label_v4, {}).get(key)
                if val is not None:
                    if has_family:
                        fam.add([self.netns, "ipv4"], float(val))
                    else:
                        fam.add([self.netns], float(val))
            if label_v6:
                val = v6.get(label_v6, {}).get(key)
                if val is not None:
                    fam.add([self.netns, "ipv6"], float(val))

        return list(fams.values())


# ── /proc/net/softnet_stat parser + collector ────────────────────────


# Column indices we surface from /proc/net/softnet_stat. Layout is
# kernel-version dependent; these four are stable from 4.x onward.
# New columns added in later kernels (e.g. ``backlog_len`` at col 11)
# are intentionally skipped — their semantics changed across releases
# and we'd rather ship less than risk a misleading metric.
_SOFTNET_FIELDS: list[tuple[int, str, str]] = [
    # (column index, metric suffix, help text)
    (0, "softnet_processed_total",
     "Packets processed by softirq on this CPU"),
    (1, "softnet_dropped_total",
     "Packets dropped because the CPU's input_pkt_queue was full"),
    (2, "softnet_time_squeeze_total",
     "NAPI polls cut short by budget or time on this CPU"),
    (9, "softnet_received_rps_total",
     "Packets received via an RPS inter-CPU IPI on this CPU"),
    (10, "softnet_flow_limit_total",
     "Packets dropped by the flow-limit filter on this CPU"),
]


def _parse_proc_net_softnet_stat(text: str) -> list[list[int]]:
    """Parse ``/proc/net/softnet_stat`` as a list of per-CPU rows.

    Each row is a list of integers decoded from ``%08x`` hex columns.
    Row *i* corresponds to CPU *i* in the kernel's online-CPU order.
    Returns ``[]`` on empty/malformed input. Pure function — no I/O.
    """
    out: list[list[int]] = []
    for line in text.splitlines():
        cols = line.split()
        if not cols:
            continue
        row: list[int] = []
        for c in cols:
            try:
                row.append(int(c, 16))
            except ValueError:
                row.append(0)
        out.append(row)
    return out


class SoftnetCollector(CollectorBase):
    """Per-CPU softirq backlog counters from ``/proc/net/softnet_stat``.

    Cheap — one small read per scrape delegated to the worker. On a
    firewall with uneven IRQ distribution the per-CPU split is the
    only way to see that one CPU is dropping packets while others
    are idle. Metrics carry the zero-based CPU index as label ``cpu``.
    """

    def __init__(self, netns: str, router: "_FileReader") -> None:
        super().__init__(netns)
        self._router = router

    def collect(self) -> list[_MetricFamily]:
        fams: dict[str, _MetricFamily] = {}
        for _idx, suffix, help_text in _SOFTNET_FIELDS:
            name = f"shorewall_nft_{suffix}"
            fams[name] = _MetricFamily(
                name, help_text, ["netns", "cpu"], mtype="counter")

        data = self._router.read_file_sync(
            self.netns, "/proc/net/softnet_stat")
        if not data:
            return list(fams.values())

        rows = _parse_proc_net_softnet_stat(data.decode(
            "utf-8", errors="replace"))
        for cpu_idx, row in enumerate(rows):
            for col_idx, suffix, _h in _SOFTNET_FIELDS:
                if col_idx >= len(row):
                    continue
                fams[f"shorewall_nft_{suffix}"].add(
                    [self.netns, str(cpu_idx)], float(row[col_idx]))
        return list(fams.values())


# ── Neighbour / address collectors (pyroute2) ────────────────────────


# Linux NUD_* bitmask → human name, ordered by priority (most specific
# first). An entry usually has a single bit set, but NUD_NOARP +
# NUD_PERMANENT can combine — we pick the first match, which is the
# one an operator cares about.
_NEIGH_STATE_BITS: list[tuple[int, str]] = [
    (0x80, "permanent"),   # NUD_PERMANENT
    (0x40, "noarp"),       # NUD_NOARP
    (0x20, "failed"),      # NUD_FAILED
    (0x10, "probe"),       # NUD_PROBE
    (0x08, "delay"),       # NUD_DELAY
    (0x04, "stale"),       # NUD_STALE
    (0x02, "reachable"),   # NUD_REACHABLE
    (0x01, "incomplete"),  # NUD_INCOMPLETE
]

# AF_INET / AF_INET6 → short label; shared by neighbour + address
# collectors. Anything else gets rendered as ``af<number>`` so novel
# families don't silently merge.
_AF_NAMES: dict[int, str] = {2: "ipv4", 10: "ipv6"}


def _neigh_state_name(state: int) -> str:
    """Translate a NUD_* bitmask to a single label value."""
    if state == 0:
        return "none"
    for bit, name in _NEIGH_STATE_BITS:
        if state & bit:
            return name
    return "unknown"


class NeighbourCollector(CollectorBase):
    """ARP / ND cache entry counts per ``(iface, family, state)``.

    One ``get_neighbours()`` + ``get_links()`` pair per scrape inside
    the target netns (``IPRoute(netns=…)``). Gateway / next-hop health
    is directly visible — a spike in ``state="failed"`` means the
    next-hop stopped answering.
    """

    def collect(self) -> list[_MetricFamily]:
        count = _MetricFamily(
            "shorewall_nft_neigh_count",
            "Neighbour table entries by state",
            ["netns", "iface", "family", "state"])

        try:
            from pyroute2 import IPRoute  # type: ignore[import-untyped]
        except ImportError:
            return [count]

        kwargs = {"netns": self.netns} if self.netns else {}
        try:
            ipr = IPRoute(**kwargs)
        except Exception:
            return [count]
        try:
            links = ipr.get_links()
            neighs = ipr.get_neighbours()
        except Exception:
            return [count]
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

        counts: dict[tuple[str, str, str], int] = {}
        for n in neighs:
            try:
                ifindex = int(n.get("ifindex", 0))
                family_raw = int(n.get("family", 0))
                state_raw = int(n.get("state", 0))
            except (AttributeError, TypeError, ValueError):
                continue
            iface = idx_to_name.get(ifindex, f"ifindex{ifindex}")
            family = _AF_NAMES.get(family_raw, f"af{family_raw}")
            state = _neigh_state_name(state_raw)
            key = (iface, family, state)
            counts[key] = counts.get(key, 0) + 1

        for (iface, family, state), n in counts.items():
            count.add(
                [self.netns, iface, family, state], float(n))

        return [count]


class AddressCollector(CollectorBase):
    """Counts of configured IP addresses per ``(iface, family)``.

    One ``get_addr()`` + ``get_links()`` dump per scrape inside the
    target netns. A VIP disappearing during a VRRP flap drops this
    gauge from N+1 to N for the affected interface — easier to alert
    on than monitoring each address individually.
    """

    def collect(self) -> list[_MetricFamily]:
        addrs = _MetricFamily(
            "shorewall_nft_addrs",
            "Number of addresses configured on an interface",
            ["netns", "iface", "family"])

        try:
            from pyroute2 import IPRoute  # type: ignore[import-untyped]
        except ImportError:
            return [addrs]

        kwargs = {"netns": self.netns} if self.netns else {}
        try:
            ipr = IPRoute(**kwargs)
        except Exception:
            return [addrs]
        try:
            links = ipr.get_links()
            rows = ipr.get_addr()
        except Exception:
            return [addrs]
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

        counts: dict[tuple[str, str], int] = {}
        for a in rows:
            try:
                ifindex = int(a.get("index", 0))
                family_raw = int(a.get("family", 0))
            except (AttributeError, TypeError, ValueError):
                continue
            iface = idx_to_name.get(ifindex, f"ifindex{ifindex}")
            family = _AF_NAMES.get(family_raw, f"af{family_raw}")
            counts[(iface, family)] = counts.get((iface, family), 0) + 1

        for (iface, family), n in counts.items():
            addrs.add([self.netns, iface, family], float(n))

        return [addrs]


# ── Flowtable collector (reuses NftScraper snapshot) ─────────────────


class FlowtableCollector(CollectorBase):
    """Flowtable existence + attached-device count per netns.

    Extracted from the shared :class:`NftScraper` snapshot — zero extra
    netlink round-trips, since the flowtable walk was folded into the
    same ``list table`` call that drives :class:`NftCollector`.

    Live **flow** counts per flowtable are NOT emitted: libnftables'
    JSON view of a flowtable carries only its definition (hook, prio,
    devices, flags), not the transient flow entries. Operators who
    want flow visibility should alert on
    ``shorewall_nft_flowtable_devices == 0`` (interface detached) and
    on a missing ``shorewall_nft_flowtable_exists`` sample (flowtable
    removed by a faulty reload).
    """

    def __init__(self, netns: str, scraper: NftScraper) -> None:
        super().__init__(netns)
        self._scraper = scraper

    def collect(self) -> list[_MetricFamily]:
        devices = _MetricFamily(
            "shorewall_nft_flowtable_devices",
            "Number of interfaces attached to the flowtable",
            ["netns", "name"])
        exists = _MetricFamily(
            "shorewall_nft_flowtable_exists",
            "1 for every configured flowtable",
            ["netns", "name", "hook"])

        snap = self._scraper.snapshot(self.netns)
        for ft in snap.flowtables:
            name = str(ft.get("name", ""))
            hook = str(ft.get("hook", ""))
            devs = ft.get("devices") or []
            devices.add([self.netns, name], float(len(devs)))
            exists.add([self.netns, name, hook], 1.0)

        return [devices, exists]


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
