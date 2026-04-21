"""QdiscCollector — per-qdisc stats via ``RTM_GETQDISC`` netlink dump.

Two dumps per scrape per netns: ``get_links()`` to build
``ifindex → ifname``, then ``get_qdiscs()``. Both are cheap (the
same pair ``tc -s qdisc`` issues). No forks, no shell-outs.
"""

from __future__ import annotations

from typing import Any

from shorewalld.exporter import CollectorBase, _MetricFamily

from ._shared import close_rtnl, get_rtnl


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
    """Per-qdisc stats via ``RTM_GETQDISC`` netlink dump."""

    def collect(self) -> list[_MetricFamily]:
        families: dict[str, _MetricFamily] = {
            name: _MetricFamily(name, help_text, _QDISC_LABELS, mtype=mtype)
            for _, name, mtype, help_text in _QDISC_FIELDS
        }

        def _all() -> list[_MetricFamily]:
            return list(families.values())

        try:
            ipr = get_rtnl(self.netns or None)
        except ImportError:
            return _all()
        except Exception:
            return _all()
        try:
            links = ipr.get_links()
            qdiscs = ipr.get_qdiscs()
        except Exception:
            close_rtnl(self.netns or None)
            return _all()

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
