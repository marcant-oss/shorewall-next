"""ConntrackStatsCollector — per-netns conntrack engine counters via CTNETLINK.

This is the lone collector that still hops through ``_in_netns()`` on
the scrape thread (CLAUDE.md §"Read RPC: netns-pinned /proc reads").
The read RPC doesn't yet proxy ``NFCTSocket`` over worker IPC, so the
setns is kept local here; every other ``/proc``-reading collector has
moved to the worker-delegated path. Deferred work: proxy CTNETLINK too.
"""

from __future__ import annotations

from typing import Any

from shorewall_nft.nft.netlink import _in_netns

from shorewalld.exporter import CollectorBase, _MetricFamily

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
    netns at open time. The kernel returns one row per CPU; we sum
    across CPUs since the per-CPU identity is never a stable label
    for Prometheus.

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
