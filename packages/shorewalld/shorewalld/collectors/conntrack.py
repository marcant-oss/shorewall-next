"""ConntrackStatsCollector — per-netns conntrack engine counters via CTNETLINK.

The read RPC proxies ``NFCTSocket`` over worker IPC so the scrape
thread never calls ``setns(2)`` — the worker is already pinned to the
target netns (``READ_KIND_CTNETLINK``). All other collectors have used
the worker-delegated path since the Read RPC shipped; this collector
is now fully aligned with that architecture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from shorewalld.exporter import CollectorBase, _MetricFamily

if TYPE_CHECKING:
    from shorewalld.read_codec import CtNetlinkStats

    from ._shared import _CtFileReader

# Per-netns conntrack counters summed from the per-CPU CTNETLINK rows.
# Legacy fields (SEARCHED / NEW / DELETE / DELETE_LIST / INSERT) are
# skipped — modern kernels never increment them and surfacing them
# would only confuse alerting rules.
_CT_STAT_FIELDS: list[tuple[str, str, str]] = [
    # (pyroute2 attr / CtNetlinkStats field, metric name, help text)
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

    Delegates the ``NFCTSocket`` call to the nft-worker that is already
    pinned to the target netns (``WorkerRouter.ctnetlink_stats_sync``),
    so the scrape thread stays in the default netns and requires no
    extra capabilities beyond what the daemon already holds.

    On ``ctnetlink_stats_sync`` returning ``None`` (worker unavailable,
    netns gone, pyroute2 missing, timeout) the collector emits the
    metric families with zero samples rather than raising — the registry
    isolates exceptions anyway, but a silent empty is friendlier for
    unprivileged dev runs.
    """

    def __init__(self, netns: str, router: "_CtFileReader") -> None:
        super().__init__(netns)
        self._router = router

    def collect(self) -> list[_MetricFamily]:
        families = {
            name: _MetricFamily(name, help_text, ["netns"], mtype="counter")
            for _attr, name, help_text in _CT_STAT_FIELDS
        }

        def _all() -> list[_MetricFamily]:
            return list(families.values())

        stats: CtNetlinkStats | None = self._router.ctnetlink_stats_sync(
            self.netns)
        if stats is None:
            return _all()

        for attr, name, _help in _CT_STAT_FIELDS:
            families[name].add([self.netns], float(getattr(stats, attr, 0)))
        return _all()
