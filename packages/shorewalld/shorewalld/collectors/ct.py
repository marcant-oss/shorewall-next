"""CtCollector — conntrack table gauges + FIB route counts per netns.

All reads delegate to the nft-worker pinned to the target netns
(``router.read_file_sync`` / ``count_lines_sync``) so the scrape
thread never does a ``setns(2)`` hop itself.
"""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, _MetricFamily

from ._shared import _FileReader, _read_int_via_router


class CtCollector(CollectorBase):
    """Conntrack table gauges + FIB (main) route counts per netns.

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
