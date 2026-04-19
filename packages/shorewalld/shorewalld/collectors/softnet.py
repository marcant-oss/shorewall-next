"""SoftnetCollector — per-CPU softirq backlog counters from softnet_stat."""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, _MetricFamily

from ._shared import _FileReader

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
