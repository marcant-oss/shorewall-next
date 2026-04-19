"""SockstatCollector — socket-count gauges from /proc/net/sockstat{,6}."""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, _MetricFamily

from ._shared import _FileReader


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
    """Socket-count gauges from ``/proc/net/sockstat`` + ``/proc/net/sockstat6``.

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
