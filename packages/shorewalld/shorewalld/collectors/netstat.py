"""NetstatCollector — selected TcpExt counters from /proc/net/netstat."""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, _MetricFamily

from ._shared import _FileReader
from .snmp import _parse_proc_net_snmp

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
