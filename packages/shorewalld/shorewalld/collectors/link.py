"""LinkCollector — per-interface rtnl_link_stats64 + oper state + MTU.

One ``IPRoute(netns=…).get_links()`` dump per scrape feeds every metric
in :data:`_LINK_STAT_FIELDS` plus ``IFLA_CARRIER_CHANGES`` (link up/down
event count) and ``IFLA_MTU`` (current MTU) — no extra netlink
round-trips for the expanded counter surface.

The ``IPRoute`` handle is obtained from the shared cache in
:mod:`shorewalld.collectors._shared` (``get_rtnl``). One handle per
netns is kept alive across scrapes; no per-scrape fork overhead.
"""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, _MetricFamily

from ._shared import close_rtnl, get_rtnl

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
            ipr = get_rtnl(self.netns or None)
        except ImportError:
            return _all()
        except Exception:
            return _all()
        try:
            links = ipr.get_links()
        except Exception:
            close_rtnl(self.netns or None)
            return _all()

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
