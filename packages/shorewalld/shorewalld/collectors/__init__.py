"""Per-scrape Prometheus collectors for shorewalld.

Each module under this package owns exactly one collector (plus its
parser helpers and static field tables). Collectors split by data
source: libnftables scraper (``nft``, ``flowtable``), pyroute2 netlink
(``link``, ``qdisc``, ``neighbour``, ``address``), ``/proc`` + ``/sys``
file reads routed through the netns-pinned worker (``ct``, ``snmp``,
``netstat``, ``sockstat``, ``softnet``), and CTNETLINK via a per-scrape
setns hop (``conntrack``). See the docstring on :mod:`shorewalld.exporter`
for the larger architecture.

Importing from :mod:`shorewalld.exporter` continues to work — the
exporter module re-exports every name below for back-compat with
callers that predate this split.
"""

from .address import AddressCollector
from .conntrack import (
    _CT_STAT_FIELDS,
    ConntrackStatsCollector,
    _sum_ct_stats_cpu,
)
from .ct import CtCollector
from .flowtable import FlowtableCollector
from .link import _LINK_STAT_FIELDS, LinkCollector
from .neighbour import NeighbourCollector, _neigh_state_name
from .netstat import _TCPEXT_FIELDS, NetstatCollector
from .nfsets import NfsetsCollector  # noqa: E402 — after exporter cycle settles
from .nft import NftCollector
from .qdisc import (
    _QDISC_FIELDS,
    _QDISC_LABELS,
    QdiscCollector,
    _extract_qdisc_row,
    _format_tc_handle,
)
from .snmp import (
    _SNMP_ICMP_FIELDS,
    _SNMP_IP_FIELDS,
    _SNMP_TCP_FIELDS,
    _SNMP_UDP_FIELDS,
    SnmpCollector,
    _parse_proc_net_snmp,
    _parse_proc_net_snmp6,
)
from .sockstat import (
    _SOCKSTAT_FIELDS,
    SockstatCollector,
    _parse_proc_net_sockstat,
)
from .softnet import (
    _SOFTNET_FIELDS,
    SoftnetCollector,
    _parse_proc_net_softnet_stat,
)
from .vrrp import VrrpCollector, VrrpInstance

__all__ = [
    "AddressCollector",
    "NfsetsCollector",
    "ConntrackStatsCollector",
    "CtCollector",
    "FlowtableCollector",
    "LinkCollector",
    "NeighbourCollector",
    "NetstatCollector",
    "NftCollector",
    "QdiscCollector",
    "SnmpCollector",
    "SockstatCollector",
    "SoftnetCollector",
    "_CT_STAT_FIELDS",
    "_LINK_STAT_FIELDS",
    "_QDISC_FIELDS",
    "_QDISC_LABELS",
    "_SNMP_ICMP_FIELDS",
    "_SNMP_IP_FIELDS",
    "_SNMP_TCP_FIELDS",
    "_SNMP_UDP_FIELDS",
    "_SOCKSTAT_FIELDS",
    "_SOFTNET_FIELDS",
    "_TCPEXT_FIELDS",
    "VrrpCollector",
    "VrrpInstance",
    "_extract_qdisc_row",
    "_format_tc_handle",
    "_neigh_state_name",
    "_parse_proc_net_snmp",
    "_parse_proc_net_snmp6",
    "_parse_proc_net_sockstat",
    "_parse_proc_net_softnet_stat",
    "_sum_ct_stats_cpu",
]
