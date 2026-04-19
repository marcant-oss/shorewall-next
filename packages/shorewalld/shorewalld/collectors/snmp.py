"""SnmpCollector — IP/TCP/UDP/ICMP counters from /proc/net/snmp{,6}.

Per scrape: two small file reads delegated to the nft-worker pinned
to the target netns.
"""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, _MetricFamily

from ._shared import _FileReader


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
