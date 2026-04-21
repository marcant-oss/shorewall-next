"""Phase 2 shorewalld exporter unit tests.

Feeds hand-built ``nftables`` JSON dicts into the collectors via a
``FakeNftInterface`` — no real netlink socket, no real ruleset, no
live netns. Exercises the core logic of ``NftCollector``,
``NftScraper`` caching, ``ShorewalldRegistry`` merging, and
``list_rule_counters`` walking.
"""
from __future__ import annotations

from typing import Any

import pytest

from shorewalld.collectors.conntrack import _CT_STAT_FIELDS, _sum_ct_stats_cpu
from shorewalld.collectors.link import _LINK_STAT_FIELDS
from shorewalld.collectors.neighbour import _neigh_state_name
from shorewalld.collectors.qdisc import _extract_qdisc_row, _format_tc_handle, _QDISC_FIELDS
from shorewalld.collectors.snmp import _parse_proc_net_snmp, _parse_proc_net_snmp6
from shorewalld.collectors.sockstat import _parse_proc_net_sockstat
from shorewalld.collectors.softnet import _parse_proc_net_softnet_stat
from shorewalld.exporter import (
    CollectorBase,
    CtCollector,
    FlowtableCollector,
    Histogram,
    NetstatCollector,
    NftCollector,
    NftScraper,
    ShorewalldRegistry,
    SnmpCollector,
    SockstatCollector,
    SoftnetCollector,
    _fmt_bucket_bound,
    _MetricFamily,
)
from shorewall_nft.nft.netlink import NftError


class FakeRouter:
    """Stub for ``WorkerRouter`` exposing just the read/count APIs the
    collectors use. ``files`` maps path → bytes (or None for NOT_FOUND);
    ``line_counts`` maps path → int (or None for missing). Any path not
    configured in either mapping returns ``None``.
    """

    def __init__(
        self,
        files: dict[str, bytes | None] | None = None,
        line_counts: dict[str, int | None] | None = None,
    ) -> None:
        self.files = files or {}
        self.line_counts = line_counts or {}
        self.read_calls: list[tuple[str, str]] = []
        self.count_calls: list[tuple[str, str]] = []

    def read_file_sync(
        self, netns: str, path: str, *, timeout: float = 5.0,
    ) -> bytes | None:
        self.read_calls.append((netns, path))
        return self.files.get(path)

    def count_lines_sync(
        self, netns: str, path: str, *, timeout: float = 5.0,
    ) -> int | None:
        self.count_calls.append((netns, path))
        return self.line_counts.get(path)

# ── Fake NftInterface (matches the shape exporter.py actually calls) ─


class FakeNftInterface:
    """In-memory stand-in for NftInterface.

    Stores a full ``list table`` JSON dict per netns. Methods raise
    NftError for unknown netns to simulate a missing table.
    """

    def __init__(self, tables: dict[str, dict[str, Any]] | None = None,
                 counters: dict[str, dict[str, dict[str, int]]] | None = None):
        self.tables = tables or {}
        self.counters = counters or {}
        self.list_table_calls = 0
        self.list_rule_counter_calls = 0

    def list_table(self, family: str = "inet", table: str = "shorewall",
                   *, netns: str | None = None) -> dict[str, Any]:
        self.list_table_calls += 1
        key = netns or ""
        if key not in self.tables:
            raise NftError(f"no table in netns={key!r}")
        return self.tables[key]

    def list_rule_counters(self, family: str = "inet", table: str = "shorewall",
                           *, netns: str | None = None) -> list[dict[str, Any]]:
        # Delegate to the real walker logic by re-using list_table output.
        self.list_rule_counter_calls += 1
        try:
            data = self.list_table(netns=netns)
        except NftError:
            return []
        out: list[dict[str, Any]] = []
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            packets = bytes_ = 0
            found = False
            for expr in rule.get("expr", []):
                c = expr.get("counter") if isinstance(expr, dict) else None
                if isinstance(c, dict):
                    packets += int(c.get("packets", 0))
                    bytes_ += int(c.get("bytes", 0))
                    found = True
            if not found:
                continue
            out.append({
                "table": rule.get("table", table),
                "chain": rule.get("chain", ""),
                "handle": rule.get("handle", 0),
                "comment": rule.get("comment", ""),
                "packets": packets,
                "bytes": bytes_,
            })
        return out

    def list_counters(self, family: str = "inet", table: str = "shorewall",
                      *, netns: str | None = None) -> dict[str, dict[str, int]]:
        return self.counters.get(netns or "", {})


def _make_ruleset():
    """A representative ``list table inet shorewall`` JSON response.

    Shape mirrors what libnftables emits: a top-level ``nftables`` list
    where each item is tagged with ``table``, ``chain``, ``set``,
    ``counter`` or ``rule``. We only wire up the fields exporter.py
    actually reads.
    """
    return {
        "nftables": [
            {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak"}},
            {"table": {"family": "inet", "name": "shorewall", "handle": 1}},
            {"chain": {
                "family": "inet", "table": "shorewall",
                "name": "forward", "handle": 2, "type": "filter",
                "hook": "forward", "prio": 0, "policy": "drop"}},
            {"set": {
                "family": "inet", "table": "shorewall",
                "name": "dns_github_com", "type": "ipv4_addr",
                "elem": ["140.82.121.3", "140.82.121.4"]}},
            {"set": {
                "family": "inet", "table": "shorewall",
                "name": "empty_set", "type": "ipv4_addr", "elem": []}},
            {"rule": {
                "family": "inet", "table": "shorewall",
                "chain": "forward", "handle": 100,
                "comment": "customer-a to adm",
                "expr": [
                    {"match": {"op": "==", "left": {"meta": "iifname"},
                               "right": "bond0.10"}},
                    {"counter": {"packets": 1234, "bytes": 56789}},
                    {"accept": None},
                ]}},
            {"rule": {
                "family": "inet", "table": "shorewall",
                "chain": "forward", "handle": 101,
                "expr": [
                    {"counter": {"packets": 7, "bytes": 420}},
                    {"drop": None},
                ]}},
            # A rule without any counter — must be skipped.
            {"rule": {
                "family": "inet", "table": "shorewall",
                "chain": "forward", "handle": 102,
                "expr": [{"accept": None}]}},
        ]
    }


# ── list_rule_counters walker ────────────────────────────────────────


def test_fake_list_rule_counters_extracts_only_counter_rules():
    fake = FakeNftInterface(tables={"": _make_ruleset()})
    rules = fake.list_rule_counters()
    assert len(rules) == 2
    handles = [r["handle"] for r in rules]
    assert handles == [100, 101]


def test_fake_list_rule_counters_captures_comment_and_counts():
    fake = FakeNftInterface(tables={"": _make_ruleset()})
    r = fake.list_rule_counters()[0]
    assert r["chain"] == "forward"
    assert r["comment"] == "customer-a to adm"
    assert r["packets"] == 1234
    assert r["bytes"] == 56789


def test_fake_list_rule_counters_returns_empty_on_missing_table():
    fake = FakeNftInterface(tables={})
    assert fake.list_rule_counters(netns="nonexistent") == []


# ── NftScraper caching ───────────────────────────────────────────────


def test_scraper_caches_within_ttl():
    fake = FakeNftInterface(tables={"fw": _make_ruleset()})
    scraper = NftScraper(fake, ttl_s=60.0)

    scraper.snapshot("fw")
    first_calls = fake.list_table_calls
    scraper.snapshot("fw")
    scraper.snapshot("fw")
    assert fake.list_table_calls == first_calls


def test_scraper_refreshes_after_ttl_expiry():
    fake = FakeNftInterface(tables={"fw": _make_ruleset()})
    scraper = NftScraper(fake, ttl_s=0.0)

    scraper.snapshot("fw")
    scraper.snapshot("fw")
    assert fake.list_table_calls >= 2


def test_scraper_invalidate():
    fake = FakeNftInterface(tables={"fw": _make_ruleset()})
    scraper = NftScraper(fake, ttl_s=60.0)

    scraper.snapshot("fw")
    scraper.invalidate("fw")
    scraper.snapshot("fw")
    assert fake.list_table_calls == 2


def test_scraper_handles_missing_table():
    fake = FakeNftInterface(tables={})
    scraper = NftScraper(fake, ttl_s=60.0)

    snap = scraper.snapshot("missing")
    assert snap.has_table is False
    assert snap.rule_counters == []
    assert snap.sets == {}


# ── NftCollector ─────────────────────────────────────────────────────


def _get_family(families: list[_MetricFamily], name: str) -> _MetricFamily:
    for f in families:
        if f.name == name:
            return f
    raise AssertionError(f"no metric family {name!r}")


def test_nft_collector_emits_per_rule_counters():
    fake = FakeNftInterface(tables={"fw": _make_ruleset()})
    scraper = NftScraper(fake, ttl_s=60.0)
    col = NftCollector("fw", scraper)

    families = col.collect()
    packets = _get_family(families, "shorewall_nft_packets_total")
    bytes_ = _get_family(families, "shorewall_nft_bytes_total")

    assert len(packets.samples) == 2
    assert len(bytes_.samples) == 2

    # Rule 100 sample: ["fw", "shorewall", "forward", "100", "customer-a to adm"]
    first_labels, first_value = packets.samples[0]
    assert first_labels[0] == "fw"
    assert first_labels[2] == "forward"
    assert first_labels[3] == "100"
    assert first_labels[4] == "customer-a to adm"
    assert first_value == 1234.0


def test_nft_collector_emits_set_element_counts():
    fake = FakeNftInterface(tables={"fw": _make_ruleset()})
    scraper = NftScraper(fake, ttl_s=60.0)
    col = NftCollector("fw", scraper)

    families = col.collect()
    sets = _get_family(families, "shorewall_nft_set_elements")
    by_name = {s[0][1]: s[1] for s in sets.samples}
    assert by_name["dns_github_com"] == 2.0
    assert by_name["empty_set"] == 0.0


def test_nft_collector_empty_when_table_missing():
    fake = FakeNftInterface(tables={})
    scraper = NftScraper(fake, ttl_s=60.0)
    col = NftCollector("ghost", scraper)

    families = col.collect()
    # Still returns the five family descriptors, all empty.
    packets = _get_family(families, "shorewall_nft_packets_total")
    assert packets.samples == []


def test_nft_collector_named_counter_objects():
    fake = FakeNftInterface(
        tables={"fw": _make_ruleset()},
        counters={"fw": {"customer-a_bytes": {"packets": 42, "bytes": 4242}}})
    scraper = NftScraper(fake, ttl_s=60.0)
    col = NftCollector("fw", scraper)

    families = col.collect()
    named = _get_family(families, "shorewall_nft_named_counter_packets_total")
    assert named.samples == [(["fw", "customer-a_bytes"], 42.0)]


# ── ShorewalldRegistry merging ───────────────────────────────────────


def test_registry_merges_families_across_netns_profiles():
    fake = FakeNftInterface(tables={
        "fw": _make_ruleset(),
        "rns1": _make_ruleset(),
    })
    scraper = NftScraper(fake, ttl_s=60.0)
    reg = ShorewalldRegistry()
    reg.add(NftCollector("fw", scraper))
    reg.add(NftCollector("rns1", scraper))

    families = reg.collect()
    packets = _get_family(families, "shorewall_nft_packets_total")
    # Two rules per netns × two netns = four samples total.
    assert len(packets.samples) == 4
    # Each netns label appears twice.
    by_netns: dict[str, int] = {}
    for labels, _ in packets.samples:
        by_netns[labels[0]] = by_netns.get(labels[0], 0) + 1
    assert by_netns == {"fw": 2, "rns1": 2}


def test_registry_isolates_collector_exceptions():
    class BrokenCollector(CollectorBase):
        def collect(self) -> list[_MetricFamily]:
            raise RuntimeError("boom")

    fake = FakeNftInterface(tables={"fw": _make_ruleset()})
    scraper = NftScraper(fake, ttl_s=60.0)
    reg = ShorewalldRegistry()
    reg.add(BrokenCollector("broken"))
    reg.add(NftCollector("fw", scraper))

    families = reg.collect()
    packets = _get_family(families, "shorewall_nft_packets_total")
    assert len(packets.samples) == 2  # broken collector didn't tank fw


# ── _format_tc_handle ────────────────────────────────────────────────


def test_format_tc_handle_reserved_values():
    # TC_H_ROOT is 0xffffffff; 0 is unspecified (ingress root).
    assert _format_tc_handle(0xFFFFFFFF) == "root"
    assert _format_tc_handle(0) == "none"


def test_format_tc_handle_major_minor_hex():
    # handle 0x00010000 → major 1, minor 0 → "1:0"
    assert _format_tc_handle(0x00010000) == "1:0"
    # handle 0x0abc1234 → "abc:1234"
    assert _format_tc_handle(0x0ABC1234) == "abc:1234"


# ── _extract_qdisc_row ───────────────────────────────────────────────


class _FakeNlaContainer:
    """Imitates a pyroute2 nested-attr object with .get_attr()."""

    def __init__(self, attrs: dict[str, Any]):
        self._attrs = attrs

    def get_attr(self, key: str) -> Any:
        return self._attrs.get(key)


class _FakeQdiscMsg:
    """Imitates a pyroute2 tcmsg for _extract_qdisc_row."""

    def __init__(self, *, index: int, handle: int, parent: int,
                 attrs: dict[str, Any]):
        self._fields = {"index": index, "handle": handle, "parent": parent}
        self._attrs = attrs

    def get(self, key: str, default: Any = None) -> Any:
        return self._fields.get(key, default)

    def get_attr(self, key: str) -> Any:
        return self._attrs.get(key)


def test_extract_qdisc_row_prefers_stats2():
    q = _FakeQdiscMsg(
        index=3, handle=0x00010000, parent=0xFFFFFFFF,
        attrs={
            "TCA_KIND": "fq_codel",
            "TCA_STATS2": _FakeNlaContainer({
                "TCA_STATS_BASIC": {"bytes": 1_000_000, "packets": 5000},
                "TCA_STATS_QUEUE": {
                    "qlen": 3, "backlog": 1500, "drops": 42,
                    "requeues": 7, "overlimits": 11},
            }),
            # TCA_STATS is legacy; it lacks requeues but carries bps/pps.
            "TCA_STATS": {"bytes": 999, "packets": 4, "drop": 0,
                          "overlimits": 0, "bps": 125000, "pps": 800,
                          "qlen": 0, "backlog": 0},
        })
    suffix, stats = _extract_qdisc_row(q, {3: "eth0"})

    assert suffix == ["eth0", "fq_codel", "1:0", "root"]
    # Counters came from TCA_STATS2 (the higher-fidelity source)
    assert stats["bytes"] == 1_000_000
    assert stats["packets"] == 5000
    assert stats["drops"] == 42
    assert stats["requeues"] == 7
    assert stats["overlimits"] == 11
    assert stats["qlen"] == 3
    assert stats["backlog"] == 1500
    # bps/pps only ever come from the legacy flat stats.
    assert stats["bps"] == 125000
    assert stats["pps"] == 800


def test_extract_qdisc_row_falls_back_to_legacy_stats():
    # Old kernel / unusual driver path: no TCA_STATS2, only TCA_STATS.
    q = _FakeQdiscMsg(
        index=7, handle=0, parent=0,
        attrs={
            "TCA_KIND": "pfifo_fast",
            "TCA_STATS": {"bytes": 500, "packets": 10, "drop": 2,
                          "overlimits": 1, "qlen": 0, "backlog": 0,
                          "bps": 0, "pps": 0},
        })
    suffix, stats = _extract_qdisc_row(q, {7: "wg0"})

    assert suffix == ["wg0", "pfifo_fast", "none", "none"]
    assert stats["bytes"] == 500
    assert stats["packets"] == 10
    assert stats["drops"] == 2        # legacy singular "drop" → "drops"
    assert stats["overlimits"] == 1
    assert stats["requeues"] == 0     # not in legacy stats, stays 0


def test_extract_qdisc_row_unknown_ifindex_gets_placeholder():
    q = _FakeQdiscMsg(
        index=99, handle=0, parent=0xFFFFFFFF,
        attrs={"TCA_KIND": "noqueue", "TCA_STATS2": _FakeNlaContainer({
            "TCA_STATS_BASIC": {"bytes": 0, "packets": 0},
            "TCA_STATS_QUEUE": {"qlen": 0, "backlog": 0, "drops": 0,
                                "requeues": 0, "overlimits": 0}})})
    suffix, _stats = _extract_qdisc_row(q, {})  # empty map
    assert suffix[0] == "ifindex99"


# ── _LINK_STAT_FIELDS coverage ───────────────────────────────────────


def test_link_stat_fields_cover_rtnl_link_stats64_struct():
    # Sanity: every kernel key we emit is unique, every metric name is
    # unique, and the set covers the expected rtnl_link_stats64 surface.
    kernel_keys = [k for k, _name, _h in _LINK_STAT_FIELDS]
    metric_names = [n for _k, n, _h in _LINK_STAT_FIELDS]
    assert len(set(kernel_keys)) == len(kernel_keys)
    assert len(set(metric_names)) == len(metric_names)
    # Key fields that any alerting rule would refer to — don't let a
    # future refactor silently drop them.
    required = {
        "rx_packets", "rx_bytes", "tx_packets", "tx_bytes",
        "rx_errors", "tx_errors", "rx_dropped", "tx_dropped",
        "rx_missed_errors", "rx_crc_errors", "tx_carrier_errors",
        "multicast", "collisions",
    }
    assert required.issubset(set(kernel_keys))


def test_qdisc_fields_cover_expected_metrics():
    metric_names = {name for _k, name, _m, _h in _QDISC_FIELDS}
    assert "shorewall_nft_qdisc_bytes_total" in metric_names
    assert "shorewall_nft_qdisc_drops_total" in metric_names
    assert "shorewall_nft_qdisc_qlen" in metric_names
    assert "shorewall_nft_qdisc_backlog_bytes" in metric_names
    assert "shorewall_nft_qdisc_rate_bps" in metric_names


# ── _sum_ct_stats_cpu ────────────────────────────────────────────────


class _FakeCtStatsRow:
    """Imitates one per-CPU nfct_stats_cpu message for unit testing."""

    def __init__(self, attrs: dict[str, int]):
        self._attrs = attrs

    def get_attr(self, key: str) -> Any:
        return self._attrs.get(key)


def test_sum_ct_stats_cpu_sums_across_rows():
    # Typical three-CPU machine where CPU 0 absorbs most of the work.
    rows = [
        _FakeCtStatsRow({
            "CTA_STATS_FOUND": 1000,
            "CTA_STATS_INVALID": 5,
            "CTA_STATS_INSERT_FAILED": 2,
            "CTA_STATS_DROP": 1,
            "CTA_STATS_EARLY_DROP": 0,
            "CTA_STATS_ERROR": 3,
            "CTA_STATS_SEARCH_RESTART": 0,
            "CTA_STATS_IGNORE": 7,
        }),
        _FakeCtStatsRow({
            "CTA_STATS_FOUND": 500, "CTA_STATS_INVALID": 1,
            "CTA_STATS_DROP": 4,
        }),
        _FakeCtStatsRow({
            "CTA_STATS_FOUND": 250, "CTA_STATS_DROP": 0,
            "CTA_STATS_SEARCH_RESTART": 12,
        }),
    ]
    totals = _sum_ct_stats_cpu(rows)
    assert totals["CTA_STATS_FOUND"] == 1750
    assert totals["CTA_STATS_INVALID"] == 6
    assert totals["CTA_STATS_INSERT_FAILED"] == 2
    assert totals["CTA_STATS_DROP"] == 5
    assert totals["CTA_STATS_EARLY_DROP"] == 0
    assert totals["CTA_STATS_ERROR"] == 3
    assert totals["CTA_STATS_SEARCH_RESTART"] == 12
    assert totals["CTA_STATS_IGNORE"] == 7


def test_sum_ct_stats_cpu_handles_empty_and_missing_attrs():
    # Empty input → all zeros, keys still present.
    totals = _sum_ct_stats_cpu([])
    assert set(totals.keys()) == {attr for attr, _n, _h in _CT_STAT_FIELDS}
    assert all(v == 0 for v in totals.values())

    # Row without get_attr is silently skipped (not every pyroute2
    # version wraps every message type uniformly).
    class _Bare:
        pass
    totals2 = _sum_ct_stats_cpu([_Bare()])
    assert all(v == 0 for v in totals2.values())


def test_ct_stat_fields_cover_critical_counters():
    metric_names = {name for _a, name, _h in _CT_STAT_FIELDS}
    # Operators alert on these specifically — don't let a refactor drop them.
    required = {
        "shorewall_nft_ct_drop_total",
        "shorewall_nft_ct_early_drop_total",
        "shorewall_nft_ct_insert_failed_total",
        "shorewall_nft_ct_invalid_total",
    }
    assert required.issubset(metric_names)


# ── /proc/net/snmp parser ────────────────────────────────────────────


_SAMPLE_SNMP = (
    "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors "
    "ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests "
    "OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails\n"
    "Ip: 1 64 1000 1 2 700 0 3 900 850 0 5 0 0 0 4\n"
    "Icmp: InMsgs InErrors InDestUnreachs InTimeExcds OutMsgs OutDestUnreachs"
    " OutTimeExcds InRedirects InEchos InEchoReps\n"
    "Icmp: 50 0 12 3 40 7 2 0 10 8\n"
    "Tcp: RtoAlgorithm RtoMin ActiveOpens PassiveOpens AttemptFails "
    "EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts\n"
    "Tcp: 1 200 123 456 7 8 42 9999 8888 77 0 22\n"
    "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n"
    "Udp: 5000 120 3 4800 0 0\n"
)


def test_parse_proc_net_snmp_populates_all_blocks():
    blocks = _parse_proc_net_snmp(_SAMPLE_SNMP)
    assert set(blocks) == {"Ip", "Icmp", "Tcp", "Udp"}
    assert blocks["Ip"]["ForwDatagrams"] == 700
    assert blocks["Ip"]["OutNoRoutes"] == 5
    assert blocks["Tcp"]["CurrEstab"] == 42
    assert blocks["Tcp"]["RetransSegs"] == 77
    assert blocks["Udp"]["NoPorts"] == 120


def test_parse_proc_net_snmp_skips_malformed_pairs():
    broken = "Ip: Forwarding\nIp: 1\nTrash no colon here\nIcmp: InMsgs\nIcmp: 7\n"
    out = _parse_proc_net_snmp(broken)
    # The trash line is skipped; Ip + Icmp still parse cleanly.
    assert out["Ip"]["Forwarding"] == 1
    assert out["Icmp"]["InMsgs"] == 7


# ── /proc/net/snmp6 parser ───────────────────────────────────────────


def test_parse_proc_net_snmp6_flat_keys():
    text = (
        "Ip6InReceives                   1234\n"
        "Ip6OutForwDatagrams             42\n"
        "Icmp6InMsgs                     17\n"
        "garbage line without a number\n"
        "Udp6NoPorts                     5\n"
    )
    out = _parse_proc_net_snmp6(text)
    assert out["Ip6InReceives"] == 1234
    assert out["Ip6OutForwDatagrams"] == 42
    assert out["Icmp6InMsgs"] == 17
    assert out["Udp6NoPorts"] == 5
    assert "garbage" not in out


# ── /proc/net/sockstat parser ────────────────────────────────────────


def test_parse_proc_net_sockstat_extracts_kv_pairs():
    text = (
        "sockets: used 1234\n"
        "TCP: inuse 42 orphan 0 tw 7 alloc 55 mem 23\n"
        "UDP: inuse 5 mem 3\n"
        "FRAG: inuse 0 memory 0\n"
    )
    out = _parse_proc_net_sockstat(text)
    assert out["sockets"]["used"] == 1234
    assert out["TCP"]["inuse"] == 42
    assert out["TCP"]["tw"] == 7
    assert out["UDP"]["mem"] == 3
    assert out["FRAG"]["memory"] == 0


def test_parse_proc_net_sockstat_v6_subset():
    # sockstat6 only carries the ``inuse`` buckets (+ FRAG memory).
    text = (
        "TCP6: inuse 12\n"
        "UDP6: inuse 3\n"
        "FRAG6: inuse 0 memory 0\n"
    )
    out = _parse_proc_net_sockstat(text)
    assert out["TCP6"]["inuse"] == 12
    assert out["UDP6"]["inuse"] == 3


# ── /proc/net/softnet_stat parser ────────────────────────────────────


def test_parse_proc_net_softnet_stat_hex_decodes_columns():
    # Two CPUs, 11 columns each (matches the 5.x+ kernel layout).
    text = (
        "00000123 00000004 00000002 00000000 00000000 "
        "00000000 00000000 00000000 00000000 0000000a 0000001f\n"
        "00000456 00000000 00000005 00000000 00000000 "
        "00000000 00000000 00000000 00000000 0000000b 00000001\n"
    )
    rows = _parse_proc_net_softnet_stat(text)
    assert len(rows) == 2
    assert rows[0][0] == 0x123
    assert rows[0][1] == 4
    assert rows[0][2] == 2
    # received_rps is column 9, flow_limit column 10.
    assert rows[0][9] == 10
    assert rows[0][10] == 0x1F
    assert rows[1][0] == 0x456


# ── NUD state translation ────────────────────────────────────────────


def test_neigh_state_name_decodes_common_masks():
    # NUD_REACHABLE == 0x02
    assert _neigh_state_name(0x02) == "reachable"
    # NUD_FAILED == 0x20
    assert _neigh_state_name(0x20) == "failed"
    # NUD_PERMANENT == 0x80 beats NUD_NOARP when both set
    assert _neigh_state_name(0x80 | 0x40) == "permanent"
    # Zero → "none" placeholder
    assert _neigh_state_name(0) == "none"


# ── SnmpCollector end-to-end via FakeRouter ──────────────────────────


def test_snmp_collector_emits_ip_family_split():
    snmp = (
        "Ip: Forwarding DefaultTTL ForwDatagrams OutNoRoutes InDiscards "
        "InHdrErrors InAddrErrors InDelivers OutRequests ReasmFails\n"
        "Ip: 1 64 111 22 3 0 0 500 480 0\n"
        "Tcp: RtoAlgorithm RtoMin ActiveOpens PassiveOpens AttemptFails "
        "EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts\n"
        "Tcp: 1 200 0 0 0 0 9 0 0 0 0 0\n"
        "Udp: InDatagrams NoPorts InErrors OutDatagrams "
        "RcvbufErrors SndbufErrors\n"
        "Udp: 0 0 0 0 0 0\n"
        "Icmp: InMsgs OutMsgs InDestUnreachs OutDestUnreachs InTimeExcds "
        "OutTimeExcds InRedirects InEchos InEchoReps\n"
        "Icmp: 0 0 0 0 0 0 0 0 0\n"
    )
    snmp6 = (
        "Ip6OutForwDatagrams     999\n"
        "Ip6OutNoRoutes          33\n"
    )
    router = FakeRouter(files={
        "/proc/net/snmp": snmp.encode(),
        "/proc/net/snmp6": snmp6.encode(),
    })
    col = SnmpCollector("fw", router)

    families = col.collect()
    fwd = _get_family(families, "shorewall_nft_ip_forwarded_total")
    no_route = _get_family(families, "shorewall_nft_ip_out_no_routes_total")
    tcp_estab = _get_family(families, "shorewall_nft_tcp_curr_estab")

    # IPv4 + IPv6 family split.
    samples = {tuple(lbl): val for lbl, val in fwd.samples}
    assert samples[("fw", "ipv4")] == 111.0
    assert samples[("fw", "ipv6")] == 999.0

    samples = {tuple(lbl): val for lbl, val in no_route.samples}
    assert samples[("fw", "ipv4")] == 22.0
    assert samples[("fw", "ipv6")] == 33.0

    # TCP has no family label (single counter covers both).
    assert tcp_estab.samples == [(["fw"], 9.0)]


def test_snmp_collector_returns_empty_families_when_router_returns_none():
    router = FakeRouter()  # no files configured
    col = SnmpCollector("fw", router)
    families = col.collect()
    # Every family is declared but empty — keeps `absent()` alerts stable.
    assert {f.name for f in families}.issuperset(
        {"shorewall_nft_ip_forwarded_total",
         "shorewall_nft_tcp_curr_estab"})
    for fam in families:
        assert fam.samples == []


# ── NetstatCollector ─────────────────────────────────────────────────


def test_netstat_collector_extracts_tcpext_block():
    text = (
        "TcpExt: ListenOverflows ListenDrops TCPBacklogDrop TCPTimeouts "
        "TCPSynRetrans PruneCalled TCPOFODrop TCPAbortOnData "
        "TCPAbortOnMemory TCPRetransFail\n"
        "TcpExt: 1 2 3 4 5 6 7 8 9 10\n"
        "IpExt: InNoRoutes\n"
        "IpExt: 99\n"
    )
    router = FakeRouter(files={"/proc/net/netstat": text.encode()})
    col = NetstatCollector("fw", router)

    families = col.collect()
    overflows = _get_family(
        families, "shorewall_nft_tcpext_listen_overflows_total")
    syn_retrans = _get_family(
        families, "shorewall_nft_tcpext_syn_retrans_total")

    assert overflows.samples == [(["fw"], 1.0)]
    assert syn_retrans.samples == [(["fw"], 5.0)]


# ── SockstatCollector ────────────────────────────────────────────────


def test_sockstat_collector_emits_family_split_for_inuse():
    v4 = (
        "sockets: used 100\n"
        "TCP: inuse 42 orphan 1 tw 7 alloc 50 mem 23\n"
        "UDP: inuse 5 mem 3\n"
        "FRAG: inuse 0 memory 0\n"
    )
    v6 = (
        "TCP6: inuse 12\n"
        "UDP6: inuse 4\n"
        "FRAG6: inuse 0 memory 0\n"
    )
    router = FakeRouter(files={
        "/proc/net/sockstat": v4.encode(),
        "/proc/net/sockstat6": v6.encode(),
    })
    col = SockstatCollector("fw", router)

    families = col.collect()
    tcp_inuse = _get_family(families, "shorewall_nft_sockstat_tcp_inuse")
    tcp_orphan = _get_family(families, "shorewall_nft_sockstat_tcp_orphan")
    sockets_used = _get_family(families, "shorewall_nft_sockstat_sockets_used")

    samples = {tuple(lbl): val for lbl, val in tcp_inuse.samples}
    assert samples[("fw", "ipv4")] == 42.0
    assert samples[("fw", "ipv6")] == 12.0

    # v4-only metrics carry no family label.
    assert tcp_orphan.samples == [(["fw"], 1.0)]
    assert sockets_used.samples == [(["fw"], 100.0)]


# ── SoftnetCollector ─────────────────────────────────────────────────


def test_softnet_collector_labels_per_cpu():
    # Two CPUs, 11 columns each.
    text = (
        "00000064 00000001 00000002 00000000 00000000 "
        "00000000 00000000 00000000 00000000 00000005 00000000\n"
        "00000100 00000003 00000004 00000000 00000000 "
        "00000000 00000000 00000000 00000000 00000007 00000002\n"
    )
    router = FakeRouter(files={"/proc/net/softnet_stat": text.encode()})
    col = SoftnetCollector("fw", router)

    families = col.collect()
    processed = _get_family(
        families, "shorewall_nft_softnet_processed_total")
    dropped = _get_family(
        families, "shorewall_nft_softnet_dropped_total")
    rps = _get_family(
        families, "shorewall_nft_softnet_received_rps_total")

    by_cpu = {lbl[1]: val for lbl, val in processed.samples}
    assert by_cpu == {"0": 100.0, "1": 256.0}
    by_cpu = {lbl[1]: val for lbl, val in dropped.samples}
    assert by_cpu == {"0": 1.0, "1": 3.0}
    by_cpu = {lbl[1]: val for lbl, val in rps.samples}
    assert by_cpu == {"0": 5.0, "1": 7.0}


# ── CtCollector with router-sourced reads ────────────────────────────


def test_ct_collector_emits_counts_and_fib_via_router():
    router = FakeRouter(
        files={
            "/proc/sys/net/netfilter/nf_conntrack_count": b"1234\n",
            "/proc/sys/net/netfilter/nf_conntrack_max": b"65536\n",
            "/proc/sys/net/netfilter/nf_conntrack_buckets": b"16384\n",
        },
        # /proc/net/route has a one-line header CtCollector subtracts.
        line_counts={
            "/proc/net/route": 42 + 1,
            "/proc/net/ipv6_route": 900_000,
        },
    )
    col = CtCollector("fw", router)
    families = col.collect()

    count = _get_family(families, "shorewall_nft_ct_count")
    mx = _get_family(families, "shorewall_nft_ct_max")
    buckets = _get_family(families, "shorewall_nft_ct_buckets")
    fib = _get_family(families, "shorewall_nft_fib_routes")

    assert count.samples == [(["fw"], 1234.0)]
    assert mx.samples == [(["fw"], 65536.0)]
    assert buckets.samples == [(["fw"], 16384.0)]
    fib_samples = {tuple(lbl): val for lbl, val in fib.samples}
    assert fib_samples[("fw", "ipv4")] == 42.0
    assert fib_samples[("fw", "ipv6")] == 900_000.0


def test_ct_collector_skips_missing_samples():
    # Router returns None for everything -> all families present, empty.
    col = CtCollector("fw", FakeRouter())
    families = col.collect()
    # Four families regardless of data availability.
    names = {f.name for f in families}
    assert names == {
        "shorewall_nft_ct_count",
        "shorewall_nft_ct_max",
        "shorewall_nft_ct_buckets",
        "shorewall_nft_fib_routes",
    }
    for fam in families:
        assert fam.samples == []


# ── FlowtableCollector via NftScraper snapshot ───────────────────────


def _make_ruleset_with_flowtables():
    """Variant of :func:`_make_ruleset` that also includes two
    flowtable descriptors. Mirrors the JSON layout libnftables emits.
    """
    return {
        "nftables": [
            {"table": {"family": "inet", "name": "shorewall", "handle": 1}},
            {"flowtable": {
                "family": "inet", "table": "shorewall",
                "name": "ft_main", "hook": "ingress", "prio": "filter",
                "devices": ["bond0.10", "bond0.20"],
                "flags": ["offload"]}},
            {"flowtable": {
                "family": "inet", "table": "shorewall",
                "name": "ft_mgmt", "hook": "ingress", "prio": "filter",
                "devices": [],
                "flags": ["offload"]}},
        ]
    }


def test_flowtable_collector_emits_device_counts_and_existence():
    fake = FakeNftInterface(tables={"fw": _make_ruleset_with_flowtables()})
    scraper = NftScraper(fake, ttl_s=60.0)
    col = FlowtableCollector("fw", scraper)

    families = col.collect()
    devices = _get_family(families, "shorewall_nft_flowtable_devices")
    exists = _get_family(families, "shorewall_nft_flowtable_exists")

    dev_map = {lbl[1]: val for lbl, val in devices.samples}
    assert dev_map == {"ft_main": 2.0, "ft_mgmt": 0.0}

    exist_labels = {(lbl[1], lbl[2]) for lbl, _ in exists.samples}
    assert exist_labels == {("ft_main", "ingress"), ("ft_mgmt", "ingress")}


def test_flowtable_collector_empty_on_missing_table():
    fake = FakeNftInterface(tables={})
    scraper = NftScraper(fake, ttl_s=60.0)
    col = FlowtableCollector("ghost", scraper)

    families = col.collect()
    for fam in families:
        assert fam.samples == []


# ── Histogram helper + _MetricFamily histogram support ───────────────


class TestHistogram:
    def test_cumulative_bucket_counts(self):
        h = Histogram([0.01, 0.05, 0.1])
        for v in [0.005, 0.03, 0.07, 0.2]:
            h.observe(v)
        # 0.005 falls into every bucket ≤ 0.01
        # 0.03 into 0.05 and 0.1
        # 0.07 into 0.1 only
        # 0.2 into +Inf only
        assert h.count == 4
        assert h.sum_value == pytest.approx(0.305)
        samples = h.bucket_samples()
        # Bound→count mapping (cumulative)
        by_bound = {b: c for b, c in samples}
        assert by_bound["0.01"] == 1.0
        assert by_bound["0.05"] == 2.0
        assert by_bound["0.1"] == 3.0
        assert by_bound["+Inf"] == 4.0

    def test_edge_equal_to_bound_included(self):
        h = Histogram([1.0])
        h.observe(1.0)
        by_bound = dict(h.bucket_samples())
        # 1.0 <= 1.0 → inside the 1.0 bucket
        assert by_bound["1"] == 1.0

    def test_fmt_bucket_bound_integer_and_float(self):
        assert _fmt_bucket_bound(1.0) == "1"
        assert _fmt_bucket_bound(0.005) == "0.005"
        assert _fmt_bucket_bound(2.5) == "2.5"


def test_metric_family_histogram_samples_carry_histogram_object():
    h = Histogram([0.01, 0.1])
    h.observe(0.005)
    fam = _MetricFamily("x_latency_seconds", "help", ["netns"],
                        mtype="histogram")
    fam.add_histogram(["fw"], h)
    assert len(fam.samples) == 1
    labels, obj = fam.samples[0]
    assert labels == ["fw"]
    assert obj is h
    assert obj.count == 1


def test_registry_renders_histogram_via_prometheus_client():
    pytest.importorskip("prometheus_client")

    class FakeHistogramCollector(CollectorBase):
        def __init__(self, hist: Histogram) -> None:
            super().__init__(netns="fw")
            self._hist = hist

        def collect(self) -> list[_MetricFamily]:
            fam = _MetricFamily("x_latency_seconds", "help",
                                ["netns"], mtype="histogram")
            fam.add_histogram(["fw"], self._hist)
            return [fam]

    hist = Histogram([0.01, 0.1, 1.0])
    for v in [0.005, 0.05, 0.5, 2.0]:
        hist.observe(v)

    reg = ShorewalldRegistry()
    reg.add(FakeHistogramCollector(hist))
    prom_families = reg.to_prom_families()
    assert len(prom_families) == 1
    mf = prom_families[0]
    # prometheus_client expands the histogram into bucket / count / sum
    # samples; make sure all three are present.
    names = {s.name for s in mf.samples}
    assert "x_latency_seconds_bucket" in names
    assert "x_latency_seconds_count" in names
    assert "x_latency_seconds_sum" in names
