"""Phase 2 shorewalld exporter unit tests.

Feeds hand-built ``nftables`` JSON dicts into the collectors via a
``FakeNftInterface`` — no real netlink socket, no real ruleset, no
live netns. Exercises the core logic of ``NftCollector``,
``NftScraper`` caching, ``ShorewalldRegistry`` merging, and
``list_rule_counters`` walking.
"""
from __future__ import annotations

from typing import Any

from shorewalld.exporter import (
    CollectorBase,
    NftCollector,
    NftScraper,
    ShorewalldRegistry,
    _extract_qdisc_row,
    _format_tc_handle,
    _LINK_STAT_FIELDS,
    _MetricFamily,
    _QDISC_FIELDS,
)
from shorewall_nft.nft.netlink import NftError

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
