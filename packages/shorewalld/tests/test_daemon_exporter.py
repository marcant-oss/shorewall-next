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
    _MetricFamily,
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
