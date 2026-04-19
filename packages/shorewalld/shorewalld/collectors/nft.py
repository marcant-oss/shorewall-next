"""NftCollector — per-rule + named-counter + set-element metrics."""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, NftScraper, _MetricFamily


class NftCollector(CollectorBase):
    """Per-rule + named-counter + set-element metrics for one netns."""

    def __init__(self, netns: str, scraper: NftScraper) -> None:
        super().__init__(netns)
        self._scraper = scraper

    def collect(self) -> list[_MetricFamily]:
        snap = self._scraper.snapshot(self.netns)

        packets = _MetricFamily(
            "shorewall_nft_packets_total",
            "Per-rule packet count in the inet shorewall table",
            ["netns", "table", "chain", "rule_handle", "comment"],
            mtype="counter")
        bytes_ = _MetricFamily(
            "shorewall_nft_bytes_total",
            "Per-rule byte count in the inet shorewall table",
            ["netns", "table", "chain", "rule_handle", "comment"],
            mtype="counter")
        named_pk = _MetricFamily(
            "shorewall_nft_named_counter_packets_total",
            "Named counter object packet count",
            ["netns", "name"],
            mtype="counter")
        named_by = _MetricFamily(
            "shorewall_nft_named_counter_bytes_total",
            "Named counter object byte count",
            ["netns", "name"],
            mtype="counter")
        set_el = _MetricFamily(
            "shorewall_nft_set_elements",
            "Element count of named sets in the inet shorewall table",
            ["netns", "set"])

        if not snap.has_table:
            return [packets, bytes_, named_pk, named_by, set_el]

        for rc in snap.rule_counters:
            labels = [
                self.netns,
                str(rc.get("table", "")),
                str(rc.get("chain", "")),
                str(rc.get("handle", 0)),
                str(rc.get("comment", "")),
            ]
            packets.add(labels, float(rc.get("packets", 0)))
            bytes_.add(labels, float(rc.get("bytes", 0)))

        for name, vals in snap.named_counters.items():
            named_pk.add([self.netns, name], float(vals.get("packets", 0)))
            named_by.add([self.netns, name], float(vals.get("bytes", 0)))

        for name, n in snap.sets.items():
            set_el.add([self.netns, name], float(n))

        return [packets, bytes_, named_pk, named_by, set_el]
