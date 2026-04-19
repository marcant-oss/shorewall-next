"""FlowtableCollector — flowtable existence + attached-device count.

Reuses the :class:`~shorewalld.exporter.NftScraper` snapshot so it adds
zero netlink round-trips; the flowtable walk was folded into the same
``list table`` call that drives :class:`~shorewalld.collectors.nft.NftCollector`.
"""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, NftScraper, _MetricFamily


class FlowtableCollector(CollectorBase):
    """Flowtable existence + attached-device count per netns.

    Live flow counts per flowtable are NOT emitted: libnftables' JSON
    view of a flowtable carries only its definition (hook, prio,
    devices, flags), not the transient flow entries. Operators who want
    flow visibility should alert on
    ``shorewall_nft_flowtable_devices == 0`` (interface detached) and on
    a missing ``shorewall_nft_flowtable_exists`` sample (flowtable
    removed by a faulty reload).
    """

    def __init__(self, netns: str, scraper: NftScraper) -> None:
        super().__init__(netns)
        self._scraper = scraper

    def collect(self) -> list[_MetricFamily]:
        devices = _MetricFamily(
            "shorewall_nft_flowtable_devices",
            "Number of interfaces attached to the flowtable",
            ["netns", "name"])
        exists = _MetricFamily(
            "shorewall_nft_flowtable_exists",
            "1 for every configured flowtable",
            ["netns", "name", "hook"])

        snap = self._scraper.snapshot(self.netns)
        for ft in snap.flowtables:
            name = str(ft.get("name", ""))
            hook = str(ft.get("hook", ""))
            devs = ft.get("devices") or []
            devices.add([self.netns, name], float(len(devs)))
            exists.add([self.netns, name, hook], 1.0)

        return [devices, exists]
