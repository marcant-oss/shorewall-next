"""AddressCollector — counts of configured IP addresses per (iface, family)."""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, _MetricFamily

from ._shared import _AF_NAMES


class AddressCollector(CollectorBase):
    """Counts of configured IP addresses per ``(iface, family)``.

    One ``get_addr()`` + ``get_links()`` dump per scrape inside the
    target netns. A VIP disappearing during a VRRP flap drops this
    gauge from N+1 to N for the affected interface — easier to alert
    on than monitoring each address individually.
    """

    def collect(self) -> list[_MetricFamily]:
        addrs = _MetricFamily(
            "shorewall_nft_addrs",
            "Number of addresses configured on an interface",
            ["netns", "iface", "family"])

        try:
            from pyroute2 import IPRoute  # type: ignore[import-untyped]
        except ImportError:
            return [addrs]

        kwargs = {"netns": self.netns} if self.netns else {}
        try:
            ipr = IPRoute(**kwargs)
        except Exception:
            return [addrs]
        try:
            links = ipr.get_links()
            rows = ipr.get_addr()
        except Exception:
            return [addrs]
        finally:
            try:
                ipr.close()
            except Exception:
                pass

        idx_to_name: dict[int, str] = {}
        for link in links:
            ifname = link.get_attr("IFLA_IFNAME")
            if ifname is not None:
                idx_to_name[int(link.get("index", 0))] = ifname

        counts: dict[tuple[str, str], int] = {}
        for a in rows:
            try:
                ifindex = int(a.get("index", 0))
                family_raw = int(a.get("family", 0))
            except (AttributeError, TypeError, ValueError):
                continue
            iface = idx_to_name.get(ifindex, f"ifindex{ifindex}")
            family = _AF_NAMES.get(family_raw, f"af{family_raw}")
            counts[(iface, family)] = counts.get((iface, family), 0) + 1

        for (iface, family), n in counts.items():
            addrs.add([self.netns, iface, family], float(n))

        return [addrs]
