"""NeighbourCollector — ARP / ND cache entry counts per (iface, family, state)."""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, _MetricFamily

from ._shared import _AF_NAMES

# Linux NUD_* bitmask → human name, ordered by priority (most specific
# first). An entry usually has a single bit set, but NUD_NOARP +
# NUD_PERMANENT can combine — we pick the first match, which is the
# one an operator cares about.
_NEIGH_STATE_BITS: list[tuple[int, str]] = [
    (0x80, "permanent"),   # NUD_PERMANENT
    (0x40, "noarp"),       # NUD_NOARP
    (0x20, "failed"),      # NUD_FAILED
    (0x10, "probe"),       # NUD_PROBE
    (0x08, "delay"),       # NUD_DELAY
    (0x04, "stale"),       # NUD_STALE
    (0x02, "reachable"),   # NUD_REACHABLE
    (0x01, "incomplete"),  # NUD_INCOMPLETE
]


def _neigh_state_name(state: int) -> str:
    """Translate a NUD_* bitmask to a single label value."""
    if state == 0:
        return "none"
    for bit, name in _NEIGH_STATE_BITS:
        if state & bit:
            return name
    return "unknown"


class NeighbourCollector(CollectorBase):
    """ARP / ND cache entry counts per ``(iface, family, state)``.

    One ``get_neighbours()`` + ``get_links()`` pair per scrape inside
    the target netns (``IPRoute(netns=…)``). Gateway / next-hop health
    is directly visible — a spike in ``state="failed"`` means the
    next-hop stopped answering.
    """

    def collect(self) -> list[_MetricFamily]:
        count = _MetricFamily(
            "shorewall_nft_neigh_count",
            "Neighbour table entries by state",
            ["netns", "iface", "family", "state"])

        try:
            from pyroute2 import IPRoute  # type: ignore[import-untyped]
        except ImportError:
            return [count]

        kwargs = {"netns": self.netns} if self.netns else {}
        try:
            ipr = IPRoute(**kwargs)
        except Exception:
            return [count]
        try:
            links = ipr.get_links()
            neighs = ipr.get_neighbours()
        except Exception:
            return [count]
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

        counts: dict[tuple[str, str, str], int] = {}
        for n in neighs:
            try:
                ifindex = int(n.get("ifindex", 0))
                family_raw = int(n.get("family", 0))
                state_raw = int(n.get("state", 0))
            except (AttributeError, TypeError, ValueError):
                continue
            iface = idx_to_name.get(ifindex, f"ifindex{ifindex}")
            family = _AF_NAMES.get(family_raw, f"af{family_raw}")
            state = _neigh_state_name(state_raw)
            key = (iface, family, state)
            counts[key] = counts.get(key, 0) + 1

        for (iface, family, state), n in counts.items():
            count.add(
                [self.netns, iface, family, state], float(n))

        return [count]
