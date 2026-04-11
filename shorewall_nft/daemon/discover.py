"""Netns discovery + per-netns profile assembly for shorewalld.

A ``NetnsProfile`` is the unit of heterogeneity: one list of
collectors per namespace. Production HA boxes run three namespaces
per node (``fw`` with the shorewall ruleset, ``rns1``/``rns2``
without one), and each gets a different collector mix.

Every profile always includes:

* ``LinkCollector`` — per-iface RX/TX via pyroute2
* ``CtCollector`` — conntrack table size via ``/proc/sys/net/...``

A profile *conditionally* includes:

* ``NftCollector`` — only when ``list table inet shorewall`` succeeds
  in that netns. A periodic re-probe loop adds/removes the collector
  as the operator loads/unloads the ruleset without having to
  restart the daemon.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from shorewall_nft.nft.netlink import NftError, NftInterface

from .exporter import (
    CtCollector,
    LinkCollector,
    NftCollector,
    NftScraper,
    ShorewalldRegistry,
)

log = logging.getLogger("shorewalld.discover")


NETNS_DIR = Path("/run/netns")


def list_named_netns(netns_dir: Path = NETNS_DIR) -> list[str]:
    """Return every named netns that exists under ``/run/netns/``.

    Sorted for determinism. Empty if the directory is missing
    (e.g. inside a minimal container).
    """
    if not netns_dir.is_dir():
        return []
    try:
        return sorted(p.name for p in netns_dir.iterdir() if p.is_file())
    except OSError:
        return []


def resolve_netns_list(spec: list[str] | str,
                       netns_dir: Path = NETNS_DIR) -> list[str]:
    """Resolve ``--netns`` into a concrete list of netns names.

    ``spec == "auto"`` walks ``/run/netns/`` and prepends the daemon's
    own netns (as ``""``). ``spec == [""]`` means "own netns only".
    Explicit lists are returned as-is.
    """
    if spec == "auto":
        own = [""]
        named = list_named_netns(netns_dir)
        return own + named
    if isinstance(spec, list):
        return spec
    return [""]


# ── NetnsProfile ─────────────────────────────────────────────────────


@dataclass
class NetnsProfile:
    """One netns's view: name + the collector bundle currently active."""

    name: str
    link_collector: LinkCollector
    ct_collector: CtCollector
    nft_collector: NftCollector | None = None
    has_table: bool = False
    collectors_added_to_registry: list[object] = field(default_factory=list)

    def close(self) -> None:
        """Best-effort teardown — called from Daemon._shutdown."""
        pass


class ProfileBuilder:
    """Assembles ``NetnsProfile`` objects and maintains them over time.

    One builder per Daemon. Owns the shared ``NftScraper`` cache and
    the ``ShorewalldRegistry``, and knows how to add/remove collectors
    as netns state changes.
    """

    def __init__(
        self,
        nft: NftInterface,
        registry: ShorewalldRegistry,
        scraper: NftScraper,
    ) -> None:
        self._nft = nft
        self._registry = registry
        self._scraper = scraper
        self._profiles: dict[str, NetnsProfile] = {}

    @property
    def profiles(self) -> dict[str, NetnsProfile]:
        return self._profiles

    def build(self, netns_names: list[str]) -> list[NetnsProfile]:
        """Create a fresh profile for every name and register its
        always-on collectors. NftCollector is NOT added yet — the
        first ``reprobe()`` call wires it up if the table is present.
        """
        for name in netns_names:
            if name in self._profiles:
                continue
            link = LinkCollector(name)
            ct = CtCollector(name)
            profile = NetnsProfile(name=name, link_collector=link,
                                   ct_collector=ct)
            self._registry.add(link)
            self._registry.add(ct)
            profile.collectors_added_to_registry.extend([link, ct])
            self._profiles[name] = profile
            log.info("shorewalld registered netns profile %r", name)
        return list(self._profiles.values())

    def reprobe(self) -> None:
        """Probe every profile for its nft table and add/remove the
        ``NftCollector`` accordingly. Called on startup and on a
        periodic ticker by ``Daemon``.
        """
        for profile in self._profiles.values():
            self._reprobe_one(profile)

    def _reprobe_one(self, profile: NetnsProfile) -> None:
        try:
            self._nft.cmd(
                "list table inet shorewall",
                netns=profile.name or None)
            has = True
        except NftError:
            has = False
        except OSError:
            has = False

        if has and profile.nft_collector is None:
            col = NftCollector(profile.name, self._scraper)
            self._registry.add(col)
            profile.nft_collector = col
            profile.collectors_added_to_registry.append(col)
            profile.has_table = True
            log.info("netns %r gained inet shorewall table", profile.name)
        elif not has and profile.nft_collector is not None:
            self._registry.remove(profile.nft_collector)
            try:
                profile.collectors_added_to_registry.remove(
                    profile.nft_collector)
            except ValueError:
                pass
            profile.nft_collector = None
            profile.has_table = False
            # Drop stale cache so the next scrape sees an empty
            # snapshot instead of the old rule counters.
            self._scraper.invalidate(profile.name)
            log.info("netns %r lost inet shorewall table", profile.name)
        profile.has_table = has

    def close_all(self) -> None:
        for profile in list(self._profiles.values()):
            for col in profile.collectors_added_to_registry:
                self._registry.remove(col)
            profile.close()
        self._profiles.clear()


# ── PID-safe named-netns probe ───────────────────────────────────────


def current_netns_inode() -> int | None:
    """Return the inode of the calling process's netns, or None on failure.

    Used to avoid registering the same netns twice (once as ``""``
    and once by name if the daemon is run inside a named netns).
    """
    try:
        return os.stat("/proc/self/ns/net").st_ino
    except OSError:
        return None
