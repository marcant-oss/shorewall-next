"""NfSetsManager — translate a ``register-instance`` nfsets payload into backend configs.

Wave 3 deliverable.  Wave 4 (``core.py`` wiring) will instantiate this class
and pass the returned configs to the appropriate trackers.

Usage::

    mgr = NfSetsManager(payload)        # payload["nfsets"] from control socket
    dns_reg, dnsr_reg = mgr.dns_registries()   # feed DnsSetTracker.load_registry()
    iplist_cfgs = mgr.iplist_configs()         # feed IpListTracker
    plain_cfgs  = mgr.plain_list_configs()     # feed PlainListTracker
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shorewall_nft.nft.dns_sets import DnsrRegistry, DnsSetRegistry
    from shorewall_nft.nft.nfsets import NfSetRegistry

    from .iplist.plain import PlainListConfig
    from .iplist.protocol import IpListConfig

log = logging.getLogger("shorewalld.nfsets_manager")

# Default refresh intervals (seconds) per backend when not specified in the
# nfsets config.
_DEFAULT_REFRESH_IPLIST = 3600
_DEFAULT_REFRESH_PLAIN = 3600


class NfSetsManager:
    """Translate the nfsets payload from ``register-instance`` into tracker inputs.

    Parameters
    ----------
    payload:
        The dict sent under ``req["nfsets"]`` by ``shorewall-nft``.
        Accepts an empty ``{}`` (no-op) or a full ``{"entries": [...]}``
        dict produced by :func:`~shorewall_nft.nft.nfsets.nfset_registry_to_payload`.
    """

    def __init__(self, payload: dict) -> None:
        self._registry: "NfSetRegistry | None" = None
        if not payload:
            return
        try:
            from shorewall_nft.nft.nfsets import payload_to_nfset_registry
            self._registry = payload_to_nfset_registry(payload)
        except Exception as exc:
            log.error("nfsets_manager: failed to parse payload: %s", exc)
            self._registry = None

    # ── Public API ────────────────────────────────────────────────────────────

    def dns_registries(self) -> "tuple[DnsSetRegistry, DnsrRegistry]":
        """Extract ``dnstap`` and ``resolver`` entries into tracker-ready registries.

        Delegates to :func:`~shorewall_nft.nft.dns_sets.nfset_registry_to_dns_registries`
        from the core package.  Returns ``(DnsSetRegistry, DnsrRegistry)`` — both empty
        when the payload was empty or contained no DNS-backed entries.
        """
        from shorewall_nft.nft.dns_sets import (
            DnsrRegistry,
            DnsSetRegistry,
            nfset_registry_to_dns_registries,
        )

        if self._registry is None or not self._registry.entries:
            return DnsSetRegistry(), DnsrRegistry()

        return nfset_registry_to_dns_registries(self._registry)

    def iplist_configs(self) -> "list[IpListConfig]":
        """Extract ``ip-list`` entries as :class:`~shorewall_nft.iplist.protocol.IpListConfig` objects.

        Each entry maps to one :class:`~shorewalld.iplist.protocol.IpListConfig`:

        * ``name`` → ``"nfset_<entry.name>"``
        * ``hosts[0]`` → ``provider`` key understood by the iplist provider registry
        * ``options["filter"]`` → ``filters`` dict (each value split on ``"="``
          into dimension/pattern pairs for provider-agnostic filtering)
        * ``entry.refresh`` → ``refresh`` (default :data:`_DEFAULT_REFRESH_IPLIST`)
        * ``set_v4`` / ``set_v6`` → derived from ``nfset_to_set_name(entry.name, "v4/v6")``
        """
        from shorewall_nft.nft.nfsets import nfset_to_set_name

        from .iplist.protocol import IpListConfig

        if self._registry is None:
            return []

        configs: list[IpListConfig] = []
        for entry in self._registry.entries:
            if entry.backend != "ip-list":
                continue
            provider = entry.hosts[0] if entry.hosts else ""
            if not provider:
                log.warning(
                    "nfsets_manager: ip-list entry %r has no hosts (provider key) — skipping",
                    entry.name,
                )
                continue

            filters = _parse_filter_options(entry.options.get("filter", []))
            refresh = entry.refresh if entry.refresh is not None else _DEFAULT_REFRESH_IPLIST

            cfg = IpListConfig(
                name=f"nfset_{entry.name}",
                provider=provider,
                filters=filters,
                set_v4=nfset_to_set_name(entry.name, "v4"),
                set_v6=nfset_to_set_name(entry.name, "v6"),
                refresh=refresh,
            )
            configs.append(cfg)

        return configs

    def plain_list_configs(self) -> "list[PlainListConfig]":
        """Extract ``ip-list-plain`` entries as :class:`~shorewalld.iplist.plain.PlainListConfig` objects.

        Each entry maps to one :class:`~shorewalld.iplist.plain.PlainListConfig`:

        * ``name`` → ``"nfset_<entry.name>"``
        * ``hosts[0]`` → ``source`` (URL, absolute path, or ``exec:`` string)
        * ``entry.refresh`` → ``refresh`` (default :data:`_DEFAULT_REFRESH_PLAIN`)
        * ``entry.inotify`` → ``inotify``
        * ``set_v4`` / ``set_v6`` derived via ``nfset_to_set_name``
        """
        from shorewall_nft.nft.nfsets import nfset_to_set_name

        from .iplist.plain import PlainListConfig

        if self._registry is None:
            return []

        configs: list[PlainListConfig] = []
        for entry in self._registry.entries:
            if entry.backend != "ip-list-plain":
                continue
            source = entry.hosts[0] if entry.hosts else ""
            if not source:
                log.warning(
                    "nfsets_manager: ip-list-plain entry %r has no source — skipping",
                    entry.name,
                )
                continue

            refresh = entry.refresh if entry.refresh is not None else _DEFAULT_REFRESH_PLAIN

            cfg = PlainListConfig(
                name=f"nfset_{entry.name}",
                source=source,
                refresh=refresh,
                inotify=entry.inotify,
                set_v4=nfset_to_set_name(entry.name, "v4"),
                set_v6=nfset_to_set_name(entry.name, "v6"),
            )
            configs.append(cfg)

        return configs


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_filter_options(filter_values: list[str]) -> "dict[str, list[str]]":
    """Convert a list of ``"dim=value"`` strings into a filters dict.

    Each value is expected in the form ``"dimension=pattern"``; values without
    an ``=`` are stored under the dimension ``"value"``.  Multiple values for
    the same dimension accumulate into a list.

    Example::

        _parse_filter_options(["region=us-east-1", "service=EC2"])
        # → {"region": ["us-east-1"], "service": ["EC2"]}
    """
    result: dict[str, list[str]] = {}
    for item in filter_values:
        if "=" in item:
            dim, _, pat = item.partition("=")
            dim = dim.strip().lower()
            pat = pat.strip()
        else:
            dim = "value"
            pat = item.strip()
        if dim and pat:
            result.setdefault(dim, []).append(pat)
    return result
