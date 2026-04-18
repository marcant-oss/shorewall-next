"""Provider registry for shorewalld.iplist.

Built-in providers are registered eagerly.  Third-party providers may
be registered via the ``shorewalld.iplist_providers`` entry-point group
(setuptools / importlib.metadata).

Usage::

    from shorewalld.iplist.providers import get_provider, REGISTRY

    cls = get_provider("aws")
    provider = cls()
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..protocol import IpListProvider

log = logging.getLogger("shorewalld.iplist")

# Registry: provider name → provider class
REGISTRY: dict[str, type[IpListProvider]] = {}


def _register_builtins() -> None:
    """Register all built-in providers into REGISTRY."""
    from .aws import AwsProvider
    from .azure import AzureProvider
    from .bogon import BogonProvider
    from .cloudflare import CloudflareProvider
    from .gcp import GcpProvider
    from .github import GithubProvider
    from .peeringdb import PeeringDbProvider

    for cls in (
        AwsProvider,
        AzureProvider,
        BogonProvider,
        CloudflareProvider,
        GcpProvider,
        GithubProvider,
        PeeringDbProvider,
    ):
        REGISTRY[cls.name] = cls  # type: ignore[attr-defined]


def _load_entry_points() -> None:
    """Load external providers via the ``shorewalld.iplist_providers`` group."""
    try:
        from importlib.metadata import entry_points
        eps = entry_points(group="shorewalld.iplist_providers")
        for ep in eps:
            try:
                cls = ep.load()
                REGISTRY[cls.name] = cls
            except Exception:
                log.exception(
                    "iplist: failed to load provider entry-point %r", ep.name)
    except Exception:
        log.debug("iplist: entry-point discovery failed (harmless)")


_register_builtins()
_load_entry_points()


def get_provider(name: str) -> type[IpListProvider]:
    """Return the provider class for *name*.

    Raises :class:`KeyError` if not found.
    """
    try:
        return REGISTRY[name]
    except KeyError:
        available = ", ".join(sorted(REGISTRY))
        raise KeyError(
            f"unknown iplist provider {name!r}; "
            f"available: {available}"
        ) from None
