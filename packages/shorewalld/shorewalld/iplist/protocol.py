"""Protocol types for the iplist subsystem.

``IpListConfig``   — per-list operator configuration
``IpListProvider`` — Protocol that every provider must satisfy
``FetchResult``    — what :func:`~fetcher.http_fetch` returns
``parse_iplist_configs`` — parse raw config-file stanzas
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Protocol

if TYPE_CHECKING:
    import aiohttp


@dataclass
class FetchResult:
    """Result of a single HTTP fetch attempt."""

    raw: bytes
    """Raw response body (empty when not_modified is True)."""

    etag: str | None
    """ETag response header value, if present."""

    last_modified: str | None
    """Last-Modified response header value, if present."""

    not_modified: bool = False
    """True when the server returned HTTP 304."""


@dataclass
class IpListConfig:
    """Operator-defined configuration for one IP prefix list."""

    name: str
    """Logical name, e.g. ``"aws_ec2_eu"``."""

    provider: str
    """Provider key, e.g. ``"aws"``, ``"azure"``, ``"bogon"``."""

    filters: dict[str, list[str]] = field(default_factory=dict)
    """Provider-specific filter dimensions.

    Keys are dimension names (``"service"``, ``"region"``, etc.),
    values are lists of match patterns (glob-style where documented).
    """

    set_v4: str | None = None
    """nft set name for IPv4 prefixes. ``None`` = skip IPv4."""

    set_v6: str | None = None
    """nft set name for IPv6 prefixes. ``None`` = skip IPv6."""

    refresh: int = 3600
    """Seconds between refreshes (default: 3600)."""

    max_prefixes: int = 100_000
    """Safety cap on the total number of prefixes (v4 + v6)."""


class IpListProvider(Protocol):
    """Protocol that every provider implementation must satisfy.

    Providers are stateless classes.  The tracker instantiates them
    once and calls :meth:`fetch` / :meth:`extract` on every refresh
    cycle.
    """

    name: ClassVar[str]
    """Registry key, e.g. ``"aws"``."""

    source_url: ClassVar[str]
    """Canonical URL for the dataset (for documentation / ``--help``)."""

    filter_dimensions: ClassVar[list[str]]
    """Dimension names accepted by :meth:`extract` / :meth:`list_dimension`."""

    async def fetch(
        self,
        session: aiohttp.ClientSession,
        etag: str | None,
        last_modified: str | None,
    ) -> FetchResult:
        """Fetch the provider's data source.

        Pass *etag* and *last_modified* from the previous successful
        fetch so the server can respond with HTTP 304 if nothing changed.
        """
        ...

    def extract(
        self,
        raw: bytes,
        filters: dict[str, list[str]],
    ) -> tuple[set[str], set[str]]:
        """Extract matching prefixes from *raw*.

        Returns ``(v4_prefixes, v6_prefixes)`` as CIDR strings.
        """
        ...

    def list_dimension(self, raw: bytes, dimension: str) -> list[str]:
        """Return the sorted list of available values for *dimension*.

        Used by ``shorewalld iplist filters <provider>``.
        """
        ...


# ── Config parser ────────────────────────────────────────────────────


def _apply_glob_filter(values: list[str], patterns: list[str]) -> bool:
    """Return True if *values* matches ANY of *patterns* (glob)."""
    for val in values:
        for pat in patterns:
            if fnmatch.fnmatchcase(val, pat):
                return True
    return False


_KNOWN_FIELDS = frozenset({
    "PROVIDER", "SET_V4", "SET_V6", "REFRESH", "MAX_PREFIXES",
})
# Fields with a sub-key: FILTER_<dim>
_KNOWN_FIELD_PREFIXES = ("FILTER_",)


def _split_iplist_key(rest: str) -> tuple[str, str] | None:
    """Split ``<NAME>_<FIELD>`` into ``(name, field)``.

    The field must be one of the known field names or start with a
    known field prefix.  The name is everything before the matched
    field suffix.  This handles compound names like ``AWS_EC2``.
    Returns ``None`` if no known field suffix is found.
    """
    # Try each possible split point (right-to-left so compound names
    # like AWS_EC2 are preferred over single-segment names).
    parts = rest.split("_")
    # Try from longest field suffix backwards.
    for i in range(1, len(parts)):
        field = "_".join(parts[i:])
        name = "_".join(parts[:i]).lower()
        if not name:
            continue
        if field in _KNOWN_FIELDS:
            return name, field
        for pfx in _KNOWN_FIELD_PREFIXES:
            if field.startswith(pfx):
                return name, field
    return None


def parse_iplist_configs(
    raw: dict[str, str],
) -> list[IpListConfig]:
    """Parse a flat ``IPLIST_<NAME>_<FIELD>=value`` dict into configs.

    ``raw`` is the full config-file dict.  Only keys starting with
    ``IPLIST_`` are examined.  Every ``IPLIST_<NAME>_PROVIDER`` key
    starts a new config; other ``_<FIELD>`` suffixes populate it.

    Filter keys use the form ``IPLIST_<NAME>_FILTER_<DIM>`` with a
    comma-separated value list.

    Names may contain underscores (e.g. ``IPLIST_AWS_EC2_PROVIDER``
    → name ``aws_ec2``).  The parser resolves ambiguity by trying
    each possible split point from longest name to shortest and
    matching against the set of known field names.
    """
    # First pass: collect all IPLIST_<NAME>_<FIELD> keys.
    by_name: dict[str, dict[str, str]] = {}
    for key, value in raw.items():
        if not key.startswith("IPLIST_"):
            continue
        rest = key[len("IPLIST_"):]
        result = _split_iplist_key(rest)
        if result is None:
            continue
        name, field_key = result
        by_name.setdefault(name, {})[field_key] = value

    configs: list[IpListConfig] = []
    for name, fields in by_name.items():
        provider = fields.get("PROVIDER", "").strip()
        if not provider:
            continue
        filters: dict[str, list[str]] = {}
        for fk, fv in fields.items():
            if fk.startswith("FILTER_"):
                dim = fk[len("FILTER_"):].lower()
                filters[dim] = [v.strip() for v in fv.split(",") if v.strip()]

        def _int(key: str, default: int, _fields: dict = fields) -> int:
            try:
                return int(_fields.get(key, default))
            except (ValueError, TypeError):
                return default

        cfg = IpListConfig(
            name=name,
            provider=provider.lower(),
            filters=filters,
            set_v4=fields.get("SET_V4") or None,
            set_v6=fields.get("SET_V6") or None,
            refresh=_int("REFRESH", 3600),
            max_prefixes=_int("MAX_PREFIXES", 100_000),
        )
        configs.append(cfg)
    return configs
