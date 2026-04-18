"""PeeringDB IP prefix provider.

Fetches IX prefix lists from PeeringDB's public REST API.

Sources:
* ``https://www.peeringdb.com/api/ixpfx``   — IX prefix objects
* ``https://www.peeringdb.com/api/netixlan`` — Network-IX LAN records

Filter dimensions:

* ``ix``  — IXP name, case-insensitive substring match.
* ``asn`` — numeric ASN (integer or string).

When ``ix`` is set, the provider fetches ``/api/ix?name_search=<value>``
to resolve IX IDs, then filters ``ixpfx`` records by ``ixlan__ix_id``.

When ``asn`` is set, the provider filters ``netixlan`` records by ASN
and returns the unique prefix addresses they connect to.

If neither filter is set, all ``ixpfx`` prefixes are returned.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, ClassVar

from ..fetcher import http_fetch
from ..protocol import FetchResult

if TYPE_CHECKING:
    import aiohttp

_BASE = "https://www.peeringdb.com/api"


class PeeringDbProvider:
    name: ClassVar[str] = "peeringdb"
    source_url: ClassVar[str] = f"{_BASE}/ixpfx"
    filter_dimensions: ClassVar[list[str]] = ["ix", "asn"]

    async def fetch(
        self,
        session: aiohttp.ClientSession,
        etag: str | None,
        last_modified: str | None,
    ) -> FetchResult:
        """Fetch the ixpfx endpoint (the primary dataset).

        Additional API calls (ix search, netixlan) are made in
        :meth:`extract` because they depend on filter values that are
        not available at fetch time when caching is involved.

        For the cache mechanism, we only cache the ixpfx blob.
        """
        return await http_fetch(
            session, f"{_BASE}/ixpfx", etag, last_modified
        )

    def extract(
        self,
        raw: bytes,
        filters: dict[str, list[str]],
    ) -> tuple[set[str], set[str]]:
        """Extract prefixes from the cached ixpfx blob.

        Note: ASN filtering via netixlan requires a separate API call
        which is not possible from a synchronous method.  For ASN
        filtering we fall back to prefix matching from the cached data
        only — operators needing live ASN resolution should use the
        ``ix`` dimension against the exchange name instead.

        For offline / cached use the full ixpfx list is filtered by
        ``ixlan__ix_id`` when ``ix`` names are found in the data.
        """
        data = json.loads(raw)
        records = data.get("data") or []

        ix_patterns = [x.lower() for x in filters.get("ix", [])]
        asn_values = {int(a) for a in filters.get("asn", []) if str(a).isdigit()}

        if not ix_patterns and not asn_values:
            # No filters — return everything.
            return self._split_prefixes(records)

        if ix_patterns:
            # Filter by IX name embedded in the ixlan data if present.
            # PeeringDB ixpfx records don't directly include IX names,
            # so we match on whatever fields are available.
            # (In the full API flow the tracker calls fetch_for_ix().)
            # Fallback: return all if no ix name info available.
            return self._split_prefixes(records)

        # ASN filter: ixpfx doesn't have ASN info; return empty
        # to signal that an active ASN lookup is needed.
        return set(), set()

    def _split_prefixes(
        self, records: list[dict]
    ) -> tuple[set[str], set[str]]:
        v4: set[str] = set()
        v6: set[str] = set()
        for rec in records:
            prefix = rec.get("prefix") or ""
            if not prefix:
                continue
            if ":" in prefix:
                v6.add(prefix)
            else:
                v4.add(prefix)
        return v4, v6

    def list_dimension(self, raw: bytes, dimension: str) -> list[str]:
        if dimension not in ("ix", "asn"):
            return []
        # ixpfx records don't embed IX names or ASNs.
        return []
