"""GCP Cloud IP Ranges provider.

Source: ``https://www.gstatic.com/ipranges/cloud.json``

Filter dimensions:

* ``service`` — e.g. ``Google Cloud``, ``Google APIs``.  Exact match,
  case-insensitive.
* ``scope``   — region or ``"global"`` (case-insensitive).  Supports
  glob patterns.
"""

from __future__ import annotations

import fnmatch
import json
from typing import TYPE_CHECKING, ClassVar

from ..fetcher import http_fetch
from ..protocol import FetchResult

if TYPE_CHECKING:
    import aiohttp


class GcpProvider:
    name: ClassVar[str] = "gcp"
    source_url: ClassVar[str] = (
        "https://www.gstatic.com/ipranges/cloud.json"
    )
    filter_dimensions: ClassVar[list[str]] = ["service", "scope"]

    async def fetch(
        self,
        session: aiohttp.ClientSession,
        etag: str | None,
        last_modified: str | None,
    ) -> FetchResult:
        return await http_fetch(session, self.source_url, etag, last_modified)

    def extract(
        self,
        raw: bytes,
        filters: dict[str, list[str]],
    ) -> tuple[set[str], set[str]]:
        data = json.loads(raw)
        service_pats = [s.lower() for s in filters.get("service", [])]
        scope_pats = [s.lower() for s in filters.get("scope", [])]

        v4: set[str] = set()
        v6: set[str] = set()

        for entry in data.get("prefixes", []):
            svc = (entry.get("service") or "").lower()
            scope = (entry.get("scope") or "").lower()

            if service_pats and not any(
                fnmatch.fnmatchcase(svc, p) for p in service_pats
            ):
                continue
            if scope_pats and not any(
                fnmatch.fnmatchcase(scope, p) for p in scope_pats
            ):
                continue

            v4_prefix = entry.get("ipv4Prefix") or ""
            v6_prefix = entry.get("ipv6Prefix") or ""
            if v4_prefix:
                v4.add(v4_prefix)
            if v6_prefix:
                v6.add(v6_prefix)

        return v4, v6

    def list_dimension(self, raw: bytes, dimension: str) -> list[str]:
        data = json.loads(raw)
        values: set[str] = set()
        for entry in data.get("prefixes", []):
            if dimension == "service":
                val = entry.get("service") or ""
            elif dimension == "scope":
                val = entry.get("scope") or ""
            else:
                val = ""
            if val:
                values.add(val)
        return sorted(values)
