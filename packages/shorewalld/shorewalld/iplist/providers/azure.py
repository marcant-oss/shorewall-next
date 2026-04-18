"""Azure Service Tags provider.

Source: Microsoft's Service Tags JSON file.  Microsoft changes the URL
with every weekly update, so the URL must be supplied by the operator
via ``IPLIST_<NAME>_FILTER_URL=<actual-url>`` or accepted as a filter
dimension value with the key ``url``.

A static fallback URL is provided for documentation purposes only.

Filter dimensions:

* ``tag``  — Service Tag name, e.g. ``AzureActiveDirectory``, also
  accepts ``Tag.Region`` style (e.g. ``Storage.EastUS``).
  Supports exact match (case-insensitive) and glob patterns.
* ``url``  — Override the download URL.  Accepts exactly one value.
"""

from __future__ import annotations

import fnmatch
import json
from typing import TYPE_CHECKING, ClassVar

from ..fetcher import http_fetch
from ..protocol import FetchResult

if TYPE_CHECKING:
    import aiohttp

# Placeholder URL — operators MUST override via filter url:...
_DEFAULT_URL = (
    "https://download.microsoft.com/download/7/1/D/"
    "71D86715-5596-4529-9B13-DA13A5DE5B63/"
    "ServiceTags_Public_20240101.json"
)


class AzureProvider:
    name: ClassVar[str] = "azure"
    source_url: ClassVar[str] = _DEFAULT_URL
    filter_dimensions: ClassVar[list[str]] = ["tag", "url"]

    async def fetch(
        self,
        session: aiohttp.ClientSession,
        etag: str | None,
        last_modified: str | None,
    ) -> FetchResult:
        return await http_fetch(session, self.source_url, etag, last_modified)

    def _get_url(self, filters: dict[str, list[str]]) -> str:
        url_overrides = filters.get("url", [])
        return url_overrides[0] if url_overrides else self.source_url

    async def fetch_with_filters(
        self,
        session: aiohttp.ClientSession,
        filters: dict[str, list[str]],
        etag: str | None,
        last_modified: str | None,
    ) -> FetchResult:
        url = self._get_url(filters)
        return await http_fetch(session, url, etag, last_modified)

    def extract(
        self,
        raw: bytes,
        filters: dict[str, list[str]],
    ) -> tuple[set[str], set[str]]:
        data = json.loads(raw)
        tag_pats = [t.lower() for t in filters.get("tag", [])]

        v4: set[str] = set()
        v6: set[str] = set()

        for item in data.get("values", []):
            tag_name = (item.get("name") or "").lower()
            if tag_pats and not any(
                fnmatch.fnmatchcase(tag_name, p) for p in tag_pats
            ):
                continue
            props = item.get("properties") or {}
            for prefix in props.get("addressPrefixes") or []:
                if not prefix:
                    continue
                if ":" in prefix:
                    v6.add(prefix)
                else:
                    v4.add(prefix)

        return v4, v6

    def list_dimension(self, raw: bytes, dimension: str) -> list[str]:
        if dimension not in ("tag",):
            return []
        data = json.loads(raw)
        values: set[str] = set()
        for item in data.get("values", []):
            name = item.get("name") or ""
            if name:
                values.add(name)
        return sorted(values)
