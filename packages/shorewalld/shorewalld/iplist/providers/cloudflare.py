"""Cloudflare IP ranges provider.

Sources:
* ``https://www.cloudflare.com/ips-v4`` — one IPv4 CIDR per line
* ``https://www.cloudflare.com/ips-v6`` — one IPv6 CIDR per line

No filter dimensions.  All prefixes are always returned.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, ClassVar

from ..fetcher import http_fetch
from ..protocol import FetchResult

if TYPE_CHECKING:
    import aiohttp

_V4_URL = "https://www.cloudflare.com/ips-v4"
_V6_URL = "https://www.cloudflare.com/ips-v6"


class CloudflareProvider:
    name: ClassVar[str] = "cloudflare"
    source_url: ClassVar[str] = _V4_URL  # primary; v6 is fetched separately
    filter_dimensions: ClassVar[list[str]] = []

    async def fetch(
        self,
        session: aiohttp.ClientSession,
        etag: str | None,
        last_modified: str | None,
    ) -> FetchResult:
        """Fetch both v4 and v6 lists and combine into a JSON blob.

        The combined payload is stored as a JSON dict
        ``{"v4": [...], "v6": [...]}`` so :meth:`extract` can split
        them without re-fetching.  ETags from the v4 URL are used as
        the cache key (v6 usually refreshes at the same time).
        """
        v4_result = await http_fetch(session, _V4_URL, etag, last_modified)
        if v4_result.not_modified:
            return v4_result

        v6_result = await http_fetch(session, _V6_URL, None, None)

        v4_lines = [
            line.strip()
            for line in v4_result.raw.decode("ascii", errors="replace").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        v6_lines = [
            line.strip()
            for line in v6_result.raw.decode("ascii", errors="replace").splitlines()
            if line.strip() and not line.startswith("#")
        ]

        combined = json.dumps({"v4": v4_lines, "v6": v6_lines}).encode()
        return FetchResult(
            raw=combined,
            etag=v4_result.etag,
            last_modified=v4_result.last_modified,
            not_modified=False,
        )

    def extract(
        self,
        raw: bytes,
        filters: dict[str, list[str]],
    ) -> tuple[set[str], set[str]]:
        data = json.loads(raw)
        v4 = set(data.get("v4") or [])
        v6 = set(data.get("v6") or [])
        return v4, v6

    def list_dimension(self, raw: bytes, dimension: str) -> list[str]:
        # No dimensions supported.
        return []
