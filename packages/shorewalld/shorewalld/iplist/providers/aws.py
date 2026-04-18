"""AWS IP Ranges provider.

Source: ``https://ip-ranges.amazonaws.com/ip-ranges.json``

Filter dimensions:

* ``service`` — e.g. ``EC2``, ``S3``, ``CLOUDFRONT`` (exact match,
  case-insensitive)
* ``region``  — e.g. ``eu-west-1``, supports glob patterns via
  ``fnmatch`` (e.g. ``eu-*``)
"""

from __future__ import annotations

import fnmatch
import json
from typing import TYPE_CHECKING, ClassVar

from ..fetcher import http_fetch
from ..protocol import FetchResult

if TYPE_CHECKING:
    import aiohttp


class AwsProvider:
    name: ClassVar[str] = "aws"
    source_url: ClassVar[str] = (
        "https://ip-ranges.amazonaws.com/ip-ranges.json"
    )
    filter_dimensions: ClassVar[list[str]] = ["service", "region"]

    # ── IpListProvider ────────────────────────────────────────────────

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
        service_pats = [s.upper() for s in filters.get("service", [])]
        region_pats = filters.get("region", [])

        v4: set[str] = set()
        v6: set[str] = set()

        for entry in data.get("prefixes", []):
            svc = (entry.get("service") or "").upper()
            reg = entry.get("region") or ""
            prefix = entry.get("ip_prefix") or ""
            if not prefix:
                continue
            if service_pats and not any(
                fnmatch.fnmatchcase(svc, p) for p in service_pats
            ):
                continue
            if region_pats and not any(
                fnmatch.fnmatchcase(reg, p) for p in region_pats
            ):
                continue
            v4.add(prefix)

        for entry in data.get("ipv6_prefixes", []):
            svc = (entry.get("service") or "").upper()
            reg = entry.get("region") or ""
            prefix = entry.get("ipv6_prefix") or ""
            if not prefix:
                continue
            if service_pats and not any(
                fnmatch.fnmatchcase(svc, p) for p in service_pats
            ):
                continue
            if region_pats and not any(
                fnmatch.fnmatchcase(reg, p) for p in region_pats
            ):
                continue
            v6.add(prefix)

        return v4, v6

    def list_dimension(self, raw: bytes, dimension: str) -> list[str]:
        data = json.loads(raw)
        if dimension == "service":
            values: set[str] = set()
            for entry in data.get("prefixes", []):
                svc = entry.get("service") or ""
                if svc:
                    values.add(svc)
            for entry in data.get("ipv6_prefixes", []):
                svc = entry.get("service") or ""
                if svc:
                    values.add(svc)
            return sorted(values)
        if dimension == "region":
            values = set()
            for entry in data.get("prefixes", []):
                reg = entry.get("region") or ""
                if reg:
                    values.add(reg)
            for entry in data.get("ipv6_prefixes", []):
                reg = entry.get("region") or ""
                if reg:
                    values.add(reg)
            return sorted(values)
        return []
