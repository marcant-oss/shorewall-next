"""Bogon/RFC-special IP ranges provider.

No HTTP fetch required — all data is hardcoded from the relevant RFCs.

Filter dimensions:

* ``type`` — ``bogon`` (default: both v4 and v6), ``ipv4_only``,
  ``ipv6_only``.

The bogon list covers:

IPv4 (RFC 1122, RFC 1918, RFC 6598, RFC 5737, RFC 3927, RFC 2544,
RFC 919, RFC 1112):
  0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
  169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
  192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
  224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32

IPv6 (RFC 4291, RFC 6052, RFC 6666, RFC 2928, RFC 5180, RFC 3849,
RFC 3068, RFC 4193, RFC 4291):
  ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 100::/64,
  2001::/32, 2001:2::/48, 2001:db8::/32, 2002::/16, fc00::/7,
  fe80::/10, ff00::/8
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, ClassVar

from ..protocol import FetchResult

if TYPE_CHECKING:
    import aiohttp

_V4_BOGONS: frozenset[str] = frozenset({
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
})

_V6_BOGONS: frozenset[str] = frozenset({
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "100::/64",
    "2001::/32",
    "2001:2::/48",
    "2001:db8::/32",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
})

# Serialised sentinel payload — avoids parsing overhead on every extract().
_SENTINEL_RAW: bytes = json.dumps({
    "v4": sorted(_V4_BOGONS),
    "v6": sorted(_V6_BOGONS),
}).encode()


class BogonProvider:
    name: ClassVar[str] = "bogon"
    source_url: ClassVar[str] = "(hardcoded — no network fetch)"
    filter_dimensions: ClassVar[list[str]] = ["type"]

    async def fetch(
        self,
        session: aiohttp.ClientSession,  # noqa: ARG002
        etag: str | None,               # noqa: ARG002
        last_modified: str | None,      # noqa: ARG002
    ) -> FetchResult:
        """Return the hardcoded bogon data immediately, no HTTP needed."""
        return FetchResult(
            raw=_SENTINEL_RAW,
            etag="bogon-v1",
            last_modified=None,
            not_modified=False,
        )

    def extract(
        self,
        raw: bytes,
        filters: dict[str, list[str]],
    ) -> tuple[set[str], set[str]]:
        # raw is always _SENTINEL_RAW; we re-parse for API consistency.
        data = json.loads(raw)
        type_filter = filters.get("type", ["bogon"])
        # Normalise — take the first value if multiple given.
        kind = (type_filter[0] if type_filter else "bogon").lower()

        if kind == "ipv4_only":
            return set(data["v4"]), set()
        if kind == "ipv6_only":
            return set(), set(data["v6"])
        # Default: both.
        return set(data["v4"]), set(data["v6"])

    def list_dimension(self, raw: bytes, dimension: str) -> list[str]:
        if dimension == "type":
            return ["bogon", "ipv4_only", "ipv6_only"]
        return []
