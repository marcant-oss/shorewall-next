"""HTTP fetch helper for IP-list providers.

Uses ``aiohttp`` for all network access.  Supports conditional GET via
``ETag`` / ``If-None-Match`` and ``Last-Modified`` / ``If-Modified-Since``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .protocol import FetchResult

if TYPE_CHECKING:
    import aiohttp


class FetchError(Exception):
    """Raised when the server returns an unexpected status code."""

    def __init__(self, url: str, status: int, message: str) -> None:
        self.url = url
        self.status = status
        self.message = message
        super().__init__(f"HTTP {status} from {url}: {message}")


async def http_fetch(
    session: aiohttp.ClientSession,
    url: str,
    etag: str | None = None,
    last_modified: str | None = None,
) -> FetchResult:
    """Fetch *url* with optional conditional-GET headers.

    Sets ``If-None-Match`` when *etag* is provided and
    ``If-Modified-Since`` when *last_modified* is provided.

    Returns:
        :class:`FetchResult` with ``not_modified=True`` on HTTP 304,
        or the full body + caching headers on HTTP 200.

    Raises:
        :class:`FetchError` for any status other than 200 or 304.
    """
    headers: dict[str, str] = {}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    async with session.get(url, headers=headers) as resp:
        if resp.status == 304:
            return FetchResult(
                raw=b"",
                etag=etag,
                last_modified=last_modified,
                not_modified=True,
            )
        if resp.status != 200:
            body = await resp.text()
            raise FetchError(url, resp.status, body[:200])
        raw = await resp.read()
        return FetchResult(
            raw=raw,
            etag=resp.headers.get("ETag"),
            last_modified=resp.headers.get("Last-Modified"),
            not_modified=False,
        )
