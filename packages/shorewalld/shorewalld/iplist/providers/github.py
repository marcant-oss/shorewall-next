"""GitHub IP ranges provider.

Source: ``https://api.github.com/meta``

Filter dimensions:

* ``group`` — one of ``actions``, ``api``, ``copilot``, ``dependabot``,
  ``git``, ``hooks``, ``packages``, ``pages``, ``web``, etc.  Supports
  glob patterns.

The ``meta`` endpoint returns a JSON object where each top-level key
(other than ``verifiable_password_authentication`` and similar non-list
fields) contains a list of CIDR strings.
"""

from __future__ import annotations

import fnmatch
import json
from typing import TYPE_CHECKING, ClassVar

from ..protocol import FetchResult

if TYPE_CHECKING:
    import aiohttp

_KNOWN_GROUPS = frozenset({
    "actions", "api", "copilot", "dependabot", "git",
    "hooks", "packages", "pages", "web",
})


class GithubProvider:
    name: ClassVar[str] = "github"
    source_url: ClassVar[str] = "https://api.github.com/meta"
    filter_dimensions: ClassVar[list[str]] = ["group"]

    async def fetch(
        self,
        session: aiohttp.ClientSession,
        etag: str | None,
        last_modified: str | None,
    ) -> FetchResult:
        headers: dict[str, str] = {"Accept": "application/json"}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        async with session.get(self.source_url, headers=headers) as resp:
            if resp.status == 304:
                return FetchResult(
                    raw=b"",
                    etag=etag,
                    last_modified=last_modified,
                    not_modified=True,
                )
            if resp.status != 200:
                from ..fetcher import FetchError
                body = await resp.text()
                raise FetchError(self.source_url, resp.status, body[:200])
            raw = await resp.read()
            return FetchResult(
                raw=raw,
                etag=resp.headers.get("ETag"),
                last_modified=resp.headers.get("Last-Modified"),
                not_modified=False,
            )

    def _iter_groups(
        self, data: dict, group_pats: list[str]
    ):
        """Yield (group_name, prefix_list) pairs that match patterns."""
        for key, value in data.items():
            if not isinstance(value, list):
                continue
            # Only yield groups whose values look like CIDR strings.
            if not value or not isinstance(value[0], str):
                continue
            if group_pats and not any(
                fnmatch.fnmatchcase(key, p) for p in group_pats
            ):
                continue
            yield key, value

    def extract(
        self,
        raw: bytes,
        filters: dict[str, list[str]],
    ) -> tuple[set[str], set[str]]:
        data = json.loads(raw)
        group_pats = [g.lower() for g in filters.get("group", [])]

        v4: set[str] = set()
        v6: set[str] = set()

        for _grp, prefixes in self._iter_groups(data, group_pats):
            for prefix in prefixes:
                if not prefix:
                    continue
                if ":" in prefix:
                    v6.add(prefix)
                else:
                    v4.add(prefix)

        return v4, v6

    def list_dimension(self, raw: bytes, dimension: str) -> list[str]:
        if dimension != "group":
            return []
        data = json.loads(raw)
        values: list[str] = []
        for key, value in data.items():
            if isinstance(value, list) and value and isinstance(value[0], str):
                values.append(key)
        return sorted(values)
