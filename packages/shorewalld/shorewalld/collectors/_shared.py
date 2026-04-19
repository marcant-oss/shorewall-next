"""Small helpers shared by more than one collector.

Kept private (underscore name + not re-exported in
:mod:`shorewalld.collectors.__init__`) — callers outside the collectors
package should not depend on these.
"""

from __future__ import annotations

from typing import Protocol


class _FileReader(Protocol):
    """Minimal duck type matching ``WorkerRouter`` for procfile reads.

    Same shape as :class:`shorewalld.exporter._FileReader`; re-declared
    here so each collector module imports it locally without pulling in
    the whole exporter module.
    """

    def read_file_sync(
        self, netns: str, path: str, *, timeout: float = ...,
    ) -> bytes | None: ...

    def count_lines_sync(
        self, netns: str, path: str, *, timeout: float = ...,
    ) -> int | None: ...


# AF_INET / AF_INET6 → short label; used by neighbour + address
# collectors. Anything else renders as ``af<number>`` so novel families
# don't silently merge.
_AF_NAMES: dict[int, str] = {2: "ipv4", 10: "ipv6"}


def _read_int_via_router(
    router: "_FileReader", netns: str, path: str,
) -> int | None:
    """Decode a single-integer ``/proc``/``/sys`` file via the router.

    Returns ``None`` when the file is missing, the worker is down, or
    the content isn't a valid integer — callers simply skip the sample
    in that case.
    """
    data = router.read_file_sync(netns, path)
    if data is None:
        return None
    try:
        return int(data.strip())
    except ValueError:
        return None
