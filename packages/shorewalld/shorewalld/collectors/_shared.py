"""Small helpers shared by more than one collector.

Kept private (underscore name + not re-exported in
:mod:`shorewalld.collectors.__init__`) — callers outside the collectors
package should not depend on these.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from shorewalld.read_codec import CtNetlinkStats

log = logging.getLogger("shorewalld.collectors")


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


class _CtFileReader(Protocol):
    """Duck type for ``WorkerRouter`` as used by ``ConntrackStatsCollector``.

    Extends :class:`_FileReader` with the :meth:`ctnetlink_stats_sync`
    method added by the ``READ_KIND_CTNETLINK`` RPC.
    """

    def ctnetlink_stats_sync(
        self, netns: str, *, timeout: float = ...,
    ) -> "CtNetlinkStats | None": ...


# AF_INET / AF_INET6 → short label; used by neighbour + address
# collectors. Anything else renders as ``af<number>`` so novel families
# don't silently merge.
_AF_NAMES: dict[int, str] = {2: "ipv4", 10: "ipv6"}


# ── Cached pyroute2 IPRoute handles ─────────────────────────────────
#
# Four collectors (link, qdisc, neighbour, address) each open an
# ``IPRoute(netns=…)`` per scrape.  pyroute2 internally forks a child
# process to bind the netlink socket to the target netns.  With N
# managed namespaces and a 15 s scrape interval the overhead is small
# but wholly avoidable — one persistent handle per netns works fine.
#
# Lifetime:
#   Created lazily on first ``get_rtnl()`` call.
#   Shared by all four collectors across all scrapes.
#   Evicted (closed + removed from cache) when any pyroute2 call raises
#   ``NetlinkError`` (stale after a netns-del/add cycle).
#   Closed cleanly on daemon shutdown via ``close_all_rtnl()``.
#
# Thread-safety:
#   ``_RTNL_LOCK`` serialises mutations to ``_RTNL_BY_NETNS``.
#   pyroute2 ``IPRoute`` is NOT documented as thread-safe; collectors
#   run on the prometheus_client scrape thread, which is a single
#   background thread — no concurrent access to the same handle in
#   normal operation.  If that ever changes, callers must acquire a
#   per-handle lock before issuing netlink requests.

_RTNL_BY_NETNS: dict[str, "Any"] = {}  # key = netns str ("" for default)
_RTNL_LOCK = threading.Lock()


def get_rtnl(netns: str | None) -> "Any":
    """Return a cached ``IPRoute`` handle for *netns*.

    Created on first call; reused across all collectors and all scrapes.
    A single pyroute2 netns fork happens on first use — subsequent
    scrapes reuse the existing netlink socket.

    Pass ``netns=None`` or ``netns=""`` for the daemon's own namespace.

    Raises ``ImportError`` if pyroute2 is not installed; callers should
    handle this and return empty families (same as before).
    """
    from pyroute2 import IPRoute  # type: ignore[import-untyped]

    key = netns or ""
    with _RTNL_LOCK:
        ipr = _RTNL_BY_NETNS.get(key)
        if ipr is None:
            ipr = IPRoute(netns=netns) if netns else IPRoute()
            _RTNL_BY_NETNS[key] = ipr
        return ipr


def close_rtnl(netns: str | None) -> None:
    """Close and forget the cached handle for *netns*.

    Called when the netns has vanished and pyroute2 ops are raising
    ``NetlinkError``.  The next ``get_rtnl()`` call will re-open a
    fresh handle if the netns comes back.
    """
    key = netns or ""
    with _RTNL_LOCK:
        ipr = _RTNL_BY_NETNS.pop(key, None)
    if ipr is not None:
        try:
            ipr.close()
        except Exception:
            log.debug("close_rtnl(%r): close failed, ignoring", key)


def close_all_rtnl() -> None:
    """Close every cached ``IPRoute`` handle.

    Called on daemon shutdown.  A close failure is logged at DEBUG and
    swallowed — it must not prevent the rest of the shutdown sequence.
    """
    with _RTNL_LOCK:
        handles = list(_RTNL_BY_NETNS.items())
        _RTNL_BY_NETNS.clear()
    for key, ipr in handles:
        try:
            ipr.close()
        except Exception:
            log.debug("close_all_rtnl: close of %r failed, ignoring", key)


def rtnl_handles_cached() -> int:
    """Return the number of currently cached ``IPRoute`` handles.

    Exposed as a Prometheus gauge by :mod:`shorewalld.collectors.rtnl_gauge`
    via :func:`shorewalld.exporter.ShorewalldRegistry`.  Cheap: just
    ``len()`` on the in-memory dict.
    """
    with _RTNL_LOCK:
        return len(_RTNL_BY_NETNS)


# ── Optional gauge: cached handle count ─────────────────────────────


class RtnlHandlesCollector:
    """Single-sample gauge: number of live cached ``IPRoute`` handles.

    Not a :class:`~shorewalld.exporter.CollectorBase` subclass to avoid
    a circular import; it implements the same ``collect()`` protocol and
    is registered directly with ``ShorewalldRegistry``.
    """

    def collect(self) -> list:  # -> list[_MetricFamily] (avoids circular)
        from shorewalld.exporter import _MetricFamily  # lazy — no cycle at runtime
        fam = _MetricFamily(
            "shorewalld_rtnl_handles_cached",
            "Number of live cached pyroute2 IPRoute handles",
            [],
        )
        fam.add([], float(rtnl_handles_cached()))
        return [fam]


# ── /proc helpers ────────────────────────────────────────────────────


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
