"""IpListTracker — fetches cloud prefix lists and writes nft interval sets.

Runs as a long-lived asyncio task.  On startup it fetches all configured
lists and applies the diff against the kernel.  Afterwards it re-fetches
each list on its own ``refresh`` schedule.

Key design choices:
* Writes directly via ``NftInterface.cmd()`` — NOT through ``SetWriter``,
  which is for DNS TTL-based sets only.
* nft ``flags interval`` sets: add/delete in batches of 200 prefixes per
  nft script to avoid overly long command strings.
* HTTP backoff per list: 60 → 120 → 300 → 3600 s on consecutive failures,
  reset to 0 on success.
* ETag / Last-Modified caching per list to avoid unnecessary downloads.
* ``max_prefixes`` safety cap: if the fetched list exceeds the cap, the
  write is skipped and an ERROR is logged.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..logsetup import get_rate_limiter

if TYPE_CHECKING:
    from shorewall_nft.nft.netlink import NftInterface

    from ..discover import NetnsProfile
    from ..exporter import ShorewalldRegistry
    from .protocol import IpListConfig

log = logging.getLogger("shorewalld.iplist")

# HTTP retry back-off schedule (seconds).
_BACKOFF = (60, 120, 300, 3600)
# Maximum prefixes per nft add/delete command.
_CHUNK_SIZE = 200


@dataclass
class _ListState:
    """Runtime state for one IpListConfig."""

    cfg: IpListConfig
    etag: str | None = None
    last_modified: str | None = None
    last_refresh_ts: float = 0.0
    current_v4: set[str] = field(default_factory=set)
    current_v6: set[str] = field(default_factory=set)
    consecutive_errors: int = 0


class IpListMetrics:
    """Lightweight metrics compatible with ShorewalldRegistry.collect()."""

    def __init__(self) -> None:
        # name -> {family: count}
        self._prefixes: dict[str, dict[str, int]] = {}
        # name -> timestamp
        self._last_refresh: dict[str, float] = {}
        # name -> fetch_durations
        self._fetch_durations: dict[str, list[float]] = {}
        # name -> {reason: count}
        self._fetch_errors: dict[str, dict[str, int]] = {}
        # name -> {op: count}
        self._updates: dict[str, dict[str, int]] = {}

    def set_prefixes(self, name: str, n_v4: int, n_v6: int) -> None:
        self._prefixes[name] = {"v4": n_v4, "v6": n_v6}

    def record_refresh(self, name: str) -> None:
        self._last_refresh[name] = time.time()

    def record_fetch_duration(self, name: str, duration: float) -> None:
        self._fetch_durations.setdefault(name, []).append(duration)
        # Keep a bounded window of the last 100 samples.
        if len(self._fetch_durations[name]) > 100:
            self._fetch_durations[name] = self._fetch_durations[name][-100:]

    def record_fetch_error(self, name: str, reason: str) -> None:
        self._fetch_errors.setdefault(name, {})
        self._fetch_errors[name][reason] = (
            self._fetch_errors[name].get(reason, 0) + 1
        )

    def record_update(self, name: str, op: str, count: int) -> None:
        self._updates.setdefault(name, {})
        self._updates[name][op] = self._updates[name].get(op, 0) + count

    def collect(self) -> list[Any]:
        """Return metric families for ShorewalldRegistry."""
        # Import here to avoid hard dep at module level.
        try:
            from shorewalld.exporter import _MetricFamily
        except ImportError:
            return []

        families: list[Any] = []

        # shorewalld_iplist_prefixes_total{name, family}
        fam = _MetricFamily(
            name="shorewalld_iplist_prefixes_total",
            help_text="Number of IP prefixes in each iplist set",
            mtype="gauge",
            labels=["name", "family"],
        )
        for name, counts in self._prefixes.items():
            for fam_label, count in counts.items():
                fam.add([name, fam_label], float(count))
        families.append(fam)

        # shorewalld_iplist_last_refresh_timestamp{name}
        fam2 = _MetricFamily(
            name="shorewalld_iplist_last_refresh_timestamp",
            help_text="Unix timestamp of last successful iplist refresh",
            mtype="gauge",
            labels=["name"],
        )
        for name, ts in self._last_refresh.items():
            fam2.add([name], ts)
        families.append(fam2)

        # shorewalld_iplist_fetch_errors_total{name, reason}
        fam3 = _MetricFamily(
            name="shorewalld_iplist_fetch_errors_total",
            help_text="Total fetch errors per iplist name and reason",
            mtype="counter",
            labels=["name", "reason"],
        )
        for name, reasons in self._fetch_errors.items():
            for reason, count in reasons.items():
                fam3.add([name, reason], float(count))
        families.append(fam3)

        # shorewalld_iplist_updates_total{name, op}
        fam4 = _MetricFamily(
            name="shorewalld_iplist_updates_total",
            help_text="Total nft set element additions/removals per iplist",
            mtype="counter",
            labels=["name", "op"],
        )
        for name, ops in self._updates.items():
            for op, count in ops.items():
                fam4.add([name, op], float(count))
        families.append(fam4)

        return families


class IpListTracker:
    """Fetches and maintains nft interval sets for all configured IP lists.

    Usage::

        tracker = IpListTracker(configs, nft, profiles)
        task = asyncio.create_task(tracker.run())
        ...
        task.cancel()
    """

    def __init__(
        self,
        configs: list[IpListConfig],
        nft: NftInterface,
        profiles: dict[str, NetnsProfile],
        registry: ShorewalldRegistry | None = None,
    ) -> None:
        self._configs = configs
        self._nft = nft
        self._profiles = profiles
        self._states: dict[str, _ListState] = {
            cfg.name: _ListState(cfg=cfg) for cfg in configs
        }
        # Per-list lock serialises _do_refresh so concurrent control-socket
        # refresh_one/refresh_all calls (and the background _list_loop) don't
        # interleave fetch → diff → apply against the same state.
        self._list_locks: dict[str, asyncio.Lock] = {
            cfg.name: asyncio.Lock() for cfg in configs
        }
        self._metrics = IpListMetrics()
        self._rate_limiter = get_rate_limiter()
        self._stop_event = asyncio.Event()
        self._refresh_tasks: dict[str, asyncio.Task[None]] = {}

        if registry is not None:
            registry.add(self._metrics)  # type: ignore[arg-type]

    # ── Public API ────────────────────────────────────────────────────

    async def run(self) -> None:
        """Main loop. Runs until cancelled or shutdown is requested."""
        log.info(
            "iplist tracker: starting with %d list(s)", len(self._configs)
        )
        # Ensure aiohttp is available.
        try:
            import aiohttp  # noqa: F401
        except ImportError:
            log.error(
                "iplist tracker: aiohttp not installed; "
                "install with pip install shorewalld[iplist]"
            )
            return

        # Start one refresh task per configured list.
        for cfg in self._configs:
            task = asyncio.create_task(
                self._list_loop(self._states[cfg.name]),
                name=f"shorewalld.iplist.{cfg.name}",
            )
            self._refresh_tasks[cfg.name] = task

        # Wait until all tasks finish (cancelled on stop).
        try:
            await asyncio.gather(
                *self._refresh_tasks.values(), return_exceptions=True
            )
        except asyncio.CancelledError:
            pass
        finally:
            for task in self._refresh_tasks.values():
                task.cancel()

    async def refresh_all(self) -> None:
        """Force an immediate refresh of all configured lists."""
        await asyncio.gather(
            *[self._do_refresh(self._states[n]) for n in self._states],
            return_exceptions=True,
        )

    async def refresh_one(self, name: str) -> None:
        """Force an immediate refresh of the named list."""
        state = self._states.get(name)
        if state is None:
            log.warning("iplist: refresh_one: unknown list %r", name)
            return
        await self._do_refresh(state)

    def status(self) -> list[dict]:
        """Return a status summary for each configured list."""
        result = []
        for name, state in self._states.items():
            result.append({
                "name": name,
                "provider": state.cfg.provider,
                "v4_prefixes": len(state.current_v4),
                "v6_prefixes": len(state.current_v6),
                "last_refresh": state.last_refresh_ts,
                "consecutive_errors": state.consecutive_errors,
                "set_v4": state.cfg.set_v4,
                "set_v6": state.cfg.set_v6,
            })
        return result

    # ── Internal loop ─────────────────────────────────────────────────

    async def _list_loop(self, state: _ListState) -> None:
        """Per-list refresh loop with exponential back-off."""
        # Initial fetch on startup.
        await self._do_refresh(state)

        while True:
            if state.consecutive_errors > 0:
                idx = min(state.consecutive_errors - 1, len(_BACKOFF) - 1)
                delay = _BACKOFF[idx]
                log.warning(
                    "iplist.%s: backing off %ds after %d consecutive error(s)",
                    state.cfg.name, delay, state.consecutive_errors,
                )
            else:
                delay = state.cfg.refresh

            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                return

            await self._do_refresh(state)

    async def _do_refresh(self, state: _ListState) -> None:
        """Fetch, extract, diff, and write one list."""
        async with self._list_locks[state.cfg.name]:
            await self._do_refresh_locked(state)

    async def _do_refresh_locked(self, state: _ListState) -> None:
        import aiohttp

        cfg = state.cfg
        list_log = logging.getLogger(f"shorewalld.iplist.{cfg.name}")

        try:
            from .providers import get_provider
            provider_cls = get_provider(cfg.provider)
        except KeyError as e:
            log.error("iplist.%s: %s", cfg.name, e)
            state.consecutive_errors += 1
            self._metrics.record_fetch_error(cfg.name, "unknown_provider")
            return

        provider = provider_cls()
        t0 = time.monotonic()

        # ── Fetch ──────────────────────────────────────────────────
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60),
                headers={"User-Agent": "shorewalld/1.0 (iplist tracker)"},
            ) as session:
                result = await provider.fetch(
                    session, state.etag, state.last_modified
                )
        except Exception as e:
            elapsed = time.monotonic() - t0
            state.consecutive_errors += 1
            reason = type(e).__name__
            self._metrics.record_fetch_error(cfg.name, reason)
            self._rate_limiter.warn(
                list_log,
                ("fetch_error", cfg.name),
                "fetch failed: %s", e,
            )
            log.debug(
                "iplist.%s: fetch error in %.1fs (error #%d): %s",
                cfg.name, elapsed, state.consecutive_errors, e,
            )
            return

        elapsed_fetch = time.monotonic() - t0
        self._metrics.record_fetch_duration(cfg.name, elapsed_fetch)

        if result.not_modified:
            list_log.debug("no change (304 Not Modified)")
            state.consecutive_errors = 0
            return

        # Update cache headers for next fetch.
        if result.etag:
            state.etag = result.etag
        if result.last_modified:
            state.last_modified = result.last_modified

        # ── Extract ────────────────────────────────────────────────
        try:
            new_v4, new_v6 = provider.extract(result.raw, cfg.filters)
        except Exception as e:
            state.consecutive_errors += 1
            self._metrics.record_fetch_error(cfg.name, "parse_error")
            log.error("iplist.%s: parse error: %s", cfg.name, e)
            return

        # Warn if filter matched nothing.
        if not new_v4 and not new_v6:
            self._rate_limiter.warn(
                list_log,
                ("empty_filter", cfg.name),
                "filter matched 0 prefixes — check filter config",
            )

        total = len(new_v4) + len(new_v6)
        if total > cfg.max_prefixes:
            log.error(
                "iplist.%s: %d prefixes exceeds max_prefixes=%d — skipping write",
                cfg.name, total, cfg.max_prefixes,
            )
            self._metrics.record_fetch_error(cfg.name, "max_prefixes_exceeded")
            state.consecutive_errors += 1
            return

        # ── Apply diff ─────────────────────────────────────────────
        t1 = time.monotonic()
        total_added = 0
        total_removed = 0
        n_netns = 0
        apply_errors = 0

        for netns, profile in self._profiles.items():
            if not profile.has_table:
                continue
            n_netns += 1

            if cfg.set_v4:
                a, r = await self._apply_set(
                    netns, cfg.set_v4, state.current_v4, new_v4,
                    cfg.name, "v4",
                )
                total_added += a
                total_removed += r
                if a < 0:
                    apply_errors += 1

            if cfg.set_v6:
                a, r = await self._apply_set(
                    netns, cfg.set_v6, state.current_v6, new_v6,
                    cfg.name, "v6",
                )
                total_added += a
                total_removed += r
                if a < 0:
                    apply_errors += 1

        # Update in-memory state only after all writes succeeded
        # (or were partially applied — best effort).
        state.current_v4 = new_v4
        state.current_v6 = new_v6

        elapsed = time.monotonic() - t0
        state.last_refresh_ts = time.time()
        state.consecutive_errors = 0

        self._metrics.set_prefixes(cfg.name, len(new_v4), len(new_v6))
        self._metrics.record_refresh(cfg.name)
        if total_added:
            self._metrics.record_update(cfg.name, "add", total_added)
        if total_removed:
            self._metrics.record_update(cfg.name, "remove", total_removed)

        etag_note = f" etag={result.etag}" if result.etag else ""
        if total_added == 0 and total_removed == 0:
            list_log.debug(
                "refresh complete — %d v4 + %d v6 prefixes (no delta) "
                "across %d netns [%.1fs%s]",
                len(new_v4), len(new_v6), n_netns, elapsed, etag_note,
            )
        else:
            list_log.info(
                "refresh complete — %d v4 + %d v6 prefixes "
                "(+%d added, -%d removed) across %d netns [%.1fs%s]",
                len(new_v4), len(new_v6),
                total_added, total_removed,
                n_netns, elapsed, etag_note,
            )

    async def _apply_set(
        self,
        netns: str,
        set_name: str,
        current: set[str],
        new: set[str],
        list_name: str,
        family: str,
    ) -> tuple[int, int]:
        """Compute and apply the diff for one set in one netns.

        Returns ``(added, removed)`` counts, or ``(-1, 0)`` on error.
        """
        to_add = new - current
        to_remove = current - new

        nft_netns = netns or None

        if to_add:
            for chunk in _chunks(to_add, _CHUNK_SIZE):
                elements = ", ".join(chunk)
                script = (
                    f"add element inet shorewall {set_name} "
                    f"{{ {elements} }}"
                )
                try:
                    self._nft.cmd(script, netns=nft_netns)
                except Exception as e:
                    log.error(
                        "iplist.%s: nft add element to %s (netns=%r) failed: %s",
                        list_name, set_name, netns, e,
                    )
                    self._metrics.record_fetch_error(list_name, "nft_write_error")
                    return -1, 0

        if to_remove:
            for chunk in _chunks(to_remove, _CHUNK_SIZE):
                elements = ", ".join(chunk)
                script = (
                    f"delete element inet shorewall {set_name} "
                    f"{{ {elements} }}"
                )
                try:
                    self._nft.cmd(script, netns=nft_netns)
                except Exception as e:
                    # Elements already absent is not fatal.
                    log.debug(
                        "iplist.%s: nft delete element from %s (netns=%r): %s",
                        list_name, set_name, netns, e,
                    )

        return len(to_add), len(to_remove)


def _chunks(items: set[str], size: int):
    """Yield successive chunks of at most *size* items from *items*."""
    it = iter(items)
    while True:
        chunk = []
        for _ in range(size):
            try:
                chunk.append(next(it))
            except StopIteration:
                break
        if not chunk:
            return
        yield chunk
