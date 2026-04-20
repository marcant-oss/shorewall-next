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

Large-set tuning
----------------
Five environment variables control the swap-rename path for large sets.
All are read at module import time; a daemon restart is required to
apply changes.

``SHOREWALLD_IPLIST_CHUNK_SIZE`` (default ``2000``, clamped to [100, 10000]):
  Maximum number of IP/CIDR elements per ``add element`` / ``delete element``
  nft command.  Larger values reduce round-trips but produce longer scripts.
  Applies to both the diff path and each ``add element`` chunk in the swap
  script.

``SHOREWALLD_IPLIST_SWAP_RENAME`` (default ``0``; set to ``1`` to enable):
  Master gate for the atomic swap-rename path.  When ``0`` the diff path is
  always used regardless of set size.  Flip to ``1`` only after observing
  ``shorewalld_iplist_apply_path_total`` metrics and confirming that diff
  performance is acceptable for your set sizes.

``SHOREWALLD_IPLIST_SWAP_ABS`` (default ``50000``):
  Absolute size threshold.  When the new element count is at or above this
  value *and* ``SWAP_RENAME=1``, the swap path is chosen.  Sets smaller
  than this always use the diff path (unless the fractional or autosize
  trigger fires).

``SHOREWALLD_IPLIST_SWAP_FRAC`` (default ``0.50``):
  Fractional-churn threshold.  When the absolute delta between old and new
  element counts exceeds this fraction of the current count (e.g. 50%
  churn), the swap path is chosen.  Keeps fast churn on large sets from
  generating huge diff scripts.

``SHOREWALLD_IPLIST_AUTOSIZE_HEADROOM`` (default ``0.90``):
  Fill-ratio autosize trigger.  When ``len(new) / declared_size`` is at or
  above this value, the swap path recreates the set with a larger capacity
  (next power-of-2 above ``max(len(new)*2, declared_size*2)``), capped at
  2^26 (64 M).  A WARNING is logged with the old and new sizes so the
  operator knows to raise ``size:`` in the nfsets config to match.
"""

from __future__ import annotations

import asyncio
import logging
import os
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
# Env-tunable: SHOREWALLD_IPLIST_CHUNK_SIZE (clamped to [100, 10000]).
_CHUNK_SIZE = max(100, min(10_000, int(os.environ.get("SHOREWALLD_IPLIST_CHUNK_SIZE", "2000"))))

# ── Swap-rename feature gate and thresholds ───────────────────────────────────
# Master gate: off by default.  Operator opts in after observing metrics.
_SWAP_ENABLED = os.environ.get("SHOREWALLD_IPLIST_SWAP_RENAME", "0") == "1"
# Absolute new-element count above which swap is preferred.
_SWAP_THRESHOLD_ABS = int(os.environ.get("SHOREWALLD_IPLIST_SWAP_ABS", "50000"))
# Fractional churn threshold (0..1) relative to current element count.
_SWAP_THRESHOLD_FRAC = float(os.environ.get("SHOREWALLD_IPLIST_SWAP_FRAC", "0.50"))
# Fill-ratio that triggers autosize (resize to larger power-of-2).
_AUTOSIZE_HEADROOM = float(os.environ.get("SHOREWALLD_IPLIST_AUTOSIZE_HEADROOM", "0.90"))
# Minimum set size for the autosize-triggered swap path (elements).
# Below this floor the proxy fill-ratio check is skipped to avoid spurious
# swap attempts on medium-sized sets whose declared capacity exceeds len(new).
# Set to match the default _SWAP_THRESHOLD_ABS so that only sets large enough
# to warrant swap attention even get the autosize fill-ratio check.
# Not exposed as an env var (operator uses SWAP_ABS for general size gating).
_AUTOSIZE_MIN_ELEMS = 50_000
# Hard cap on autosize upper bound: 2^26 = 64 M elements.
_AUTOSIZE_MAX = 67_108_864


def _next_pow2(n: int) -> int:
    """Return the smallest power of 2 >= *n* (minimum 1)."""
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()


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
        # (name, family) -> {sum: float, count: int}
        self._apply_durations: dict[tuple[str, str], dict[str, float]] = {}
        # (name, family) -> {path: count}
        self._apply_paths: dict[tuple[str, str], dict[str, int]] = {}
        # (name, family) -> {kind: value}  kind ∈ used/declared
        self._apply_capacity: dict[tuple[str, str], dict[str, int]] = {}

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

    def record_apply_duration(self, name: str, family: str, seconds: float) -> None:
        """Wall-clock time spent in _apply_set for one (list, family) pair."""
        key = (name, family)
        entry = self._apply_durations.setdefault(key, {"sum": 0.0, "count": 0})
        entry["sum"] += seconds
        entry["count"] += 1

    def record_apply_path(self, name: str, family: str, path: str) -> None:
        """Code path taken: 'diff' | 'swap' | 'fallback-from-swap'.

        Agent C will emit 'swap' and 'fallback-from-swap'; this module only
        emits 'diff'.
        """
        key = (name, family)
        entry = self._apply_paths.setdefault(key, {})
        entry[path] = entry.get(path, 0) + 1

    def record_apply_capacity(
        self, name: str, family: str, used: int, declared: int
    ) -> None:
        """Post-apply capacity check.

        Records how full the set is relative to its declared size.
        Emits a WARN log when used/declared >= 0.8.
        """
        key = (name, family)
        self._apply_capacity[key] = {"used": used, "declared": declared}
        if declared and used / declared >= 0.8:
            log.warning(
                "iplist.%s: %s set at %.0f%% capacity (%d/%d) — "
                "operator should raise `size:` in nfsets config",
                name, family, used / declared * 100.0, used, declared,
            )

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

        # shorewalld_iplist_apply_duration_seconds_sum{list, family}
        fam5 = _MetricFamily(
            name="shorewalld_iplist_apply_duration_seconds_sum",
            help_text="Cumulative wall-clock seconds spent in _apply_set per (list, family)",
            mtype="counter",
            labels=["list", "family"],
        )
        # shorewalld_iplist_apply_duration_seconds_count{list, family}
        fam6 = _MetricFamily(
            name="shorewalld_iplist_apply_duration_seconds_count",
            help_text="Number of _apply_set calls per (list, family)",
            mtype="counter",
            labels=["list", "family"],
        )
        for (lname, fam_label), entry in self._apply_durations.items():
            fam5.add([lname, fam_label], entry["sum"])
            fam6.add([lname, fam_label], float(entry["count"]))
        families.append(fam5)
        families.append(fam6)

        # shorewalld_iplist_apply_path_total{list, family, path}
        fam7 = _MetricFamily(
            name="shorewalld_iplist_apply_path_total",
            help_text="Apply code-path counts per (list, family, path); path ∈ diff/swap/fallback/saturated",
            mtype="counter",
            labels=["list", "family", "path"],
        )
        for (lname, fam_label), paths in self._apply_paths.items():
            for path, count in paths.items():
                fam7.add([lname, fam_label, path], float(count))
        families.append(fam7)

        # shorewalld_iplist_set_capacity{list, family, kind}  kind ∈ used/declared
        fam8 = _MetricFamily(
            name="shorewalld_iplist_set_capacity",
            help_text="nft set element count (used) and declared size per (list, family)",
            mtype="gauge",
            labels=["list", "family", "kind"],
        )
        # shorewalld_iplist_set_headroom_ratio{list, family}  — 1.0 means full
        fam9 = _MetricFamily(
            name="shorewalld_iplist_set_headroom_ratio",
            help_text="Fraction of declared set capacity in use (1.0 = full) per (list, family)",
            mtype="gauge",
            labels=["list", "family"],
        )
        for (lname, fam_label), cap in self._apply_capacity.items():
            fam8.add([lname, fam_label, "used"], float(cap["used"]))
            fam8.add([lname, fam_label, "declared"], float(cap["declared"]))
            if cap["declared"]:
                ratio = cap["used"] / cap["declared"]
            else:
                ratio = 0.0
            fam9.add([lname, fam_label], ratio)
        families.append(fam8)
        families.append(fam9)

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

    # Kernel error substrings that indicate the nft set is full.
    _SET_FULL_MARKERS = ("Set is full", "Cannot resize", "No space left on device")

    async def _apply_set(
        self,
        netns: str,
        set_name: str,
        current: set[str],
        new: set[str],
        list_name: str,
        family: str,
    ) -> tuple[int, int]:
        """Compute and apply the diff (or atomic swap-rename) for one set in one netns.

        Returns ``(added, removed)`` counts, or ``(-1, 0)`` on error.

        Path selection
        ~~~~~~~~~~~~~~
        When ``_SWAP_ENABLED`` is ``True`` and one of the three triggers fires
        (absolute size, large churn fraction, or autosize headroom), the method
        probes the existing set's metadata via libnftables JSON, constructs a
        single atomic script (``add set`` → ``add element`` × N chunks →
        ``delete set`` → ``rename set``), and submits it in one ``cmd()`` call.

        On ANY failure during the swap path the method falls back to the
        standard diff path, emits ``record_apply_path("fallback-from-swap")``,
        and then emits ``record_apply_path("diff")`` to keep per-path totals
        consistent.
        """
        t_start = time.monotonic()
        nft_netns = netns or None

        # ── Decide whether to attempt the swap path ───────────────────────
        total_delta = abs(len(new) - len(current))
        # Proxy fill_ratio for the autosize trigger: use len(current) as the
        # declared_size approximation (in steady state len(current) ≈ declared
        # size).  Only computed when len(new) >= _AUTOSIZE_MIN_ELEMS to avoid
        # spurious swap attempts on tiny sets.
        _proxy_declared = max(len(current), 1) if current else max(len(new), 1)
        _proxy_fill_ratio = (
            len(new) / _proxy_declared if len(new) >= _AUTOSIZE_MIN_ELEMS else 0.0
        )
        use_swap = _SWAP_ENABLED and (
            len(new) >= _SWAP_THRESHOLD_ABS
            or (current and total_delta / max(1, len(current)) >= _SWAP_THRESHOLD_FRAC)
            or _proxy_fill_ratio >= _AUTOSIZE_HEADROOM
        )

        if use_swap:
            ok, added, removed, elapsed = await self._try_swap_rename(
                nft_netns, set_name, current, new, list_name, family, t_start
            )
            if ok:
                return added, removed
            # Fallback: drop through to diff path below.
            self._metrics.record_apply_path(list_name, family, "fallback-from-swap")
            # Re-read t_start so diff timing excludes the failed swap attempt.
            t_start = time.monotonic()

        # ── Standard diff path ────────────────────────────────────────────
        to_add = new - current
        to_remove = current - new

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
                    err_str = str(e)
                    if any(m in err_str for m in self._SET_FULL_MARKERS):
                        log.error(
                            "iplist.%s: set %s (netns=%r) is full — "
                            "raise `size:` in nfsets config: %s",
                            list_name, set_name, netns, e,
                        )
                        self._metrics.record_fetch_error(
                            list_name, "set_capacity_exceeded"
                        )
                    else:
                        log.error(
                            "iplist.%s: nft add element to %s (netns=%r) failed: %s",
                            list_name, set_name, netns, e,
                        )
                        self._metrics.record_fetch_error(list_name, "nft_write_error")
                    elapsed = time.monotonic() - t_start
                    self._metrics.record_apply_duration(list_name, family, elapsed)
                    self._metrics.record_apply_path(list_name, family, "diff")
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

        elapsed = time.monotonic() - t_start
        self._metrics.record_apply_duration(list_name, family, elapsed)
        self._metrics.record_apply_path(list_name, family, "diff")

        # ── Capacity probe (non-fatal) ─────────────────────────────────────
        try:
            result = self._nft.cmd(
                f"list set inet shorewall {set_name}",
                netns=nft_netns,
                json_output=True,
            )
            # libnftables JSON shape:
            # {"nftables": [..., {"set": {"name": ..., "size": N, "elem": [...]}}]}
            declared = 0
            if isinstance(result, dict):
                for entry in result.get("nftables", []):
                    if isinstance(entry, dict) and "set" in entry:
                        declared = entry["set"].get("size", 0)
                        break
            used = len(new)
            self._metrics.record_apply_capacity(list_name, family, used, declared)
        except Exception as exc:
            log.debug(
                "iplist.%s: capacity probe failed: %s (non-fatal)", list_name, exc
            )

        return len(to_add), len(to_remove)

    async def _try_swap_rename(
        self,
        nft_netns: str | None,
        set_name: str,
        current: set[str],
        new: set[str],
        list_name: str,
        family: str,
        t_start: float,
    ) -> tuple[bool, int, int, float]:
        """Attempt an atomic swap-rename for *set_name*.

        Returns ``(success, added, removed, elapsed)``.  On any failure returns
        ``(False, 0, 0, 0.0)`` so the caller can fall back to the diff path.
        The caller is responsible for emitting ``fallback-from-swap`` when
        ``success`` is ``False``.
        """
        # Step 1: probe current set metadata.
        try:
            probe = self._nft.cmd(
                f"list set inet shorewall {set_name}",
                netns=nft_netns,
                json_output=True,
            )
        except Exception as exc:
            log.warning(
                "iplist.%s: swap probe failed for %s — will fall back to diff: %s",
                list_name, set_name, exc,
            )
            return False, 0, 0, 0.0

        # Step 2: parse the probe result.
        try:
            set_type, set_flags, declared_size = _parse_set_probe(probe)
        except Exception as exc:
            log.warning(
                "iplist.%s: swap probe parse error for %s — will fall back to diff: %s",
                list_name, set_name, exc,
            )
            return False, 0, 0, 0.0

        # Step 3: re-evaluate autosize trigger with the real declared_size.
        fill_ratio = len(new) / max(1, declared_size)
        if fill_ratio >= _AUTOSIZE_HEADROOM:
            new_size = min(
                _next_pow2(max(len(new) * 2, declared_size * 2)),
                _AUTOSIZE_MAX,
            )
            log.warning(
                "iplist.%s: autosize %s %d → %d (fill %.0f%%, "
                "operator should raise `size:` in nfsets config to match)",
                list_name, set_name, declared_size, new_size, fill_ratio * 100,
            )
        else:
            new_size = declared_size if declared_size else max(len(new) * 2, 65536)

        # Step 4: build and submit one atomic script.
        tmp_name = f"{set_name}_new"
        flags_str = ", ".join(set_flags) if set_flags else ""
        flags_line = f" flags {flags_str};" if flags_str else ""
        script_lines = [
            f"add set inet shorewall {tmp_name} {{ type {set_type};{flags_line} size {new_size}; }}",
        ]
        for chunk in _chunks(new, _CHUNK_SIZE):
            elements = ", ".join(chunk)
            script_lines.append(
                f"add element inet shorewall {tmp_name} {{ {elements} }}"
            )
        script_lines.append(f"delete set inet shorewall {set_name}")
        script_lines.append(f"rename set inet shorewall {tmp_name} {set_name}")
        script = "\n".join(script_lines)

        try:
            self._nft.cmd(script, netns=nft_netns)
        except Exception as exc:
            log.warning(
                "iplist.%s: swap script rejected for %s — will fall back to diff: %s",
                list_name, set_name, exc,
            )
            return False, 0, 0, 0.0

        elapsed = time.monotonic() - t_start
        self._metrics.record_apply_duration(list_name, family, elapsed)
        self._metrics.record_apply_path(list_name, family, "swap")
        self._metrics.record_apply_capacity(list_name, family, len(new), new_size)

        return True, len(new), len(current), elapsed


def _parse_set_probe(probe: object) -> tuple[str, list[str], int]:
    """Extract (type_str, flags_list, size) from a libnftables JSON probe result.

    Raises ``ValueError`` if the probe result is not in the expected shape.
    """
    if not isinstance(probe, dict):
        raise ValueError(f"probe result is not a dict: {type(probe)!r}")
    nftables = probe.get("nftables", [])
    for entry in nftables:
        if isinstance(entry, dict) and "set" in entry:
            s = entry["set"]
            set_type = s.get("type", "ipv4_addr")
            # flags may be a list or absent
            raw_flags = s.get("flags", [])
            if isinstance(raw_flags, str):
                raw_flags = [raw_flags]
            set_flags = list(raw_flags)
            declared_size = int(s.get("size", 65536))
            return set_type, set_flags, declared_size
    raise ValueError("no 'set' entry found in probe result")


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
