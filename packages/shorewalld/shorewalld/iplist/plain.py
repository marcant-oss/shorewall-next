"""Plain-list backend for shorewalld nft interval sets.

Handles three source types:

1. **HTTP(S) URL** (``http://`` / ``https://``) — periodic fetch, one IP or
   CIDR per line.  Uses ``urllib.request`` to avoid adding another dependency
   beyond what the rest of the iplist subsystem already requires.
2. **Absolute file path** (starts with ``/``) — ``open().read()`` parse; if
   ``inotify=True`` an ``inotify_simple.INotify`` watch is set up on the
   file.  If ``inotify_simple`` is not installed a WARNING is emitted and the
   tracker falls back to periodic polling.
3. **exec: prefix** (``exec:/path/to/script``) — ``asyncio.create_subprocess_exec``
   captures stdout, one IP/CIDR per line.  Only the explicit path after
   ``exec:`` is used — no shell expansion.

``PlainListConfig`` is the per-source configuration dataclass consumed by
:class:`NfSetsManager` and by :class:`PlainListTracker`.

``PlainListTracker`` mirrors the structure of :class:`~shorewalld.iplist.tracker.IpListTracker`
so :mod:`shorewalld.core` can start and stop it uniformly.

Wave 4 (``core.py``) wires this into the daemon lifecycle.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger("shorewalld.iplist.plain")

# How many seconds to wait for an exec: subprocess before giving up.
_EXEC_TIMEOUT_CAP = 60

# Back-off schedule on consecutive errors (seconds).
_BACKOFF = (60, 120, 300, 3600)

# Maximum prefixes allowed per list (safety cap).
_MAX_PREFIXES = 200_000


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class PlainListConfig:
    """Operator-defined configuration for one plain-list source.

    Parameters
    ----------
    name:
        Logical name used for logging and metrics (e.g. ``"nfset_blocklist"``).
    source:
        One of:

        * ``"http://..."`` / ``"https://..."`` — HTTP(S) URL to fetch.
        * ``"/abs/path"`` — absolute path to a local file.
        * ``"exec:/path/to/script"`` — script whose stdout is parsed.
    refresh:
        Seconds between re-fetches / re-reads.  Default: ``3600``.
    inotify:
        When ``True`` and *source* is a file path, set up an inotify watch
        so changes trigger an immediate reload rather than waiting for the
        next poll cycle.  Silently falls back to polling if ``inotify_simple``
        is not installed.
    set_v4:
        nft set name for IPv4 prefixes (``"nfset_<sanitized>_v4"``).
    set_v6:
        nft set name for IPv6 prefixes (``"nfset_<sanitized>_v6"``).
    max_prefixes:
        Safety cap on the total number of prefixes (v4 + v6).  If the parsed
        list exceeds this cap the write is skipped and an ERROR is logged.
    """

    name: str
    source: str
    refresh: int = 3600
    inotify: bool = False
    set_v4: str = ""
    set_v6: str = ""
    max_prefixes: int = _MAX_PREFIXES


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_lines(text: str) -> tuple[set[str], set[str]]:
    """Parse one-IP/CIDR-per-line text into ``(v4_set, v6_set)``.

    Blank lines and lines whose first non-whitespace character is ``#``
    are ignored.  Entries that are not parseable as IPv4 or IPv6 addresses
    or networks are silently skipped (a DEBUG line is emitted).
    """
    v4: set[str] = set()
    v6: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline comments.
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                v4.add(str(net))
            else:
                v6.add(str(net))
        except ValueError:
            log.debug("plain: skipping unparseable entry %r", entry)
    return v4, v6


# ---------------------------------------------------------------------------
# Source handlers
# ---------------------------------------------------------------------------


def _fetch_url(url: str) -> str:
    """Synchronous HTTP(S) fetch; returns the response body as text."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "shorewalld/1.0 (plain list tracker)"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        raw = resp.read()
    return raw.decode("utf-8", errors="replace")


def _read_file(path: str) -> str:
    """Read an absolute file path; returns its text content."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


async def _exec_source(path: str, timeout: int) -> str:
    """Run *path* as a subprocess and return its stdout as text.

    Only the explicit path is passed to ``create_subprocess_exec`` — no
    shell expansion, no user-controlled arguments.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        effective_timeout = min(timeout, _EXEC_TIMEOUT_CAP)
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=effective_timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise TimeoutError(
                f"exec: {path} timed out after {effective_timeout}s"
            )
        if proc.returncode != 0:
            err_preview = (stderr or b"").decode("utf-8", errors="replace")[:200]
            raise RuntimeError(
                f"exec: {path} exited with code {proc.returncode}: {err_preview}"
            )
        return stdout.decode("utf-8", errors="replace")
    except (FileNotFoundError, PermissionError) as exc:
        raise RuntimeError(f"exec: cannot run {path}: {exc}") from exc


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------


@dataclass
class _PlainListState:
    """Runtime state for one PlainListConfig."""

    cfg: PlainListConfig
    current_v4: set[str] = field(default_factory=set)
    current_v6: set[str] = field(default_factory=set)
    consecutive_errors: int = 0
    last_refresh_ts: float = 0.0


class PlainListTracker:
    """Fetches and maintains nft interval sets for all configured plain lists.

    Mirrors the public API of :class:`~shorewalld.iplist.tracker.IpListTracker`
    so ``core.py`` can start and stop both with the same pattern::

        tracker = PlainListTracker(configs, nft, profiles)
        task = asyncio.create_task(tracker.run())
        ...
        task.cancel()

    Wave 4 notes
    ------------
    ``__init__`` signature: ``(configs, nft, profiles)`` where *nft* is a
    :class:`~shorewall_nft.nft.netlink.NftInterface` and *profiles* is the
    ``dict[str, NetnsProfile]`` from :mod:`shorewalld.discover`.

    ``run()`` is a coroutine that runs until cancelled.

    ``refresh_all()`` / ``refresh_one(name)`` force an immediate refresh.

    ``status()`` returns a list of dicts with per-list state.
    """

    def __init__(
        self,
        configs: list[PlainListConfig],
        nft: object,   # NftInterface — typed as object to avoid import at module level
        profiles: dict,   # dict[str, NetnsProfile]
    ) -> None:
        self._configs = configs
        self._nft = nft
        self._profiles = profiles
        self._states: dict[str, _PlainListState] = {
            cfg.name: _PlainListState(cfg=cfg) for cfg in configs
        }
        self._list_locks: dict[str, asyncio.Lock] = {
            cfg.name: asyncio.Lock() for cfg in configs
        }
        self._refresh_tasks: dict[str, asyncio.Task] = {}
        self._inotify_tasks: dict[str, asyncio.Task] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Main loop; runs until cancelled."""
        log.info("plain list tracker: starting with %d source(s)", len(self._configs))

        for cfg in self._configs:
            state = self._states[cfg.name]
            task = asyncio.create_task(
                self._list_loop(state),
                name=f"shorewalld.plain.{cfg.name}",
            )
            self._refresh_tasks[cfg.name] = task

            # Set up inotify watch for file sources when requested.
            if cfg.inotify and cfg.source.startswith("/"):
                inotify_task = asyncio.create_task(
                    self._inotify_watch(state),
                    name=f"shorewalld.plain.inotify.{cfg.name}",
                )
                self._inotify_tasks[cfg.name] = inotify_task

        all_tasks = list(self._refresh_tasks.values()) + list(
            self._inotify_tasks.values()
        )
        try:
            await asyncio.gather(*all_tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        finally:
            for task in all_tasks:
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
            log.warning("plain: refresh_one: unknown list %r", name)
            return
        await self._do_refresh(state)

    def status(self) -> list[dict]:
        """Return a status summary for each configured source."""
        result = []
        for name, state in self._states.items():
            result.append({
                "name": name,
                "source": state.cfg.source,
                "v4_prefixes": len(state.current_v4),
                "v6_prefixes": len(state.current_v6),
                "last_refresh": state.last_refresh_ts,
                "consecutive_errors": state.consecutive_errors,
                "set_v4": state.cfg.set_v4,
                "set_v6": state.cfg.set_v6,
            })
        return result

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _list_loop(self, state: _PlainListState) -> None:
        """Per-list refresh loop with exponential back-off."""
        await self._do_refresh(state)
        while True:
            if state.consecutive_errors > 0:
                idx = min(state.consecutive_errors - 1, len(_BACKOFF) - 1)
                delay = _BACKOFF[idx]
                log.warning(
                    "plain.%s: backing off %ds after %d consecutive error(s)",
                    state.cfg.name, delay, state.consecutive_errors,
                )
            else:
                delay = state.cfg.refresh
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                return
            await self._do_refresh(state)

    async def _inotify_watch(self, state: _PlainListState) -> None:
        """Watch a file path via inotify and trigger refreshes on changes."""
        try:
            import inotify_simple  # type: ignore[import-untyped]
        except ImportError:
            log.warning(
                "plain.%s: inotify=True but inotify_simple is not installed — "
                "falling back to refresh polling",
                state.cfg.name,
            )
            return

        inotify = inotify_simple.INotify()
        flags = inotify_simple.flags.CLOSE_WRITE | inotify_simple.flags.MOVED_TO
        try:
            inotify.add_watch(state.cfg.source, flags)
            log.debug(
                "plain.%s: inotify watch active on %s",
                state.cfg.name, state.cfg.source,
            )
            loop = asyncio.get_running_loop()
            while True:
                # Blocking read in a thread pool so we don't block the event loop.
                events = await loop.run_in_executor(
                    None, lambda: inotify.read(timeout=None)
                )
                if events:
                    log.debug(
                        "plain.%s: inotify event — triggering refresh",
                        state.cfg.name,
                    )
                    await self._do_refresh(state)
        except asyncio.CancelledError:
            pass
        finally:
            try:
                inotify.close()
            except Exception:  # noqa: BLE001
                pass

    async def _do_refresh(self, state: _PlainListState) -> None:
        """Fetch, parse, diff, and write one list."""
        async with self._list_locks[state.cfg.name]:
            await self._do_refresh_locked(state)

    async def _do_refresh_locked(self, state: _PlainListState) -> None:
        import time

        cfg = state.cfg
        list_log = logging.getLogger(f"shorewalld.plain.{cfg.name}")

        # ── Fetch ──────────────────────────────────────────────────────────
        try:
            if cfg.source.startswith(("http://", "https://")):
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(None, _fetch_url, cfg.source)
            elif cfg.source.startswith("exec:"):
                path = cfg.source[len("exec:"):]
                text = await _exec_source(path, cfg.refresh)
            elif cfg.source.startswith("/"):
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(None, _read_file, cfg.source)
            else:
                log.error(
                    "plain.%s: unrecognised source type %r — skipping",
                    cfg.name, cfg.source,
                )
                state.consecutive_errors += 1
                return
        except Exception as exc:
            state.consecutive_errors += 1
            log.warning("plain.%s: fetch error: %s", cfg.name, exc)
            return

        # ── Parse ──────────────────────────────────────────────────────────
        try:
            new_v4, new_v6 = _parse_lines(text)
        except Exception as exc:
            state.consecutive_errors += 1
            log.error("plain.%s: parse error: %s", cfg.name, exc)
            return

        total = len(new_v4) + len(new_v6)
        if total > cfg.max_prefixes:
            log.error(
                "plain.%s: %d prefixes exceeds max_prefixes=%d — skipping write",
                cfg.name, total, cfg.max_prefixes,
            )
            state.consecutive_errors += 1
            return

        # ── Apply diff ─────────────────────────────────────────────────────
        total_added = 0
        total_removed = 0
        for _netns, profile in self._profiles.items():
            if not getattr(profile, "has_table", False):
                continue
            nft_netns = _netns or None

            if cfg.set_v4:
                a, r = await self._apply_set(
                    nft_netns, cfg.set_v4, state.current_v4, new_v4, cfg.name, "v4"
                )
                total_added += max(0, a)
                total_removed += max(0, r)

            if cfg.set_v6:
                a, r = await self._apply_set(
                    nft_netns, cfg.set_v6, state.current_v6, new_v6, cfg.name, "v6"
                )
                total_added += max(0, a)
                total_removed += max(0, r)

        state.current_v4 = new_v4
        state.current_v6 = new_v6
        state.last_refresh_ts = time.time()
        state.consecutive_errors = 0

        if total_added or total_removed:
            list_log.info(
                "refresh complete — %d v4 + %d v6 (+%d added, -%d removed)",
                len(new_v4), len(new_v6), total_added, total_removed,
            )
        else:
            list_log.debug(
                "refresh complete — %d v4 + %d v6 (no delta)",
                len(new_v4), len(new_v6),
            )

    async def _apply_set(
        self,
        netns: str | None,
        set_name: str,
        current: set[str],
        new: set[str],
        list_name: str,
        family: str,
    ) -> tuple[int, int]:
        """Compute and apply the diff for one set in one netns.

        Returns ``(added, removed)`` counts or ``(-1, 0)`` on error.
        """
        from .tracker import _chunks  # reuse the shared helper

        to_add = new - current
        to_remove = current - new

        if to_add:
            for chunk in _chunks(to_add, 200):
                elements = ", ".join(chunk)
                script = (
                    f"add element inet shorewall {set_name} {{ {elements} }}"
                )
                try:
                    self._nft.cmd(script, netns=netns)
                except Exception as exc:
                    log.error(
                        "plain.%s: nft add element to %s (netns=%r) failed: %s",
                        list_name, set_name, netns, exc,
                    )
                    return -1, 0

        if to_remove:
            for chunk in _chunks(to_remove, 200):
                elements = ", ".join(chunk)
                script = (
                    f"delete element inet shorewall {set_name} {{ {elements} }}"
                )
                try:
                    self._nft.cmd(script, netns=netns)
                except Exception as exc:
                    log.debug(
                        "plain.%s: nft delete element from %s (netns=%r): %s",
                        list_name, set_name, netns, exc,
                    )

        return len(to_add), len(to_remove)
