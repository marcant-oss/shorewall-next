"""Multi-instance shorewall-nft config management for shorewalld.

An "instance" is one shorewall-nft config directory served by a single
shorewalld process.  Operators configure multiple instances when running
shorewall-nft in multiple network namespaces on the same host.

Each instance tracks one compiled allowlist
(``config_dir/dnsnames.compiled``) and reloads it into the DNS-set
tracker when the file changes.

File-watching uses ``watchfiles`` if available, otherwise falls back to
polling every 5 s.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .dns_set_tracker import DnsSetTracker
    from .worker_router import WorkerRouter

log = logging.getLogger("shorewalld.instance")


@dataclass
class InstanceConfig:
    """Configuration for one shorewall-nft instance."""

    name: str
    """Derived from the netns name or the config directory basename."""

    netns: str
    """Network namespace name; ``""`` = root namespace."""

    config_dir: Path
    """The merged shorewall-nft config directory."""

    allowlist_path: Path
    """``config_dir / "dnsnames.compiled"`` — the compiled DNS allowlist."""


def parse_instance_spec(spec: str) -> InstanceConfig:
    """Parse a ``[netns:]<dir>`` instance spec into an :class:`InstanceConfig`.

    Examples::

        parse_instance_spec("fw:/etc/shorewall")
        # → InstanceConfig(name="fw", netns="fw", config_dir=Path("/etc/shorewall"), ...)

        parse_instance_spec("/etc/shorewall")
        # → InstanceConfig(name="shorewall", netns="", config_dir=Path("/etc/shorewall"), ...)
    """
    if ":" in spec:
        netns, _, dir_s = spec.partition(":")
        netns = netns.strip()
        dir_path = Path(dir_s.strip())
    else:
        netns = ""
        dir_path = Path(spec.strip())
    name = netns or dir_path.name
    return InstanceConfig(
        name=name,
        netns=netns,
        config_dir=dir_path,
        allowlist_path=dir_path / "dnsnames.compiled",
    )


@dataclass
class _InstanceState:
    """Runtime state for one instance."""

    cfg: InstanceConfig
    last_loaded_ts: float = 0.0
    last_n_qnames: int = 0
    error: str | None = None


class InstanceManager:
    """Manages one or more shorewall-nft instances.

    Responsibilities:

    * Load the compiled allowlist for each instance on start.
    * Optionally watch for changes and reload automatically.
    * Expose a control-server handler for explicit reloads.
    """

    def __init__(
        self,
        configs: list[InstanceConfig],
        tracker: DnsSetTracker,
        router: WorkerRouter,
        monitor: bool = False,
    ) -> None:
        self._configs = configs
        self._tracker = tracker
        self._router = router
        self._monitor = monitor
        self._states: dict[str, _InstanceState] = {
            cfg.name: _InstanceState(cfg=cfg) for cfg in configs
        }
        self._monitor_task: asyncio.Task[None] | None = None
        self._monitor_warned = False

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self) -> None:
        """Load all instances and optionally start the file monitor."""
        for cfg in self._configs:
            await self._load_instance(self._states[cfg.name])

        if self._monitor:
            if not self._monitor_warned:
                log.warning(
                    "instance monitor: --monitor enabled; this may conflict "
                    "with explicit shorewall-nft start/reload hooks"
                )
                self._monitor_warned = True
            self._monitor_task = asyncio.create_task(
                self._watch_loop(), name="shorewalld.instance_monitor"
            )

    async def shutdown(self) -> None:
        """Cancel the file monitor if running."""
        if self._monitor_task is not None:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

    # ── Public API ─────────────────────────────────────────────────────

    async def reload(self, name: str | None = None) -> None:
        """Reload one or all instances.

        *name* = ``None`` reloads all instances.
        """
        if name is None:
            for state in self._states.values():
                await self._load_instance(state)
        else:
            state = self._states.get(name)
            if state is None:
                log.warning("instance: reload: unknown instance %r", name)
                return
            await self._load_instance(state)

    def status(self) -> list[dict]:
        """Return a status list for the control server."""
        result = []
        for name, state in self._states.items():
            result.append({
                "name": name,
                "netns": state.cfg.netns,
                "config_dir": str(state.cfg.config_dir),
                "allowlist_path": str(state.cfg.allowlist_path),
                "last_loaded": state.last_loaded_ts,
                "qnames": state.last_n_qnames,
                "error": state.error,
            })
        return result

    # ── Internal ───────────────────────────────────────────────────────

    async def _load_instance(self, state: _InstanceState) -> None:
        """Read and apply the compiled allowlist for one instance."""
        cfg = state.cfg
        path = cfg.allowlist_path
        try:
            from shorewall_nft.nft.dns_sets import read_compiled_allowlist
        except ImportError:
            log.error(
                "instance %s: shorewall_nft not installed — "
                "cannot read allowlist",
                cfg.name,
            )
            state.error = "shorewall_nft not installed"
            return

        try:
            registry = read_compiled_allowlist(path)
        except FileNotFoundError:
            log.warning(
                "instance %s: allowlist %s not found (skipping)",
                cfg.name, path,
            )
            state.error = f"allowlist not found: {path}"
            return
        except Exception as e:
            log.error(
                "instance %s: failed to read allowlist %s: %s",
                cfg.name, path, e,
            )
            state.error = str(e)
            return

        try:
            self._tracker.load_registry(registry)
        except Exception as e:
            log.error(
                "instance %s: failed to load registry: %s",
                cfg.name, e,
            )
            state.error = str(e)
            return

        n_qnames = sum(1 for _ in registry.iter_sorted())
        state.last_loaded_ts = time.time()
        state.last_n_qnames = n_qnames
        state.error = None
        log.info(
            "instance %s: reloaded allowlist (%d qnames)", cfg.name, n_qnames
        )

    async def _watch_loop(self) -> None:
        """Watch all instance allowlist files for changes."""
        paths = [str(state.cfg.allowlist_path) for state in self._states.values()]
        log.info(
            "instance monitor: watching %d path(s) for changes", len(paths)
        )
        try:
            await self._watch_with_watchfiles(paths)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.debug(
                "instance monitor: watchfiles unavailable, falling back to polling"
            )
            await self._watch_with_polling()

    async def _watch_with_watchfiles(self, paths: list[str]) -> None:
        """File watching via watchfiles (if installed)."""
        import watchfiles  # type: ignore[import-not-found]

        async for changes in watchfiles.awatch(*paths):
            changed_paths = {change[1] for change in changes}
            for state in self._states.values():
                if str(state.cfg.allowlist_path) in changed_paths:
                    log.debug(
                        "instance monitor: %s changed, reloading",
                        state.cfg.allowlist_path,
                    )
                    await self._load_instance(state)

    async def _watch_with_polling(self) -> None:
        """Polling fallback when watchfiles is not available (5 s interval)."""
        # Build initial mtime map.
        mtimes: dict[str, float] = {}
        for state in self._states.values():
            p = state.cfg.allowlist_path
            try:
                mtimes[state.cfg.name] = p.stat().st_mtime
            except OSError:
                mtimes[state.cfg.name] = 0.0

        while True:
            try:
                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                return
            for state in self._states.values():
                p = state.cfg.allowlist_path
                try:
                    mtime = p.stat().st_mtime
                except OSError:
                    continue
                if mtime != mtimes.get(state.cfg.name, 0.0):
                    mtimes[state.cfg.name] = mtime
                    log.debug(
                        "instance monitor: %s changed (poll), reloading", p
                    )
                    await self._load_instance(state)
