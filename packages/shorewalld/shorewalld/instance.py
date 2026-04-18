"""Multi-instance shorewall-nft config management for shorewalld.

An "instance" is one shorewall-nft config directory served by a single
shorewalld process.  Operators configure multiple instances when running
shorewall-nft in multiple network namespaces on the same host.

Each instance tracks one compiled allowlist
(``config_dir/dnsnames.compiled``) and reloads it into the DNS-set
tracker when the file changes.

Instances can be registered dynamically via the control socket
(``register-instance`` / ``deregister-instance``). Dynamically registered
instances are **not** monitored by :class:`InstanceManager`'s file watcher
— they are updated explicitly via the control socket from the
``shorewall-nft`` lifecycle commands.

File-watching uses ``watchfiles`` if available, otherwise falls back to
polling every 5 s.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Awaitable, Callable

if TYPE_CHECKING:
    from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsrRegistry

    from .dns_pull_resolver import PullResolver
    from .dns_set_tracker import DnsSetTracker
    from .worker_router import WorkerRouter

    PullResolverFactory = Callable[
        ["DnsrRegistry"], Awaitable["PullResolver | None"]
    ]
else:
    PullResolverFactory = object  # runtime placeholder

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
    last_dns_registry: "DnsSetRegistry | None" = field(default=None, repr=False)
    last_dnsr_registry: "DnsrRegistry | None" = field(default=None, repr=False)


class InstanceManager:
    """Manages one or more shorewall-nft instances.

    Responsibilities:

    * Load the compiled allowlist for each instance on start.
    * Optionally watch for changes and reload automatically.
    * Expose control-server handlers for explicit reload / register /
      deregister.

    Writer model: :meth:`_load_instance` reads an instance's allowlist
    from disk into the per-instance cache, then calls
    :meth:`_apply_merged` which is the *sole* writer of the merged state
    into ``DnsSetTracker`` and ``PullResolver``. This matters because
    ``DnsSetTracker.load_registry()`` is destructive — any name not in
    the passed registry is evicted. Merging all instance caches before
    the single write keeps multi-instance setups correct.
    """

    def __init__(
        self,
        configs: list[InstanceConfig],
        tracker: "DnsSetTracker",
        router: "WorkerRouter",
        monitor: bool = False,
        pull_resolver: "PullResolver | None" = None,
        pull_resolver_factory: "PullResolverFactory | None" = None,
    ) -> None:
        self._configs = configs
        self._tracker = tracker
        self._router = router
        self._monitor = monitor
        self._pull_resolver = pull_resolver
        # Factory invoked lazily when the first dnsr group appears via
        # dynamic register-instance. Returns the created PullResolver
        # or None if prerequisites aren't met.
        self._pull_resolver_factory = pull_resolver_factory
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
        """Reload one or all instances from disk.

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

    async def register(self, config: InstanceConfig) -> int:
        """Dynamically add or refresh an instance.

        If the instance name is unknown, it is added to the managed set.
        If it already exists, its config is updated in place. In both
        cases the allowlist is re-read from disk and the merged state is
        applied to the tracker and pull resolver.

        Returns the number of DNS qnames loaded for this instance.
        """
        if config.name not in self._states:
            self._states[config.name] = _InstanceState(cfg=config)
            log.info(
                "instance: registering new instance %r (%s, netns=%r)",
                config.name, config.config_dir, config.netns,
            )
        else:
            self._states[config.name].cfg = config
            log.info("instance: re-registering instance %r", config.name)
        await self._load_instance(self._states[config.name])
        return self._states[config.name].last_n_qnames

    async def deregister(self, name: str) -> None:
        """Remove an instance and recompute the merged tracker/pull_resolver.

        Names exclusive to this instance are evicted from the tracker;
        names shared with other instances remain active. DNSR groups
        from this instance are removed from the pull resolver.
        """
        if name not in self._states:
            log.warning("instance: deregister: unknown instance %r", name)
            return
        del self._states[name]
        log.info("instance: deregistered %r", name)
        await self._apply_merged()

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
        """Read compiled allowlist into the per-instance cache, then merge."""
        try:
            from shorewall_nft.nft.dns_sets import (
                read_compiled_allowlist,
                read_compiled_dnsr_allowlist,
            )
        except ImportError:
            log.error(
                "instance %s: shorewall_nft not installed — "
                "cannot read allowlist",
                state.cfg.name,
            )
            state.error = "shorewall_nft not installed"
            return

        cfg = state.cfg
        path = cfg.allowlist_path

        try:
            state.last_dns_registry = read_compiled_allowlist(path)
        except FileNotFoundError:
            log.warning(
                "instance %s: allowlist %s not found (skipping)",
                cfg.name, path,
            )
            state.last_dns_registry = None
            state.last_dnsr_registry = None
            state.error = f"allowlist not found: {path}"
            await self._apply_merged()
            return
        except Exception as e:
            log.error(
                "instance %s: failed to read allowlist %s: %s",
                cfg.name, path, e,
            )
            state.error = str(e)
            return

        try:
            state.last_dnsr_registry = read_compiled_dnsr_allowlist(path)
        except FileNotFoundError:
            state.last_dnsr_registry = None
        except Exception as e:
            log.warning(
                "instance %s: dnsr section read failed: %s", cfg.name, e)
            state.last_dnsr_registry = None

        n_dns = sum(1 for _ in state.last_dns_registry.iter_sorted())
        n_dnsr = (
            len(state.last_dnsr_registry.groups)
            if state.last_dnsr_registry is not None else 0
        )
        state.last_loaded_ts = time.time()
        state.last_n_qnames = n_dns
        state.error = None
        log.info(
            "instance %s: cached allowlist (%d dns, %d dnsr)",
            cfg.name, n_dns, n_dnsr,
        )
        await self._apply_merged()

    async def _apply_merged(self) -> None:
        """Merge all instance caches and write to tracker + pull_resolver.

        This is the ONLY place that writes to the tracker / pull_resolver.
        ``tracker.load_registry()`` is destructive (evicts names not in
        the passed registry), so we must merge across all instances
        before calling it — otherwise multi-instance setups would have
        each instance evict the others' names.
        """
        from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsrRegistry

        from .dns_set_tracker import FAMILY_V4, FAMILY_V6

        merged_dns = DnsSetRegistry()
        merged_dnsr = DnsrRegistry()
        for state in self._states.values():
            if state.last_dns_registry is not None:
                for spec in state.last_dns_registry.iter_sorted():
                    merged_dns.add_spec(spec)
            if state.last_dnsr_registry is not None:
                # Merge via add_from_rule so duplicate primaries across
                # instances combine their qnames and OR their
                # pull_enabled flags correctly.
                for group in state.last_dnsr_registry.iter_sorted():
                    merged = merged_dnsr.add_from_rule(
                        group.primary_qname,
                        group.qnames,
                        pull_enabled=group.pull_enabled,
                    )
                    # Preserve per-group TTL/size overrides from the
                    # source registry (add_from_rule only uses defaults).
                    merged.ttl_floor = group.ttl_floor
                    merged.ttl_ceil = group.ttl_ceil
                    merged.size = group.size
                    if group.comment and not merged.comment:
                        merged.comment = group.comment

        self._tracker.load_registry(merged_dns)

        # Re-wire dnsr secondary aliases after the tracker reload —
        # load_registry() rebuilds set_ids and clears aliases.
        for group in merged_dnsr.iter_sorted():
            for alias in group.qnames[1:]:  # primary is qnames[0]
                self._tracker.add_qname_alias(
                    alias, group.primary_qname, FAMILY_V4)
                self._tracker.add_qname_alias(
                    alias, group.primary_qname, FAMILY_V6)

        # Lazily create the pull resolver the first time we see a
        # pull-enabled group — a daemon that booted without any may
        # get its first one via dynamic register-instance. Tap-only
        # groups (multi-host ``dns:``) don't need a pull resolver.
        if (
            self._pull_resolver is None
            and self._pull_resolver_factory is not None
            and any(g.pull_enabled for g in merged_dnsr.groups.values())
        ):
            self._pull_resolver = await self._pull_resolver_factory(merged_dnsr)

        if self._pull_resolver is not None:
            await self._pull_resolver.update_registry(merged_dnsr)

        log.info(
            "instance: merged %d instance(s) → %d dns, %d dnsr",
            len(self._states), len(merged_dns.specs), len(merged_dnsr.groups),
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
