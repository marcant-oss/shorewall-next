"""Multi-instance shorewall-nft config management for shorewalld.

An "instance" is one shorewall-nft config directory served by a single
shorewalld process.  Operators configure multiple instances when running
shorewall-nft in multiple network namespaces on the same host.

Each instance tracks one compiled allowlist
(``config_dir/dnsnames.compiled``).  Reloads are driven explicitly via
the control socket (``register-instance`` / ``reload-instance``).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Awaitable, Callable

if TYPE_CHECKING:
    from shorewall_nft.nft.dns_sets import DnsrRegistry, DnsSetRegistry

    from .dns_pull_resolver import PullResolver
    from .dns_set_tracker import DnsSetTracker
    from .state import InstanceCache
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
        pull_resolver: "PullResolver | None" = None,
        pull_resolver_factory: "PullResolverFactory | None" = None,
        cache: "InstanceCache | None" = None,
    ) -> None:
        self._configs = configs
        self._tracker = tracker
        self._router = router
        self._pull_resolver = pull_resolver
        # Factory invoked lazily when the first dnsr group appears via
        # dynamic register-instance. Returns the created PullResolver
        # or None if prerequisites aren't met.
        self._pull_resolver_factory = pull_resolver_factory
        self._cache = cache
        # Names from the initial CLI config — never written to the cache
        # since they survive restart via CLI flags.
        self._static_names: frozenset[str] = frozenset(
            cfg.name for cfg in configs
        )
        self._states: dict[str, _InstanceState] = {
            cfg.name: _InstanceState(cfg=cfg) for cfg in configs
        }

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self) -> None:
        """Load all instances, restoring cached dynamic ones first."""
        await self._restore_from_cache()
        for cfg in self._configs:
            await self._load_instance(self._states[cfg.name])

    async def shutdown(self) -> None:
        """No-op — file monitoring removed; instances are updated via control socket."""

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

    async def register(
        self,
        config: InstanceConfig,
        dns_payload: dict | None = None,
    ) -> int:
        """Dynamically add or refresh an instance.

        If the instance name is unknown, it is added to the managed set.
        If it already exists, its config is updated in place.

        When *dns_payload* is provided (the inline ``"dns"``/``"dnsr"``
        dict from the control-socket message) the registries are parsed
        directly from it — no file I/O.  Without it the legacy file-based
        path is used as a fallback.

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
        state = self._states[config.name]
        if dns_payload is not None:
            await self._load_instance_from_payload(state, dns_payload)
        else:
            await self._load_instance(state)
        if self._cache is not None and config.name not in self._static_names:
            self._cache.update(config, dns_payload)
        return state.last_n_qnames

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
        if self._cache is not None:
            self._cache.remove(name)
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

    async def _restore_from_cache(self) -> None:
        """Re-register dynamic instances saved from a previous run."""
        if self._cache is None:
            return
        restored = 0
        for name, netns, config_dir_s, allowlist_path_s, dns_payload in (
            self._cache.load()
        ):
            if name in self._static_names:
                log.debug(
                    "instance cache: skipping static instance %r", name)
                continue
            if name in self._states:
                log.debug(
                    "instance cache: instance %r already registered", name)
                continue
            cfg = InstanceConfig(
                name=name,
                netns=netns,
                config_dir=Path(config_dir_s),
                allowlist_path=Path(allowlist_path_s),
            )
            self._states[name] = _InstanceState(cfg=cfg)
            state = self._states[name]
            log.info("instance: restoring cached instance %r", name)
            if dns_payload is not None:
                await self._load_instance_from_payload(state, dns_payload)
            else:
                await self._load_instance(state)
            restored += 1
        if restored:
            log.info("instance cache: restored %d dynamic instance(s)", restored)

    async def _load_instance_from_payload(
        self, state: _InstanceState, payload: dict,
    ) -> None:
        """Parse inline DNS registries from a control-socket payload dict."""
        try:
            from shorewall_nft.nft.dns_sets import payload_to_registries
        except ImportError:
            log.error(
                "instance %s: shorewall_nft not installed — "
                "cannot parse inline allowlist",
                state.cfg.name,
            )
            state.error = "shorewall_nft not installed"
            return

        try:
            state.last_dns_registry, state.last_dnsr_registry = (
                payload_to_registries(payload)
            )
        except Exception as e:
            log.error(
                "instance %s: failed to parse inline allowlist: %s",
                state.cfg.name, e,
            )
            state.error = str(e)
            return

        n_dns = sum(1 for _ in state.last_dns_registry.iter_sorted())
        n_dnsr = (
            len(state.last_dnsr_registry.groups)
            if state.last_dnsr_registry is not None else 0
        )
        state.last_loaded_ts = time.time()
        state.last_n_qnames = n_dns
        state.error = None
        log.info(
            "instance %s: loaded inline allowlist (%d dns, %d dnsr)",
            state.cfg.name, n_dns, n_dnsr,
        )
        await self._apply_merged()

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
        from shorewall_nft.nft.dns_sets import DnsrRegistry, DnsSetRegistry

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

