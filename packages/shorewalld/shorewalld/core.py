"""shorewalld core lifecycle.

``Daemon`` is the single top-level object that owns every subsystem:

* signal handlers + idempotent shutdown (mirrors SimController pattern)
* Prometheus HTTP scrape endpoint
* per-netns collector profiles (wired up in Phase 2/3)
* the dnstap consumer (wired up in Phase 4, off by default)

Phase 1 only exercises the lifecycle — subsystems are stubbed out so
that ``Daemon(...)`` is constructible and ``shutdown()`` is idempotent
in unit tests. Phases 2+ fill in the real work.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import os
import signal
import socket
from pathlib import Path
from typing import Any

from shorewall_nft.nft.netlink import NftInterface

from .discover import ProfileBuilder, resolve_netns_list
from .dnstap import DnstapMetricsCollector, DnstapServer
from .exporter import NftScraper, ShorewalldRegistry

log = logging.getLogger("shorewalld")


class Daemon:
    """shorewalld top-level. One instance per process."""

    def __init__(
        self,
        *,
        prom_host: str,
        prom_port: int,
        api_socket: str | None,
        netns_spec: list[str] | str,
        scrape_interval: float,
        reprobe_interval: float,
        allowlist_file: Path | None = None,
        pbdns_socket: str | None = None,
        pbdns_tcp: str | None = None,
        socket_mode: int | None = None,
        socket_owner: str | int | None = None,
        socket_group: str | int | None = None,
        peer_bind_host: str | None = None,
        peer_bind_port: int | None = None,
        peer_host: str | None = None,
        peer_port: int | None = None,
        peer_auth_key_file: Path | None = None,
        peer_heartbeat_interval: float = 5.0,
        state_dir: Path | None = None,
        state_enabled: bool = True,
        state_no_load: bool = False,
        state_flush: bool = False,
        instances: list[str] | None = None,
        control_socket: str | None = None,
        control_socket_netns: str | None = None,
        iplist_configs: list[Any] | None = None,
    ) -> None:
        self.prom_host = prom_host
        self.prom_port = prom_port
        self.api_socket = api_socket
        self.netns_spec = netns_spec
        self.scrape_interval = scrape_interval
        self.reprobe_interval = reprobe_interval

        # DNS-set pipeline opt-in config.
        self.allowlist_file = allowlist_file
        self.pbdns_socket = pbdns_socket
        self.pbdns_tcp = pbdns_tcp
        self.socket_mode = socket_mode
        self.socket_owner = socket_owner
        self.socket_group = socket_group
        self.peer_bind_host = peer_bind_host
        self.peer_bind_port = peer_bind_port
        self.peer_host = peer_host
        self.peer_port = peer_port
        self.peer_auth_key_file = peer_auth_key_file
        self.peer_heartbeat_interval = peer_heartbeat_interval
        self.state_dir = state_dir
        self.state_enabled = state_enabled
        self.state_no_load = state_no_load
        self.state_flush = state_flush

        # New multi-instance / iplist / control settings.
        self.instances: list[str] = instances or []
        self.control_socket = control_socket
        self.control_socket_netns = control_socket_netns
        self.iplist_configs: list[Any] = iplist_configs or []

        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown_done = False
        self._cleanup_registered = False
        self._stop_event: asyncio.Event | None = None

        # Subsystems wired up in run().
        self._nft: NftInterface | None = None
        self._registry: ShorewalldRegistry | None = None
        self._scraper: NftScraper | None = None
        self._profile_builder: ProfileBuilder | None = None
        self._reprobe_task: asyncio.Task[None] | None = None

        self._prom_server: Any | None = None
        self._dnstap_server: Any | None = None

        # DNS-set pipeline subsystems (opt-in via allowlist_file).
        self._tracker: Any | None = None
        self._router: Any | None = None
        self._set_writer: Any | None = None
        self._tracker_bridge: Any | None = None
        self._state_store: Any | None = None
        self._pbdns_server: Any | None = None
        self._peer_link: Any | None = None

        self._pull_resolver: Any | None = None
        self._pull_resolver_netns: str = ""

        # New subsystems.
        self._iplist_tracker: Any | None = None
        self._iplist_task: asyncio.Task[None] | None = None
        self._instance_manager: Any | None = None
        self._control_server: Any | None = None

    # ── lifecycle ────────────────────────────────────────────────────

    async def run(self) -> int:
        """Build subsystems, install signal handlers, block until shutdown."""
        self._loop = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()
        self._register_cleanup()

        log.info(
            "shorewalld starting: prom=%s:%d api=%s netns=%s",
            self.prom_host, self.prom_port,
            self.api_socket or "(disabled)",
            self.netns_spec,
        )

        # ── subsystem startup ─────────────────────────────────────
        self._nft = NftInterface()
        self._registry = ShorewalldRegistry()
        self._scraper = NftScraper(self._nft, ttl_s=self.scrape_interval)
        # Create the worker router early (tracker attaches later
        # during DNS-pipeline bootstrap) so the exporter's /proc-reading
        # collectors can delegate their reads to netns-pinned workers
        # from the first scrape onwards. Workers are forked lazily on
        # first use (scrape or SetWriter dispatch).
        from .worker_router import WorkerRouter
        self._router = WorkerRouter(loop=self._loop)
        self._profile_builder = ProfileBuilder(
            self._nft, self._registry, self._scraper, self._router)

        netns_list = resolve_netns_list(self.netns_spec)
        self._profile_builder.build(netns_list)
        self._profile_builder.reprobe()
        log.info(
            "shorewalld built %d netns profile(s): %s",
            len(self._profile_builder.profiles),
            list(self._profile_builder.profiles),
        )

        # Prometheus HTTP scrape endpoint. Deferred import so
        # ``--help`` works without prometheus_client installed.
        self._start_prom_server()

        # Periodic re-probe to pick up rulesets that appear/disappear
        # after the daemon started (e.g. an operator running
        # `shorewall-nft start` in a recursor netns).
        self._reprobe_task = asyncio.create_task(
            self._reprobe_loop(), name="shorewalld.reprobe")

        # Optional DNS-set pipeline (Phase 5–10). Requires a compiled
        # allowlist file to bootstrap the tracker; everything else
        # (pbdns / peer link / state / reload monitor) layers on top.
        # Started BEFORE the dnstap server so the DnstapServer can
        # pick up the tracker bridge for its routing path.
        #
        # When --instance specs are given without --allowlist-file,
        # bootstrap the pipeline from the first instance's allowlist
        # path so the tracker is available for the InstanceManager.
        bootstrap_allowlist = self.allowlist_file
        if bootstrap_allowlist is None and self.instances:
            from .instance import parse_instance_spec
            first_spec = parse_instance_spec(self.instances[0])
            if first_spec.allowlist_path.exists():
                bootstrap_allowlist = first_spec.allowlist_path

        if bootstrap_allowlist is not None:
            _orig = self.allowlist_file
            self.allowlist_file = bootstrap_allowlist
            await self._start_dns_pipeline(netns_list)
            self.allowlist_file = _orig

        # When only a control socket is configured and no allowlist was
        # available to bootstrap from, seed an empty pipeline so the
        # InstanceManager starts and register-instance is available.
        if self._tracker is None and self.control_socket:
            await self._start_empty_dns_pipeline(netns_list)

        # Multi-instance manager: layers on the DNS pipeline.
        # When --instance is used, the InstanceManager takes over
        # allowlist management from the reload monitor.  It is also
        # started (with an empty instance list) when a control socket
        # is configured — this lets ``shorewall-nft start`` dynamically
        # register itself without operators needing to repeat the path
        # in both shorewalld's ``--instance`` and shorewall-nft's
        # config directory.
        if self._tracker is not None and (
            self.instances or self.control_socket
        ):
            await self._start_instance_manager()

        # IP-list tracker (fetches cloud prefix lists into nft sets).
        if self.iplist_configs:
            await self._start_iplist_tracker(netns_list)

        # Optional dnstap consumer (Phase 4). Off by default.
        if self.api_socket:
            await self._start_dnstap_server(netns_list)

        # Control socket server.
        if self.control_socket:
            await self._start_control_server()

        # Install SIGUSR1 handler for manual iplist refresh.
        self._install_sigusr1()

        try:
            await self._stop_event.wait()
        finally:
            await self._async_shutdown()
        return 0

    async def _start_dns_pipeline(self, netns_list: list[str]) -> None:
        """Wire up tracker + router + setwriter + optional ingress/peer.

        All subsystems are optional; this is only called when the
        caller passed ``allowlist_file`` because without a compiled
        allowlist the tracker has nothing to dedup against.
        """
        assert self.allowlist_file is not None
        assert self._nft is not None
        from shorewall_nft.nft.dns_sets import (
            read_compiled_allowlist,
            read_compiled_dnsr_allowlist,
        )

        from .dns_set_tracker import FAMILY_V4, FAMILY_V6, DnsSetTracker
        from .dnstap_bridge import TrackerBridge
        from .setwriter import SetWriter
        from .state import StateConfig, StateStore

        try:
            registry = read_compiled_allowlist(self.allowlist_file)
        except Exception:
            log.exception(
                "failed to read allowlist file %s", self.allowlist_file)
            return

        self._tracker = DnsSetTracker()
        self._tracker.load_registry(registry)
        log.info(
            "dns pipeline: loaded allowlist (%d qnames)",
            sum(1 for _ in registry.iter_sorted()),
        )

        # Load pull-resolver groups and wire secondary qnames as tracker
        # aliases so the tap pipeline also populates dnsr: sets.
        try:
            dnsr_registry = read_compiled_dnsr_allowlist(self.allowlist_file)
        except Exception:
            log.exception(
                "failed to read dnsr section from allowlist %s",
                self.allowlist_file)
            dnsr_registry = None

        if dnsr_registry and dnsr_registry.groups:
            pull_count = 0
            for group in dnsr_registry.iter_sorted():
                for secondary in group.qnames[1:]:
                    for family in (FAMILY_V4, FAMILY_V6):
                        self._tracker.add_qname_alias(
                            secondary, group.primary_qname, family)
                if group.pull_enabled:
                    pull_count += 1
            log.info(
                "dns pipeline: loaded %d dns-set group(s) "
                "(%d pull, %d tap-only)",
                len(dnsr_registry.groups),
                pull_count,
                len(dnsr_registry.groups) - pull_count,
            )

        loop = asyncio.get_running_loop()
        # Router was created early in run() so the exporter could start
        # using it; here we just attach the freshly-built tracker so
        # newly spawned workers get the right set-name lookup closure.
        # Any workers already forked for read-only scrape traffic must
        # be respawned so their captured (None) tracker gets replaced.
        assert self._router is not None
        already_spawned = list(self._router.iter_workers())
        self._router.attach_tracker(self._tracker)
        for worker in already_spawned:
            try:
                await self._router.respawn_netns(worker.netns)
            except Exception:
                log.exception(
                    "router: tracker-attach respawn failed for %r",
                    worker.netns)
        for netns in netns_list:
            try:
                await self._router.add_netns(netns)
            except Exception:
                log.exception(
                    "router: failed to add netns %r", netns)

        self._set_writer = SetWriter(self._tracker, self._router, loop=loop)
        await self._set_writer.start()

        self._tracker_bridge = TrackerBridge(
            self._tracker, self._set_writer,
            default_netns=netns_list[0] if netns_list else "",
        )

        assert self._registry is not None
        from .dns_set_tracker import DnsSetMetricsCollector
        from .dnstap_bridge import BridgeMetricsCollector
        from .setwriter import SetWriterMetricsCollector
        from .worker_router import WorkerRouterMetricsCollector
        self._registry.add(SetWriterMetricsCollector(self._set_writer))
        self._registry.add(WorkerRouterMetricsCollector(self._router))
        self._registry.add(BridgeMetricsCollector(self._tracker_bridge))
        self._registry.add(DnsSetMetricsCollector(self._tracker))

        # State persistence.
        if self.state_enabled:
            state_cfg = StateConfig(
                state_dir=self.state_dir or StateConfig().state_dir,
                enabled=True,
                load_on_start=not self.state_no_load,
                flush_on_start=self.state_flush,
            )
            self._state_store = StateStore(self._tracker, state_cfg)
            try:
                self._state_store.load()
            except Exception:
                log.exception("state load failed")
            await self._state_store.start(loop)
            from .state import StateMetricsCollector
            self._registry.add(StateMetricsCollector(self._state_store))

        # PBDNSMessage (PowerDNS recursor protobuf logger) ingress.
        # Accepts unix socket (for out-of-tree producers) and/or TCP
        # (required for pdns-recursor's Lua protobufServer() which
        # speaks TCP only). Both can be enabled simultaneously.
        if self.pbdns_socket or self.pbdns_tcp:
            from .pbdns import PbdnsMetricsCollector, PbdnsServer
            tcp_host, tcp_port = None, None
            if self.pbdns_tcp:
                host, _, port_s = self.pbdns_tcp.rpartition(":")
                tcp_host = host or "0.0.0.0"
                try:
                    tcp_port = int(port_s)
                except ValueError:
                    log.error(
                        "pbdns tcp spec %r: bad port", self.pbdns_tcp)
                    tcp_port = None
            pbdns_kwargs: dict = {
                "socket_path": self.pbdns_socket,
                "bridge": self._tracker_bridge,
                "tcp_host": tcp_host,
                "tcp_port": tcp_port,
                "socket_owner": self.socket_owner,
                "socket_group": self.socket_group,
            }
            if self.socket_mode is not None:
                pbdns_kwargs["socket_mode"] = self.socket_mode
            self._pbdns_server = PbdnsServer(**pbdns_kwargs)
            try:
                await self._pbdns_server.start()
            except Exception:
                log.exception(
                    "pbdns server failed to bind "
                    "(socket=%s tcp=%s)",
                    self.pbdns_socket, self.pbdns_tcp)
                self._pbdns_server = None
            else:
                assert self._registry is not None
                self._registry.add(PbdnsMetricsCollector(self._pbdns_server))

        # HA peer link.
        if (self.peer_host and self.peer_port
                and self.peer_auth_key_file is not None):
            from .peer import HmacSha256Auth, PeerLink
            try:
                auth = HmacSha256Auth.from_file(self.peer_auth_key_file)
            except Exception:
                log.exception(
                    "peer auth key load failed from %s",
                    self.peer_auth_key_file)
                auth = None
            if auth is not None:
                self._peer_link = PeerLink(
                    tracker=self._tracker,
                    writer=self._set_writer,
                    auth=auth,
                    bind_host=self.peer_bind_host or "0.0.0.0",
                    bind_port=self.peer_bind_port or 9749,
                    peer_host=self.peer_host,
                    peer_port=self.peer_port,
                    origin_node=socket.gethostname(),
                    heartbeat_interval=self.peer_heartbeat_interval,
                )
                try:
                    await self._peer_link.start(loop)
                except Exception:
                    log.exception(
                        "peer link start failed on %s:%d → %s:%d",
                        self.peer_bind_host, self.peer_bind_port,
                        self.peer_host, self.peer_port)
                    self._peer_link = None
                else:
                    from .peer import PeerMetricsCollector
                    self._registry.add(PeerMetricsCollector(self._peer_link))

        # Pull resolver — active DNS resolution for dnsr: groups.
        # Created eagerly iff groups are known at bootstrap; otherwise
        # InstanceManager may create it lazily when the first dnsr group
        # arrives via register-instance (see _ensure_pull_resolver).
        self._pull_resolver_netns = netns_list[0] if netns_list else ""
        if dnsr_registry and dnsr_registry.groups:
            await self._ensure_pull_resolver(dnsr_registry)

        log.info(
            "dns pipeline: ready (pbdns=%s peer=%s state=%s pull=%s)",
            "on" if self._pbdns_server else "off",
            "on" if self._peer_link else "off",
            "on" if self._state_store else "off",
            "on" if self._pull_resolver else "off",
        )

    async def _ensure_pull_resolver(self, dnsr_registry: Any) -> Any | None:
        """Create the PullResolver on first use, or return the existing one.

        Called both at bootstrap (from :meth:`_start_dns_pipeline` when
        the initial allowlist already contains a ``dnsr:`` group) and
        lazily from :class:`InstanceManager` when a dynamically
        registered instance brings the first one. Idempotent.

        Tap-only groups (``pull_enabled=False``, created by multi-host
        ``dns:`` tokens) do not trigger creation — their secondaries
        are wired via ``tracker.add_qname_alias`` alone.
        """
        if self._pull_resolver is not None:
            return self._pull_resolver
        if self._tracker is None or self._set_writer is None:
            return None
        if not dnsr_registry:
            return None
        pull_groups = [
            g for g in dnsr_registry.groups.values() if g.pull_enabled
        ]
        if not pull_groups:
            return None
        from .dns_pull_resolver import PullResolver
        self._pull_resolver = PullResolver(
            dnsr_registry,
            self._tracker,
            self._set_writer,
            default_netns=self._pull_resolver_netns,
        )
        await self._pull_resolver.start()
        if self._registry is not None:
            from .dns_pull_resolver import PullResolverMetricsCollector
            self._registry.add(PullResolverMetricsCollector(self._pull_resolver))
        # Wire the refresh-dns control handler now if the control server
        # is up; otherwise _start_control_server does it later.
        self._register_refresh_dns_handler()
        log.info(
            "dns pipeline: pull resolver started (%d group(s))",
            len(pull_groups),
        )
        return self._pull_resolver

    def _register_refresh_dns_handler(self) -> None:
        """Register the refresh-dns handler if both server and resolver exist."""
        if self._control_server is None or self._pull_resolver is None:
            return
        resolver = self._pull_resolver

        async def _handle_refresh_dns(req: dict) -> dict:
            hostname = req.get("hostname")
            n = await resolver.refresh(hostname)
            return {"ok": True, "rescheduled": n}

        self._control_server.register_handler(
            "refresh-dns", _handle_refresh_dns)

    async def _start_iplist_tracker(self, netns_list: list[str]) -> None:
        """Start the IP-list tracker for cloud prefix sets."""
        assert self._nft is not None
        assert self._profile_builder is not None
        from .iplist.tracker import IpListTracker

        profiles = self._profile_builder.profiles
        self._iplist_tracker = IpListTracker(
            configs=self.iplist_configs,
            nft=self._nft,
            profiles=profiles,
            registry=self._registry,
        )
        self._iplist_task = asyncio.create_task(
            self._iplist_tracker.run(),
            name="shorewalld.iplist",
        )
        log.info(
            "iplist tracker: started with %d list(s)",
            len(self.iplist_configs),
        )

    async def _start_empty_dns_pipeline(self, netns_list: list[str]) -> None:
        """Bootstrap a minimal empty DNS pipeline for the control-socket path.

        Called when a control socket is configured but no allowlist is
        available at start time.  The InstanceManager will populate the
        tracker via register-instance on first shorewall-nft start.
        """
        assert self._nft is not None
        from .dns_set_tracker import DnsSetTracker
        from .dnstap_bridge import TrackerBridge
        from .setwriter import SetWriter

        try:
            from shorewall_nft.nft.dns_sets import DnsSetRegistry
        except ImportError:
            log.error(
                "dns pipeline: shorewall_nft not installed — "
                "cannot initialise empty pipeline"
            )
            return

        self._tracker = DnsSetTracker()
        self._tracker.load_registry(DnsSetRegistry())

        loop = asyncio.get_running_loop()
        # Router was pre-created in run(); attach the empty tracker now
        # and respawn any scrape-only workers so the lookup closure
        # picks up the new (empty) tracker. Real content is injected
        # later by the InstanceManager.
        assert self._router is not None
        already_spawned = list(self._router.iter_workers())
        self._router.attach_tracker(self._tracker)
        for worker in already_spawned:
            try:
                await self._router.respawn_netns(worker.netns)
            except Exception:
                log.exception(
                    "router: tracker-attach respawn failed for %r",
                    worker.netns)
        # Do NOT pre-start workers here. Workers for non-empty netns fork
        # a child process that inherits a copy of the tracker. If we fork
        # now the tracker is still empty; set-name lookups in the child
        # would always return None and ops would be silently dropped.
        # WorkerRouter.dispatch() spawns workers lazily on first use, by
        # which time the tracker has been populated by InstanceManager.

        self._set_writer = SetWriter(self._tracker, self._router, loop=loop)
        await self._set_writer.start()

        self._tracker_bridge = TrackerBridge(
            self._tracker, self._set_writer,
            default_netns=netns_list[0] if netns_list else "",
        )

        assert self._registry is not None
        from .dns_set_tracker import DnsSetMetricsCollector
        from .dnstap_bridge import BridgeMetricsCollector
        from .setwriter import SetWriterMetricsCollector
        from .worker_router import WorkerRouterMetricsCollector
        self._registry.add(SetWriterMetricsCollector(self._set_writer))
        self._registry.add(WorkerRouterMetricsCollector(self._router))
        self._registry.add(BridgeMetricsCollector(self._tracker_bridge))
        self._registry.add(DnsSetMetricsCollector(self._tracker))

        log.info("dns pipeline: empty pipeline ready for dynamic registration")

    async def _start_instance_manager(self) -> None:
        """Start the multi-instance allowlist manager."""
        assert self._tracker is not None
        assert self._router is not None
        from .instance import InstanceManager, parse_instance_spec
        from .state import DEFAULT_STATE_DIR, InstanceCache

        configs = [parse_instance_spec(spec) for spec in self.instances]

        cache = None
        if self.state_enabled:
            state_dir = self.state_dir or Path(DEFAULT_STATE_DIR)
            cache = InstanceCache(state_dir)

        self._instance_manager = InstanceManager(
            configs=configs,
            tracker=self._tracker,
            router=self._router,
            pull_resolver=self._pull_resolver,
            pull_resolver_factory=self._ensure_pull_resolver,
            cache=cache,
        )
        try:
            await self._instance_manager.start()
        except Exception:
            log.exception("instance manager start failed")
            self._instance_manager = None

    async def _start_control_server(self) -> None:
        """Bind the control Unix socket and register handlers."""
        assert self.control_socket is not None
        from .control import ControlServer

        self._control_server = ControlServer(
            socket_path=self.control_socket,
            netns=self.control_socket_netns,
            socket_mode=self.socket_mode,
        )

        # Register iplist handlers if the tracker is running.
        if self._iplist_tracker is not None:
            tracker = self._iplist_tracker

            async def _handle_refresh_iplist(req: dict) -> dict:
                name = req.get("name")
                if name:
                    await tracker.refresh_one(name)
                else:
                    await tracker.refresh_all()
                return {"ok": True}

            async def _handle_iplist_status(_req: dict) -> dict:
                return {"ok": True, "lists": tracker.status()}

            self._control_server.register_handler(
                "refresh-iplist", _handle_refresh_iplist
            )
            self._control_server.register_handler(
                "iplist-status", _handle_iplist_status
            )

        # Register instance handlers if the manager is running.
        if self._instance_manager is not None:
            mgr = self._instance_manager

            async def _handle_reload_instance(req: dict) -> dict:
                name = req.get("name")
                await mgr.reload(name)
                return {"ok": True}

            async def _handle_instance_status(_req: dict) -> dict:
                return {"ok": True, "instances": mgr.status()}

            async def _handle_register_instance(req: dict) -> dict:
                from pathlib import Path

                from .instance import InstanceConfig
                config_dir = req.get("config_dir")
                netns = req.get("netns") or ""
                if not config_dir:
                    return {"ok": False, "error": "missing 'config_dir'"}
                dir_path = Path(config_dir)
                # Client-supplied name wins (from INSTANCE_NAME / CLI);
                # otherwise derive deterministically.
                name = (req.get("name") or netns or dir_path.name).strip()
                allowlist_path = Path(
                    req.get("allowlist_path")
                    or (dir_path / "dnsnames.compiled")
                )
                cfg = InstanceConfig(
                    name=name,
                    netns=netns,
                    config_dir=dir_path,
                    allowlist_path=allowlist_path,
                )
                dns_payload = None
                if "dns" in req or "dnsr" in req:
                    dns_payload = {
                        k: req[k] for k in ("dns", "dnsr") if k in req
                    }
                n = await mgr.register(cfg, dns_payload=dns_payload)
                return {"ok": True, "name": cfg.name, "qnames": n}

            async def _handle_deregister_instance(req: dict) -> dict:
                name = req.get("name")
                if not name:
                    config_dir = req.get("config_dir")
                    netns = req.get("netns") or ""
                    if config_dir:
                        from pathlib import Path
                        name = netns or Path(config_dir).name
                if not name:
                    return {
                        "ok": False,
                        "error": "missing 'name' or 'config_dir'",
                    }
                await mgr.deregister(name)
                return {"ok": True, "name": name}

            self._control_server.register_handler(
                "reload-instance", _handle_reload_instance
            )
            self._control_server.register_handler(
                "instance-status", _handle_instance_status
            )
            self._control_server.register_handler(
                "register-instance", _handle_register_instance
            )
            self._control_server.register_handler(
                "deregister-instance", _handle_deregister_instance
            )

        # Seed coordinator — answers request-seed commands from shorewall-nft.
        if self._tracker is not None:
            from .seed import SeedCoordinator, SeedMetricsCollector
            _seed = SeedCoordinator(
                tracker=self._tracker,
                pull_resolver=self._pull_resolver,
                peer_link=self._peer_link,
                iplist_tracker=self._iplist_tracker,
                dnstap_active=self._dnstap_server is not None,
                pbdns_active=self._pbdns_server is not None,
            )
            self._control_server.register_handler("request-seed", _seed.handle)
            if self._registry is not None:
                self._registry.add(SeedMetricsCollector(_seed))

        try:
            await self._control_server.start()
        except Exception:
            log.exception(
                "control server failed to start on %s", self.control_socket
            )
            self._control_server = None
            return

        # Now that the control server is up, register handlers for
        # subsystems that came online before it.
        self._register_refresh_dns_handler()
        if self._registry is not None:
            from .control import ControlMetricsCollector
            self._registry.add(ControlMetricsCollector(self._control_server))

    def _install_sigusr1(self) -> None:
        """Install a SIGUSR1 handler that triggers iplist refresh_all."""
        if self._loop is None:
            return
        loop = self._loop
        tracker = self._iplist_tracker

        def _handler() -> None:
            log.info("shorewalld caught SIGUSR1 — triggering iplist refresh")
            if tracker is not None:
                loop.create_task(
                    tracker.refresh_all(),
                    name="shorewalld.iplist.sigusr1_refresh",
                )

        try:
            loop.add_signal_handler(signal.SIGUSR1, _handler)
        except (ValueError, OSError, NotImplementedError):
            pass

    def _start_prom_server(self) -> None:
        """Stand up a prometheus_client-backed HTTP scrape endpoint.

        Uses a custom ``Collector`` that funnels our Registry into the
        default prometheus_client REGISTRY, so the stock
        ``start_http_server`` helper works unchanged.
        """
        try:
            from prometheus_client import (  # type: ignore[import-untyped]
                REGISTRY,
                start_http_server,
            )
        except ImportError:
            log.warning(
                "prometheus_client not installed — install with "
                "'pip install shorewall-nft[daemon]' to enable metrics")
            return

        outer = self

        class _Adapter:
            def collect(self):
                assert outer._registry is not None
                return outer._registry.to_prom_families()

        REGISTRY.register(_Adapter())
        try:
            server, thread = start_http_server(
                self.prom_port, addr=self.prom_host)
        except Exception as e:
            log.error("failed to bind prom endpoint %s:%d: %s",
                      self.prom_host, self.prom_port, e)
            return
        self._prom_server = server
        log.info("shorewalld prom endpoint live on %s:%d",
                 self.prom_host, self.prom_port)

    async def _start_dnstap_server(self, netns_list: list[str]) -> None:
        """Bind the dnstap unix socket and start the decode worker pool."""
        assert self._nft is not None and self.api_socket is not None
        assert self._registry is not None
        dnstap_kwargs: dict = {
            # If the DNS pipeline was initialised first, route every
            # decoded DnsUpdate through the tracker-aware bridge
            # (dedup + batch + persistent worker) instead of the
            # legacy direct-nft SetWriter.
            "bridge": self._tracker_bridge,
            "socket_owner": self.socket_owner,
            "socket_group": self.socket_group,
        }
        if self.socket_mode is not None:
            dnstap_kwargs["socket_mode"] = self.socket_mode
        self._dnstap_server = DnstapServer(
            self.api_socket, self._nft, netns_list,
            **dnstap_kwargs,
        )
        try:
            await self._dnstap_server.start()
        except Exception:
            log.exception("failed to start dnstap server on %s",
                          self.api_socket)
            self._dnstap_server = None
            return
        # Register the metrics collector so queue depth / frame
        # counters show up on the Prometheus endpoint.
        self._registry.add(DnstapMetricsCollector(self._dnstap_server))
        # serve_forever runs as a background task; shutdown() closes
        # the server which makes it return.
        asyncio.create_task(
            self._dnstap_server.serve_forever(),
            name="shorewalld.dnstap")

    async def _reprobe_loop(self) -> None:
        """Tick every ``reprobe_interval`` seconds and refresh profiles."""
        try:
            while not (self._stop_event and self._stop_event.is_set()):
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),  # type: ignore[union-attr]
                        timeout=self.reprobe_interval)
                    return  # stop_event fired
                except asyncio.TimeoutError:
                    pass
                if self._profile_builder is not None:
                    try:
                        self._profile_builder.reprobe()
                    except Exception:
                        log.exception("reprobe failed")
        except asyncio.CancelledError:
            pass

    def request_stop(self) -> None:
        """Ask the ``run()`` coroutine to return cleanly."""
        if self._stop_event is not None and self._loop is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)

    # ── shutdown (pattern lifted from simlab/controller.py) ──────────

    def _register_cleanup(self) -> None:
        if self._cleanup_registered:
            return
        atexit.register(self._shutdown)
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._sig_handler)
            except (ValueError, OSError):
                pass
        self._cleanup_registered = True

    def _sig_handler(self, signum: int, frame: Any) -> None:  # noqa: ARG002
        log.info("shorewalld caught signal %d, shutting down", signum)
        self._shutdown()
        os._exit(128 + signum)

    def shutdown(self) -> None:
        """Public idempotent shutdown entry point (for tests)."""
        self._shutdown()

    async def _async_shutdown(self) -> None:
        """Shutdown path called from ``run()`` while the loop is alive.

        Tears down the async DNS-pipeline subsystems in reverse wiring
        order, then delegates the synchronous parts to :meth:`_shutdown`.
        """
        if self._shutdown_done:
            return

        # Control server: close before tearing down subsystems it references.
        if self._control_server is not None:
            try:
                await self._control_server.shutdown()
            except Exception:
                log.exception("control server shutdown failed")
            self._control_server = None

        # Pull resolver.
        if self._pull_resolver is not None:
            try:
                await self._pull_resolver.shutdown()
            except Exception:
                log.exception("pull resolver shutdown failed")
            self._pull_resolver = None

        # IP-list tracker.
        if self._iplist_task is not None:
            self._iplist_task.cancel()
            try:
                await self._iplist_task
            except (asyncio.CancelledError, Exception):
                pass
            self._iplist_task = None
            self._iplist_tracker = None

        # Instance manager.
        if self._instance_manager is not None:
            try:
                await self._instance_manager.shutdown()
            except Exception:
                log.exception("instance manager shutdown failed")
            self._instance_manager = None

        # Peer link: stop sending heartbeats and close the UDP socket.
        if self._peer_link is not None:
            try:
                await self._peer_link.stop()
            except Exception:
                log.exception("peer link stop failed")
            self._peer_link = None

        # pbdns ingress server.
        if self._pbdns_server is not None:
            try:
                await self._pbdns_server.close()
            except Exception:
                log.exception("pbdns server close failed")
            self._pbdns_server = None

        # State store: final save before the tracker gets torn down.
        if self._state_store is not None:
            try:
                await self._state_store.stop()
            except Exception:
                log.exception("state store stop failed")
            self._state_store = None

        # SetWriter: flush pending batches through the worker router.
        if self._set_writer is not None:
            try:
                await self._set_writer.shutdown()
            except Exception:
                log.exception("set writer shutdown failed")
            self._set_writer = None

        # Worker router: terminate every per-netns fork worker.
        if self._router is not None:
            try:
                await self._router.shutdown()
            except Exception:
                log.exception("worker router shutdown failed")
            self._router = None

        # Drop tracker + bridge references — they own no kernel state.
        self._tracker_bridge = None
        self._tracker = None

        # Synchronous subsystems (prom server, profile teardown, …).
        self._shutdown()

    def _shutdown(self) -> None:
        if self._shutdown_done:
            return
        self._shutdown_done = True

        # 1. Cancel the reprobe loop.
        if self._reprobe_task is not None:
            try:
                self._reprobe_task.cancel()
            except Exception:
                pass
            self._reprobe_task = None

        # 2. Stop the dnstap consumer (Phase 4).
        if self._dnstap_server is not None:
            try:
                self._dnstap_server.close()
            except Exception:
                log.exception("dnstap server close failed")
            self._dnstap_server = None

        # 3. Stop the Prometheus HTTP server (Phase 2).
        if self._prom_server is not None:
            try:
                self._prom_server.shutdown()  # type: ignore[attr-defined]
            except Exception:
                try:
                    self._prom_server.close()
                except Exception:
                    log.exception("prom server close failed")
            self._prom_server = None

        # 4. Tear down every netns profile (Phase 3).
        if self._profile_builder is not None:
            try:
                self._profile_builder.close_all()
            except Exception:
                log.exception("profile teardown failed")
            self._profile_builder = None

        # 5. Wake the main loop so run() returns.
        if self._stop_event is not None and not self._stop_event.is_set():
            if self._loop is not None and self._loop.is_running():
                try:
                    self._loop.call_soon_threadsafe(self._stop_event.set)
                except RuntimeError:
                    pass
            else:
                # No loop running (unit test called shutdown() directly).
                self._stop_event.set()
