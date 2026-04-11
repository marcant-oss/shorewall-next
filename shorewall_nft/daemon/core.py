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
    ) -> None:
        self.prom_host = prom_host
        self.prom_port = prom_port
        self.api_socket = api_socket
        self.netns_spec = netns_spec
        self.scrape_interval = scrape_interval
        self.reprobe_interval = reprobe_interval

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
        self._profile_builder = ProfileBuilder(
            self._nft, self._registry, self._scraper)

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

        # Optional dnstap consumer (Phase 4). Off by default.
        if self.api_socket:
            await self._start_dnstap_server(netns_list)

        try:
            await self._stop_event.wait()
        finally:
            self._shutdown()
        return 0

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
        self._dnstap_server = DnstapServer(
            self.api_socket, self._nft, netns_list)
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
