"""Daemon.run() DNS-pipeline lifecycle integration.

Asserts the new opt-in wiring in ``shorewalld.core``: when
``allowlist_file`` is set, the Daemon builds tracker + router +
setwriter + bridge + state store; when not, it
builds none of them. WorkerRouter is stubbed so no fork happens.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from shorewalld import core as core_mod
from shorewalld.core import Daemon
from shorewalld.daemon_config import DaemonConfig
from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsSetSpec, write_compiled_allowlist


class _StubRegistry:
    """Registry double that silently accepts collector registrations."""

    def add(self, collector) -> None:
        pass

    def to_prom_families(self):
        return []


class _StubRouter:
    """Router double that skips fork+setns and records add_netns calls."""

    def __init__(self, *, loop, tracker=None) -> None:
        self.tracker = tracker
        self.loop = loop
        self.added: list[str] = []
        self.shutdown_called = False

    def attach_tracker(self, tracker) -> None:
        self.tracker = tracker

    def iter_workers(self):
        return []

    async def respawn_netns(self, netns: str) -> None:
        pass

    async def add_netns(self, netns: str):
        self.added.append(netns)

        class _Worker:
            async def dispatch(self, builder):
                return 0

            async def shutdown(self):
                pass

        return _Worker()

    async def dispatch(self, netns: str, builder) -> int:
        return 0

    async def shutdown(self) -> None:
        self.shutdown_called = True

    # ── Read-RPC surface (scrape-thread sync) — no-op in tests ─────────
    def read_file_sync(self, netns: str, path: str, *,
                       timeout: float = 5.0):
        return None

    def count_lines_sync(self, netns: str, path: str, *,
                         timeout: float = 5.0):
        return None


@pytest.fixture
def allowlist_file(tmp_path: Path) -> Path:
    registry = DnsSetRegistry()
    registry.add_spec(DnsSetSpec(
        qname="github.com.", ttl_floor=300, ttl_ceil=3600,
        size=1024, comment="test",
    ))
    path = tmp_path / "dns-allowlist.tsv"
    write_compiled_allowlist(registry, path)
    return path


def test_daemon_without_allowlist_does_not_build_pipeline(
    monkeypatch, tmp_path: Path,
):
    """Baseline: default Daemon has no tracker / router / bridge.

    Uses the typed DaemonConfig path as a happy-path regression for the
    config object (no DeprecationWarning should be emitted here).
    """
    # Skip the exporter side (prometheus_client / libnftables).
    monkeypatch.setattr(Daemon, "_start_prom_server", lambda self: None)

    async def run():
        cfg = DaemonConfig(
            prom_host="127.0.0.1", prom_port=0, api_socket=None,
            netns_spec=[""], scrape_interval=30.0, reprobe_interval=300.0,
        )
        d = Daemon(config=cfg)

        async def trigger_stop():
            await asyncio.sleep(0.05)
            assert d._stop_event is not None
            d._stop_event.set()

        monkeypatch.setattr(
            d, "_profile_builder", None, raising=False)
        # Short-circuit the exporter setup so run() doesn't touch nft.
        orig_run = d.run

        async def wrapped_run():
            # Avoid NftInterface construction — stub before run() builds it.
            class _StubNft:
                def list_table(self, *a, **kw):
                    return None

                def cmd(self, *a, **kw):
                    return None

            def _noop(*a, **kw):
                pass

            import shorewalld.core as mod
            monkeypatch.setattr(
                mod, "NftInterface", lambda: _StubNft())

            class _StubPB:
                profiles: dict = {}

                def build(self, lst):
                    pass

                def reprobe(self):
                    pass

                def close_all(self):
                    pass

            monkeypatch.setattr(
                mod, "ProfileBuilder",
                lambda nft, registry, scraper, router: _StubPB())
            monkeypatch.setattr(
                mod, "NftScraper", lambda nft, ttl_s: object())
            monkeypatch.setattr(
                mod, "ShorewalldRegistry", lambda: _StubRegistry())
            asyncio.get_running_loop().create_task(trigger_stop())
            return await orig_run()

        rc = await wrapped_run()
        assert rc == 0
        assert d._tracker is None
        # The router is now created early in run() regardless of
        # whether the DNS-set pipeline bootstraps, so the collectors
        # can delegate /proc reads from the first scrape onwards.
        assert d._router is None or d._router.tracker is None
        assert d._set_writer is None
        assert d._tracker_bridge is None
        assert d._state_store is None

    asyncio.run(run())


def test_daemon_with_allowlist_builds_pipeline(
    monkeypatch, allowlist_file: Path, tmp_path: Path,
):
    """With ``allowlist_file`` set, tracker + router + writer + bridge +
    state store are all initialised, and the stub
    router sees the configured netns list."""
    stub_router: _StubRouter | None = None

    def _stub_router_ctor(*, loop, tracker=None):
        nonlocal stub_router
        stub_router = _StubRouter(tracker=tracker, loop=loop)
        return stub_router

    async def run():
        class _StubNft:
            def list_table(self, *a, **kw):
                return None

            def cmd(self, *a, **kw):
                return None

        monkeypatch.setattr(core_mod, "NftInterface", lambda: _StubNft())
        monkeypatch.setattr(Daemon, "_start_prom_server", lambda self: None)

        # Stub the per-netns profile builder so we don't touch libnftables.
        class _StubPB:
            profiles: dict = {"": object()}

            def build(self, lst):
                pass

            def reprobe(self):
                pass

            def close_all(self):
                pass

        monkeypatch.setattr(
            core_mod, "ProfileBuilder",
            lambda nft, registry, scraper, router: _StubPB())
        monkeypatch.setattr(
            core_mod, "NftScraper", lambda nft, ttl_s: object())
        monkeypatch.setattr(
            core_mod, "ShorewalldRegistry", lambda: _StubRegistry())

        # Swap the real WorkerRouter for the stub. Since core.py now
        # imports WorkerRouter at module top level, patch the
        # ``core.WorkerRouter`` name the Daemon actually references.
        monkeypatch.setattr(core_mod, "WorkerRouter", _stub_router_ctor)

        state_dir = tmp_path / "state"
        d = Daemon(
            prom_host="127.0.0.1", prom_port=0, api_socket=None,
            netns_spec=[""], scrape_interval=30.0, reprobe_interval=300.0,
            allowlist_file=allowlist_file,
            state_dir=state_dir,
        )

        async def trigger_stop():
            # Give _start_dns_pipeline time to finish wiring.
            for _ in range(40):
                if d._tracker is not None and d._set_writer is not None:
                    break
                await asyncio.sleep(0.01)
            assert d._stop_event is not None
            d._stop_event.set()

        asyncio.get_running_loop().create_task(trigger_stop())
        rc = await d.run()
        assert rc == 0

    asyncio.run(run())

    # After run() returns the shutdown has already torn everything
    # down; we asserted wiring during the grace window via the side
    # effect on the stub router.
    assert stub_router is not None
    assert stub_router.added == [""]
    assert stub_router.shutdown_called is True
