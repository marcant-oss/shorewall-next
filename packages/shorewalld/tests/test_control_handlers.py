"""Unit tests for ControlHandlers (M-1/A-3/M-5 coverage).

Tests exercise every handler method via direct async calls — no Unix socket
needed.  Subsystem dependencies are provided via lightweight test doubles.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from shorewalld.control_handlers import ControlHandlers


# ── Helpers / doubles ──────────────────────────────────────────────────────


class _StubIpListTracker:
    """Minimal IpListTracker stand-in."""

    def __init__(self) -> None:
        self.refresh_one_calls: list[str] = []
        self.refresh_all_called = False
        self._status: list[dict] = [{"name": "aws", "entries": 42}]

    async def refresh_one(self, name: str) -> None:
        self.refresh_one_calls.append(name)

    async def refresh_all(self) -> None:
        self.refresh_all_called = True

    def status(self) -> list[dict]:
        return self._status


class _StubInstanceManager:
    """Minimal InstanceManager stand-in."""

    def __init__(self) -> None:
        self.reload_calls: list[str | None] = []
        self.register_calls: list[Any] = []
        self.deregister_calls: list[str] = []
        self._status: list[dict] = [{"name": "shorewall", "qnames": 3}]
        self._register_return: int = 5

    async def reload(self, name: str | None = None) -> None:
        self.reload_calls.append(name)

    async def register(
        self,
        cfg: Any,
        *,
        dns_payload: Any = None,
        nfsets_payload: Any = None,
    ) -> int:
        self.register_calls.append(cfg)
        return self._register_return

    async def deregister(self, name: str) -> None:
        self.deregister_calls.append(name)

    def status(self) -> list[dict]:
        return self._status


class _StubPullResolver:
    """Minimal PullResolver stand-in."""

    def __init__(self, rescheduled: int = 2) -> None:
        self.refresh_calls: list[str | None] = []
        self._rescheduled = rescheduled

    async def refresh(self, hostname: str | None = None) -> int:
        self.refresh_calls.append(hostname)
        return self._rescheduled


# ── iplist handler tests ───────────────────────────────────────────────────


class TestRefreshIplist:
    def test_refresh_all_when_no_name(self):
        tracker = _StubIpListTracker()
        h = ControlHandlers(iplist_tracker=tracker)
        result = asyncio.run(h.handle_refresh_iplist({"cmd": "refresh-iplist"}))
        assert result == {"ok": True}
        assert tracker.refresh_all_called is True
        assert tracker.refresh_one_calls == []

    def test_refresh_one_when_name_given(self):
        tracker = _StubIpListTracker()
        h = ControlHandlers(iplist_tracker=tracker)
        result = asyncio.run(
            h.handle_refresh_iplist({"cmd": "refresh-iplist", "name": "aws"})
        )
        assert result == {"ok": True}
        assert tracker.refresh_one_calls == ["aws"]
        assert tracker.refresh_all_called is False

    def test_error_when_tracker_absent(self):
        h = ControlHandlers()
        result = asyncio.run(h.handle_refresh_iplist({}))
        assert result["ok"] is False
        assert "not running" in result["error"]


class TestIplistStatus:
    def test_returns_lists(self):
        tracker = _StubIpListTracker()
        h = ControlHandlers(iplist_tracker=tracker)
        result = asyncio.run(h.handle_iplist_status({}))
        assert result["ok"] is True
        assert result["lists"] == [{"name": "aws", "entries": 42}]

    def test_error_when_tracker_absent(self):
        h = ControlHandlers()
        result = asyncio.run(h.handle_iplist_status({}))
        assert result["ok"] is False


# ── instance handler tests ─────────────────────────────────────────────────


class TestReloadInstance:
    def test_reload_all_when_no_name(self):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        result = asyncio.run(h.handle_reload_instance({}))
        assert result == {"ok": True}
        assert mgr.reload_calls == [None]

    def test_reload_named_instance(self):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        result = asyncio.run(
            h.handle_reload_instance({"name": "shorewall"})
        )
        assert result == {"ok": True}
        assert mgr.reload_calls == ["shorewall"]

    def test_reload_name_passed_through(self):
        """Only the name from the request is passed — no transformation."""
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        asyncio.run(h.handle_reload_instance({"name": "fw"}))
        assert mgr.reload_calls == ["fw"]

    def test_error_when_manager_absent(self):
        h = ControlHandlers()
        result = asyncio.run(h.handle_reload_instance({}))
        assert result["ok"] is False
        assert "not running" in result["error"]


class TestInstanceStatus:
    def test_returns_instances(self):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        result = asyncio.run(h.handle_instance_status({}))
        assert result["ok"] is True
        assert result["instances"] == [{"name": "shorewall", "qnames": 3}]

    def test_error_when_manager_absent(self):
        h = ControlHandlers()
        result = asyncio.run(h.handle_instance_status({}))
        assert result["ok"] is False


class TestRegisterInstance:
    def test_happy_path(self, tmp_path: Path):
        mgr = _StubInstanceManager()
        nfsets_hook_called = []

        async def _hook():
            nfsets_hook_called.append(True)

        h = ControlHandlers(instance_mgr=mgr, nfsets_hook=_hook)
        req = {
            "config_dir": str(tmp_path),
            "netns": "",
            "name": "myinstance",
        }
        result = asyncio.run(h.handle_register_instance(req))
        assert result["ok"] is True
        assert result["name"] == "myinstance"
        assert result["qnames"] == 5
        assert len(mgr.register_calls) == 1
        assert nfsets_hook_called == [True]

    def test_name_derived_from_dir_when_absent(self, tmp_path: Path):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        req = {"config_dir": str(tmp_path)}
        result = asyncio.run(h.handle_register_instance(req))
        assert result["ok"] is True
        # name is derived from the directory basename
        assert result["name"] == tmp_path.name

    def test_missing_config_dir_returns_error(self):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        result = asyncio.run(h.handle_register_instance({}))
        assert result["ok"] is False
        assert "config_dir" in result["error"]

    def test_dns_payload_forwarded(self, tmp_path: Path):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        req = {
            "config_dir": str(tmp_path),
            "dns": ["example.com."],
            "dnsr": [],
        }
        result = asyncio.run(h.handle_register_instance(req))
        assert result["ok"] is True

    def test_error_when_manager_absent(self):
        h = ControlHandlers()
        result = asyncio.run(
            h.handle_register_instance({"config_dir": "/tmp/x"})
        )
        assert result["ok"] is False

    def test_nfsets_hook_not_called_on_error(self):
        """nfsets_hook must NOT be called when config_dir is missing."""
        hook_called = []

        async def _hook():
            hook_called.append(True)

        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr, nfsets_hook=_hook)
        asyncio.run(h.handle_register_instance({}))
        assert hook_called == []


class TestDeregisterInstance:
    def test_deregister_by_name(self):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        result = asyncio.run(
            h.handle_deregister_instance({"name": "shorewall"})
        )
        assert result == {"ok": True, "name": "shorewall"}
        assert mgr.deregister_calls == ["shorewall"]

    def test_deregister_by_config_dir(self, tmp_path: Path):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        req = {"config_dir": str(tmp_path), "netns": ""}
        result = asyncio.run(h.handle_deregister_instance(req))
        assert result["ok"] is True
        assert result["name"] == tmp_path.name

    def test_deregister_by_config_dir_with_netns(self, tmp_path: Path):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        req = {"config_dir": str(tmp_path), "netns": "fw"}
        result = asyncio.run(h.handle_deregister_instance(req))
        assert result["ok"] is True
        # netns takes priority over dir basename
        assert result["name"] == "fw"

    def test_missing_name_and_config_dir_returns_error(self):
        mgr = _StubInstanceManager()
        h = ControlHandlers(instance_mgr=mgr)
        result = asyncio.run(h.handle_deregister_instance({}))
        assert result["ok"] is False
        assert "name" in result["error"] or "config_dir" in result["error"]

    def test_error_when_manager_absent(self):
        h = ControlHandlers()
        result = asyncio.run(
            h.handle_deregister_instance({"name": "x"})
        )
        assert result["ok"] is False


# ── refresh-dns handler tests ──────────────────────────────────────────────


class TestRefreshDns:
    def test_refresh_all(self):
        resolver = _StubPullResolver(rescheduled=3)
        h = ControlHandlers(pull_resolver=resolver)
        result = asyncio.run(h.handle_refresh_dns({}))
        assert result == {"ok": True, "rescheduled": 3}
        assert resolver.refresh_calls == [None]

    def test_refresh_named_hostname(self):
        resolver = _StubPullResolver()
        h = ControlHandlers(pull_resolver=resolver)
        result = asyncio.run(
            h.handle_refresh_dns({"hostname": "example.com."})
        )
        assert result["ok"] is True
        assert resolver.refresh_calls == ["example.com."]

    def test_error_when_resolver_absent(self):
        h = ControlHandlers()
        result = asyncio.run(h.handle_refresh_dns({}))
        assert result["ok"] is False
        assert "not running" in result["error"]


# ── shutdown error aggregation (M-4) ──────────────────────────────────────


class TestShutdownErrorAggregation:
    """Verify that _async_shutdown aggregates errors without fail-fast.

    Strategy: stub every subsystem so that 'set_writer' raises a
    TypeError during shutdown, then confirm:
    1. sys.exit(1) was called (or would be).
    2. worker_router.shutdown() was still reached (no fail-fast).
    """

    def test_shutdown_aggregates_errors_and_exits_nonzero(self, monkeypatch):
        """A broken subsystem must not suppress other shutdown steps."""
        from shorewalld.core import Daemon

        # Build a minimal daemon without starting the event loop.
        d = Daemon(
            prom_host="127.0.0.1",
            prom_port=0,
            api_socket=None,
            netns_spec=[""],
            scrape_interval=30.0,
            reprobe_interval=300.0,
        )

        # Arm the stop event so _shutdown() doesn't deadlock.
        loop = asyncio.new_event_loop()

        # Track calls to individual subsystems.
        router_shutdown_called = []
        setwriter_shutdown_called = []

        class _BrokenSetWriter:
            async def shutdown(self) -> None:
                raise TypeError("deliberate test error")

        class _OkRouter:
            async def shutdown(self) -> None:
                router_shutdown_called.append(True)

        d._set_writer = _BrokenSetWriter()
        d._router = _OkRouter()
        d._shutdown_done = False

        # Suppress all the None-guard branches for subsystems we didn't set.
        # (They're already None so the guards short-circuit.)

        exit_codes: list[int] = []

        def _fake_exit(code: int) -> None:
            exit_codes.append(code)

        monkeypatch.setattr(sys, "exit", _fake_exit)

        # _shutdown() tries to fire _stop_event; give it one.
        import asyncio as _asyncio
        stop_event = _asyncio.Event()
        # Pre-set so _shutdown()'s call_soon_threadsafe path doesn't hang.
        d._stop_event = stop_event
        d._loop = loop

        async def _run():
            stop_event.set()
            await d._async_shutdown()

        loop.run_until_complete(_run())
        loop.close()

        # set_writer raised → exit(1) expected.
        assert exit_codes == [1], f"expected [1], got {exit_codes}"
        # router step must have been reached despite set_writer error.
        assert router_shutdown_called == [True], (
            "worker_router.shutdown() was not called after set_writer failure"
        )

    def test_clean_shutdown_does_not_exit_nonzero(self, monkeypatch):
        """When all steps succeed, sys.exit must NOT be called."""
        from shorewalld.core import Daemon

        d = Daemon(
            prom_host="127.0.0.1",
            prom_port=0,
            api_socket=None,
            netns_spec=[""],
            scrape_interval=30.0,
            reprobe_interval=300.0,
        )

        exit_codes: list[int] = []
        monkeypatch.setattr(sys, "exit", lambda c: exit_codes.append(c))

        loop = asyncio.new_event_loop()
        import asyncio as _asyncio
        stop_event = _asyncio.Event()
        d._stop_event = stop_event
        d._loop = loop

        async def _run():
            stop_event.set()
            await d._async_shutdown()

        loop.run_until_complete(_run())
        loop.close()

        assert exit_codes == [], f"unexpected sys.exit calls: {exit_codes}"
