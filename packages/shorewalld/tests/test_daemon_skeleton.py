"""Phase 1 shorewalld skeleton: CLI + Daemon lifecycle unit tests."""
from __future__ import annotations

import asyncio

import pytest

from shorewalld.cli import (
    _parse_listen_addr,
    _parse_netns_spec,
    build_parser,
)
from shorewalld.core import Daemon

# ── CLI parsing ───────────────────────────────────────────────────────


def test_parse_listen_addr_with_host():
    assert _parse_listen_addr("127.0.0.1:9748") == ("127.0.0.1", 9748)


def test_parse_listen_addr_bare_port():
    assert _parse_listen_addr(":9748") == ("0.0.0.0", 9748)


def test_parse_listen_addr_invalid_port():
    with pytest.raises(Exception):
        _parse_listen_addr(":notaport")


def test_parse_listen_addr_out_of_range():
    with pytest.raises(Exception):
        _parse_listen_addr(":70000")


def test_parse_listen_addr_missing_colon():
    with pytest.raises(Exception):
        _parse_listen_addr("9748")


def test_parse_netns_spec_empty_means_own_netns():
    assert _parse_netns_spec("") == [""]


def test_parse_netns_spec_auto():
    assert _parse_netns_spec("auto") == "auto"


def test_parse_netns_spec_comma_list():
    assert _parse_netns_spec("fw,rns1,rns2") == ["fw", "rns1", "rns2"]


def test_parse_netns_spec_strips_whitespace():
    assert _parse_netns_spec(" fw , rns1 ") == ["fw", "rns1"]


def test_parser_defaults_match_spec():
    args = build_parser().parse_args([])
    assert args.listen_prom == ":9748"
    assert args.listen_api is None
    assert args.netns == ""
    assert args.scrape_interval == 30.0
    assert args.reprobe_interval == 300.0
    assert args.log_level == "info"


def test_parser_full_roundtrip():
    args = build_parser().parse_args([
        "--listen-prom", "0.0.0.0:9999",
        "--listen-api", "/run/shorewalld.sock",
        "--netns", "fw,rns1,rns2",
        "--scrape-interval", "5",
        "--reprobe-interval", "60",
        "--log-level", "debug",
    ])
    assert args.listen_prom == "0.0.0.0:9999"
    assert args.listen_api == "/run/shorewalld.sock"
    assert args.netns == "fw,rns1,rns2"
    assert args.scrape_interval == 5.0
    assert args.reprobe_interval == 60.0
    assert args.log_level == "debug"


# ── Daemon lifecycle ──────────────────────────────────────────────────


def _make_daemon(**overrides) -> Daemon:
    defaults = dict(
        prom_host="127.0.0.1",
        prom_port=9748,
        api_socket=None,
        netns_spec=[""],
        scrape_interval=30.0,
        reprobe_interval=300.0,
    )
    defaults.update(overrides)
    return Daemon(**defaults)


def test_daemon_constructs():
    d = _make_daemon()
    assert d.prom_port == 9748
    assert d.api_socket is None
    assert d.netns_spec == [""]


def test_daemon_shutdown_is_idempotent():
    d = _make_daemon()
    d.shutdown()
    # Second call must be a no-op, not raise.
    d.shutdown()
    d.shutdown()


def test_daemon_shutdown_clears_subsystems():
    d = _make_daemon()
    # Stub a subsystem and verify _shutdown tears it down exactly once.
    calls = []

    class FakeServer:
        def close(self):
            calls.append("close")

    d._prom_server = FakeServer()
    d.shutdown()
    assert calls == ["close"]
    assert d._prom_server is None


def test_daemon_run_returns_on_stop():
    """run() must unblock cleanly when request_stop() is called."""
    d = _make_daemon()

    async def driver():
        task = asyncio.create_task(d.run())
        # Give the daemon a chance to enter the wait.
        await asyncio.sleep(0.01)
        d.request_stop()
        return await asyncio.wait_for(task, timeout=2.0)

    rc = asyncio.run(driver())
    assert rc == 0
