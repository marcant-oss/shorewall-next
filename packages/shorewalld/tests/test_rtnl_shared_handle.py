"""Tests for the shared pyroute2 IPRoute handle cache in collectors/_shared.py.

Scenarios covered:
- get_rtnl() returns the same object on repeated calls (no extra IPRoute
  construction).
- close_rtnl() evicts the cached handle; next get_rtnl() constructs a new one.
- close_all_rtnl() clears every cached handle.
- Thread-safety: 10 concurrent get_rtnl() calls from different threads produce
  exactly one IPRoute construction.
- Different netns keys produce independent cache entries.
- rtnl_handles_cached() reflects the current cache size.
- RtnlHandlesCollector.collect() emits the gauge metric.
"""
from __future__ import annotations

import threading
from typing import Any

import pytest


# ── Fake IPRoute ─────────────────────────────────────────────────────


class FakeIPRoute:
    """Counting stub that records every construction."""

    # Class-level counter so we can reset it between tests.
    count = 0
    instances: list["FakeIPRoute"]

    def __init__(self, **kwargs: Any) -> None:
        type(self).count += 1
        type(self).instances.append(self)
        self.kwargs = kwargs
        self._closed = False

    def close(self) -> None:
        self._closed = True

    @classmethod
    def reset(cls) -> None:
        cls.count = 0
        cls.instances = []


FakeIPRoute.instances = []


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clean_rtnl_cache(monkeypatch):
    """Ensure the rtnl cache is empty before and after each test.

    Also patches ``pyroute2.IPRoute`` with ``FakeIPRoute`` so no real
    netlink sockets are opened.
    """
    # Trigger the full import chain in the correct order so the circular
    # import between shorewalld.exporter and shorewalld.collectors is
    # resolved before we access _shared.
    import shorewalld.exporter  # noqa: F401 — resolves the circular chain
    import shorewalld.collectors._shared as shared  # noqa: F401

    # Clear the cache before the test.
    with shared._RTNL_LOCK:
        shared._RTNL_BY_NETNS.clear()

    # Reset the construction counter.
    FakeIPRoute.reset()

    # Patch IPRoute inside the _shared module's lazy import.
    import sys
    fake_pyroute2 = type(sys)("pyroute2")
    fake_pyroute2.IPRoute = FakeIPRoute
    monkeypatch.setitem(sys.modules, "pyroute2", fake_pyroute2)

    yield

    # Clear the cache after the test to avoid cross-test pollution.
    with shared._RTNL_LOCK:
        shared._RTNL_BY_NETNS.clear()
    FakeIPRoute.reset()


# ── Tests ─────────────────────────────────────────────────────────────


def test_get_rtnl_creates_handle_on_first_call():
    from shorewalld.collectors._shared import get_rtnl
    ipr = get_rtnl("fw")
    assert FakeIPRoute.count == 1
    assert ipr is not None


def test_get_rtnl_returns_same_handle_on_repeated_calls():
    from shorewalld.collectors._shared import get_rtnl
    ipr1 = get_rtnl("fw")
    ipr2 = get_rtnl("fw")
    ipr3 = get_rtnl("fw")
    assert FakeIPRoute.count == 1
    assert ipr1 is ipr2
    assert ipr2 is ipr3


def test_get_rtnl_none_and_empty_string_map_to_same_key():
    from shorewalld.collectors._shared import get_rtnl
    ipr1 = get_rtnl(None)
    ipr2 = get_rtnl("")
    assert FakeIPRoute.count == 1
    assert ipr1 is ipr2


def test_get_rtnl_uses_netns_kwarg_for_named_netns():
    from shorewalld.collectors._shared import get_rtnl
    get_rtnl("fw")
    assert FakeIPRoute.instances[0].kwargs == {"netns": "fw"}


def test_get_rtnl_no_kwarg_for_default_netns():
    from shorewalld.collectors._shared import get_rtnl
    get_rtnl(None)
    assert FakeIPRoute.instances[0].kwargs == {}


def test_different_netns_produce_separate_handles():
    from shorewalld.collectors._shared import get_rtnl
    ipr_fw = get_rtnl("fw")
    ipr_rns = get_rtnl("rns1")
    assert FakeIPRoute.count == 2
    assert ipr_fw is not ipr_rns


def test_close_rtnl_evicts_handle():
    from shorewalld.collectors._shared import close_rtnl, get_rtnl
    ipr1 = get_rtnl("fw")
    assert FakeIPRoute.count == 1

    close_rtnl("fw")
    assert ipr1._closed  # underlying close() was called

    # Next call must create a new one.
    ipr2 = get_rtnl("fw")
    assert FakeIPRoute.count == 2
    assert ipr2 is not ipr1


def test_close_rtnl_noop_for_unknown_netns():
    """close_rtnl on a netns that was never cached must not raise."""
    from shorewalld.collectors._shared import close_rtnl
    close_rtnl("never_seen")  # must not raise


def test_close_all_rtnl_clears_all_handles():
    from shorewalld.collectors._shared import (
        _RTNL_BY_NETNS,
        close_all_rtnl,
        get_rtnl,
    )
    get_rtnl("fw")
    get_rtnl("rns1")
    get_rtnl(None)
    assert FakeIPRoute.count == 3

    close_all_rtnl()
    assert _RTNL_BY_NETNS == {}
    for inst in FakeIPRoute.instances:
        assert inst._closed


def test_close_all_rtnl_next_get_creates_fresh():
    from shorewalld.collectors._shared import close_all_rtnl, get_rtnl
    get_rtnl("fw")
    close_all_rtnl()

    get_rtnl("fw")
    assert FakeIPRoute.count == 2


def test_rtnl_handles_cached_reflects_current_count():
    from shorewalld.collectors._shared import (
        close_all_rtnl,
        get_rtnl,
        rtnl_handles_cached,
    )
    assert rtnl_handles_cached() == 0

    get_rtnl("fw")
    assert rtnl_handles_cached() == 1

    get_rtnl("rns1")
    assert rtnl_handles_cached() == 2

    close_all_rtnl()
    assert rtnl_handles_cached() == 0


def test_thread_safety_single_construction():
    """10 concurrent get_rtnl('fw') calls must produce exactly one IPRoute."""
    from shorewalld.collectors._shared import get_rtnl

    results: list[Any] = []
    lock = threading.Lock()

    def worker() -> None:
        ipr = get_rtnl("fw")
        with lock:
            results.append(ipr)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert FakeIPRoute.count == 1
    # Every thread must have received the same object.
    first = results[0]
    assert all(r is first for r in results)


def test_rtnl_handles_collector_emits_gauge():
    """RtnlHandlesCollector.collect() must emit shorewalld_rtnl_handles_cached."""
    from shorewalld.collectors._shared import RtnlHandlesCollector, get_rtnl

    get_rtnl("fw")
    get_rtnl("rns1")

    col = RtnlHandlesCollector()
    families = col.collect()
    assert len(families) == 1
    fam = families[0]
    assert fam.name == "shorewalld_rtnl_handles_cached"
    assert len(fam.samples) == 1
    _labels, value = fam.samples[0]
    assert value == 2.0
