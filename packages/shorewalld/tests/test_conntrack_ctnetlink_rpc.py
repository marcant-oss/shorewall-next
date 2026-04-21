"""Tests for the READ_KIND_CTNETLINK worker RPC and ConntrackStatsCollector.

Covers:

* Wire codec for ``READ_KIND_CTNETLINK`` (encode / decode round-trip).
* ``_handle_read_ctnetlink`` worker-side handler with a mock
  ``NFCTSocket``.
* End-to-end happy path via :func:`inproc_worker_pair` (SEQPACKET,
  no fork) — ``ctnetlink_stats_sync`` returns the correct counters.
* Error paths: ENOENT (netns gone), pyroute2 absent, worker timeout.
* ``ConntrackStatsCollector.collect()`` uses the router (no setns).
* Verify no live ``setns`` / ``_in_netns`` calls exist in the
  ``collectors/`` package.
"""
from __future__ import annotations

import asyncio
import threading
from dataclasses import fields
from unittest.mock import MagicMock, patch

import pytest

from shorewalld.nft_worker import _handle_read_ctnetlink
from shorewalld.read_codec import (
    CT_STATS_FIELDS,
    CT_STATS_STRUCT_SIZE,
    READ_KIND_CTNETLINK,
    READ_STATUS_ERROR,
    READ_STATUS_OK,
    CtNetlinkStats,
    decode_ct_stats,
    encode_ct_stats,
    encode_read_request,
)


# ── Wire codec round-trip ─────────────────────────────────────────────


def test_encode_decode_ct_stats_roundtrip():
    original = CtNetlinkStats(
        CTA_STATS_FOUND=1750,
        CTA_STATS_INVALID=6,
        CTA_STATS_IGNORE=100,
        CTA_STATS_INSERT_FAILED=2,
        CTA_STATS_DROP=5,
        CTA_STATS_EARLY_DROP=0,
        CTA_STATS_ERROR=3,
        CTA_STATS_SEARCH_RESTART=12,
    )
    packed = encode_ct_stats(original)
    assert len(packed) == CT_STATS_STRUCT_SIZE  # 64 bytes

    decoded = decode_ct_stats(packed)
    assert decoded.CTA_STATS_FOUND == 1750
    assert decoded.CTA_STATS_INVALID == 6
    assert decoded.CTA_STATS_IGNORE == 100
    assert decoded.CTA_STATS_INSERT_FAILED == 2
    assert decoded.CTA_STATS_DROP == 5
    assert decoded.CTA_STATS_EARLY_DROP == 0
    assert decoded.CTA_STATS_ERROR == 3
    assert decoded.CTA_STATS_SEARCH_RESTART == 12


def test_ct_stats_default_all_zeros():
    stats = CtNetlinkStats()
    for f in fields(stats):
        assert getattr(stats, f.name) == 0


def test_ct_stats_struct_size_is_64_bytes():
    assert CT_STATS_STRUCT_SIZE == 64


def test_decode_ct_stats_raises_on_short_input():
    from shorewalld.read_codec import ReadWireError
    with pytest.raises(ReadWireError, match="too short"):
        decode_ct_stats(b"\x00" * 10)


def test_ct_stats_fields_covers_all_cta_attrs():
    """CT_STATS_FIELDS contains exactly the CTA_STATS_* attrs used by the collector.

    We check against the canonical list rather than reimporting conntrack
    (which would trigger an exporter/collectors circular import in some
    test isolation modes).
    """
    expected = (
        "CTA_STATS_FOUND",
        "CTA_STATS_INVALID",
        "CTA_STATS_IGNORE",
        "CTA_STATS_INSERT_FAILED",
        "CTA_STATS_DROP",
        "CTA_STATS_EARLY_DROP",
        "CTA_STATS_ERROR",
        "CTA_STATS_SEARCH_RESTART",
    )
    assert CT_STATS_FIELDS == expected


def test_encode_read_request_ctnetlink_empty_path():
    """CTNETLINK requests use an empty path — header encodes cleanly."""
    payload = encode_read_request(
        kind=READ_KIND_CTNETLINK, req_id=99, path="")
    assert len(payload) == 18  # header only, no path bytes


# ── _handle_read_ctnetlink with mocked NFCTSocket ─────────────────────


class _FakeCtRow:
    """Minimal stand-in for a pyroute2 nfct_stats_cpu message."""

    def __init__(self, attrs: dict[str, int]) -> None:
        self._attrs = attrs

    def get_attr(self, key: str) -> int | None:
        return self._attrs.get(key)


def _make_rows(n_cpus: int, **per_cpu_attrs: int) -> list[_FakeCtRow]:
    """Build *n_cpus* identical fake rows with the given attribute values."""
    return [_FakeCtRow(per_cpu_attrs) for _ in range(n_cpus)]


def test_handle_read_ctnetlink_sums_three_cpus():
    rows = _make_rows(
        3,
        CTA_STATS_FOUND=100,
        CTA_STATS_INVALID=1,
        CTA_STATS_DROP=2,
        CTA_STATS_SEARCH_RESTART=5,
    )
    fake_sock = MagicMock()
    fake_sock.stat.return_value = rows

    import shorewalld.nft_worker as _worker_mod
    original = _worker_mod._nfct_socket
    try:
        _worker_mod._nfct_socket = fake_sock
        status, data = _handle_read_ctnetlink()
    finally:
        _worker_mod._nfct_socket = original

    assert status == READ_STATUS_OK
    assert len(data) == CT_STATS_STRUCT_SIZE
    decoded = decode_ct_stats(data)
    assert decoded.CTA_STATS_FOUND == 300   # 3 × 100
    assert decoded.CTA_STATS_INVALID == 3   # 3 × 1
    assert decoded.CTA_STATS_DROP == 6      # 3 × 2
    assert decoded.CTA_STATS_SEARCH_RESTART == 15  # 3 × 5
    assert decoded.CTA_STATS_IGNORE == 0
    assert decoded.CTA_STATS_INSERT_FAILED == 0


def test_handle_read_ctnetlink_returns_error_on_netlink_exception():
    """NetlinkError / OSError from NFCTSocket → READ_STATUS_ERROR + message."""
    fake_sock = MagicMock()
    fake_sock.stat.side_effect = OSError("ENOENT: netns gone")

    import shorewalld.nft_worker as _worker_mod
    original = _worker_mod._nfct_socket
    try:
        _worker_mod._nfct_socket = fake_sock
        status, data = _handle_read_ctnetlink()
    finally:
        _worker_mod._nfct_socket = original

    assert status == READ_STATUS_ERROR
    assert b"ENOENT" in data


def test_handle_read_ctnetlink_missing_pyroute2():
    """ImportError when pyroute2 not installed → READ_STATUS_ERROR."""
    import shorewalld.nft_worker as _worker_mod
    original = _worker_mod._nfct_socket
    try:
        _worker_mod._nfct_socket = None  # reset so _get_nfct_socket runs
        with patch.dict("sys.modules", {"pyroute2": None}):
            with patch("builtins.__import__", side_effect=lambda name, *a, **kw: (
                (_ for _ in ()).throw(ImportError("no pyroute2"))
                if name == "pyroute2" else __import__(name, *a, **kw)
            )):
                status, data = _handle_read_ctnetlink()
    finally:
        _worker_mod._nfct_socket = original

    assert status == READ_STATUS_ERROR


def test_handle_read_ctnetlink_empty_rows():
    """Zero rows → all-zero stats struct, OK status."""
    fake_sock = MagicMock()
    fake_sock.stat.return_value = []

    import shorewalld.nft_worker as _worker_mod
    original = _worker_mod._nfct_socket
    try:
        _worker_mod._nfct_socket = fake_sock
        status, data = _handle_read_ctnetlink()
    finally:
        _worker_mod._nfct_socket = original

    assert status == READ_STATUS_OK
    decoded = decode_ct_stats(data)
    for f in fields(decoded):
        assert getattr(decoded, f.name) == 0


# ── End-to-end via inproc_worker_pair ────────────────────────────────


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


def _run_loop_in_thread(loop: asyncio.AbstractEventLoop) -> threading.Thread:
    """Start *loop* in a background daemon thread, return the thread."""
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    return t


def test_ctnetlink_stats_async_happy_path(
    event_loop: asyncio.AbstractEventLoop,
):
    """ParentWorker.ctnetlink_stats() returns correct counters end-to-end.

    Uses the inproc SEQPACKET pair (no fork) and drives the coroutine
    via run_until_complete — avoids the threading complexity of the sync
    wrappers while still exercising the full SEQPACKET dispatch.
    """
    from shorewalld.worker_router import inproc_worker_pair

    rows = _make_rows(2,
                      CTA_STATS_FOUND=500,
                      CTA_STATS_INVALID=7,
                      CTA_STATS_DROP=3)
    fake_sock = MagicMock()
    fake_sock.stat.return_value = rows

    import shorewalld.nft_worker as _worker_mod
    original = _worker_mod._nfct_socket

    pw, _worker_t = inproc_worker_pair(
        tracker=None,
        loop=event_loop,
        set_name_lookup=lambda _k: None,
    )

    try:
        _worker_mod._nfct_socket = fake_sock
        stats = event_loop.run_until_complete(pw.ctnetlink_stats())
    finally:
        _worker_mod._nfct_socket = original
        event_loop.run_until_complete(pw.shutdown())

    assert stats is not None
    assert stats.CTA_STATS_FOUND == 1000   # 2 × 500
    assert stats.CTA_STATS_INVALID == 14   # 2 × 7
    assert stats.CTA_STATS_DROP == 6       # 2 × 3


def test_ctnetlink_stats_async_returns_none_on_worker_error(
    event_loop: asyncio.AbstractEventLoop,
):
    """If the worker returns READ_STATUS_ERROR, coroutine returns None."""
    from shorewalld.worker_router import inproc_worker_pair

    fake_sock = MagicMock()
    fake_sock.stat.side_effect = OSError("netns gone")

    import shorewalld.nft_worker as _worker_mod
    original = _worker_mod._nfct_socket

    pw, _worker_t = inproc_worker_pair(
        tracker=None,
        loop=event_loop,
        set_name_lookup=lambda _k: None,
    )

    try:
        _worker_mod._nfct_socket = fake_sock
        stats = event_loop.run_until_complete(pw.ctnetlink_stats())
    finally:
        _worker_mod._nfct_socket = original
        event_loop.run_until_complete(pw.shutdown())

    assert stats is None


def test_ctnetlink_stats_sync_timeout_returns_none():
    """When the worker hangs, sync adapter → None without stalling the caller.

    Runs the event loop in a background thread so run_coroutine_threadsafe
    can schedule work, then calls ctnetlink_stats_sync from the main
    thread to exercise the thread-safety path.
    """
    from shorewalld.worker_router import WorkerRouter

    loop = asyncio.new_event_loop()
    bg = _run_loop_in_thread(loop)

    class _HangingParent:
        async def ctnetlink_stats(self):
            await asyncio.sleep(60)  # longer than the 0.1s timeout

    router = WorkerRouter(loop=loop)
    router._workers["hang"] = _HangingParent()
    try:
        stats = router.ctnetlink_stats_sync("hang", timeout=0.1)
    finally:
        loop.call_soon_threadsafe(loop.stop)
        bg.join(timeout=2.0)
        loop.close()

    assert stats is None


def test_ctnetlink_stats_sync_happy_path_threaded():
    """ctnetlink_stats_sync called from a non-loop thread returns stats.

    This is the production scrape-thread path: the event loop is running
    in a background thread; the scrape thread calls ctnetlink_stats_sync
    via run_coroutine_threadsafe.
    """
    from shorewalld.worker_router import WorkerRouter, inproc_worker_pair

    rows = _make_rows(1, CTA_STATS_FOUND=77, CTA_STATS_DROP=3)
    fake_sock = MagicMock()
    fake_sock.stat.return_value = rows

    import shorewalld.nft_worker as _worker_mod
    original = _worker_mod._nfct_socket

    loop = asyncio.new_event_loop()
    bg = _run_loop_in_thread(loop)

    # Wire up the worker: schedule setup on the bg loop, wait for it.
    ready = threading.Event()
    pw_holder: list = []

    def _setup_on_loop():
        pw, _wt = inproc_worker_pair(
            tracker=None, loop=loop,
            set_name_lookup=lambda _k: None)
        pw_holder.append(pw)
        ready.set()

    loop.call_soon_threadsafe(_setup_on_loop)
    assert ready.wait(timeout=2.0), "worker setup timed out"

    pw = pw_holder[0]
    router = WorkerRouter(loop=loop)
    router._workers["inproc"] = pw

    try:
        _worker_mod._nfct_socket = fake_sock
        stats = router.ctnetlink_stats_sync("inproc", timeout=5.0)
    finally:
        _worker_mod._nfct_socket = original
        asyncio.run_coroutine_threadsafe(
            pw.shutdown(), loop).result(timeout=2.0)
        loop.call_soon_threadsafe(loop.stop)
        bg.join(timeout=2.0)
        loop.close()

    assert stats is not None
    assert stats.CTA_STATS_FOUND == 77
    assert stats.CTA_STATS_DROP == 3


# ── ConntrackStatsCollector via FakeRouter ────────────────────────────


class _FakeCtRouter:
    """Minimal stub implementing ctnetlink_stats_sync for collector tests."""

    def __init__(self, stats: CtNetlinkStats | None) -> None:
        self._stats = stats
        self.calls: list[str] = []

    def ctnetlink_stats_sync(
        self, netns: str, *, timeout: float = 5.0,
    ) -> CtNetlinkStats | None:
        self.calls.append(netns)
        return self._stats


def test_conntrack_stats_collector_emits_all_families():
    """Collector emits all 8 metric families on success."""
    from shorewalld.collectors.conntrack import (
        _CT_STAT_FIELDS,
        ConntrackStatsCollector,
    )

    stats = CtNetlinkStats(
        CTA_STATS_FOUND=1000,
        CTA_STATS_INVALID=5,
        CTA_STATS_IGNORE=20,
        CTA_STATS_INSERT_FAILED=2,
        CTA_STATS_DROP=1,
        CTA_STATS_EARLY_DROP=0,
        CTA_STATS_ERROR=3,
        CTA_STATS_SEARCH_RESTART=7,
    )
    router = _FakeCtRouter(stats)
    col = ConntrackStatsCollector("fw", router)
    families = col.collect()

    assert len(families) == len(_CT_STAT_FIELDS)
    by_name = {f.name: f for f in families}

    assert by_name["shorewall_nft_ct_found_total"].samples == [
        (["fw"], 1000.0)]
    assert by_name["shorewall_nft_ct_invalid_total"].samples == [
        (["fw"], 5.0)]
    assert by_name["shorewall_nft_ct_drop_total"].samples == [
        (["fw"], 1.0)]
    assert by_name["shorewall_nft_ct_search_restart_total"].samples == [
        (["fw"], 7.0)]

    assert router.calls == ["fw"]


def test_conntrack_stats_collector_skips_sample_on_none():
    """When router returns None the collector emits empty families."""
    from shorewalld.collectors.conntrack import (
        _CT_STAT_FIELDS,
        ConntrackStatsCollector,
    )

    router = _FakeCtRouter(None)
    col = ConntrackStatsCollector("fw", router)
    families = col.collect()

    assert len(families) == len(_CT_STAT_FIELDS)
    for fam in families:
        assert fam.samples == [], f"{fam.name} should be empty, got {fam.samples}"


def test_conntrack_stats_collector_emits_correct_netns_label():
    """The netns label in samples matches the constructor argument."""
    from shorewalld.collectors.conntrack import ConntrackStatsCollector

    stats = CtNetlinkStats(CTA_STATS_FOUND=42)
    router = _FakeCtRouter(stats)
    col = ConntrackStatsCollector("ns_firewall", router)
    families = col.collect()

    found = next(f for f in families
                 if f.name == "shorewall_nft_ct_found_total")
    assert found.samples[0][0] == ["ns_firewall"]


# ── Verify no setns in collectors/ ───────────────────────────────────


def test_collectors_package_has_no_setns_calls():
    """After the conversion, no collector module must call setns/_in_netns.

    Reads the source files directly so the check is not fooled by import
    guards or conditional imports.

    Strategy: scan every non-comment, non-docstring line for patterns
    that would indicate an active call or import:
      - ``_in_netns(`` — direct call
      - ``import _in_netns`` — import
      - ``setns(`` — direct syscall wrapper call

    References that appear only inside triple-quoted docstrings (for
    historical context) are not caught because they don't contain a bare
    ``(`` after the token in an import/call pattern — but the filter
    checks explicitly for call-site patterns.
    """
    import ast
    from pathlib import Path
    import shorewalld.collectors as _pkg
    pkg_dir = Path(_pkg.__file__).parent

    violations = []
    for py_file in sorted(pkg_dir.glob("*.py")):
        if py_file.name.startswith("__"):
            continue
        text = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(py_file))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            # Check for import of _in_netns
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                src = ast.unparse(node)
                if "_in_netns" in src or "setns" in src:
                    violations.append(
                        f"{py_file.name}:{node.lineno}: {src}")
            # Check for direct calls to _in_netns() or setns()
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    if func.id in ("_in_netns", "setns"):
                        violations.append(
                            f"{py_file.name}:{node.lineno}: "
                            f"call to {func.id}()")
                elif isinstance(func, ast.Attribute):
                    if func.attr in ("_in_netns", "setns"):
                        violations.append(
                            f"{py_file.name}:{node.lineno}: "
                            f"call to .{func.attr}()")

    assert violations == [], (
        "Active setns/_in_netns calls found in collectors/:\n"
        + "\n".join(violations)
    )
