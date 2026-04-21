"""Tests for shorewalld._ingress_metrics._IngressMetricsBase.

Covers:
- Basic counter increment via inc().
- inc() on an undeclared counter raises KeyError with a clear message.
- snapshot() returns an independent copy.
- set_last_frame_now() updates last_frame_mono.
- Concurrent inc() from 10 threads × 1000 iterations yields exactly 10 000
  (GIL atomicity of dict[int] += 1 on pre-registered keys).
- Subclass with its own _COUNTER_NAMES works end-to-end.
"""

from __future__ import annotations

import threading
import time

import pytest

from shorewalld._ingress_metrics import _IngressMetricsBase


# ── Concrete subclass for testing ────────────────────────────────────


class _SimpleMetrics(_IngressMetricsBase):
    _COUNTER_NAMES = ("packets", "errors", "drops")


# ── Basic behaviour ──────────────────────────────────────────────────


def test_counters_initialised_to_zero():
    m = _SimpleMetrics()
    assert m._counters == {"packets": 0, "errors": 0, "drops": 0}


def test_inc_declared_counter():
    m = _SimpleMetrics()
    m.inc("packets")
    assert m._counters["packets"] == 1


def test_inc_by_n():
    m = _SimpleMetrics()
    m.inc("packets", 5)
    assert m._counters["packets"] == 5


def test_inc_negative_n():
    """Decrement is permitted (used for gauge-style counters like connections)."""
    m = _SimpleMetrics()
    m.inc("packets", 3)
    m.inc("packets", -1)
    assert m._counters["packets"] == 2


def test_inc_undeclared_raises_key_error():
    m = _SimpleMetrics()
    with pytest.raises(KeyError) as exc_info:
        m.inc("nonexistent")
    msg = str(exc_info.value)
    assert "nonexistent" in msg
    assert "_COUNTER_NAMES" in msg


def test_inc_unknown_counter_error_mentions_class_name():
    m = _SimpleMetrics()
    with pytest.raises(KeyError) as exc_info:
        m.inc("bogus_counter")
    assert "_SimpleMetrics" in str(exc_info.value)


# ── snapshot() independence ───────────────────────────────────────────


def test_snapshot_returns_all_counters():
    m = _SimpleMetrics()
    m.inc("packets", 7)
    snap = m.snapshot()
    assert snap["packets"] == 7
    assert snap["errors"] == 0
    assert snap["drops"] == 0


def test_snapshot_is_independent_copy():
    m = _SimpleMetrics()
    m.inc("packets", 3)
    snap = m.snapshot()
    # Mutating the snapshot must not affect the source
    snap["packets"] = 9999
    assert m._counters["packets"] == 3


def test_snapshot_does_not_include_undeclared_keys():
    m = _SimpleMetrics()
    snap = m.snapshot()
    assert set(snap.keys()) == {"packets", "errors", "drops"}


# ── set_last_frame_now() ──────────────────────────────────────────────


def test_set_last_frame_now_updates_timestamp():
    m = _SimpleMetrics()
    assert m.last_frame_mono == 0.0
    before = time.monotonic()
    m.set_last_frame_now()
    after = time.monotonic()
    assert before <= m.last_frame_mono <= after


def test_last_frame_mono_starts_at_zero():
    m = _SimpleMetrics()
    assert m.last_frame_mono == 0.0


# ── Attribute-style access via __getattr__ ───────────────────────────


def test_attribute_style_read_of_registered_counter():
    m = _SimpleMetrics()
    m.inc("packets", 42)
    # __getattr__ should forward to _counters
    assert m.packets == 42


def test_attribute_style_read_of_unknown_raises_attribute_error():
    m = _SimpleMetrics()
    with pytest.raises(AttributeError):
        _ = m.not_a_counter


# ── Concurrent increment (GIL atomicity) ─────────────────────────────


def test_concurrent_inc_is_atomic():
    """10 threads × 1000 increments on the same counter must sum to 10 000.

    Under CPython, ``dict[key] += 1`` for a pre-registered key is
    effectively atomic because the GIL is held for the entire
    BINARY_SUBSCR + INPLACE_ADD + STORE_SUBSCR sequence.  No lock
    is required and no increment should be lost.
    """
    N_THREADS = 10
    N_ITERS = 1000

    m = _SimpleMetrics()

    def hammer() -> None:
        for _ in range(N_ITERS):
            m.inc("packets")

    threads = [threading.Thread(target=hammer) for _ in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert m._counters["packets"] == N_THREADS * N_ITERS


# ── Subclass with its own _COUNTER_NAMES ─────────────────────────────


class _PbdnsLike(_IngressMetricsBase):
    _COUNTER_NAMES = (
        "frames_total",
        "frames_error_total",
        "connections",
    )


def test_subclass_counter_names_are_initialised():
    m = _PbdnsLike()
    assert set(m._counters.keys()) == {
        "frames_total", "frames_error_total", "connections"}


def test_subclass_inc_and_snapshot():
    m = _PbdnsLike()
    m.inc("frames_total", 3)
    m.inc("connections")
    m.inc("connections", -1)
    snap = m.snapshot()
    assert snap["frames_total"] == 3
    assert snap["connections"] == 0


def test_subclass_unknown_counter_raises():
    m = _PbdnsLike()
    with pytest.raises(KeyError):
        m.inc("frames_accepted_total")  # not in this subclass


# ── Benchmark (opt-in, -m bench) ─────────────────────────────────────


@pytest.mark.bench
def test_bench_inc_1m_iterations():
    """1 000 000 increments of a single counter — measures hot-path cost.

    Run with: pytest -m bench packages/shorewalld/tests/test_ingress_metrics_base.py

    With a 3 GHz CPU and the GIL, expect < 0.5 s (500 ns/op overhead).
    The old lock path typically costs 5–20 µs/op under contention.
    """
    m = _SimpleMetrics()
    N = 1_000_000
    t0 = time.monotonic()
    for _ in range(N):
        m.inc("packets")
    elapsed = time.monotonic() - t0
    assert m._counters["packets"] == N
    # Soft upper bound: 2 s for 1M iterations on any reasonably modern box.
    assert elapsed < 2.0, (
        f"1M inc() iterations took {elapsed:.3f}s — unexpectedly slow")
