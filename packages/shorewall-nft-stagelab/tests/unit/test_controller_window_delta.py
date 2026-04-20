"""Unit tests for the _window_delta helper and related controller helpers."""

from __future__ import annotations

import math

import pytest

from shorewall_nft_stagelab.controller import (
    _compute_conntrack_window_delta,
    _compute_syn_pass_ratio_delta,
    _window_delta,
)
from shorewall_nft_stagelab.metrics import MetricRow

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(ts: float, key: str = "node_conntrack_count", value: float = 1.0) -> MetricRow:
    return MetricRow(source="test", ts_unix=ts, key=key, value=value)


# ---------------------------------------------------------------------------
# Test 1 — _window_delta happy-path: correct rows are returned per window
# ---------------------------------------------------------------------------


def test_window_delta_happy_path():
    # baseline: ts 0.0–10.0; dos: ts 10.0–20.0
    baseline_rows = [_row(1.0, value=100.0), _row(5.0, value=110.0), _row(9.0, value=115.0)]
    dos_rows = [_row(11.0, value=500.0), _row(15.0, value=520.0)]
    other = [_row(25.0, value=600.0)]  # outside both windows
    all_rows = baseline_rows + dos_rows + other

    found_baseline = _window_delta(all_rows, 0.0, 10.0, "node_conntrack_count")
    found_dos = _window_delta(all_rows, 10.0, 20.0, "node_conntrack_count")

    assert len(found_baseline) == 3
    assert len(found_dos) == 2
    assert set(r.ts_unix for r in found_baseline) == {1.0, 5.0, 9.0}
    assert set(r.ts_unix for r in found_dos) == {11.0, 15.0}


# ---------------------------------------------------------------------------
# Test 2 — _window_delta edge: empty baseline (no rows) → returns empty list
# No ZeroDivisionError should be raised.
# ---------------------------------------------------------------------------


def test_window_delta_empty_baseline_no_error():
    dos_rows = [_row(11.0, value=500.0)]
    # Baseline window [0.0, 5.0] has no rows
    result = _window_delta(dos_rows, 0.0, 5.0, "node_conntrack_count")
    assert result == []
    # Calling the higher-level helper with empty baseline is safe:
    delta_info = _compute_conntrack_window_delta(dos_rows, scenario_start=10.0,
                                                  baseline_window_s=5.0, dos_window_s=5.0)
    ratio = delta_info["conntrack_count_increase_ratio"]
    # baseline is empty → ratio is inf (unbounded increase)
    assert ratio == float("inf") or math.isinf(ratio)


# ---------------------------------------------------------------------------
# Test 3 — _window_delta edge: start_ts >= end_ts → returns empty list
# This handles the case where baseline and dos windows would "overlap" at
# a zero-width window. Callers are expected to pass non-overlapping windows;
# overlapping windows are not prevented here — callers must ensure disjoint
# windows by construction.
# ---------------------------------------------------------------------------


def test_window_delta_inverted_window():
    rows = [_row(5.0, value=100.0)]
    # start >= end → empty result, no error
    result = _window_delta(rows, 10.0, 5.0, "node_conntrack_count")
    assert result == []


# ---------------------------------------------------------------------------
# Test 4 — _compute_syn_pass_ratio_delta basic arithmetic
# ---------------------------------------------------------------------------


def test_compute_syn_pass_ratio_delta_basic():
    delta = _compute_syn_pass_ratio_delta(baseline_pass_ratio=0.01, dos_pass_ratio=0.20)
    assert delta == pytest.approx(0.19)


def test_compute_syn_pass_ratio_delta_no_regression():
    delta = _compute_syn_pass_ratio_delta(baseline_pass_ratio=0.01, dos_pass_ratio=0.01)
    assert delta == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Test 5 — _compute_conntrack_window_delta returns inf when baseline_min == 0
# ---------------------------------------------------------------------------


def test_compute_conntrack_window_delta_zero_baseline():
    rows = [
        _row(12.0, value=5000.0),  # in dos window
    ]
    # scenario_start=10.0, baseline=[0,10), dos=[10,20]
    # Baseline rows: ts 2.0 with value=0.0
    rows_with_zero_baseline = [_row(2.0, value=0.0)] + rows
    result = _compute_conntrack_window_delta(
        rows_with_zero_baseline,
        scenario_start=10.0,
        baseline_window_s=10.0,
        dos_window_s=10.0,
    )
    ratio = result["conntrack_count_increase_ratio"]
    assert ratio == float("inf") or math.isinf(ratio)
