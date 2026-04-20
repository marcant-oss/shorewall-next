"""Unit tests for shorewall_nft_stagelab.metrics."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from shorewall_nft_stagelab.metrics import (
    MetricRow,
    poll_conntrack,
    poll_nft_counters,
    rows_to_csv,
)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

NFT_COUNTERS_STUB = """\
table inet filter {
    counter input_accept {
        comment "accepted in"
        packets 100 bytes 8192
    }
    counter output_drop {
        packets 50 bytes 4096
    }
    counter fw_fwd {
        packets 0 bytes 0
    }
}
"""

CONNTRACK_TWO_CPU_STUB = """\
cpu=0           found=10 invalid=2 insert=5 insert_failed=0 drop=1 early_drop=0 error=0 search_restart=3
cpu=1           found=20 invalid=3 insert=8 insert_failed=1 drop=2 early_drop=0 error=0 search_restart=1
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_rows_to_csv_roundtrip(tmp_path: Path) -> None:
    rows = [
        MetricRow(source="test-src", ts_unix=1_000.0, key=f"k{i}", value=float(i))
        for i in range(5)
    ]
    out = tmp_path / "metrics.csv"
    rows_to_csv(rows, out)

    with out.open() as fh:
        reader = csv.DictReader(fh)
        read_rows = list(reader)

    assert len(read_rows) == 5, "Expected 5 data rows"
    # Verify header columns
    assert set(read_rows[0].keys()) == {"ts_unix", "source", "key", "value"}
    # Verify a round-trip value
    assert read_rows[2]["key"] == "k2"
    assert float(read_rows[2]["value"]) == pytest.approx(2.0)
    assert read_rows[0]["source"] == "test-src"


def test_poll_nft_counters_parses_stub() -> None:
    def ssh_runner(argv: list[str]) -> str:  # noqa: ARG001
        return NFT_COUNTERS_STUB

    rows = poll_nft_counters(ssh_runner)

    # 3 counters × 2 rows (packets + bytes) = 6 rows
    assert len(rows) == 6

    # Check sources split correctly
    pkt_rows = [r for r in rows if r.source == "nft-counters-packets"]
    byte_rows = [r for r in rows if r.source == "nft-counters-bytes"]
    assert len(pkt_rows) == 3
    assert len(byte_rows) == 3

    # Check known values for "input_accept"
    ia_pkt = next(r for r in pkt_rows if r.key == "input_accept")
    ia_byte = next(r for r in byte_rows if r.key == "input_accept")
    assert ia_pkt.value == pytest.approx(100)
    assert ia_byte.value == pytest.approx(8192)

    # Zero-value counter "fw_fwd" must still appear
    fwd_pkt = next(r for r in pkt_rows if r.key == "fw_fwd")
    assert fwd_pkt.value == pytest.approx(0)


def test_poll_conntrack_sums_per_cpu() -> None:
    def ssh_runner(argv: list[str]) -> str:  # noqa: ARG001
        return CONNTRACK_TWO_CPU_STUB

    rows = poll_conntrack(ssh_runner)

    by_key = {r.key: int(r.value) for r in rows}

    # "found": cpu0=10 + cpu1=20 = 30
    assert by_key["found"] == 30
    # "invalid": 2 + 3 = 5
    assert by_key["invalid"] == 5
    # "insert_failed": 0 + 1 = 1
    assert by_key["insert_failed"] == 1
    # "drop": 1 + 2 = 3
    assert by_key["drop"] == 3
    # "cpu" must NOT appear as a key
    assert "cpu" not in by_key
