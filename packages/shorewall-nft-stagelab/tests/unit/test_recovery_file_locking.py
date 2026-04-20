"""Concurrency + robustness tests for topology_dpdk recovery-file locking.

Tests are synchronous (multiprocessing-based); no asyncio.
"""

from __future__ import annotations

import multiprocessing
import time

from shorewall_nft_stagelab import topology_dpdk

# Use fork so that the pre-fork RECOVERY_FILE patch is visible in workers.
multiprocessing.set_start_method("fork", force=True)

# ---------------------------------------------------------------------------
# Module-level mutable used by workers (populated pre-fork by each test).
# ---------------------------------------------------------------------------

_RECOVERY_PATH: object = None  # set to a pathlib.Path before spawning workers


# ---------------------------------------------------------------------------
# Worker callables (must be module-level to be picklable, even under fork).
# ---------------------------------------------------------------------------


def _worker_append(i: int) -> None:
    """Append one entry with a unique PCI address."""
    topology_dpdk.RECOVERY_FILE = _RECOVERY_PATH  # type: ignore[assignment]
    pci = f"{i // 256:04x}:{(i % 256) // 16:02x}:{i % 16:02x}.0"
    topology_dpdk._append_recovery(
        {
            "pci_addr": pci,
            "orig_driver": "virtio_net",
            "name": f"ep-{i}",
            "bound_at_ts": 0.0,
        }
    )


def _worker_append_then_remove(i: int) -> None:
    """Append an entry, wait briefly, then remove it."""
    topology_dpdk.RECOVERY_FILE = _RECOVERY_PATH  # type: ignore[assignment]
    pci = f"{i // 256:04x}:{(i % 256) // 16:02x}:{i % 16:02x}.0"
    topology_dpdk._append_recovery(
        {
            "pci_addr": pci,
            "orig_driver": "virtio_net",
            "name": f"ep-{i}",
            "bound_at_ts": 0.0,
        }
    )
    time.sleep(0.1)
    topology_dpdk._remove_recovery(pci)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRecoveryFileLocking:
    """fcntl LOCK_EX correctness under concurrent access."""

    def test_append_does_not_corrupt_under_concurrency(self, tmp_path):
        """50 parallel appends must produce exactly 50 unique entries."""
        global _RECOVERY_PATH
        rec = tmp_path / "rec.json"
        _RECOVERY_PATH = rec

        # Also patch the module attribute in the parent so _read_recovery works.
        topology_dpdk.RECOVERY_FILE = rec  # type: ignore[assignment]

        n = 50
        with multiprocessing.Pool(20) as pool:
            pool.map(_worker_append, range(n))

        entries = topology_dpdk._read_recovery()

        assert len(entries) == n, (
            f"Expected {n} entries, got {len(entries)} — "
            "likely lost due to a race or corruption"
        )

        pci_addrs = [e["pci_addr"] for e in entries]
        assert len(set(pci_addrs)) == n, (
            "Duplicate PCI addresses detected — corruption under concurrency"
        )

    def test_append_and_remove_interleaved_no_losses(self, tmp_path):
        """20 workers each append then remove; file must be empty at the end."""
        global _RECOVERY_PATH
        rec = tmp_path / "rec.json"
        _RECOVERY_PATH = rec
        topology_dpdk.RECOVERY_FILE = rec  # type: ignore[assignment]

        n = 20
        with multiprocessing.Pool(n) as pool:
            pool.map(_worker_append_then_remove, range(n))

        entries = topology_dpdk._read_recovery()

        assert entries == [], (
            f"Expected empty list after all removes, got {len(entries)} entries: "
            f"{[e.get('pci_addr') for e in entries]}"
        )

    def test_recovery_file_json_remains_valid_after_interrupt(self, tmp_path, monkeypatch):
        """_read_recovery must not raise on truncated/corrupt file content.

        If this test FAILS it means _read_recovery propagates json.JSONDecodeError
        on corrupt input — a robustness gap that should be fixed in topology_dpdk.py.
        """
        rec = tmp_path / "rec.json"
        monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec)

        # Write a well-formed entry first.
        topology_dpdk._append_recovery(
            {
                "pci_addr": "0000:01:00.0",
                "orig_driver": "virtio_net",
                "name": "ep-0",
                "bound_at_ts": 0.0,
            }
        )
        assert rec.exists()

        # Simulate a SIGKILL mid-write by truncating the file to half its size.
        original = rec.read_bytes()
        rec.write_bytes(original[: len(original) // 2])

        # _read_recovery must either return [] or raise — we assert the former.
        # If it raises, the test fails and the bug is reported.
        result = topology_dpdk._read_recovery()
        assert result == [], (
            "_read_recovery should return [] on corrupt/truncated JSON, "
            f"but returned: {result!r}"
        )
