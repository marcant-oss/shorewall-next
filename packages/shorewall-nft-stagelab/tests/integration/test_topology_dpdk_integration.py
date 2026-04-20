"""Integration tests for topology_dpdk — root-gated, dpdk-devbind.py required."""

from __future__ import annotations

import json
import os
import shutil

import pytest

from shorewall_nft_stagelab import topology_dpdk
from shorewall_nft_stagelab.topology_dpdk import recover_from_crash

# Skip the entire module unless running as root AND dpdk-devbind.py is available
_is_root = os.geteuid() == 0
_has_devbind = shutil.which("dpdk-devbind.py") is not None

pytestmark = pytest.mark.skipif(
    not (_is_root and _has_devbind),
    reason="Integration tests require root and dpdk-devbind.py on PATH",
)


# ---------------------------------------------------------------------------
# Test 1 — recover_from_crash smoke with a bogus PCI address
# ---------------------------------------------------------------------------


def test_recover_from_crash_smoke(tmp_path, monkeypatch):
    """Write a recovery file with a bogus PCI + driver; call recover_from_crash.

    The devbind calls are expected to fail (bogus PCI), but the function must:
    - not hang or propagate exceptions
    - truncate RECOVERY_FILE to [] at the end
    """
    rec_file = tmp_path / "rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)

    entries = [{"pci_addr": "0000:ff:ff.0", "orig_driver": "foo", "name": "ep-bogus", "bound_at_ts": 0.0}]
    rec_file.write_text(json.dumps(entries))

    # recover_from_crash must not raise even if devbind fails
    result = recover_from_crash()

    # The result is either [] (devbind failed before append) or the bogus pci
    assert result == [] or result == ["0000:ff:ff.0"]

    # Recovery file must be truncated regardless
    assert json.loads(rec_file.read_text()) == []


# ---------------------------------------------------------------------------
# Test 2 — full cycle with virtio-user (skipped, future Phase 3 gate)
# ---------------------------------------------------------------------------


def test_full_cycle_with_virtio_user():
    pytest.skip("virtio-user binding requires extra kernel config, Phase 3 gate")
