"""Unit tests for topology_dpdk — all subprocess/sysfs calls are mocked."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock

import pytest

from shorewall_nft_stagelab import topology_dpdk
from shorewall_nft_stagelab.topology_dpdk import (
    DpdkEndpointSpec,
    recover_from_crash,
    setup_dpdk_endpoint,
    teardown_dpdk_endpoint,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GOOD_PCI = "0000:01:00.0"
_GOOD_SPEC = DpdkEndpointSpec(
    name="ep0",
    pci_addr=_GOOD_PCI,
    dpdk_cores=(4, 5),
    hugepages_gib=2,
)


def _fake_devbind_factory(fail_on: str | None = None):
    """Return a _run_devbind mock that records calls and optionally raises on an arg."""
    calls: list[list[str]] = []

    def _fake(args: list[str]) -> MagicMock:
        calls.append(list(args))
        if fail_on and fail_on in args:
            raise RuntimeError(f"simulated devbind failure for {args}")
        result = MagicMock(spec=subprocess.CompletedProcess)
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        return result

    _fake.calls = calls  # type: ignore[attr-defined]
    return _fake


# ---------------------------------------------------------------------------
# Test 1 — setup invokes unbind then bind vfio-pci in correct order
# ---------------------------------------------------------------------------


def test_setup_invokes_unbind_then_bind_vfio(tmp_path, monkeypatch):
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", tmp_path / "rec.json")
    monkeypatch.setattr(topology_dpdk, "_read_current_driver", lambda _: "ixgbe")

    fake = _fake_devbind_factory()
    monkeypatch.setattr(topology_dpdk, "_run_devbind", fake)

    setup_dpdk_endpoint(_GOOD_SPEC)

    assert fake.calls == [
        ["-u", _GOOD_PCI],
        ["-b", "vfio-pci", _GOOD_PCI],
    ]


# ---------------------------------------------------------------------------
# Test 2 — setup writes a recovery entry with pci_addr + orig_driver
# ---------------------------------------------------------------------------


def test_setup_writes_recovery_entry(tmp_path, monkeypatch):
    rec_file = tmp_path / "rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)
    monkeypatch.setattr(topology_dpdk, "_read_current_driver", lambda _: "virtio-pci")
    monkeypatch.setattr(topology_dpdk, "_run_devbind", _fake_devbind_factory())

    setup_dpdk_endpoint(_GOOD_SPEC)

    assert rec_file.exists()
    entries = json.loads(rec_file.read_text())
    assert len(entries) == 1
    assert entries[0]["pci_addr"] == _GOOD_PCI
    assert entries[0]["orig_driver"] == "virtio-pci"


# ---------------------------------------------------------------------------
# Test 3 — invalid PCI address raises ValueError
# ---------------------------------------------------------------------------


def test_setup_invalid_pci_rejected():
    bad_spec = DpdkEndpointSpec(
        name="bad",
        pci_addr="badstring",
        dpdk_cores=(0,),
        hugepages_gib=1,
    )
    with pytest.raises(ValueError, match="Invalid PCI address"):
        setup_dpdk_endpoint(bad_spec)


# ---------------------------------------------------------------------------
# Test 4 — setup rolls back to orig_driver when bind step fails
# ---------------------------------------------------------------------------


def test_setup_rollback_on_bind_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", tmp_path / "rec.json")
    monkeypatch.setattr(topology_dpdk, "_read_current_driver", lambda _: "ixgbe")

    # Fail when "vfio-pci" appears in args (i.e. the bind step)
    fake = _fake_devbind_factory(fail_on="vfio-pci")
    monkeypatch.setattr(topology_dpdk, "_run_devbind", fake)

    with pytest.raises(RuntimeError):
        setup_dpdk_endpoint(_GOOD_SPEC)

    # calls: unbind, (attempted) bind vfio-pci, rollback rebind ixgbe
    assert ["-u", _GOOD_PCI] in fake.calls
    assert ["-b", "ixgbe", _GOOD_PCI] in fake.calls


# ---------------------------------------------------------------------------
# Test 5 — teardown rebinds to orig_driver and clears recovery entry
# ---------------------------------------------------------------------------


def test_teardown_rebinds_and_removes_recovery(tmp_path, monkeypatch):
    rec_file = tmp_path / "rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)
    monkeypatch.setattr(topology_dpdk, "_read_current_driver", lambda _: "ixgbe")

    fake = _fake_devbind_factory()
    monkeypatch.setattr(topology_dpdk, "_run_devbind", fake)

    handle = setup_dpdk_endpoint(_GOOD_SPEC)
    fake.calls.clear()

    teardown_dpdk_endpoint(handle)

    # Must unbind and rebind to ixgbe
    assert ["-u", _GOOD_PCI] in fake.calls
    assert ["-b", "ixgbe", _GOOD_PCI] in fake.calls

    # Recovery file must be empty after teardown
    entries = json.loads(rec_file.read_text())
    assert entries == []


# ---------------------------------------------------------------------------
# Test 6 — teardown is idempotent (no raise on second call)
# ---------------------------------------------------------------------------


def test_teardown_idempotent(tmp_path, monkeypatch):
    rec_file = tmp_path / "rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)
    monkeypatch.setattr(topology_dpdk, "_read_current_driver", lambda _: "ixgbe")
    monkeypatch.setattr(topology_dpdk, "_run_devbind", _fake_devbind_factory())

    handle = setup_dpdk_endpoint(_GOOD_SPEC)

    # First teardown
    teardown_dpdk_endpoint(handle)
    # Second teardown must not raise
    teardown_dpdk_endpoint(handle)


# ---------------------------------------------------------------------------
# Test 7 — recover_from_crash rebinds all entries and truncates recovery file
# ---------------------------------------------------------------------------


def test_recover_from_crash_rebinds_all(tmp_path, monkeypatch):
    rec_file = tmp_path / "rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)

    entries = [
        {"pci_addr": "0000:01:00.0", "orig_driver": "ixgbe", "name": "ep0", "bound_at_ts": 1.0},
        {"pci_addr": "0000:02:00.0", "orig_driver": "virtio-pci", "name": "ep1", "bound_at_ts": 2.0},
    ]
    rec_file.write_text(json.dumps(entries))

    fake = _fake_devbind_factory()
    monkeypatch.setattr(topology_dpdk, "_run_devbind", fake)

    recovered = recover_from_crash()

    assert set(recovered) == {"0000:01:00.0", "0000:02:00.0"}

    # Must have issued unbind + rebind for both NICs
    assert ["-b", "ixgbe", "0000:01:00.0"] in fake.calls
    assert ["-b", "virtio-pci", "0000:02:00.0"] in fake.calls

    # RECOVERY_FILE must be truncated to empty list
    remaining = json.loads(rec_file.read_text())
    assert remaining == []


# ---------------------------------------------------------------------------
# Test 8 — recover_from_crash returns [] when file is absent
# ---------------------------------------------------------------------------


def test_recover_from_crash_missing_file_returns_empty(tmp_path, monkeypatch):
    rec_file = tmp_path / "nonexistent-rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)

    result = recover_from_crash()
    assert result == []
