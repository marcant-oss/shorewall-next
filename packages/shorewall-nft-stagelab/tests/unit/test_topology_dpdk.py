"""Unit tests for topology_dpdk — all subprocess/sysfs calls are mocked."""

from __future__ import annotations

import json
import logging
import subprocess
from unittest.mock import MagicMock

import pytest

from shorewall_nft_stagelab import topology_dpdk
from shorewall_nft_stagelab.topology_dpdk import (
    DpdkEndpointHandle,
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
    monkeypatch.setattr(topology_dpdk, "_pci_to_ifname", lambda _: "eth1")
    monkeypatch.setattr(topology_dpdk, "_read_master", lambda _: ("bond0", "bond"))

    setup_dpdk_endpoint(_GOOD_SPEC)

    assert rec_file.exists()
    entries = json.loads(rec_file.read_text())
    assert len(entries) == 1
    assert entries[0]["pci_addr"] == _GOOD_PCI
    assert entries[0]["orig_driver"] == "virtio-pci"
    assert entries[0]["orig_master"] == "bond0"
    assert entries[0]["orig_master_kind"] == "bond"


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


# ---------------------------------------------------------------------------
# Test 9 — setup snapshots bond master into handle and recovery entry
# ---------------------------------------------------------------------------


def test_setup_snapshots_bond_master(tmp_path, monkeypatch):
    rec_file = tmp_path / "rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)
    monkeypatch.setattr(topology_dpdk, "_read_current_driver", lambda _: "virtio-pci")
    monkeypatch.setattr(topology_dpdk, "_run_devbind", _fake_devbind_factory())
    monkeypatch.setattr(topology_dpdk, "_pci_to_ifname", lambda _: "eth1")
    monkeypatch.setattr(topology_dpdk, "_read_master", lambda _: ("bond0", "bond"))

    handle = setup_dpdk_endpoint(_GOOD_SPEC)

    assert handle.orig_master == "bond0"
    assert handle.orig_master_kind == "bond"

    entries = json.loads(rec_file.read_text())
    assert entries[0]["orig_master"] == "bond0"
    assert entries[0]["orig_master_kind"] == "bond"


# ---------------------------------------------------------------------------
# Test 10 — teardown re-attaches bond master in correct sequence
# ---------------------------------------------------------------------------


def test_teardown_reattaches_bond_master(tmp_path, monkeypatch):
    rec_file = tmp_path / "rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)
    rec_file.write_text("[]")

    handle = DpdkEndpointHandle(
        name="ep0",
        pci_addr=_GOOD_PCI,
        orig_driver="virtio-pci",
        bound_at_ts=1.0,
        orig_master="bond0",
        orig_master_kind="bond",
    )

    run_calls: list[list[str]] = []

    def _fake_run(cmd: list[str]) -> None:
        run_calls.append(list(cmd))

    monkeypatch.setattr(topology_dpdk, "_run_devbind", _fake_devbind_factory())
    monkeypatch.setattr(topology_dpdk, "_wait_for_netdev", lambda pci, timeout_s=2.0: "eth1")
    monkeypatch.setattr(topology_dpdk, "_run", _fake_run)

    teardown_dpdk_endpoint(handle)

    # Bond sequence: down → master → up → master up
    assert ["ip", "link", "set", "eth1", "down"] in run_calls
    assert ["ip", "link", "set", "eth1", "master", "bond0"] in run_calls
    assert ["ip", "link", "set", "eth1", "up"] in run_calls
    assert ["ip", "link", "set", "bond0", "up"] in run_calls

    # Ordering: down before master
    idx_down = run_calls.index(["ip", "link", "set", "eth1", "down"])
    idx_master = run_calls.index(["ip", "link", "set", "eth1", "master", "bond0"])
    assert idx_down < idx_master


# ---------------------------------------------------------------------------
# Test 11 — teardown re-attaches bridge master (no intermediate down)
# ---------------------------------------------------------------------------


def test_teardown_reattaches_bridge_master(tmp_path, monkeypatch):
    rec_file = tmp_path / "rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)
    rec_file.write_text("[]")

    handle = DpdkEndpointHandle(
        name="ep0",
        pci_addr=_GOOD_PCI,
        orig_driver="virtio-pci",
        bound_at_ts=1.0,
        orig_master="br-trunk",
        orig_master_kind="bridge",
    )

    run_calls: list[list[str]] = []

    def _fake_run(cmd: list[str]) -> None:
        run_calls.append(list(cmd))

    monkeypatch.setattr(topology_dpdk, "_run_devbind", _fake_devbind_factory())
    monkeypatch.setattr(topology_dpdk, "_wait_for_netdev", lambda pci, timeout_s=2.0: "eth1")
    monkeypatch.setattr(topology_dpdk, "_run", _fake_run)

    teardown_dpdk_endpoint(handle)

    # Bridge sequence: master → up → master up (no down step)
    assert ["ip", "link", "set", "eth1", "master", "br-trunk"] in run_calls
    assert ["ip", "link", "set", "eth1", "up"] in run_calls
    assert ["ip", "link", "set", "br-trunk", "up"] in run_calls
    # Must NOT have a 'down' for eth1
    assert ["ip", "link", "set", "eth1", "down"] not in run_calls


# ---------------------------------------------------------------------------
# Test 12 — teardown master-restore failure is best-effort (does not raise)
# ---------------------------------------------------------------------------


def test_teardown_master_restore_best_effort(tmp_path, monkeypatch, caplog):
    rec_file = tmp_path / "rec.json"
    monkeypatch.setattr(topology_dpdk, "RECOVERY_FILE", rec_file)
    rec_file.write_text("[]")

    handle = DpdkEndpointHandle(
        name="ep0",
        pci_addr=_GOOD_PCI,
        orig_driver="virtio-pci",
        bound_at_ts=1.0,
        orig_master="bond0",
        orig_master_kind="bond",
    )

    def _failing_run(cmd: list[str]) -> None:
        if "master" in cmd:
            raise RuntimeError("simulated ip link set master failure")

    monkeypatch.setattr(topology_dpdk, "_run_devbind", _fake_devbind_factory())
    monkeypatch.setattr(topology_dpdk, "_wait_for_netdev", lambda pci, timeout_s=2.0: "eth1")
    monkeypatch.setattr(topology_dpdk, "_run", _failing_run)

    # Must not raise — master restore is best-effort
    with caplog.at_level(logging.WARNING, logger="shorewall_nft_stagelab.topology_dpdk"):
        teardown_dpdk_endpoint(handle)

    assert any("master restore failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Test 13 — _check_numa_affinity warns when core is on different NUMA node
# ---------------------------------------------------------------------------


def test_numa_mismatch_warns(tmp_path, caplog):
    """NIC on node 0, core 4 on node 1 → WARNING with 'cross-socket DMA'."""
    # Build a minimal fake sysfs tree under tmp_path:
    #   sys/bus/pci/devices/0000:01:00.0/numa_node  → "0"
    #   sys/devices/system/cpu/cpu4/node1/           → directory (exists)
    nic_numa = tmp_path / "sys/bus/pci/devices/0000:01:00.0"
    nic_numa.mkdir(parents=True)
    (nic_numa / "numa_node").write_text("0\n")

    cpu4_dir = tmp_path / "sys/devices/system/cpu/cpu4"
    cpu4_dir.mkdir(parents=True)
    (cpu4_dir / "node1").mkdir()

    with caplog.at_level(logging.WARNING, logger="shorewall_nft_stagelab.topology_dpdk"):
        topology_dpdk._check_numa_affinity("0000:01:00.0", (4,), sysfs_root=tmp_path)

    assert any("cross-socket DMA" in m for m in caplog.messages)


# ---------------------------------------------------------------------------
# Test 14 — _check_numa_affinity is silent when core is on same NUMA node
# ---------------------------------------------------------------------------


def test_numa_match_silent(tmp_path, caplog):
    """NIC on node 0, core 4 on node 0 → no warning."""
    nic_numa = tmp_path / "sys/bus/pci/devices/0000:01:00.0"
    nic_numa.mkdir(parents=True)
    (nic_numa / "numa_node").write_text("0\n")

    cpu4_dir = tmp_path / "sys/devices/system/cpu/cpu4"
    cpu4_dir.mkdir(parents=True)
    (cpu4_dir / "node0").mkdir()

    with caplog.at_level(logging.WARNING, logger="shorewall_nft_stagelab.topology_dpdk"):
        topology_dpdk._check_numa_affinity("0000:01:00.0", (4,), sysfs_root=tmp_path)

    assert not any("cross-socket DMA" in m for m in caplog.messages)
