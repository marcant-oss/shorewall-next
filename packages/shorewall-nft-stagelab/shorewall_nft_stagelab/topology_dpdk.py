"""DPDK endpoint topology: NIC unbind from kernel, bind to vfio-pci, crash recovery."""

from __future__ import annotations

import fcntl
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

RECOVERY_FILE = Path("/var/lib/stagelab/dpdk-bindings.json")

# PCI address as Linux sysfs uses: DDDD:BB:ss.f
_PCI_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")

# Well-known fallback paths for dpdk-devbind.py
_DEVBIND_FALLBACKS = [
    "/usr/share/dpdk/usertools/dpdk-devbind.py",
    "/usr/sbin/dpdk-devbind.py",
    "/usr/bin/dpdk-devbind.py",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DpdkEndpointSpec:
    name: str                    # endpoint label, used only for logging/handle
    pci_addr: str                # e.g. "0000:01:00.0"
    dpdk_cores: tuple[int, ...]  # CPU cores that will drive this port
    hugepages_gib: int           # memory footprint (informational)


@dataclass(frozen=True)
class DpdkEndpointHandle:
    name: str
    pci_addr: str
    orig_driver: str             # "ixgbe" / "mlx5_core" / "virtio-pci" / ...
    bound_at_ts: float           # time.time() when we bound to vfio-pci


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def setup_dpdk_endpoint(spec: DpdkEndpointSpec) -> DpdkEndpointHandle:
    """Unbind NIC from kernel driver, bind to vfio-pci, register recovery entry.

    1. Validate spec (pci regex, cores non-empty, hugepages >= 1).
    2. Read current driver via /sys/bus/pci/devices/<pci_addr>/driver symlink.
       If already vfio-pci, skip bind steps but still register in RECOVERY_FILE.
    3. dpdk-devbind.py -u <pci_addr>  (unbind)
    4. dpdk-devbind.py -b vfio-pci <pci_addr>  (bind)
    5. Append JSON entry to RECOVERY_FILE.
    6. Return DpdkEndpointHandle.

    On any bind failure: attempt rebind to orig_driver (best effort), then raise.
    """
    _validate_spec(spec)

    orig_driver = _read_current_driver(spec.pci_addr)
    already_dpdk = orig_driver == "vfio-pci"

    if not already_dpdk:
        try:
            _run_devbind(["-u", spec.pci_addr])
        except RuntimeError as exc:
            raise RuntimeError(
                f"dpdk: unbind {spec.pci_addr} failed: {exc}"
            ) from exc

        try:
            _run_devbind(["-b", "vfio-pci", spec.pci_addr])
        except RuntimeError as exc:
            # Best-effort rollback to original driver
            if orig_driver:
                try:
                    _run_devbind(["-b", orig_driver, spec.pci_addr])
                except RuntimeError:
                    pass
            raise RuntimeError(
                f"dpdk: bind vfio-pci {spec.pci_addr} failed: {exc}"
            ) from exc

    bound_at = time.time()
    entry = {
        "name": spec.name,
        "pci_addr": spec.pci_addr,
        "orig_driver": orig_driver or "",
        "bound_at_ts": bound_at,
    }
    _append_recovery(entry)

    return DpdkEndpointHandle(
        name=spec.name,
        pci_addr=spec.pci_addr,
        orig_driver=orig_driver or "",
        bound_at_ts=bound_at,
    )


def teardown_dpdk_endpoint(handle: DpdkEndpointHandle) -> None:
    """Rebind NIC to original driver and remove recovery entry.

    Idempotent — double-teardown on the same handle does not raise.
    """
    # Unbind from vfio-pci (best effort — may already be unbound)
    try:
        _run_devbind(["-u", handle.pci_addr])
    except RuntimeError:
        pass

    # Rebind to original driver (best effort)
    if handle.orig_driver:
        try:
            _run_devbind(["-b", handle.orig_driver, handle.pci_addr])
        except RuntimeError:
            pass

    _remove_recovery(handle.pci_addr)


def recover_from_crash() -> list[str]:
    """Called at agent start. Read RECOVERY_FILE; rebind all entries to orig_driver.

    Returns list of pci addresses that were processed. Truncates RECOVERY_FILE
    to [] at the end regardless of individual rebind outcomes. Never raises.
    """
    try:
        entries = _read_recovery()
    except Exception:
        return []

    recovered: list[str] = []
    for entry in entries:
        pci = entry.get("pci_addr", "")
        driver = entry.get("orig_driver", "")
        if not pci:
            continue
        try:
            _run_devbind(["-u", pci])
        except RuntimeError:
            pass
        if driver:
            try:
                _run_devbind(["-b", driver, pci])
            except RuntimeError:
                pass
        recovered.append(pci)

    # Truncate regardless of individual outcomes
    try:
        _write_recovery([])
    except Exception:
        pass

    return recovered


# ---------------------------------------------------------------------------
# Internals (exposed for unit tests)
# ---------------------------------------------------------------------------


def _validate_spec(spec: DpdkEndpointSpec) -> None:
    if not _PCI_RE.match(spec.pci_addr):
        raise ValueError(
            f"Invalid PCI address {spec.pci_addr!r}: "
            r"must match ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$"
        )
    if not spec.dpdk_cores:
        raise ValueError("dpdk_cores must be non-empty")
    if spec.hugepages_gib < 1:
        raise ValueError(f"hugepages_gib must be >= 1, got {spec.hugepages_gib}")


def _read_current_driver(pci_addr: str) -> str | None:
    """Return driver name bound to pci_addr, or None if no driver is bound.

    Reads /sys/bus/pci/devices/<pci_addr>/driver symlink and extracts basename.
    """
    driver_link = Path(f"/sys/bus/pci/devices/{pci_addr}/driver")
    try:
        target = driver_link.resolve()
        return target.name or None
    except (OSError, FileNotFoundError):
        return None


def _find_devbind() -> str:
    """Locate dpdk-devbind.py — check PATH first, then well-known paths."""
    found = shutil.which("dpdk-devbind.py")
    if found:
        return found
    for candidate in _DEVBIND_FALLBACKS:
        if Path(candidate).exists():
            return candidate
    raise RuntimeError(
        "dpdk-devbind.py not found in PATH or well-known locations "
        f"({', '.join(_DEVBIND_FALLBACKS)}). "
        "Install dpdk-tools (Debian) or dpdk (RHEL/Fedora)."
    )


def _run_devbind(args: list[str]) -> subprocess.CompletedProcess:
    """Run dpdk-devbind.py with the given args.

    Raises RuntimeError with stderr excerpt on CalledProcessError.
    """
    devbind = _find_devbind()
    cmd = [devbind] + args
    try:
        return subprocess.run(cmd, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        stderr_slice = (exc.stderr or "").strip()[-400:]
        raise RuntimeError(
            f"dpdk-devbind.py {' '.join(args)} failed (rc={exc.returncode}): "
            f"{stderr_slice}"
        ) from exc


def _read_recovery() -> list[dict]:
    """Read and parse RECOVERY_FILE. Returns [] if missing or empty."""
    if not RECOVERY_FILE.exists():
        return []
    text = RECOVERY_FILE.read_text().strip()
    if not text:
        return []
    return json.loads(text)


def _write_recovery(entries: list[dict]) -> None:
    """Write entries list to RECOVERY_FILE (no locking — use inside flock)."""
    RECOVERY_FILE.parent.mkdir(parents=True, exist_ok=True)
    RECOVERY_FILE.write_text(json.dumps(entries, indent=2))


def _append_recovery(entry: dict) -> None:
    """Append one entry to RECOVERY_FILE under an exclusive file lock."""
    RECOVERY_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Open (or create) for read+write without truncation
    with open(RECOVERY_FILE, "a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        text = fh.read().strip()
        entries: list[dict] = json.loads(text) if text else []
        entries.append(entry)
        fh.seek(0)
        fh.truncate()
        json.dump(entries, fh, indent=2)


def _remove_recovery(pci_addr: str) -> None:
    """Remove the entry for pci_addr from RECOVERY_FILE under an exclusive lock."""
    if not RECOVERY_FILE.exists():
        return
    with open(RECOVERY_FILE, "r+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        text = fh.read().strip()
        entries: list[dict] = json.loads(text) if text else []
        entries = [e for e in entries if e.get("pci_addr") != pci_addr]
        fh.seek(0)
        fh.truncate()
        json.dump(entries, fh, indent=2)
