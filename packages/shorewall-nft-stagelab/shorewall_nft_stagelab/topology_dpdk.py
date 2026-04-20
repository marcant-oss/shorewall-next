"""DPDK endpoint topology: NIC unbind from kernel, bind to vfio-pci, crash recovery."""

from __future__ import annotations

import fcntl
import json
import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)

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
    # master-interface snapshot (captured before unbind)
    orig_master: str | None = None        # bond/bridge master iface name, or None
    orig_master_kind: str | None = None   # "bond" | "bridge" | None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def setup_dpdk_endpoint(spec: DpdkEndpointSpec) -> DpdkEndpointHandle:
    """Unbind NIC from kernel driver, bind to vfio-pci, register recovery entry.

    Validates spec, reads orig_driver + master-snapshot, unbinds, binds vfio-pci,
    appends recovery entry. On bind failure: rollback to orig_driver then raise.
    """
    _validate_spec(spec)

    orig_driver = _read_current_driver(spec.pci_addr)
    already_dpdk = orig_driver == "vfio-pci"

    ifname = _pci_to_ifname(spec.pci_addr)
    orig_master, orig_master_kind = _read_master(ifname) if ifname else (None, None)

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
        "orig_master": orig_master,
        "orig_master_kind": orig_master_kind,
    }
    _append_recovery(entry)

    return DpdkEndpointHandle(
        name=spec.name,
        pci_addr=spec.pci_addr,
        orig_driver=orig_driver or "",
        bound_at_ts=bound_at,
        orig_master=orig_master,
        orig_master_kind=orig_master_kind,
    )


def teardown_dpdk_endpoint(handle: DpdkEndpointHandle) -> None:
    """Rebind NIC to original driver, restore bond/bridge master, remove recovery entry.

    Idempotent; master restore is best-effort.
    """
    try:
        _run_devbind(["-u", handle.pci_addr])
    except RuntimeError:
        pass
    if handle.orig_driver:
        try:
            _run_devbind(["-b", handle.orig_driver, handle.pci_addr])
        except RuntimeError:
            pass

    # Restore bond/bridge membership (best-effort)
    if handle.orig_master and handle.orig_master_kind:
        try:
            ifname = _wait_for_netdev(handle.pci_addr, timeout_s=2.0)
            _restore_master(ifname, handle.orig_master, handle.orig_master_kind)
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "dpdk: master restore failed for %s (master=%s kind=%s): %s",
                handle.pci_addr, handle.orig_master, handle.orig_master_kind, exc,
            )

    _remove_recovery(handle.pci_addr)


def recover_from_crash() -> list[str]:
    """Rebind all RECOVERY_FILE entries to orig_driver; restore master if present.

    Returns processed pci addresses. Truncates file at end. Never raises.
    """
    try:
        entries = _read_recovery()
    except Exception:
        return []

    recovered: list[str] = []
    for entry in entries:
        pci = entry.get("pci_addr", "")
        driver = entry.get("orig_driver", "")
        orig_master = entry.get("orig_master")
        orig_master_kind = entry.get("orig_master_kind")
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
        if orig_master and orig_master_kind:
            try:
                ifname = _wait_for_netdev(pci, timeout_s=2.0)
                _restore_master(ifname, orig_master, orig_master_kind)
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "dpdk: crash-recovery master restore failed for %s: %s", pci, exc
                )
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


def _pci_to_ifname(pci_addr: str) -> str | None:
    """Return kernel netdev name for pci_addr via sysfs, or None."""
    net_dir = Path(f"/sys/bus/pci/devices/{pci_addr}/net")
    try:
        names = list(net_dir.iterdir())
        return names[0].name if names else None
    except (OSError, FileNotFoundError):
        return None


def _read_master(ifname: str) -> tuple[str | None, str | None]:
    """Return (master_ifname, kind) where kind in {"bond","bridge"}, or (None,None)."""
    master_link = Path(f"/sys/class/net/{ifname}/master")
    try:
        master_name = master_link.resolve().name
        if not master_name:
            return (None, None)
    except (OSError, FileNotFoundError):
        return (None, None)
    if Path(f"/sys/class/net/{master_name}/bonding").exists():
        return (master_name, "bond")
    if Path(f"/sys/class/net/{master_name}/bridge").exists():
        return (master_name, "bridge")
    _log.warning("dpdk: master %r for %r has unknown kind; skipping restore", master_name, ifname)
    return (None, None)


def _wait_for_netdev(pci_addr: str, timeout_s: float = 2.0) -> str:
    """Poll sysfs until a netdev appears for pci_addr. Raises RuntimeError on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        ifname = _pci_to_ifname(pci_addr)
        if ifname:
            return ifname
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"dpdk: netdev for {pci_addr} did not appear within {timeout_s}s after rebind"
            )
        time.sleep(0.1)


def _run(cmd: list[str]) -> None:
    """Run cmd; raise RuntimeError with stderr on non-zero exit."""
    try:
        subprocess.run(cmd, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"{' '.join(cmd)} failed (rc={exc.returncode}): {(exc.stderr or '').strip()[-400:]}"
        ) from exc


def _restore_master(ifname: str, master: str, kind: str) -> None:
    """Re-enslave ifname to master. Bond: down→master→up; bridge: master→up."""
    if kind == "bond":
        _run(["ip", "link", "set", ifname, "down"])
        _run(["ip", "link", "set", ifname, "master", master])
        _run(["ip", "link", "set", ifname, "up"])
        _run(["ip", "link", "set", master, "up"])
    elif kind == "bridge":
        _run(["ip", "link", "set", ifname, "master", master])
        _run(["ip", "link", "set", ifname, "up"])
        _run(["ip", "link", "set", master, "up"])
    else:
        _log.warning("dpdk: unknown master kind %r; skipping restore for %s", kind, ifname)


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
    """Return driver name bound to pci_addr (via sysfs symlink), or None."""
    driver_link = Path(f"/sys/bus/pci/devices/{pci_addr}/driver")
    try:
        target = driver_link.resolve()
        return target.name or None
    except (OSError, FileNotFoundError):
        return None


def _find_devbind() -> str:
    """Locate dpdk-devbind.py — PATH first, then well-known paths."""
    found = shutil.which("dpdk-devbind.py")
    if found:
        return found
    for candidate in _DEVBIND_FALLBACKS:
        if Path(candidate).exists():
            return candidate
    raise RuntimeError(
        "dpdk-devbind.py not found in PATH or well-known locations "
        f"({', '.join(_DEVBIND_FALLBACKS)}). Install dpdk-tools (Debian) or dpdk (RHEL/Fedora)."
    )


def _run_devbind(args: list[str]) -> subprocess.CompletedProcess:
    """Run dpdk-devbind.py; raise RuntimeError with stderr on failure."""
    devbind = _find_devbind()
    cmd = [devbind] + args
    try:
        return subprocess.run(cmd, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"dpdk-devbind.py {' '.join(args)} failed (rc={exc.returncode}): "
            f"{(exc.stderr or '').strip()[-400:]}"
        ) from exc


def _read_recovery() -> list[dict]:
    """Read and parse RECOVERY_FILE. Returns [] if missing, empty, or
    corrupt — e.g., after a SIGKILL mid-write left partial JSON. A
    corrupt file is a better-lost-than-dangerous situation: continuing
    with stale bindings beats refusing to start and leaving NICs stuck."""
    if not RECOVERY_FILE.exists():
        return []
    text = RECOVERY_FILE.read_text().strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return []


def _write_recovery(entries: list[dict]) -> None:
    """Write entries to RECOVERY_FILE (no locking — call inside flock)."""
    RECOVERY_FILE.parent.mkdir(parents=True, exist_ok=True)
    RECOVERY_FILE.write_text(json.dumps(entries, indent=2))


def _append_recovery(entry: dict) -> None:
    """Append one entry to RECOVERY_FILE under an exclusive lock."""
    RECOVERY_FILE.parent.mkdir(parents=True, exist_ok=True)
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
