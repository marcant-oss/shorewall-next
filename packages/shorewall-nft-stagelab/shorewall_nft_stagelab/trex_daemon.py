"""TRex daemon lifecycle management: spawn / wait / stop t-rex-64 --daemon."""

from __future__ import annotations

import logging
import os
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)

DEFAULT_TREX_BINARY = Path(os.environ.get("STAGELAB_TREX_BINARY", "/opt/trex/v3.04/t-rex-64"))
CFG_DIR = Path("/tmp")


@dataclass(frozen=True)
class TrexDaemonSpec:
    mode: str                    # "stl" | "astf"
    port: int                    # RPC port (4501 STL, 4502 ASTF)
    pci_ports: tuple[str, ...]   # ordered — position = TRex port id
    cores: tuple[int, ...]       # CPU cores DPDK poll threads bind to
    binary_path: Path = DEFAULT_TREX_BINARY


@dataclass(frozen=True)
class TrexDaemonHandle:
    mode: str
    port: int
    pid: int
    started_at_ts: float
    cfg_path: Path


def ensure_running(spec: TrexDaemonSpec) -> TrexDaemonHandle:
    """Idempotent. If a daemon is already listening on spec.port, return a handle
    with the existing pid. Otherwise write cfg, spawn, wait ≤10 s for RPC socket.

    Raises RuntimeError on spawn failure.
    """
    cfg_path = CFG_DIR / f"trex-{spec.mode}-{spec.port}.yaml"

    if is_running(spec.port):
        pid = _find_pid(cfg_path, spec.binary_path)
        _log.info("trex: daemon already running port=%d pid=%d", spec.port, pid)
        return TrexDaemonHandle(mode=spec.mode, port=spec.port, pid=pid,
                                started_at_ts=time.time(), cfg_path=cfg_path)

    if not spec.binary_path.exists():
        raise RuntimeError(f"TRex binary not found: {spec.binary_path}")

    _write_cfg(spec, cfg_path)
    proc = subprocess.Popen(_spawn_argv(spec, cfg_path), start_new_session=True)
    cfg_path.with_suffix(".pid").write_text(str(proc.pid))

    deadline = time.monotonic() + 10.0
    while True:
        if is_running(spec.port):
            _log.info("trex: daemon started port=%d pid=%d", spec.port, proc.pid)
            return TrexDaemonHandle(mode=spec.mode, port=spec.port, pid=proc.pid,
                                    started_at_ts=time.time(), cfg_path=cfg_path)
        if time.monotonic() >= deadline:
            proc.kill()
            raise RuntimeError(
                f"TRex daemon did not open RPC port {spec.port} within 10 s (pid={proc.pid})"
            )
        time.sleep(0.2)


def stop(handle: TrexDaemonHandle) -> None:
    """SIGTERM pid, wait 5 s, SIGKILL if still alive, delete cfg_path. Idempotent."""
    pid = handle.pid
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, OSError):
        _cleanup_cfg(handle.cfg_path)
        return

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.5)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    _cleanup_cfg(handle.cfg_path)


def is_running(port: int) -> bool:
    """TCP probe 127.0.0.1:port. True = something is listening."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except (ConnectionRefusedError, OSError):
        return False
    finally:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass


def recover_orphaned(binary_path: Path = DEFAULT_TREX_BINARY) -> list[int]:
    """Best-effort: scan /tmp for trex-*.yaml, SIGTERM each found pid. Never raises."""
    stopped: list[int] = []
    try:
        cfg_files = list(CFG_DIR.glob("trex-*.yaml"))
    except Exception:  # noqa: BLE001
        return stopped

    for cfg_path in cfg_files:
        try:
            pid = _find_pid(cfg_path, binary_path)
            if pid < 0:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                stopped.append(pid)
                _log.info("trex: orphan SIGTERM pid=%d cfg=%s", pid, cfg_path)
            except (ProcessLookupError, OSError) as exc:
                _log.warning("trex: SIGTERM pid=%d: %s", pid, exc)
            _cleanup_cfg(cfg_path)
        except Exception as exc:  # noqa: BLE001
            _log.warning("trex: recover_orphaned error %s: %s", cfg_path, exc)

    return stopped


# --- Internals exposed for unit tests ---

def _write_cfg(spec: TrexDaemonSpec, path: Path) -> None:
    """Emit TRex --cfg YAML (stdlib only, no yaml import)."""
    ifaces = ", ".join(f'"{p}"' for p in spec.pci_ports)
    cores = ", ".join(str(c) for c in spec.cores)
    path.write_text(
        f"- port_limit: {len(spec.pci_ports)}\n"
        f"  version: 2\n"
        f"  interfaces: [{ifaces}]\n"
        f"  platform:\n"
        f"    master_thread_id: 0\n"
        f"    latency_thread_id: 1\n"
        f"    dual_if:\n"
        f"      - socket: 0\n"
        f"        threads: [{cores}]\n"
    )


def _spawn_argv(spec: TrexDaemonSpec, cfg_path: Path) -> list[str]:
    """Build ['t-rex-64', '--daemon', '-i', '--cfg', ..., '--no-scapy-server', ...]"""
    return [str(spec.binary_path), "--daemon", "-i",
            "--cfg", str(cfg_path), "--no-scapy-server", "--software-mode"]


# --- Private helpers ---

def _find_pid(cfg_path: Path, binary_path: Path) -> int:
    """Return pid for cfg_path from .pid file or pgrep; -1 if not found."""
    pid_path = cfg_path.with_suffix(".pid")
    if pid_path.exists():
        try:
            return int(pid_path.read_text().strip())
        except (ValueError, OSError):
            pass
    try:
        out = subprocess.check_output(["pgrep", "-af", str(binary_path)], text=True)
        for line in out.splitlines():
            if cfg_path.name in line:
                return int(line.split()[0])
    except (subprocess.CalledProcessError, ValueError, OSError):
        pass
    return -1


def _cleanup_cfg(cfg_path: Path) -> None:
    """Remove cfg and .pid files (best-effort)."""
    for p in (cfg_path, cfg_path.with_suffix(".pid")):
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass
