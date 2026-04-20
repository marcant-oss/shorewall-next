"""Persistent state for the DnsSetTracker.

Why this module exists
----------------------

Without persistence, a shorewalld restart (``systemctl restart``,
host reboot, crash) means the in-memory ``DnsSetTracker`` starts
empty. The compiled allowlist is still there, and the declared nft
sets exist, but until the recursor sends fresh answers for each
name those sets are empty — which for a fail-closed rule means
traffic to listed hostnames is denied for up to a TTL.

The :class:`StateStore` fixes that by:

1. Periodically snapshotting the tracker state to a JSON file on
   disk (``/var/lib/shorewalld/dns_sets.json`` by default).
2. On startup, loading that file, pruning any entries whose
   deadline has already passed in wall-clock time, and asking the
   tracker to replay the surviving entries.
3. On shutdown, saving one final snapshot synchronously via the
   daemon's SIGTERM hook so the very last 30 s of updates aren't
   lost to periodic-save latency.

Monotonic vs wall clock
-----------------------

The tracker stores deadlines as ``monotonic()`` timestamps because
that's what :meth:`time.monotonic` hands out and monotonic is the
right clock for elapsed-time comparisons. But the save file has to
outlive the process, and monotonic values reset to zero on reboot.

So the save file stores wall-clock absolute deadlines — each
``(deadline_mono, now_mono)`` pair is converted to
``deadline_wall = time.time() + (deadline_mono - now_mono)`` on
write, and back to monotonic on read. Both clocks advance at the
same rate within a single process, so this conversion is an
arithmetic offset only — no NTP calculations.

Concurrency
-----------

The periodic save task runs on the asyncio loop and offloads the
actual JSON write to a thread via :func:`asyncio.to_thread` so
the loop is never blocked on disk I/O. Load at startup is
synchronous because it happens before the loop is running.

Atomic write uses tmp+rename so a crash mid-save never leaves a
truncated file behind.

Metrics
-------

The exporter publishes::

    shorewalld_state_dns_sets_saves_total
    shorewalld_state_dns_sets_save_errors_total
    shorewalld_state_dns_sets_load_entries_total
    shorewalld_state_dns_sets_load_expired_total
    shorewalld_state_dns_sets_load_unknown_total
    shorewalld_state_last_save_age_seconds
    shorewalld_state_file_bytes

which answer the two questions operators actually have: "when did
we last save?" and "how many entries did we just carry across a
restart?".
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .dns_set_tracker import DnsSetTracker
from .exporter import CollectorBase, _MetricFamily
from .logsetup import get_logger

log = get_logger("state")

# File-format version. Bumped whenever the schema changes in an
# incompatible way; the loader refuses files with an unknown
# version so operators catch the drift instead of silently losing
# state on an upgrade.
STATE_FILE_VERSION = 1

DEFAULT_STATE_DIR = "/var/lib/shorewalld"
DEFAULT_DNS_SETS_FILENAME = "dns_sets.json"
DEFAULT_PERSIST_INTERVAL = 30.0


@dataclass
class StateMetrics:
    saves_total: int = 0
    save_errors_total: int = 0
    load_entries_total: int = 0
    load_expired_total: int = 0
    load_unknown_total: int = 0
    last_save_mono: float = 0.0
    file_bytes: int = 0

    def snapshot(self) -> dict[str, float]:
        age = (
            time.monotonic() - self.last_save_mono
            if self.last_save_mono else 0.0
        )
        return {
            "saves_total": self.saves_total,
            "save_errors_total": self.save_errors_total,
            "load_entries_total": self.load_entries_total,
            "load_expired_total": self.load_expired_total,
            "load_unknown_total": self.load_unknown_total,
            "last_save_age_seconds": age,
            "file_bytes": self.file_bytes,
        }


@dataclass
class StateConfig:
    """User-configurable knobs for the state store.

    ``state_dir`` maps to ``STATE_DIR`` in ``shorewalld.conf``,
    ``persist_interval`` to ``STATE_PERSIST_INTERVAL``, and the
    two boolean switches to the CLI flags ``--no-state-load`` /
    ``--state-flush``.
    """
    state_dir: Path = field(default_factory=lambda: Path(DEFAULT_STATE_DIR))
    persist_interval: float = DEFAULT_PERSIST_INTERVAL
    enabled: bool = True
    load_on_start: bool = True
    flush_on_start: bool = False

    @property
    def dns_sets_path(self) -> Path:
        return self.state_dir / DEFAULT_DNS_SETS_FILENAME


# ── Serialise / deserialise ──────────────────────────────────────────


def _encode_entry(
    qname: str, family: int, ip_bytes: bytes, deadline_mono: float,
    *, now_mono: float, now_wall: float,
) -> dict:
    """Turn one tracker entry into a JSON-friendly dict.

    Deadline is converted to wall-clock absolute seconds so the
    loader can subtract ``time.time()`` after a reboot and still
    get a sensible remaining TTL. IPs are base64-encoded so the
    file stays valid UTF-8.
    """
    remaining = deadline_mono - now_mono
    deadline_wall = now_wall + max(0.0, remaining)
    return {
        "qname": qname,
        "family": family,
        "ip": base64.b64encode(ip_bytes).decode("ascii"),
        "deadline": round(deadline_wall, 3),
    }


def _decode_entry(
    entry: dict, *, now_wall: float, now_mono: float,
) -> tuple[str, int, bytes, float] | None:
    """Parse one JSON entry back into tracker form.

    Returns ``None`` for malformed rows so the loader can count
    them and continue — a partially corrupted file is still useful.
    """
    try:
        qname = entry["qname"]
        family = int(entry["family"])
        ip_bytes = base64.b64decode(entry["ip"])
        deadline_wall = float(entry["deadline"])
    except (KeyError, TypeError, ValueError):
        return None
    if family not in (4, 6):
        return None
    if (family == 4 and len(ip_bytes) != 4) or \
            (family == 6 and len(ip_bytes) != 16):
        return None
    remaining = deadline_wall - now_wall
    deadline_mono = now_mono + remaining
    return (qname, family, ip_bytes, deadline_mono)


def serialise_state(tracker: DnsSetTracker) -> str:
    """Produce the JSON string that gets written to disk.

    Pulled out of :meth:`StateStore.save_sync` so tests can
    exercise the format without touching a real file.
    """
    now_mono = time.monotonic()
    now_wall = time.time()
    entries_out: list[dict] = []
    for qname, family, ip_bytes, deadline_mono in tracker.export_state():
        entries_out.append(_encode_entry(
            qname, family, ip_bytes, deadline_mono,
            now_mono=now_mono, now_wall=now_wall))
    doc = {
        "version": STATE_FILE_VERSION,
        "saved_at": round(now_wall, 3),
        "hostname": _safe_hostname(),
        "entries": entries_out,
    }
    return json.dumps(doc, separators=(",", ":"))


def deserialise_state(
    text: str,
) -> tuple[list[tuple[str, int, bytes, float]], int]:
    """Return ``(entries_for_tracker, expired_count)`` from a file body.

    Entries are already converted from wall-clock absolute back to
    monotonic using the current clocks at load time. Expired
    entries (deadline ≤ now) are counted but not returned so the
    tracker never sees them.

    Raises ``StateFileError`` on version mismatch or JSON errors.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise StateFileError(f"state file invalid JSON: {e}") from e
    version = doc.get("version")
    if version != STATE_FILE_VERSION:
        raise StateFileError(
            f"state file version {version!r} unsupported "
            f"(expected {STATE_FILE_VERSION})")
    now_wall = time.time()
    now_mono = time.monotonic()
    entries: list[tuple[str, int, bytes, float]] = []
    expired = 0
    for raw in doc.get("entries") or []:
        decoded = _decode_entry(
            raw, now_wall=now_wall, now_mono=now_mono)
        if decoded is None:
            continue
        qname, family, ip, deadline_mono = decoded
        if deadline_mono <= now_mono:
            expired += 1
            continue
        entries.append((qname, family, ip, deadline_mono))
    return entries, expired


class StateFileError(Exception):
    """Raised when the state file can't be loaded."""


def _safe_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except OSError:
        return ""


# ── StateStore — the lifecycle owner ─────────────────────────────────


class StateStore:
    """Periodic save + on-demand load for the DnsSetTracker.

    Typical usage inside :class:`Daemon`::

        store = StateStore(tracker, config)
        store.load()                         # cold-boot replay
        await store.start(loop)              # schedule periodic saves
        ...
        await store.stop()                   # final save + cancel task
    """

    def __init__(
        self,
        tracker: DnsSetTracker,
        config: StateConfig | None = None,
    ) -> None:
        self._tracker = tracker
        self._config = config or StateConfig()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._save_task: asyncio.Task[None] | None = None
        self._stopping = False
        self.metrics = StateMetrics()

    # Synchronous API used by the lifecycle -------------------------

    def load(self) -> int:
        """Replay a previously-saved state file into the tracker.

        Returns the number of entries actually installed. Must be
        called before the daemon starts accepting ingest frames so
        the pre-populated sets are visible to any rule reload.
        """
        cfg = self._config
        if not cfg.enabled or not cfg.load_on_start:
            log.info(
                "state load skipped",
                extra={"reason":
                       "disabled" if not cfg.enabled else "no_load"})
            return 0
        path = cfg.dns_sets_path
        if cfg.flush_on_start:
            self._unlink(path)
            log.info("state flushed on start", extra={"path": str(path)})
            return 0
        if not path.exists():
            log.info("state file missing — skipping load",
                     extra={"path": str(path)})
            return 0
        try:
            text = path.read_text()
            self.metrics.file_bytes = len(text)
        except OSError as e:
            log.warning("state load read failed: %s", e)
            return 0
        try:
            entries, expired = deserialise_state(text)
        except StateFileError as e:
            log.warning("state load parse failed: %s", e)
            self.metrics.load_expired_total += 0  # no-op for symmetry
            return 0
        before = self._tracker.snapshot().totals.elements
        installed = self._tracker.import_state(entries)
        after = self._tracker.snapshot().totals.elements
        self.metrics.load_entries_total += installed
        self.metrics.load_expired_total += expired
        self.metrics.load_unknown_total += (
            len(entries) - (after - before))
        log.info(
            "state loaded",
            extra={
                "path": str(path),
                "installed": installed,
                "expired": expired,
            },
        )
        return installed

    def save_sync(self) -> None:
        """Write the state file synchronously.

        Called from the asyncio loop via ``run_in_executor`` so it
        doesn't block the event loop, and also directly from
        :meth:`stop` as the last thing the daemon does on shutdown.
        """
        cfg = self._config
        if not cfg.enabled:
            return
        path = cfg.dns_sets_path
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            text = serialise_state(self._tracker)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(text)
            os.replace(tmp, path)
            self.metrics.saves_total += 1
            self.metrics.last_save_mono = time.monotonic()
            self.metrics.file_bytes = len(text)
        except OSError as e:
            self.metrics.save_errors_total += 1
            log.warning("state save failed: %s", e)

    # Async lifecycle -----------------------------------------------

    async def start(
        self, loop: asyncio.AbstractEventLoop | None = None
    ) -> None:
        """Kick off the periodic-save background task."""
        if self._save_task is not None:
            return
        if not self._config.enabled:
            return
        self._loop = loop or asyncio.get_running_loop()
        self._save_task = self._loop.create_task(
            self._save_loop(), name="shorewalld.state")

    async def stop(self) -> None:
        """Cancel the background task, do one final synchronous save."""
        self._stopping = True
        if self._save_task is not None:
            self._save_task.cancel()
            try:
                await self._save_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._save_task = None
        self.save_sync()

    async def _save_loop(self) -> None:
        cfg = self._config
        while not self._stopping:
            try:
                await asyncio.sleep(cfg.persist_interval)
            except asyncio.CancelledError:
                return
            try:
                loop = self._loop or asyncio.get_running_loop()
                await loop.run_in_executor(None, self.save_sync)
            except Exception as e:  # noqa: BLE001
                self.metrics.save_errors_total += 1
                log.warning("periodic state save failed: %s", e)

    # helpers ------------------------------------------------------

    def _unlink(self, path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


INSTANCES_FILE_VERSION = 1
_INSTANCES_FILENAME = "instances.json"

_log_inst = get_logger("state.instances")


class InstanceCache:
    """Persist dynamically registered instance configs to disk.

    Stored alongside the DNS-set state as ``<state_dir>/instances.json``.
    Atomic write (tmp+rename) prevents truncation on crash.

    ``__init__`` pre-populates the in-memory dict from the file so that
    ``update()`` / ``remove()`` calls before ``load()`` never overwrite
    entries that were cached in a previous run.
    """

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / _INSTANCES_FILENAME
        self._instances: dict[str, dict] = self._read_raw()

    # ── I/O ──────────────────────────────────────────────────────────

    def _read_raw(self) -> "dict[str, dict]":
        """Read the file silently; return empty dict on any error."""
        if not self._path.exists():
            return {}
        try:
            doc = json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
        if doc.get("version") != INSTANCES_FILE_VERSION:
            return {}
        result: dict[str, dict] = {}
        for entry in doc.get("instances") or []:
            name = entry.get("name")
            if isinstance(name, str) and name:
                result[name] = entry
        return result

    def load(self) -> "list[tuple[str, str, str, str, dict | None, dict | None]]":
        """Return cached instances as raw tuples with warnings on errors.

        Each tuple is ``(name, netns, config_dir, allowlist_path,
        dns_payload_or_None, nfsets_payload_or_None)``. Also syncs the
        in-memory dict so subsequent ``update()`` calls preserve all
        cached entries. Never raises — returns ``[]`` on any error.
        """
        if not self._path.exists():
            return []
        try:
            text = self._path.read_text()
            doc = json.loads(text)
        except (OSError, json.JSONDecodeError) as e:
            _log_inst.warning("instance cache load failed: %s", e)
            return []
        if doc.get("version") != INSTANCES_FILE_VERSION:
            _log_inst.warning(
                "instance cache version %r unsupported — ignoring",
                doc.get("version"),
            )
            return []
        result = []
        for entry in doc.get("instances") or []:
            try:
                name = entry["name"]
                netns = entry.get("netns") or ""
                config_dir = entry["config_dir"]
                allowlist_path = entry["allowlist_path"]
                dns_payload = entry.get("dns_payload")
                nfsets_payload = entry.get("nfsets_payload")
                self._instances[name] = entry  # keep in-memory dict fresh
                result.append(
                    (name, netns, config_dir, allowlist_path, dns_payload, nfsets_payload)
                )
            except (KeyError, TypeError) as e:
                _log_inst.warning(
                    "instance cache: skipping malformed entry: %s", e)
        _log_inst.info("instance cache: loaded %d entry(ies)", len(result))
        return result

    def update(
        self,
        config: "Any",
        dns_payload: "dict | None" = None,
        nfsets_payload: "dict | None" = None,
    ) -> None:
        """Add or update one instance and persist to disk atomically.

        *nfsets_payload* is the raw ``req["nfsets"]`` dict from the
        ``register-instance`` message; ``None`` means the instance has no
        nfsets config (pre-Wave-3 shorewall-nft or no ``nfsets`` file).
        """
        entry: dict = {
            "name": config.name,
            "netns": config.netns,
            "config_dir": str(config.config_dir),
            "allowlist_path": str(config.allowlist_path),
        }
        if dns_payload is not None:
            entry["dns_payload"] = dns_payload
        if nfsets_payload is not None:
            entry["nfsets_payload"] = nfsets_payload
        self._instances[config.name] = entry
        self._save()

    def remove(self, name: str) -> None:
        """Remove one instance and persist to disk atomically."""
        self._instances.pop(name, None)
        self._save()

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "version": INSTANCES_FILE_VERSION,
            "saved_at": round(time.time(), 3),
            "instances": list(self._instances.values()),
        }
        text = json.dumps(doc, separators=(",", ":"))
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            tmp.write_text(text)
            os.replace(tmp, self._path)
        except OSError as e:
            _log_inst.warning("instance cache save failed: %s", e)


class StateMetricsCollector(CollectorBase):
    """Prometheus collector for the DNS-set persistence store."""

    def __init__(self, store: "StateStore") -> None:
        super().__init__(netns="")
        self._store = store

    def collect(self) -> list[_MetricFamily]:
        snap = self._store.metrics.snapshot()
        fams: list[_MetricFamily] = []

        def counter(name: str, help_text: str, key: str) -> None:
            fam = _MetricFamily(name, help_text, [], mtype="counter")
            fam.add([], float(snap[key]))
            fams.append(fam)

        def gauge(name: str, help_text: str, key: str) -> None:
            fam = _MetricFamily(name, help_text, [])
            fam.add([], float(snap[key]))
            fams.append(fam)

        counter("shorewalld_state_saves_total",
                "Successful DNS-set state snapshots written to disk",
                "saves_total")
        counter("shorewalld_state_save_errors_total",
                "Failed state snapshot writes",
                "save_errors_total")
        counter("shorewalld_state_load_entries_total",
                "Entries loaded from state file on daemon startup",
                "load_entries_total")
        counter("shorewalld_state_load_expired_total",
                "Entries pruned as expired during startup load",
                "load_expired_total")
        gauge("shorewalld_state_last_save_age_seconds",
              "Seconds since the last successful periodic state save",
              "last_save_age_seconds")
        gauge("shorewalld_state_file_bytes",
              "Current size of the on-disk state file in bytes",
              "file_bytes")
        return fams
