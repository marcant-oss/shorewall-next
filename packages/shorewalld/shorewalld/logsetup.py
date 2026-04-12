"""shorewalld logging foundation.

Hierarchical loggers per subsystem (``shorewalld.core``, ``shorewalld.dnstap``,
``shorewalld.peer``, …). One root logger ``shorewalld`` sets the default level
and handlers; each subsystem inherits unless explicitly overridden.

Targets supported:

* ``stderr`` (default) — also the right choice when running under systemd,
  because journald captures stderr automatically.
* ``stdout`` — symmetric to stderr for tooling that prefers it.
* ``syslog`` — ``SysLogHandler(address=LOG_SYSLOG_SOCKET)`` against
  ``/dev/log`` (AF_UNIX DGRAM). Facility configurable.
* ``journal`` — uses ``systemd.journal.JournalHandler`` if the systemd
  python bindings are installed, otherwise falls back to stderr with a
  warning.
* ``file:/absolute/path`` — rotating file handler (size-based).

Format variants:

* ``human`` (default) — ``TIMESTAMP LEVEL NAME  MESSAGE`` for terminals.
* ``structured`` — ``ts=… level=… logger=… msg="…" k=v k=v`` for grep and
  syslog ingestion.
* ``json`` — one JSON object per line, suitable for log aggregators.

Hot-path discipline: this module provides :class:`RateLimiter` for
rate-limiting log emissions from loops that fire at 20 k/s. The rule in
the shorewalld performance doctrine (``CLAUDE.md``) is: **never log per
frame**. Per-batch/per-reload/per-reconnect is OK. Persistent warnings
from the hot path must go through ``RateLimiter.warn``.

``configure_logging()`` is idempotent: calling it a second time tears
down the previously installed handlers and rebuilds from the new config.
Tests exercise this to verify clean setup/teardown.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

# Root logger name. All subsystem loggers are children
# (shorewalld.dnstap, shorewalld.peer, etc.).
ROOT = "shorewalld"

# Well-known subsystem logger names. Declared here so every module
# imports the same constants — no typos, no drift.
SUBSYSTEMS = (
    "core",
    "dnstap",
    "pbdns",
    "decoder",
    "setwriter",
    "tracker",
    "worker",
    "state",
    "reload",
    "peer",
    "exporter",
    "tap",
    "cli",
    "discover",
    "framestream",
)

# Levels accepted from CLI/config as lower-case strings.
_LEVEL_NAMES = ("debug", "info", "warning", "error", "critical")


@dataclass
class LogConfig:
    """Parameters for :func:`configure_logging`.

    All fields have sensible defaults so a minimal CLI can call
    ``configure_logging(LogConfig())`` and get a working stderr logger.
    """

    level: str = "info"
    target: str = "stderr"                       # stderr|stdout|syslog|journal|file:PATH
    format: str = "human"                        # human|structured|json
    syslog_socket: str = "/dev/log"
    syslog_facility: str = "daemon"
    file_max_bytes: int = 10 * 1024 * 1024        # rotating file handler
    file_backup_count: int = 5
    rate_limit_window: float = 60.0               # seconds
    subsys_levels: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


class _HumanFormatter(logging.Formatter):
    """Terminal-friendly format.

    ``2026-04-11T20:58:12.123Z INFO  shorewalld.dnstap  message text``

    Level column is fixed-width (5) so logger names line up visually.
    """

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
        ts = f"{ts}.{int(record.msecs):03d}Z"
        level = record.levelname.ljust(5)
        msg = record.getMessage()
        # Keep logger name column short — strip the "shorewalld." prefix.
        name = record.name
        if name.startswith(ROOT + "."):
            name = name[len(ROOT) + 1:]
        elif name == ROOT:
            name = "root"
        line = f"{ts} {level} shorewalld.{name:<12} {msg}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


class _StructuredFormatter(logging.Formatter):
    """``key=value`` one-line format for syslog / grep.

    Extra keys on the LogRecord are emitted after the canonical fields.
    Strings containing whitespace are quoted.
    """

    _RESERVED = frozenset(
        logging.LogRecord(
            "x", logging.INFO, "x", 0, "x", None, None).__dict__.keys()
    )

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
        ts = f"{ts}.{int(record.msecs):03d}Z"
        parts = [
            f"ts={ts}",
            f"level={record.levelname.lower()}",
            f"logger={record.name}",
            f"msg={_quote(record.getMessage())}",
        ]
        for k, v in record.__dict__.items():
            if k in self._RESERVED or k.startswith("_"):
                continue
            parts.append(f"{k}={_quote(str(v))}")
        line = " ".join(parts)
        if record.exc_info:
            line += " exc=" + _quote(self.formatException(record.exc_info))
        return line


class _JsonFormatter(logging.Formatter):
    """One JSON object per line for log aggregators (Loki, Elastic, …)."""

    _RESERVED = frozenset(
        logging.LogRecord(
            "x", logging.INFO, "x", 0, "x", None, None).__dict__.keys()
    )

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
        ts = f"{ts}.{int(record.msecs):03d}Z"
        doc: dict[str, object] = {
            "ts": ts,
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k in self._RESERVED or k.startswith("_"):
                continue
            doc[k] = v
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, separators=(",", ":"), default=str)


def _quote(s: str) -> str:
    """Quote a value for structured output if it needs it."""
    if not s or any(c in s for c in " \t\"\\"):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


_FORMATTERS: dict[str, type[logging.Formatter]] = {
    "human": _HumanFormatter,
    "structured": _StructuredFormatter,
    "json": _JsonFormatter,
}


# ---------------------------------------------------------------------------
# Handler construction
# ---------------------------------------------------------------------------


_SYSLOG_FACILITIES = {
    "kern": logging.handlers.SysLogHandler.LOG_KERN,
    "user": logging.handlers.SysLogHandler.LOG_USER,
    "mail": logging.handlers.SysLogHandler.LOG_MAIL,
    "daemon": logging.handlers.SysLogHandler.LOG_DAEMON,
    "auth": logging.handlers.SysLogHandler.LOG_AUTH,
    "syslog": logging.handlers.SysLogHandler.LOG_SYSLOG,
    "lpr": logging.handlers.SysLogHandler.LOG_LPR,
    "news": logging.handlers.SysLogHandler.LOG_NEWS,
    "uucp": logging.handlers.SysLogHandler.LOG_UUCP,
    "cron": logging.handlers.SysLogHandler.LOG_CRON,
    "local0": logging.handlers.SysLogHandler.LOG_LOCAL0,
    "local1": logging.handlers.SysLogHandler.LOG_LOCAL1,
    "local2": logging.handlers.SysLogHandler.LOG_LOCAL2,
    "local3": logging.handlers.SysLogHandler.LOG_LOCAL3,
    "local4": logging.handlers.SysLogHandler.LOG_LOCAL4,
    "local5": logging.handlers.SysLogHandler.LOG_LOCAL5,
    "local6": logging.handlers.SysLogHandler.LOG_LOCAL6,
    "local7": logging.handlers.SysLogHandler.LOG_LOCAL7,
}


def _build_handler(cfg: LogConfig) -> logging.Handler:
    target = cfg.target
    if target == "stderr":
        return logging.StreamHandler(sys.stderr)
    if target == "stdout":
        return logging.StreamHandler(sys.stdout)
    if target == "syslog":
        facility = _SYSLOG_FACILITIES.get(
            cfg.syslog_facility.lower(),
            logging.handlers.SysLogHandler.LOG_DAEMON,
        )
        return logging.handlers.SysLogHandler(
            address=cfg.syslog_socket, facility=facility)
    if target == "journal":
        try:
            from systemd.journal import JournalHandler  # type: ignore
        except ImportError:
            fallback = logging.StreamHandler(sys.stderr)
            fallback.setLevel(logging.WARNING)
            logging.getLogger(ROOT).warning(
                "LOG_TARGET=journal requested but systemd.journal is not "
                "available; falling back to stderr")
            return fallback
        return JournalHandler(SYSLOG_IDENTIFIER="shorewalld")
    if target.startswith("file:"):
        path = Path(target[5:])
        path.parent.mkdir(parents=True, exist_ok=True)
        return logging.handlers.RotatingFileHandler(
            str(path),
            maxBytes=cfg.file_max_bytes,
            backupCount=cfg.file_backup_count,
        )
    raise ValueError(f"unsupported log target: {target!r}")


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Dedupe hot-path warnings over a time window.

    Usage::

        from shorewalld.logsetup import get_rate_limiter, get_logger

        log = get_logger("dnstap")
        limiter = get_rate_limiter()

        def on_frame_error(reason: str) -> None:
            limiter.warn(log, ("frame_error", reason),
                         "dnstap decode error: %s", reason)

    The ``key`` tuple identifies the category; repeated warnings for the
    same key within ``window`` seconds are silently counted and dropped.
    When the window elapses, the next call logs a summary including the
    number of suppressed messages.

    Thread-safe: a single ``threading.Lock`` guards the state dict.
    The critical section is microseconds, so contention cost is
    negligible even at 20 k/s frame rates.
    """

    def __init__(self, window: float = 60.0) -> None:
        self._window = max(0.0, float(window))
        self._lock = threading.Lock()
        # (logger_name, key) -> (last_emit_ts, suppressed_count)
        self._state: dict[tuple[str, object], tuple[float, int]] = {}
        self._dropped_total = 0

    @property
    def dropped_total(self) -> int:
        """Total count of suppressed warnings over the lifetime.

        Exposed so the exporter can publish
        ``shorewalld_log_dropped_total{reason="rate_limit"}``.
        """
        with self._lock:
            return self._dropped_total

    def _should_emit(
        self, logger_name: str, key: object
    ) -> tuple[bool, int]:
        """Decide whether to emit; return ``(emit, suppressed_since_last)``."""
        now = time.monotonic()
        state_key = (logger_name, key)
        with self._lock:
            entry = self._state.get(state_key)
            if entry is None or now - entry[0] >= self._window:
                suppressed = entry[1] if entry else 0
                self._state[state_key] = (now, 0)
                return True, suppressed
            self._state[state_key] = (entry[0], entry[1] + 1)
            self._dropped_total += 1
            return False, 0

    def warn(
        self,
        logger: logging.Logger,
        key: object,
        msg: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        """Emit a warning if the key is not within the current window.

        ``key`` should identify the event category — typically a tuple
        of ``(event_name, subcategory)``. Uniqueness is determined by
        ``(logger.name, key)``.
        """
        emit, suppressed = self._should_emit(logger.name, key)
        if emit:
            if suppressed:
                logger.warning(
                    msg + " (suppressed %d similar in the last %.0fs)",
                    *args, suppressed, self._window, **kwargs)
            else:
                logger.warning(msg, *args, **kwargs)

    def info(
        self,
        logger: logging.Logger,
        key: object,
        msg: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        """Same shape as :meth:`warn` but at INFO level.

        Useful for periodic status notes from a loop — "still waiting for
        peer fw-b", "queue depth above 50%", etc.
        """
        emit, suppressed = self._should_emit(logger.name, key)
        if emit:
            if suppressed:
                logger.info(
                    msg + " (suppressed %d similar in the last %.0fs)",
                    *args, suppressed, self._window, **kwargs)
            else:
                logger.info(msg, *args, **kwargs)

    def reset(self) -> None:
        """Clear all tracked state (tests use this between cases)."""
        with self._lock:
            self._state.clear()
            self._dropped_total = 0


_GLOBAL_LIMITER: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Return the process-wide :class:`RateLimiter`.

    Shared across all subsystems so dedup is consistent regardless of
    which logger fired. Tests can call :meth:`RateLimiter.reset` to
    clear state between cases.
    """
    global _GLOBAL_LIMITER
    if _GLOBAL_LIMITER is None:
        _GLOBAL_LIMITER = RateLimiter()
    return _GLOBAL_LIMITER


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_logger(subsystem: str) -> logging.Logger:
    """Return the named subsystem logger under the shorewalld root.

    ``subsystem`` should be one of :data:`SUBSYSTEMS` — passing an
    unknown name still works but flags a warning on first use so typos
    surface in development.
    """
    if subsystem not in SUBSYSTEMS and subsystem != "":
        logging.getLogger(ROOT).debug(
            "get_logger(%r): unknown subsystem, not in SUBSYSTEMS",
            subsystem)
    name = ROOT if not subsystem else f"{ROOT}.{subsystem}"
    return logging.getLogger(name)


def _coerce_level(name: str) -> int:
    n = name.lower().strip()
    if n not in _LEVEL_NAMES:
        raise ValueError(
            f"unknown log level {name!r}; expected one of {_LEVEL_NAMES}")
    return getattr(logging, n.upper())


def configure_logging(cfg: LogConfig) -> None:
    """Install handlers and levels onto the ``shorewalld`` root logger.

    Idempotent: calling this again removes previously installed handlers
    and rebuilds from the new config. Called once from
    :class:`Daemon.__init__` before any subsystem emits, and from tests
    with different configs between cases.

    Also resets the global :class:`RateLimiter` so tests get a clean
    slate.
    """
    level = _coerce_level(cfg.level)
    fmt_cls = _FORMATTERS.get(cfg.format)
    if fmt_cls is None:
        raise ValueError(
            f"unknown log format {cfg.format!r}; "
            f"expected {tuple(_FORMATTERS)}")

    root = logging.getLogger(ROOT)
    # Idempotent teardown — remove handlers we previously installed.
    for h in list(root.handlers):
        root.removeHandler(h)
        try:
            h.close()
        except Exception:  # noqa: BLE001
            pass

    handler = _build_handler(cfg)
    handler.setFormatter(fmt_cls())
    handler.setLevel(level)
    root.addHandler(handler)
    root.setLevel(level)
    # Don't propagate to the Python root logger — otherwise a caller
    # that also ran ``logging.basicConfig()`` would double-log.
    root.propagate = False

    # Per-subsystem overrides: each listed subsystem gets its own level;
    # inheritance from the root handles filtering via logger.isEnabledFor.
    for name, lvl_name in cfg.subsys_levels.items():
        lvl = _coerce_level(lvl_name)
        logging.getLogger(f"{ROOT}.{name}").setLevel(lvl)

    # Reset the process-wide rate limiter so test isolation works.
    limiter = get_rate_limiter()
    limiter._window = cfg.rate_limit_window
    limiter.reset()
