"""Unit tests for shorewalld.logsetup."""

from __future__ import annotations

import json
import logging
import time

import pytest

from shorewalld.logsetup import (
    ROOT,
    SUBSYSTEMS,
    LogConfig,
    RateLimiter,
    _HumanFormatter,
    _JsonFormatter,
    _StructuredFormatter,
    configure_logging,
    get_logger,
    get_rate_limiter,
)


@pytest.fixture(autouse=True)
def _reset_root_logger():
    """Tear down any handlers between tests so state doesn't leak."""
    root = logging.getLogger(ROOT)
    saved_level = root.level
    saved_handlers = list(root.handlers)
    saved_propagate = root.propagate
    yield
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in saved_handlers:
        root.addHandler(h)
    root.setLevel(saved_level)
    root.propagate = saved_propagate


def _make_record(
    name: str = "shorewalld.dnstap",
    level: int = logging.INFO,
    msg: str = "hello",
) -> logging.LogRecord:
    return logging.LogRecord(
        name=name, level=level, pathname="x.py", lineno=1,
        msg=msg, args=(), exc_info=None)


class TestHumanFormatter:
    def test_format_has_timestamp_level_and_msg(self):
        fmt = _HumanFormatter()
        rec = _make_record(msg="hello world")
        line = fmt.format(rec)
        assert "INFO" in line
        assert "hello world" in line
        assert "dnstap" in line
        # ISO 8601-ish timestamp with trailing Z
        assert "Z " in line

    def test_strips_shorewalld_prefix(self):
        fmt = _HumanFormatter()
        rec = _make_record(name="shorewalld.core")
        line = fmt.format(rec)
        assert "shorewalld.core " in line


class TestStructuredFormatter:
    def test_format_includes_core_fields(self):
        fmt = _StructuredFormatter()
        rec = _make_record(msg="peer unreachable")
        line = fmt.format(rec)
        assert "level=info" in line
        assert "logger=shorewalld.dnstap" in line
        assert 'msg="peer unreachable"' in line
        assert "ts=" in line

    def test_extra_kwargs_go_after_canonical_fields(self):
        fmt = _StructuredFormatter()
        rec = _make_record()
        rec.peer = "fw-b"
        rec.missed = 3
        line = fmt.format(rec)
        assert "peer=fw-b" in line
        assert "missed=3" in line


class TestJsonFormatter:
    def test_format_is_valid_json_line(self):
        fmt = _JsonFormatter()
        rec = _make_record(msg="hello")
        line = fmt.format(rec)
        doc = json.loads(line)
        assert doc["msg"] == "hello"
        assert doc["level"] == "info"
        assert doc["logger"] == "shorewalld.dnstap"
        assert doc["ts"].endswith("Z")

    def test_extra_fields_land_on_doc(self):
        fmt = _JsonFormatter()
        rec = _make_record()
        rec.peer = "fw-b"
        rec.count = 17
        doc = json.loads(fmt.format(rec))
        assert doc["peer"] == "fw-b"
        assert doc["count"] == 17


class TestConfigureLogging:
    def test_idempotent(self, capsys):
        configure_logging(LogConfig(level="info", target="stderr"))
        configure_logging(LogConfig(level="debug", target="stderr"))
        root = logging.getLogger(ROOT)
        assert root.level == logging.DEBUG
        # Only one handler installed even after a second call.
        assert len(root.handlers) == 1

    def test_invalid_level_raises(self):
        with pytest.raises(ValueError):
            configure_logging(LogConfig(level="verbose"))

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError):
            configure_logging(LogConfig(format="yaml"))

    def test_per_subsystem_level_override(self):
        configure_logging(LogConfig(
            level="warning",
            subsys_levels={"dnstap": "debug"},
        ))
        root = logging.getLogger(ROOT)
        dnstap = logging.getLogger(f"{ROOT}.dnstap")
        core = logging.getLogger(f"{ROOT}.core")
        assert root.level == logging.WARNING
        assert dnstap.level == logging.DEBUG
        # Core inherits from root.
        assert core.level == logging.NOTSET
        assert core.getEffectiveLevel() == logging.WARNING

    def test_file_target(self, tmp_path):
        path = tmp_path / "shorewalld.log"
        configure_logging(LogConfig(
            level="info", target=f"file:{path}", format="human"))
        log = get_logger("core")
        log.info("written to file")
        # Flush via tear-down.
        for h in logging.getLogger(ROOT).handlers:
            h.flush()
        text = path.read_text()
        assert "written to file" in text

    def test_stdout_target_writes_to_stdout(self, capsys):
        configure_logging(LogConfig(
            level="info", target="stdout", format="human"))
        get_logger("core").info("hello stdout")
        captured = capsys.readouterr()
        assert "hello stdout" in captured.out
        assert "hello stdout" not in captured.err

    def test_stderr_target_writes_to_stderr(self, capsys):
        configure_logging(LogConfig(
            level="info", target="stderr", format="human"))
        get_logger("core").info("hello stderr")
        captured = capsys.readouterr()
        assert "hello stderr" in captured.err
        assert "hello stderr" not in captured.out


class TestGetLogger:
    def test_returns_namespaced_logger(self):
        log = get_logger("dnstap")
        assert log.name == "shorewalld.dnstap"

    def test_empty_subsystem_returns_root(self):
        log = get_logger("")
        assert log.name == "shorewalld"

    def test_unknown_subsystem_still_works(self):
        # Typos should return a logger but also emit a debug note.
        log = get_logger("nonesuch")
        assert log.name == "shorewalld.nonesuch"

    def test_all_declared_subsystems_are_unique(self):
        assert len(SUBSYSTEMS) == len(set(SUBSYSTEMS))


class TestRateLimiter:
    def test_first_warning_emits(self, caplog):
        limiter = RateLimiter(window=60.0)
        log = logging.getLogger("shorewalld.dnstap")
        with caplog.at_level(logging.WARNING, logger=log.name):
            limiter.warn(log, "frame_error", "bad frame: %s", "truncated")
        assert any("bad frame: truncated" in r.message for r in caplog.records)

    def test_repeated_warnings_are_suppressed(self, caplog):
        limiter = RateLimiter(window=60.0)
        log = logging.getLogger("shorewalld.dnstap")
        with caplog.at_level(logging.WARNING, logger=log.name):
            for _ in range(5):
                limiter.warn(log, "frame_error", "bad frame")
        # Only the first one goes through.
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert limiter.dropped_total == 4

    def test_different_keys_do_not_share_budget(self, caplog):
        limiter = RateLimiter(window=60.0)
        log = logging.getLogger("shorewalld.dnstap")
        with caplog.at_level(logging.WARNING, logger=log.name):
            limiter.warn(log, "err_a", "error A")
            limiter.warn(log, "err_b", "error B")
        assert len([r for r in caplog.records
                    if r.levelno == logging.WARNING]) == 2

    def test_window_expiry_allows_next_emit(self, caplog):
        limiter = RateLimiter(window=0.01)
        log = logging.getLogger("shorewalld.dnstap")
        with caplog.at_level(logging.WARNING, logger=log.name):
            limiter.warn(log, "err", "first")
            limiter.warn(log, "err", "suppressed 1")
            limiter.warn(log, "err", "suppressed 2")
            time.sleep(0.02)
            limiter.warn(log, "err", "second (with summary)")
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        # One before sleep, one after.
        assert len(warnings) == 2
        assert "suppressed 2" in warnings[1].message

    def test_reset_clears_state(self):
        limiter = RateLimiter(window=60.0)
        log = logging.getLogger("shorewalld.test")
        limiter.warn(log, "k", "m")
        limiter.warn(log, "k", "m")
        assert limiter.dropped_total == 1
        limiter.reset()
        assert limiter.dropped_total == 0

    def test_info_level_variant(self, caplog):
        limiter = RateLimiter(window=60.0)
        log = logging.getLogger("shorewalld.peer")
        log.setLevel(logging.INFO)
        with caplog.at_level(logging.INFO, logger=log.name):
            limiter.info(log, "heartbeat", "peer %s ok", "fw-b")
            limiter.info(log, "heartbeat", "peer %s ok", "fw-b")  # suppressed
        infos = [r for r in caplog.records if r.levelno == logging.INFO]
        assert len(infos) == 1

    def test_global_limiter_is_singleton(self):
        a = get_rate_limiter()
        b = get_rate_limiter()
        assert a is b
