"""shorewalld.conf parser tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from shorewalld.config import (
    ConfigError,
    load_defaults,
    parse_conf_text,
)


def test_parse_empty_and_comments():
    assert parse_conf_text("") == {}
    assert parse_conf_text("# header\n\n# comment only\n") == {}


def test_parse_simple():
    cfg = parse_conf_text(
        "LISTEN_PROM=:9748\n"
        "ALLOWLIST_FILE=/etc/shorewall/dns-allowlist.tsv\n"
    )
    assert cfg["LISTEN_PROM"] == ":9748"
    assert cfg["ALLOWLIST_FILE"] == "/etc/shorewall/dns-allowlist.tsv"


def test_parse_quoted_values():
    cfg = parse_conf_text('NETNS="fw,rns1,rns2"\n' "PEER_ADDRESS='10.0.0.2:9749'\n")
    assert cfg["NETNS"] == "fw,rns1,rns2"
    assert cfg["PEER_ADDRESS"] == "10.0.0.2:9749"


def test_parse_rejects_malformed():
    with pytest.raises(ConfigError):
        parse_conf_text("no_equals\n")
    with pytest.raises(ConfigError):
        parse_conf_text("bad key=value\n")


def test_parse_duplicate_last_wins():
    cfg = parse_conf_text("STATE_DIR=/tmp/a\nSTATE_DIR=/tmp/b\n")
    assert cfg["STATE_DIR"] == "/tmp/b"


def test_load_defaults_typed(tmp_path: Path):
    conf = tmp_path / "shorewalld.conf"
    conf.write_text(
        "LISTEN_PROM=127.0.0.1:9900\n"
        "ALLOWLIST_FILE=/var/lib/shorewalld/allowlist.tsv\n"
        "PBDNS_SOCKET=/run/shorewalld/pbdns.sock\n"
        "PEER_LISTEN=0.0.0.0:9749\n"
        "PEER_ADDRESS=10.0.0.2:9749\n"
        "PEER_SECRET_FILE=/etc/shorewall/peer.key\n"
        "PEER_HEARTBEAT_INTERVAL=3.5\n"
        "STATE_DIR=/var/lib/shorewalld\n"
        "STATE_ENABLED=yes\n"
        "LOG_LEVEL=debug\n"
        "LOG_LEVEL_peer=info\n"
    )
    d = load_defaults(conf)
    assert d.listen_prom == "127.0.0.1:9900"
    assert d.allowlist_file == "/var/lib/shorewalld/allowlist.tsv"
    assert d.pbdns_socket == "/run/shorewalld/pbdns.sock"
    assert d.peer_listen == "0.0.0.0:9749"
    assert d.peer_address == "10.0.0.2:9749"
    assert d.peer_secret_file == "/etc/shorewall/peer.key"
    assert d.peer_heartbeat_interval == 3.5
    assert d.state_dir == "/var/lib/shorewalld"
    assert d.state_enabled is True
    assert d.log_level == "debug"
    assert d.subsys_log_levels == {"peer": "info"}


def test_load_defaults_missing_file(tmp_path: Path):
    d = load_defaults(tmp_path / "nope.conf")
    # All-None defaults object — nothing configured.
    assert d.listen_prom is None
    assert d.allowlist_file is None
    assert d.state_enabled is None


def test_bool_coercion_rejects_garbage(tmp_path: Path):
    conf = tmp_path / "bad.conf"
    conf.write_text("STATE_ENABLED=maybe\n")
    with pytest.raises(ConfigError):
        load_defaults(conf)


def test_float_coercion_rejects_garbage(tmp_path: Path):
    conf = tmp_path / "bad.conf"
    conf.write_text("SCRAPE_INTERVAL=soon\n")
    with pytest.raises(ConfigError):
        load_defaults(conf)


def test_unknown_keys_are_ignored(tmp_path: Path):
    conf = tmp_path / "forward.conf"
    conf.write_text("FUTURE_KNOB=42\nLISTEN_PROM=:9748\n")
    d = load_defaults(conf)
    assert d.listen_prom == ":9748"


def test_cli_merges_conf_defaults(tmp_path: Path, monkeypatch):
    """Smoke test: CLI main() picks up conf values when no flag passed."""
    conf = tmp_path / "shorewalld.conf"
    conf.write_text("LISTEN_PROM=127.0.0.1:9900\nSTATE_DIR=/tmp/foo\n")
    captured: dict = {}

    class _FakeDaemon:
        def __init__(self, **kw):
            captured.update(kw)

        async def run(self):
            return 0

    import shorewalld.core as core_mod
    from shorewalld import cli as cli_mod

    monkeypatch.setattr(core_mod, "Daemon", _FakeDaemon)
    # configure_logging mutates the shorewalld logger tree — stub it
    # out so these tests don't leak handlers into later tests.
    monkeypatch.setattr(cli_mod, "configure_logging", lambda cfg: None)
    rc = cli_mod.main(["--config-file", str(conf)])
    assert rc == 0
    assert captured["prom_host"] == "127.0.0.1"
    assert captured["prom_port"] == 9900
    assert str(captured["state_dir"]) == "/tmp/foo"


def test_cli_flag_overrides_conf(tmp_path: Path, monkeypatch):
    """Explicit CLI flag must win over conf value."""
    conf = tmp_path / "shorewalld.conf"
    conf.write_text("LISTEN_PROM=127.0.0.1:9900\n")
    captured: dict = {}

    class _FakeDaemon:
        def __init__(self, **kw):
            captured.update(kw)

        async def run(self):
            return 0

    import shorewalld.core as core_mod
    from shorewalld import cli as cli_mod

    monkeypatch.setattr(core_mod, "Daemon", _FakeDaemon)
    # configure_logging mutates the shorewalld logger tree — stub it
    # out so these tests don't leak handlers into later tests.
    monkeypatch.setattr(cli_mod, "configure_logging", lambda cfg: None)
    rc = cli_mod.main([
        "--config-file", str(conf),
        "--listen-prom", "0.0.0.0:9999",
    ])
    assert rc == 0
    assert captured["prom_host"] == "0.0.0.0"
    assert captured["prom_port"] == 9999
