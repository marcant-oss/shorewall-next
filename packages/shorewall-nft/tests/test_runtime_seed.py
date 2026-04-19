"""Tests for seed handshake: inject_seed_elements + request_seeds_from_shorewalld.

Coverage:
* inject_seed_elements inserts elements = { … } after size N;
* noop when dns_seeds is empty
* preserves unrelated (non-DNS) sets
* both v4 and v6 families in the same set block
* client returns None when daemon unreachable
* client returns None on malformed response
* client returns None on ok=false
* _resolve_seed_config precedence: CLI > env > conf > default
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from shorewall_nft.nft.dns_sets import inject_seed_elements, qname_to_set_name
from shorewall_nft.runtime.seed import SeedResult, request_seeds_from_shorewalld


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GITHUB_V4_NAME = qname_to_set_name("github.com", "v4")
GITHUB_V6_NAME = qname_to_set_name("github.com", "v6")

SAMPLE_SCRIPT = f"""\
table inet shorewall {{
\t# github.com
\tset {GITHUB_V4_NAME} {{
\t\ttype ipv4_addr;
\t\tflags timeout;
\t\tsize 512;
\t}}
\tset {GITHUB_V6_NAME} {{
\t\ttype ipv6_addr;
\t\tflags timeout;
\t\tsize 512;
\t}}
\tset unrelated_set {{
\t\ttype ipv4_addr;
\t\tsize 100;
\t}}
}}
"""


def _make_dns_seeds(**kwargs) -> dict:
    """Build a dns_seeds dict from keyword args: qname=dict(v4=[...], v6=[...])."""
    return {qname: data for qname, data in kwargs.items()}


# ---------------------------------------------------------------------------
# inject_seed_elements tests
# ---------------------------------------------------------------------------


def test_inject_into_timeout_set_v4():
    """Elements are inserted after size N; with correct nft syntax."""
    dns_seeds = _make_dns_seeds(**{
        "github.com": {
            "v4": [{"ip": "140.82.121.3", "ttl": 60}],
            "v6": [],
        }
    })
    modified, n = inject_seed_elements(SAMPLE_SCRIPT, dns_seeds)
    assert n == 1
    # The elements line must follow size 512; in the v4 set block.
    lines = modified.splitlines()
    # Find size and elements lines within the v4 set block.
    v4_block_start = next(
        i for i, l in enumerate(lines) if GITHUB_V4_NAME in l and "set " in l)
    size_idx = next(
        i for i, l in enumerate(lines[v4_block_start:], v4_block_start)
        if "size" in l and "512" in l)
    elements_idx = size_idx + 1
    assert "elements" in lines[elements_idx]
    assert "140.82.121.3" in lines[elements_idx]
    assert "timeout 60s" in lines[elements_idx]
    assert "expires 60s" in lines[elements_idx]


def test_inject_noop_when_no_seeds():
    """Empty dns_seeds → script returned byte-identical."""
    modified, n = inject_seed_elements(SAMPLE_SCRIPT, {})
    assert n == 0
    assert modified == SAMPLE_SCRIPT


def test_inject_preserves_unrelated_sets():
    """Sets not in dns_seeds are untouched."""
    dns_seeds = _make_dns_seeds(**{
        "github.com": {
            "v4": [{"ip": "1.2.3.4", "ttl": 60}],
            "v6": [],
        }
    })
    modified, _ = inject_seed_elements(SAMPLE_SCRIPT, dns_seeds)
    # unrelated_set must not have an elements line.
    lines = modified.splitlines()
    unrelated_start = next(
        i for i, l in enumerate(lines) if "unrelated_set" in l and "set " in l)
    block = lines[unrelated_start:]
    close = next(i for i, l in enumerate(block) if l.strip() == "}")
    block_body = block[:close]
    assert not any("elements" in l for l in block_body)


def test_inject_both_families():
    """Both v4 and v6 elements are injected when seeds contain both."""
    dns_seeds = _make_dns_seeds(**{
        "github.com": {
            "v4": [{"ip": "140.82.121.3", "ttl": 60}],
            "v6": [{"ip": "2606:50c0:8000::153", "ttl": 300}],
        }
    })
    modified, n = inject_seed_elements(SAMPLE_SCRIPT, dns_seeds)
    assert n == 2
    assert "140.82.121.3" in modified
    assert "2606:50c0:8000::153" in modified


def test_inject_skips_zero_ttl():
    """Entries with ttl=0 are silently omitted."""
    dns_seeds = _make_dns_seeds(**{
        "github.com": {
            "v4": [{"ip": "1.2.3.4", "ttl": 0}],
            "v6": [],
        }
    })
    modified, n = inject_seed_elements(SAMPLE_SCRIPT, dns_seeds)
    assert n == 0
    assert modified == SAMPLE_SCRIPT


# ---------------------------------------------------------------------------
# request_seeds_from_shorewalld tests
# ---------------------------------------------------------------------------


def test_seed_client_daemon_unreachable():
    """FileNotFoundError → None (no exception)."""
    result = request_seeds_from_shorewalld(
        socket_path="/tmp/shorewalld-nonexistent-XXXX.sock",
        netns="",
        name="test",
        qnames=["github.com"],
        iplist_sets=[],
        timeout_ms=1000,
    )
    assert result is None


def test_seed_client_malformed_response():
    """Malformed JSON response → None."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sock_path = os.path.join(tmpdir, "control.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)
        srv.settimeout(2.0)

        def _respond():
            try:
                conn, _ = srv.accept()
                conn.recv(4096)
                conn.sendall(b"NOT JSON AT ALL\n")
                conn.close()
            except Exception:
                pass
            finally:
                srv.close()

        t = threading.Thread(target=_respond, daemon=True)
        t.start()

        result = request_seeds_from_shorewalld(
            socket_path=sock_path,
            netns="",
            name="test",
            qnames=["github.com"],
            iplist_sets=[],
            timeout_ms=1000,
        )
        t.join(timeout=3)
    assert result is None


def test_seed_client_ok_false():
    """ok=false response → None."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sock_path = os.path.join(tmpdir, "control.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)
        srv.settimeout(2.0)

        def _respond():
            try:
                conn, _ = srv.accept()
                conn.recv(4096)
                resp = json.dumps({"ok": False, "error": "test error"}).encode() + b"\n"
                conn.sendall(resp)
                conn.close()
            except Exception:
                pass
            finally:
                srv.close()

        t = threading.Thread(target=_respond, daemon=True)
        t.start()

        result = request_seeds_from_shorewalld(
            socket_path=sock_path,
            netns="",
            name="test",
            qnames=["github.com"],
            iplist_sets=[],
            timeout_ms=1000,
        )
        t.join(timeout=3)
    assert result is None


def test_seed_client_success():
    """Successful response → SeedResult with dns data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sock_path = os.path.join(tmpdir, "control.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)
        srv.settimeout(2.0)

        payload = {
            "ok": True,
            "elapsed_ms": 50,
            "complete": True,
            "timeout_hit": False,
            "dnstap_waited": False,
            "sources_contributed": ["tracker"],
            "seeds": {
                "dns": {
                    "github.com": {
                        "v4": [{"ip": "140.82.121.3", "ttl": 60}],
                        "v6": [],
                    }
                },
                "iplist": {},
            },
        }

        def _respond():
            try:
                conn, _ = srv.accept()
                conn.recv(4096)
                conn.sendall(json.dumps(payload).encode() + b"\n")
                conn.close()
            except Exception:
                pass
            finally:
                srv.close()

        t = threading.Thread(target=_respond, daemon=True)
        t.start()

        result = request_seeds_from_shorewalld(
            socket_path=sock_path,
            netns="",
            name="test",
            qnames=["github.com"],
            iplist_sets=[],
            timeout_ms=5000,
        )
        t.join(timeout=3)

    assert result is not None
    assert isinstance(result, SeedResult)
    assert "github.com" in result.dns
    assert result.sources_contributed == ["tracker"]
    assert result.elapsed_ms == 50


def test_seed_client_noop_when_no_qnames():
    """No qnames AND no iplist_sets → None without connecting."""
    result = request_seeds_from_shorewalld(
        socket_path="/tmp/would-not-exist.sock",
        netns="",
        name="test",
        qnames=[],
        iplist_sets=[],
        timeout_ms=1000,
    )
    assert result is None


# ---------------------------------------------------------------------------
# _resolve_seed_config tests
# ---------------------------------------------------------------------------


def test_seed_timeout_precedence_cli_over_env(monkeypatch):
    """CLI value wins over environment variable."""
    from shorewall_nft.runtime.cli import _resolve_seed_config
    monkeypatch.setenv("SHOREWALLD_SEED_TIMEOUT", "999s")
    _enabled, timeout_ms, _wp = _resolve_seed_config(None, "5s", None, None)
    assert timeout_ms == 5000


def test_seed_timeout_precedence_env_over_conf(monkeypatch):
    """Environment variable wins over shorewall.conf."""
    from shorewall_nft.runtime.cli import _resolve_seed_config
    monkeypatch.setenv("SHOREWALLD_SEED_TIMEOUT", "20s")
    _enabled, timeout_ms, _wp = _resolve_seed_config(None, None, None,
                                                      {"SHOREWALLD_SEED_TIMEOUT": "5s"})
    assert timeout_ms == 20_000


def test_seed_timeout_precedence_conf_over_default(monkeypatch):
    """shorewall.conf wins over hard default."""
    from shorewall_nft.runtime.cli import _resolve_seed_config
    monkeypatch.delenv("SHOREWALLD_SEED_TIMEOUT", raising=False)
    _enabled, timeout_ms, _wp = _resolve_seed_config(None, None, None,
                                                      {"SHOREWALLD_SEED_TIMEOUT": "30s"})
    assert timeout_ms == 30_000


def test_seed_enabled_conf_no(monkeypatch):
    """SHOREWALLD_SEED_ENABLED=No in conf disables seed."""
    from shorewall_nft.runtime.cli import _resolve_seed_config
    monkeypatch.delenv("SHOREWALLD_SEED_ENABLED", raising=False)
    enabled, _tm, _wp = _resolve_seed_config(None, None, None,
                                              {"SHOREWALLD_SEED_ENABLED": "No"})
    assert enabled is False


def test_seed_enabled_default_is_true(monkeypatch):
    """Default: enabled=True when nothing is configured."""
    from shorewall_nft.runtime.cli import _resolve_seed_config
    monkeypatch.delenv("SHOREWALLD_SEED_ENABLED", raising=False)
    enabled, _tm, _wp = _resolve_seed_config(None, None, None, {})
    assert enabled is True
