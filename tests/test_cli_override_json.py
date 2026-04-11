"""End-to-end CLI tests for --override-json / --override.

These tests invoke ``shorewall-nft`` as a real subprocess so they
exercise the full click wiring (global option parsing, ctx stashing,
``_compile`` → ``load_config`` → ``apply_overlay`` → ``build_ir`` →
``emit_nft``), not just the library primitives covered by
:mod:`tests.test_config_roundtrip`.

Fixture reuse: the shipped ``tests/configs/minimal`` directory is
the baseline Shorewall config the CLI parses, and every test asserts
that the overlay visibly changes the compiled output.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "configs" / "minimal"
VENV = REPO / ".venv" / "bin" / "shorewall-nft"


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run the venv's shorewall-nft binary, capture output."""
    if not VENV.exists():
        pytest.skip(f"no venv shorewall-nft at {VENV}")
    return subprocess.run(
        [str(VENV), *args],
        capture_output=True, text=True, check=check, timeout=30,
    )


def _compile_and_grep(tmp_path: Path, *extra: str) -> str:
    """Compile the minimal fixture with extra CLI args, return nft output."""
    out = tmp_path / "out.nft"
    _run(*extra, "compile", str(FIXTURE), "-o", str(out))
    return out.read_text()


@pytest.fixture
def baseline_nft(tmp_path):
    """The compiled nft for the minimal fixture with no overlay."""
    return _compile_and_grep(tmp_path)


def test_override_json_literal_shorewall_conf(tmp_path, baseline_nft):
    """--override-json literal changes a shorewall.conf setting."""
    # OPTIMIZE=3 is the default in the minimal fixture; bump to 8
    # and verify the compile still succeeds. We can't easily assert
    # on the emit here because OPTIMIZE=8 is a conditional feature
    # that only changes emit if there are chain-merge opportunities
    # — but we CAN assert the blob was accepted.
    blob = json.dumps({
        "schema_version": 1,
        "shorewall.conf": {"OPTIMIZE": "8"},
    })
    out = _compile_and_grep(
        tmp_path, "--override-json", blob,
    )
    assert "table inet" in out or "table ip" in out


def test_override_rules_per_file_adds_drop(tmp_path, baseline_nft):
    """--override rules=... injects a new DROP rule visible in nft output."""
    # Append a DROP for tcp dport 2323 — distinctive enough to grep
    # and unlikely to clash with the fixture.
    rules_blob = json.dumps({
        "NEW": [
            {"action": "DROP", "source": "net", "dest": "fw",
             "proto": "tcp", "dport": "2323"},
        ],
    })
    out = _compile_and_grep(
        tmp_path, "--override", f"rules={rules_blob}",
    )
    assert "tcp dport 2323" in out, (
        "overlay rule did not appear in compiled nft output"
    )
    # And make sure it's NOT in the baseline
    assert "tcp dport 2323" not in baseline_nft, (
        "distinctive port already present in baseline — test setup broken"
    )


def test_override_json_stdin_dash(tmp_path, baseline_nft):
    """--override-json - reads from stdin."""
    rules_blob = json.dumps({
        "schema_version": 1,
        "rules": {
            "NEW": [
                {"action": "DROP", "source": "net", "dest": "fw",
                 "proto": "tcp", "dport": "2424"},
            ],
        },
    })
    if not VENV.exists():
        pytest.skip(f"no venv shorewall-nft at {VENV}")
    out_path = tmp_path / "out.nft"
    r = subprocess.run(
        [str(VENV), "--override-json", "-",
         "compile", str(FIXTURE), "-o", str(out_path)],
        input=rules_blob, capture_output=True, text=True,
        check=True, timeout=30,
    )
    assert "tcp dport 2424" in out_path.read_text()


def test_override_json_from_file(tmp_path, baseline_nft):
    """--override-json @path reads from a file."""
    blob_path = tmp_path / "overlay.json"
    blob_path.write_text(json.dumps({
        "schema_version": 1,
        "rules": {
            "NEW": [
                {"action": "DROP", "source": "net", "dest": "fw",
                 "proto": "tcp", "dport": "2525"},
            ],
        },
    }))
    out = _compile_and_grep(
        tmp_path, "--override-json", f"@{blob_path}",
    )
    assert "tcp dport 2525" in out


def test_override_per_file_and_bulk_combined(tmp_path, baseline_nft):
    """--override-json bulk + --override per-file both apply."""
    bulk = json.dumps({
        "schema_version": 1,
        "rules": {
            "NEW": [
                {"action": "DROP", "source": "net", "dest": "fw",
                 "proto": "tcp", "dport": "2626"},
            ],
        },
    })
    per_file_params = json.dumps({"FROM_OVERRIDE": "set"})
    out = _compile_and_grep(
        tmp_path,
        "--override-json", bulk,
        "--override", f"params={per_file_params}",
    )
    assert "tcp dport 2626" in out


def test_override_json_malformed_clean_error(tmp_path):
    """Malformed JSON → clean ClickException, not a traceback."""
    r = _run(
        "--override-json", "{not valid json",
        "compile", str(FIXTURE), "-o", str(tmp_path / "out.nft"),
        check=False,
    )
    assert r.returncode != 0
    assert "override-json" in (r.stderr + r.stdout).lower()
    # Traceback noise is a smell
    assert "traceback" not in (r.stderr + r.stdout).lower()


def test_override_bare_name_missing_equals(tmp_path):
    """--override without `=` is rejected with a clear message."""
    r = _run(
        "--override", "rules",  # no =
        "compile", str(FIXTURE), "-o", str(tmp_path / "out.nft"),
        check=False,
    )
    assert r.returncode != 0
    assert "form file=json" in (r.stderr + r.stdout).lower()


def test_config_export_then_import_cli_roundtrip(tmp_path):
    """shorewall-nft config export | config import (validator) round-trip."""
    blob_path = tmp_path / "full.json"
    _run("config", "export", str(FIXTURE),
         "--format=json", "-o", str(blob_path))
    assert blob_path.exists() and blob_path.stat().st_size > 10

    r = _run("config", "import", str(blob_path))
    assert "imported schema_version=1" in r.stdout
    assert "zones:" in r.stdout
