"""Tests for the `shorewall-nft config template` host-tag expander."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


def _cli(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)}
    return subprocess.run(
        [sys.executable, "-m", "shorewall_nft.main", *args],
        capture_output=True, text=True, timeout=15, env=env)


@pytest.fixture
def tagged_file(tmp_path: Path) -> Path:
    """Multi-host template covering the patterns we care about."""
    p = tmp_path / "keepalived.conf"
    p.write_text(
        "global_defs {\n"
        "@host-a\trouter_id A\n"
        "@host-b\trouter_id B\n"
        "@host-a\t\tnotification_email_from a@example.com\n"
        "@host-b\t\tnotification_email_from b@example.com\n"
        "\tnotification_email {\n"
        "\t\troot@example.com\n"
        "\t}\n"
        "}\n"
        "vrrp_instance VI {\n"
        "@host-a\tpriority 200\n"
        "@host-b\tpriority 150\n"
        "}\n"
    )
    return p


def test_template_keeps_host_a_drops_others(tagged_file: Path):
    r = _cli("config", "template", str(tagged_file), "--host", "host-a")
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "router_id A" in out
    assert "router_id B" not in out
    assert "priority 200" in out
    assert "priority 150" not in out
    # Untagged lines pass through.
    assert "global_defs {" in out
    assert "vrrp_instance VI {" in out
    assert "root@example.com" in out


def test_template_preserves_indent_after_tag_strip(tagged_file: Path):
    r = _cli("config", "template", str(tagged_file), "--host", "host-a")
    assert r.returncode == 0, r.stderr
    # `@host-a\t\tnotification_email_from …` → after stripping
    # `@host-a\t` exactly one tab remains as the body indent.
    body_line = next(
        l for l in r.stdout.splitlines()
        if "notification_email_from" in l)
    assert body_line.startswith("\t"), repr(body_line)


def test_template_writes_output_file(tagged_file: Path, tmp_path: Path):
    out = tmp_path / "out.conf"
    r = _cli("config", "template", str(tagged_file),
             "--host", "host-b", "-o", str(out))
    assert r.returncode == 0, r.stderr
    assert out.exists()
    text = out.read_text()
    assert "router_id B" in text
    assert "router_id A" not in text
    # Stderr summary line shows the kept/dropped counts.
    assert "kept" in r.stderr and "dropped" in r.stderr


def test_template_unknown_host_drops_everything_tagged(tagged_file: Path):
    r = _cli("config", "template", str(tagged_file), "--host", "ghost")
    assert r.returncode == 0, r.stderr
    # No `router_id` line survives — both A and B are tagged for
    # other hosts.
    assert "router_id" not in r.stdout
    # But untagged lines do.
    assert "global_defs {" in r.stdout


def test_template_no_tags_pass_through(tmp_path: Path):
    p = tmp_path / "plain.conf"
    p.write_text("line1\nline2\n")
    r = _cli("config", "template", str(p), "--host", "anything")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "line1\nline2"
