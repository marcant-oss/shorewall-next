"""Unit tests for trafgen_nmap."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from shorewall_nft_stagelab.trafgen_nmap import (
    NmapSpec,
    build_argv,
    parse_xml,
    run_nmap,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parse_tcp_scan() -> None:
    xml = (FIXTURES / "nmap_tcp_open_closed.xml").read_text()
    result = parse_xml(xml, "10.0.0.1")
    assert result.ok is True
    assert result.tool == "nmap"
    assert len(result.ports) == 3
    by_port = {p.port: p for p in result.ports}
    assert by_port[22].proto == "tcp"
    assert by_port[22].state == "open"
    assert by_port[22].service == "ssh"
    assert by_port[80].state == "closed"
    assert by_port[80].service == "http"
    assert by_port[443].state == "filtered"
    assert by_port[443].service == ""


def test_parse_no_host_not_ok() -> None:
    xml = (FIXTURES / "nmap_no_host.xml").read_text()
    result = parse_xml(xml, "10.0.0.1")
    assert result.ok is False
    assert result.ports == ()


def test_build_argv_tcp() -> None:
    spec = NmapSpec(target="10.0.0.0/24", ports="1-100", timing=4)
    argv = build_argv(spec)
    assert "-Pn" in argv
    assert "-T4" in argv
    assert "-p" in argv
    assert "1-100" in argv
    assert "-sS" in argv
    assert "10.0.0.0/24" in argv
    # XML output flags must appear as adjacent pair
    assert "-oX" in argv
    oX_idx = argv.index("-oX")
    assert argv[oX_idx + 1] == "-"


def test_run_nmap_nonzero_exit_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "shorewall_nft_stagelab.trafgen_nmap.subprocess.run",
        lambda *_a, **_kw: subprocess.CompletedProcess(
            args=[], returncode=2, stdout="", stderr="permission denied"
        ),
    )
    spec = NmapSpec(target="10.0.0.1")
    with pytest.raises(RuntimeError, match="permission denied"):
        run_nmap(spec)
