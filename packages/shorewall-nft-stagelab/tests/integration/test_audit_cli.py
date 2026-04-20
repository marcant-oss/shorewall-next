"""Integration test: stagelab audit CLI writes a valid HTML report."""

from __future__ import annotations

import json
from pathlib import Path


def test_audit_cli_writes_html(tmp_path: Path) -> None:
    run_dir = tmp_path / "2026-04-20T10:00:00Z"
    run_dir.mkdir()
    (run_dir / "run.json").write_text(json.dumps({
        "run_id": "2026-04-20T10:00:00Z",
        "config_path": "example.yaml",
        "scenarios": [{
            "scenario_id": "smoke",
            "kind": "throughput",
            "ok": True,
            "duration_s": 10.0,
            "raw": {"throughput_gbps": 9.5},
        }],
        "recommendations": [],
    }))

    from click.testing import CliRunner

    from shorewall_nft_stagelab.cli import main

    # Skip pdf to avoid weasyprint dependency in CI
    r = CliRunner().invoke(main, ["audit", str(run_dir), "--format", "html"])
    assert r.exit_code == 0, r.output
    assert (run_dir / "audit.html").exists()
    html = (run_dir / "audit.html").read_text()
    assert "<!DOCTYPE html>" in html
    assert "Stagelab Firewall Validation Report" in html
    assert "smoke" in html
