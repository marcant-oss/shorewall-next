"""Unit tests for shorewall_nft_stagelab.cli (CliRunner, no real agents)."""

from __future__ import annotations

import textwrap

from click.testing import CliRunner

from shorewall_nft_stagelab.cli import main

# ---------------------------------------------------------------------------
# Minimal valid YAML (one host with address "local:", one probe endpoint,
# zero scenarios — satisfies all Pydantic constraints).
# ---------------------------------------------------------------------------

_VALID_YAML = textwrap.dedent("""\
    hosts:
      - name: h1
        address: "local:"

    dut:
      kind: external

    endpoints:
      - name: ep1
        host: h1
        mode: probe
        bridge: br0

    scenarios: []

    report:
      output_dir: /tmp/stagelab-test-reports
""")

_BAD_YAML = textwrap.dedent("""\
    hosts: []
    dut:
      kind: external
    endpoints: []
    scenarios: []
    report:
      output_dir: /tmp/stagelab-test-reports
      keep_pcaps: invalid_value
""")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_validate_happy_path(tmp_path):
    """validate exits 0 and prints 'OK' for a minimal valid YAML."""
    cfg_file = tmp_path / "cfg.yaml"
    cfg_file.write_text(_VALID_YAML)

    runner = CliRunner()
    result = runner.invoke(main, ["validate", str(cfg_file)])

    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_validate_failing_yaml(tmp_path):
    """validate exits non-zero and prints an error for invalid YAML."""
    cfg_file = tmp_path / "bad.yaml"
    cfg_file.write_text(_BAD_YAML)

    runner = CliRunner()
    result = runner.invoke(main, ["validate", str(cfg_file)])

    assert result.exit_code != 0
    # Error text should be present somewhere in combined output
    combined = result.output + (result.exception.__str__() if result.exception else "")
    assert "error" in combined.lower() or "invalid" in combined.lower()


def test_inspect_reads_summary_md(tmp_path):
    """inspect prints summary.md contents to stdout."""
    report_dir = tmp_path / "2026-04-20T00:00:00Z"
    report_dir.mkdir()
    (report_dir / "summary.md").write_text("hello from summary\n")

    runner = CliRunner()
    result = runner.invoke(main, ["inspect", str(report_dir)])

    assert result.exit_code == 0, result.output
    assert "hello" in result.output


def test_run_refuses_bad_config_path():
    """run exits non-zero when the config path does not exist."""
    runner = CliRunner()
    result = runner.invoke(main, ["run", "/nonexistent/path/cfg.yaml"])

    assert result.exit_code != 0
