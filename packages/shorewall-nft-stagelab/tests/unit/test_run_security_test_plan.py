"""Unit-style tests for tools/run-security-test-plan.sh.

Uses subprocess.run to drive the script directly — no network, no root
required.  Tests cover:

- --help exits 0 and prints usage text.
- --standards with an unknown name exits non-zero with a helpful message.
- --config missing exits non-zero with an error message.
- --dry-run with a minimal base config + a tiny catalogue fragment prints
  the expected stagelab command lines and exits 0 (or exits with a non-zero
  code from merge_config when the base config is intentionally broken).
- Valid --dry-run produces the expected stagelab validate / run / audit lines.
"""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path


def _repo_root() -> Path:
    """Return absolute path to the repository root."""
    this_file = Path(__file__).resolve()
    # tests/unit/test_... -> tests -> packages/pkg -> packages -> repo-root
    return this_file.parents[4]


def _script() -> str:
    return str(_repo_root() / "tools" / "run-security-test-plan.sh")


def _run(*args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_script(), *args],
        capture_output=True,
        text=True,
        **kw,
    )


# ---------------------------------------------------------------------------
# Basic interface tests
# ---------------------------------------------------------------------------


def test_help_exits_zero():
    result = _run("--help")
    assert result.returncode == 0


def test_help_output_contains_usage():
    result = _run("--help")
    assert "usage:" in result.stdout.lower()
    assert "--config" in result.stdout
    assert "--standards" in result.stdout
    assert "--dry-run" in result.stdout


def test_unknown_standard_exits_nonzero():
    result = _run("--standards", "bogus", "--config", "/dev/null")
    assert result.returncode != 0


def test_unknown_standard_error_message():
    result = _run("--standards", "bogus", "--config", "/dev/null")
    combined = (result.stdout + result.stderr).lower()
    assert "unknown standard" in combined


def test_missing_config_exits_nonzero():
    result = _run("--standards", "cis")
    assert result.returncode != 0


def test_missing_config_error_message():
    result = _run("--standards", "cis")
    combined = result.stdout + result.stderr
    assert "--config" in combined


# ---------------------------------------------------------------------------
# --dry-run smoke with a minimal fixture
# ---------------------------------------------------------------------------


def _make_base_config(tmp_path: Path) -> Path:
    """Write a minimal valid-looking base stagelab YAML."""
    cfg = tmp_path / "base.yaml"
    cfg.write_text(
        textwrap.dedent("""\
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
    )
    return cfg


def _make_catalogue_fragment(tmp_path: Path, std: str) -> Path:
    """Write a minimal catalogue fragment with one covered and one partial test."""
    frag = tmp_path / f"security-test-plan.{std}.yaml"
    frag.write_text(
        textwrap.dedent(f"""\
        standard: {std}
        standard_title: "Test standard {std}"

        tests:

          - test_id: {std}-test-1
            standard_refs: [{std}-test-1]
            title: "Test 1 — covered"
            status: covered
            maps_to_scenario:
              id: {std}-test-1-scenario
              kind: rule_scan
              source: ep1
              target_subnet: 10.0.0.0/8
              random_count: 10
              test_id: {std}-test-1
              acceptance_criteria:
                fail_accept_count: 0

          - test_id: {std}-test-2
            standard_refs: [{std}-test-2]
            title: "Test 2 — partial (should be skipped)"
            status: partial
            maps_to_scenario:
              id: {std}-test-2-scenario
              kind: rule_scan
              source: ep1
              target_subnet: 10.0.0.0/8
              random_count: 10
        """)
    )
    return frag


def test_dry_run_exits_zero(tmp_path: Path):
    base_cfg = _make_base_config(tmp_path)
    _make_catalogue_fragment(tmp_path, "cis")
    result = _run(
        "--standards", "cis",
        "--config", str(base_cfg),
        "--out", str(tmp_path / "out"),
        "--catalogue-dir", str(tmp_path),
        "--dry-run",
    )
    assert result.returncode == 0, result.stderr


def test_dry_run_prints_validate_line(tmp_path: Path):
    base_cfg = _make_base_config(tmp_path)
    _make_catalogue_fragment(tmp_path, "cis")
    result = _run(
        "--standards", "cis",
        "--config", str(base_cfg),
        "--out", str(tmp_path / "out"),
        "--catalogue-dir", str(tmp_path),
        "--dry-run",
    )
    combined = result.stdout + result.stderr
    assert "stagelab validate" in combined


def test_dry_run_prints_run_line(tmp_path: Path):
    base_cfg = _make_base_config(tmp_path)
    _make_catalogue_fragment(tmp_path, "cis")
    result = _run(
        "--standards", "cis",
        "--config", str(base_cfg),
        "--out", str(tmp_path / "out"),
        "--catalogue-dir", str(tmp_path),
        "--dry-run",
    )
    combined = result.stdout + result.stderr
    assert "stagelab run" in combined


def test_dry_run_prints_audit_line(tmp_path: Path):
    base_cfg = _make_base_config(tmp_path)
    _make_catalogue_fragment(tmp_path, "cis")
    result = _run(
        "--standards", "cis",
        "--config", str(base_cfg),
        "--out", str(tmp_path / "out"),
        "--catalogue-dir", str(tmp_path),
        "--dry-run",
    )
    combined = result.stdout + result.stderr
    assert "stagelab audit" in combined


def test_dry_run_missing_fragment_warns_and_continues(tmp_path: Path):
    """When cc fragment is absent, script warns but exits 0 in --dry-run."""
    base_cfg = _make_base_config(tmp_path)
    # cc fragment intentionally absent.
    result = _run(
        "--standards", "cc",
        "--config", str(base_cfg),
        "--out", str(tmp_path / "out"),
        "--catalogue-dir", str(tmp_path),
        "--dry-run",
    )
    combined = result.stdout + result.stderr
    assert "skipping" in combined.lower() or "not found" in combined.lower()


def test_dry_run_no_output_dirs_created(tmp_path: Path):
    """--dry-run must not create any output directories."""
    base_cfg = _make_base_config(tmp_path)
    _make_catalogue_fragment(tmp_path, "bsi")
    out_dir = tmp_path / "out"
    _run(
        "--standards", "bsi",
        "--config", str(base_cfg),
        "--out", str(out_dir),
        "--catalogue-dir", str(tmp_path),
        "--dry-run",
    )
    assert not out_dir.exists(), "dry-run must not create output directories"


def test_dry_run_multiple_standards(tmp_path: Path):
    """Multiple standards in one dry-run invocation."""
    base_cfg = _make_base_config(tmp_path)
    _make_catalogue_fragment(tmp_path, "cis")
    _make_catalogue_fragment(tmp_path, "owasp")
    result = _run(
        "--standards", "cis,owasp",
        "--config", str(base_cfg),
        "--out", str(tmp_path / "out"),
        "--catalogue-dir", str(tmp_path),
        "--dry-run",
    )
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    assert "cis" in combined
    assert "owasp" in combined


def test_dry_run_simlab_flag_printed(tmp_path: Path):
    base_cfg = _make_base_config(tmp_path)
    _make_catalogue_fragment(tmp_path, "cis")
    result = _run(
        "--standards", "cis",
        "--config", str(base_cfg),
        "--out", str(tmp_path / "out"),
        "--catalogue-dir", str(tmp_path),
        "--dry-run",
        "--simlab",
    )
    combined = result.stdout + result.stderr
    assert "simlab" in combined.lower()
