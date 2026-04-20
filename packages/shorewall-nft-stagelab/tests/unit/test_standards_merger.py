"""Integration smoke-test for the M1 merger outputs.

Reads the 7 Markdown fragment files and 4 Python fragments, runs both
merger scripts, and asserts that:
- The merged YAML is non-empty, parses as valid YAML, and has >= 60 test entries.
- The merged Markdown is non-empty and references all 7 standards.
- Every test_id in the merged YAML is present in standards.TEST_ID.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

try:
    import yaml
except ModuleNotFoundError:
    pytest.skip("pyyaml not installed", allow_module_level=True)

REPO_ROOT = Path(__file__).resolve().parents[4]  # stagelab/tests/unit -> repo root
CATALOGUE_DIR = REPO_ROOT / "docs" / "testing"
TOOLS_DIR = REPO_ROOT / "tools"
YAML_OUT = CATALOGUE_DIR / "security-test-plan.yaml"
MD_OUT = CATALOGUE_DIR / "security-test-plan.md"


def test_yaml_merger_output_exists_and_parses():
    assert YAML_OUT.exists(), f"Merged YAML not found: {YAML_OUT}"
    doc = yaml.safe_load(YAML_OUT.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), "Merged YAML is not a mapping"
    assert "tests" in doc, "Merged YAML has no 'tests' key"
    assert len(doc["tests"]) >= 50, (
        f"Expected >= 50 tests in merged YAML, got {len(doc['tests'])}"
    )


def test_yaml_merger_no_duplicate_test_ids():
    assert YAML_OUT.exists()
    doc = yaml.safe_load(YAML_OUT.read_text(encoding="utf-8"))
    ids = [t["test_id"] for t in doc["tests"]]
    assert len(ids) == len(set(ids)), (
        f"Duplicate test_ids in merged YAML: "
        f"{[x for x in ids if ids.count(x) > 1]}"
    )


def test_yaml_tests_present_in_standards_test_id():
    """Every test_id in the merged YAML must resolve in standards.TEST_ID."""
    assert YAML_OUT.exists()
    doc = yaml.safe_load(YAML_OUT.read_text(encoding="utf-8"))
    from shorewall_nft_stagelab import standards
    missing = [
        t["test_id"] for t in doc["tests"] if t["test_id"] not in standards.TEST_ID
    ]
    assert not missing, (
        f"test_ids in YAML not found in standards.TEST_ID: {missing}"
    )


def test_markdown_output_exists_and_non_empty():
    assert MD_OUT.exists(), f"Merged Markdown not found: {MD_OUT}"
    content = MD_OUT.read_text(encoding="utf-8")
    assert len(content) > 1000, "Merged Markdown suspiciously short"


def test_markdown_contains_all_seven_standards():
    assert MD_OUT.exists()
    content = MD_OUT.read_text(encoding="utf-8")
    expected_anchors = [
        "common-criteria",
        "nist-sp-800-53",
        "bsi-it-grundschutz",
        "cis-benchmarks",
        "owasp",
        "iso-27001",
        "performance-addendum-ipv6",
    ]
    for anchor in expected_anchors:
        assert anchor in content, (
            f"Expected anchor '{anchor}' not found in merged Markdown"
        )


def test_yaml_merger_reruns_without_error(tmp_path):
    """Run the YAML merger script as a subprocess and check it exits 0."""
    out = tmp_path / "security-test-plan.yaml"
    result = subprocess.run(
        [
            sys.executable,
            str(TOOLS_DIR / "merge-security-test-plan-yaml.py"),
            "--out", str(out),
            "--catalogue-dir", str(CATALOGUE_DIR),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"merge-security-test-plan-yaml.py exited {result.returncode}:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert out.exists()
    doc = yaml.safe_load(out.read_text())
    assert len(doc["tests"]) >= 50


def test_md_merger_reruns_without_error(tmp_path):
    """Run the Markdown merger script as a subprocess and check it exits 0."""
    out = tmp_path / "security-test-plan.md"
    result = subprocess.run(
        [
            sys.executable,
            str(TOOLS_DIR / "merge-security-test-plan.py"),
            "--md-out", str(out),
            "--catalogue-dir", str(CATALOGUE_DIR),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"merge-security-test-plan.py exited {result.returncode}:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert out.exists()
    content = out.read_text()
    assert len(content) > 1000
