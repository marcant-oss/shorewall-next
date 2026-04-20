"""Integration test: stagelab review --open-pr against a fake local gh binary.

Exercises the full CLI wiring + argv construction; not just monkeypatched
subprocess.run in unit tests.
"""

from __future__ import annotations

import os
import textwrap

import pytest
from click.testing import CliRunner

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="fake gh shell wrapper is POSIX-only",
)


def test_review_invokes_gh_pr_create(tmp_path, monkeypatch):
    # 1. Stage a fake report-dir with review-able artifacts.
    report_dir = tmp_path / "2026-04-20T10:00:00Z"
    report_dir.mkdir()
    (report_dir / "recommendations.yaml").write_text(textwrap.dedent("""\
        recommendations:
          - tier: B
            signal: conntrack_headroom
            action: "sysctl -w net.netfilter.nf_conntrack_max=8388608"
            target: fw
            confidence: medium
            rationale: "conntrack_count=820000 / conntrack_max=1000000 (82%)"
    """))
    (report_dir / "rule-order-hint.yaml").write_text(textwrap.dedent("""\
        rule_order_hints: []
    """))

    # 2. Stage a fake gh binary that logs argv to a file and prints a canned URL.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    argv_log = tmp_path / "gh_argv.txt"
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(
        f"#!/bin/sh\n"
        f": > {argv_log}\n"
        f'for arg in "$@"; do\n'
        f'    printf \'%s\\n\' "$arg" >> {argv_log}\n'
        f"done\n"
        f"echo 'https://github.com/fake/repo/pull/42'\n"
    )
    fake_gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")

    # 3. Run the CLI.
    from shorewall_nft_stagelab.cli import main

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "review",
            "--open-pr",
            "--repo", "fake/repo",
            "--branch", "test-branch",
            str(report_dir),
        ],
    )

    # 4. Assertions.
    assert result.exit_code == 0, result.output
    assert "https://github.com/fake/repo/pull/42" in result.output

    captured = argv_log.read_text().splitlines()

    # gh pr create must be the first three argv tokens.
    assert captured[:3] == ["pr", "create", "--repo"], captured

    # Required flags must appear.
    assert "pr" in captured
    assert "create" in captured
    assert "--repo" in captured
    assert "fake/repo" in captured
    assert "--title" in captured
    assert "--body-file" in captured
    # open_pr() always passes --base main (branch kwarg is not forwarded to gh).
    assert "--base" in captured
    assert "main" in captured
    # body-file must point at something; the path appears right after --body-file.
    body_file_idx = captured.index("--body-file")
    body_file_path = captured[body_file_idx + 1]
    assert body_file_path, "expected a non-empty --body-file argument"
