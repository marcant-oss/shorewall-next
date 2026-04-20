"""Unit tests for shorewall_nft_stagelab.review."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from shorewall_nft_stagelab.review import (
    ReviewPayload,
    load_from_run_dir,
    open_pr,
    render_markdown,
    write,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_REC_YAML = yaml.safe_dump({
    "recommendations": [
        {
            "tier": "A",
            "signal": "rx_no_buffer",
            "action": "ethtool -G eth0 rx 4096",
            "target": "testhost",
            "confidence": "high",
            "rationale": "rx_no_buffer_count=5",
        },
        {
            "tier": "B",
            "signal": "conntrack_headroom",
            "action": "sysctl -w net.netfilter.nf_conntrack_max=8388608",
            "target": "fw",
            "confidence": "high",
            "rationale": "conntrack fill 85%",
        },
        {
            "tier": "C",
            "signal": "rule_order_topN",
            "action": "Reorder hot rules to top of chain",
            "target": "compiler",
            "confidence": "medium",
            "rationale": "top-3 account for 75%",
        },
    ]
}, sort_keys=False)

_HINT_YAML = yaml.safe_dump({
    "rule_order_hints": [
        {
            "chain": "forward",
            "table": "inet filter",
            "group_count": 3,
            "original_order": [10, 20, 30],
            "suggested_order": [10, 30, 20],
            "rationale": "reordered 1 group by counter packets desc",
        }
    ]
}, sort_keys=False)


# ---------------------------------------------------------------------------
# Test 1
# ---------------------------------------------------------------------------


def test_load_from_run_dir_with_both_files(tmp_path):
    """load_from_run_dir returns tier-B/C recs and all hints; tier-A excluded."""
    run_dir = tmp_path / "2026-04-20T12:00:00Z"
    run_dir.mkdir()
    (run_dir / "recommendations.yaml").write_text(_REC_YAML)
    (run_dir / "rule-order-hint.yaml").write_text(_HINT_YAML)

    payload = load_from_run_dir(run_dir)

    assert payload.run_id == "2026-04-20T12:00:00Z"
    # tier-A filtered out; B and C remain
    assert len(payload.tier_b_recommendations) == 2
    signals = {r["signal"] for r in payload.tier_b_recommendations}
    assert signals == {"conntrack_headroom", "rule_order_topN"}
    # rule_order hints loaded
    assert len(payload.rule_order_hints) == 1
    assert payload.rule_order_hints[0]["chain"] == "forward"


# ---------------------------------------------------------------------------
# Test 2
# ---------------------------------------------------------------------------


def test_load_from_run_dir_empty(tmp_path):
    """load_from_run_dir with no yaml files returns empty payload."""
    run_dir = tmp_path / "empty-run"
    run_dir.mkdir()

    payload = load_from_run_dir(run_dir)

    assert payload.run_id == "empty-run"
    assert payload.tier_b_recommendations == ()
    assert payload.rule_order_hints == ()


# ---------------------------------------------------------------------------
# Test 3
# ---------------------------------------------------------------------------


def test_render_markdown_emits_tier_sections():
    """render_markdown includes both section headers, action text, and hint chain."""
    payload = ReviewPayload(
        run_id="2026-04-20T00:00:00Z",
        tier_b_recommendations=(
            {
                "tier": "B",
                "signal": "conntrack_headroom",
                "action": "sysctl -w net.netfilter.nf_conntrack_max=8388608",
                "rationale": "fill at 85%",
            },
        ),
        rule_order_hints=(
            {
                "chain": "forward",
                "table": "inet filter",
                "group_count": 2,
                "original_order": [10, 20],
                "suggested_order": [20, 10],
                "rationale": "reordered 1 group",
            },
        ),
    )

    md = render_markdown(payload)

    assert "## Tier-B recommendations" in md
    assert "## Tier-C rule-order hints" in md
    assert "conntrack_headroom" in md
    assert "sysctl -w net.netfilter.nf_conntrack_max=8388608" in md
    assert "forward" in md
    assert "inet filter" in md


# ---------------------------------------------------------------------------
# Test 4
# ---------------------------------------------------------------------------


def test_render_markdown_handles_empty():
    """Empty payload still emits both section headers with placeholder text."""
    payload = ReviewPayload(
        run_id="no-data",
        tier_b_recommendations=(),
        rule_order_hints=(),
    )

    md = render_markdown(payload)

    assert "## Tier-B recommendations" in md
    assert "## Tier-C rule-order hints" in md
    assert "*No tier-B recommendations.*" in md
    assert "*No rule-order hints.*" in md


# ---------------------------------------------------------------------------
# Test 5
# ---------------------------------------------------------------------------


def test_write_refuses_overwrite(tmp_path):
    """write() raises FileExistsError if review.md already exists."""
    out_dir = tmp_path / "run-x"
    out_dir.mkdir()
    (out_dir / "review.md").write_text("old content\n")

    payload = ReviewPayload(
        run_id="run-x",
        tier_b_recommendations=(),
        rule_order_hints=(),
    )

    with pytest.raises(FileExistsError):
        write(payload, out_dir)


# ---------------------------------------------------------------------------
# Test 6
# ---------------------------------------------------------------------------


def test_open_pr_invokes_gh(monkeypatch):
    """open_pr calls subprocess.run with the expected gh arguments."""
    fake_result = MagicMock()
    fake_result.stdout = "https://github.com/x/y/pull/1\n"

    captured: list = []

    def fake_run(cmd, **kwargs):
        captured.append(cmd)
        return fake_result

    monkeypatch.setattr("shorewall_nft_stagelab.review.subprocess.run", fake_run)

    payload = ReviewPayload(
        run_id="2026-04-20T00:00:00Z",
        tier_b_recommendations=(),
        rule_order_hints=(),
    )

    url = open_pr(
        payload,
        repo="x/y",
        branch="stagelab/2026-04-20",
        body_path=Path("/tmp/foo.md"),
    )

    assert url == "https://github.com/x/y/pull/1"
    assert len(captured) == 1
    cmd = captured[0]
    assert cmd[0] == "gh"
    assert "pr" in cmd
    assert "create" in cmd
    assert "--repo" in cmd
    assert "x/y" in cmd
    assert "--body-file" in cmd
    assert "/tmp/foo.md" in cmd
    assert "--base" in cmd
    assert "main" in cmd
