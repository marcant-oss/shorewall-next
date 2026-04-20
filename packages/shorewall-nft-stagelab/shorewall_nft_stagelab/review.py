"""Consolidate tier-B/C recommendations + rule-order hints into a review bundle.

Tier-A recommendations are excluded — they are testhost-local, auto-applied by
tuning_sweep, and do not require operator review for FW-side changes.
"""

from __future__ import annotations

import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Data transfer object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewPayload:
    """Consolidated view of everything an operator needs to decide about
    a stagelab run's FW-side changes."""

    run_id: str
    tier_b_recommendations: tuple[dict, ...]   # filtered from recommendations.yaml
    rule_order_hints: tuple[dict, ...]          # from rule-order-hint.yaml
    # Tier A (testhost-local) is excluded — those are auto-applied / already
    # run by tuning_sweep; no operator review needed.


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_from_run_dir(run_dir: Path) -> ReviewPayload:
    """Read recommendations.yaml (if present) and rule-order-hint.yaml
    (if present) from run_dir. Filter recommendations to tier in {"B", "C"}.
    Return a payload even if both files are missing — empty tuples."""
    run_id = run_dir.name

    # recommendations.yaml
    rec_path = run_dir / "recommendations.yaml"
    tier_b: list[dict] = []
    if rec_path.exists():
        data = yaml.safe_load(rec_path.read_text()) or {}
        for rec in data.get("recommendations", []):
            if rec.get("tier") in {"B", "C"}:
                tier_b.append(rec)

    # rule-order-hint.yaml
    hint_path = run_dir / "rule-order-hint.yaml"
    hints: list[dict] = []
    if hint_path.exists():
        data = yaml.safe_load(hint_path.read_text()) or {}
        hints = data.get("rule_order_hints", [])

    return ReviewPayload(
        run_id=run_id,
        tier_b_recommendations=tuple(tier_b),
        rule_order_hints=tuple(hints),
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_markdown(payload: ReviewPayload) -> str:
    """Human-readable review.

    # Stagelab Review — <run_id>

    ## Tier-B recommendations (review required for FW changes)

    - [B] **signal** — `action`
      *Rationale:* rationale

    ## Tier-C rule-order hints (compiler input)

    Per chain: table, chain, group_count, original vs suggested handles.
    """
    lines: list[str] = []
    lines.append(f"# Stagelab Review — {payload.run_id}")
    lines.append("")

    # --- Tier-B/C recommendations section ---
    lines.append("## Tier-B recommendations (review required for FW changes)")
    lines.append("")
    if payload.tier_b_recommendations:
        for rec in payload.tier_b_recommendations:
            tier = rec.get("tier", "B")
            signal = rec.get("signal", "")
            action = rec.get("action", "")
            rationale = rec.get("rationale", "")
            lines.append(f"- [{tier}] **{signal}** — `{action}`")
            if rationale:
                wrapped = textwrap.fill(
                    rationale, width=76,
                    initial_indent="  *Rationale:* ",
                    subsequent_indent="  ",
                )
                lines.append(wrapped)
    else:
        lines.append("*No tier-B recommendations.*")
    lines.append("")

    # --- Rule-order hints section ---
    lines.append("## Tier-C rule-order hints (compiler input)")
    lines.append("")
    if payload.rule_order_hints:
        for hint in payload.rule_order_hints:
            table = hint.get("table", "")
            chain = hint.get("chain", "")
            group_count = hint.get("group_count", 0)
            original = hint.get("original_order", [])
            suggested = hint.get("suggested_order", [])
            rationale = hint.get("rationale", "")
            lines.append(f"- **{table} / {chain}** — {group_count} groups")
            lines.append(f"  Original:  {original}")
            lines.append(f"  Suggested: {suggested}")
            if rationale:
                lines.append(f"  *{rationale}*")
    else:
        lines.append("*No rule-order hints.*")
    lines.append("")

    return "\n".join(lines)


def render_yaml(payload: ReviewPayload) -> str:
    """Flat yaml dump. Useful for downstream automation (PR generators,
    dashboards). Uses yaml.safe_dump, sort_keys=False."""
    data = {
        "run_id": payload.run_id,
        "tier_b_recommendations": list(payload.tier_b_recommendations),
        "rule_order_hints": list(payload.rule_order_hints),
    }
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def write(payload: ReviewPayload, out_dir: Path) -> tuple[Path, Path]:
    """Write review.md and review.yaml into out_dir.

    Returns (md_path, yaml_path). Creates out_dir if missing.
    Refuses to overwrite — raises FileExistsError if either file already exists.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "review.md"
    yaml_path = out_dir / "review.yaml"

    if md_path.exists():
        raise FileExistsError(f"review.md already exists: {md_path}")
    if yaml_path.exists():
        raise FileExistsError(f"review.yaml already exists: {yaml_path}")

    md_path.write_text(render_markdown(payload))
    yaml_path.write_text(render_yaml(payload))
    return md_path, yaml_path


# ---------------------------------------------------------------------------
# PR opener
# ---------------------------------------------------------------------------


def open_pr(
    payload: ReviewPayload,
    *,
    repo: str,
    branch: str,
    title: str = "",
    body_path: Path | None = None,
    gh_binary: str = "gh",
) -> str:
    """Create a PR via ``gh pr create``. Returns the PR URL from gh's stdout.

    If body_path is None, renders markdown from payload and writes to a
    temporary location.  Caller is responsible for creating the branch,
    committing artifact files, and pushing.  This function only runs
    ``gh pr create``.  Propagates errors from gh without silent fallback.
    """
    if body_path is None:
        # Render inline and pass via a temporary file-like mechanism.
        # We write to a temp path derived from the run_id.
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False
        ) as tmp:
            tmp.write(render_markdown(payload))
            _body_path = Path(tmp.name)
    else:
        _body_path = body_path

    effective_title = title or f"stagelab review: {payload.run_id}"

    cmd = [
        gh_binary, "pr", "create",
        "--repo", repo,
        "--title", effective_title,
        "--body-file", str(_body_path),
        "--base", "main",
    ]
    result = subprocess.run(cmd, check=True, text=True, capture_output=True)
    return result.stdout.strip()


__all__ = [
    "ReviewPayload",
    "load_from_run_dir",
    "render_markdown",
    "render_yaml",
    "write",
    "open_pr",
]
