"""JSON and Markdown report generation for stagelab run results."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from .advisor import Recommendation


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    kind: str           # "throughput" | "conn_storm" | "rule_scan"
    ok: bool
    duration_s: float
    raw: dict           # tool-specific result dict
    criteria_results: dict = field(default_factory=dict)  # criterion_name -> bool
    test_id: str | None = None
    standard_refs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RunReport:
    run_id: str                    # UTC ISO8601, e.g. "2026-04-20T15:00:00Z"
    config_path: str
    scenarios: list[ScenarioResult]
    recommendations: tuple["Recommendation", ...] = field(default_factory=tuple)


def write(run: RunReport, output_dir: Path) -> Path:
    """Create the run directory and write run.json + summary.md.

    Also writes recommendations.yaml if run.recommendations is non-empty.
    Returns the created directory path.
    Raises FileExistsError if the run directory already exists — never overwrites.
    """
    run_dir = output_dir / run.run_id
    if run_dir.exists():
        raise FileExistsError(f"Run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)

    # JSON report — serialise dataclasses to plain dicts
    payload = {
        "run_id": run.run_id,
        "config_path": run.config_path,
        "scenarios": [asdict(s) for s in run.scenarios],
    }
    (run_dir / "run.json").write_text(json.dumps(payload, indent=2))

    # Markdown summary
    (run_dir / "summary.md").write_text(_render_markdown(run))

    # Sweep CSV files — one per tuning_sweep scenario
    for s in run.scenarios:
        if s.kind == "tuning_sweep":
            csv_text = _render_sweep_csv(s)
            (run_dir / f"sweep-{s.scenario_id}.csv").write_text(csv_text)

    # Recommendations YAML (only when non-empty)
    if run.recommendations:
        rec_list = [
            {
                "tier": r.tier,
                "signal": r.signal,
                "action": r.action,
                "target": r.target,
                "confidence": r.confidence,
                "rationale": r.rationale,
            }
            for r in run.recommendations
        ]
        payload_yaml = {"recommendations": rec_list}
        (run_dir / "recommendations.yaml").write_text(
            yaml.safe_dump(payload_yaml, sort_keys=False, allow_unicode=True)
        )

    return run_dir


def _render_markdown(run: RunReport) -> str:
    """Produce a Markdown summary of the run.

    rule_scan scenarios always get a false-drop / false-accept breakdown.
    """
    lines: list[str] = []
    lines.append(f"# stagelab run {run.run_id}")
    lines.append("")
    lines.append(f"Config: {run.config_path}")
    lines.append("")
    lines.append("## Scenarios")
    lines.append("")

    for s in run.scenarios:
        status = "OK" if s.ok else "FAIL"
        lines.append(f"### {s.scenario_id} ({s.kind}) — {status}")
        lines.append("")
        lines.append(f"Duration: {s.duration_s:.3f}s")
        lines.append("")

        if s.kind == "throughput":
            _render_throughput(lines, s.raw)
        elif s.kind == "conn_storm":
            _render_conn_storm(lines, s.raw)
        elif s.kind == "rule_scan":
            _render_rule_scan(lines, s.raw)
        elif s.kind == "tuning_sweep":
            _render_tuning_sweep(lines, s.raw)
        else:
            # Generic fallback — dump raw keys
            for k, v in s.raw.items():
                lines.append(f"- {k}: {v}")
            lines.append("")

        if s.criteria_results:
            lines.append("**Acceptance criteria:**")
            lines.append("")
            for name, passed in s.criteria_results.items():
                verdict = "PASS" if passed else "FAIL"
                lines.append(f"- {name}: {verdict}")
            lines.append("")

    # Recommendations section (only when non-empty)
    if run.recommendations:
        lines.append("## Recommendations")
        lines.append("")
        tiers: dict[str, list] = {"A": [], "B": [], "C": []}
        for rec in run.recommendations:
            tiers.setdefault(rec.tier, []).append(rec)
        for tier in ("A", "B", "C"):
            recs = tiers.get(tier, [])
            if not recs:
                continue
            lines.append(f"### Tier {tier}")
            lines.append("")
            for rec in recs:
                lines.append(
                    f"- **[{rec.tier}] {rec.signal}** — {rec.action} ({rec.rationale})"
                )
            lines.append("")

    return "\n".join(lines) + "\n"


def _render_throughput(lines: list[str], raw: dict) -> None:
    gbps = raw.get("gbps")
    retransmits = raw.get("retransmits")
    duration = raw.get("duration_s")
    if gbps is not None:
        lines.append(f"- Gbps: {gbps:.3f}")
    if retransmits is not None:
        lines.append(f"- Retransmits: {retransmits}")
    if duration is not None:
        lines.append(f"- Measured duration: {duration:.3f}s")
    lines.append("")


def _render_conn_storm(lines: list[str], raw: dict) -> None:
    target = raw.get("target_conns")
    established = raw.get("established")
    failed = raw.get("failed")
    if target is not None:
        lines.append(f"- Target connections: {target}")
    if established is not None:
        lines.append(f"- Established: {established}")
    if failed is not None:
        lines.append(f"- Failed: {failed}")
    lines.append("")


def _render_rule_scan(lines: list[str], raw: dict) -> None:
    """Render rule_scan section with mandatory false-drop / false-accept split.

    Each mismatch dict has keys: probe_id, src_ip, dst_ip, proto,
    expected ("accept"|"drop"), actual, oracle_rule.
    """
    mismatches: list[dict] = raw.get("mismatches", [])
    total = raw.get("total_probes", len(mismatches))
    passed = raw.get("passed", total - len(mismatches))

    lines.append(f"- Total probes: {total}")
    lines.append(f"- Passed: {passed}")
    lines.append(f"- Mismatches: {len(mismatches)}")
    lines.append("")

    false_drops = [m for m in mismatches if m.get("expected") == "accept"]
    false_accepts = [m for m in mismatches if m.get("expected") == "drop"]

    # False-drop section
    lines.append(f"**False-drop (expected accept but dropped): {len(false_drops)}**")
    lines.append("")
    if false_drops:
        for m in false_drops:
            probe = _format_probe(m)
            oracle = m.get("oracle_rule", "")
            entry = f"- {probe}"
            if oracle:
                entry += f"  ↳ oracle: `{oracle}`"
            lines.append(entry)
        lines.append("")
    else:
        lines.append("*(none)*")
        lines.append("")

    # False-accept section
    lines.append(
        f"**False-accept (expected drop but accepted): {len(false_accepts)}**"
    )
    lines.append("")
    if false_accepts:
        for m in false_accepts:
            probe = _format_probe(m)
            oracle = m.get("oracle_rule", "")
            entry = f"- {probe}"
            if oracle:
                entry += f"  ↳ oracle: `{oracle}`"
            lines.append(entry)
        lines.append("")
    else:
        lines.append("*(none)*")
        lines.append("")


def _format_probe(m: dict) -> str:
    probe_id = m.get("probe_id", "?")
    src = m.get("src_ip", "?")
    dst = m.get("dst_ip", "?")
    proto = m.get("proto", "?")
    actual = m.get("actual", "?")
    return f"probe {probe_id}: {src} → {dst} ({proto}) got={actual}"


# ---------------------------------------------------------------------------
# Tuning sweep renderer
# ---------------------------------------------------------------------------

_SWEEP_AXES = ("rss_queues", "rmem_max", "wmem_max")


def _render_tuning_sweep(lines: list[str], raw: dict) -> None:
    """Render a tuning_sweep section with optimum line + Markdown table."""
    optimum: dict | None = raw.get("optimum")
    points: list[dict] = raw.get("points", [])

    if optimum:
        opt_point = optimum.get("point", {})
        opt_tput = optimum.get("throughput_gbps", 0.0)
        opt_parts = "  ".join(f"{k}={v}" for k, v in opt_point.items()) if opt_point else "(baseline)"
        lines.append(f"Optimum:  {opt_parts}  →  {opt_tput:.1f} Gbps")
    else:
        lines.append("Optimum:  (none — all points failed)")
    lines.append("")

    if not points:
        lines.append("*(no data points)*")
        lines.append("")
        return

    # Determine which axes are actually present in data.
    present_axes = [ax for ax in _SWEEP_AXES if any(ax in p.get("point", {}) for p in points)]

    # Table header
    header_cols = present_axes + ["throughput_gbps", "ok"]
    sep_cols = ["-" * max(len(c), 3) for c in header_cols]
    lines.append("| " + " | ".join(header_cols) + " |")
    lines.append("| " + " | ".join(sep_cols) + " |")

    for p in points:
        point_params = p.get("point", {})
        row_vals: list[str] = []
        for ax in present_axes:
            row_vals.append(str(point_params[ax]) if ax in point_params else "—")
        row_vals.append(f"{p.get('throughput_gbps', 0.0):.1f}")
        row_vals.append("✓" if p.get("ok") else "✗")
        lines.append("| " + " | ".join(row_vals) + " |")

    lines.append("")


def _render_sweep_csv(s: "ScenarioResult") -> str:
    """Produce a CSV string for a tuning_sweep ScenarioResult."""
    raw = s.raw
    points: list[dict] = raw.get("points", [])

    present_axes = [ax for ax in _SWEEP_AXES if any(ax in p.get("point", {}) for p in points)]
    fieldnames = present_axes + ["throughput_gbps", "ok"]

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for p in points:
        point_params = p.get("point", {})
        row: dict = {ax: point_params.get(ax, "") for ax in present_axes}
        row["throughput_gbps"] = f"{p.get('throughput_gbps', 0.0):.3f}"
        row["ok"] = "true" if p.get("ok") else "false"
        writer.writerow(row)
    return buf.getvalue()
