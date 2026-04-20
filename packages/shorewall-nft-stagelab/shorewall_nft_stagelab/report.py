"""JSON and Markdown report generation for stagelab run results."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    kind: str           # "throughput" | "conn_storm" | "rule_scan"
    ok: bool
    duration_s: float
    raw: dict           # tool-specific result dict


@dataclass(frozen=True)
class RunReport:
    run_id: str                    # UTC ISO8601, e.g. "2026-04-20T15:00:00Z"
    config_path: str
    scenarios: list[ScenarioResult]


def write(run: RunReport, output_dir: Path) -> Path:
    """Create the run directory and write run.json + summary.md.

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
        else:
            # Generic fallback — dump raw keys
            for k, v in s.raw.items():
                lines.append(f"- {k}: {v}")
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
