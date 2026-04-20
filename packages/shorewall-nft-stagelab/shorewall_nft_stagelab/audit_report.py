"""Audit report generator: consolidates stagelab run-dirs into a single HTML/PDF report."""

from __future__ import annotations

import json
import os
import warnings
from dataclasses import dataclass
from pathlib import Path

from . import standards as _standards

# ---------------------------------------------------------------------------
# Category / severity / grade constants
# ---------------------------------------------------------------------------

_CATEGORY_MAP: dict[str, str] = {
    "throughput": "Performance",
    "throughput_dpdk": "Performance",
    "tuning_sweep": "Performance",
    "conn_storm": "Performance",
    "conn_storm_astf": "Performance",
    "rule_scan": "Rule-Coverage",
    "rule_coverage_matrix": "Rule-Coverage",
    "dos_syn_flood": "DoS-Resilience",
    "dos_dns_query": "DoS-Resilience",
    "dos_half_open": "DoS-Resilience",
    "ha_failover": "HA",
    "stateful_helper_ftp": "Stateful-Protocol",
    "evasion_probes": "Evasion",
    "reload_atomicity": "Operational",
    "long_flow_survival": "Operational",
}

_CATEGORY_SEVERITY_WEIGHT: dict[str, int] = {
    "Evasion": 10,
    "HA": 8,
    "Rule-Coverage": 5,
    "Stateful-Protocol": 5,
    "DoS-Resilience": 4,
    "Operational": 3,
    "Performance": 2,
    "Other": 1,
}

_GRADE_THRESHOLDS: list[tuple[float, str]] = [
    (95.0, "A+"),
    (90.0, "A"),
    (80.0, "B"),
    (70.0, "C"),
    (60.0, "D"),
    (0.0, "F"),
]

# Severity labels for failed scenarios
_CAT_SEVERITY: dict[str, str] = {
    "Evasion": "critical",
    "HA": "high",
    "Rule-Coverage": "high",
    "Stateful-Protocol": "medium",
    "DoS-Resilience": "medium",
    "Operational": "low",
    "Performance": "low",
    "Other": "low",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditPayload:
    run_id: str
    operator: str
    config_path: str
    scenarios: tuple[dict, ...]           # normalised ScenarioResult dicts
    recommendations: tuple[dict, ...]     # tier B+C Recommendation dicts
    # System-under-test facts (best-effort, optional):
    sut_facts: dict                       # host info, ruleset git hash etc.
    # Test-setup facts:
    setup_facts: dict                     # tester hosts, versions, tool list
    # Stream D2 integration (wired now, populated later):
    simlab_report: Path | None = None


def load_runs(run_dirs: list[Path]) -> AuditPayload:
    """Read run.json (and recommendations.yaml if present) from each run
    dir; merge into a single AuditPayload. For multi-run input, each
    scenario keeps its original run_id; the top-level AuditPayload.run_id
    is the most recent.
    """
    import yaml as _yaml

    all_scenarios: list[dict] = []
    all_recs: list[dict] = []
    run_id = ""
    config_path = ""
    operator = os.environ.get("USER", "unknown")

    # Expand: if a given path has no run.json directly, look for timestamped
    # subdirectories (the pattern stagelab run creates: output_dir/<run_id>/run.json).
    expanded: list[Path] = []
    for d in run_dirs:
        if (d / "run.json").exists():
            expanded.append(d)
        else:
            subdirs = sorted(
                (sd for sd in d.iterdir() if sd.is_dir() and (sd / "run.json").exists()),
                key=lambda sd: sd.name,
            )
            expanded.extend(subdirs)

    sorted_dirs = sorted(expanded, key=lambda d: d.name)
    if not sorted_dirs:
        raise FileNotFoundError(
            f"No run.json found in any of: {[str(d) for d in run_dirs]}"
        )

    for run_dir in sorted_dirs:
        run_json = run_dir / "run.json"
        if not run_json.exists():
            raise FileNotFoundError(f"run.json not found in {run_dir}")
        data = json.loads(run_json.read_text())

        run_id = data.get("run_id", run_dir.name)
        config_path = data.get("config_path", "")

        for s in data.get("scenarios", []):
            sc = dict(s)
            # Ensure scenario_id exists
            sc.setdefault("scenario_id", sc.get("id", "unknown"))
            sc.setdefault("kind", "unknown")
            sc.setdefault("ok", False)
            sc.setdefault("duration_s", 0.0)
            sc.setdefault("raw", {})
            sc.setdefault("note", "")
            sc.setdefault("criteria_results", {})
            sc.setdefault("test_id", None)
            sc.setdefault("standard_refs", [])
            all_scenarios.append(sc)

        # Recommendations from run.json or separate recommendations.yaml
        recs_from_json = data.get("recommendations", [])
        if recs_from_json:
            all_recs.extend(recs_from_json)

        rec_yaml = run_dir / "recommendations.yaml"
        if rec_yaml.exists():
            rec_data = _yaml.safe_load(rec_yaml.read_text()) or {}
            yaml_recs = rec_data.get("recommendations", [])
            # Avoid double-counting if run.json already had them
            if not recs_from_json:
                all_recs.extend(yaml_recs)

    # Filter to tier B+C only (tier A is auto-applied, not for operator review)
    bc_recs = [r for r in all_recs if r.get("tier") in {"B", "C"}]

    sut_facts: dict = {}
    setup_facts: dict = {"config": config_path} if config_path else {}

    return AuditPayload(
        run_id=run_id,
        operator=operator,
        config_path=config_path,
        scenarios=tuple(all_scenarios),
        recommendations=tuple(bc_recs),
        sut_facts=sut_facts,
        setup_facts=setup_facts,
    )


def _load_simlab_scenarios(simlab_path: Path) -> list[dict]:
    """Parse a simlab.json (schema_version 1) and return its ``scenarios``
    list with ``source: "simlab"`` injected into every entry.

    Returns an empty list on any parse/IO error so callers don't need to
    guard against bad files.
    """
    try:
        data = json.loads(simlab_path.read_text())
    except Exception:
        return []
    out: list[dict] = []
    for s in data.get("scenarios", []):
        sc = dict(s)
        sc["source"] = "simlab"
        sc.setdefault("scenario_id", sc.get("test_id", "simlab-unknown"))
        sc.setdefault("kind", "simlab_correctness")
        sc.setdefault("ok", False)
        sc.setdefault("duration_s", 0.0)
        sc.setdefault("raw", {})
        sc.setdefault("note", "")
        sc.setdefault("criteria_results", {})
        sc.setdefault("test_id", None)
        sc.setdefault("standard_refs", [])
        out.append(sc)
    return out


def grade(pct: float) -> str:
    """Return one of A+ A B C D F per _GRADE_THRESHOLDS."""
    for threshold, label in _GRADE_THRESHOLDS:
        if pct >= threshold:
            return label
    return "F"


def risk_score(payload: AuditPayload) -> int:
    """Sum of failed_count[cat] × severity_weight[cat] across categories."""
    failed_by_cat: dict[str, int] = {}
    for s in payload.scenarios:
        if not s.get("ok", False):
            cat = _CATEGORY_MAP.get(s.get("kind", ""), "Other")
            failed_by_cat[cat] = failed_by_cat.get(cat, 0) + 1
    return sum(
        count * _CATEGORY_SEVERITY_WEIGHT.get(cat, 1)
        for cat, count in failed_by_cat.items()
    )


def classify(scenario: dict) -> tuple[str, str]:
    """Return (category, severity) for the scenario.

    severity in {"critical","high","medium","low",""} — "" when passed.
    """
    cat = _CATEGORY_MAP.get(scenario.get("kind", ""), "Other")
    if scenario.get("ok", False):
        return cat, ""
    return cat, _CAT_SEVERITY.get(cat, "low")


def _risk_color(score: int) -> str:
    if score == 0:
        return "green"
    if score <= 10:
        return "yellow"
    if score <= 30:
        return "orange"
    return "red"


def render_html(payload: AuditPayload, template_dir: Path | None = None) -> str:
    """Render the audit HTML as a single-file string (inline CSS, no
    external assets). Uses Jinja2 autoescape ON.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:
        raise ImportError(
            "jinja2 is required for HTML report generation. "
            "Install it: pip install 'jinja2>=3.1'"
        ) from exc

    if template_dir is None:
        template_dir = Path(__file__).parent / "templates"

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "j2"]),
    )

    # Load simlab scenarios if a simlab report was supplied.
    simlab_scenarios: list[dict] = []
    if payload.simlab_report is not None:
        simlab_scenarios = _load_simlab_scenarios(payload.simlab_report)

    total = len(payload.scenarios) + len(simlab_scenarios)
    passed = (
        sum(1 for s in payload.scenarios if s.get("ok", False))
        + sum(1 for s in simlab_scenarios if s.get("ok", False))
    )
    pass_pct = round((passed / total * 100) if total > 0 else 100.0, 1)
    g = grade(pass_pct)
    rs = risk_score(payload)
    rc = _risk_color(rs)

    # Annotate each stagelab scenario with category and standards info.
    annotated: list[dict] = []
    for s in payload.scenarios:
        cat, _sev = classify(s)
        test_id = s.get("test_id")
        std_ref = _standards.lookup(test_id) if test_id else None
        annotated.append({
            **s,
            "category": cat,
            "std_ref": std_ref,
            "source": s.get("source", "stagelab"),
        })

    # Annotate simlab scenarios.
    annotated_simlab: list[dict] = []
    for s in simlab_scenarios:
        test_id = s.get("test_id")
        std_ref = _standards.lookup(test_id) if test_id else None
        annotated_simlab.append({
            **s,
            "category": "Correctness (simlab)",
            "std_ref": std_ref,
            "source": "simlab",
        })

    # Group stagelab scenarios by category (preserve insertion order).
    scenarios_by_category: dict[str, list[dict]] = {}
    for s in annotated:
        cat = s["category"]
        scenarios_by_category.setdefault(cat, []).append(s)

    # Simlab gets its own category bucket, rendered separately in the template.
    if annotated_simlab:
        scenarios_by_category["Correctness (simlab)"] = annotated_simlab

    all_scenarios_combined = annotated + annotated_simlab

    tmpl = env.get_template("audit_report.html.j2")
    return tmpl.render(
        run_id=payload.run_id,
        operator=payload.operator,
        config_path=payload.config_path,
        grade=g,
        risk_score=rs,
        risk_color=rc,
        pass_pct=pass_pct,
        sut_facts=payload.sut_facts,
        setup_facts=payload.setup_facts,
        scenarios_by_category=scenarios_by_category,
        all_scenarios=all_scenarios_combined,
        recommendations=list(payload.recommendations),
    )


def render_json(payload: AuditPayload) -> str:
    """Return a JSON string with the full audit payload.

    Schema version 1. Use json.dumps(default=str) so Path/datetime objects
    serialise gracefully.

    When ``payload.simlab_report`` is set, simlab scenarios are merged into
    the top-level ``scenarios`` list with ``source: "simlab"``.  Stagelab
    scenarios carry ``source: "stagelab"``.
    """
    scenarios_out = []
    for s in payload.scenarios:
        test_id = s.get("test_id")
        std_ref = _standards.lookup(test_id) if test_id else None
        scenarios_out.append({
            "scenario_id": s.get("scenario_id", ""),
            "kind": s.get("kind", ""),
            "ok": s.get("ok", False),
            "duration_s": s.get("duration_s", 0.0),
            "test_id": test_id,
            "standard_refs": s.get("standard_refs", []),
            "criteria_results": s.get("criteria_results", {}),
            "standard": std_ref.standard if std_ref else None,
            "control": std_ref.control if std_ref else None,
            "raw": s.get("raw", {}),
            "source": s.get("source", "stagelab"),
        })

    # Merge simlab scenarios if supplied.
    if payload.simlab_report is not None:
        for s in _load_simlab_scenarios(payload.simlab_report):
            test_id = s.get("test_id")
            std_ref = _standards.lookup(test_id) if test_id else None
            scenarios_out.append({
                "scenario_id": s.get("scenario_id", ""),
                "kind": s.get("kind", ""),
                "ok": s.get("ok", False),
                "duration_s": s.get("duration_s", 0.0),
                "test_id": test_id,
                "standard_refs": s.get("standard_refs", []),
                "criteria_results": s.get("criteria_results", {}),
                "standard": std_ref.standard if std_ref else None,
                "control": std_ref.control if std_ref else None,
                "raw": s.get("raw", {}),
                "source": "simlab",
            })

    doc = {
        "schema_version": 1,
        "run_id": payload.run_id,
        "operator": payload.operator,
        "config_path": payload.config_path,
        "scenarios": scenarios_out,
        "recommendations": list(payload.recommendations),
        "sut_facts": payload.sut_facts,
        "setup_facts": payload.setup_facts,
    }
    return json.dumps(doc, indent=2, sort_keys=True, default=str)


def _render_pdf_to_file(html: str, out_path: Path) -> None:
    """Internal helper that actually writes the PDF (avoids name shadowing in write())."""
    render_pdf(html, out_path)


def render_pdf(html: str, out_path: Path) -> None:
    """Lazy-import weasyprint; writes the PDF. Raises ImportError with a
    clear message if weasyprint isn't installed.
    """
    try:
        from weasyprint import HTML as _WeasyHTML  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "weasyprint is required for PDF output. "
            "Install it: pip install 'weasyprint>=60' "
            "or install the optional extra: pip install 'shorewall-nft-stagelab[pdf]'"
        ) from exc
    _WeasyHTML(string=html).write_pdf(str(out_path))


def write(payload: AuditPayload, out_dir: Path, *, render_pdf: bool = True) -> dict:
    """Write audit.html, audit.json and (if weasyprint available + render_pdf=True)
    audit.pdf to out_dir. Returns {"html": Path, "json": Path, "pdf": Path | None}.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    html_content = render_html(payload)
    html_path = out_dir / "audit.html"
    html_path.write_text(html_content, encoding="utf-8")

    json_path = out_dir / "audit.json"
    json_path.write_text(render_json(payload), encoding="utf-8")

    pdf_path: Path | None = None
    if render_pdf:
        pdf_out = out_dir / "audit.pdf"
        try:
            _render_pdf_to_file(html_content, pdf_out)
            pdf_path = pdf_out
        except ImportError as exc:
            warnings.warn(
                f"PDF generation skipped: {exc}",
                stacklevel=2,
            )

    return {"html": html_path, "json": json_path, "pdf": pdf_path}


__all__ = [
    "AuditPayload",
    "load_runs",
    "grade",
    "risk_score",
    "classify",
    "render_html",
    "render_json",
    "render_pdf",
    "write",
    "_CATEGORY_MAP",
    "_CATEGORY_SEVERITY_WEIGHT",
    "_GRADE_THRESHOLDS",
]
