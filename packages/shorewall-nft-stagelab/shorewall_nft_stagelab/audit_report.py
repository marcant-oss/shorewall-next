"""Audit report generator: consolidates stagelab run-dirs into a single HTML/PDF report."""

from __future__ import annotations

import json
import os
import warnings
from dataclasses import dataclass
from pathlib import Path

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

    sorted_dirs = sorted(run_dirs, key=lambda d: d.name)

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

    total = len(payload.scenarios)
    passed = sum(1 for s in payload.scenarios if s.get("ok", False))
    pass_pct = round((passed / total * 100) if total > 0 else 100.0, 1)
    g = grade(pass_pct)
    rs = risk_score(payload)
    rc = _risk_color(rs)

    # Annotate each scenario with category
    annotated: list[dict] = []
    for s in payload.scenarios:
        cat, _sev = classify(s)
        annotated.append({**s, "category": cat})

    # Group by category (preserve insertion order)
    scenarios_by_category: dict[str, list[dict]] = {}
    for s in annotated:
        cat = s["category"]
        scenarios_by_category.setdefault(cat, []).append(s)

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
        all_scenarios=annotated,
        recommendations=list(payload.recommendations),
    )


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
    """Write audit.html and (if weasyprint available + render_pdf=True)
    audit.pdf to out_dir. Returns {"html": Path, "pdf": Path | None}.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    html_content = render_html(payload)
    html_path = out_dir / "audit.html"
    html_path.write_text(html_content, encoding="utf-8")

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

    return {"html": html_path, "pdf": pdf_path}


__all__ = [
    "AuditPayload",
    "load_runs",
    "grade",
    "risk_score",
    "classify",
    "render_html",
    "render_pdf",
    "write",
    "_CATEGORY_MAP",
    "_CATEGORY_SEVERITY_WEIGHT",
    "_GRADE_THRESHOLDS",
]
