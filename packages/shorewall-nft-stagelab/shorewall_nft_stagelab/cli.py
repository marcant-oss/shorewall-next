"""CLI entry points: stagelab validate / run / inspect."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from pydantic import ValidationError

from . import config as _config
from . import report as _report
from . import review as _review
from .controller import StagelabController


@click.group()
def main() -> None:
    """shorewall-nft-stagelab — distributed bridge-lab for FW testing."""


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@main.command()
@click.argument("config_path", type=click.Path(exists=True, dir_okay=False))
def validate(config_path: str) -> None:
    """Load and Pydantic-validate CONFIG; exit 0 on success, 1 on error."""
    try:
        _config.load(config_path)
        click.echo("OK")
    except (ValidationError, Exception) as exc:  # noqa: BLE001
        click.echo(f"Validation error: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


@main.command("run")
@click.argument("config_path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False),
    default=None,
    help="Override report.output_dir from config.",
)
def run_cmd(config_path: str, output_dir: str | None) -> None:
    """Connect agents, execute all scenarios, write a report to OUTPUT_DIR."""
    import datetime

    async def _run() -> tuple[Path, Exception | None]:
        """Returns (run_dir, setup_error).  On setup failure a partial run.json
        is written so the audit step has something to consume."""
        cfg = _config.load(config_path)
        if output_dir is not None:
            # Override the output dir from config.
            # We do this via model_copy so the original is not mutated.
            report_spec = cfg.report.model_copy(update={"output_dir": output_dir})
            cfg = cfg.model_copy(update={"report": report_spec})

        # Warn before firing DoS-class scenarios.
        _dos_scenarios = [s for s in cfg.scenarios if s.kind.startswith("dos_")]
        if _dos_scenarios:
            from . import dos_safety
            summaries = [
                f"{s.kind} id={s.id!r} "
                f"(see run config for parameters)"
                for s in _dos_scenarios
            ]
            dos_safety.preflight_warning(summaries, countdown_s=3)

        controller = StagelabController(cfg, config_path=config_path)
        setup_error: Exception | None = None
        run: _report.RunReport | None = None
        try:
            await controller.connect()
            await controller.start_scraping()
            try:
                await controller.setup_endpoints()
            except Exception as exc:  # noqa: BLE001
                setup_error = exc
            if setup_error is None:
                try:
                    run = await controller.run_scenarios()
                finally:
                    await controller.stop_scraping()
                    await controller.teardown_endpoints()
            else:
                await controller.stop_scraping()
                # Best-effort teardown of any endpoints that did set up.
                try:
                    await controller.teardown_endpoints()
                except Exception:  # noqa: BLE001
                    pass
        finally:
            await controller.close()

        out = Path(cfg.report.output_dir)

        if run is not None:
            run_dir = _report.write(run, out)
        else:
            # Endpoint setup failed: emit a partial run with each configured
            # scenario recorded as ok=False (setup-failed) so the audit step
            # has a run_dir to consume.
            run_id = datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            setup_error_msg = str(setup_error) if setup_error else "setup failed"
            partial_scenarios = [
                _report.ScenarioResult(
                    scenario_id=sc.id,
                    kind=sc.kind,
                    ok=False,
                    duration_s=0.0,
                    raw={"setup_error": setup_error_msg},
                    criteria_results={},
                    test_id=getattr(sc, "test_id", None),
                    standard_refs=list(getattr(sc, "standard_refs", []) or []),
                )
                for sc in cfg.scenarios
            ]
            partial_run = _report.RunReport(
                run_id=run_id,
                config_path=config_path,
                scenarios=partial_scenarios,
            )
            run_dir = _report.write(partial_run, out)

        return run_dir, setup_error

    try:
        run_dir, setup_error = asyncio.run(_run())
        click.echo(str(run_dir))
        if setup_error is not None:
            # Endpoint setup failed; a partial run.json was written so the
            # audit step can still consume it.  We warn to stderr but exit 0
            # so the executor shell script adds this run_dir to the audit
            # input — the scenarios are recorded as ok=False which is the
            # correct representation of a setup-failed run.
            click.echo(f"Warning: endpoint setup failed: {setup_error}", err=True)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


@main.command()
@click.argument("report_dir", type=click.Path(exists=True, file_okay=False))
def inspect(report_dir: str) -> None:
    """Print summary.md from REPORT_DIR to stdout."""
    summary = Path(report_dir) / "summary.md"
    if not summary.exists():
        click.echo(f"Error: {summary} not found", err=True)
        sys.exit(1)
    click.echo(summary.read_text(), nl=False)


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------


@main.command()
@click.argument("report_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--output", type=click.Path(file_okay=False), default=None,
              help="Write review artifacts here (default: REPORT_DIR).")
@click.option("--open-pr", "open_pr_flag", is_flag=True, default=False,
              help="Open a PR on the remote FW-config repo (see --repo).")
@click.option("--repo", default=None,
              help="owner/name — required when --open-pr is set.")
@click.option("--branch", default=None,
              help="Branch name for the PR (default: stagelab/<run_id>).")
def review(report_dir: str, output: str | None, open_pr_flag: bool,
           repo: str | None, branch: str | None) -> None:
    """Consolidate tier-B recommendations + rule-order hints into a
    human-readable review bundle. Optionally open a PR."""
    run_dir = Path(report_dir)
    payload = _review.load_from_run_dir(run_dir)

    if not payload.tier_b_recommendations and not payload.rule_order_hints:
        click.echo("nothing to review")
        return

    out_dir = Path(output) if output else run_dir
    try:
        md_path, yaml_path = _review.write(payload, out_dir)
    except FileExistsError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(str(md_path))
    click.echo(str(yaml_path))

    if open_pr_flag:
        if not repo:
            click.echo("Error: --repo is required when --open-pr is set.", err=True)
            sys.exit(1)
        effective_branch = branch or f"stagelab/{payload.run_id}"
        try:
            url = _review.open_pr(payload, repo=repo, branch=effective_branch,
                                  body_path=md_path)
            click.echo(url)
        except Exception as exc:  # noqa: BLE001
            click.echo(f"Error opening PR: {exc}", err=True)
            sys.exit(1)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


@main.command()
@click.argument("report_dirs", nargs=-1, type=click.Path(exists=True, file_okay=False), required=True)
@click.option("--output", type=click.Path(file_okay=False), default=None,
              help="Write audit.html (+audit.pdf) here (default: first REPORT_DIR).")
@click.option("--format", "output_format", type=click.Choice(["html", "pdf", "both"]),
              default="both",
              help="Output format. Defaults to both; pdf requires weasyprint.")
@click.option("--operator", default=None,
              help="Operator name for the cover page (default: $USER).")
@click.option("--simlab-report", "simlab_report", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Path to simlab.json produced by simlab-smoketest --output-json.")
def audit(report_dirs: tuple, output: str | None, output_format: str,
          operator: str | None, simlab_report: str | None) -> None:
    """Consolidate one or more stagelab run-dirs into a signed-off audit
    report (single-file HTML + optional PDF)."""
    import os as _os

    from . import audit_report as _audit

    paths = [Path(p) for p in report_dirs]
    try:
        payload = _audit.load_runs(paths)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error loading run dirs: {exc}", err=True)
        sys.exit(1)

    simlab_path = Path(simlab_report) if simlab_report else None

    if operator:
        payload = _audit.AuditPayload(
            run_id=payload.run_id,
            operator=operator,
            config_path=payload.config_path,
            scenarios=payload.scenarios,
            recommendations=payload.recommendations,
            sut_facts=payload.sut_facts,
            setup_facts=payload.setup_facts,
            simlab_report=simlab_path,
        )
    elif not payload.operator:
        payload = _audit.AuditPayload(
            run_id=payload.run_id,
            operator=_os.environ.get("USER", "unknown"),
            config_path=payload.config_path,
            scenarios=payload.scenarios,
            recommendations=payload.recommendations,
            sut_facts=payload.sut_facts,
            setup_facts=payload.setup_facts,
            simlab_report=simlab_path,
        )
    elif simlab_path is not None:
        # operator already set by load_runs; still need to attach simlab_report
        payload = _audit.AuditPayload(
            run_id=payload.run_id,
            operator=payload.operator,
            config_path=payload.config_path,
            scenarios=payload.scenarios,
            recommendations=payload.recommendations,
            sut_facts=payload.sut_facts,
            setup_facts=payload.setup_facts,
            simlab_report=simlab_path,
        )

    out_dir = Path(output) if output else paths[0]
    render_pdf_flag = output_format in ("pdf", "both")
    try:
        written = _audit.write(payload, out_dir, render_pdf=render_pdf_flag)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(str(written["html"]))
    if written.get("json"):
        click.echo(str(written["json"]))
    if written.get("pdf"):
        click.echo(str(written["pdf"]))


__all__ = ["main"]
