"""CLI entry points: stagelab validate / run / inspect."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from pydantic import ValidationError

from . import config as _config
from . import report as _report
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

    async def _run() -> Path:
        cfg = _config.load(config_path)
        if output_dir is not None:
            # Override the output dir from config.
            # We do this via model_copy so the original is not mutated.
            report_spec = cfg.report.model_copy(update={"output_dir": output_dir})
            cfg = cfg.model_copy(update={"report": report_spec})

        controller = StagelabController(cfg, config_path=config_path)
        try:
            await controller.connect()
            run = await controller.run_scenarios()
        finally:
            await controller.close()

        out = Path(cfg.report.output_dir)
        run_dir = _report.write(run, out)
        return run_dir

    try:
        run_dir = asyncio.run(_run())
        click.echo(str(run_dir))
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


__all__ = ["main"]
