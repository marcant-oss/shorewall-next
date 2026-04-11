#!/usr/bin/env python3
"""Migration tool: verify a Shorewall config can be compiled by shorewall-nft.

Usage:
    python -m shorewall_nft.tools.migrate /etc/shorewall [--iptables dump.txt]

Steps:
1. Compile the Shorewall config with shorewall-nft
2. Validate the nft output with nft -c -f (dry-run)
3. If --iptables given: run triangle verification
4. Report any issues
"""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command()
@click.argument("config_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--iptables", type=click.Path(exists=True, path_type=Path), default=None,
              help="iptables-save dump for triangle verification.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write compiled nft script to file.")
@click.option("--dry-run", is_flag=True, help="Validate with nft -c -f.")
def migrate(config_dir: Path, iptables: Path | None, output: Path | None,
            dry_run: bool):
    """Verify and migrate a Shorewall config to shorewall-nft."""
    from shorewall_nft.compiler.ir import build_ir
    from shorewall_nft.config.parser import load_config
    from shorewall_nft.nft.emitter import emit_nft
    from shorewall_nft.nft.sets import parse_init_for_sets

    click.echo(f"Migrating {config_dir}...")
    click.echo()

    # Step 1: Parse
    click.echo("[1/4] Parsing configuration...")
    try:
        config = load_config(config_dir)
        click.echo(f"  Params: {len(config.params)}")
        click.echo(f"  Zones: {len(config.zones)}")
        click.echo(f"  Interfaces: {len(config.interfaces)}")
        click.echo(f"  Rules: {len(config.rules)}")
        click.echo(f"  Macros: {len(config.macros)}")
    except Exception as e:
        click.echo(f"  ERROR: {e}", err=True)
        sys.exit(1)

    # Step 2: Compile
    click.echo("[2/4] Compiling to nft...")
    try:
        ir = build_ir(config)
        sets = parse_init_for_sets(config_dir / "init", config_dir)
        static_nft = None
        static_path = config_dir / "static.nft"
        if static_path.exists():
            static_nft = static_path.read_text()
        script = emit_nft(ir, static_nft=static_nft, nft_sets=sets)
        total_rules = sum(len(c.rules) for c in ir.chains.values())
        click.echo(f"  Chains: {len(ir.chains)}")
        click.echo(f"  Rules: {total_rules}")
        click.echo(f"  nft lines: {len(script.splitlines())}")
    except Exception as e:
        click.echo(f"  ERROR: {e}", err=True)
        sys.exit(1)

    # Step 3: Write output
    if output:
        output.write_text(script)
        click.echo(f"  Written to {output}")

    # Step 4: Dry-run validation
    if dry_run:
        click.echo("[3/4] Validating with nft -c...")
        from shorewall_nft.nft.netlink import NftInterface
        nft = NftInterface()
        valid = nft.validate(script)
        if valid:
            click.echo("  nft syntax: VALID")
        else:
            click.echo("  nft syntax: INVALID", err=True)
            sys.exit(1)
    else:
        click.echo("[3/4] Skipped nft validation (use --dry-run)")

    # Step 5: Triangle verification
    if iptables:
        click.echo("[4/4] Triangle verification...")
        from shorewall_nft.verify.triangle import run_triangle
        report = run_triangle(
            shorewall_config_dir=config_dir,
            iptables_dump=iptables,
        )
        click.echo(f"  {report.summarize()}")
        if not report.passed:
            failing = [p for p in report.pair_reports if not p.passed]
            for p in failing[:5]:
                click.echo(f"    {p.zone_pair}: miss={len(p.missing)} extra={len(p.extra)}")
    else:
        click.echo("[4/4] Skipped verification (use --iptables)")

    click.echo()
    click.echo("Migration check complete.")


if __name__ == "__main__":
    migrate()
