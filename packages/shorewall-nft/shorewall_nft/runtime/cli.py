"""CLI interface for shorewall-nft.

Provides Shorewall-compatible commands plus nft-native extensions.

Shorewall-compatible: start, stop, restart, reload, clear, status, check,
    compile, save, restore, show/list, dump, version, logwatch, reset,
    allow, drop, reject, logdrop, logreject, blacklist

nft-native extensions: verify, trace, counters, generate-sysctl,
    generate-systemd, generate-tc, blacklist-add, blacklist-del,
    blacklist-list
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from shorewall_nft import __version__

# Default config directory — same as Shorewall
DEFAULT_CONFIG_DIR = Path("/etc/shorewall")
MERGED_CONFIG_DIR = Path("/etc/shorewall46")


def _extract_table(ruleset_text: str, family: str, name: str) -> str | None:
    """Extract a single `table FAMILY NAME { ... }` block from
    `nft list ruleset` output.

    Returns a standalone nft script that contains just that table
    (with a leading `delete table` for atomic replacement), or None
    if the table is not present. Used by `shorewall-nft debug` to
    restore the original shorewall table without touching unrelated
    tables loaded by other services.
    """
    lines = ruleset_text.splitlines()
    start = -1
    depth = 0
    end = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if start < 0:
            if stripped.startswith(f"table {family} {name}"):
                start = i
                depth = 1 if "{" in stripped else 0
                continue
        else:
            depth += line.count("{")
            depth -= line.count("}")
            if depth == 0:
                end = i
                break
    if start < 0 or end < 0:
        return None
    body = "\n".join(lines[start:end + 1])
    return (
        f"table {family} {name}\n"
        f"delete table {family} {name}\n"
        f"{body}\n"
    )


def _get_config_dir(directory: Path | None) -> Path:
    """Resolve config directory with shorewall-next precedence rules.

    Resolution order:
      1. Explicit `directory` argument (CLI --config-dir or positional) wins.
      2. If /etc/shorewall46 exists (produced by merge-config), it is used as
         the authoritative dual-stack source. /etc/shorewall and /etc/shorewall6
         are ignored.
      3. Fall back to /etc/shorewall (legacy mode, auto-merges with shorewall6
         if present).
    """
    if directory is not None:
        return directory
    if MERGED_CONFIG_DIR.is_dir():
        return MERGED_CONFIG_DIR
    return DEFAULT_CONFIG_DIR


def _derive_v4_sibling(v6_dir: Path) -> Path | None:
    """Given a v6 directory (e.g. /etc/shorewall6), return the v4 sibling
    (e.g. /etc/shorewall) if it exists, else None."""
    name = v6_dir.name
    if name.endswith("6"):
        candidate = v6_dir.parent / name[:-1]
        if candidate.is_dir():
            return candidate
    return None


def _resolve_config_paths(
    positional: Path | None,
    config_dir: Path | None,
    config_dir4: Path | None,
    config6_dir: Path | None,
    no_auto_v4: bool,
    no_auto_v6: bool,
) -> tuple[Path, Path | None, bool]:
    """Resolve CLI config options into (primary, secondary, skip_sibling).

    primary: the Path passed as first arg to load_config
    secondary: optional config6_dir kwarg for load_config (explicit v6 dir)
    skip_sibling: if True, disable parser's v6 sibling auto-detection

    Modes supported:
      --config-dir /srv/merged
            → merged mode, single dir, no sibling merge
      --config-dir4 /srv/v4 --config6-dir /srv/v6
            → explicit dual mode
      --config-dir4 /srv/v4
            → v4 + auto-detected v6 sibling (legacy behavior)
      --config-dir4 /srv/v4 --no-auto-v6
            → v4-only, no sibling merge
      --config6-dir /srv/v6
            → v6 + auto-detected v4 sibling (symmetric)
      --config6-dir /srv/v6 --no-auto-v4
            → v6-only
      positional /srv/foo
            → equivalent to --config-dir4 /srv/foo (or --config-dir if
              the name ends in "46" — auto-detect via load_config)
      (no args)
            → /etc/shorewall46 if present, else /etc/shorewall + sibling
    """
    # Conflict checks
    if config_dir is not None and (config_dir4 is not None
                                   or config6_dir is not None):
        raise click.UsageError(
            "--config-dir is mutually exclusive with "
            "--config-dir4/--config6-dir")
    if positional is not None and (config_dir is not None
                                   or config_dir4 is not None
                                   or config6_dir is not None):
        raise click.UsageError(
            "Positional directory cannot be combined with --config-dir, "
            "--config-dir4 or --config6-dir")

    # 1. Explicit merged dir
    if config_dir is not None:
        return config_dir, None, True

    # 2. Explicit v4 + v6 (fully specified dual mode)
    if config_dir4 is not None and config6_dir is not None:
        return config_dir4, config6_dir, True

    # 3. v4 only (with optional no-auto-v6)
    if config_dir4 is not None:
        return config_dir4, None, bool(no_auto_v6)

    # 4. v6 only / v6 + auto v4 sibling
    if config6_dir is not None:
        if no_auto_v4:
            return config6_dir, None, True
        v4_sibling = _derive_v4_sibling(config6_dir)
        if v4_sibling is not None:
            return v4_sibling, config6_dir, True
        return config6_dir, None, True

    # 5. Positional arg (legacy behavior — parser auto-detects sibling)
    if positional is not None:
        return positional, None, bool(no_auto_v6)

    # 6. Defaults: prefer /etc/shorewall46, fall back to /etc/shorewall
    default = _get_config_dir(None)
    # If default is the merged dir, it implicitly has no sibling.
    # If it's the legacy /etc/shorewall, let parser auto-detect sibling
    # unless the user explicitly said --no-auto-v6.
    return default, None, bool(no_auto_v6) or default.name.endswith("46")


def config_options(f):
    """Click decorator: add config directory override options to a command.

    Adds:
      -c, --config-dir   explicit merged config directory
      --config-dir4      explicit IPv4 config directory
      --config6-dir      explicit IPv6 config directory
      --no-auto-v4       disable auto-detection of a v4 sibling
      --no-auto-v6       disable auto-detection of a v6 sibling
    """
    f = click.option("--no-auto-v6", is_flag=True, default=False,
                     help="Disable auto-detection of a v6 sibling "
                          "directory.")(f)
    f = click.option("--no-auto-v4", is_flag=True, default=False,
                     help="Disable auto-detection of a v4 sibling "
                          "directory.")(f)
    f = click.option("--config6-dir", "config6_dir",
                     type=click.Path(exists=True, file_okay=False,
                                     path_type=Path),
                     default=None,
                     help="Explicit IPv6 config directory "
                          "(use with --config-dir4 for dual mode).")(f)
    f = click.option("--config-dir4", "config_dir4",
                     type=click.Path(exists=True, file_okay=False,
                                     path_type=Path),
                     default=None,
                     help="Explicit IPv4 config directory.")(f)
    f = click.option("-c", "--config-dir", "config_dir",
                     type=click.Path(exists=True, file_okay=False,
                                     path_type=Path),
                     default=None,
                     help="Explicit merged config directory "
                          "(overrides /etc/shorewall46 default).")(f)
    return f


# ──────────────────────────────────────────────────────────────────────
# Start-command progress reporter
# ──────────────────────────────────────────────────────────────────────

import contextlib


class _Step:
    """Detail / warning collector yielded inside a :class:`_Progress` step."""

    def __init__(self) -> None:
        self._detail: list[str] = []
        self._warnings: list[str] = []

    def info(self, msg: str) -> None:
        self._detail.append(msg)

    def warn(self, msg: str) -> None:
        self._warnings.append(msg)

    @property
    def has_warnings(self) -> bool:
        return bool(self._warnings)

    def _detail_str(self) -> str:
        return ", ".join(self._detail)


class _Progress:
    """Step-by-step progress for interactive terminals and journal output.

    TTY: inline overwrite  ``  … label`` → ``  ✓ label  (detail)``
    with ANSI colour via :func:`click.style`.

    Non-TTY (journal, pipe): one plain text line per step, no \\\\r, no
    ANSI — clean for ``journalctl`` and log files.
    """

    def __init__(self) -> None:
        self._tty = sys.stdout.isatty()

    def header(self, msg: str) -> None:
        if self._tty:
            click.secho(msg, bold=True)
        else:
            click.echo(msg)

    @contextlib.contextmanager
    def step(self, label: str):
        s = _Step()
        if self._tty:
            sys.stdout.write(f"  \033[2m\u2026\033[0m {label}")
            sys.stdout.flush()
        try:
            yield s
        except Exception as exc:
            detail = s._detail_str()
            suffix = f"  ({detail})" if detail else ""
            err_msg = str(exc)
            if self._tty:
                marker = click.style("\u2717", fg="red", bold=True)
                sys.stdout.write(
                    f"\r  {marker} {label}{suffix}"
                    + (f"\n    {err_msg}" if err_msg else "") + "\n")
                sys.stdout.flush()
            else:
                click.echo(f"  \u2717 {label}{suffix}"
                           + (f": {err_msg}" if err_msg else ""))
            raise
        else:
            detail = s._detail_str()
            suffix = f"  ({detail})" if detail else ""
            if s.has_warnings:
                if self._tty:
                    marker = click.style("\u26a0", fg="yellow", bold=True)
                    sys.stdout.write(f"\r  {marker} {label}{suffix}\n")
                    sys.stdout.flush()
                    for w in s._warnings:
                        click.secho(f"    \u26a0  {w}", fg="yellow")
                else:
                    click.echo(f"  \u26a0 {label}{suffix}")
                    for w in s._warnings:
                        click.echo(f"    warn: {w}")
            else:
                if self._tty:
                    marker = click.style("\u2713", fg="green", bold=True)
                    sys.stdout.write(f"\r  {marker} {label}{suffix}\n")
                    sys.stdout.flush()
                else:
                    click.echo(f"  \u2713 {label}{suffix}")

    def done(self, msg: str) -> None:
        if self._tty:
            click.secho(msg, fg="green", bold=True)
        else:
            click.echo(msg)


# ──────────────────────────────────────────────────────────────────────


def _check_loaded_hash(config_dir: Path, netns: str | None) -> tuple[str, str | None]:
    """Compare the hash of the on-disk config vs the loaded ruleset.

    Returns (source_hash, loaded_hash_or_None). ``loaded_hash_or_None``
    is None when no ruleset is loaded or no hash marker is found.
    Uses :meth:`NftInterface.run_in_netns` — enters the namespace via
    in-process ``setns()`` on root, falls back to sudo run-netns otherwise.
    """
    from shorewall_nft.config.hash import compute_config_hash, extract_hash_from_ruleset
    from shorewall_nft.nft.netlink import NftInterface

    source_hash = compute_config_hash(config_dir)
    nft = NftInterface()
    try:
        r = nft.run_in_netns(
            [nft._nft_bin, "list", "table", "inet", "shorewall"],
            netns=netns, capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return source_hash, None
        loaded_hash = extract_hash_from_ruleset(r.stdout)
        return source_hash, loaded_hash
    except Exception:
        return source_hash, None


def _compile(config_dir: Path, config6_dir: Path | None = None,
             debug: bool = False,
             skip_sibling_merge: bool = False,
             override: dict | None = None):
    """Compile helper — returns (ir, script, sets).

    ``override`` is a structured JSON blob (see
    ``docs/cli/override-json.md``) applied on top of the parsed
    config via :func:`shorewall_nft.config.importer.apply_overlay`.
    Load order is *defaults → on-disk → override*, so the overlay
    always wins on collisions.
    """
    from shorewall_nft.compiler.ir import build_ir
    from shorewall_nft.config.hash import compute_config_hash
    from shorewall_nft.config.parser import load_config
    from shorewall_nft.nft.emitter import emit_nft

    config = load_config(config_dir, config6_dir=config6_dir,
                         skip_sibling_merge=skip_sibling_merge)
    if override:
        from shorewall_nft.config.importer import apply_overlay
        apply_overlay(config, override)
    ir = build_ir(config)
    static_nft = _load_static_nft(config_dir)
    nft_sets = _load_sets(config_dir)
    config_hash = compute_config_hash(config_dir)
    script = emit_nft(ir, static_nft=static_nft, nft_sets=nft_sets,
                      debug=debug, config_hash=config_hash)
    return ir, script, nft_sets


def _compile_from_cli(directory, config_dir, config_dir4, config6_dir,
                      no_auto_v4, no_auto_v6, debug=False,
                      override=None):
    """Helper for commands using @config_options + positional directory.

    Resolves the CLI flags to (primary, secondary, skip) and calls _compile.
    """
    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    if override is None:
        # Pick up the ctx-stashed overlay if a subcommand caller
        # didn't explicitly pass one.
        try:
            override = click.get_current_context().obj.get(
                "override_json")
        except Exception:
            override = None
    return _compile(primary, config6_dir=secondary,
                    skip_sibling_merge=skip, debug=debug,
                    override=override), (primary, secondary, skip)


def _load_override_arg(arg: str) -> dict:
    """Read a --override-json argument.

    Accepts a literal JSON string, ``@path`` (reads from file), or
    ``-`` (reads from stdin). File extension may be ``.yaml`` for
    YAML, default is JSON.
    """
    import json as _json
    if arg == "-":
        text = sys.stdin.read()
        suffix = ""
    elif arg.startswith("@"):
        p = Path(arg[1:])
        text = p.read_text()
        suffix = p.suffix
    else:
        text = arg
        suffix = ""
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            raise click.ClickException(
                "--override-json YAML requested but PyYAML not installed")
        return yaml.safe_load(text)
    return _json.loads(text)


@click.group()
@click.version_option(version=__version__)
@click.option("-q", is_flag=True, help="Quiet mode.")
@click.option("-v", "verbose", count=True, help="Verbose mode (-v, -vv).")
@click.option(
    "--override-json", "override_json", default=None,
    metavar="JSON_OR_@FILE",
    help="Structured JSON merged over every parsed config file at "
         "runtime. Accepts a literal JSON string, ``@path`` (reads a "
         "JSON/YAML file; YAML auto-detected by .yaml/.yml extension), "
         "or ``-`` (reads from stdin). See docs/cli/override-json.md.")
@click.option(
    "--override", "override_per_file", multiple=True,
    metavar="FILE=JSON_OR_@FILE",
    help="Per-file overlay entry, repeatable. "
         "``--override rules=@extra.json`` merges the JSON in "
         "extra.json under the ``rules`` top-level key. Mergeable "
         "with --override-json (later wins on collision).")
@click.pass_context
def cli(ctx, q, verbose, override_json, override_per_file):
    """shorewall-nft: nftables-native firewall compiler."""
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = q
    ctx.obj["verbose"] = verbose

    # Assemble the effective overlay: --override-json first, then
    # each --override FILE=JSON layered on top in argv order.
    overlay: dict = {}
    if override_json:
        try:
            overlay.update(_load_override_arg(override_json))
        except Exception as e:
            raise click.ClickException(
                f"failed to parse --override-json: {e}")
    for entry in override_per_file:
        if "=" not in entry:
            raise click.ClickException(
                f"--override must be of the form FILE=JSON: {entry!r}")
        file, _, value = entry.partition("=")
        try:
            overlay[file] = _load_override_arg(value)
        except Exception as e:
            raise click.ClickException(
                f"failed to parse --override {file}=...: {e}")
    ctx.obj["override_json"] = overlay or None


# ──────────────────────────────────────────────────────────────────────
# Shorewall-compatible commands
# ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Apply in network namespace.")
@config_options
def start(directory, netns, config_dir, config_dir4, config6_dir,
          no_auto_v4, no_auto_v6):
    """Compile and apply firewall rules (like shorewall start)."""
    prog = _Progress()
    prog.header("Starting shorewall-nft\u2026")

    # ── Step 1: parse + compile ───────────────────────────────────────
    with prog.step("Parsing and compiling config") as s:
        (ir, script, _), _ = _compile_from_cli(
            directory, config_dir, config_dir4, config6_dir,
            no_auto_v4, no_auto_v6)
        n_rules = sum(len(c.rules) for c in ir.chains.values())
        s.info(f"{len(ir.chains)} chains, {n_rules} rules")

    # ── Step 2: capability probe — non-fatal ─────────────────────────
    # Probing failures or missing capabilities produce warnings, not
    # hard errors.  The actual kernel verdict comes in step 3 when the
    # ruleset is loaded: if nft rejects it, *that* is the hard failure.
    nft_iface = None
    with prog.step("Probing kernel capabilities") as s:
        try:
            from shorewall_nft.compiler.capability_check import (
                check_capabilities, format_errors)
            from shorewall_nft.nft.capabilities import NftCapabilities
            from shorewall_nft.nft.netlink import NftInterface
            nft_iface = NftInterface()
            caps = NftCapabilities.probe(netns=netns, nft=nft_iface)
            n_ok = sum(1 for a in dir(caps)
                       if a.startswith("has_") and getattr(caps, a))
            cap_errors = check_capabilities(ir, caps)
            if cap_errors:
                s.info(f"{n_ok} ok, {len(cap_errors)} warning(s)")
                for line in format_errors(cap_errors).splitlines():
                    if line.strip():
                        s.warn(line)
            else:
                s.info(f"{n_ok} available")
        except Exception as exc:
            s.warn(f"probe failed ({exc}) — attempting load anyway")

    # ── Step 3: apply ruleset — this is the real gate ─────────────────
    with prog.step("Applying ruleset") as s:
        from shorewall_nft.netns.apply import apply_nft
        apply_nft(script, netns=netns)
        s.info(f"{len(ir.chains)} chains")

    # ── Step 4: proxy-ARP / NDP ───────────────────────────────────────
    with prog.step("Proxy-ARP / NDP") as s:
        try:
            from shorewall_nft.compiler.proxyarp import (
                apply_proxyarp, parse_proxyarp)
            from shorewall_nft.config.parser import load_config
            primary, secondary, skip = _resolve_config_paths(
                directory, config_dir, config_dir4, config6_dir,
                no_auto_v4, no_auto_v6)
            cfg = load_config(primary, config6_dir=secondary,
                              skip_sibling_merge=skip)
            proxy_entries = (
                parse_proxyarp(getattr(cfg, "proxyarp", []) or []) +
                parse_proxyarp(getattr(cfg, "proxyndp", []) or []))
            if proxy_entries:
                applied, skipped, errs = apply_proxyarp(
                    proxy_entries, netns=netns)
                s.info(f"{applied} applied"
                       + (f", {skipped} skipped" if skipped else ""))
                for e in errs:
                    s.warn(e)
            else:
                s.info("none configured")
        except Exception as exc:
            s.warn(f"skipped ({exc})")

    # ── Step 5: tear down leftover shorewall_stopped table ────────────
    with prog.step("Cleanup") as s:
        try:
            from shorewall_nft.nft.netlink import NftError, NftInterface
            if nft_iface is None:
                nft_iface = NftInterface()
            try:
                nft_iface.cmd(
                    "delete table inet shorewall_stopped", netns=netns)
                s.info("stopped table removed")
            except NftError:
                s.info("nothing to clean")
        except Exception:
            s.info("nothing to clean")

    prog.done(f"Shorewall-nft started.")


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Target network namespace.")
@config_options
def stop(directory, netns, config_dir, config_dir4, config6_dir,
         no_auto_v4, no_auto_v6):
    """Stop the firewall.

    Removes the running ``inet shorewall`` table. If the configuration
    contains a ``routestopped`` file, the compiled
    ``inet shorewall_stopped`` table is loaded so the listed
    (interface, host) pairs remain reachable while the firewall is down.
    Without ``routestopped`` the kernel falls back to its default
    (typically wide-open) policy — same behaviour as before.
    """
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()

    # Try to compile so we can load shorewall_stopped if defined.
    # Compile failures must not block the stop — fall through to the
    # plain `delete table inet shorewall` path.
    stopped_script: str | None = None
    try:
        (ir, _script, _sets), _paths = _compile_from_cli(
            directory, config_dir, config_dir4, config6_dir,
            no_auto_v4, no_auto_v6)
        from shorewall_nft.nft.emitter import emit_stopped_nft
        s = emit_stopped_nft(ir)
        if s.strip():
            stopped_script = s
    except Exception as e:
        click.echo(f"Note: stopped-table compile failed ({e}); "
                   "falling back to plain delete.", err=True)

    def _run(cmd_str: str) -> None:
        nft.cmd(cmd_str, netns=netns)

    # Best-effort delete of the running table.
    try:
        _run("delete table inet shorewall")
    except (NftError, Exception) as e:
        click.echo(f"Note: {e}", err=True)

    if stopped_script is not None:
        from shorewall_nft.netns.apply import apply_nft
        try:
            apply_nft(stopped_script, netns=netns)
            click.echo("Shorewall-nft stopped (routestopped table loaded).")
        except Exception as e:
            click.echo(f"Note: failed to load shorewall_stopped: {e}",
                       err=True)

    # Remove non-persistent proxy ARP/NDP entries via pyroute2.
    try:
        from shorewall_nft.compiler.proxyarp import (
            parse_proxyarp,
            remove_proxyarp,
        )
        from shorewall_nft.config.parser import load_config
        primary, secondary, skip = _resolve_config_paths(
            directory, config_dir, config_dir4, config6_dir,
            no_auto_v4, no_auto_v6)
        cfg = load_config(primary, config6_dir=secondary,
                          skip_sibling_merge=skip)
        proxy_entries = (
            parse_proxyarp(getattr(cfg, "proxyarp", []) or []) +
            parse_proxyarp(getattr(cfg, "proxyndp", []) or []))
        if proxy_entries:
            n = remove_proxyarp(proxy_entries, netns=netns)
            if n:
                click.echo(f"proxy-arp/ndp: {n} entries removed")
    except Exception as e:
        click.echo(f"proxy-arp/ndp removal: skipped ({e})", err=True)

    if stopped_script is None:
        click.echo("Shorewall-nft stopped.")


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Target network namespace.")
@config_options
def restart(directory, netns, config_dir, config_dir4, config6_dir,
            no_auto_v4, no_auto_v6):
    """Recompile and atomically replace the ruleset."""
    (ir, script, _), _ = _compile_from_cli(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    from shorewall_nft.netns.apply import apply_nft
    apply_nft(script, netns=netns)
    click.echo(f"Shorewall-nft restarted ({len(ir.chains)} chains).")


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Target network namespace.")
@config_options
def reload(directory, netns, config_dir, config_dir4, config6_dir,
           no_auto_v4, no_auto_v6):
    """Reload rules (same as restart for nft — atomic replace)."""
    (ir, script, _), _ = _compile_from_cli(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    from shorewall_nft.netns.apply import apply_nft
    apply_nft(script, netns=netns)
    click.echo(f"Shorewall-nft reloaded ({len(ir.chains)} chains).")


@cli.command()
@click.option("--netns", type=str, default=None, help="Target network namespace.")
def clear(netns: str | None):
    """Clear all firewall rules (accept all traffic)."""
    # In nft: delete table then create empty with accept policies
    clear_script = """
table inet shorewall
delete table inet shorewall
table inet shorewall {
    chain input { type filter hook input priority 0; policy accept; }
    chain forward { type filter hook forward priority 0; policy accept; }
    chain output { type filter hook output priority 0; policy accept; }
}
"""
    from shorewall_nft.netns.apply import apply_nft
    apply_nft(clear_script.strip(), netns=netns)
    click.echo("Shorewall-nft cleared (all traffic accepted).")


@cli.command()
@click.option("--netns", type=str, default=None, help="Target network namespace.")
def status(netns: str | None):
    """Show firewall status."""
    from shorewall_nft.nft.netlink import NftInterface
    nft = NftInterface()

    result = nft.run_in_netns(
        [nft._nft_bin, "list", "table", "inet", "shorewall"],
        netns=netns, capture_output=True, text=True)
    if result.returncode == 0:
        click.echo("Shorewall-nft is running.")
        # Count chains and rules
        lines = result.stdout.splitlines()
        chains = sum(1 for l in lines if l.strip().startswith("chain "))
        rules = sum(1 for l in lines if l.strip() and not l.strip().startswith(("chain ", "table ", "type ", "}", "{", "#", "set ", "flags ", "elements ", "priority")))
        click.echo(f"  Chains: {chains}")
        click.echo(f"  Rules: ~{rules}")

        # Hash drift detection
        from shorewall_nft.config.hash import extract_hash_from_ruleset
        loaded_hash = extract_hash_from_ruleset(result.stdout)
        if loaded_hash:
            try:
                source_hash, _ = _check_loaded_hash(
                    _get_config_dir(None), netns)
                if loaded_hash == source_hash:
                    click.echo(f"  Config hash: {loaded_hash} (matches source)")
                else:
                    click.secho(
                        f"  Config hash: {loaded_hash} (loaded)",
                        fg="yellow")
                    click.secho(
                        f"               {source_hash} (on-disk) — DRIFT!",
                        fg="yellow", bold=True)
                    click.secho(
                        "  WARNING: loaded ruleset differs from on-disk "
                        "config. Run `shorewall-nft reload` to sync.",
                        fg="yellow")
            except Exception:
                pass
        # Debug marker
        if "debug" in result.stdout[:500]:
            import re as _re
            if _re.search(r'config-hash:\S+\s+debug', result.stdout):
                click.secho(
                    "  DEBUG MODE ACTIVE — this is not a production ruleset.",
                    fg="magenta", bold=True)
    else:
        click.echo("Shorewall-nft is stopped.", err=True)
        sys.exit(1)


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--skip-caps", is_flag=True, help="Skip capability check.")
@config_options
def check(directory, skip_caps, config_dir, config_dir4, config6_dir,
          no_auto_v4, no_auto_v6):
    """Validate config without applying (like shorewall check)."""
    try:
        (ir, script, _), _ = _compile_from_cli(
            directory, config_dir, config_dir4, config6_dir,
            no_auto_v4, no_auto_v6)
        click.echo(f"Configuration compiled ({len(ir.chains)} chains).")

        if not skip_caps:
            from shorewall_nft.compiler.capability_check import check_capabilities, format_errors
            from shorewall_nft.nft.capabilities import NftCapabilities

            click.echo("Checking kernel capabilities...")
            caps = NftCapabilities.probe()
            errors = check_capabilities(ir, caps)
            if errors:
                click.echo(format_errors(errors), err=True)
                sys.exit(1)
            else:
                click.echo(f"All {len([a for a in dir(caps) if a.startswith('has_') and getattr(caps, a)])} required capabilities available.")
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file.")
@config_options
def compile(directory, output, config_dir, config_dir4, config6_dir,
            no_auto_v4, no_auto_v6):
    """Compile config to nft script (like shorewall compile)."""
    (_, script, _), _ = _compile_from_cli(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    if output:
        output.write_text(script)
        click.echo(f"Compiled to {output}")
    else:
        click.echo(script)


@cli.command()
@click.option("-C", is_flag=True, help="Include counters.")
@click.option("--netns", type=str, default=None, help="Target network namespace.")
@click.argument("filename", required=False)
def save(c, netns: str | None, filename: str | None):
    """Save current ruleset (like shorewall save)."""
    from shorewall_nft.nft.netlink import NftInterface
    nft = NftInterface()

    result = nft.run_in_netns(
        [nft._nft_bin, "list", "ruleset"],
        netns=netns, capture_output=True, text=True)
    if result.returncode != 0:
        click.echo("ERROR: No ruleset to save.", err=True)
        sys.exit(1)

    if filename:
        Path(filename).write_text(result.stdout)
        click.echo(f"Ruleset saved to {filename}")
    else:
        click.echo(result.stdout)


@cli.command()
@click.option("--netns", type=str, default=None, help="Target network namespace.")
@click.argument("filename", type=click.Path(exists=True, path_type=Path))
def restore(netns: str | None, filename: Path):
    """Restore a saved ruleset (like shorewall restore)."""
    from shorewall_nft.netns.apply import apply_nft
    script = filename.read_text()
    apply_nft(script, netns=netns)
    click.echo(f"Ruleset restored from {filename}")


@cli.command()
@click.option("-x", is_flag=True, help="Show exact counters.")
@click.option("--netns", type=str, default=None, help="Target network namespace.")
@click.argument("what", required=False)
def show(x, netns: str | None, what: str | None):
    """Show firewall info (like shorewall show). Subcommands: zones, policies, config, connections."""
    from shorewall_nft.nft.netlink import NftInterface
    nft = NftInterface()

    if what in ("zones", "connections"):
        args = [nft._nft_bin, "list", "table", "inet", "shorewall"]
    elif what == "counters":
        args = [nft._nft_bin, "list", "counters", "table", "inet", "shorewall"]
    elif what == "sets":
        args = [nft._nft_bin, "list", "sets", "table", "inet", "shorewall"]
    else:
        args = [nft._nft_bin, "list", "ruleset"]

    result = nft.run_in_netns(args, netns=netns, capture_output=True, text=True)
    click.echo(result.stdout if result.returncode == 0 else "No rules loaded.")


# Aliases
cli.add_command(show, "list")
cli.add_command(show, "ls")
cli.add_command(show, "dump")


@cli.command()
@click.option("--netns", type=str, default=None, help="Target network namespace.")
@click.argument("chains", nargs=-1)
def reset(netns: str | None, chains: tuple[str]):
    """Reset counters (like shorewall reset)."""
    from shorewall_nft.nft.netlink import NftInterface
    nft = NftInterface()

    result = nft.run_in_netns(
        [nft._nft_bin, "reset", "counters", "table", "inet", "shorewall"],
        netns=netns, capture_output=True, text=True)
    click.echo("Counters reset." if result.returncode == 0 else f"Error: {result.stderr}")


# ──────────────────────────────────────────────────────────────────────
# Dynamic blacklist commands (Shorewall-compatible + extensions)
# ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("addresses", nargs=-1, required=True)
@click.option("--netns", type=str, default=None)
def drop(addresses: tuple[str], netns: str | None):
    """Dynamically drop traffic from addresses (like shorewall drop)."""
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    for addr in addresses:
        try:
            nft.add_set_element("dynamic_blacklist", addr, timeout="0s", netns=netns)
            click.echo(f"Dropping {addr}")
        except NftError as e:
            click.echo(f"Error: {e}", err=True)


@cli.command()
@click.argument("addresses", nargs=-1, required=True)
@click.option("--netns", type=str, default=None)
def allow(addresses: tuple[str], netns: str | None):
    """Remove addresses from the blacklist (like shorewall allow)."""
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    for addr in addresses:
        try:
            nft.delete_set_element("dynamic_blacklist", addr, netns=netns)
            click.echo(f"Allowed {addr}")
        except NftError as e:
            click.echo(f"Error: {e}", err=True)


@cli.command()
@click.argument("addresses", nargs=-1, required=True)
@click.option("--netns", type=str, default=None)
def reject(addresses: tuple[str], netns: str | None):
    """Dynamically reject traffic from addresses (like shorewall reject)."""
    # In nft, we use the same blacklist set — reject vs drop distinction
    # would require a separate set. For now, treat same as drop.
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    for addr in addresses:
        try:
            nft.add_set_element("dynamic_blacklist", addr, timeout="0s", netns=netns)
            click.echo(f"Rejecting {addr}")
        except NftError as e:
            click.echo(f"Error: {e}", err=True)


@cli.command()
@click.argument("address")
@click.option("-t", "--timeout", default="1h", help="Timeout (e.g. 1h, 30m, 1d).")
@click.option("--netns", type=str, default=None)
def blacklist(address: str, timeout: str, netns: str | None):
    """Add address to dynamic blacklist with timeout (like shorewall blacklist)."""
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    try:
        nft.add_set_element("dynamic_blacklist", address, timeout=timeout, netns=netns)
        click.echo(f"Blacklisted {address} (timeout: {timeout})")
    except NftError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────
# nft-native extensions
# ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--iptables", type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to iptables-save dump (ground truth).")
@config_options
def verify(directory, iptables, config_dir, config_dir4, config6_dir,
           no_auto_v4, no_auto_v6):
    """Verify compiled output against iptables baseline."""
    primary, secondary, _ = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    config_dir = primary
    from shorewall_nft.verify.triangle import run_triangle

    if secondary is not None:
        config6_dir = secondary
    else:
        config6 = config_dir.parent / (config_dir.name + "6")
        config6_dir = config6 if config6.is_dir() else None

    # IPv4 verification
    report = run_triangle(
        shorewall_config_dir=config_dir,
        iptables_dump=iptables,
        config6_dir=config6_dir,
        family=4,
    )
    click.echo(f"IPv4: {report.summarize()}")

    # IPv6 verification (auto-detect ip6tables dump). For a merged
    # shorewall46 config, there is no separate config6_dir — the v6
    # rules live in the same directory and are tagged via ?FAMILY.
    ip6_dump = iptables.parent / iptables.name.replace("iptables", "ip6tables")
    if ip6_dump.exists():
        report6 = run_triangle(
            shorewall_config_dir=config_dir,
            iptables_dump=iptables,
            ip6tables_dump=ip6_dump,
            config6_dir=config6_dir,
            family=6,
        )
        click.echo(f"IPv6: {report6.summarize()}")
    if not report.passed:
        failing = [pr for pr in report.pair_reports if not pr.passed]
        for pr in failing[:20]:
            click.echo(f"  {pr.zone_pair}: ok={pr.ok} missing={len(pr.missing)} extra={len(pr.extra)} order={len(pr.order_conflicts)}")
        if report.order_conflicts > 0:
            click.echo(f"\nWARNING: {report.order_conflicts} rule ordering conflicts!")

    sys.exit(0 if report.passed else 1)


@cli.command()
@click.option("--netns", type=str, default=None, help="Trace in network namespace.")
def trace(netns: str | None):
    """Start live packet tracing (nft monitor trace)."""
    from shorewall_nft.runtime.monitor import trace_start
    trace_start(netns=netns)


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False,
                                             path_type=Path), required=False)
@click.option("--netns", type=str, default=None,
              help="Target network namespace.")
@click.option("--no-restore", is_flag=True,
              help="Do not restore the original ruleset on exit.")
@click.option("--trace", "trace_filter", type=str, default=None,
              metavar="NFT_MATCH",
              help="Auto-install a `meta nftrace set 1` rule in the input "
                   "chain for the given nft match (e.g. 'ip saddr 1.2.3.4' "
                   "or 'meta l4proto icmp'). Removed on exit.")
@config_options
def debug(directory, netns, no_restore, trace_filter,
          config_dir, config_dir4, config6_dir,
          no_auto_v4, no_auto_v6):
    """Temporarily load a debug-annotated ruleset.

    Compiles the given config (or the default config dir) with debug mode
    enabled. Every rule gets a named counter and a source-location comment.
    The current ruleset is saved, the debug ruleset is loaded, and a short
    help is printed. Press Ctrl+C to restore the original ruleset.

    Use `nft list counters table inet shorewall` to see per-rule hits, or
    `nft monitor trace` (after inserting a `meta nftrace set 1` rule, or
    automatically via `--trace MATCH`) to see the source reference in the
    trace output as a rule comment.
    """
    import signal
    import subprocess
    import sys
    import tempfile

    from shorewall_nft.netns.apply import apply_nft
    from shorewall_nft.nft.netlink import NftInterface

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    config_dir = primary

    # Step 0: Hash drift check. If a production ruleset is loaded AND
    # its hash doesn't match the on-disk config, this debug session would
    # replace a DIFFERENT ruleset than what the user expects. Require
    # explicit confirmation.
    source_hash, loaded_hash = _check_loaded_hash(config_dir, netns)
    if loaded_hash is not None and loaded_hash != source_hash:
        click.secho("\n── WARNING: Config drift detected ──",
                    fg="yellow", bold=True)
        click.echo(f"  Loaded ruleset hash:  {loaded_hash}")
        click.echo(f"  On-disk config hash:  {source_hash}")
        click.echo("")
        click.echo(
            "The currently loaded ruleset was compiled from a DIFFERENT")
        click.echo(
            "config than the one on disk. Entering debug mode will")
        click.echo(
            "RELOAD the firewall with the current on-disk config, which")
        click.echo(
            "may change production behavior until you exit debug mode.")
        click.echo("")
        if not click.confirm(
                "Do you want to proceed and reload with debug annotations?",
                default=False):
            click.echo("Aborted.")
            sys.exit(1)

    # Step 1: save the current ruleset
    nft = NftInterface()
    result = nft.run_in_netns(
        [nft._nft_bin, "list", "ruleset"],
        netns=netns, capture_output=True, text=True)
    saved_path: Path | None = None
    if result.returncode == 0 and result.stdout.strip():
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".nft", delete=False,
            prefix="shorewall-next-sim-debug-saved-")
        tmp.write(result.stdout)
        tmp.close()
        saved_path = Path(tmp.name)
        click.echo(f"Saved current ruleset to {saved_path}")
    else:
        click.echo("(no existing ruleset to save)")

    # Step 2: compile with debug=True (uses _compile helper which adds
    # the config hash automatically)
    _, script, _ = _compile(config_dir, config6_dir=secondary,
                            skip_sibling_merge=skip, debug=True)

    debug_path = Path(tempfile.mkstemp(
        suffix=".nft", prefix="shorewall-next-sim-debug-")[1])
    debug_path.write_text(script)

    # Step 3: load the debug ruleset
    click.echo(f"Loading debug ruleset from {debug_path}")
    try:
        apply_nft(script, netns=netns)
    except Exception as e:
        click.echo(f"ERROR loading debug ruleset: {e}", err=True)
        if saved_path:
            click.echo(f"Saved original is at {saved_path}")
        sys.exit(1)

    # Step 3b: optional auto-install trace filter
    if trace_filter:
        # Inserts `<FILTER> meta nftrace set 1` as the first rule in the
        # input chain. The rule is removed on exit (see _restore_and_exit).
        try:
            nft.cmd(
                f"insert rule inet shorewall input "
                f"{trace_filter} meta nftrace set 1",
                netns=netns)
            click.echo(f"Trace filter active: {trace_filter}")
        except Exception as exc:
            click.echo(f"WARNING: --trace filter install failed: {exc}",
                       err=True)
            trace_filter = None  # don't try to remove later

    # Step 4: print instructions
    ns_prefix = (f"sudo /usr/local/bin/run-netns exec {netns} "
                 if netns else "")
    click.secho("\n── Debug mode active ──", fg="cyan", bold=True)
    click.echo("Every rule has a named counter and source-location comment.")
    click.echo("")
    click.echo("Useful commands:")
    click.echo(f"  {ns_prefix}nft list counters table inet shorewall")
    click.echo(f"  {ns_prefix}nft list counter inet shorewall r_<chain>_<idx>")
    click.echo(f"  {ns_prefix}nft monitor trace")
    if not trace_filter:
        click.echo("  # To enable trace for specific traffic:")
        click.echo(f"  {ns_prefix}nft insert rule inet shorewall input "
                   f"ip saddr <IP> meta nftrace set 1")
        click.echo("  # ... or use --trace 'ip saddr 1.2.3.4' on debug.")
    click.echo("")
    if no_restore:
        click.echo("--no-restore: Ctrl+C will NOT restore the ruleset.")
    else:
        click.echo("Press Ctrl+C to restore the original ruleset.")

    # Step 5: wait for Ctrl+C
    def _restore_and_exit(*_):
        click.echo("\n── Restoring original ruleset ──")
        if no_restore:
            click.echo(f"(skipped — ruleset kept at {debug_path})")
            sys.exit(0)
        try:
            # Drop ONLY the debug `inet shorewall` table. Do NOT flush
            # the entire ruleset — that would also remove unrelated
            # tables (docker, fail2ban, libvirt, ...) that we never
            # touched and have no business restoring.
            #
            # The saved file contains `table inet shorewall { ... }`
            # blocks that will be re-added by apply_nft. If the saved
            # ruleset had additional tables, they weren't changed by
            # debug mode, so they're already correct and don't need
            # re-loading.
            try:
                nft.cmd("delete table inet shorewall", netns=netns)
            except Exception:
                pass

            if saved_path and saved_path.exists():
                saved_text = saved_path.read_text()
                # Only reapply the shorewall table section of the save
                # to avoid accidentally overwriting live state in other
                # tables that may have changed during the debug session
                # (e.g. docker adding new chains).
                shorewall_only = _extract_table(
                    saved_text, "inet", "shorewall")
                if shorewall_only:
                    apply_nft(shorewall_only, netns=netns)
                    click.echo("Restored.")
                else:
                    click.echo("(saved ruleset had no shorewall table; "
                               "left state untouched)")
            else:
                click.echo("(no saved ruleset — shorewall table removed)")
        except Exception as e:
            click.echo(f"ERROR restoring: {e}", err=True)
            if saved_path:
                click.echo(f"Saved ruleset is at {saved_path}")
            sys.exit(1)
        sys.exit(0)

    signal.signal(signal.SIGINT, _restore_and_exit)
    signal.signal(signal.SIGTERM, _restore_and_exit)

    # Idle loop
    try:
        signal.pause()
    except KeyboardInterrupt:
        _restore_and_exit()


@cli.command()
@click.option("--netns", type=str, default=None)
def counters(netns: str | None):
    """List all counter values (packets/bytes)."""
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    try:
        ctrs = nft.list_counters(netns=netns)
        if ctrs:
            for name, vals in sorted(ctrs.items()):
                click.echo(f"{name}: packets={vals['packets']} bytes={vals['bytes']}")
        else:
            click.echo("No counters found.")
    except NftError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--iptables", type=click.Path(exists=True, path_type=Path), default=None,
              help="iptables-save dump for verification.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
@click.option("--dry-run", is_flag=True, help="Validate with nft -c.")
@config_options
def migrate(directory, iptables, output, dry_run,
            config_dir, config_dir4, config6_dir, no_auto_v4, no_auto_v6):
    """Verify migration from Shorewall to shorewall-nft."""
    from shorewall_nft.tools.migrate import migrate as run_migrate
    primary, _, _ = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    ctx = click.Context(run_migrate)
    ctx.invoke(run_migrate, config_dir=primary,
               iptables=iptables, output=output, dry_run=dry_run)


@cli.command("load-sets")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Target network namespace.")
@click.option("--geoip-dir", type=click.Path(exists=True, path_type=Path), default=None,
              help="GeoIP prefix directory.")
@config_options
def load_sets(directory, netns, geoip_dir,
              config_dir, config_dir4, config6_dir, no_auto_v4, no_auto_v6):
    """Load external sets (ipsets, GeoIP) into nft after apply."""
    from shorewall_nft.nft.set_loader import SetLoader

    primary, _, _ = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    config_dir = primary
    loader = SetLoader(netns=netns)

    # Load sets from init script
    init_path = config_dir / "init"
    if init_path.exists():
        results = loader.load_from_init(init_path, config_dir)
        for name, count in results.items():
            click.echo(f"  Loaded {name}: {count} elements")

    # Load GeoIP sets
    if geoip_dir:
        results = loader.load_geoip_dir(geoip_dir)
        for name, count in results.items():
            click.echo(f"  Loaded {name}: {count} elements")

    if not init_path.exists() and not geoip_dir:
        click.echo("No sets to load.")


@cli.command("generate-set-loader")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@config_options
def generate_set_loader(directory, config_dir, config_dir4, config6_dir,
                        no_auto_v4, no_auto_v6):
    """Generate a shell script that loads external sets."""
    from shorewall_nft.nft.set_loader import generate_set_loader_script

    primary, _, _ = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    click.echo(generate_set_loader_script(primary))


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--iptables", type=click.Path(exists=True, path_type=Path), required=True,
              help="iptables-save dump (ground truth).")
@click.option("--target", default="203.0.113.5", help="Target IP for tests.")
@click.option("--targets", default=None,
              help="Comma-separated list of target IPs, or @FILE with one IP "
                   "per line. Bypasses --target; all targets share a single "
                   "netns topology so the nft ruleset is loaded once.")
@click.option("--ip6tables", "ip6tables_dump",
              type=click.Path(exists=True, path_type=Path), default=None,
              help="ip6tables-save dump for IPv6 tests (optional).")
@click.option("--targets6", default=None,
              help="Comma-separated list or @FILE of IPv6 target addresses. "
                   "Requires --ip6tables.")
@click.option("--src-iface", default=None,
              help="Override the src-zone interface name in the FW netns "
                   f"(default: {'bond1'}). Use to exercise a different "
                   "source zone than net.")
@click.option("--dst-iface", default=None,
              help="Override the dst-zone interface name in the FW netns "
                   f"(default: {'bond0.20'}). Use to exercise a different "
                   "destination zone than host.")
@click.option("--all-zones", is_flag=True,
              help="Multi-zone topology: create one veth pair per zone "
                   "from the shorewall config and derive test cases across "
                   "every <src>2<dst> chain in the iptables dump. Runs as "
                   "a single simulate pass against one loaded ruleset.")
@click.option("--max-tests", "-n", default=60,
              help="Max test cases per target.")
@click.option("--seed", default=42, help="Random seed for sampling.")
@click.option("-V", "--sim-verbose", is_flag=True, help="Show all test results.")
@click.option("--parallel", "-j", default=4, help="Parallel test threads.")
@click.option("--no-trace", is_flag=True, help="Disable nft trace logging.")
@config_options
def simulate(directory, iptables, target, targets, ip6tables_dump, targets6,
             src_iface, dst_iface, all_zones, max_tests, seed, sim_verbose,
             parallel, no_trace,
             config_dir, config_dir4, config6_dir, no_auto_v4, no_auto_v6):
    """Run packet-level simulation in 3 network namespaces."""
    from shorewall_nft.verify.simulate import (
        DST_IFACE_DEFAULT,
        SRC_IFACE_DEFAULT,
        run_simulation,
    )

    primary, _, _ = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    config_dir = primary

    def _parse_list(val: str | None) -> list[str] | None:
        if not val:
            return None
        if val.startswith("@"):
            return [
                line.strip()
                for line in Path(val[1:]).read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        return [t.strip() for t in val.split(",") if t.strip()]

    target_list = _parse_list(targets)
    target_list6 = _parse_list(targets6)
    sif = src_iface or SRC_IFACE_DEFAULT
    dif = dst_iface or DST_IFACE_DEFAULT

    click.echo(f"Simulating {config_dir} against {iptables}")
    click.echo(f"Topology: src-iface={sif}, dst-iface={dif}")
    if target_list or target_list6:
        n4 = len(target_list) if target_list else 0
        n6 = len(target_list6) if target_list6 else 0
        click.echo(f"Targets: {n4} v4 + {n6} v6 (single topology), "
                   f"max per target: {max_tests}, seed: {seed}, "
                   f"parallel: {parallel}, trace: {not no_trace}")
    else:
        click.echo(f"Target: {target}, max tests: {max_tests}, seed: {seed}, "
                   f"parallel: {parallel}, trace: {not no_trace}")
    click.echo()

    if all_zones:
        click.echo("All-zones mode: one topology, derive tests across every "
                   "known <src>2<dst> chain in the dump.")

    results = run_simulation(
        config_dir=config_dir,
        iptables_dump=iptables,
        target_ip=target,
        targets=target_list,
        ip6tables_dump=ip6tables_dump,
        targets6=target_list6,
        max_tests=max_tests,
        seed=seed,
        verbose=sim_verbose,
        parallel=parallel,
        trace=not no_trace,
        all_zones_from_config=all_zones,
        src_iface=sif,
        dst_iface=dif,
    )

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    total = len(results)

    click.echo()
    click.echo(f"Results: {passed} passed, {failed} failed ({total} total)")

    if failed > 0:
        click.echo("\nFailed tests:")
        for r in results:
            if not r.passed:
                tc = r.test
                port_str = f":{tc.port}" if tc.port else ""
                click.echo(f"  {tc.src_ip} → {tc.dst_ip} {tc.proto}{port_str} "
                          f"expect={tc.expected} got={r.got}")
        sys.exit(1)


@cli.command("capabilities")
@click.option("--netns", type=str, default=None, help="Probe in network namespace.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def capabilities(netns: str | None, as_json: bool):
    """Detect nftables capabilities of the running kernel."""
    import json as json_mod

    from shorewall_nft.nft.capabilities import NftCapabilities

    click.echo("Probing nft capabilities...")
    caps = NftCapabilities.probe(netns=netns)

    if as_json:
        d = {k: v for k, v in caps.__dict__.items() if not k.startswith("_")}
        click.echo(json_mod.dumps(d, indent=2))
    else:
        click.echo(caps.summary())


@cli.command("explain-nft-features")
@click.option("--probe", is_flag=True, help="Probe kernel for feature availability.")
@click.option("--category", "-c", type=str, default=None,
              help="Filter by category (e.g. 'Sets', 'NAT', 'IPv6').")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def explain_nft_features(probe: bool, category: str | None, as_json: bool):
    """Show nft features with syntax examples and availability."""
    from shorewall_nft.nft.explain import (
        format_features,
        get_features_with_availability,
    )

    caps = None
    if probe:
        click.echo("Probing kernel capabilities...")
        from shorewall_nft.nft.capabilities import NftCapabilities
        caps = NftCapabilities.probe()

    features = get_features_with_availability(caps)

    if as_json:
        import json as json_mod
        data = [
            {
                "name": f.name,
                "category": f.category,
                "description": f.description,
                "nft_syntax": f.nft_syntax,
                "shorewall_equivalent": f.shorewall_equivalent,
                "available": f.available,
            }
            for f in features
            if not category or f.category.lower() == category.lower()
        ]
        click.echo(json_mod.dumps(data, indent=2))
    else:
        click.echo(format_features(features, category=category))


@cli.command("merge-config")
@click.argument("shorewall_dir", type=click.Path(exists=True, path_type=Path))
@click.argument("shorewall6_dir", type=click.Path(exists=True, path_type=Path),
                required=False)
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Output directory (default: <parent>/shorewall46)")
@click.option("--guided", is_flag=True, default=False,
              help="Interactive mode: ask on each collision")
@click.option("--no-plugins", is_flag=True, default=False,
              help="Disable plugin enrichment even if plugins.conf exists")
def merge_config(shorewall_dir: Path, shorewall6_dir: Path | None,
                 output: Path | None, guided: bool, no_plugins: bool):
    """Merge Shorewall + Shorewall6 configs into unified directory.

    If only the v4 dir is given, the v6 sibling is auto-detected by
    appending '6' to the v4 dir name (e.g. /etc/shorewall → /etc/shorewall6).
    """
    if shorewall6_dir is None:
        candidate = shorewall_dir.parent / (shorewall_dir.name + "6")
        if not candidate.is_dir():
            raise click.UsageError(
                f"No v6 config given and {candidate} not found. "
                f"Specify both directories or create the sibling.")
        shorewall6_dir = candidate
        click.echo(f"Auto-detected v6 sibling: {shorewall6_dir}")

    from shorewall_nft.tools.merge_config import merge_config as do_merge
    ctx = click.Context(do_merge)
    ctx.invoke(do_merge, shorewall_dir=shorewall_dir,
               shorewall6_dir=shorewall6_dir, output=output,
               guided=guided, no_plugins=no_plugins)


@cli.command("lookup")
@click.argument("ip")
@click.option("--config-dir", "-c", type=click.Path(exists=True, path_type=Path),
              default=None, help="Config dir with plugins.conf")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output raw JSON (machine-readable).")
def lookup_cmd(ip: str, config_dir: Path | None, as_json: bool):
    """Lookup an IP address across all configured plugins."""
    import json as json_mod

    from shorewall_nft.plugins.manager import PluginManager

    cdir = config_dir or _get_config_dir(None)
    pm = PluginManager(cdir)
    if not pm.plugins:
        if as_json:
            click.echo(json_mod.dumps({"error": "no plugins loaded",
                                       "config_dir": str(cdir)}))
        else:
            click.echo("No plugins loaded. Configure plugins.conf in "
                       f"{cdir}", err=True)
        raise SystemExit(1)
    info = pm.lookup_ip(ip)
    if not info:
        if as_json:
            click.echo(json_mod.dumps({"ip": ip, "found": False}))
        else:
            click.echo(f"No info for {ip}", err=True)
        raise SystemExit(1)
    # Both modes emit JSON, but the default-mode version is indented
    # for human reading. --json just guarantees a pure JSON stream on
    # stdout even on errors.
    click.echo(json_mod.dumps(
        info, indent=None if as_json else 2))


@cli.command("enrich")
@click.argument("directory", type=click.Path(exists=True, file_okay=False,
                                             path_type=Path), required=False)
@click.option("--no-backup", is_flag=True, default=False,
              help="Skip .bak file creation (dangerous)")
@click.option("--dry-run", is_flag=True, default=False,
              help="Preview changes without touching disk (shows a unified diff).")
def enrich_cmd(directory: Path | None, no_backup: bool, dry_run: bool):
    """Run plugin enrichment in-place on a config directory.

    Rewrites rules and params with plugin annotations.
    Creates .bak backups unless --no-backup is passed.

    With --dry-run, no files are modified — instead a unified diff of
    the would-be changes is printed. Useful for reviewing plugin output
    before committing to the rewrite.
    """
    import difflib
    import shutil

    from shorewall_nft.plugins.manager import PluginManager
    from shorewall_nft.tools.merge_config import (
        _apply_enrich_to_block,
        _parse_comment_blocks,
        _parse_params,
    )

    cdir = _get_config_dir(directory)
    pm = PluginManager(cdir)
    if not pm.plugins:
        click.echo(f"No plugins configured in {cdir}/plugins.conf",
                   err=True)
        raise SystemExit(1)

    mode = "Dry-run" if dry_run else "Enriching"
    click.echo(f"{mode} {cdir} with plugins: "
               f"{', '.join(p.name for p in pm.plugins)}")

    # Enrich rules file
    rules_path = cdir / "rules"
    if rules_path.exists():
        original_text = rules_path.read_text(errors="replace")

        header, blocks = _parse_comment_blocks(rules_path)
        lines = list(header)
        enriched_count = 0
        for tag, block_lines in blocks.items():
            import re as re_mod
            content = [l for l in block_lines
                       if not re_mod.match(r'^\?COMMENT', l.strip(),
                                           re_mod.IGNORECASE)]
            enrich = pm.enrich_comment_block(tag, content, [])
            new_block = _apply_enrich_to_block(block_lines, tag, enrich)
            if not enrich.is_empty():
                enriched_count += 1
            lines.append("")
            lines.extend(new_block)
        new_text = "\n".join(lines) + "\n"

        if dry_run:
            # Show unified diff
            diff = list(difflib.unified_diff(
                original_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"{rules_path.name}",
                tofile=f"{rules_path.name} (enriched)",
                n=3,
            ))
            if diff:
                click.echo(f"\n--- rules diff ({enriched_count}/"
                           f"{len(blocks)} blocks changed) ---")
                click.echo("".join(diff))
            else:
                click.echo("  rules: no changes")
        else:
            if not no_backup:
                shutil.copy2(rules_path, rules_path.with_suffix(".bak"))
            rules_path.write_text(new_text)
            click.echo(f"  rules: {enriched_count}/{len(blocks)} "
                       f"blocks enriched")

    # Enrich params file (report pairs, don't rewrite)
    params_path = cdir / "params"
    if params_path.exists():
        v4p = _parse_params(params_path)
        pe = pm.enrich_params(v4p, {})
        if pe.pairs:
            click.echo(f"  params: {len(pe.pairs)} pairs detected "
                       f"(rewrite only during merge-config)")

    click.echo("Dry-run complete." if dry_run else "Done.")


@cli.command("plugins")
@click.argument("subcommand", type=click.Choice(["list"]), default="list",
                required=False)
@click.option("--config-dir", "-c", type=click.Path(exists=True, path_type=Path),
              default=None)
def plugins_cmd(subcommand: str, config_dir: Path | None):
    """Manage shorewall-nft plugins."""
    from shorewall_nft.plugins.manager import PluginManager

    cdir = config_dir or _get_config_dir(None)
    pm = PluginManager(cdir)
    if subcommand == "list":
        if not pm.plugins:
            click.echo(f"No plugins loaded (plugins.conf in {cdir})")
            return
        click.echo(f"Loaded plugins (from {cdir}/plugins.conf):")
        for p in pm.plugins:
            click.echo(f"  {p.name:15s} v{p.version}  priority={p.priority}")


# Register plugin-provided CLI commands at module load time
def _register_plugin_commands():
    """Load plugins from default config and register their CLI commands.

    Best-effort: if no plugins.conf exists, this is a no-op.
    """
    try:
        from shorewall_nft.plugins.manager import PluginManager
        cdir = _get_config_dir(None)
        if not (cdir / "plugins.conf").exists():
            return
        pm = PluginManager(cdir)
        pm.register_cli_commands(cli)
    except Exception:
        pass  # Never block CLI startup on plugin errors


_register_plugin_commands()


@cli.command("generate-sysctl")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@config_options
def generate_sysctl(directory, config_dir, config_dir4, config6_dir,
                    no_auto_v4, no_auto_v6):
    """Generate sysctl configuration script."""
    from shorewall_nft.config.parser import load_config
    from shorewall_nft.runtime.sysctl import generate_sysctl_script

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    config = load_config(primary, config6_dir=secondary,
                         skip_sibling_merge=skip)
    click.echo(generate_sysctl_script(config))


@cli.command("generate-systemd")
@click.option("--netns", is_flag=True, help="Generate template for network namespaces.")
@click.option("-o", "--output-dir", type=click.Path(path_type=Path), default=None)
def generate_systemd(netns: bool, output_dir: Path | None):
    """Generate systemd service files."""
    from shorewall_nft.netns.systemd import generate_netns_service, generate_service

    if netns:
        content = generate_netns_service()
        filename = "shorewall-nft@.service"
    else:
        content = generate_service()
        filename = "shorewall-nft.service"

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / filename).write_text(content)
        click.echo(f"Written to {output_dir / filename}")
    else:
        click.echo(content)


@cli.command("generate-conntrackd")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--sync-iface", default=None,
              help="Interface used for the conntrackd sync link. "
                   "Defaults to the CONNTRACKD_IFACE setting.")
@click.option("--peer-ip", default=None,
              help="IPv4 of the other HA node on the sync link.")
@click.option("--local-ip", default=None,
              help="IPv4 of this node on the sync link.")
@click.option("--cluster-ip", default=None,
              help="Shared VIP that HA failover moves.")
@config_options
def generate_conntrackd(directory, sync_iface, peer_ip, local_ip, cluster_ip,
                        config_dir, config_dir4, config6_dir,
                        no_auto_v4, no_auto_v6):
    """Generate a conntrackd.conf fragment for an HA firewall pair.

    Honours CT_ZONE_TAG_MASK to build a Mark filter that replicates
    only zone bits across the sync link, keeping routing / policy
    marks local to each node.
    """
    from shorewall_nft.config.parser import load_config
    from shorewall_nft.runtime.conntrackd import generate_conntrackd_fragment

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    config = load_config(primary, config6_dir=secondary,
                         skip_sibling_merge=skip)
    click.echo(generate_conntrackd_fragment(
        config,
        sync_iface=sync_iface,
        peer_ip=peer_ip,
        local_ip=local_ip,
        cluster_ip=cluster_ip,
    ))


@cli.command("generate-tc")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@config_options
def generate_tc(directory, config_dir, config_dir4, config6_dir,
                no_auto_v4, no_auto_v6):
    """Generate tc (traffic control) commands."""
    from shorewall_nft.compiler.tc import emit_tc_commands, parse_tc_config
    from shorewall_nft.config.parser import load_config

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir4, config6_dir,
        no_auto_v4, no_auto_v6)
    config = load_config(primary, config6_dir=secondary,
                         skip_sibling_merge=skip)
    tc = parse_tc_config(config)
    if tc.devices or tc.classes:
        click.echo(emit_tc_commands(tc))
    else:
        click.echo("No TC configuration found.")


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _load_static_nft(config_dir: Path) -> str | None:
    static_path = config_dir / "static.nft"
    if static_path.exists():
        return static_path.read_text()
    return None


def _load_sets(config_dir: Path) -> list | None:
    from shorewall_nft.nft.sets import parse_init_for_sets
    init_path = config_dir / "init"
    sets = parse_init_for_sets(init_path, config_dir)
    return sets if sets else None


# ──────────────────────────────────────────────────────────────────────
# Structured config I/O (docs/cli/override-json.md)
# ──────────────────────────────────────────────────────────────────────
# Read-only first slice: ``config export`` serialises a parsed config
# directory into the structured blob shape documented in the roadmap.
# ``config import`` and ``config edit`` + full ``--override-json``
# wiring land in a follow-up commit once the importer + overlay
# applier are in place.

@cli.group()
def config() -> None:
    """Structured config I/O (export / import / edit — planned)."""


@config.command("export")
@click.argument("directory", type=click.Path(exists=True, file_okay=False,
                                             path_type=Path),
                required=False)
@click.option("--format", "fmt",
              type=click.Choice(["json", "yaml"]), default="json",
              show_default=True,
              help="Output format. YAML needs PyYAML available.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Write to FILE instead of stdout. Extension auto-"
                   "selects the format if --format is not given.")
@click.option("--include-trace", is_flag=True,
              help="Keep _file / _lineno / _comment diagnostics in the "
                   "output (off by default for stable diffs).")
@click.option("--indent", type=int, default=2, show_default=True,
              help="JSON indent (ignored for YAML).")
def config_export(directory: Path | None, fmt: str, output: Path | None,
                  include_trace: bool, indent: int) -> None:
    """Dump a Shorewall config directory as a structured JSON/YAML blob.

    Columnar files emit one object per row with column names as keys;
    ``rules`` / ``blrules`` / ``policy`` are nested under their
    ``?SECTION`` labels.
    """
    from shorewall_nft.config.exporter import export_config
    from shorewall_nft.config.parser import load_config

    cfg_dir = directory or Path("/etc/shorewall46")
    cfg = load_config(cfg_dir)
    blob = export_config(cfg, include_trace=include_trace)

    # Auto-format from extension when -o is given and --format wasn't.
    if output is not None and output.suffix in (".yaml", ".yml"):
        fmt = "yaml"

    if fmt == "yaml":
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            click.echo(
                "YAML output requested but PyYAML is not installed. "
                "Install python3-yaml or pass --format=json.", err=True)
            sys.exit(2)
        text = yaml.safe_dump(blob, sort_keys=False, default_flow_style=False,
                              allow_unicode=True)
    else:
        import json as _json
        text = _json.dumps(blob, indent=indent, ensure_ascii=False,
                           sort_keys=False) + "\n"

    if output is not None:
        output.write_text(text)
        click.echo(f"wrote {output} ({len(text)} bytes)")
    else:
        click.echo(text, nl=False)


@config.command("import")
@click.argument("source", type=click.Path(path_type=Path),
                required=True)
@click.option("--format", "fmt",
              type=click.Choice(["json", "yaml", "auto"]), default="auto",
              show_default=True,
              help="Input format. 'auto' selects by file extension.")
@click.option("--to", "target", type=click.Path(path_type=Path), default=None,
              help="Target directory. When given, the parsed blob is "
                   "written back as on-disk Shorewall files. Otherwise "
                   "the command only validates the blob.")
@click.option("--force", is_flag=True,
              help="Overwrite --to target even if it is not empty.")
@click.option("--dry-run", is_flag=True,
              help="Parse + validate only, print a summary. Implied "
                   "when --to is absent.")
def config_import(source: Path, fmt: str, target: Path | None,
                  force: bool, dry_run: bool) -> None:
    """Import a structured JSON/YAML config blob into a ShorewalConfig.

    Currently the CLI validates the blob and prints a summary
    (zones / interfaces / rules / etc counts). Writing back to a
    target directory is a follow-up — the in-memory path is already
    enough for the ``--override-json`` wiring and for round-trip
    testing.
    """
    from shorewall_nft.config.importer import (
        ImportError as CfgImportError,
    )
    from shorewall_nft.config.importer import (
        blob_to_config,
        write_config_dir,
    )

    if source.name == "-":
        text = sys.stdin.read()
        suffix = ""
    else:
        if not source.exists():
            click.echo(f"input not found: {source}", err=True)
            sys.exit(2)
        text = source.read_text()
        suffix = source.suffix

    if fmt == "auto":
        fmt = "yaml" if suffix in (".yaml", ".yml") else "json"
    if fmt == "yaml":
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            click.echo("YAML input requested but PyYAML not installed.",
                       err=True)
            sys.exit(2)
        blob = yaml.safe_load(text)
    else:
        import json as _json
        blob = _json.loads(text)

    try:
        config = blob_to_config(blob)
    except CfgImportError as e:
        click.echo(f"import failed: {e}", err=True)
        sys.exit(2)

    click.echo(f"imported schema_version={blob.get('schema_version')}")
    click.echo(f"  shorewall.conf: {len(config.settings)} keys")
    click.echo(f"  params:         {len(config.params)} keys")
    click.echo(f"  zones:          {len(config.zones)} rows")
    click.echo(f"  interfaces:     {len(config.interfaces)} rows")
    click.echo(f"  hosts:          {len(config.hosts)} rows")
    click.echo(f"  policy:         {len(config.policy)} rows")
    click.echo(f"  rules:          {len(config.rules)} rows")
    click.echo(f"  blrules:        {len(config.blrules)} rows")
    click.echo(f"  masq:           {len(config.masq)} rows")
    click.echo(f"  conntrack:      {len(config.conntrack)} rows")
    click.echo(f"  macros:         {len(config.macros)} defined")
    click.echo(f"  scripts:        {len(config.scripts)} files")

    if target is not None and not dry_run:
        try:
            written = write_config_dir(config, target, force=force)
        except CfgImportError as e:
            click.echo(f"write failed: {e}", err=True)
            sys.exit(2)
        click.echo(f"wrote {len(written)} files to {target}")


@config.command("template")
@click.argument("source", type=click.Path(exists=True, dir_okay=False,
                                          path_type=Path),
                required=True)
@click.option("--host", "host_name", required=True,
              help="Target host name. Lines prefixed with `@<other>` "
                   "are dropped, lines prefixed with `@<host>` keep "
                   "the rest of the line, unprefixed lines pass "
                   "through unchanged.")
@click.option("-o", "--output", type=click.Path(path_type=Path),
              default=None,
              help="Write to FILE. Defaults to stdout.")
def config_template(source: Path, host_name: str,
                    output: Path | None) -> None:
    """Expand a multi-host text template against a target host name.

    Implements the prefix-templating convention used by the legacy
    keepalived / conntrackd snapshots: every line that's specific
    to a single host is tagged with ``@<hostname>`` at column 1
    (followed by a tab or space), and lines without a tag are
    shared. This subcommand walks one input file, drops every
    line tagged for a host other than ``--host``, strips the tag
    from lines that match, and emits the result.

    Shorewall config files don't use this convention — only
    keepalived/conntrackd do — so the helper lives here as a
    generic file-level utility rather than a parser feature.

    Example::

        shorewall-nft config template ../legacy/keepalived.conf \\
            --host fw-primary -o /etc/keepalived/keepalived.conf
    """
    import re
    text = source.read_text()
    out_lines: list[str] = []
    # Match lines that begin with `@<word>` followed by ONE
    # whitespace separator. Capturing only one whitespace char
    # (not the whole run) preserves the writer's intended
    # indentation: a row written as `@fw-primary\t\trouter_id fw-primary-legacy`
    # round-trips to `\trouter_id fw-primary-legacy` after the tag + first
    # tab are stripped, keeping the body aligned with the
    # surrounding shared lines.
    tag_re = re.compile(r"^@(\S+)[ \t](.*)$")
    kept = 0
    dropped = 0
    untagged = 0
    for raw in text.splitlines():
        m = tag_re.match(raw)
        if m is None:
            out_lines.append(raw)
            untagged += 1
            continue
        tag = m.group(1)
        rest = m.group(2)
        if tag == host_name:
            out_lines.append(rest)
            kept += 1
        else:
            dropped += 1
            continue

    body = "\n".join(out_lines)
    if not body.endswith("\n"):
        body += "\n"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(body)
        click.echo(
            f"wrote {output} — {kept} kept, {dropped} dropped, "
            f"{untagged} untagged for host {host_name}",
            err=True)
    else:
        click.echo(body, nl=False)


@config.command("merge")
@click.argument("sources", nargs=-1, required=True,
                type=click.Path(exists=True, file_okay=False,
                                path_type=Path))
@click.option("--to", "target", required=True,
              type=click.Path(path_type=Path),
              help="Target directory for the merged output. "
                   "Pretty-printed (aligned columns + zone-pair "
                   "grouping + tail-sorted catch-all DROPs).")
@click.option("--force", is_flag=True,
              help="Overwrite --to even if it exists and is "
                   "non-empty.")
@click.option("--provenance", is_flag=True,
              help="Interleave `# from <file>:<lineno>` shell "
                   "comments before each rule so a future bisect "
                   "can blame the origin file/line.")
@click.option("--config6-dir", "config6_dir",
              type=click.Path(exists=True, file_okay=False,
                              path_type=Path),
              default=None,
              help="Optional v6 sibling for the FIRST source dir. "
                   "When given, the parser merges shorewall + "
                   "shorewall6 into a unified inet config.")
def config_merge(sources: tuple[Path, ...], target: Path, force: bool,
                 provenance: bool, config6_dir: Path | None) -> None:
    """Merge one or more Shorewall config directories into a pretty
    unified output (TODO #13: 3-firewall config-merge replay).

    Reads each SOURCE directory in turn, parses it through the
    standard ``load_config`` (with ``shorewall6`` sibling
    auto-detection), and unions the resulting in-memory configs
    into a single ``ShorewalConfig``. The merged result is
    written via ``write_config_dir`` with ``pretty=True``, so
    the on-disk output gets:

      * column alignment per block
      * zone-pair grouping (all ``foo→bar`` rules adjacent)
      * catch-all ``DROP`` / ``REJECT`` rules tail-sorted within
        each zone-pair group
      * optional provenance markers when ``--provenance`` is set

    Multi-source merge semantics: later sources extend earlier
    ones — duplicate rules are appended verbatim (the
    ``_reorder_rules_block`` pass de-dups by sort key only when
    the columns are byte-equal). Settings (``shorewall.conf`` /
    ``params``) follow last-wins on key collisions.

    Use this when re-doing the unified ``/etc/shorewall46``
    layout from a hand-pruned host snapshot — the output is the
    canonical form going forward.
    """
    from shorewall_nft.config.importer import (
        ImportError as CfgImportError,
    )
    from shorewall_nft.config.importer import (
        write_config_dir,
    )
    from shorewall_nft.config.parser import load_config

    if not sources:
        raise click.UsageError("at least one SOURCE directory required")

    merged = None
    total_rules = 0
    for i, src in enumerate(sources):
        c6 = config6_dir if i == 0 else None
        cfg = load_config(src, config6_dir=c6)
        n = len(cfg.rules)
        click.echo(f"loaded {src} → {n} rules, "
                   f"{len(cfg.policy)} policies, "
                   f"{len(cfg.zones)} zones")
        total_rules += n
        if merged is None:
            merged = cfg
            continue
        # Concatenate the columnar lists. Dedup happens after
        # all sources are loaded so the order across sources is
        # preserved (first occurrence wins, later duplicates
        # drop).
        for attr in ("zones", "interfaces", "hosts", "policy",
                     "rules", "blrules", "masq", "conntrack",
                     "notrack", "rawnat", "stoppedrules",
                     "routestopped", "providers", "tunnels",
                     "maclist", "accounting", "tcrules", "mangle",
                     "netmap", "blacklist", "arprules", "proxyarp",
                     "proxyndp", "ecn", "nfacct", "scfilter"):
            existing = getattr(merged, attr, None)
            new = getattr(cfg, attr, None)
            if existing is None:
                setattr(merged, attr, new)
            elif new:
                existing.extend(new)
        # last-wins for KEY=VALUE settings
        for k, v in cfg.settings.items():
            merged.settings[k] = v
        for k, v in cfg.params.items():
            if not k.startswith("__"):
                merged.params[k] = v
        # last-wins for plugin files (plugins.conf + plugins/*.toml +
        # plugins/*.token) and macro definitions. The exporter
        # writes whatever ends up in these dicts byte-for-byte.
        for k, v in (getattr(cfg, "plugin_files", None) or {}).items():
            merged.plugin_files[k] = v
        for k, v in (getattr(cfg, "macros", None) or {}).items():
            merged.macros[k] = v
        for k, v in (getattr(cfg, "scripts", None) or {}).items():
            merged.scripts[k] = v

    assert merged is not None

    # Dedup pass: drop later occurrences of byte-equal rows in
    # the columnar lists. The merge of multiple host snapshots
    # often produces overlapping rules — dedup is the difference
    # between a tidy unified config and a config that lists every
    # rule twice. The match key is ``(section, columns)`` so
    # rules in different ``?SECTION`` blocks (NEW vs ESTABLISHED
    # in the legacy v4 dump) stay separate.
    deduped_total = 0
    for attr in ("zones", "interfaces", "hosts", "policy",
                 "rules", "blrules", "masq", "conntrack",
                 "notrack", "rawnat", "stoppedrules",
                 "routestopped", "providers", "tunnels",
                 "maclist", "accounting", "tcrules", "mangle",
                 "netmap", "blacklist", "arprules", "proxyarp",
                 "proxyndp", "ecn", "nfacct", "scfilter"):
        rows = getattr(merged, attr, None) or []
        if len(rows) < 2:
            continue
        seen: set[tuple] = set()
        out_list = []
        dropped = 0
        for ln in rows:
            key = (ln.section or "", tuple(ln.columns))
            if key in seen:
                dropped += 1
                continue
            seen.add(key)
            out_list.append(ln)
        if dropped:
            setattr(merged, attr, out_list)
            deduped_total += dropped
    if deduped_total:
        click.echo(f"dedup: dropped {deduped_total} byte-equal "
                   f"duplicate rows across all columnar files")
    try:
        written = write_config_dir(
            merged, target, force=force, pretty=True,
            provenance=provenance,
        )
    except CfgImportError as e:
        click.echo(f"merge write failed: {e}", err=True)
        sys.exit(2)
    click.echo(
        f"merged {len(sources)} sources → {target} "
        f"({len(written)} files, {total_rules} rules total"
        + (", with provenance" if provenance else "") + ")")
