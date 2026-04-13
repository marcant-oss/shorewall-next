#!/usr/bin/env python3
"""Merge Shorewall + Shorewall6 configs into a unified shorewall-nft config.

Two modes:
  --auto (default): automatic merge with sensible defaults
  --guided:         interactive, asks on every collision

Usage:
    shorewall-nft merge-config /etc/shorewall /etc/shorewall6
    shorewall-nft merge-config /etc/shorewall /etc/shorewall6 --guided
    shorewall-nft merge-config /etc/shorewall /etc/shorewall6 -o /etc/shorewall-nft
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from shorewall_nft.plugins.manager import PluginManager


# ── Collision resolution ─────────────────────────────────────────────

def _ask_collision(label: str, v4_value: str, v6_value: str,
                   merge_proposal: str, guided: bool) -> str:
    """Resolve a collision between v4 and v6 values.

    In auto mode, returns merge_proposal.
    In guided mode, prompts the user interactively.
    """
    if not guided:
        return merge_proposal

    click.echo("")
    click.secho(f"  ╔══ Collision: {label}", fg="yellow", bold=True)
    click.echo(f"  ║ v4: {v4_value}")
    click.echo(f"  ║ v6: {v6_value}")
    click.echo("  ║")
    click.echo("  ║ Merge proposal:")
    for line in merge_proposal.splitlines():
        click.echo(f"  ║   {line}")
    click.echo("  ╚══")
    click.echo("")

    choices = {
        "1": ("Keep v4 only", v4_value),
        "2": ("Keep v6 only", v6_value),
        "3": ("Use merge proposal", merge_proposal),
        "4": ("Enter custom value", None),
    }
    for key, (desc, _) in choices.items():
        click.echo(f"    [{key}] {desc}")

    while True:
        choice = click.prompt("  Choice", default="3", show_default=True).strip()
        if choice in choices:
            if choice == "4":
                custom = click.prompt("  Enter value", default=merge_proposal)
                return custom
            return choices[choice][1]
        click.echo("  Invalid choice, try again.")


def _ask_block_collision(label: str, v4_lines: list[str], v6_lines: list[str],
                         merged: list[str], guided: bool) -> list[str]:
    """Resolve a collision between v4 and v6 multi-line blocks.

    In auto mode, returns merged.
    In guided mode, prompts the user interactively.
    """
    if not guided:
        return merged

    # Filter to content lines only (no ?COMMENT directives) for display
    v4_content = [l for l in v4_lines
                  if not re.match(r'^\?COMMENT', l.strip(), re.IGNORECASE)]
    v6_content = [l for l in v6_lines
                  if not re.match(r'^\?COMMENT', l.strip(), re.IGNORECASE)]

    if not v6_content:
        return merged

    click.echo("")
    click.secho(f"  ╔══ Block collision: {label}", fg="yellow", bold=True)
    click.echo(f"  ║ v4 ({len(v4_content)} rules):")
    for line in v4_content[:10]:
        click.echo(f"  ║   {line}")
    if len(v4_content) > 10:
        click.echo(f"  ║   ... ({len(v4_content) - 10} more)")
    click.echo("  ║")
    click.echo(f"  ║ v6 ({len(v6_content)} rules):")
    for line in v6_content[:10]:
        click.echo(f"  ║   {line}")
    if len(v6_content) > 10:
        click.echo(f"  ║   ... ({len(v6_content) - 10} more)")
    click.echo("  ╚══")
    click.echo("")

    choices = {
        "1": "Keep v4 only",
        "2": "Keep v6 only",
        "3": "Merge both (v4 + v6 combined)",
    }
    for key, desc in choices.items():
        click.echo(f"    [{key}] {desc}")

    while True:
        choice = click.prompt("  Choice", default="3", show_default=True).strip()
        if choice == "1":
            return list(v4_lines)
        elif choice == "2":
            return list(v6_lines)
        elif choice == "3":
            return merged
        click.echo("  Invalid choice, try again.")


# ── Parsers ──────────────────────────────────────────────────────────

def _parse_zones(path: Path) -> dict[str, str]:
    """Parse zones file → {zone_name: full_line}."""
    zones: dict[str, str] = {}
    if not path.exists():
        return zones
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if parts:
            zones[parts[0]] = stripped
    return zones


def _parse_policies(path: Path) -> list[tuple[str, str, str]]:
    """Parse policy file → [(source, dest, full_line), ...]."""
    policies: list[tuple[str, str, str]] = []
    if not path.exists():
        return policies
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 3:
            policies.append((parts[0], parts[1], stripped))
    return policies


def _parse_params(path: Path) -> dict[str, str]:
    """Parse params file → {VAR_NAME: full_line}."""
    params: dict[str, str] = {}
    if not path.exists():
        return params
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r'^(\w+)=', stripped)
        if m:
            params[m.group(1)] = stripped
    return params


def _parse_comment_blocks(path: Path) -> tuple[list[str], dict[str, list[str]]]:
    """Parse a rules/masq/conntrack file into header + ?COMMENT-tagged blocks.

    Returns:
        (header_lines, {tag: [lines_in_block]})

    Lines before the first ?COMMENT or with no tag go into header.
    The ?COMMENT and ?COMMENT (end) directives are preserved in the blocks.
    """
    header: list[str] = []
    blocks: dict[str, list[str]] = {}
    current_tag: str | None = None
    block_order: list[str] = []

    if not path.exists():
        return header, blocks

    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r'^\?COMMENT\s*(.*)', line, re.IGNORECASE)
        if m:
            tag = m.group(1).strip()
            if tag:
                current_tag = tag
                if tag not in blocks:
                    blocks[tag] = []
                    block_order.append(tag)
                blocks[tag].append(line)
            else:
                # ?COMMENT (empty) = end tag
                if current_tag and current_tag in blocks:
                    blocks[current_tag].append(line)
                current_tag = None
            continue

        if current_tag is None:
            header.append(line)
        else:
            blocks[current_tag].append(line)

    ordered: dict[str, list[str]] = {}
    for tag in block_order:
        ordered[tag] = blocks[tag]
    return header, ordered


def _parse_conf_settings(path: Path) -> dict[str, str]:
    """Parse shorewall.conf → {KEY: full_line}."""
    settings: dict[str, str] = {}
    if not path.exists():
        return settings
    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r'^(\w+)=', line.strip())
        if m:
            settings[m.group(1)] = line.strip()
    return settings


# ── Merge functions ──────────────────────────────────────────────────

_VAR_REF_RE = re.compile(r'\$\{?(\w+)\}?')


def _compute_v6_var_rewrites(v4_params: dict[str, str],
                             v6_params: dict[str, str]) -> set[str]:
    """Return variable names whose v6 value must be accessed via $VAR_V6.

    Two cases trigger a rewrite:
      1. Direct collision: both v4 and v6 define VAR with different values.
      2. Transitive: VAR's value (same in v4 and v6 literally) references
         another variable that itself needs rewriting. Example:
             v4: DC1=192.168.195.3, ALL_DC=$DC1,$DC2
             v6: DC1=2001:db8:0:1::3, ALL_DC=$DC1,$DC2
         ALL_DC has the same literal value in both, but its expansion
         differs — so v6 rules referencing $ALL_DC must use $ALL_DC_V6.

    Computed as a fixed-point: seed with direct collisions, then repeatedly
    add any v6 variable whose value references a rewritten variable.
    """
    rewrites: set[str] = set()

    # Seed: direct collisions
    for varname, v6_line in v6_params.items():
        if varname not in v4_params:
            continue
        if v4_params[varname] == v6_line:
            continue
        rewrites.add(varname)

    # Transitive: iterate until fixed point
    changed = True
    while changed:
        changed = False
        for varname, v6_line in v6_params.items():
            if varname in rewrites:
                continue
            # Extract the value portion (VAR=value)
            _, _, value = v6_line.partition("=")
            refs = _VAR_REF_RE.findall(value)
            if any(ref in rewrites for ref in refs):
                rewrites.add(varname)
                changed = True
    return rewrites


def _rewrite_v6_vars(line: str, vars_to_rewrite: set[str]) -> str:
    """Rewrite $VAR and ${VAR} references to $VAR_V6 / ${VAR_V6}.

    Only matches exact variable names (word boundary) — $ORG_ADM
    is not rewritten if only $ORG is in the set.
    """
    if not vars_to_rewrite:
        return line
    for var in vars_to_rewrite:
        line = re.sub(r'\$\{' + re.escape(var) + r'\}',
                      '${' + var + '_V6}', line)
        line = re.sub(r'\$' + re.escape(var) + r'(?![A-Za-z0-9_])',
                      '$' + var + '_V6', line)
    return line


def _apply_enrich_to_block(block_lines: list[str], tag: str,
                           enrich) -> list[str]:
    """Apply an EnrichResult to a comment block (lines including ?COMMENT open/close).

    The block may start with '?COMMENT <tag>' and optionally end with '?COMMENT'.
    Prepend comments go right after the opening tag, append comments right
    before the closing tag (or at the end if no close).
    """
    if enrich.drop:
        return []

    if enrich.is_empty():
        return list(block_lines)

    # Find the opening ?COMMENT line and possibly closing one
    open_idx = -1
    close_idx = -1
    for i, line in enumerate(block_lines):
        if re.match(r'^\?COMMENT\s+\S', line.strip(), re.IGNORECASE):
            open_idx = i
            break
    for i in range(len(block_lines) - 1, -1, -1):
        if block_lines[i].strip().lower() == "?comment":
            close_idx = i
            break

    result = list(block_lines)

    # Rename the ?COMMENT tag if requested
    if enrich.tag is not None and open_idx >= 0:
        result[open_idx] = f"?COMMENT {enrich.tag}"

    # Replace rules entirely if requested
    if enrich.replace_rules is not None:
        opener = result[open_idx] if open_idx >= 0 else f"?COMMENT {tag}"
        closer = result[close_idx] if close_idx >= 0 else None
        result = [opener] + list(enrich.replace_rules)
        if closer is not None:
            result.append(closer)
        return result

    # Insert prepend comments after opening tag
    if enrich.prepend_comments and open_idx >= 0:
        insert_at = open_idx + 1
        result[insert_at:insert_at] = list(enrich.prepend_comments)
        # Recompute close_idx because we inserted lines
        if close_idx >= insert_at:
            close_idx += len(enrich.prepend_comments)

    # Insert append comments before closing tag (or at end)
    if enrich.append_comments:
        insert_at = close_idx if close_idx >= 0 else len(result)
        result[insert_at:insert_at] = list(enrich.append_comments)

    return result


def _merge_rules(v4_path: Path, v6_path: Path, out_path: Path,
                 guided: bool = False,
                 plugin_manager: "PluginManager | None" = None,
                 v6_var_rewrites: set[str] | None = None) -> None:
    """Merge rules files: same ?COMMENT blocks get combined.

    If plugin_manager is provided, each block is passed through
    enrich_comment_block hooks to add customer/host annotations.

    If v6_var_rewrites is provided, v6-originated rules get $VAR → $VAR_V6
    rewriting for colliding variable names.
    """
    v4_header, v4_blocks = _parse_comment_blocks(v4_path)
    v6_header, v6_blocks = _parse_comment_blocks(v6_path)

    rewrites = v6_var_rewrites or set()

    def _rw(lines: list[str]) -> list[str]:
        """Apply v6 variable rewrites to a list of lines."""
        if not rewrites:
            return lines
        return [_rewrite_v6_vars(l, rewrites) for l in lines]

    lines: list[str] = []

    # Write v4 header (contains ?SECTION, ?FORMAT, column headers, untagged rules)
    lines.extend(v4_header)

    # Merge v6 header lines that are actual rules (not comments/section directives)
    v6_header_rules = []
    for line in v6_header:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("?"):
            continue
        v6_header_rules.append(line)

    if v6_header_rules:
        lines.append("")
        lines.append("# === IPv6 untagged rules (from shorewall6) ===")
        lines.append("?FAMILY ipv6")
        lines.extend(_rw(v6_header_rules))
        lines.append("?FAMILY any")

    # Merge ?COMMENT blocks
    merged_tags: set[str] = set()

    def _content_only(block_lines: list[str]) -> list[str]:
        """Strip ?COMMENT directives to get pure rule lines for plugin inspection."""
        return [l for l in block_lines
                if not re.match(r'^\?COMMENT', l.strip(), re.IGNORECASE)]

    for tag, v4_lines in v4_blocks.items():
        if tag in v6_blocks:
            merged_tags.add(tag)
            v6_lines = v6_blocks[tag]

            # Collect v6 content (without ?COMMENT directives), apply var rewrites
            v6_content_only = [l for l in v6_lines
                               if not re.match(r'^\?COMMENT', l.strip(),
                                               re.IGNORECASE)]
            v6_content_only = _rw(v6_content_only)
            # Wrap v6 content with ?FAMILY directives so the compiler knows
            # these rules are v6-origin and should emit meta nfproto ipv6
            v6_content = (["?FAMILY ipv6"] + v6_content_only
                          + ["?FAMILY any"]) if v6_content_only else []

            # Build auto-merged block: INSERT v6 content INSIDE the v4 block,
            # right before the closing ?COMMENT. If there is no closing tag,
            # append at the end. Critical: v6 rules must stay within the tag
            # scope so they inherit the ?COMMENT annotation on compile.
            auto_merged = list(v4_lines)
            # Locate the closing ?COMMENT (bare, no tag)
            close_idx = -1
            for i in range(len(auto_merged) - 1, -1, -1):
                if auto_merged[i].strip().lower() == "?comment":
                    close_idx = i
                    break
            if close_idx >= 0:
                auto_merged[close_idx:close_idx] = v6_content
            else:
                auto_merged.extend(v6_content)

            block = _ask_block_collision(
                f"?COMMENT {tag}", v4_lines, v6_lines, auto_merged, guided)

            # Apply plugin enrichment
            if plugin_manager is not None:
                enrich = plugin_manager.enrich_comment_block(
                    tag, _content_only(v4_lines), _content_only(v6_lines))
                block = _apply_enrich_to_block(block, tag, enrich)

            lines.append("")
            lines.extend(block)
        else:
            block = list(v4_lines)
            if plugin_manager is not None:
                enrich = plugin_manager.enrich_comment_block(
                    tag, _content_only(v4_lines), [])
                block = _apply_enrich_to_block(block, tag, enrich)
            lines.append("")
            lines.extend(block)

        merged_tags.add(tag)

    # Append v6-only blocks (with variable rewriting)
    v6_only_tags = [tag for tag in v6_blocks if tag not in merged_tags]
    if v6_only_tags:
        lines.append("")
        lines.append("# === IPv6-only mandants (from shorewall6) ===")
        lines.append("?FAMILY ipv6")
        for tag in v6_only_tags:
            block = _rw(list(v6_blocks[tag]))
            if plugin_manager is not None:
                enrich = plugin_manager.enrich_comment_block(
                    tag, [], _content_only(block))
                block = _apply_enrich_to_block(block, tag, enrich)
            lines.append("")
            lines.extend(block)
        lines.append("?FAMILY any")

    out_path.write_text("\n".join(lines) + "\n")


def _parse_interfaces(path: Path) -> dict[str, str]:
    """Parse interfaces file → {interface_name: full_line}.

    Zone is column 0, interface name is column 1 in Shorewall format.
    """
    ifaces: dict[str, str] = {}
    if not path.exists():
        return ifaces
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            ifaces[parts[1]] = stripped
    return ifaces


def _merge_interfaces(v4_path: Path, v6_path: Path, out_path: Path,
                      guided: bool = False) -> None:
    """Merge interfaces: keep all v4, add v6-only interfaces at the end.

    A v6-only interface (e.g. eth4 only in shorewall6) is added to the
    merged file so the dual-stack compile sees it. Interfaces present
    in both files keep the v4 definition (v4 typically has more options
    like `detect` broadcast and `nosmurfs`).
    """
    v4_ifaces = _parse_interfaces(v4_path)
    v6_ifaces = _parse_interfaces(v6_path)

    lines: list[str] = []
    if v4_path.exists():
        lines.extend(v4_path.read_text(errors="replace").splitlines())

    v6_unique = {name: line for name, line in v6_ifaces.items()
                 if name not in v4_ifaces}
    if v6_unique:
        lines.append("")
        lines.append("# IPv6-only interfaces (from shorewall6)")
        for _name, line in v6_unique.items():
            lines.append(line)

    out_path.write_text("\n".join(lines) + "\n")


def _merge_zones(v4_path: Path, v6_path: Path, out_path: Path,
                 guided: bool = False) -> None:
    """Merge zones: keep all v4, handle v6 zones by mode."""
    v4_zones = _parse_zones(v4_path)
    v6_zones = _parse_zones(v6_path)

    lines: list[str] = []

    if v4_path.exists():
        lines.extend(v4_path.read_text(errors="replace").splitlines())

    # Handle v6 zones
    for name, v6_line in v6_zones.items():
        if name == "fw":
            continue
        if name in v4_zones:
            v4_line = v4_zones[name]
            # Same zone exists in both — collision
            if guided:
                # In guided mode: ask what to do
                merged_line = v4_line  # default: keep v4
                result = _ask_collision(
                    f"Zone '{name}'",
                    v4_line, v6_line,
                    v4_line,  # proposal: keep v4 (inet handles both families)
                    guided,
                )
                if result != v4_line:
                    # User chose differently — replace v4 line
                    lines = [result if l.strip().split()[0:1] == [name]
                             and not l.strip().startswith("#")
                             else l for l in lines]
            else:
                # Auto mode: zone exists in both v4 and v6 → dual-stack.
                # Promote "ipv4" type to "ip" so the emitter generates
                # dispatch rules without a meta nfproto qualifier.
                def _promote_to_ip(l: str) -> str:
                    s = l.strip()
                    if s.startswith("#") or not s:
                        return l
                    parts = s.split()
                    if len(parts) >= 2 and parts[0] == name and parts[1] == "ipv4":
                        return l.replace("\tipv4", "\tip", 1).replace(" ipv4 ", " ip ", 1)
                    return l
                lines = [_promote_to_ip(l) for l in lines]
        else:
            # v6-unique zone
            converted = v6_line.replace("\tipv6\t", "\t-\t").replace(" ipv6 ", " - ")
            if guided:
                result = _ask_collision(
                    f"IPv6-only zone '{name}'",
                    "(not in v4)", v6_line,
                    converted,
                    guided,
                )
                lines.append(result)
            else:
                if not any(l.strip() == "# IPv6-only zones (from shorewall6)"
                           for l in lines):
                    lines.append("")
                    lines.append("# IPv6-only zones (from shorewall6)")
                lines.append(converted)

    out_path.write_text("\n".join(lines) + "\n")


def _merge_policies(v4_path: Path, v6_path: Path, out_path: Path,
                    guided: bool = False) -> None:
    """Merge policies: keep v4, handle v6 by mode."""
    v4_policies = _parse_policies(v4_path)
    v6_policies = _parse_policies(v6_path)

    v4_map = {(src, dst): line for src, dst, line in v4_policies}

    lines: list[str] = []

    if v4_path.exists():
        lines.extend(v4_path.read_text(errors="replace").splitlines())

    v6_unique: list[str] = []
    for src, dst, v6_line in v6_policies:
        key = (src, dst)
        if key in v4_map:
            v4_line = v4_map[key]
            if v4_line.strip() != v6_line.strip() and guided:
                # Same pair, different policy/loglevel
                result = _ask_collision(
                    f"Policy {src} → {dst}",
                    v4_line, v6_line,
                    v4_line,  # proposal: keep v4
                    guided,
                )
                if result != v4_line:
                    lines = [result if (l.strip().split()[0:2] == [src, dst]
                             and not l.strip().startswith("#"))
                             else l for l in lines]
            # Auto or identical: keep v4
        else:
            v6_unique.append(v6_line)

    if v6_unique:
        lines.append("")
        lines.append("# IPv6-only policies (from shorewall6)")
        lines.extend(v6_unique)

    out_path.write_text("\n".join(lines) + "\n")


def _merge_params(v4_path: Path, v6_path: Path, out_path: Path,
                  guided: bool = False,
                  plugin_manager: "PluginManager | None" = None) -> None:
    """Merge params: keep v4, handle v6 collisions by mode.

    If plugin_manager detects v4/v6 pairs (same host), they are grouped
    with an explanatory comment instead of being silently renamed.
    """
    v4_params = _parse_params(v4_path)
    v6_params_dict = _parse_params(v6_path)
    # Compute transitive rewrites so that params whose value references a
    # collided variable also get a _V6 definition, even if the literal value
    # is identical to v4 (e.g. ALL_DC=$DC1,$DC2 in both).
    transitive_rewrites = _compute_v6_var_rewrites(v4_params, v6_params_dict)

    # Ask plugins for pair detection
    pairs: dict[str, tuple[str, str]] = {}
    annotations: dict[str, str] = {}
    if plugin_manager is not None:
        pe = plugin_manager.enrich_params(v4_params, v6_params_dict)
        pairs = pe.pairs
        annotations = pe.annotations

    lines: list[str] = []

    if v4_path.exists():
        lines.extend(v4_path.read_text(errors="replace").splitlines())

    if not v6_path.exists():
        out_path.write_text("\n".join(lines) + "\n")
        return

    lines.append("")
    lines.append("# === IPv6 params (from shorewall6) ===")

    def _rewrite_refs_in_value(value: str) -> str:
        """Rewrite $VAR and ${VAR} references for transitively renamed vars."""
        return _rewrite_v6_vars(value, transitive_rewrites)

    for line in v6_path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue
        m = re.match(r'^(\w+)=', stripped)
        if m:
            varname = m.group(1)
            if varname in v4_params:
                if (v4_params[varname] == stripped
                        and varname not in transitive_rewrites):
                    # Identical AND not transitively affected — skip
                    continue

                # Transitive rewrite: same literal value but dependencies
                # differ. Emit a _V6 version with rewritten var refs.
                if (v4_params[varname] == stripped
                        and varname in transitive_rewrites):
                    renamed = stripped.replace(
                        f"{varname}=", f"{varname}_V6=", 1)
                    renamed = _rewrite_refs_in_value(renamed)
                    lines.append(
                        f"# --- {varname} (v6-transitive) ---")
                    lines.append(renamed)
                    continue

                # Plugin-detected pair: group with an explanatory comment
                if varname in pairs:
                    renamed = stripped.replace(
                        f"{varname}=", f"{varname}_V6=", 1)
                    renamed = _rewrite_refs_in_value(renamed)
                    note = annotations.get(
                        varname, f"# --- {varname} (v4/v6 pair) ---")
                    lines.append("")
                    lines.append(note)
                    lines.append(renamed)
                    continue

                # Regular collision
                auto_renamed = stripped.replace(
                    f"{varname}=", f"{varname}_V6=", 1)
                auto_renamed = _rewrite_refs_in_value(auto_renamed)
                auto_proposal = (
                    f"# v4: {v4_params[varname]}\n{auto_renamed}")

                result = _ask_collision(
                    f"Param ${varname}",
                    v4_params[varname], stripped,
                    auto_proposal,
                    guided,
                )
                lines.extend(result.splitlines())
            else:
                # v6-only var — but still may need ref rewriting
                lines.append(_rewrite_refs_in_value(stripped))
        else:
            lines.append(line)

    out_path.write_text("\n".join(lines) + "\n")


def _merge_config_file(v4_path: Path, v6_path: Path, out_path: Path,
                       name: str, guided: bool = False) -> None:
    """Merge a generic config file (conntrack, notrack, masq, blrules)."""
    if not v6_path.exists() or v6_path.stat().st_size == 0:
        if v4_path.exists():
            shutil.copy2(v4_path, out_path)
        return

    if not v4_path.exists():
        shutil.copy2(v6_path, out_path)
        return

    v4_text = v4_path.read_text(errors="replace")
    v6_text = v6_path.read_text(errors="replace")
    has_comments = "?COMMENT" in v4_text or "?COMMENT" in v6_text

    if has_comments:
        _merge_rules(v4_path, v6_path, out_path, guided=guided)
    else:
        # Simple append, but in guided mode ask for each v6 section
        if guided:
            v6_content_lines = [l for l in v6_text.splitlines()
                                if l.strip() and not l.strip().startswith("#")]
            if v6_content_lines:
                auto_merged = v4_text.rstrip("\n") + (
                    f"\n\n# === IPv6 {name} (from shorewall6) ===\n"
                    + v6_text)
                result = _ask_block_collision(
                    f"Config file: {name}",
                    v4_text.splitlines(), v6_text.splitlines(),
                    auto_merged.splitlines(), guided)
                out_path.write_text("\n".join(result) + "\n")
                return

        lines = v4_text.rstrip("\n").split("\n")
        lines.append("")
        lines.append(f"# === IPv6 {name} (from shorewall6) ===")
        lines.extend(v6_text.splitlines())
        out_path.write_text("\n".join(lines) + "\n")


def _merge_shorewall_conf(v4_path: Path, v6_path: Path, out_path: Path,
                          guided: bool = False) -> None:
    """Merge shorewall.conf: take v4 as base, handle v6 differences."""
    if not v4_path.exists():
        if v6_path.exists():
            shutil.copy2(v6_path, out_path)
        return

    v4_settings = _parse_conf_settings(v4_path)
    lines = v4_path.read_text(errors="replace").rstrip("\n").split("\n")

    if v6_path.exists():
        v6_settings = _parse_conf_settings(v6_path)

        v6_only: list[str] = []
        for key, v6_line in v6_settings.items():
            if key not in v4_settings:
                v6_only.append(v6_line)
            elif v4_settings[key] != v6_line and guided:
                # Same setting, different value
                result = _ask_collision(
                    f"shorewall.conf: {key}",
                    v4_settings[key], v6_line,
                    v4_settings[key],  # proposal: keep v4
                    guided,
                )
                if result != v4_settings[key]:
                    lines = [result if l.strip().startswith(f"{key}=") else l
                             for l in lines]

        if v6_only:
            lines.append("")
            lines.append("# === IPv6-only settings (from shorewall6) ===")
            lines.extend(v6_only)

    out_path.write_text("\n".join(lines) + "\n")


# ── Main command ─────────────────────────────────────────────────────

@click.command()
@click.argument("shorewall_dir", type=click.Path(exists=True, path_type=Path))
@click.argument("shorewall6_dir", type=click.Path(exists=True, path_type=Path))
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Output directory (default: <parent>/shorewall46)")
@click.option("--guided", is_flag=True, default=False,
              help="Interactive mode: ask on each collision")
@click.option("--no-plugins", is_flag=True, default=False,
              help="Disable plugin enrichment even if plugins.conf exists")
def merge_config(shorewall_dir: Path, shorewall6_dir: Path,
                 output: Path | None, guided: bool, no_plugins: bool = False):
    """Merge Shorewall and Shorewall6 configs into a unified directory.

    Two modes:

      AUTO (default): merges automatically with sensible defaults.
      v4 config is kept as base, v6-only items are added,
      collisions are resolved by keeping v4 and renaming v6.

      GUIDED (--guided): interactive mode that asks on each collision.
      Shows v4 value, v6 value, and a merge proposal. User picks:
      [1] keep v4, [2] keep v6, [3] merge proposal, [4] custom input.
    """
    if output is None:
        output = shorewall_dir.parent / "shorewall46"

    output.mkdir(parents=True, exist_ok=True)

    # Load plugin manager if configured
    plugin_manager = None
    if not no_plugins and (shorewall_dir / "plugins.conf").exists():
        from shorewall_nft.plugins.manager import PluginManager
        plugin_manager = PluginManager(shorewall_dir)
        if plugin_manager.plugins:
            click.echo(
                f"Plugins enabled: "
                f"{', '.join(f'{p.name}({p.priority})' for p in plugin_manager.plugins)}"
            )

    if guided:
        click.secho(f"Guided merge: {shorewall_dir} + {shorewall6_dir}",
                    fg="cyan", bold=True)
        click.echo(f"Output: {output}\n")

    # 1. Copy v4 base files (excluding special ones we merge explicitly)
    merge_files = {"zones", "interfaces", "policy", "rules", "params",
                   "shorewall.conf", "shorewall6.conf",
                   "masq", "conntrack", "notrack", "blrules"}
    for f in shorewall_dir.iterdir():
        if f.is_file() and not f.name.startswith(".") and not f.name.endswith(".bak"):
            if f.name not in merge_files:
                shutil.copy2(f, output / f.name)

    # 2. Copy macros directory
    macros_v4 = shorewall_dir / "macros"
    if macros_v4.is_dir():
        shutil.copytree(macros_v4, output / "macros", dirs_exist_ok=True)

    rules_d_v4 = shorewall_dir / "rules.d"
    if rules_d_v4.is_dir():
        shutil.copytree(rules_d_v4, output / "rules.d", dirs_exist_ok=True)

    # 3. Merge v6 macros
    macros_v6 = shorewall6_dir / "macros"
    if macros_v6.is_dir():
        macros_out = output / "macros"
        macros_out.mkdir(exist_ok=True)
        for f in macros_v6.iterdir():
            if f.is_file():
                target = macros_out / f.name
                if target.exists():
                    v4_text = target.read_text(errors="replace")
                    v6_text = f.read_text(errors="replace")
                    if v6_text.strip() != v4_text.strip():
                        if guided:
                            auto = v4_text.rstrip("\n") + (
                                "\n# IPv6 entries from shorewall6\n" + v6_text)
                            result = _ask_block_collision(
                                f"Macro: {f.name}",
                                v4_text.splitlines(), v6_text.splitlines(),
                                auto.splitlines(), guided)
                            target.write_text("\n".join(result) + "\n")
                        else:
                            with open(target, "a") as mf:
                                mf.write("\n# IPv6 entries from shorewall6\n")
                                mf.write(v6_text)
                else:
                    shutil.copy2(f, target)

    # 4. Smart merges
    _merge_zones(shorewall_dir / "zones", shorewall6_dir / "zones",
                 output / "zones", guided=guided)

    _merge_interfaces(shorewall_dir / "interfaces",
                      shorewall6_dir / "interfaces",
                      output / "interfaces", guided=guided)

    _merge_policies(shorewall_dir / "policy", shorewall6_dir / "policy",
                    output / "policy", guided=guided)

    # Compute which variable names need $VAR → $VAR_V6 rewriting in v6 rules.
    # These are variables defined in BOTH v4 and v6 with different values —
    # they get the _V6 suffix in the merged params file, so v6 rules that
    # reference them must be updated accordingly.
    v4_params_pre = _parse_params(shorewall_dir / "params")
    v6_params_pre = _parse_params(shorewall6_dir / "params")
    v6_var_rewrites = _compute_v6_var_rewrites(v4_params_pre, v6_params_pre)

    _merge_rules(shorewall_dir / "rules", shorewall6_dir / "rules",
                 output / "rules", guided=guided,
                 plugin_manager=plugin_manager,
                 v6_var_rewrites=v6_var_rewrites)

    _merge_params(shorewall_dir / "params", shorewall6_dir / "params",
                  output / "params", guided=guided,
                  plugin_manager=plugin_manager)

    _merge_shorewall_conf(shorewall_dir / "shorewall.conf",
                          shorewall6_dir / "shorewall6.conf",
                          output / "shorewall.conf", guided=guided)

    # 5. Merge other config files
    for name in ("masq", "conntrack", "notrack", "blrules"):
        _merge_config_file(shorewall_dir / name, shorewall6_dir / name,
                           output / name, name, guided=guided)

    # Report
    file_count = len(list(output.iterdir()))
    click.echo(f"\nMerged config written to {output}")
    click.echo(f"  {file_count} files/dirs")

    v4_zones = _parse_zones(shorewall_dir / "zones")
    v6_zones = _parse_zones(shorewall6_dir / "zones")
    v6_unique_zones = {n for n in v6_zones if n not in v4_zones and n != "fw"}
    dup_zones = {n for n in v6_zones if n in v4_zones and n != "fw"}

    if dup_zones:
        click.echo(f"  Zones: {len(dup_zones)} identical dropped, "
                   f"{len(v6_unique_zones)} IPv6-only added")

    _, v4_blocks = _parse_comment_blocks(shorewall_dir / "rules")
    _, v6_blocks = _parse_comment_blocks(shorewall6_dir / "rules")
    merged = {t for t in v6_blocks if t in v4_blocks}
    v6_only = {t for t in v6_blocks if t not in v4_blocks}
    if merged or v6_only:
        click.echo(f"  Rules: {len(merged)} mandant blocks merged, "
                   f"{len(v6_only)} IPv6-only appended")

    if plugin_manager is not None and plugin_manager.plugins:
        v4p = _parse_params(shorewall_dir / "params")
        v6p = _parse_params(shorewall6_dir / "params")
        pe = plugin_manager.enrich_params(v4p, v6p)
        if pe.pairs:
            click.echo(f"  Plugins: {len(pe.pairs)} v4/v6 param pairs detected")


if __name__ == "__main__":
    merge_config()
