"""Plugin manager: discovery, loading, priority-ordered dispatch."""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from shorewall_nft.plugins.base import (
    EnrichResult,
    ParamEnrichResult,
    Plugin,
)

if TYPE_CHECKING:
    import click


# Mapping from plugin name (in plugins.conf) to module path
_BUILTIN_PLUGINS = {
    "ip-info": "shorewall_nft.plugins.builtin.ip_info:IpInfoPlugin",
    "netbox": "shorewall_nft.plugins.builtin.netbox:NetboxPlugin",
}


class PluginManager:
    """Loads and dispatches to plugins.

    Plugins are sorted by priority (DESC) so highest-priority plugins
    are asked first in priority-ordered lookups.
    """

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.plugins: list[Plugin] = []
        self._load_config()

    def _load_config(self) -> None:
        """Load plugins.conf and instantiate enabled plugins."""
        conf_path = self.config_dir / "plugins.conf"
        if not conf_path.exists():
            return

        with open(conf_path, "rb") as f:
            data = tomllib.load(f)

        for entry in data.get("plugins", []):
            name = entry.get("name")
            if not name:
                continue
            if not entry.get("enabled", True):
                continue

            plugin_cls = _resolve_plugin_class(name)
            if plugin_cls is None:
                # Unknown plugin — skip silently (will be reported by plugins list)
                continue

            # Load plugin-specific config
            plugin_config_path = self.config_dir / "plugins" / f"{name}.toml"
            plugin_config: dict = {}
            if plugin_config_path.exists():
                with open(plugin_config_path, "rb") as f:
                    plugin_config = tomllib.load(f)

            try:
                instance = plugin_cls(plugin_config, self.config_dir)
                instance.load()
                self.plugins.append(instance)
            except Exception as e:
                # Don't crash merge-config if a plugin fails to load
                import sys
                print(f"Warning: plugin '{name}' failed to load: {e}",
                      file=sys.stderr)

        # Sort by priority DESC
        self.plugins.sort(key=lambda p: -p.priority)

    # ── Priority-ordered lookups (first non-None wins) ──

    def map_v4_to_v6(self, ip: str) -> str | None:
        """Ask plugins in priority order, return first non-None result."""
        for plugin in self.plugins:
            result = plugin.map_v4_to_v6(ip)
            if result is not None:
                return result
        return None

    def map_v6_to_v4(self, ip: str) -> str | None:
        """Ask plugins in priority order, return first non-None result."""
        for plugin in self.plugins:
            result = plugin.map_v6_to_v4(ip)
            if result is not None:
                return result
        return None

    def lookup_ip(self, ip: str) -> dict:
        """Aggregate info from all plugins.

        Higher-priority plugins take precedence on key conflicts.
        Returns {} if no plugin has info.
        """
        merged: dict = {}
        # Iterate in reverse priority order so high-priority overrides
        for plugin in reversed(self.plugins):
            result = plugin.lookup_ip(ip)
            if result:
                merged.update(result)
        # Add a "_sources" list for transparency
        sources = [p.name for p in self.plugins if p.lookup_ip(ip)]
        if sources:
            merged["_sources"] = sources
        return merged

    # ── Merge enrichment (aggregates from all plugins) ──

    def enrich_comment_block(
        self, tag: str, v4_rules: list[str], v6_rules: list[str]
    ) -> EnrichResult:
        """Call all plugins, merge their EnrichResults in priority order."""
        combined = EnrichResult()
        for plugin in self.plugins:
            result = plugin.enrich_comment_block(tag, v4_rules, v6_rules)
            if result.is_empty():
                continue
            # Higher-priority tag rename wins (first plugin sets it)
            if combined.tag is None and result.tag is not None:
                combined.tag = result.tag
            combined.prepend_comments.extend(result.prepend_comments)
            combined.append_comments.extend(result.append_comments)
            # replace_rules: first plugin that sets it wins
            if combined.replace_rules is None and result.replace_rules is not None:
                combined.replace_rules = result.replace_rules
            if result.drop:
                combined.drop = True
        return combined

    def enrich_params(
        self, v4_params: dict[str, str], v6_params: dict[str, str]
    ) -> ParamEnrichResult:
        """Call all plugins, merge their ParamEnrichResults."""
        combined = ParamEnrichResult()
        for plugin in self.plugins:
            result = plugin.enrich_params(v4_params, v6_params)
            # Higher-priority pairs win
            for varname, pair in result.pairs.items():
                if varname not in combined.pairs:
                    combined.pairs[varname] = pair
            for varname, ann in result.annotations.items():
                if varname not in combined.annotations:
                    combined.annotations[varname] = ann
        return combined

    # ── Lifecycle ──

    def refresh_all(self) -> None:
        """Refresh cached data in all plugins."""
        for plugin in self.plugins:
            plugin.refresh()

    # ── CLI registration ──

    def register_cli_commands(self, cli_group: "click.Group") -> None:
        """Let each plugin register its own commands."""
        for plugin in self.plugins:
            try:
                plugin.register_cli(cli_group)
            except Exception as e:
                import sys
                print(f"Warning: plugin '{plugin.name}' failed to "
                      f"register CLI: {e}", file=sys.stderr)


def _resolve_plugin_class(name: str) -> type[Plugin] | None:
    """Resolve a plugin name to its class via the built-in registry."""
    spec = _BUILTIN_PLUGINS.get(name)
    if not spec:
        return None
    module_path, _, class_name = spec.partition(":")
    try:
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except (ImportError, AttributeError):
        return None
