"""Plugin base class and result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import click


@dataclass
class EnrichResult:
    """Result of enriching a ?COMMENT block."""

    tag: str | None = None
    """Rename the ?COMMENT tag (e.g. add '(Kunde 12345)'). None = keep."""

    prepend_comments: list[str] = field(default_factory=list)
    """Comment lines to add at the top of the block (after the ?COMMENT tag)."""

    append_comments: list[str] = field(default_factory=list)
    """Comment lines to add at the bottom of the block (before the closing ?COMMENT)."""

    replace_rules: list[str] | None = None
    """If set, replace the entire block content with these lines. None = keep."""

    drop: bool = False
    """If True, drop the entire block from output."""

    def is_empty(self) -> bool:
        return (self.tag is None and not self.prepend_comments
                and not self.append_comments and self.replace_rules is None
                and not self.drop)


@dataclass
class ParamEnrichResult:
    """Result of analyzing v4/v6 params for pairs."""

    pairs: dict[str, tuple[str, str]] = field(default_factory=dict)
    """{varname: (v4_line, v6_line)} — paired v4/v6 params for the same host.

    merge_params emits these with a grouping comment:
        # --- MAIL5 (v4/v6 pair) ---
        MAIL5=203.0.113.86
        MAIL5_V6=2001:db8:0:100:203:0:113:86
    """

    annotations: dict[str, str] = field(default_factory=dict)
    """{varname: comment} — extra comment to add above a param (e.g. customer info)."""


class Plugin:
    """Base class for shorewall-nft plugins.

    Subclasses should override:
    - `name` and `version` class attributes
    - `priority` (higher = asked first in priority-ordered lookups)
    - relevant hook methods (return None if not applicable)
    """

    name: str = ""
    version: str = "0.0.0"
    priority: int = 50

    def __init__(self, config: dict, config_dir: Path):
        """Initialize the plugin.

        Args:
            config: Plugin-specific settings (from plugins/<name>.toml).
            config_dir: Shorewall config directory (for locating cache files).
        """
        self.config = config
        self.config_dir = config_dir

    # ── Lifecycle hooks ──

    def load(self) -> None:
        """Load static data or cached state from disk."""

    def refresh(self) -> None:
        """Refresh from external source (e.g. API). No-op for offline plugins."""

    # ── Data lookup hooks (return None if plugin has no info) ──

    def lookup_ip(self, ip: str) -> dict | None:
        """Return metadata dict for an IP, or None if unknown."""
        return None

    def map_v4_to_v6(self, ip: str) -> str | None:
        """Map v4 address to its v6 equivalent, or None if unknown."""
        return None

    def map_v6_to_v4(self, ip: str) -> str | None:
        """Map v6 address to its v4 equivalent, or None if unknown."""
        return None

    # ── Merge hooks ──

    def enrich_comment_block(
        self, tag: str, v4_rules: list[str], v6_rules: list[str]
    ) -> EnrichResult:
        """Enrich a ?COMMENT-tagged block during merge-config.

        Args:
            tag: The ?COMMENT tag name (e.g. "mandant-b").
            v4_rules: Rule lines from the v4 block (excluding ?COMMENT directives).
            v6_rules: Rule lines from the v6 block (may be empty).

        Returns:
            EnrichResult with comments/tag changes.
        """
        return EnrichResult()

    def enrich_params(
        self, v4_params: dict[str, str], v6_params: dict[str, str]
    ) -> ParamEnrichResult:
        """Detect paired v4/v6 params and add annotations.

        Args:
            v4_params: {varname: full_line} from v4 params file.
            v6_params: {varname: full_line} from v6 params file.

        Returns:
            ParamEnrichResult with detected pairs.
        """
        return ParamEnrichResult()

    # ── CLI registration ──

    def register_cli(self, cli_group: "click.Group") -> None:
        """Register plugin-specific commands under a subgroup.

        The plugin should add its commands as a subgroup named after `self.name`.
        Example: creates `shorewall-nft ip-info v4-to-v6 <ip>`.
        """
