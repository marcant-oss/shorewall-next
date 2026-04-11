"""Plugin system for shorewall-nft.

Plugins extend shorewall-nft with:
- IP address lookups and v4↔v6 mappings
- Comment block enrichment (e.g. with customer data)
- Params pair detection
- Custom CLI commands

Built-in plugins:
- ip-info: pattern-based v4↔v6 mapping (fallback)
- netbox: authoritative source via Netbox API
"""

from shorewall_nft.plugins.base import (
    EnrichResult,
    ParamEnrichResult,
    Plugin,
)
from shorewall_nft.plugins.manager import PluginManager

__all__ = ["Plugin", "EnrichResult", "ParamEnrichResult", "PluginManager"]
