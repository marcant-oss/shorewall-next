"""shorewalld — async monitoring + DNS-set API daemon.

Exposes per-netns nftables counters as Prometheus metrics and (opt-in)
accepts DNS response frames from a recursor sidecar for dynamic nft
set population. See docs/roadmap/shorewalld.md for the design.
"""

from __future__ import annotations

from .cli import main

__all__ = ["main"]
