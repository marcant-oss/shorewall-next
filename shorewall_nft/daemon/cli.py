"""shorewalld CLI entry point.

Parses command-line arguments and launches the ``Daemon`` asyncio loop.
Kept intentionally thin — everything non-trivial lives in ``core.py`` /
``exporter.py`` / ``discover.py`` / ``api_server.py`` and is unit-testable
without the CLI.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys


def _parse_listen_addr(spec: str) -> tuple[str, int]:
    """Parse a ``host:port`` or ``:port`` listen spec.

    Empty host means "bind to all interfaces".
    """
    if ":" not in spec:
        raise argparse.ArgumentTypeError(
            f"expected host:port or :port, got {spec!r}")
    host, _, port_s = spec.rpartition(":")
    try:
        port = int(port_s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            f"invalid port in {spec!r}: {e}") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            f"port {port} out of range")
    return (host or "0.0.0.0", port)


def _parse_netns_spec(spec: str) -> list[str] | str:
    """Parse ``--netns`` into a list, or the literal ``"auto"``.

    Empty spec / unset means "only the daemon's own netns", which
    we represent as a single-entry list ``[""]``.
    """
    s = spec.strip()
    if not s:
        return [""]
    if s == "auto":
        return "auto"
    return [p.strip() for p in s.split(",") if p.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shorewalld",
        description="shorewall-nft monitoring + DNS-set API daemon")
    p.add_argument(
        "--listen-prom", default=":9748", metavar="HOST:PORT",
        help="Prometheus scrape endpoint (default: :9748)")
    p.add_argument(
        "--listen-api", default=None, metavar="PATH",
        help="unix socket path for the DNS sidecar API "
             "(off by default — Phase 4 opt-in)")
    p.add_argument(
        "--netns", default="", metavar="SPEC",
        help="namespace selection: empty=own netns, "
             "'auto'=walk /run/netns/, or comma list like 'fw,rns1,rns2'")
    p.add_argument(
        "--scrape-interval", type=float, default=30.0, metavar="SECS",
        help="minimum age (s) for cached counters before a fresh scrape "
             "(default: 30)")
    p.add_argument(
        "--reprobe-interval", type=float, default=300.0, metavar="SECS",
        help="how often (s) to re-check whether a netns has acquired or "
             "lost its 'inet shorewall' table (default: 300)")
    p.add_argument(
        "--log-level", default="info",
        choices=("debug", "info", "warning", "error"),
        help="log level (default: info)")
    return p


def main(argv: list[str] | None = None) -> int:
    """shorewalld entry point. Returns exit code."""
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    prom_host, prom_port = _parse_listen_addr(args.listen_prom)
    netns_spec = _parse_netns_spec(args.netns)

    # Imported lazily so --help works without prometheus_client installed.
    from .core import Daemon

    daemon = Daemon(
        prom_host=prom_host,
        prom_port=prom_port,
        api_socket=args.listen_api,
        netns_spec=netns_spec,
        scrape_interval=args.scrape_interval,
        reprobe_interval=args.reprobe_interval,
    )
    try:
        return asyncio.run(daemon.run())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
