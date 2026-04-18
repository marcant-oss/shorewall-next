"""``shorewalld iplist`` — IP list provider CLI.

Subcommands::

    shorewalld iplist providers
        List all registered providers with their filter dimensions.

    shorewalld iplist filters <provider> --dimension <dim>
        Fetch the source and list available values for <dim>.

    shorewalld iplist show <provider> --filters key:val,... [--family v4|v6]
        Fetch, filter, and print matching prefixes.

No shell-out; all fetching is done via aiohttp in-process.
"""

from __future__ import annotations

import argparse
import asyncio
import sys


def _build_iplist_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shorewalld iplist",
        description="Inspect and query IP list providers",
    )
    sub = p.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")
    sub.required = True

    sub.add_parser(
        "providers",
        help="List all registered providers (no network access)",
    )

    fp = sub.add_parser(
        "filters",
        help="List available filter dimension values for a provider",
    )
    fp.add_argument("provider", help="Provider name (e.g. aws, gcp, bogon)")
    fp.add_argument(
        "--dimension", "-d", required=True, metavar="DIM",
        help="Dimension name to enumerate (e.g. service, region, group)",
    )

    sp = sub.add_parser(
        "show",
        help="Fetch and print matching prefixes from a provider",
    )
    sp.add_argument("provider", help="Provider name")
    sp.add_argument(
        "--filters", default="", metavar="KEY:VAL,...",
        help="Comma-separated filter key:value pairs "
             "(e.g. service:EC2,region:eu-*)",
    )
    sp.add_argument(
        "--family", choices=("v4", "v6", "both"), default="both",
        help="Address family to show (default: both)",
    )

    return p


def _parse_filters(spec: str) -> dict[str, list[str]]:
    """Parse ``key:val,key2:val2`` into ``{key: [val], key2: [val2]}``."""
    result: dict[str, list[str]] = {}
    if not spec:
        return result
    for pair in spec.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" in pair:
            key, _, val = pair.partition(":")
            result.setdefault(key.strip(), []).append(val.strip())
        else:
            # Boolean filter — treat as key with empty value list.
            result.setdefault(pair, [])
    return result


async def _cmd_providers() -> int:
    from .iplist.providers import REGISTRY

    if not REGISTRY:
        print("(no providers registered)")
        return 0

    col_w = max(len(name) for name in REGISTRY) + 2
    print(f"{'PROVIDER':<{col_w}}  FILTER DIMENSIONS      SOURCE URL")
    print("-" * 80)
    for name in sorted(REGISTRY):
        cls = REGISTRY[name]
        dims = ", ".join(getattr(cls, "filter_dimensions", []))
        url = getattr(cls, "source_url", "(none)")
        # Truncate URL if needed.
        if len(url) > 40:
            url = url[:37] + "..."
        print(f"{name:<{col_w}}  {dims:<22} {url}")
    return 0


async def _cmd_filters(provider_name: str, dimension: str) -> int:
    from .iplist.providers import get_provider

    try:
        provider_cls = get_provider(provider_name)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    provider = provider_cls()
    dims = getattr(provider, "filter_dimensions", [])
    if dimension not in dims:
        print(
            f"error: provider {provider_name!r} does not support "
            f"dimension {dimension!r}; available: {dims}",
            file=sys.stderr,
        )
        return 1

    # Bogon provider doesn't need HTTP.
    if provider_name == "bogon":
        from .iplist.providers.bogon import _SENTINEL_RAW
        values = provider.list_dimension(_SENTINEL_RAW, dimension)
        for v in values:
            print(v)
        return 0

    # For other providers, fetch first.
    try:
        import aiohttp
    except ImportError:
        print(
            "error: aiohttp not installed; "
            "pip install shorewalld[iplist]",
            file=sys.stderr,
        )
        return 1

    print(
        f"Fetching {getattr(provider, 'source_url', '...')} ...",
        file=sys.stderr,
    )
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            headers={"User-Agent": "shorewalld-cli/1.0"},
        ) as session:
            result = await provider.fetch(session, None, None)
    except Exception as e:
        print(f"error: fetch failed: {e}", file=sys.stderr)
        return 1

    values = provider.list_dimension(result.raw, dimension)
    for v in values:
        print(v)
    return 0


async def _cmd_show(
    provider_name: str, filters_spec: str, family: str
) -> int:
    from .iplist.providers import get_provider

    try:
        provider_cls = get_provider(provider_name)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    provider = provider_cls()
    filters = _parse_filters(filters_spec)

    # Bogon provider doesn't need HTTP.
    if provider_name == "bogon":
        from .iplist.providers.bogon import _SENTINEL_RAW
        v4, v6 = provider.extract(_SENTINEL_RAW, filters)
        _print_prefixes(v4, v6, family)
        return 0

    try:
        import aiohttp
    except ImportError:
        print(
            "error: aiohttp not installed; "
            "pip install shorewalld[iplist]",
            file=sys.stderr,
        )
        return 1

    print(
        f"Fetching {getattr(provider, 'source_url', '...')} ...",
        file=sys.stderr,
    )
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            headers={"User-Agent": "shorewalld-cli/1.0"},
        ) as session:
            result = await provider.fetch(session, None, None)
    except Exception as e:
        print(f"error: fetch failed: {e}", file=sys.stderr)
        return 1

    try:
        v4, v6 = provider.extract(result.raw, filters)
    except Exception as e:
        print(f"error: extract failed: {e}", file=sys.stderr)
        return 1

    _print_prefixes(v4, v6, family)
    return 0


def _print_prefixes(v4: set[str], v6: set[str], family: str) -> None:
    if family in ("v4", "both"):
        for p in sorted(v4):
            print(p)
    if family in ("v6", "both"):
        for p in sorted(v6):
            print(p)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``shorewalld iplist``."""
    parser = _build_iplist_parser()
    args = parser.parse_args(argv)

    if args.subcommand == "providers":
        coro = _cmd_providers()
    elif args.subcommand == "filters":
        coro = _cmd_filters(args.provider, args.dimension)
    elif args.subcommand == "show":
        coro = _cmd_show(args.provider, args.filters, args.family)
    else:
        parser.print_help()
        return 1

    return asyncio.run(coro)
