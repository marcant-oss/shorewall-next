"""Provider / Multi-ISP policy routing support.

Handles providers, routes, and rtrules config files.
Generates nft mark rules for policy routing and ip rule commands.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shorewall_nft.config.parser import ConfigLine


@dataclass
class Provider:
    """A routing provider (ISP)."""
    name: str
    number: int
    mark: int
    interface: str
    gateway: str | None = None
    options: list[str] = field(default_factory=list)
    table: str = ""


@dataclass
class Route:
    """A static route for a provider."""
    provider: str
    dest: str
    gateway: str | None = None
    device: str | None = None


@dataclass
class RoutingRule:
    """An ip rule for policy routing."""
    source: str | None = None
    dest: str | None = None
    provider: str | None = None
    priority: int = 0


def parse_providers(lines: list[ConfigLine]) -> list[Provider]:
    """Parse providers config file.

    Format: NAME NUMBER MARK INTERFACE GATEWAY OPTIONS
    """
    providers = []
    for line in lines:
        cols = line.columns
        if len(cols) < 4:
            continue
        name = cols[0]
        try:
            number = int(cols[1])
            mark = int(cols[2])
        except ValueError:
            continue
        interface = cols[3]
        gateway = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        options = cols[5].split(",") if len(cols) > 5 and cols[5] != "-" else []

        providers.append(Provider(
            name=name, number=number, mark=mark,
            interface=interface, gateway=gateway, options=options,
            table=str(number),
        ))
    return providers


def parse_routes(lines: list[ConfigLine]) -> list[Route]:
    """Parse routes config file.

    Format: PROVIDER DEST GATEWAY DEVICE
    """
    routes = []
    for line in lines:
        cols = line.columns
        if len(cols) < 2:
            continue
        routes.append(Route(
            provider=cols[0],
            dest=cols[1],
            gateway=cols[2] if len(cols) > 2 and cols[2] != "-" else None,
            device=cols[3] if len(cols) > 3 and cols[3] != "-" else None,
        ))
    return routes


def parse_rtrules(lines: list[ConfigLine]) -> list[RoutingRule]:
    """Parse rtrules config file.

    Format: SOURCE DEST PROVIDER PRIORITY
    """
    rules = []
    for line in lines:
        cols = line.columns
        if len(cols) < 3:
            continue
        rules.append(RoutingRule(
            source=cols[0] if cols[0] != "-" else None,
            dest=cols[1] if cols[1] != "-" else None,
            provider=cols[2],
            priority=int(cols[3]) if len(cols) > 3 and cols[3] != "-" else 0,
        ))
    return rules
