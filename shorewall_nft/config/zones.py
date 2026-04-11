"""Zone and interface model for Shorewall configuration.

Parses zones, interfaces, and hosts config files into a structured model.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shorewall_nft.config.parser import ShorewalConfig


@dataclass
class Interface:
    """A network interface assigned to a zone."""
    name: str
    zone: str
    broadcast: str | None = None
    options: list[str] = field(default_factory=list)


@dataclass
class Host:
    """A host group within a zone."""
    zone: str
    interface: str
    addresses: list[str] = field(default_factory=list)
    options: list[str] = field(default_factory=list)


# Valid Shorewall zone types
ZONE_TYPES = {"firewall", "ipv4", "ipv6", "ipsec", "ipsec4", "ipsec6",
              "bport", "bport4", "bport6", "vserver", "loopback", "local"}


@dataclass
class Zone:
    """A firewall zone."""
    name: str
    zone_type: str  # firewall, ipv4, ipv6, bport4, bport6, ipsec, ...
    parent: str | None = None  # Parent zone for nested zones (bport)
    interfaces: list[Interface] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    in_options: list[str] = field(default_factory=list)
    out_options: list[str] = field(default_factory=list)

    @property
    def is_firewall(self) -> bool:
        return self.zone_type == "firewall"

    @property
    def is_ipv4(self) -> bool:
        return self.zone_type in ("ipv4", "bport4", "ipsec4")

    @property
    def is_ipv6(self) -> bool:
        return self.zone_type in ("ipv6", "bport6", "ipsec6")

    @property
    def is_bport(self) -> bool:
        return self.zone_type in ("bport", "bport4", "bport6")


@dataclass
class ZoneModel:
    """Complete zone/interface model."""
    zones: dict[str, Zone] = field(default_factory=dict)
    firewall_zone: str = ""

    def get_zone(self, name: str) -> Zone:
        """Get a zone by name. Raises KeyError if not found."""
        if name == "$FW" or name == "fw":
            name = self.firewall_zone
        return self.zones[name]

    def zone_names(self) -> list[str]:
        """Return all zone names excluding the firewall zone."""
        return [z for z in self.zones if z != self.firewall_zone]

    def all_zone_names(self) -> list[str]:
        """Return all zone names including the firewall zone."""
        return list(self.zones.keys())


def build_zone_model(config: ShorewalConfig) -> ZoneModel:
    """Build the zone model from parsed config."""
    model = ZoneModel()

    # Parse zones
    for line in config.zones:
        cols = line.columns
        name = cols[0]
        zone_type = cols[1] if len(cols) > 1 else "ipv4"
        options = _parse_options(cols[2]) if len(cols) > 2 else []
        in_options = _parse_options(cols[3]) if len(cols) > 3 else []
        out_options = _parse_options(cols[4]) if len(cols) > 4 else []

        # Handle parent zone syntax: ZONE:PARENT or type:parent
        parent = None
        if ":" in name:
            name, parent = name.split(":", 1)
        if ":" in zone_type:
            zone_type, parent = zone_type.split(":", 1)

        zone = Zone(
            name=name,
            zone_type=zone_type,
            parent=parent,
            options=options,
            in_options=in_options,
            out_options=out_options,
        )
        model.zones[name] = zone

        if zone_type == "firewall":
            model.firewall_zone = name

    # Parse interfaces
    for line in config.interfaces:
        cols = line.columns
        zone_name = cols[0]
        iface_name = cols[1]
        broadcast = cols[2] if len(cols) > 2 else None
        options = _parse_options(cols[3]) if len(cols) > 3 else []

        # Shorewall bridge-port syntax: "bridge:port" means the interface
        # is a port on a bridge. Linux kernel interface names cannot
        # contain colons, so the actual interface for nft matching is
        # just the port side. The bridge name is informational only.
        if ":" in iface_name:
            bridge, port = iface_name.split(":", 1)
            iface_name = port

        if broadcast == "-" or broadcast == "detect":
            broadcast = None

        iface = Interface(
            name=iface_name,
            zone=zone_name,
            broadcast=broadcast,
            options=options,
        )

        if zone_name in model.zones:
            model.zones[zone_name].interfaces.append(iface)

    # Parse hosts
    for line in config.hosts:
        cols = line.columns
        zone_name = cols[0]
        # Format: ZONE HOST(S) [OPTIONS]
        # HOST(S) is interface:address[,address...]
        host_spec = cols[1] if len(cols) > 1 else ""
        options = _parse_options(cols[2]) if len(cols) > 2 else []

        if ":" in host_spec:
            iface, addr_str = host_spec.split(":", 1)
            addresses = [a.strip() for a in addr_str.split(",")]
        else:
            iface = host_spec
            addresses = []

        host = Host(
            zone=zone_name,
            interface=iface,
            addresses=addresses,
            options=options,
        )

        if zone_name in model.zones:
            model.zones[zone_name].hosts.append(host)

    if not model.firewall_zone:
        raise ValueError("No firewall zone defined in zones config")

    return model


def _parse_options(text: str) -> list[str]:
    """Parse a comma-separated options string."""
    if not text or text == "-":
        return []
    return [o.strip() for o in text.split(",") if o.strip()]
