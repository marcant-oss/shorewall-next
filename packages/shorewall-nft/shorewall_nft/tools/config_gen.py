"""Random Shorewall config generator for fuzz-testing.

Generates syntactically and semantically valid Shorewall configs
with randomized zones, interfaces, policies, and rules.
Reproducible via seed.

Usage:
    gen = ConfigGenerator(seed=42)
    gen.generate(Path("/tmp/random-fw"), num_zones=5, num_rules=50)
"""

from __future__ import annotations

import random
from pathlib import Path

# Pool of realistic zone names
_ZONE_NAMES = [
    "net", "loc", "dmz", "web", "srv", "mgmt", "vpn", "guest",
    "iot", "voip", "cam", "stor", "dev", "test", "prod", "lab",
    "ext", "int", "wan", "lan", "wifi", "infra", "mon", "db",
    "app", "mail", "dns", "ntp", "log", "bkup",
]

# Macros for rule generation
_MACROS = [
    "SSH", "DNS", "HTTP", "HTTPS", "Ping", "NTP", "SMTP", "FTP",
    "Web", "SNMP", "Syslog", "MySQL", "PostgreSQL", "RDP",
    "LDAP", "LDAPS", "IMAP", "IMAPS", "POP3", "Telnet",
]

_ACTIONS = ["ACCEPT", "DROP", "REJECT"]
_POLICIES = ["ACCEPT", "DROP", "REJECT"]


class ConfigGenerator:
    """Generate random but valid Shorewall configurations."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self._subnet_counter = 0

    def generate(self, output_dir: Path, *,
                 num_zones: int = 5,
                 num_rules: int = 50,
                 dual_stack: bool = False,
                 features: set[str] | None = None) -> None:
        """Generate a complete Shorewall config directory."""
        if features is None:
            features = {"macros", "rfc1918", "nat"}

        output_dir.mkdir(parents=True, exist_ok=True)
        num_zones = min(num_zones, len(_ZONE_NAMES))

        # Pick zone names
        zone_names = self.rng.sample(_ZONE_NAMES, num_zones)

        # Generate files
        self._gen_shorewall_conf(output_dir, features)
        self._gen_params(output_dir, zone_names)
        self._gen_zones(output_dir, zone_names)
        interfaces = self._gen_interfaces(output_dir, zone_names, features)
        self._gen_policy(output_dir, zone_names)
        self._gen_rules(output_dir, zone_names, num_rules, features)

        if "nat" in features:
            self._gen_masq(output_dir, zone_names, interfaces)

        if dual_stack:
            self._gen_ipv6(output_dir, zone_names)

    def _next_subnet(self) -> str:
        """Generate a unique /24 subnet."""
        self._subnet_counter += 1
        second = (self._subnet_counter // 256) + 10
        third = self._subnet_counter % 256
        return f"172.{second}.{third}"

    def _gen_shorewall_conf(self, d: Path, features: set[str]) -> None:
        lines = [
            "STARTUP_ENABLED=Yes",
            "VERBOSITY=1",
            'LOGFORMAT="Shorewall:%s:%s:"',
            "IP_FORWARDING=On",
            f"FASTACCEPT={'No' if 'accounting' in features else 'Yes'}",
            "OPTIMIZE=8",
        ]
        if "blacklist" in features:
            lines.append("DYNAMIC_BLACKLIST=Yes")
        (d / "shorewall.conf").write_text("\n".join(lines) + "\n")

    def _gen_params(self, d: Path, zones: list[str]) -> None:
        lines = ["LOG=info"]
        for z in zones:
            subnet = self._next_subnet()
            lines.append(f"{z.upper()}_NET={subnet}.0/24")
            lines.append(f"{z.upper()}_GW={subnet}.1")
            # A few host IPs
            for i in range(2, self.rng.randint(3, 6)):
                lines.append(f"{z.upper()}_HOST{i}={subnet}.{i}")
        (d / "params").write_text("\n".join(lines) + "\n")

    def _gen_zones(self, d: Path, zones: list[str]) -> None:
        lines = ["fw\tfirewall"]
        for z in zones:
            lines.append(f"{z}\tipv4")
        (d / "zones").write_text("\n".join(lines) + "\n")

    def _gen_interfaces(self, d: Path, zones: list[str],
                        features: set[str]) -> dict[str, str]:
        """Generate interfaces file. Returns {zone: interface_name}."""
        interfaces: dict[str, str] = {}
        lines = []
        for i, z in enumerate(zones):
            iface = f"eth{i}"
            opts = ["tcpflags"]
            if self.rng.random() < 0.3:
                opts.append("nosmurfs")
            if self.rng.random() < 0.2:
                opts.append("routefilter")
            if self.rng.random() < 0.15 and "dhcp" in (features or set()):
                opts.append("dhcp")
            if self.rng.random() < 0.1:
                opts.append("routeback")
            lines.append(f"{z}\t{iface}\tdetect\t{','.join(opts)}")
            interfaces[z] = iface
        (d / "interfaces").write_text("\n".join(lines) + "\n")
        return interfaces

    def _gen_policy(self, d: Path, zones: list[str]) -> None:
        lines = ["$FW\tall\tACCEPT"]
        for z in zones:
            if z == zones[0]:
                # First zone (usually "net") → DROP to all
                lines.append(f"{z}\tall\tDROP\t$LOG")
            else:
                # Other zones → mostly REJECT
                policy = self.rng.choice(["REJECT", "REJECT", "DROP"])
                lines.append(f"{z}\tall\t{policy}\t$LOG")
        lines.append("all\tall\tREJECT\t$LOG")
        (d / "policy").write_text("\n".join(lines) + "\n")

    def _gen_rules(self, d: Path, zones: list[str],
                   num_rules: int, features: set[str]) -> None:
        lines = ["?SECTION NEW"]

        for _ in range(num_rules):
            rule_type = self.rng.choice(["macro", "plain", "macro", "plain", "rfc1918"])

            if rule_type == "rfc1918" and "rfc1918" in features:
                src = self.rng.choice(zones)
                lines.append(f"Rfc1918/DROP:$LOG\t{src}\tall")

            elif rule_type == "macro" and "macros" in features:
                macro = self.rng.choice(_MACROS)
                action = self.rng.choice(["ACCEPT", "ACCEPT", "DROP"])
                src = self.rng.choice(["all"] + zones)
                dst = self.rng.choice(["all", "$FW"] + zones)
                if src == dst and src != "all":
                    dst = "$FW"
                lines.append(f"{macro}({action})\t{src}\t{dst}")

            else:
                action = self.rng.choice(_ACTIONS)
                src = self.rng.choice(["all"] + zones)
                dst = self.rng.choice(["all", "$FW"] + zones)
                if src == dst and src != "all":
                    dst = "$FW"
                proto = self.rng.choice(["tcp", "udp", "icmp"])
                if proto == "icmp":
                    lines.append(f"{action}\t{src}\t{dst}\ticmp")
                else:
                    port = self.rng.randint(1, 65535)
                    lines.append(f"{action}\t{src}\t{dst}\t{proto}\t{port}")

        (d / "rules").write_text("\n".join(lines) + "\n")

    def _gen_masq(self, d: Path, zones: list[str],
                  interfaces: dict[str, str]) -> None:
        if len(zones) < 2:
            return
        net_zone = zones[0]
        iface = interfaces.get(net_zone, "eth0")
        subnet = self._next_subnet()
        lines = [f"{iface}\t{subnet}.0/24"]
        (d / "masq").write_text("\n".join(lines) + "\n")

    def _gen_ipv6(self, d: Path, zones: list[str]) -> None:
        """Generate shorewall6 config for dual-stack."""
        d6 = d.parent / (d.name + "6")
        d6.mkdir(exist_ok=True)

        # zones
        lines = ["fw\tfirewall"]
        for z in zones:
            lines.append(f"{z}\tipv6")
        (d6 / "zones").write_text("\n".join(lines) + "\n")

        # interfaces (same as v4)
        lines = []
        for i, z in enumerate(zones):
            lines.append(f"{z}\teth{i}\t-\ttcpflags")
        (d6 / "interfaces").write_text("\n".join(lines) + "\n")

        # policy (same as v4)
        lines = ["$FW\tall\tACCEPT"]
        for z in zones:
            lines.append(f"{z}\tall\tREJECT\t$LOG")
        lines.append("all\tall\tREJECT\t$LOG")
        (d6 / "policy").write_text("\n".join(lines) + "\n")

        # minimal rules
        lines = [
            "?SECTION NEW",
            "Ping(ACCEPT)\tall\tall",
        ]
        for z in zones[:3]:
            lines.append(f"SSH(ACCEPT)\t{z}\t$FW")
        (d6 / "rules").write_text("\n".join(lines) + "\n")

        # params
        lines = ["LOG=info"]
        (d6 / "params").write_text("\n".join(lines) + "\n")

        # shorewall.conf
        (d6 / "shorewall.conf").write_text("STARTUP_ENABLED=Yes\n")
