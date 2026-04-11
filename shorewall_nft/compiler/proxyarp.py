"""Proxy ARP / Proxy NDP support.

Generates sysctl settings and nft rules for proxy ARP/NDP.

Config: proxyarp file with FORMAT: ADDRESS INTERFACE EXTERNAL HAVEROUTE PERSISTENT
"""

from __future__ import annotations

from shorewall_nft.config.parser import ConfigLine


def generate_proxyarp_sysctl(proxyarp_lines: list[ConfigLine]) -> list[str]:
    """Generate sysctl commands for proxy ARP.

    Returns list of 'sysctl -w ...' commands.
    """
    sysctls: list[str] = []
    interfaces: set[str] = set()

    for line in proxyarp_lines:
        cols = line.columns
        if len(cols) < 3:
            continue
        iface = cols[1]
        ext_iface = cols[2]
        interfaces.add(iface)
        interfaces.add(ext_iface)

    for iface in sorted(interfaces):
        sysctls.append(f"sysctl -w net.ipv4.conf.{iface}.proxy_arp=1")

    return sysctls
