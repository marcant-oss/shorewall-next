"""Plugin utility functions: IP extraction, subnet matching."""

from __future__ import annotations

import ipaddress
import re

# Match IPv4 addresses (with optional /mask and comma-separated lists)
_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')

# Match IPv6 addresses (hex groups, double-colon, optional /mask)
# This matches the v6 format used inside angle brackets in Shorewall configs
_IPV6_RE = re.compile(
    r'(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?'
)


def extract_ipv4(text: str) -> list[str]:
    """Extract all IPv4 addresses from a text line.

    Returns addresses without CIDR masks (just the IP).
    Filters out obviously invalid matches (>255 octets).
    """
    result = []
    for match in _IPV4_RE.findall(text):
        ip = match.split("/")[0]
        try:
            ipaddress.IPv4Address(ip)
            result.append(ip)
        except ValueError:
            continue
    return result


def extract_ipv6(text: str) -> list[str]:
    """Extract all IPv6 addresses from a text line.

    Returns addresses without CIDR masks. Handles Shorewall's
    <...> angle-bracket notation by stripping the brackets.
    """
    # Normalize: remove angle brackets
    normalized = text.replace("<", " ").replace(">", " ")
    result = []
    for match in _IPV6_RE.findall(normalized):
        ip = match.split("/")[0]
        # Must contain at least one colon to be valid IPv6
        if ":" not in ip:
            continue
        try:
            ipaddress.IPv6Address(ip)
            result.append(ip)
        except ValueError:
            continue
    return result


def extract_all_ips(text: str) -> tuple[list[str], list[str]]:
    """Extract all IPv4 and IPv6 addresses from a text line."""
    return extract_ipv4(text), extract_ipv6(text)


def ip_in_subnet(ip: str, subnet: str) -> bool:
    """Check if an IP address is within a subnet."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False


def is_ipv4(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_ipv6(ip: str) -> bool:
    """Check if a string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False
