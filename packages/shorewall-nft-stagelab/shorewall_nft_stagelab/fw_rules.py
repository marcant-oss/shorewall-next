"""Firewall rule discovery via SSH + nft list ruleset.

Provides AcceptRule dataclass and discover_accept_rules() to parse nft
ACCEPT rules from a remote firewall host, and find_best_rule() to match
proto/port/zone against discovered rules.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass

log = logging.getLogger(__name__)


# Chain name pattern: matches "src2dst" or "src2dst-" variants
# Examples: "net2$FW", "net2$FW-foo", "lan2net"
_CHAIN_RE = re.compile(r'^(?P<src>[^2]+)2(?P<dst>[^-]+)(?:-.*)?$')


@dataclass(frozen=True)
class AcceptRule:
    """An ACCEPT rule extracted from an nft chain.

    Attributes:
        zone_src: Source zone from chain name (e.g. "net" from "net2$FW").
        zone_dst: Destination zone (e.g. "$FW").
        proto: Protocol name ("tcp", "udp", "icmp").
        port: Port number if proto is tcp/udp, None for icmp.
        rule_index: Rule index in chain (for debugging/logging).
    """
    zone_src: str
    zone_dst: str
    proto: str
    port: int | None
    rule_index: int


def _extract_zones_from_chain(chain_name: str) -> tuple[str, str] | None:
    """Extract source and destination zones from a chain name.

    Args:
        chain_name: nft chain name (e.g. "net2$FW", "lan2net-foo").

    Returns:
        (zone_src, zone_dst) tuple or None if pattern doesn't match.
    """
    m = _CHAIN_RE.match(chain_name)
    if m:
        return m.group("src"), m.group("dst")
    return None


async def discover_accept_rules(
    fw_host: str,
    timeout_s: float = 10.0,
) -> list[AcceptRule]:
    """SSH into fw_host, run `nft -j list ruleset`, parse ACCEPT rules.

    Args:
        fw_host: SSH target (e.g. "root@192.168.1.1" or "fw-hostname").
        timeout_s: SSH connection timeout in seconds.

    Returns:
        List of AcceptRule objects sorted by rule_index. Empty list on error.
    """
    ssh_opts = [
        "-A",  # Forward authentication agent
        "-o", "BatchMode=yes",  # Never ask for passwords
        "-o", "ConnectTimeout=5",  # Connection timeout
        "-o", "StrictHostKeyChecking=no",  # Don't prompt for host key
    ]

    cmd = [
        "ssh",
        *ssh_opts,
        fw_host,
        "nft",
        "-j",  # JSON output
        "list",
        "ruleset",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout_s,
        )

        if proc.returncode != 0:
            log.warning(
                "discover_accept_rules: ssh %s nft -j list ruleset failed "
                "(exit=%d): %s",
                fw_host,
                proc.returncode,
                stderr.decode(errors="replace"),
            )
            return []

    except (OSError, asyncio.TimeoutError) as exc:
        log.warning("discover_accept_rules: SSH to %s failed: %s", fw_host, exc)
        return []

    # Parse JSON output
    try:
        ruleset = json.loads(stdout.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        log.warning("discover_accept_rules: Failed to parse nft JSON: %s", exc)
        return []

    rules: list[AcceptRule] = []

    # nftables JSON is a list of dicts; look for "rule" entries
    for entry in ruleset.get("nftables", []):
        rule_data = entry.get("rule")
        if not rule_data:
            continue

        # Extract chain name from "rule" -> "chain" field
        chain_name = rule_data.get("chain", "")
        zones = _extract_zones_from_chain(chain_name)
        if not zones:
            continue  # Skip rules not in zone-pair chains

        zone_src, zone_dst = zones

        # Extract expressions to find proto/port
        expressions = rule_data.get("expr", [])
        proto: str | None = None
        port: int | None = None

        for expr in expressions:
            # Match protocol: {"match": {"op": "==", "right": "tcp"}}
            match = expr.get("match")
            if match:
                right = match.get("right")
                if isinstance(right, str):
                    if right in ("tcp", "udp", "icmp"):
                        proto = right

            # Match port: {"match": {"op": "==", "right": 22}}
            # Port can be int or string
            if match:
                right = match.get("right")
                if isinstance(right, int):
                    # Could be dport or sport; assume dport for ACCEPT rules
                    if right > 0 and right <= 65535:
                        port = right
                elif isinstance(right, str) and right.isdigit():
                    port_val = int(right)
                    if 0 < port_val <= 65535:
                        port = port_val

        # Only include rules with a known protocol
        if proto:
            # Get rule index if available (for debugging)
            handle = rule_data.get("handle")
            rule_index = handle if isinstance(handle, int) else 0

            rules.append(AcceptRule(
                zone_src=zone_src,
                zone_dst=zone_dst,
                proto=proto,
                port=port,
                rule_index=rule_index,
            ))

    # Sort by rule_index for stable ordering
    rules.sort(key=lambda r: r.rule_index)
    return rules


def find_best_rule(
    rules: list[AcceptRule],
    proto: str,
    port: int | None,
    zone_src: str,
    zone_dst: str,
) -> AcceptRule | None:
    """Find the best-matching rule from a list of AcceptRule objects.

    Scoring:
        +1 for protocol match
        +1 for port match (if port is not None)
        +1 for source zone match
        +1 for destination zone match

    The rule with the highest score wins. Ties are broken by rule_index
    (first rule in the list). Returns None if rules is empty.

    Args:
        rules: List of AcceptRule objects (from discover_accept_rules).
        proto: Protocol to match ("tcp", "udp", "icmp").
        port: Port number to match, or None for ICMP.
        zone_src: Source zone name.
        zone_dst: Destination zone name.

    Returns:
        Best-matching AcceptRule, or None if rules is empty.
    """
    if not rules:
        return None

    best_rule: AcceptRule | None = None
    best_score = -1

    for rule in rules:
        score = 0

        # Protocol match is mandatory
        if rule.proto == proto:
            score += 1
        else:
            continue  # Skip rules with wrong protocol

        # Port match (if caller specified a port)
        if port is not None:
            if rule.port == port:
                score += 1
            # If rule has no port but we do, still consider it (partial match)
        elif rule.port is None:
            # Both are portless (e.g. ICMP)
            score += 1

        # Zone matches
        if rule.zone_src == zone_src:
            score += 1
        if rule.zone_dst == zone_dst:
            score += 1

        # Update best if this rule scores higher
        if score > best_score:
            best_score = score
            best_rule = rule

    return best_rule


__all__ = [
    "AcceptRule",
    "discover_accept_rules",
    "find_best_rule",
]
