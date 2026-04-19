"""Seed-request client for shorewall-nft.

Sends a ``request-seed`` command to shorewalld over the control socket and
returns pre-warmed DNS IP addresses for injection into the initial nft script.

All failure paths (daemon down, timeout, malformed JSON, ``ok=false``) return
``None`` — the caller continues without seeds.  This module has no side effects
and does not import any nft or compiler code.
"""

from __future__ import annotations

import json
import logging
import socket
from dataclasses import dataclass, field

log = logging.getLogger("shorewall_nft.seed")


@dataclass
class SeedResult:
    """Parsed seed response from shorewalld."""

    dns: dict     # qname → {"v4": [{"ip": ..., "ttl": N}], "v6": [...]}
    iplist: dict  # set_name → [cidr, ...]
    elapsed_ms: int = 0
    complete: bool = True
    timeout_hit: bool = False
    sources_contributed: list[str] = field(default_factory=list)


def request_seeds_from_shorewalld(
    *,
    socket_path: str,
    netns: str,
    name: str,
    qnames: list[str],
    iplist_sets: list[str],
    timeout_ms: int = 10_000,
    wait_for_passive: bool = True,
) -> SeedResult | None:
    """Send ``request-seed`` to shorewalld; return result or ``None`` on any error.

    The socket timeout is set to ``timeout_ms / 1000 + 5`` seconds so the
    client always outlasts the server-side deadline.

    Errors are classified:
    * ``FileNotFoundError`` (socket not found) → ``None`` silently (debug log).
    * All other errors → ``None`` with a warning log.
    """
    if not qnames and not iplist_sets:
        return None

    req = {
        "cmd": "request-seed",
        "netns": netns,
        "name": name,
        "timeout_ms": timeout_ms,
        "qnames": qnames,
        "iplist_sets": iplist_sets,
        "wait_for_passive": wait_for_passive,
    }
    payload = json.dumps(req, separators=(",", ":")).encode() + b"\n"
    sock_timeout = timeout_ms / 1000.0 + 5.0

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(sock_timeout)
        try:
            s.connect(socket_path)
            s.sendall(payload)
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            s.close()
    except FileNotFoundError:
        log.debug("seed: shorewalld socket not found (%s) — skipped", socket_path)
        return None
    except Exception as exc:
        log.warning("seed: request failed: %s", exc)
        return None

    if not buf:
        log.warning("seed: empty response from shorewalld")
        return None

    try:
        resp = json.loads(buf.split(b"\n", 1)[0])
    except json.JSONDecodeError as exc:
        log.warning("seed: malformed JSON response: %s", exc)
        return None

    if not resp.get("ok", False):
        log.warning("seed: daemon returned error: %s", resp.get("error"))
        return None

    seeds = resp.get("seeds") or {}
    return SeedResult(
        dns=seeds.get("dns") or {},
        iplist=seeds.get("iplist") or {},
        elapsed_ms=int(resp.get("elapsed_ms") or 0),
        complete=bool(resp.get("complete", True)),
        timeout_hit=bool(resp.get("timeout_hit", False)),
        sources_contributed=list(resp.get("sources_contributed") or []),
    )
