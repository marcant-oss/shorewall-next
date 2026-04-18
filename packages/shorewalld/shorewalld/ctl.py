"""``shorewalld ctl`` — control socket client CLI.

Connects to a running shorewalld control socket and sends a command.

Usage::

    shorewalld ctl --socket /run/shorewalld/control.sock ping
    shorewalld ctl --socket /run/shorewalld/control.sock refresh-iplist
    shorewalld ctl --socket /run/shorewalld/control.sock refresh-iplist --name aws_ec2_eu
    shorewalld ctl --socket /run/shorewalld/control.sock iplist-status
    shorewalld ctl --socket /run/shorewalld/control.sock reload-instance
    shorewalld ctl --socket /run/shorewalld/control.sock reload-instance --name fw
    shorewalld ctl --socket /run/shorewalld/control.sock instance-status
    shorewalld ctl --socket /run/shorewalld/control.sock register-instance --config-dir /etc/shorewall
    shorewalld ctl --socket /run/shorewalld/control.sock deregister-instance --name shorewall
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from typing import Any

_RETRY_COUNT = 10
_RETRY_FACTOR = 1.5


class _ConnectError(Exception):
    """Control socket unavailable — retriable."""


def _build_ctl_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shorewalld ctl",
        description="Send a command to a running shorewalld control socket",
    )
    p.add_argument(
        "--socket", default="/run/shorewalld/control.sock",
        metavar="PATH",
        help="Path to the shorewalld control socket "
             "(default: /run/shorewalld/control.sock)",
    )
    sub = p.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    sub.add_parser("ping", help="Check if shorewalld is alive")

    ri = sub.add_parser(
        "refresh-iplist", help="Trigger an immediate IP list refresh"
    )
    ri.add_argument(
        "--name", default=None, metavar="NAME",
        help="Refresh only this named list (default: all)",
    )

    sub.add_parser("iplist-status", help="Show IP list status")

    rl = sub.add_parser(
        "reload-instance",
        help="Reload the DNS allowlist for one or all instances",
    )
    rl.add_argument(
        "--name", default=None, metavar="NAME",
        help="Reload only this instance (default: all)",
    )

    sub.add_parser("instance-status", help="Show instance status")

    rd = sub.add_parser(
        "refresh-dns",
        help="Trigger an immediate DNS re-resolve for dnsr: pull-resolver groups",
    )
    rd.add_argument(
        "--hostname", default=None, metavar="HOSTNAME",
        help="Refresh only this primary hostname (default: all groups)",
    )

    ri = sub.add_parser(
        "register-instance",
        help="Dynamically register a shorewall-nft instance",
    )
    ri.add_argument(
        "--config-dir", required=True, metavar="PATH",
        help="Shorewall config directory containing dnsnames.compiled",
    )
    ri.add_argument(
        "--netns", default="", metavar="NAME",
        help="Network namespace (default: root ns)",
    )
    ri.add_argument(
        "--name", default=None, metavar="NAME",
        help="Explicit instance name (default: netns or config_dir basename)",
    )
    ri.add_argument(
        "--allowlist-path", default=None, metavar="PATH",
        help="Path to dnsnames.compiled (default: <config-dir>/dnsnames.compiled)",
    )
    ri.add_argument(
        "--retry-delay", type=float, default=1.0, metavar="SECONDS",
        help="Initial delay between retries in seconds; grows by factor "
             f"{_RETRY_FACTOR} each attempt (default: 1.0, max {_RETRY_COUNT} retries)",
    )

    di = sub.add_parser(
        "deregister-instance",
        help="Deregister a dynamically registered shorewall-nft instance",
    )
    di.add_argument(
        "--name", default=None, metavar="NAME",
        help="Instance name (derived from --netns or --config-dir basename if omitted)",
    )
    di.add_argument(
        "--config-dir", default=None, metavar="PATH",
        help="Shorewall config directory (used to derive --name when not given)",
    )
    di.add_argument(
        "--netns", default="", metavar="NAME",
        help="Network namespace (used to derive --name when not given)",
    )

    return p


def _build_request(args: argparse.Namespace) -> dict:
    """Translate parsed args into a JSON request dict."""
    cmd = args.command
    req: dict[str, Any] = {"cmd": cmd}

    if cmd == "refresh-iplist" and args.name:
        req["name"] = args.name
    elif cmd == "reload-instance" and args.name:
        req["name"] = args.name
    elif cmd == "refresh-dns" and args.hostname:
        req["hostname"] = args.hostname
    elif cmd == "register-instance":
        req["config_dir"] = args.config_dir
        if args.netns:
            req["netns"] = args.netns
        if args.name:
            req["name"] = args.name
        if args.allowlist_path:
            req["allowlist_path"] = args.allowlist_path
    elif cmd == "deregister-instance":
        if args.name:
            req["name"] = args.name
        if args.config_dir:
            req["config_dir"] = args.config_dir
        if args.netns:
            req["netns"] = args.netns

    return req


def _send(socket_path: str, request: dict) -> dict:
    """Send *request* over the control socket and return the response."""
    payload = json.dumps(request, separators=(",", ":")).encode() + b"\n"

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as e:
        raise SystemExit(f"ctl: cannot create socket: {e}") from e

    try:
        sock.connect(socket_path)
    except FileNotFoundError:
        raise _ConnectError(
            f"control socket not found: {socket_path} "
            f"(is shorewalld running with --control-socket?)"
        ) from None
    except PermissionError:
        raise SystemExit(f"ctl: permission denied: {socket_path}") from None
    except OSError as e:
        raise _ConnectError(f"connect to {socket_path}: {e}") from e

    try:
        sock.settimeout(15.0)
        sock.sendall(payload)
        # Read until newline.
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    except OSError as e:
        raise SystemExit(f"ctl: I/O error: {e}") from e
    finally:
        sock.close()

    line = buf.split(b"\n", 1)[0]
    try:
        return json.loads(line)
    except json.JSONDecodeError as e:
        raise SystemExit(f"ctl: invalid JSON response: {e}; got {line!r}") from e


def _send_with_retry(socket_path: str, request: dict, retry_delay: float) -> dict:
    """Send *request*, retrying up to _RETRY_COUNT times on connection errors."""
    delay = retry_delay
    for attempt in range(_RETRY_COUNT + 1):
        try:
            return _send(socket_path, request)
        except _ConnectError as e:
            if attempt == _RETRY_COUNT:
                raise SystemExit(f"ctl: {e} (gave up after {_RETRY_COUNT} retries)") from e
            print(
                f"ctl: {e} — retry {attempt + 1}/{_RETRY_COUNT} in {delay:.1f}s",
                file=sys.stderr,
            )
            time.sleep(delay)
            delay *= _RETRY_FACTOR
    raise AssertionError("unreachable")  # noqa: unreachable


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``shorewalld ctl``."""
    parser = _build_ctl_parser()
    args = parser.parse_args(argv)

    request = _build_request(args)

    try:
        if args.command == "register-instance":
            response = _send_with_retry(args.socket, request, args.retry_delay)
        else:
            response = _send(args.socket, request)
    except (_ConnectError, SystemExit) as e:
        print(str(e), file=sys.stderr)
        return 1

    # Pretty-print the response.
    print(json.dumps(response, indent=2))

    if not response.get("ok", False):
        error = response.get("error", "command failed")
        print(f"ctl: error: {error}", file=sys.stderr)
        return 1

    return 0
