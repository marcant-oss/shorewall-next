"""shorewalld CLI entry point.

Parses command-line arguments and launches the ``Daemon`` asyncio loop.
Kept intentionally thin — everything non-trivial lives in ``core.py`` /
``exporter.py`` / ``discover.py`` / ``api_server.py`` and is unit-testable
without the CLI.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .config import ConfDefaults, ConfigError, load_defaults
from .logsetup import SUBSYSTEMS, LogConfig, configure_logging


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
        "--config-file", default=None, metavar="PATH",
        help="Read shorewalld.conf from PATH "
             "(default: /etc/shorewall/shorewalld.conf then "
             "/etc/shorewalld.conf; missing file is OK). CLI flags "
             "always override config-file values.")
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
        choices=("debug", "info", "warning", "error", "critical"),
        help="log level (default: info)")
    p.add_argument(
        "--log-target", default="stderr", metavar="TARGET",
        help="log destination: stderr|stdout|syslog|journal|file:PATH "
             "(default: stderr)")
    p.add_argument(
        "--log-format", default="human",
        choices=("human", "structured", "json"),
        help="log format (default: human)")
    p.add_argument(
        "--log-syslog-socket", default="/dev/log", metavar="PATH",
        help="syslog AF_UNIX socket path (default: /dev/log)")
    p.add_argument(
        "--log-syslog-facility", default="daemon", metavar="FACILITY",
        help="syslog facility (default: daemon)")
    p.add_argument(
        "--log-rate-limit-window", type=float, default=60.0, metavar="SECS",
        help="dedup window (s) for rate-limited hot-path warnings "
             "(default: 60)")
    # ── DNS-set pipeline (opt-in) ─────────────────────────────────────
    p.add_argument(
        "--allowlist-file", default=None, metavar="PATH",
        help="Compiled DNS allowlist file (produced by `shorewall-nft "
             "compile`). When set, activates the DNS-set pipeline: "
             "tracker, worker router, setwriter, reload monitor, "
             "and the optional state / pbdns / peer subsystems.")
    p.add_argument(
        "--listen-pbdns", default=None, metavar="PATH",
        help="Unix socket path for the PBDNSMessage logger stream "
             "from PowerDNS recursor (off by default).")
    p.add_argument(
        "--listen-pbdns-tcp", default=None, metavar="HOST:PORT",
        help="TCP host:port for the PBDNSMessage logger stream. "
             "Required for pdns-recursor's protobufServer() Lua "
             "directive because it speaks TCP only (dnstap accepts "
             "both, pbdns does not). Runs alongside --listen-pbdns.")
    p.add_argument(
        "--socket-mode", default=None, metavar="MODE",
        help="Octal permission mode applied to every daemon-owned "
             "unix socket (dnstap, pbdns). Default: 0660. Typical "
             "production value: 0660 with SOCKET_GROUP=pdns so the "
             "recursor can connect without root.")
    p.add_argument(
        "--socket-owner", default=None, metavar="USER",
        help="User name or numeric uid to chown the unix sockets "
             "to after bind. Default: leave the current process "
             "owner (usually root).")
    p.add_argument(
        "--socket-group", default=None, metavar="GROUP",
        help="Group name or numeric gid to chgrp the unix sockets "
             "to after bind. Default: leave unchanged. Use this "
             "with SOCKET_MODE=0660 to grant the DNS producer's "
             "group write access without changing ownership.")
    p.add_argument(
        "--peer-host", default=None, metavar="HOST",
        help="HA peer IP/hostname for DNS-set replication (off by default).")
    p.add_argument(
        "--peer-port", type=int, default=9749, metavar="PORT",
        help="HA peer UDP port (default: 9749).")
    p.add_argument(
        "--peer-bind", default="0.0.0.0:9749", metavar="HOST:PORT",
        help="HA peer local bind (default: 0.0.0.0:9749).")
    p.add_argument(
        "--peer-auth-key-file", default=None, metavar="PATH",
        help="Pre-shared HMAC-SHA256 secret file for HA peer link "
             "(required when --peer-host is set; mode ≤0600; ≥16 bytes).")
    p.add_argument(
        "--peer-heartbeat-interval", type=float, default=5.0, metavar="SECS",
        help="HA peer heartbeat interval (default: 5s).")
    p.add_argument(
        "--state-dir", default=None, metavar="PATH",
        help="Directory for DNS-set state persistence "
             "(default: /var/lib/shorewalld).")
    p.add_argument(
        "--no-state", action="store_true",
        help="Disable DNS-set state persistence entirely.")
    p.add_argument(
        "--no-state-load", action="store_true",
        help="Skip loading state on start; still save periodically.")
    p.add_argument(
        "--state-flush", action="store_true",
        help="Delete the state file on start (fresh boot).")
    p.add_argument(
        "--reload-poll-interval", type=float, default=2.0, metavar="SECS",
        help="Reload monitor poll interval (default: 2s).")
    # ── Multi-instance support ────────────────────────────────────────
    p.add_argument(
        "--instance", action="append", default=[], dest="instances",
        metavar="[NETNS:]DIR",
        help="shorewall-nft config directory for one instance. "
             "Repeat for multiple instances. Format: [netns:]<dir>. "
             "Omitting netns (or the colon) means root netns. "
             "Deprecated --allowlist-file is an alias for --instance <file>.")
    p.add_argument(
        "--monitor", action="store_true", default=False,
        help="Watch instance config dirs with inotify and reload on change. "
             "Optional — breaks the explicit shorewall-nft start/reload hook "
             "flow.")
    p.add_argument(
        "--control-socket", default=None, metavar="PATH",
        help="Unix socket path for the control API (refresh-iplist, "
             "reload-instance, status). Off by default.")
    p.add_argument(
        "--control-socket-netns", default=None, metavar="NETNS",
        help="Bind the control socket inside this named netns.")
    for sub in SUBSYSTEMS:
        p.add_argument(
            f"--log-level-{sub}", default=None, metavar="LEVEL",
            choices=("debug", "info", "warning", "error", "critical"),
            help=argparse.SUPPRESS)  # discoverable via `--help`? use repeat cfg
    return p


def _merge_conf_defaults(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    argv: list[str],
    defaults: ConfDefaults,
) -> argparse.Namespace:
    """Apply shorewalld.conf values for flags the user didn't pass.

    Precedence: explicit CLI flag > config-file value > argparse
    hard-coded default. Without this the conf file would be shadowed
    by the built-in argparse defaults on every run.
    """
    # argparse doesn't expose "was this flag explicitly provided?"
    # so we infer by scanning argv for the long-form name. Good
    # enough for long options (``--flag`` / ``--flag=value``).
    explicit: set[str] = set()
    for token in argv:
        if token.startswith("--"):
            key = token[2:].split("=", 1)[0]
            explicit.add(key.replace("-", "_"))

    def take(dest: str, conf_value: object) -> None:
        if dest in explicit or conf_value is None:
            return
        setattr(args, dest, conf_value)

    take("listen_prom", defaults.listen_prom)
    take("listen_api", defaults.listen_api)
    take("netns", defaults.netns)
    take("scrape_interval", defaults.scrape_interval)
    take("reprobe_interval", defaults.reprobe_interval)
    take("allowlist_file", defaults.allowlist_file)
    take("listen_pbdns", defaults.pbdns_socket)
    take("listen_pbdns_tcp", defaults.pbdns_tcp)
    take("socket_mode", defaults.socket_mode)
    take("socket_owner", defaults.socket_owner)
    take("socket_group", defaults.socket_group)
    take("peer_bind", defaults.peer_listen)
    take("peer_auth_key_file", defaults.peer_secret_file)
    take("peer_heartbeat_interval", defaults.peer_heartbeat_interval)
    take("state_dir", defaults.state_dir)
    take("reload_poll_interval", defaults.reload_poll_interval)
    take("log_level", defaults.log_level)
    take("log_target", defaults.log_target)
    take("log_format", defaults.log_format)
    take("log_rate_limit_window", defaults.log_rate_limit_window)

    # PEER_ADDRESS is "host:port" in the config file — split it.
    if "peer_host" not in explicit and defaults.peer_address:
        host, _, port = defaults.peer_address.rpartition(":")
        if host:
            args.peer_host = host
            if port:
                try:
                    args.peer_port = int(port)
                except ValueError:
                    parser.error(
                        f"PEER_ADDRESS has non-numeric port: "
                        f"{defaults.peer_address!r}")

    if "no_state" not in explicit and defaults.state_enabled is False:
        args.no_state = True

    # Multi-instance / control / iplist settings from config file.
    # For instances: config-file specs are *appended* to the CLI list
    # (so --instance on the CLI always wins; conf-file extends).
    if defaults.instances and not args.instances:
        args.instances = list(defaults.instances)

    if "monitor" not in explicit and defaults.monitor is True:
        args.monitor = True

    take("control_socket", defaults.control_socket)
    take("control_socket_netns", defaults.control_socket_netns)

    return args


def main(argv: list[str] | None = None) -> int:
    """shorewalld entry point. Returns exit code.

    Recognises subcommands that dispatch to their own CLIs:
    * ``tap``    — operator tap CLI
    * ``ctl``    — control socket client
    * ``iplist`` — IP list provider query CLI
    Everything else is parsed as the daemon arguments.
    """
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "tap":
        from .tap import main as tap_main
        return tap_main(argv[1:])
    if argv and argv[0] == "ctl":
        from .ctl import main as ctl_main
        return ctl_main(argv[1:])
    if argv and argv[0] == "iplist":
        from .iplist_cli import main as iplist_main
        return iplist_main(argv[1:])
    parser = build_parser()
    args = parser.parse_args(argv)

    # Load shorewalld.conf defaults for any flag the user did not
    # pass explicitly. A missing file is a silent no-op.
    try:
        defaults = load_defaults(
            Path(args.config_file) if args.config_file else None)
    except ConfigError as e:
        parser.error(str(e))
        return 2  # never reached — parser.error exits
    args = _merge_conf_defaults(parser, args, argv, defaults)

    subsys_levels: dict[str, str] = dict(defaults.subsys_log_levels)
    for sub in SUBSYSTEMS:
        val = getattr(args, f"log_level_{sub}", None)
        if val:
            subsys_levels[sub] = val
    configure_logging(LogConfig(
        level=args.log_level,
        target=args.log_target,
        format=args.log_format,
        syslog_socket=args.log_syslog_socket,
        syslog_facility=args.log_syslog_facility,
        rate_limit_window=args.log_rate_limit_window,
        subsys_levels=subsys_levels,
    ))

    prom_host, prom_port = _parse_listen_addr(args.listen_prom)
    netns_spec = _parse_netns_spec(args.netns)

    peer_bind_host, peer_bind_port = _parse_listen_addr(args.peer_bind)

    # Handle --allowlist-file deprecation: treat it as --instance <path>.
    # Done after config-file merge so the config-file ALLOWLIST_FILE
    # also gets the deprecation path.
    if args.allowlist_file and not args.instances:
        import warnings
        warnings.warn(
            "--allowlist-file is deprecated; use --instance <path>",
            DeprecationWarning,
            stacklevel=1,
        )
        args.instances = [str(args.allowlist_file)]

    # Imported lazily so --help works without prometheus_client installed.
    from .core import Daemon

    socket_mode_int: int | None = None
    if args.socket_mode is not None:
        try:
            socket_mode_int = int(str(args.socket_mode), 8)
        except ValueError:
            parser.error(
                f"--socket-mode/SOCKET_MODE must be octal, "
                f"got {args.socket_mode!r}")

    # Parse IPLIST_* config lines into IpListConfig objects.
    iplist_cfgs: list = []
    if defaults.iplist_configs:
        try:
            from .iplist.protocol import parse_iplist_configs
            raw_iplist = {}
            for line in defaults.iplist_configs:
                if "=" in line:
                    k, _, v = line.partition("=")
                    raw_iplist[k.strip()] = v.strip()
            iplist_cfgs = parse_iplist_configs(raw_iplist)
        except Exception as e:
            parser.error(f"IPLIST_* config parse error: {e}")

    daemon = Daemon(
        prom_host=prom_host,
        prom_port=prom_port,
        api_socket=args.listen_api,
        netns_spec=netns_spec,
        scrape_interval=args.scrape_interval,
        reprobe_interval=args.reprobe_interval,
        allowlist_file=(
            Path(args.allowlist_file) if args.allowlist_file else None),
        pbdns_socket=args.listen_pbdns,
        pbdns_tcp=args.listen_pbdns_tcp,
        socket_mode=socket_mode_int,
        socket_owner=args.socket_owner,
        socket_group=args.socket_group,
        peer_bind_host=peer_bind_host,
        peer_bind_port=peer_bind_port,
        peer_host=args.peer_host,
        peer_port=args.peer_port,
        peer_auth_key_file=(
            Path(args.peer_auth_key_file)
            if args.peer_auth_key_file else None),
        peer_heartbeat_interval=args.peer_heartbeat_interval,
        state_dir=Path(args.state_dir) if args.state_dir else None,
        state_enabled=not args.no_state,
        state_no_load=args.no_state_load,
        state_flush=args.state_flush,
        reload_poll_interval=args.reload_poll_interval,
        instances=list(args.instances),
        monitor=args.monitor,
        control_socket=args.control_socket,
        control_socket_netns=args.control_socket_netns,
        iplist_configs=iplist_cfgs,
    )
    try:
        return asyncio.run(daemon.run())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
