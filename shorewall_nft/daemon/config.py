"""``shorewalld.conf`` parser.

Shell-flavoured ``KEY=value`` file — comments start with ``#``, blank
lines are ignored, values may optionally be wrapped in ``"`` or ``'``.
No variable interpolation, no nesting — keep it boring. CLI flags
always override config file values, so an operator can temporarily
flip a knob without editing the file.

The canonical location is ``/etc/shorewall/shorewalld.conf``; the
daemon falls back to ``/etc/shorewalld.conf`` for distributions that
don't ship ``/etc/shorewall``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATHS = (
    Path("/etc/shorewall/shorewalld.conf"),
    Path("/etc/shorewalld.conf"),
)


class ConfigError(ValueError):
    """Raised for malformed ``shorewalld.conf`` lines."""


def _unquote(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def parse_conf_text(text: str) -> dict[str, str]:
    """Parse a config file body into a flat ``KEY → str`` dict.

    Duplicate keys: later wins (same as Shorewall).
    Raises :class:`ConfigError` on malformed lines.
    """
    out: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError(
                f"shorewalld.conf line {lineno}: expected KEY=value, "
                f"got {raw!r}")
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            raise ConfigError(
                f"shorewalld.conf line {lineno}: invalid key {key!r}")
        out[key] = _unquote(value)
    return out


def parse_conf_file(path: Path) -> dict[str, str]:
    """Read and parse a ``shorewalld.conf`` file.

    Missing files return an empty dict so the daemon can run with
    pure CLI flags. IO errors and parse errors both surface as
    :class:`ConfigError`.
    """
    try:
        text = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise ConfigError(f"failed to read {path}: {e}") from e
    return parse_conf_text(text)


def find_default_config() -> Path | None:
    """Return the first existing default config path, or ``None``."""
    for candidate in DEFAULT_CONFIG_PATHS:
        if candidate.exists():
            return candidate
    return None


# ── Daemon settings dataclass ──────────────────────────────────────

# Keys documented in docs/reference/shorewalld.md. All optional —
# anything unset falls back to the CLI default.
_BOOL_KEYS = frozenset({"STATE_ENABLED"})
_INT_KEYS = frozenset({
    "PEER_PORT",
    "PEER_BIND_PORT",
})
_FLOAT_KEYS = frozenset({
    "SCRAPE_INTERVAL",
    "REPROBE_INTERVAL",
    "PEER_HEARTBEAT_INTERVAL",
    "STATE_PERSIST_INTERVAL",
    "RELOAD_POLL_INTERVAL",
    "LOG_RATE_LIMIT_WINDOW",
})


def _coerce(key: str, value: str) -> object:
    if key in _BOOL_KEYS:
        v = value.strip().lower()
        if v in ("1", "yes", "true", "on"):
            return True
        if v in ("0", "no", "false", "off"):
            return False
        raise ConfigError(f"{key}: expected yes/no, got {value!r}")
    if key in _INT_KEYS:
        try:
            return int(value)
        except ValueError as e:
            raise ConfigError(f"{key}: expected int, got {value!r}") from e
    if key in _FLOAT_KEYS:
        try:
            return float(value)
        except ValueError as e:
            raise ConfigError(f"{key}: expected float, got {value!r}") from e
    return value


@dataclass
class ConfDefaults:
    """Typed view of a parsed ``shorewalld.conf`` file.

    Holds exactly what the CLI looks up before falling back to its
    built-in defaults. Anything not set is ``None`` so the CLI can
    detect "user didn't configure this" vs "user explicitly set it".
    """

    listen_prom: str | None = None
    listen_api: str | None = None
    dnstap_tcp: str | None = None
    netns: str | None = None
    scrape_interval: float | None = None
    reprobe_interval: float | None = None
    allowlist_file: str | None = None
    pbdns_socket: str | None = None
    pbdns_tcp: str | None = None
    socket_mode: str | None = None     # octal string, e.g. "0660"
    socket_owner: str | None = None    # user name or numeric uid
    socket_group: str | None = None    # group name or numeric gid
    peer_listen: str | None = None
    peer_address: str | None = None
    peer_secret_file: str | None = None
    peer_heartbeat_interval: float | None = None
    state_dir: str | None = None
    state_enabled: bool | None = None
    reload_poll_interval: float | None = None
    log_level: str | None = None
    log_target: str | None = None
    log_format: str | None = None
    log_rate_limit_window: float | None = None
    subsys_log_levels: dict[str, str] = field(default_factory=dict)


# Map config key → ConfDefaults attribute. Keys not in this map are
# silently ignored so adding future knobs is forward-compatible.
_CONF_KEY_MAP: dict[str, str] = {
    "LISTEN_PROM": "listen_prom",
    "LISTEN_API": "listen_api",
    "DNSTAP_TCP": "dnstap_tcp",
    "NETNS": "netns",
    "SCRAPE_INTERVAL": "scrape_interval",
    "REPROBE_INTERVAL": "reprobe_interval",
    "ALLOWLIST_FILE": "allowlist_file",
    "PBDNS_SOCKET": "pbdns_socket",
    "PBDNS_TCP": "pbdns_tcp",
    "SOCKET_MODE": "socket_mode",
    "SOCKET_OWNER": "socket_owner",
    "SOCKET_GROUP": "socket_group",
    "PEER_LISTEN": "peer_listen",
    "PEER_ADDRESS": "peer_address",
    "PEER_SECRET_FILE": "peer_secret_file",
    "PEER_HEARTBEAT_INTERVAL": "peer_heartbeat_interval",
    "STATE_DIR": "state_dir",
    "STATE_ENABLED": "state_enabled",
    "RELOAD_POLL_INTERVAL": "reload_poll_interval",
    "LOG_LEVEL": "log_level",
    "LOG_TARGET": "log_target",
    "LOG_FORMAT": "log_format",
    "LOG_RATE_LIMIT_WINDOW": "log_rate_limit_window",
}


def load_defaults(path: Path | None) -> ConfDefaults:
    """Read ``path`` (or the first default path) into a :class:`ConfDefaults`.

    ``path=None`` walks :data:`DEFAULT_CONFIG_PATHS`. A missing file
    returns an all-``None`` defaults object. Unknown ``LOG_LEVEL_<sub>``
    keys are gathered into ``subsys_log_levels`` so logsetup can apply
    per-subsystem overrides from the file.
    """
    if path is None:
        path = find_default_config()
    if path is None:
        return ConfDefaults()
    raw = parse_conf_file(path)
    defaults = ConfDefaults()
    for key, value in raw.items():
        if key.startswith("LOG_LEVEL_"):
            sub = key[len("LOG_LEVEL_"):].lower()
            if sub:
                defaults.subsys_log_levels[sub] = value
            continue
        attr = _CONF_KEY_MAP.get(key)
        if attr is None:
            continue
        setattr(defaults, attr, _coerce(key, value))
    return defaults
