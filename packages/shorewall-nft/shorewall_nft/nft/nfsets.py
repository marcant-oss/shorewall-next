"""Named dynamic nft sets — data model, parser, and emitter helpers.

This module covers the *compiler side* of the ``nfsets`` config file:

* :class:`NfSetEntry` — one logical named set with its backend and options.
* :class:`NfSetRegistry` — the collection of all declared sets.
* :func:`build_nfset_registry` — parse ``ConfigLine`` rows from the
  ``nfsets`` file into a registry.
* :func:`nfset_to_set_name` — deterministic ``name + family`` → nft set name.
* :func:`emit_nfset_declarations` — produce nft ``set`` declaration lines.
* :func:`nfset_registry_to_payload` / :func:`payload_to_nfset_registry` —
  JSON-safe round-trip for the control-socket ``register-instance`` payload.

shorewalld consumes the payload via ``NfSetsManager`` (Wave 2+).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from shorewall_nft.nft.dns_sets import (
    _SAFE_CHAR,  # noqa: PLC2701 — shared private constant, intentional
    MAX_SET_NAME_LEN,
    canonical_qname,
)
from shorewall_nft.util.brace_expand import expand_brace

# ---------------------------------------------------------------------------
# Naming constants
# ---------------------------------------------------------------------------

_NFSET_PREFIX = "nfset_"
_SUFFIX_V4 = "_v4"
_SUFFIX_V6 = "_v6"
# Overhead: len("nfset_") + len("_v4") = 9 chars;  body limit = 31 - 9 = 22.
_NFSET_BODY_LIMIT = MAX_SET_NAME_LEN - len(_NFSET_PREFIX) - len(_SUFFIX_V4)

# Valid backend identifiers.
_BACKENDS: frozenset[str] = frozenset({
    "dnstap", "resolver", "ip-list", "ip-list-plain",
})
_DNS_BACKENDS: frozenset[str] = frozenset({"dnstap", "resolver"})
_IPLIST_BACKENDS: frozenset[str] = frozenset({"ip-list", "ip-list-plain"})

# Valid dnstype values (SRV is tracked but not implemented this wave).
_DNS_TYPES: frozenset[str] = frozenset({"a", "aaaa", "srv"})

# Duration suffix multipliers.
_DURATION_UNITS: dict[str, int] = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# Size suffix multipliers (k = 1024, M = 1048576).
_SIZE_UNITS: dict[str, int] = {"k": 1024, "M": 1024 * 1024}

# Operator-configurable size bounds.
_SIZE_MIN = 1
_SIZE_MAX = 64 * 1024 * 1024  # 64M entries


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class NfSetEntry:
    """One logical named set declared in the ``nfsets`` config file.

    Multiple ``nfsets`` rows with the **same** ``name`` and the **same**
    ``backend`` are merged into one entry: their ``hosts`` lists are
    concatenated (after brace expansion).  Options must be compatible
    (non-conflicting); a :exc:`ValueError` is raised on conflict.

    Multiple ``nfsets`` rows with the **same** ``name`` but **different**
    backends are stored as separate entries (N6 additive model).  The
    resulting logical nft set receives writes from all backends
    simultaneously.  See :func:`build_nfset_registry` for details.
    """

    name: str
    """User-defined logical set name (as written in the config file)."""

    hosts: list[str]
    """Resolved host entries (after brace expansion).

    For ``dnstap`` / ``resolver`` backends these are DNS qnames.
    For ``ip-list`` / ``ip-list-plain`` backends these are provider
    identifiers, URLs, file paths, or ``exec:`` strings.
    """

    backend: str
    """One of ``"dnstap"``, ``"resolver"``, ``"ip-list"``, ``"ip-list-plain"``."""

    options: dict[str, list[str]] = field(default_factory=dict)
    """Multi-valued options (e.g. ``{"filter": ["region=us-east-1"]}``)."""

    refresh: int | None = None
    """Refresh interval in seconds; ``None`` means use the backend default."""

    dns_servers: list[str] = field(default_factory=list)
    """Explicit DNS server IPs for the ``resolver`` backend (``dns=`` option)."""

    inotify: bool = False
    """Watch file for changes via inotify (``ip-list-plain`` only)."""

    dnstype: str | None = None
    """DNS record type filter: ``"a"``, ``"aaaa"``, or ``"srv"``; ``None``
    means resolve both A and AAAA."""

    size: int | None = None
    """Explicit nft set size override (in entries).  ``None`` means use the
    per-backend default (262144 for ip-list/ip-list-plain, 4096 for DNS
    backends).  Set via ``size=N`` in the options string; accepts k/M
    suffixes (1k = 1024, 1M = 1048576).  Valid range: 1 – 67108864 (64M)."""


@dataclass
class NfSetRegistry:
    """Collection of all named sets declared in the ``nfsets`` config file.

    Each :class:`NfSetEntry` in :attr:`entries` represents one
    ``(name, backend)`` combination.  Multiple entries may share the same
    ``name`` when the N6 additive model is in use (different backends for
    the same logical nft set).  :attr:`set_names` is the set of distinct
    logical names, regardless of backend count.
    """

    entries: list[NfSetEntry] = field(default_factory=list)
    """Ordered list of entries (insertion order from the config file).

    Multiple entries with the same :attr:`~NfSetEntry.name` are possible
    when different backends feed the same nft set.
    """

    set_names: set[str] = field(default_factory=set)
    """Logical set names already registered.

    Always the set of *distinct* names — not affected by how many backends
    a single name has.
    """


# ---------------------------------------------------------------------------
# Naming helpers
# ---------------------------------------------------------------------------


def nfset_to_set_name(name: str, family: str) -> str:
    """Map a logical nfset name + family to a deterministic nft set name.

    Uses the **same sanitisation algorithm** as ``qname_to_set_name()`` in
    ``shorewall_nft.nft.dns_sets``:

    * Lower-case the name.
    * Replace every non-``[a-z0-9]`` character with ``_``.
    * Collapse runs of ``_``.
    * Truncate the body to ``MAX_SET_NAME_LEN - len("nfset__v4") = 22``
      characters, using a SHA-1 prefix as a collision-safe tail when needed.
    * Prepend ``nfset_`` and append ``_v4`` / ``_v6``.

    ``family`` must be ``"v4"`` or ``"v6"``.
    """
    body = "".join(ch if _SAFE_CHAR.match(ch) else "_" for ch in name.lower())
    while "__" in body:
        body = body.replace("__", "_")
    body = body.strip("_")
    if not body:
        body = "x"

    if len(body) > _NFSET_BODY_LIMIT:
        import hashlib
        h = hashlib.sha1(name.encode()).hexdigest()[:6]
        head_len = _NFSET_BODY_LIMIT - len(h) - 1
        body = f"{body[:head_len]}_{h}"

    suffix = _SUFFIX_V4 if family == "v4" else _SUFFIX_V6
    return f"{_NFSET_PREFIX}{body}{suffix}"


# ---------------------------------------------------------------------------
# Duration parsing
# ---------------------------------------------------------------------------


def _parse_size(value: str, entry_name: str = "<unknown>") -> int:
    """Parse a set-size string like ``262144``, ``256k``, or ``10M``.

    Suffixes: ``k`` = 1024, ``M`` = 1048576.

    Valid range: :data:`_SIZE_MIN` – :data:`_SIZE_MAX` (1 – 64M).

    Raises :exc:`ValueError` on unrecognised format or out-of-range value.
    """
    v = value.strip()
    if not v:
        raise ValueError(f"nfsets entry {entry_name!r}: empty size value")
    # Plain integer (no suffix)?
    m = re.fullmatch(r"(\d+)", v)
    if m:
        n = int(m.group(1))
    else:
        # Integer with k/M suffix.
        m = re.fullmatch(r"(\d+)([kM])", v)
        if m:
            n = int(m.group(1)) * _SIZE_UNITS[m.group(2)]
        else:
            raise ValueError(
                f"nfsets entry {entry_name!r}: unrecognised size format: {value!r}"
                " (expected integer, or integer with k/M suffix)")
    if not (_SIZE_MIN <= n <= _SIZE_MAX):
        raise ValueError(
            f"nfsets entry {entry_name!r}: size {n} out of range "
            f"({_SIZE_MIN}–{_SIZE_MAX})")
    return n


def _parse_duration(value: str) -> int:
    """Parse a duration string like ``5m``, ``1h``, ``30s``, or plain int.

    Returns the equivalent number of seconds as an ``int``.

    Raises :exc:`ValueError` on unrecognised input.
    """
    v = value.strip()
    if not v:
        raise ValueError(f"empty duration: {value!r}")
    # Plain integer (seconds)?
    m = re.fullmatch(r"(\d+)", v)
    if m:
        return int(m.group(1))
    # Numeric with optional unit suffix.
    m = re.fullmatch(r"(\d+)([smhd])", v)
    if m:
        return int(m.group(1)) * _DURATION_UNITS[m.group(2)]
    raise ValueError(f"unrecognised duration format: {value!r}")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _parse_options(options_str: str) -> dict:
    """Parse the options column of one ``nfsets`` row.

    Returns a dict with these keys (all optional):

    ``backend``
        One of the backend strings.
    ``dns_servers``
        List of ``str`` from ``dns=<ip>`` tokens.
    ``filter``
        List of ``str`` from ``filter=<expr>`` tokens.
    ``refresh``
        ``int`` seconds, from ``refresh=<duration>``.
    ``inotify``
        ``bool``, ``True`` if the bare ``inotify`` token is present.
    ``dnstype``
        ``str`` or ``None``.

    Raises :exc:`ValueError` for unknown tokens.
    """
    result: dict = {
        "backend": None,
        "dns_servers": [],
        "filter": [],
        "refresh": None,
        "inotify": False,
        "dnstype": None,
        "size": None,
    }
    if not options_str or options_str == "-":
        return result

    for token in re.split(r"\s*,\s*", options_str.strip()):
        token = token.strip()
        if not token:
            continue

        # Backend keyword (bare token, no "=").
        if token in _BACKENDS:
            if result["backend"] is not None and result["backend"] != token:
                raise ValueError(
                    f"conflicting backends: {result['backend']!r} vs {token!r}")
            result["backend"] = token
            continue

        # inotify flag.
        if token == "inotify":
            result["inotify"] = True
            continue

        # key=value tokens.
        if "=" in token:
            key, _, val = token.partition("=")
            key = key.strip()
            val = val.strip()
            if key == "dns":
                result["dns_servers"].append(val)
            elif key == "filter":
                result["filter"].append(val)
            elif key == "refresh":
                result["refresh"] = _parse_duration(val)
            elif key == "dnstype":
                if val not in _DNS_TYPES:
                    raise ValueError(
                        f"unknown dnstype {val!r}; valid: {sorted(_DNS_TYPES)}")
                result["dnstype"] = val
            elif key == "size":
                # Defer range validation to _parse_size at registry build time
                # (we don't have the entry name here); store raw string.
                result["size"] = val
            else:
                raise ValueError(
                    f"unknown nfsets option: {token!r}")
            continue

        raise ValueError(f"unknown nfsets option token: {token!r}")

    return result


def build_nfset_registry(lines: list) -> NfSetRegistry:
    """Parse ``ConfigLine`` rows from the ``nfsets`` file into an
    :class:`NfSetRegistry`.

    **Same name, same backend** — rows are merged: their ``hosts`` lists are
    concatenated and options are combined (the last ``refresh=`` wins,
    ``inotify`` accumulates, ``dns=`` servers accumulate).

    **Same name, different backend** (N6 additive model) — rows are stored as
    separate :class:`NfSetEntry` objects.  Both backends will write to the
    same pair of nft sets (``nfset_<name>_v4`` / ``nfset_<name>_v6``)
    simultaneously at runtime.  The emitter computes per-name flags as the
    union of all backends for that name.

    Brace expansion (``{a,b}.host.org``) is applied to the ``hosts``
    column at parse time.

    ``lines`` is a list of ``ConfigLine`` objects (from the shorewall-nft
    parser); each must have at least two columns (name, hosts).  The third
    column (options) is optional and defaults to ``"-"`` when absent.

    Raises :exc:`ValueError` on unknown option tokens or other parse errors.
    """
    import logging as _logging

    registry = NfSetRegistry()
    # (name, backend) → NfSetEntry for same-name-same-backend merging.
    by_name_backend: dict[tuple[str, str], NfSetEntry] = {}

    for line in lines:
        cols = list(line.columns) if hasattr(line, "columns") else list(line)
        if not cols:
            continue

        name = cols[0].strip()
        hosts_raw = cols[1].strip() if len(cols) > 1 else ""
        options_str = cols[2].strip() if len(cols) > 2 else "-"

        if not name or name == "-":
            continue

        # Expand brace patterns in hosts column.
        expanded_hosts: list[str] = []
        for host_token in re.split(r"\s+", hosts_raw.strip()):
            if not host_token or host_token == "-":
                continue
            expanded_hosts.extend(expand_brace(host_token))
        # Canonicalise qnames for dns backends (safe for all backends).
        expanded_hosts = [canonical_qname(h) if "." in h else h
                          for h in expanded_hosts]

        opts = _parse_options(options_str)
        backend = opts["backend"]
        if backend is None:
            raise ValueError(
                f"nfsets entry {name!r}: no backend specified in options "
                f"(must be one of {sorted(_BACKENDS)})")

        # Parse size= option (with range validation) now that we have the name.
        parsed_size: int | None = None
        if opts["size"] is not None:
            parsed_size = _parse_size(opts["size"], entry_name=name)

        key = (name, backend)

        # Merge with existing entry for same (name, backend), or create new.
        if key in by_name_backend:
            entry = by_name_backend[key]
            entry.hosts.extend(expanded_hosts)
            entry.dns_servers.extend(opts["dns_servers"])
            if opts["filter"]:
                entry.options.setdefault("filter", []).extend(opts["filter"])
            if opts["refresh"] is not None:
                entry.refresh = opts["refresh"]
            if opts["inotify"]:
                entry.inotify = True
            if opts["dnstype"] is not None:
                entry.dnstype = opts["dnstype"]
            if parsed_size is not None:
                if entry.size is not None and parsed_size != entry.size:
                    _logging.debug(
                        "nfsets entry %r backend %r: multiple size= values "
                        "(%d, %d); using max %d",
                        name, backend, entry.size, parsed_size,
                        max(entry.size, parsed_size),
                    )
                    entry.size = max(entry.size, parsed_size)
                else:
                    entry.size = parsed_size
        else:
            entry = NfSetEntry(
                name=name,
                hosts=expanded_hosts,
                backend=backend,
                options={"filter": opts["filter"]} if opts["filter"] else {},
                refresh=opts["refresh"],
                dns_servers=opts["dns_servers"],
                inotify=opts["inotify"],
                dnstype=opts["dnstype"],
                size=parsed_size,
            )
            by_name_backend[key] = entry
            registry.entries.append(entry)
            registry.set_names.add(name)

    return registry


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------


def emit_nfset_declarations(
    registry: NfSetRegistry, indent: str = "\t"
) -> list[str]:
    """Return nft script lines declaring all named sets in *registry*.

    **One set declaration per logical name** (per family) — not per entry.
    When multiple entries share a name (N6 additive model), they all feed
    the same nft set, so only a single ``set`` block is emitted per
    ``(name, family)`` pair.

    **Flags** are determined per name group (W15 per-set flags):

    * Group has only ``dnstap`` / ``resolver`` backends → ``flags timeout``
    * Group has only ``ip-list`` / ``ip-list-plain`` backends → ``flags interval``
    * Group has a mix → ``flags timeout, interval``

    **Size** is resolved per name group:

    1. If any entry in the group specifies an explicit ``size=N``, take the
       maximum across all explicit overrides in the group.  A ``logging.debug``
       note is emitted when multiple conflicting values are found.
    2. Otherwise, if any entry in the group uses an ``ip-list`` or
       ``ip-list-plain`` backend, use the ip-list default (**262144**).
    3. Otherwise use the DNS default (**4096**).

    Valid size range: 1 – 67108864 (64M).  Accepts k/M suffixes via the
    options string: ``size=1M`` → 1048576.

    .. note::
        Existing nft sets compiled with the old defaults (size 65536 for
        ip-list, size 512 for DNS) will be recreated with the new defaults on
        the next compile + ``nft -f`` reload.  The kernel keeps the **old**
        in-memory size until the ruleset is flushed and reloaded (e.g. via
        ``shorewall-nft restart``).  No action needed for correctness; stale
        sets simply keep the old capacity until next restart.
    """
    import logging as _logging

    if not registry.entries:
        return []

    _DEFAULT_SIZE_IPLIST = 262144
    _DEFAULT_SIZE_DNS = 4096

    # Group entries by logical name, preserving first-seen order.
    groups: dict[str, list[NfSetEntry]] = {}
    for entry in registry.entries:
        groups.setdefault(entry.name, []).append(entry)

    lines: list[str] = []
    lines.append("")
    lines.append(f"{indent}# Named nft sets (populated by shorewalld nfsets manager)")

    for name, group_entries in groups.items():
        # Per-name backend set → per-set flags.
        group_backends = {e.backend for e in group_entries}
        has_dns = bool(group_backends & _DNS_BACKENDS)
        has_ip = bool(group_backends & _IPLIST_BACKENDS)
        if has_dns and has_ip:
            flags_str = "timeout, interval"
        elif has_ip:
            flags_str = "interval"
        else:
            flags_str = "timeout"

        # Per-name size resolution.
        explicit_sizes = [e.size for e in group_entries if e.size is not None]
        if explicit_sizes:
            if len(set(explicit_sizes)) > 1:
                _logging.debug(
                    "nfsets name %r: multiple size= values %r; using max %d",
                    name, explicit_sizes, max(explicit_sizes),
                )
            set_size = max(explicit_sizes)
        elif has_ip:
            set_size = _DEFAULT_SIZE_IPLIST
        else:
            set_size = _DEFAULT_SIZE_DNS

        # Backend list for the comment (sorted for determinism).
        backends_label = ", ".join(sorted(group_backends))

        v4_name = nfset_to_set_name(name, "v4")
        v6_name = nfset_to_set_name(name, "v6")
        for set_name, nft_type in (
            (v4_name, "ipv4_addr"),
            (v6_name, "ipv6_addr"),
        ):
            lines.append(f"{indent}# nfset:{name} ({backends_label})")
            lines.append(f"{indent}set {set_name} {{")
            lines.append(f"{indent}\ttype {nft_type};")
            lines.append(f"{indent}\tflags {flags_str};")
            lines.append(f"{indent}\tsize {set_size};")
            lines.append(f"{indent}}}")
            lines.append("")

    return lines


# ---------------------------------------------------------------------------
# Payload round-trip
# ---------------------------------------------------------------------------


def nfset_registry_to_payload(registry: NfSetRegistry) -> dict:
    """Serialise *registry* to a JSON-safe dict for the control socket.

    The returned dict can be merged into a ``register-instance`` payload
    under the ``"nfsets"`` key.  Use :func:`payload_to_nfset_registry` on
    the daemon side to reconstruct the registry.
    """
    return {
        "entries": [
            {
                "name": e.name,
                "hosts": list(e.hosts),
                "backend": e.backend,
                "options": {k: list(v) for k, v in e.options.items()},
                "refresh": e.refresh,
                "dns_servers": list(e.dns_servers),
                "inotify": e.inotify,
                "dnstype": e.dnstype,
                "size": e.size,
            }
            for e in registry.entries
        ],
    }


def payload_to_nfset_registry(payload: dict) -> NfSetRegistry:
    """Reconstruct an :class:`NfSetRegistry` from a payload dict.

    Counterpart to :func:`nfset_registry_to_payload`.  Round-trips
    losslessly: ``payload_to_nfset_registry(nfset_registry_to_payload(r))``
    returns a registry equal to *r*.
    """
    registry = NfSetRegistry()
    for d in payload.get("entries", []):
        entry = NfSetEntry(
            name=d["name"],
            hosts=list(d["hosts"]),
            backend=d["backend"],
            options={k: list(v) for k, v in d.get("options", {}).items()},
            refresh=d.get("refresh"),
            dns_servers=list(d.get("dns_servers", [])),
            inotify=bool(d.get("inotify", False)),
            dnstype=d.get("dnstype"),
            size=d.get("size"),
        )
        registry.entries.append(entry)
        registry.set_names.add(entry.name)
    return registry
