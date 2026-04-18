"""Shared helpers for DNS-backed nftables sets.

The compiler and shorewalld both need to agree on:

1. **Naming** — how a hostname like ``api.stripe.com`` becomes an nft
   set name. Must be deterministic so the compiler can declare the set
   and shorewalld can write to the exact same one from dnstap/pbdns
   frames without any string manipulation drift.

2. **Set schema** — the type, flags, and size-limit of each DNS set.
   Declared by the compiler inside ``inet shorewall``; populated at
   runtime by shorewalld via ``add element inet shorewall <name>``.

3. **Allowlist file format** — the compiler emits
   ``/etc/shorewall/dnsnames.compiled`` listing every hostname that
   appears in the active ruleset, together with the per-name
   TTL floor/ceil/size overrides. shorewalld reads that file at
   startup and loads it into its ``QnameFilter`` so only interesting
   qnames make it past the two-pass decoder.

Both sides import this module. Never duplicate the sanitisation rules
anywhere else — drift between compiler-side and runtime-side naming
means the ruleset references a set the daemon never populates.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from pathlib import Path

# nftables identifier limit: 31 chars including trailing NUL on older
# kernels, 255 on modern ones. We target 31 for maximum compatibility.
# This leaves ``_v4`` / ``_v6`` suffix (3 chars) + ``dns_`` prefix (4)
# = 7 overhead, leaving 24 chars for the sanitised qname body.
MAX_SET_NAME_LEN = 31
_PREFIX = "dns_"
_SUFFIX_V4 = "_v4"
_SUFFIX_V6 = "_v6"
_BODY_LIMIT = MAX_SET_NAME_LEN - len(_PREFIX) - len(_SUFFIX_V4)

# Default values — overridable per-name in the ``dnsnames`` config file
# or globally via ``shorewall.conf`` keys ``DNS_SET_TTL_FLOOR``,
# ``DNS_SET_TTL_CEIL``, ``DNS_SET_SIZE``.
DEFAULT_TTL_FLOOR = 300      # seconds — don't let super-short TTLs thrash
DEFAULT_TTL_CEIL = 86400     # seconds — cap pathological multi-day records
DEFAULT_SET_SIZE = 512       # max elements per set

# A character is safe for an nft identifier body if it matches this.
_SAFE_CHAR = re.compile(r"[a-z0-9]")

# A token is considered a DNS hostname if it contains at least one
# letter, at least one dot, and no characters that belong to IPv4 or
# IPv6 literals. Used by the rules parser to classify ``dns:…`` tokens.
_HOST_LABEL = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?$")


@dataclass(frozen=True)
class DnsSetSpec:
    """Per-hostname override for compiled DNS sets.

    A ``dnsnames`` file line produces one ``DnsSetSpec``; hostnames
    that appear only in ``rules`` (no explicit entry) fall back to the
    global defaults from ``shorewall.conf``.

    ``declare_set`` is True for any hostname the emitter should
    materialise as an nft set, False for ``dnsr:`` secondaries that
    only need to be in the allowlist so the tap filter passes them
    through to the primary's set via tracker alias.
    """

    qname: str                  # canonical lower-case form, no trailing dot
    ttl_floor: int = DEFAULT_TTL_FLOOR
    ttl_ceil: int = DEFAULT_TTL_CEIL
    size: int = DEFAULT_SET_SIZE
    comment: str = ""
    declare_set: bool = True


@dataclass
class DnsSetRegistry:
    """Collects every hostname referenced by the compiled ruleset.

    Populated during IR build by ``_process_rules`` (when it sees a
    ``dns:`` token) and ``_process_dnsnames`` (explicit declarations
    from the ``dnsnames`` file). The emitter reads this at the end to
    produce set declarations, and the start command writes the compiled
    allowlist file that shorewalld consumes.
    """

    # qname → resolved spec (possibly a default-filled one)
    specs: dict[str, DnsSetSpec] = field(default_factory=dict)
    # Global defaults, applied to any qname that has no explicit entry.
    default_ttl_floor: int = DEFAULT_TTL_FLOOR
    default_ttl_ceil: int = DEFAULT_TTL_CEIL
    default_size: int = DEFAULT_SET_SIZE

    def add_from_rule(
        self, qname: str, *, declare_set: bool = True,
    ) -> DnsSetSpec:
        """Register a hostname seen in ``rules``.

        Creates a default-filled spec if none exists yet; leaves an
        existing one untouched so per-name overrides from ``dnsnames``
        always win over rule-origin discovery.

        ``declare_set=False`` marks the entry as a tap-filter-only
        allowlist entry (``dnsr:`` secondary). A subsequent call with
        ``declare_set=True`` promotes it so the emitter materialises
        the set — explicit ``dns:`` references always win over a
        secondary-only registration.
        """
        qn = canonical_qname(qname)
        if qn not in self.specs:
            self.specs[qn] = DnsSetSpec(
                qname=qn,
                ttl_floor=self.default_ttl_floor,
                ttl_ceil=self.default_ttl_ceil,
                size=self.default_size,
                declare_set=declare_set,
            )
        elif declare_set and not self.specs[qn].declare_set:
            # Promote: was a secondary-only entry, now also referenced
            # as a primary → emit the set.
            self.specs[qn] = dataclasses.replace(
                self.specs[qn], declare_set=True,
            )
        return self.specs[qn]

    def add_spec(self, spec: DnsSetSpec) -> None:
        """Register or replace a spec from the ``dnsnames`` config file."""
        self.specs[canonical_qname(spec.qname)] = spec

    def set_names(self, qname: str) -> tuple[str, str]:
        """Return ``(v4_name, v6_name)`` for a hostname.

        Deterministic: same input always yields the same pair, so the
        compiler and runtime can agree without any shared state.
        """
        qn = canonical_qname(qname)
        return qname_to_set_name(qn, "v4"), qname_to_set_name(qn, "v6")

    def iter_sorted(self) -> list[DnsSetSpec]:
        """Sorted list of specs for stable emitter output."""
        return [self.specs[k] for k in sorted(self.specs)]


# ---------------------------------------------------------------------------
# Sanitisation and classification
# ---------------------------------------------------------------------------


def canonical_qname(qname: str) -> str:
    """Lower-case and strip trailing dot from a DNS name.

    ``Github.Com.`` → ``github.com``. The canonical form is what
    registries and the tracker key on — never hash a mixed-case or
    trailing-dot name without normalising first, or the compiler and
    runtime will disagree about set identity.
    """
    s = qname.strip().lower()
    if s.endswith("."):
        s = s[:-1]
    return s


@dataclass
class DnsrGroup:
    """A DNS-set alias group: one or more hostnames share one nft set.

    Covers two related concepts with the same data shape:

    * ``dnsr:host1,host2,…`` (``pull_enabled=True``): shorewalld actively
      resolves every hostname on a TTL-driven schedule AND the tap
      pipeline routes any matching dnstap/pbdns frame into the primary's
      set via a tracker alias.
    * ``dns:host1,host2,…`` with multiple hosts (``pull_enabled=False``):
      tap-only aliasing — the primary's set absorbs every secondary's
      answer but shorewalld does not actively resolve.

    Single-host ``dns:host`` does not create a group at all (no alias
    needed).
    """
    primary_qname: str           # determines the set name (dns_<primary>_v4/v6)
    qnames: list[str]            # all hostnames (primary first, then secondaries)
    ttl_floor: int = DEFAULT_TTL_FLOOR
    ttl_ceil: int = DEFAULT_TTL_CEIL
    size: int = DEFAULT_SET_SIZE
    comment: str = ""
    pull_enabled: bool = True


@dataclass
class DnsrRegistry:
    """Collects all ``dnsr:`` groups declared in the compiled ruleset.

    Groups are keyed by ``primary_qname``.  Multiple rules that share
    the same primary hostname merge their secondary qname lists into
    one group so the pull resolver resolves each hostname exactly once
    per TTL cycle regardless of how many rules reference it.
    """
    groups: dict[str, DnsrGroup] = field(default_factory=dict)
    default_ttl_floor: int = DEFAULT_TTL_FLOOR
    default_ttl_ceil: int = DEFAULT_TTL_CEIL
    default_size: int = DEFAULT_SET_SIZE

    def add_from_rule(
        self,
        primary: str,
        qnames: list[str],
        *,
        pull_enabled: bool = True,
    ) -> DnsrGroup:
        """Register or extend a group from a ``dns:`` / ``dnsr:`` token.

        ``pull_enabled=True`` (default) marks the group as a
        pull-resolver target; ``False`` records only the tap-alias
        relationship (used by multi-host ``dns:``). If a group is
        referenced once as ``dnsr:`` and once as ``dns:``, the
        pull-enabled flag wins — a later ``dns:`` reference never
        demotes an active pull group.
        """
        pqn = canonical_qname(primary)
        if pqn not in self.groups:
            self.groups[pqn] = DnsrGroup(
                primary_qname=pqn,
                qnames=list(dict.fromkeys(
                    canonical_qname(q) for q in qnames)),
                ttl_floor=self.default_ttl_floor,
                ttl_ceil=self.default_ttl_ceil,
                size=self.default_size,
                pull_enabled=pull_enabled,
            )
        else:
            existing = self.groups[pqn]
            seen = set(existing.qnames)
            for q in qnames:
                cq = canonical_qname(q)
                if cq not in seen:
                    existing.qnames.append(cq)
                    seen.add(cq)
            if pull_enabled and not existing.pull_enabled:
                existing.pull_enabled = True
        return self.groups[pqn]

    def iter_sorted(self) -> list[DnsrGroup]:
        """Stable-sorted list for deterministic output."""
        return [self.groups[k] for k in sorted(self.groups)]


def is_dns_token(value: str) -> bool:
    """True if ``value`` looks like a Shorewall ``dns:hostname`` token.

    The compiler's rule parser calls this to classify DEST/SOURCE
    column entries before deciding which match expression to emit.
    """
    return value.startswith("dns:") and len(value) > 4


def is_dnsr_token(value: str) -> bool:
    """True if ``value`` looks like a ``dnsr:hostname[,hostname…]`` token.

    ``dnsr:`` is the pull-resolver variant of ``dns:``.  Same nft set,
    same set-name formula — shorewalld additionally resolves the listed
    hostnames actively on a TTL-driven schedule.
    """
    return value.startswith("dnsr:") and len(value) > 5


def qname_to_set_name(qname: str, family: str) -> str:
    """Deterministic hostname → nft set name mapping.

    Rules:

    * Canonicalise to lower-case, strip trailing dot.
    * Replace every non-``[a-z0-9]`` character (dots, hyphens, wildcards,
      anything weird) with ``_``.
    * Collapse runs of ``_`` so ``foo..bar`` and ``foo-.bar`` both
      become ``foo_bar``.
    * Truncate the body to ``MAX_SET_NAME_LEN - len("dns__v4") = 24``
      characters. Truncation uses the SHA-1 prefix of the full qname
      as a collision-safe tail so two long, similar names stay unique.
    * Prepend ``dns_`` and append ``_v4`` / ``_v6`` per family.

    Deterministic across Python versions — no ``hash()`` involved.
    The SHA-1 is purely for collision avoidance on truncated names,
    not for any security purpose.
    """
    qn = canonical_qname(qname)
    # Sanitise body — replace unsafe characters with underscore.
    body = "".join(
        ch if _SAFE_CHAR.match(ch) else "_" for ch in qn)
    # Collapse repeated underscores.
    while "__" in body:
        body = body.replace("__", "_")
    body = body.strip("_")
    if not body:
        body = "x"

    if len(body) > _BODY_LIMIT:
        # Keep a deterministic short hash suffix so similarly-prefixed
        # truncations stay unique. SHA-1 is not used for security here.
        import hashlib
        h = hashlib.sha1(qn.encode("utf-8")).hexdigest()[:6]
        head_len = _BODY_LIMIT - len(h) - 1
        body = f"{body[:head_len]}_{h}"

    suffix = _SUFFIX_V4 if family == "v4" else _SUFFIX_V6
    return f"{_PREFIX}{body}{suffix}"


def is_valid_hostname(value: str) -> bool:
    """Strict hostname validation used when parsing ``dns:`` tokens.

    Rejects empty strings, IP literals disguised as hostnames, and
    inputs with control characters or whitespace. Each label must
    satisfy RFC 1035 length and character rules.
    """
    if not value or len(value) > 253:
        return False
    s = value.rstrip(".")
    if not s:
        return False
    # IPv4 literal?
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s):
        return False
    # IPv6 literal?
    if ":" in s:
        return False
    labels = s.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not _HOST_LABEL.match(label):
            return False
    return True


# ---------------------------------------------------------------------------
# nft set declaration emission
# ---------------------------------------------------------------------------


def emit_dns_set_declarations(
    registry: DnsSetRegistry, indent: str = "\t"
) -> list[str]:
    """Return nft script lines declaring all DNS sets.

    Called by the emitter to append DNS set blocks to the
    ``inet shorewall`` table body, right after the regular
    ``emit_nft_sets()`` output. Each hostname produces two sets —
    one for ``ipv4_addr`` and one for ``ipv6_addr`` — so dual-stack
    rules can reference either half.

    Format::

        set dns_github_com_v4 {
                type ipv4_addr;
                flags timeout;
                size 512;
        }
        set dns_github_com_v6 {
                type ipv6_addr;
                flags timeout;
                size 512;
        }

    ``timeout`` flag is mandatory — shorewalld adds elements with
    per-element timeouts derived from the DNS answer's TTL, so the
    set must accept timeout values.
    """
    if not registry.specs:
        return []
    lines: list[str] = []
    lines.append("")
    lines.append(f"{indent}# DNS-managed sets (populated by shorewalld")
    lines.append(f"{indent}# from dnstap/pbdns frames; see dnsnames.compiled)")
    for spec in registry.iter_sorted():
        # Secondaries of dnsr: groups live in the allowlist for the tap
        # filter but share the primary's nft set — skip declaration.
        if not spec.declare_set:
            continue
        v4_name, v6_name = qname_to_set_name(spec.qname, "v4"), \
            qname_to_set_name(spec.qname, "v6")
        for name, nft_type in ((v4_name, "ipv4_addr"), (v6_name, "ipv6_addr")):
            if spec.comment:
                lines.append(
                    f'{indent}# {spec.qname}: {spec.comment}')
            else:
                lines.append(f"{indent}# {spec.qname}")
            lines.append(f"{indent}set {name} {{")
            lines.append(f"{indent}\ttype {nft_type};")
            lines.append(f"{indent}\tflags timeout;")
            lines.append(f"{indent}\tsize {spec.size};")
            lines.append(f"{indent}}}")
            lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Compiled allowlist file — the compiler↔shorewalld interface
# ---------------------------------------------------------------------------


ALLOWLIST_HEADER = (
    "# shorewall-nft compiled DNS name allowlist.\n"
    "# Generated by the compiler — do not edit by hand.\n"
    "# [dns] columns: qname ttl_floor ttl_ceil size comment\n"
)

_DNSR_SECTION_HEADER = (
    "\n[dnsr]\n"
    "# primary_qname\tttl_floor\tttl_ceil\tsize\tqnames\tpull\tcomment\n"
)


def write_compiled_allowlist(
    registry: DnsSetRegistry,
    path: Path,
    *,
    dnsr_registry: "DnsrRegistry | None" = None,
) -> None:
    """Write the per-qname allowlist file consumed by shorewalld.

    One line per hostname in stable sorted order. The file serves two
    purposes:

    * **Allowlist**: shorewalld's two-pass decoder rejects any frame
      whose qname is not in this file before the expensive full decode.
    * **Per-name overrides**: the daemon honours the per-name TTL
      floor/ceil and set size when pushing elements, so the compiler's
      intent stays authoritative.

    When ``dnsr_registry`` is supplied, a ``[dnsr]`` section is appended
    listing the pull-resolver groups.  shorewalld reads this section to
    know which hostnames to resolve actively and which sets to populate.

    Atomic write via temp-and-rename so a concurrent daemon reload
    never sees a half-written file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    parts = [ALLOWLIST_HEADER]
    for spec in registry.iter_sorted():
        comment = spec.comment.replace("\t", " ").replace("\n", " ")
        parts.append(
            f"{spec.qname}\t{spec.ttl_floor}\t"
            f"{spec.ttl_ceil}\t{spec.size}\t{comment}\n")
    if dnsr_registry and dnsr_registry.groups:
        parts.append(_DNSR_SECTION_HEADER)
        for group in dnsr_registry.iter_sorted():
            comment = group.comment.replace("\t", " ").replace("\n", " ")
            qnames_str = ",".join(group.qnames)
            pull = "1" if group.pull_enabled else "0"
            parts.append(
                f"{group.primary_qname}\t{group.ttl_floor}\t"
                f"{group.ttl_ceil}\t{group.size}\t{qnames_str}\t"
                f"{pull}\t{comment}\n")
    tmp.write_text("".join(parts))
    tmp.replace(path)


def read_compiled_allowlist(path: Path) -> DnsSetRegistry:
    """Parse the ``[dns]`` section of the compiled allowlist.

    Used by shorewalld at startup (and on reload-monitor signals) to
    load the current set of managed hostnames without re-parsing the
    raw ``dnsnames`` file — the compiled form is the stable contract.

    Stops at the ``[dnsr]`` section header; that section is read by
    :func:`read_compiled_dnsr_allowlist`.
    """
    registry = DnsSetRegistry()
    if not path.exists():
        return registry
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            break  # stop at any section header (e.g. [dnsr])
        cols = line.split("\t")
        if len(cols) < 4:
            continue
        try:
            qn = canonical_qname(cols[0])
            ttl_floor = int(cols[1])
            ttl_ceil = int(cols[2])
            size = int(cols[3])
        except ValueError:
            continue
        comment = cols[4] if len(cols) > 4 else ""
        registry.add_spec(DnsSetSpec(
            qname=qn,
            ttl_floor=ttl_floor,
            ttl_ceil=ttl_ceil,
            size=size,
            comment=comment,
        ))
    return registry


def read_compiled_dnsr_allowlist(path: Path) -> DnsrRegistry:
    """Parse the ``[dnsr]`` section of the compiled allowlist.

    Returns a :class:`DnsrRegistry` listing every pull-resolver group
    the compiler found in the ruleset.  Each group maps a primary
    hostname (which determines the nft set name) to the full list of
    hostnames that should be actively resolved into that set.

    Returns an empty registry if the file does not exist or has no
    ``[dnsr]`` section.
    """
    registry = DnsrRegistry()
    if not path.exists():
        return registry
    in_dnsr = False
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line == "[dnsr]":
            in_dnsr = True
            continue
        if not in_dnsr:
            continue
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) < 5:
            continue
        try:
            primary = canonical_qname(cols[0])
            ttl_floor = int(cols[1])
            ttl_ceil = int(cols[2])
            size = int(cols[3])
        except ValueError:
            continue
        qnames_str = cols[4]
        qnames = [canonical_qname(q) for q in qnames_str.split(",") if q.strip()]
        # New format: pull column before comment. Older files without
        # the pull column default to pull_enabled=True (legacy dnsr:
        # groups all had active pull).
        pull_enabled = True
        comment = ""
        if len(cols) > 5:
            pull_col = cols[5].strip()
            if pull_col in ("0", "1"):
                pull_enabled = pull_col == "1"
                comment = cols[6] if len(cols) > 6 else ""
            else:
                # Legacy: column 5 is the comment.
                comment = pull_col
        if not qnames:
            qnames = [primary]
        registry.groups[primary] = DnsrGroup(
            primary_qname=primary,
            qnames=qnames,
            ttl_floor=ttl_floor,
            ttl_ceil=ttl_ceil,
            size=size,
            comment=comment,
            pull_enabled=pull_enabled,
        )
    return registry


def parse_dnsnames_file(
    lines: list[str] | list["object"],
    default_ttl_floor: int = DEFAULT_TTL_FLOOR,
    default_ttl_ceil: int = DEFAULT_TTL_CEIL,
    default_size: int = DEFAULT_SET_SIZE,
) -> list[DnsSetSpec]:
    """Parse raw rows of the ``dnsnames`` config file.

    Format (columns separated by whitespace, ``-`` for "use default"):

    ::

        # NAME            TTL_FLOOR  TTL_CEIL  SIZE   COMMENT
        github.com        300        86400     256    GitHub API+web
        api.stripe.com    60         3600      64     Payment webhooks
        cdn.example.com   -          -         -      Uses defaults

    Input is either a raw list of strings (one line each) or the
    ``ConfigLine`` objects produced by the columnar parser; the
    function accepts both by duck-typing on ``.columns``.
    """
    specs: list[DnsSetSpec] = []
    for item in lines:
        cols: list[str]
        if hasattr(item, "columns"):
            cols = list(item.columns)  # type: ignore[arg-type]
        elif isinstance(item, str):
            stripped = item.strip()
            if not stripped or stripped.startswith("#"):
                continue
            cols = stripped.split()
        else:
            continue
        if not cols:
            continue
        qname = cols[0]
        if not is_valid_hostname(qname):
            continue
        floor = _int_or_default(cols[1] if len(cols) > 1 else "-",
                                default_ttl_floor)
        ceil = _int_or_default(cols[2] if len(cols) > 2 else "-",
                               default_ttl_ceil)
        size = _int_or_default(cols[3] if len(cols) > 3 else "-",
                               default_size)
        comment = " ".join(cols[4:]) if len(cols) > 4 else ""
        specs.append(DnsSetSpec(
            qname=canonical_qname(qname),
            ttl_floor=floor,
            ttl_ceil=ceil,
            size=size,
            comment=comment,
        ))
    return specs


def _int_or_default(value: str, default: int) -> int:
    v = value.strip()
    if not v or v == "-":
        return default
    try:
        return int(v)
    except ValueError:
        return default
