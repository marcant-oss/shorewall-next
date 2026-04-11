"""Flowtable generation for hardware/software offloading.

Generates nft flowtable declarations and flow offload rules
in the forward chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# nft hook-priority keywords for the ingress hook. These are the
# standard aliases shipped in the kernel; numeric priorities are also
# accepted via int(). Keep in sync with:
# https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains
_PRIORITY_ALIASES = {
    "raw":     -300,
    "mangle":  -150,
    "dstnat":  -100,
    "filter":     0,
    "security":  50,
    "srcnat":   100,
}

# Tokens accepted in FLOWTABLE_FLAGS. Anything else is passed through
# verbatim (for forward compatibility with newer kernels) but warned
# about in the compiler output.
_KNOWN_FLAGS = frozenset({"offload"})


@dataclass
class Flowtable:
    """An nft flowtable for connection offloading."""
    name: str = "ft"
    hook: str = "ingress"
    priority: int = 0
    devices: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    counter: bool = False


def parse_priority(raw: str | int) -> int:
    """Normalise a priority spec (keyword or int) to a kernel value.

    Accepts any of the standard hook-priority keywords ``raw``,
    ``mangle``, ``dstnat``, ``filter``, ``security``, ``srcnat`` — or
    a signed integer literal. Unknown strings raise ``ValueError``.
    """
    if isinstance(raw, int):
        return raw
    s = raw.strip().lower()
    if not s:
        return 0
    if s in _PRIORITY_ALIASES:
        return _PRIORITY_ALIASES[s]
    try:
        return int(s, 0)
    except ValueError as e:
        raise ValueError(
            f"invalid flowtable priority {raw!r}: "
            f"expected integer or one of {sorted(_PRIORITY_ALIASES)}"
        ) from e


def parse_flags(raw: str) -> list[str]:
    """Parse a FLOWTABLE_FLAGS=… shorewall.conf value into a flag list.

    Accepts comma- or whitespace-separated tokens. Empty/disabled values
    return an empty list. Duplicate flags are collapsed; order is
    preserved.
    """
    s = (raw or "").strip().strip('"').strip("'")
    if not s or s.lower() in ("no", "false", "0", "off"):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for tok in s.replace(",", " ").split():
        t = tok.strip().lower()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def emit_flowtable(ft: Flowtable) -> str:
    """Generate an nft flowtable declaration.

    Produces a single stanza suitable for embedding at the top of an
    ``inet``/``ip`` table. Counter and flags are emitted as separate
    lines so each is optional and easy to grep.
    """
    devices = ", ".join(f'"{d}"' for d in ft.devices)
    body_lines = [
        f"\t\thook {ft.hook} priority {ft.priority};",
        f"\t\tdevices = {{ {devices} }};",
    ]
    if ft.counter:
        body_lines.append("\t\tcounter")
    if ft.flags:
        body_lines.append(f"\t\tflags {', '.join(ft.flags)};")
    return "\tflowtable {} {{\n{}\n\t}}".format(ft.name, "\n".join(body_lines))


def emit_flow_offload_rule(ft_name: str = "ft") -> str:
    """Generate a flow offload rule for the forward chain."""
    return f"meta l4proto {{ tcp, udp }} flow add @{ft_name}"
