"""Brace expansion for nfsets host patterns.

Supports a single (non-nested) brace group of the form ``{a,b,c}.suffix``.
No nesting, no escaping.  If the input contains no ``{``, the input is
returned as a one-element list unchanged.
"""

from __future__ import annotations

import re

# Match exactly one brace group (non-nested) and capture prefix, alternatives,
# and suffix.  Example: "{a,b}.example.org" → prefix="", alts="a,b",
# suffix=".example.org".
_BRACE_RE = re.compile(r"^([^{]*)\{([^{}]*)\}(.*)$")


def expand_brace(pattern: str) -> list[str]:
    """Expand ``{a,b,c}.foo.org`` → ``["a.foo.org", "b.foo.org", "c.foo.org"]``.

    Only the **first** (left-most) brace group is expanded.  Nested braces
    and multiple brace groups are out of scope — the function expands the
    first group and leaves any remaining brace syntax in the suffix
    un-expanded.

    Special cases:

    * No braces → returns ``[pattern]`` (single-element list, unchanged).
    * Empty braces ``{}`` → returns a single entry with an empty substitution,
      i.e. ``expand_brace("{}.example.org")`` → ``[".example.org"]``.
    * Empty alternatives inside braces (e.g. ``{a,,b}``) → the empty
      alternative produces an entry with an empty substitution for that slot,
      i.e. ``["a.x", ".x", "b.x"]``.

    The function never raises; callers that want to reject empty alternatives
    should inspect the result themselves.
    """
    m = _BRACE_RE.match(pattern)
    if m is None:
        return [pattern]

    prefix, alts_str, suffix = m.group(1), m.group(2), m.group(3)
    alternatives = alts_str.split(",")
    return [f"{prefix}{alt}{suffix}" for alt in alternatives]
