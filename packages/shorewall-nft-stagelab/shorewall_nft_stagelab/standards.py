"""Standards-reference lookup for security-test-plan.

Each test_id maps to (standard, control, title) so that audit_report can
render the test alongside its compliance reference without the YAML
catalogue having to repeat descriptions.

Fragments are merged at import time by _build(); a duplicate test_id across
fragments raises ValueError immediately.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import (
    standards_bsi_cis,
    standards_cc_nist,
    standards_owasp_iso27001,
    standards_perf,
    standards_simlab,
)


@dataclass(frozen=True)
class StandardRef:
    standard: str   # e.g. "cis-benchmarks", "nist-800-53", "cc-iso-15408", "bsi-grundschutz", "owasp", "iso-27001"
    control: str    # e.g. "5.2.1", "SC-5", "FDP_IFF.1", "NET.3.2.A5", "FW-3", "A.13.1.3"
    title: str      # short human-readable


_FRAGMENTS = (
    standards_cc_nist.TEST_ID_FRAGMENT,
    standards_bsi_cis.TEST_ID_FRAGMENT,
    standards_owasp_iso27001.TEST_ID_FRAGMENT,
    standards_perf.TEST_ID_FRAGMENT,
    standards_simlab.TEST_ID_FRAGMENT,
)


def _build() -> dict[str, StandardRef]:
    out: dict[str, StandardRef] = {}
    for frag in _FRAGMENTS:
        for tid, tup in frag.items():
            if tid in out:
                raise ValueError(
                    f"duplicate test_id across standards fragments: {tid!r}"
                )
            out[tid] = StandardRef(*tup)
    return out


TEST_ID: dict[str, StandardRef] = _build()


def lookup(test_id: str) -> StandardRef | None:
    """Return the StandardRef for *test_id* or None if unknown."""
    return TEST_ID.get(test_id)


def all_standards() -> set[str]:
    """Return the set of distinct standard labels present."""
    return {ref.standard for ref in TEST_ID.values()}


__all__ = ["StandardRef", "TEST_ID", "lookup", "all_standards"]
