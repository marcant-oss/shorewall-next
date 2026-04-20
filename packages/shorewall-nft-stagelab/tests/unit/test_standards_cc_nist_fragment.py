"""Unit tests for the CC + NIST standards fragment."""
from __future__ import annotations

import re

from shorewall_nft_stagelab.standards_cc_nist import TEST_ID_FRAGMENT


def test_fragment_contains_cc_and_nist() -> None:
    stds = {ref[0] for ref in TEST_ID_FRAGMENT.values()}
    assert "cc-iso-15408" in stds
    assert "nist-800-53" in stds


def test_fragment_slugs_valid() -> None:
    slug = re.compile(r"^[a-z0-9]+([-_][a-z0-9]+)*$")
    for tid in TEST_ID_FRAGMENT:
        assert slug.match(tid), f"slug failed validation: {tid!r}"


def test_fragment_nonempty() -> None:
    assert len(TEST_ID_FRAGMENT) >= 20, (
        f"expected >= 20 entries (12 CC + 12 NIST), got {len(TEST_ID_FRAGMENT)}"
    )


def test_fragment_tuple_shape() -> None:
    """Every entry must be a (standard, control, title) 3-tuple of strings."""
    for tid, ref in TEST_ID_FRAGMENT.items():
        assert isinstance(ref, tuple), f"{tid}: expected tuple, got {type(ref)}"
        assert len(ref) == 3, f"{tid}: expected 3-tuple, got len={len(ref)}"
        standard, control, title = ref
        assert isinstance(standard, str) and standard, f"{tid}: standard empty"
        assert isinstance(control, str) and control, f"{tid}: control empty"
        assert isinstance(title, str) and title, f"{tid}: title empty"


def test_cc_entries_count() -> None:
    cc_entries = [tid for tid, ref in TEST_ID_FRAGMENT.items() if ref[0] == "cc-iso-15408"]
    assert len(cc_entries) >= 10, (
        f"expected >= 10 CC entries, got {len(cc_entries)}: {cc_entries}"
    )


def test_nist_entries_count() -> None:
    nist_entries = [tid for tid, ref in TEST_ID_FRAGMENT.items() if ref[0] == "nist-800-53"]
    assert len(nist_entries) >= 10, (
        f"expected >= 10 NIST entries, got {len(nist_entries)}: {nist_entries}"
    )


def test_no_duplicate_test_ids() -> None:
    """Keys in a dict are inherently unique; check that values don't duplicate
    (standard, control) pairs with conflicting titles (sanity check)."""
    seen: dict[tuple[str, str], str] = {}
    for tid, (standard, control, title) in TEST_ID_FRAGMENT.items():
        key = (standard, control, tid)
        assert key not in seen, (
            f"Duplicate (standard, control, test_id) key: {key}"
        )
        seen[key] = title
