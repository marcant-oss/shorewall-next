"""Unit tests for shorewall_nft_stagelab.standards."""

from __future__ import annotations

from shorewall_nft_stagelab.standards import TEST_ID, StandardRef, all_standards, lookup


def test_lookup_known_returns_standard_ref():
    # owasp-fw-3-default-deny is defined in standards_owasp_iso27001 fragment
    ref = lookup("owasp-fw-3-default-deny")
    assert isinstance(ref, StandardRef)
    assert ref.control == "FW-3"
    assert ref.standard == "owasp"


def test_lookup_unknown_returns_none():
    result = lookup("does-not-exist")
    assert result is None


def test_all_standards_contains_expected():
    stds = all_standards()
    assert "owasp" in stds
    assert "nist-800-53" in stds
    assert "cc-iso-15408" in stds
    assert "bsi-grundschutz" in stds
    assert "cis-benchmarks" in stds
    assert "iso-27001" in stds
    assert "performance-ipv6" in stds


def test_test_id_has_minimum_entries():
    assert len(TEST_ID) >= 50, (
        f"expected >= 50 test_ids across all fragments, got {len(TEST_ID)}"
    )


def test_no_duplicate_test_ids():
    # _build() raises at import time if any duplicate exists; this test is
    # a belt-and-suspenders check that the dict is the correct length.
    from shorewall_nft_stagelab import (
        standards_bsi_cis,
        standards_cc_nist,
        standards_owasp_iso27001,
        standards_perf,
        standards_simlab,
    )
    total = sum(
        len(f)
        for f in (
            standards_cc_nist.TEST_ID_FRAGMENT,
            standards_bsi_cis.TEST_ID_FRAGMENT,
            standards_owasp_iso27001.TEST_ID_FRAGMENT,
            standards_perf.TEST_ID_FRAGMENT,
            standards_simlab.TEST_ID_FRAGMENT,
        )
    )
    assert len(TEST_ID) == total, (
        f"TEST_ID has {len(TEST_ID)} entries but fragments sum to {total}; "
        "likely a cross-fragment duplicate was silently dropped"
    )
