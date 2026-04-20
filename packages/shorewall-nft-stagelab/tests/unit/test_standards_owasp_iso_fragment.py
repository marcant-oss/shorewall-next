"""Unit tests for the OWASP + ISO/IEC 27001 standards fragment (B3)."""
from __future__ import annotations

import re

import pytest

from shorewall_nft_stagelab.standards_owasp_iso27001 import (
    OUT_OF_SCOPE,
    TEST_ID_FRAGMENT,
)

_SLUG_RE = re.compile(r"^[a-z0-9]+([-_][a-z0-9]+)*$")

_ALLOWED_STANDARDS = {"owasp", "iso-27001"}


class TestFragmentNonEmpty:
    def test_fragment_has_entries(self) -> None:
        assert len(TEST_ID_FRAGMENT) > 0, "TEST_ID_FRAGMENT must not be empty"

    def test_out_of_scope_has_entries(self) -> None:
        assert len(OUT_OF_SCOPE) > 0, "OUT_OF_SCOPE must not be empty"


class TestSlugValidity:
    @pytest.mark.parametrize("slug", list(TEST_ID_FRAGMENT.keys()))
    def test_slug_format(self, slug: str) -> None:
        assert _SLUG_RE.match(slug), (
            f"test_id slug {slug!r} does not match ^[a-z0-9]+([-_][a-z0-9]+)*$"
        )

    @pytest.mark.parametrize("slug", list(OUT_OF_SCOPE.keys()))
    def test_out_of_scope_slug_format(self, slug: str) -> None:
        assert _SLUG_RE.match(slug), (
            f"out_of_scope slug {slug!r} does not match ^[a-z0-9]+([-_][a-z0-9]+)*$"
        )


class TestTupleShape:
    @pytest.mark.parametrize("slug,entry", list(TEST_ID_FRAGMENT.items()))
    def test_entry_is_3_tuple(self, slug: str, entry: object) -> None:
        assert isinstance(entry, tuple), f"{slug}: expected tuple, got {type(entry)}"
        assert len(entry) == 3, f"{slug}: expected 3-tuple, got {len(entry)}-tuple"  # type: ignore[arg-type]

    @pytest.mark.parametrize("slug,entry", list(TEST_ID_FRAGMENT.items()))
    def test_entry_fields_are_strings(self, slug: str, entry: tuple) -> None:
        standard, control, title = entry
        assert isinstance(standard, str) and standard, f"{slug}: standard must be non-empty str"
        assert isinstance(control, str) and control, f"{slug}: control must be non-empty str"
        assert isinstance(title, str) and title, f"{slug}: title must be non-empty str"


class TestStandards:
    def test_only_allowed_standards(self) -> None:
        found = {entry[0] for entry in TEST_ID_FRAGMENT.values()}
        unknown = found - _ALLOWED_STANDARDS
        assert not unknown, (
            f"Unexpected standard labels: {unknown!r}. "
            f"Allowed: {_ALLOWED_STANDARDS!r}"
        )

    def test_both_standards_present(self) -> None:
        found = {entry[0] for entry in TEST_ID_FRAGMENT.values()}
        for expected in _ALLOWED_STANDARDS:
            assert expected in found, (
                f"Standard {expected!r} has no entries in TEST_ID_FRAGMENT"
            )


class TestCounts:
    def test_owasp_entry_count(self) -> None:
        owasp = [slug for slug, e in TEST_ID_FRAGMENT.items() if e[0] == "owasp"]
        assert len(owasp) >= 8, (
            f"Expected at least 8 OWASP entries, got {len(owasp)}: {owasp}"
        )

    def test_iso27001_entry_count(self) -> None:
        iso = [slug for slug, e in TEST_ID_FRAGMENT.items() if e[0] == "iso-27001"]
        assert len(iso) >= 8, (
            f"Expected at least 8 ISO-27001 entries, got {len(iso)}: {iso}"
        )


class TestKeyOWASPEntries:
    """Spot-check that critical OWASP controls are present."""

    @pytest.mark.parametrize("slug", [
        "owasp-fw-1-config-review",
        "owasp-fw-2-rulebase-audit",
        "owasp-fw-3-default-deny",
        "owasp-fw-4-evasion-bypass",
        "owasp-fw-5-stateful-inspection",
        "owasp-fw-6-ha-failover",
        "owasp-fw-7-protocol-stack",
        "owasp-fw-8-operational-hardening",
    ])
    def test_owasp_slug_present(self, slug: str) -> None:
        assert slug in TEST_ID_FRAGMENT, f"Missing expected OWASP entry: {slug!r}"

    @pytest.mark.parametrize("slug,expected_control", [
        ("owasp-fw-1-config-review", "FW-1"),
        ("owasp-fw-3-default-deny", "FW-3"),
        ("owasp-fw-6-ha-failover", "FW-6"),
    ])
    def test_owasp_control_id(self, slug: str, expected_control: str) -> None:
        _std, control, _title = TEST_ID_FRAGMENT[slug]
        assert control == expected_control, (
            f"{slug}: expected control {expected_control!r}, got {control!r}"
        )


class TestKeyISO27001Entries:
    """Spot-check that critical ISO 27001 controls are present."""

    @pytest.mark.parametrize("slug", [
        "iso27001-a-13-1-1-network-controls",
        "iso27001-a-13-1-3-network-segregation",
        "iso27001-a-12-4-1-event-logging",
        "iso27001-a-18-2-1-security-review",
        "iso27001-a-18-2-2-policy-compliance",
    ])
    def test_iso27001_slug_present(self, slug: str) -> None:
        assert slug in TEST_ID_FRAGMENT, f"Missing expected ISO-27001 entry: {slug!r}"

    @pytest.mark.parametrize("slug,expected_control", [
        ("iso27001-a-13-1-1-network-controls", "A.13.1.1"),
        ("iso27001-a-13-1-3-network-segregation", "A.13.1.3"),
        ("iso27001-a-18-2-1-security-review", "A.18.2.1"),
    ])
    def test_iso27001_control_id(self, slug: str, expected_control: str) -> None:
        _std, control, _title = TEST_ID_FRAGMENT[slug]
        assert control == expected_control, (
            f"{slug}: expected control {expected_control!r}, got {control!r}"
        )


class TestNoDuplicateSlugs:
    def test_all_slugs_unique(self) -> None:
        # dict keys are inherently unique; verify count vs sorted list as
        # a sanity check against copy-paste errors.
        slugs = list(TEST_ID_FRAGMENT.keys())
        assert len(slugs) == len(set(slugs)), "Duplicate slug detected in TEST_ID_FRAGMENT"
