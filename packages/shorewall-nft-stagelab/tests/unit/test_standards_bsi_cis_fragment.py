"""Unit tests for the BSI IT-Grundschutz + CIS Benchmarks standards fragment."""

from __future__ import annotations

import re

import pytest

from shorewall_nft_stagelab.standards_bsi_cis import TEST_ID_FRAGMENT

_SLUG_RE = re.compile(r"^[a-z0-9]+([-_][a-z0-9]+)*$")
_ALLOWED_STANDARDS = {"bsi-grundschutz", "cis-benchmarks"}


# ---------------------------------------------------------------------------
# Basic sanity
# ---------------------------------------------------------------------------


def test_fragment_non_empty():
    assert len(TEST_ID_FRAGMENT) > 0, "TEST_ID_FRAGMENT must not be empty"


def test_fragment_has_bsi_entries():
    bsi_entries = {
        tid
        for tid, (std, _ctrl, _title) in TEST_ID_FRAGMENT.items()
        if std == "bsi-grundschutz"
    }
    assert len(bsi_entries) >= 8, (
        f"Expected at least 8 BSI entries, got {len(bsi_entries)}: {sorted(bsi_entries)}"
    )


def test_fragment_has_cis_entries():
    cis_entries = {
        tid
        for tid, (std, _ctrl, _title) in TEST_ID_FRAGMENT.items()
        if std == "cis-benchmarks"
    }
    assert len(cis_entries) >= 7, (
        f"Expected at least 7 CIS entries, got {len(cis_entries)}: {sorted(cis_entries)}"
    )


# ---------------------------------------------------------------------------
# Slug validity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("test_id", list(TEST_ID_FRAGMENT.keys()))
def test_slug_valid(test_id: str):
    assert _SLUG_RE.match(test_id), (
        f"test_id {test_id!r} does not match slug pattern ^[a-z0-9]+([-_][a-z0-9]+)*$"
    )


# ---------------------------------------------------------------------------
# Standard label validity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("test_id,entry", list(TEST_ID_FRAGMENT.items()))
def test_standard_label_allowed(test_id: str, entry: tuple):
    standard, _ctrl, _title = entry
    assert standard in _ALLOWED_STANDARDS, (
        f"test_id {test_id!r}: standard {standard!r} not in {_ALLOWED_STANDARDS}"
    )


# ---------------------------------------------------------------------------
# Structure validity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("test_id,entry", list(TEST_ID_FRAGMENT.items()))
def test_entry_is_three_tuple(test_id: str, entry: tuple):
    assert len(entry) == 3, (
        f"test_id {test_id!r}: entry must be (standard, control, title), got {entry!r}"
    )


@pytest.mark.parametrize("test_id,entry", list(TEST_ID_FRAGMENT.items()))
def test_entry_fields_non_empty(test_id: str, entry: tuple):
    standard, control, title = entry
    assert standard, f"test_id {test_id!r}: standard must not be empty"
    assert control, f"test_id {test_id!r}: control must not be empty"
    assert title, f"test_id {test_id!r}: title must not be empty"


# ---------------------------------------------------------------------------
# Specific key existence checks
# ---------------------------------------------------------------------------


def test_known_bsi_keys_present():
    expected = {
        "bsi-net-3-2-a2-function-separation",
        "bsi-net-3-2-a5-dos-protection",
        "bsi-net-3-2-a6-connection-state",
        "bsi-net-3-2-a12-redundancy-ha",
    }
    missing = expected - set(TEST_ID_FRAGMENT)
    assert not missing, f"Missing expected BSI keys: {missing}"


def test_known_cis_keys_present():
    expected = {
        "cis-5-2-1-firewall-default-deny-ingress",
        "cis-5-2-2-firewall-default-deny-egress",
        "cis-5-4-1-established-traffic",
        "cis-5-4-2-outbound-rules-coverage",
    }
    missing = expected - set(TEST_ID_FRAGMENT)
    assert not missing, f"Missing expected CIS keys: {missing}"


# ---------------------------------------------------------------------------
# Uniqueness
# ---------------------------------------------------------------------------


def test_all_test_ids_unique():
    ids = list(TEST_ID_FRAGMENT.keys())
    assert len(ids) == len(set(ids)), "Duplicate test_id keys in TEST_ID_FRAGMENT"


def test_standards_set():
    standards = {entry[0] for entry in TEST_ID_FRAGMENT.values()}
    assert standards == {"bsi-grundschutz", "cis-benchmarks"}, (
        f"Expected exactly the two standards, got: {standards}"
    )
