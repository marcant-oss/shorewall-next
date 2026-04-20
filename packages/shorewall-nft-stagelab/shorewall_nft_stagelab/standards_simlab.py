"""Simlab correctness TEST_ID fragment.

simlab.report.write_json emits two synthetic scenarios (fail_accept_is_zero,
fail_drop_within_tolerance) that land in the stagelab audit report alongside
regular scenarios. These entries give them a proper standards lookup so the
audit HTML/JSON shows control+standard columns instead of null.

Merged into standards.TEST_ID by the package-level aggregator.
"""
from __future__ import annotations

TEST_ID_FRAGMENT: dict[str, tuple[str, str, str]] = {
    "simlab-fail-accept": (
        "cc-iso-15408",
        "FDP_IFF.1",
        "simlab: zero false-accept probes (information flow control correctness)",
    ),
    "simlab-fail-drop": (
        "cc-iso-15408",
        "FDP_IFF.1",
        "simlab: false-drop probes within tolerance (information flow control correctness)",
    ),
}
