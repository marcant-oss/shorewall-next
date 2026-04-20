"""Unit tests for Bug A1 fix — worker_router lookup honours DnsSetSpec.set_name.

When a DnsSetSpec carries a non-None set_name (base name without _v4/_v6),
the lookup closure in _start_forked() and LocalWorker.dispatch() must
return the family-suffixed form of that base name instead of the
qname_to_set_name() derivation.

These tests exercise the lookup logic extracted into a helper so we don't
need to fork real processes.
"""

from __future__ import annotations

from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    FAMILY_V6,
    DnsSetTracker,
)
from shorewall_nft.nft.dns_sets import (
    DnsSetRegistry,
    DnsSetSpec,
    qname_to_set_name,
)
from shorewall_nft.nft.nfsets import nfset_to_set_name


# ---------------------------------------------------------------------------
# Helper: mirror the lookup closure logic from worker_router.py
# ---------------------------------------------------------------------------


def _make_lookup(tracker: DnsSetTracker):
    """Reproduce the lookup closure from ParentWorker._start_forked() for testing."""

    def lookup(key: tuple[int, int]) -> str | None:
        entry = tracker.name_for(key[0])
        if entry is None:
            return None
        qname, family = entry
        fam_str = "v4" if family == 4 else "v6"
        # Honour set_name override (base name → append family suffix).
        state = tracker._states.get(
            tracker._by_name.get((qname, family), -1))
        if state is not None and state.spec.set_name is not None:
            sn = state.spec.set_name
            if not sn.endswith("_v4") and not sn.endswith("_v6"):
                return f"{sn}_{fam_str}"
            return sn
        return qname_to_set_name(qname, fam_str)

    return lookup


# ---------------------------------------------------------------------------
# Tests — default path (no set_name override)
# ---------------------------------------------------------------------------


class TestLookupDefaultPath:
    def test_default_returns_qname_derived_name(self):
        """Without set_name, lookup returns qname_to_set_name() result."""
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec(qname="cdn.example.com"))
        t = DnsSetTracker()
        t.load_registry(reg)

        sid = t.set_id_for("cdn.example.com", FAMILY_V4)
        assert sid is not None
        lookup = _make_lookup(t)
        result = lookup((sid, FAMILY_V4))
        assert result == qname_to_set_name("cdn.example.com", "v4")

    def test_default_v6_returns_qname_derived_name(self):
        """Without set_name, v6 lookup returns qname_to_set_name() with v6 suffix."""
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec(qname="cdn.example.com"))
        t = DnsSetTracker()
        t.load_registry(reg)

        sid = t.set_id_for("cdn.example.com", FAMILY_V6)
        lookup = _make_lookup(t)
        result = lookup((sid, FAMILY_V6))
        assert result == qname_to_set_name("cdn.example.com", "v6")

    def test_unknown_set_id_returns_none(self):
        """Unknown set_id → None (no crash)."""
        t = DnsSetTracker()
        t.load_registry(DnsSetRegistry())
        lookup = _make_lookup(t)
        result = lookup((9999, FAMILY_V4))
        assert result is None


# ---------------------------------------------------------------------------
# Tests — set_name override (Bug A1 fix)
# ---------------------------------------------------------------------------


class TestLookupSetNameOverride:
    def test_base_name_gets_v4_suffix(self):
        """Base set_name (no suffix) → append _v4 for v4 family."""
        # Compute the base name from an nfset entry name "mycdn"
        v4_full = nfset_to_set_name("mycdn", "v4")
        base_name = v4_full[:-3]  # strip "_v4"

        reg = DnsSetRegistry()
        reg.add_with_target("cdn.example.com", base_name)
        t = DnsSetTracker()
        t.load_registry(reg)

        sid = t.set_id_for("cdn.example.com", FAMILY_V4)
        assert sid is not None
        lookup = _make_lookup(t)
        result = lookup((sid, FAMILY_V4))
        assert result == f"{base_name}_v4", (
            f"expected {base_name}_v4, got {result!r}")
        # Must NOT be the qname-derived name
        assert result != qname_to_set_name("cdn.example.com", "v4")

    def test_base_name_gets_v6_suffix(self):
        """Base set_name (no suffix) → append _v6 for v6 family."""
        v4_full = nfset_to_set_name("mycdn", "v4")
        base_name = v4_full[:-3]

        reg = DnsSetRegistry()
        reg.add_with_target("cdn.example.com", base_name)
        t = DnsSetTracker()
        t.load_registry(reg)

        sid = t.set_id_for("cdn.example.com", FAMILY_V6)
        assert sid is not None
        lookup = _make_lookup(t)
        result = lookup((sid, FAMILY_V6))
        assert result == f"{base_name}_v6", (
            f"expected {base_name}_v6, got {result!r}")

    def test_family_suffix_correct_for_two_qnames_sharing_set(self):
        """Two qnames sharing the same base set_name both resolve correctly."""
        v4_full = nfset_to_set_name("shared", "v4")
        base_name = v4_full[:-3]

        reg = DnsSetRegistry()
        reg.add_with_target("a.example.com", base_name)
        reg.add_with_target("b.example.com", base_name)
        t = DnsSetTracker()
        t.load_registry(reg)

        lookup = _make_lookup(t)

        sid_a = t.set_id_for("a.example.com", FAMILY_V4)
        sid_b = t.set_id_for("b.example.com", FAMILY_V4)
        assert sid_a == sid_b, "same base name → same set_id"

        result_a = lookup((sid_a, FAMILY_V4))
        result_b = lookup((sid_b, FAMILY_V4))
        assert result_a == f"{base_name}_v4"
        assert result_b == f"{base_name}_v4"

    def test_verbatim_v4_suffix_set_name_returned_unchanged(self):
        """If set_name already ends with _v4, return it verbatim (legacy compat)."""
        v4_full = nfset_to_set_name("legacy", "v4")  # e.g. "nfset_legacy_v4"

        reg = DnsSetRegistry()
        # Pass the full name with suffix (legacy style)
        reg.add_with_target("x.example.com", v4_full)
        t = DnsSetTracker()
        t.load_registry(reg)

        sid = t.set_id_for("x.example.com", FAMILY_V4)
        lookup = _make_lookup(t)
        result = lookup((sid, FAMILY_V4))
        # set_name ends with _v4 → returned verbatim
        assert result == v4_full
