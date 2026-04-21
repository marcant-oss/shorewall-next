"""Unit tests for DnsSetTracker N→1 qname-to-set-name grouping.

When DnsSetSpec.set_name is non-None, multiple qnames that share the same
(set_name, family) pair must map to a single set_id so their resolved IPs
all flow into the same nft set.

When set_name is None the tracker behaves identically to the old code —
every (qname, family) gets its own set_id.
"""

from __future__ import annotations


from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    FAMILY_V6,
    DnsSetTracker,
    Proposal,
    Verdict,
)
from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsSetSpec


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_tracker(*specs: DnsSetSpec) -> DnsSetTracker:
    reg = DnsSetRegistry()
    for s in specs:
        reg.add_spec(s)
    t = DnsSetTracker()
    t.load_registry(reg)
    return t


def _spec(qname: str, set_name: str | None = None) -> DnsSetSpec:
    return DnsSetSpec(
        qname=qname,
        ttl_floor=300,
        ttl_ceil=3600,
        size=256,
        set_name=set_name,
    )


# ---------------------------------------------------------------------------
# Tests — N→1 sharing
# ---------------------------------------------------------------------------


class TestN1Sharing:
    def test_two_qnames_same_set_name_share_one_set_id(self):
        """Two qnames with the same set_name override share one set_id."""
        t = _build_tracker(
            _spec("a.example.com", set_name="nfset_myset_v4"),
            _spec("b.example.com", set_name="nfset_myset_v4"),
        )
        sid_a = t.set_id_for("a.example.com", FAMILY_V4)
        sid_b = t.set_id_for("b.example.com", FAMILY_V4)
        assert sid_a is not None
        assert sid_b is not None
        assert sid_a == sid_b, "same set_name → same set_id"

    def test_both_qnames_populate_same_state(self):
        """Proposals from either qname commit into the same _SetState."""
        t = _build_tracker(
            _spec("a.example.com", set_name="nfset_shared_v4"),
            _spec("b.example.com", set_name="nfset_shared_v4"),
        )
        sid = t.set_id_for("a.example.com", FAMILY_V4)
        assert sid == t.set_id_for("b.example.com", FAMILY_V4)

        ip_a = int.from_bytes(bytes([198, 51, 100, 1]), "big")
        ip_b = int.from_bytes(bytes([198, 51, 100, 2]), "big")

        p_a = Proposal(set_id=sid, ip=ip_a, ttl=300)
        p_b = Proposal(set_id=sid, ip=ip_b, ttl=300)

        v_a = t.propose(p_a)
        v_b = t.propose(p_b)
        assert v_a == Verdict.ADD
        assert v_b == Verdict.ADD

        t.commit([p_a, p_b], [v_a, v_b])

        snap = t.snapshot()
        # Both IPs should appear in the same set.
        key = (sid, FAMILY_V4)
        assert snap.per_set[key].elements == 2

    def test_v4_and_v6_are_separate_groups(self):
        """Same set_name but different family → different set_ids."""
        t = _build_tracker(
            _spec("a.example.com", set_name="nfset_shared"),
            _spec("b.example.com", set_name="nfset_shared"),
        )
        # V4 and V6 share within their family but not across.
        sid_a_v4 = t.set_id_for("a.example.com", FAMILY_V4)
        sid_a_v6 = t.set_id_for("a.example.com", FAMILY_V6)
        sid_b_v4 = t.set_id_for("b.example.com", FAMILY_V4)
        sid_b_v6 = t.set_id_for("b.example.com", FAMILY_V6)

        assert sid_a_v4 == sid_b_v4, "same family, same set_name → shared"
        assert sid_a_v6 == sid_b_v6, "same family, same set_name → shared"
        assert sid_a_v4 != sid_a_v6, "different family → separate set_ids"


# ---------------------------------------------------------------------------
# Tests — backward compat (no set_name override)
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    def test_two_qnames_without_override_get_separate_set_ids(self):
        """Regression: qnames without set_name must each get their own set_id."""
        t = _build_tracker(
            _spec("github.com"),
            _spec("example.org"),
        )
        sid_gh_v4 = t.set_id_for("github.com", FAMILY_V4)
        sid_gh_v6 = t.set_id_for("github.com", FAMILY_V6)
        sid_ex_v4 = t.set_id_for("example.org", FAMILY_V4)
        sid_ex_v6 = t.set_id_for("example.org", FAMILY_V6)

        ids = {sid_gh_v4, sid_gh_v6, sid_ex_v4, sid_ex_v6}
        assert len(ids) == 4, "four distinct set_ids (old behaviour)"

    def test_propose_commit_roundtrip_unchanged(self):
        """Existing propose/commit semantics are unaffected."""
        t = _build_tracker(_spec("github.com"))
        sid = t.set_id_for("github.com", FAMILY_V4)
        ip = int.from_bytes(bytes([198, 51, 100, 10]), "big")
        p = Proposal(set_id=sid, ip=ip, ttl=300)
        v = t.propose(p)
        assert v == Verdict.ADD
        t.commit([p], [v])
        # Second proposal with > 50% TTL remaining → DEDUP.
        v2 = t.propose(Proposal(set_id=sid, ip=ip, ttl=300))
        assert v2 == Verdict.DEDUP


# ---------------------------------------------------------------------------
# Tests — mixed (one qname with override, one without)
# ---------------------------------------------------------------------------


class TestMixed:
    def test_mixed_two_separate_set_ids(self):
        """One qname with override, one without → two separate set_ids."""
        t = _build_tracker(
            _spec("a.example.com", set_name="nfset_target_v4"),
            _spec("b.example.com"),  # no override
        )
        sid_a_v4 = t.set_id_for("a.example.com", FAMILY_V4)
        sid_b_v4 = t.set_id_for("b.example.com", FAMILY_V4)
        assert sid_a_v4 is not None
        assert sid_b_v4 is not None
        assert sid_a_v4 != sid_b_v4, "different effective set names → different set_ids"

    def test_correct_set_names_logged_in_snapshot(self):
        """Snapshot must contain entries for both set_ids."""
        t = _build_tracker(
            _spec("a.example.com", set_name="nfset_target_v4"),
            _spec("b.example.com"),
        )
        snap = t.snapshot()
        # 4 entries: (sid_a, V4), (sid_a, V6), (sid_b, V4), (sid_b, V6)
        assert len(snap.per_set) == 4


# ---------------------------------------------------------------------------
# Tests — reload stability
# ---------------------------------------------------------------------------


class TestReloadStability:
    def test_reload_preserves_shared_set_id(self):
        """Reloading the same registry keeps the set_id stable."""
        spec_a = _spec("a.example.com", set_name="nfset_stable_v4")
        spec_b = _spec("b.example.com", set_name="nfset_stable_v4")

        reg = DnsSetRegistry()
        reg.add_spec(spec_a)
        reg.add_spec(spec_b)

        t = DnsSetTracker()
        t.load_registry(reg)
        sid_before = t.set_id_for("a.example.com", FAMILY_V4)

        # Reload the same registry.
        t.load_registry(reg)
        sid_after = t.set_id_for("a.example.com", FAMILY_V4)

        assert sid_before == sid_after, "set_id must be stable across reloads"

    def test_reload_adding_second_qname_to_existing_group(self):
        """Adding a second qname to an existing group wires it to the existing set_id."""
        spec_a = _spec("a.example.com", set_name="nfset_grow_v4")

        reg1 = DnsSetRegistry()
        reg1.add_spec(spec_a)

        t = DnsSetTracker()
        t.load_registry(reg1)
        sid_first = t.set_id_for("a.example.com", FAMILY_V4)
        assert sid_first is not None

        spec_b = _spec("b.example.com", set_name="nfset_grow_v4")
        reg2 = DnsSetRegistry()
        reg2.add_spec(spec_a)
        reg2.add_spec(spec_b)

        changed = t.load_registry(reg2)
        assert changed, "new qname added → should return True"

        sid_a = t.set_id_for("a.example.com", FAMILY_V4)
        sid_b = t.set_id_for("b.example.com", FAMILY_V4)
        assert sid_a == sid_b, "new qname joins the existing group"
        assert sid_a == sid_first, "original set_id is preserved"
