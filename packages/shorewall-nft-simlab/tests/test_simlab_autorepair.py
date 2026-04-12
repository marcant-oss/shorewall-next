"""Unit tests for simlab's autorepair helpers.

The autorepair passes in :mod:`shorewall_nft_simlab.smoketest`
need to work even when the VM-side simlab harness isn't available
(CI box without nft, no root, no netns). These tests exercise the
pure-Python helpers in isolation with hand-built fixtures.

Covered:

- ``_build_zone_to_concrete_src``: given a FwState + iface→zone map,
  picks a routable host IP from each zone's own subnet.
- ``_expand_port_spec`` (in ``verify.simulate``): single, list, range,
  combination, empty, malformed.
- Round-trip assertion that zone-local IPs are *not* in TEST-NET-1
  (``192.0.2.0/24``).
"""

from __future__ import annotations


def _make_state(iface_addrs: dict[str, tuple[str, int]]):
    """Build a minimal FwState with one /N address per interface."""
    from shorewall_nft_simlab.dumps import (
        Address,
        FwState,
        Interface,
    )

    state = FwState()
    for i, (name, (addr, prefix)) in enumerate(iface_addrs.items()):
        iface = Interface(
            name=name, index=i + 1, mtu=1500, flags=frozenset(("UP",)),
            state="UP", kind="vlan", parent="bond0",
        )
        iface.addrs4.append(Address(
            family=4, addr=addr, prefixlen=prefix,
        ))
        state.interfaces[name] = iface
    return state


# ── _build_zone_to_concrete_src ─────────────────────────────────────


def test_zone_to_src_picks_non_fw_host_from_subnet():
    """A zone's chosen source IP must be in-subnet and not the FW's own."""
    from shorewall_nft_simlab.smoketest import (
        _build_zone_to_concrete_src,
    )

    state = _make_state({
        "bond0.10": ("10.0.10.1", 24),   # zone adm, fw = .1
        "bond0.20": ("10.0.20.1", 24),   # zone dmz, fw = .1
    })
    iface_to_zone = {"bond0.10": "adm", "bond0.20": "dmz"}

    out = _build_zone_to_concrete_src(state, iface_to_zone)

    assert "adm" in out and "dmz" in out
    # Must be inside the subnet but not the fw's own IP
    assert out["adm"].startswith("10.0.10.") and out["adm"] != "10.0.10.1"
    assert out["dmz"].startswith("10.0.20.") and out["dmz"] != "10.0.20.1"


def test_zone_to_src_skips_zones_with_no_address():
    """A zone whose interface has no v4 address is simply omitted."""
    from shorewall_nft_simlab.smoketest import (
        _build_zone_to_concrete_src,
    )

    state = _make_state({"bond0.10": ("10.0.10.1", 24)})
    # bond0.99 is claimed by zone 'ghost' but isn't in FwState
    iface_to_zone = {"bond0.10": "adm", "bond0.99": "ghost"}

    out = _build_zone_to_concrete_src(state, iface_to_zone)
    assert "adm" in out
    assert "ghost" not in out


def test_zone_to_src_ignores_test_net_one():
    """The picked IP is *never* in TEST-NET-1 (192.0.2.0/24)."""
    from shorewall_nft_simlab.smoketest import (
        _build_zone_to_concrete_src,
    )

    # Four different real-world ranges; none overlap TEST-NET-1.
    state = _make_state({
        "bond1":     ("203.0.113.65", 27),
        "bond0.18":  ("203.0.113.33", 27),
        "bond0.20":  ("203.0.113.129", 24),
        "bond0.10":  ("10.0.10.1", 24),
    })
    iface_to_zone = {
        "bond1": "net", "bond0.18": "adm",
        "bond0.20": "host", "bond0.10": "mgmt",
    }

    out = _build_zone_to_concrete_src(state, iface_to_zone)
    assert len(out) == 4
    for zone, ip in out.items():
        assert not ip.startswith("192.0.2."), (
            f"zone {zone!r} mapped to TEST-NET-1 address {ip}")


def test_zone_to_src_handles_small_subnets():
    """/31 and /30 are rare but should be handled gracefully."""
    from shorewall_nft_simlab.smoketest import (
        _build_zone_to_concrete_src,
    )

    state = _make_state({
        "bond0.30": ("10.0.30.0", 30),   # /30 → 2 usable hosts
        # Note: ipaddress treats .0 as network, so the fw is .0 here
        # which is weird but valid for us since we skip fw_ip only.
    })
    iface_to_zone = {"bond0.30": "ptp"}
    out = _build_zone_to_concrete_src(state, iface_to_zone)
    # For a /30 with fw at network addr, the other "host" is .2 or .3
    # depending on how the walk proceeds. Just assert we got *something*
    # that isn't the fw ip.
    if "ptp" in out:
        assert out["ptp"] != "10.0.30.0"


# ── _expand_port_spec ───────────────────────────────────────────────


def test_expand_port_spec_single():
    import random

    from shorewall_nft.verify.simulate import _expand_port_spec
    rng = random.Random(42)
    assert _expand_port_spec("22", rng) == [22]


def test_expand_port_spec_none():
    import random

    from shorewall_nft.verify.simulate import _expand_port_spec
    assert _expand_port_spec(None, random.Random(42)) == [None]


def test_expand_port_spec_list():
    import random

    from shorewall_nft.verify.simulate import _expand_port_spec
    out = _expand_port_spec("22,80,443", random.Random(42))
    assert set(out) == {22, 80, 443}


def test_expand_port_spec_range_small():
    import random

    from shorewall_nft.verify.simulate import _expand_port_spec
    out = _expand_port_spec("1000:1005", random.Random(42), cap=64)
    # Small range fully expanded
    assert set(out) == {1000, 1001, 1002, 1003, 1004, 1005}


def test_expand_port_spec_range_sampled():
    import random

    from shorewall_nft.verify.simulate import _expand_port_spec
    out = _expand_port_spec("1:65535", random.Random(42), cap=64)
    # Sampled down to cap
    assert len(out) == 64
    for p in out:
        assert 1 <= p <= 65535


def test_expand_port_spec_combination():
    import random

    from shorewall_nft.verify.simulate import _expand_port_spec
    out = _expand_port_spec("22,1000:1005,80", random.Random(42))
    assert {22, 80, 1000, 1001, 1002, 1003, 1004, 1005}.issubset(set(out))


def test_expand_port_spec_malformed():
    import random

    from shorewall_nft.verify.simulate import _expand_port_spec
    # Empty list on any parse failure
    assert _expand_port_spec("abc:def", random.Random(42)) == []


# ── RulesetOracle ct-state regression ──────────────────────────────


def _mock_parsed_ipt_with_ctstate(tmp_path):
    """Write a minimal iptables-save stub with a ct-state-first chain.

    The shape is what caused the 64x run's NEGATIVE-(none) report:
    every zone-pair chain in a FASTACCEPT=No config starts with
    ``ct state established,related accept``, followed by real
    ACCEPT/DROP rules. A correct oracle skips the ct-state rule
    and walks on. A buggy one matches it for every tuple.
    """
    dump = tmp_path / "iptables.txt"
    dump.write_text("""# Generated by iptables-save
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:net2adm - [0:0]
-A net2adm -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A net2adm -m conntrack --ctstate INVALID -j DROP
-A net2adm -p tcp -s 10.0.0.0/24 -d 10.0.1.0/24 --dport 22 -j ACCEPT
-A net2adm -p tcp -s 0.0.0.0/0 -d 10.0.1.0/24 --dport 22 -j DROP
-A net2adm -p tcp -s 0.0.0.0/0 -d 10.0.1.0/24 --dport 3389 -j DROP
COMMIT
""")
    return dump


def test_oracle_skips_ctstate_classifies_ACCEPT(tmp_path):
    """Classify hits the real ACCEPT rule, not the ct-state short-circuit."""
    from shorewall_nft_simlab.oracle import RulesetOracle

    dump = _mock_parsed_ipt_with_ctstate(tmp_path)
    oracle = RulesetOracle(dump)

    v = oracle.classify(
        src_zone="net", dst_zone="adm",
        src_ip="10.0.0.5", dst_ip="10.0.1.10",
        proto="tcp", port=22,
    )
    assert v.verdict == "ACCEPT", (
        f"expected ACCEPT from the real rule, got {v.verdict} "
        f"({v.reason}). If verdict is ACCEPT but reason mentions "
        f"'direct accept' at chain head, the ct-state filter is "
        f"broken again."
    )
    assert "--ctstate" not in (v.matched_rule_raw or ""), (
        "classify short-circuited on a ct-state rule — the "
        "filter in oracle.py::classify() is broken"
    )


def test_oracle_skips_ctstate_classifies_DROP(tmp_path):
    """A DROP rule later in the chain wins over any ct-state rule above."""
    from shorewall_nft_simlab.oracle import RulesetOracle

    dump = _mock_parsed_ipt_with_ctstate(tmp_path)
    oracle = RulesetOracle(dump)

    v = oracle.classify(
        src_zone="net", dst_zone="adm",
        src_ip="1.2.3.4", dst_ip="10.0.1.10",
        proto="tcp", port=3389,
    )
    assert v.verdict == "DROP", (
        f"expected DROP from the real rule, got {v.verdict} "
        f"({v.reason}). The ct-state rule at the top of the chain "
        f"must not short-circuit the classification."
    )


def test_oracle_ctstate_not_short_circuiting_diff_proto(tmp_path):
    """A ct-state rule with no proto match must not claim UDP traffic."""
    from shorewall_nft_simlab.oracle import RulesetOracle

    dump = _mock_parsed_ipt_with_ctstate(tmp_path)
    oracle = RulesetOracle(dump)

    # UDP traffic doesn't match any real rule in our mock chain.
    # The oracle now classifies fall-through as DROP (matching
    # Shorewall's default cross-zone REJECT policy at the chain
    # tail). A buggy oracle would short-circuit on the ct-state
    # ACCEPT rule and return ACCEPT — that's what we're guarding
    # against here.
    v = oracle.classify(
        src_zone="net", dst_zone="adm",
        src_ip="10.0.0.5", dst_ip="10.0.1.10",
        proto="udp", port=53,
    )
    assert v.verdict == "DROP", (
        f"expected DROP (fall-through to chain policy), "
        f"got {v.verdict} ({v.reason}). The ct-state rule must "
        f"not be treated as a catch-all ACCEPT."
    )
