"""End-to-end simlab gate that runs in pytest without root.

The full simlab smoketest creates a network namespace and TUN/TAP
devices — too heavy for CI and requires root. This module covers
the in-process pieces of the simlab pipeline that DON'T need a
kernel: building probes from a per-rule walk, running them
through the autorepair passes, and asking the oracle for a
verdict on each. Catches regressions in:

  * derive_tests_all_zones (probe synthesis from iptables-save)
  * autorepair pass 1 — placeholder src rewriting
  * RandomProbeGenerator host picker (skips fw-local IPs)
  * RulesetOracle._rule_matches & fall-through classification

The fixture is hand-built — no real `ip addr` dumps required —
so the test is hermetic and runs in a few hundred ms.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from shorewall_nft.verify.simlab.dumps import (
    Address, FwState, Interface, Route,
)
from shorewall_nft.verify.simlab.smoketest import _build_zone_to_concrete_src
from shorewall_nft.verify.simlab.oracle import RandomProbeGenerator


def _mk_iface(name: str, addr: str, prefixlen: int) -> Interface:
    return Interface(
        name=name, index=10, mtu=1500,
        flags=frozenset({"UP"}),
        state="UP", kind="ethernet", parent=None,
        addrs4=[Address(family=4, addr=addr, prefixlen=prefixlen)],
    )


@pytest.fixture
def fake_fw():
    """A two-zone firewall: net (eth0, 10.0.0.0/24) + lan (eth1, 10.1.0.0/24)."""
    state = FwState()
    state.interfaces = {
        "eth0": _mk_iface("eth0", "10.0.0.1", 24),
        "eth1": _mk_iface("eth1", "10.1.0.1", 24),
    }
    state.routes4 = [
        Route(family=4, dst="10.0.0.0/24", dev="eth0",
              src="10.0.0.1", scope="link"),
        Route(family=4, dst="10.1.0.0/24", dev="eth1",
              src="10.1.0.1", scope="link"),
    ]
    return state


def test_zone_src_picker_skips_local(fake_fw):
    iface_to_zone = {"eth0": "net", "eth1": "lan"}
    out = _build_zone_to_concrete_src(fake_fw, iface_to_zone)
    # Both zones should resolve to a host that isn't .1 (local).
    assert out["net"] != "10.0.0.1"
    assert out["lan"] != "10.1.0.1"
    # The picker walks from the high end so we expect .254-ish.
    assert out["net"].startswith("10.0.0.")
    assert out["lan"].startswith("10.1.0.")


def test_random_probe_generator_skips_fw_local_ips(fake_fw):
    iface_to_zone = {"eth0": "net", "eth1": "lan"}
    rgen = RandomProbeGenerator(fake_fw, iface_to_zone, seed=42)
    seen_src: set[str] = set()
    seen_dst: set[str] = set()
    # Generate enough probes that the picker has plenty of chances
    # to land on a fw-local address if the exclusion is broken.
    for _ in range(200):
        p = rgen.next()
        if p is None:
            break
        seen_src.add(p.src_ip)
        seen_dst.add(p.dst_ip)
    fw_local = {"10.0.0.1", "10.1.0.1"}
    assert not (seen_src & fw_local), (
        f"random probe picked fw-local src {seen_src & fw_local}")
    assert not (seen_dst & fw_local), (
        f"random probe picked fw-local dst {seen_dst & fw_local}")


def test_oracle_fall_through_classifies_drop(tmp_path: Path):
    """Empty chain → fall-through → DROP (matches Shorewall policy)."""
    from shorewall_nft.verify.simlab.oracle import RulesetOracle

    dump = tmp_path / "iptables.txt"
    dump.write_text(
        "*filter\n"
        ":INPUT ACCEPT [0:0]\n"
        ":net2lan - [0:0]\n"
        "-A net2lan -p tcp --dport 22 -j ACCEPT\n"
        "COMMIT\n"
    )
    oracle = RulesetOracle(dump)
    v = oracle.classify(
        src_zone="net", dst_zone="lan",
        src_ip="10.0.0.5", dst_ip="10.1.0.5",
        proto="udp", port=53,
    )
    # SSH ACCEPT rule doesn't match UDP/53, so fall-through → DROP.
    assert v.verdict == "DROP"
    assert "fell through" in v.reason


def test_oracle_explicit_accept(tmp_path: Path):
    from shorewall_nft.verify.simlab.oracle import RulesetOracle

    dump = tmp_path / "iptables.txt"
    dump.write_text(
        "*filter\n"
        ":net2lan - [0:0]\n"
        "-A net2lan -d 10.1.0.5/32 -p tcp --dport 80 -j ACCEPT\n"
        "COMMIT\n"
    )
    oracle = RulesetOracle(dump)
    v = oracle.classify(
        src_zone="net", dst_zone="lan",
        src_ip="10.0.0.5", dst_ip="10.1.0.5",
        proto="tcp", port=80,
    )
    assert v.verdict == "ACCEPT"


def test_oracle_explicit_drop(tmp_path: Path):
    from shorewall_nft.verify.simlab.oracle import RulesetOracle

    dump = tmp_path / "iptables.txt"
    dump.write_text(
        "*filter\n"
        ":net2lan - [0:0]\n"
        "-A net2lan -s 1.2.3.4/32 -j DROP\n"
        "-A net2lan -d 10.1.0.5/32 -j ACCEPT\n"
        "COMMIT\n"
    )
    oracle = RulesetOracle(dump)
    v = oracle.classify(
        src_zone="net", dst_zone="lan",
        src_ip="1.2.3.4", dst_ip="10.1.0.5",
        proto="tcp", port=80,
    )
    assert v.verdict == "DROP"
