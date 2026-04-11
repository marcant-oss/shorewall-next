"""Unit tests for shorewall_nft.compiler.proxyarp.

The pyroute2-backed apply/remove paths need a real netlink socket
to exercise meaningfully — those are deliberately not unit-tested
here. We cover:

  * the parser shape (file rows → ProxyArpEntry)
  * the v4/v6 split based on the ADDRESS column
  * the legacy shell-snippet emitter (still used by
    ``generate-proxyarp`` for sites that prefer a script)
  * HAVEROUTE / PERSISTENT bool parsing
"""
from __future__ import annotations

from shorewall_nft.compiler.proxyarp import (
    ProxyArpEntry,
    emit_proxyarp_script,
    parse_proxyarp,
)
from shorewall_nft.config.parser import ConfigLine


def _row(cols):
    return ConfigLine(columns=cols, file="proxyarp", lineno=0)


def test_parse_minimal_row():
    rows = [_row(["10.0.0.1", "eth1", "eth0"])]
    out = parse_proxyarp(rows)
    assert len(out) == 1
    e = out[0]
    assert e.address == "10.0.0.1"
    assert e.iface == "eth1"
    assert e.ext_iface == "eth0"
    assert e.haveroute is False
    assert e.persistent is False


def test_parse_haveroute_yes():
    rows = [_row(["10.0.0.1", "eth1", "eth0", "yes"])]
    e = parse_proxyarp(rows)[0]
    assert e.haveroute is True


def test_parse_persistent_yes():
    rows = [_row(["10.0.0.1", "eth1", "eth0", "no", "yes"])]
    e = parse_proxyarp(rows)[0]
    assert e.haveroute is False
    assert e.persistent is True


def test_emit_script_v4():
    entries = [
        ProxyArpEntry(
            address="10.0.0.1", iface="eth1", ext_iface="eth0",
            haveroute=False, persistent=False),
        ProxyArpEntry(
            address="10.0.0.2", iface="eth1", ext_iface="eth0",
            haveroute=True, persistent=False),
    ]
    script = emit_proxyarp_script(entries, family=4)
    assert "sysctl -wq net.ipv4.conf.eth0.proxy_arp=1" in script
    assert "sysctl -wq net.ipv4.conf.eth1.proxy_arp=1" in script
    assert "ip -4 neigh replace proxy 10.0.0.1 dev eth0" in script
    assert "ip -4 neigh replace proxy 10.0.0.2 dev eth0" in script
    # only the haveroute=False entry gets a route line
    assert "ip -4 route replace 10.0.0.1/32 dev eth1" in script
    assert "ip -4 route replace 10.0.0.2/32" not in script


def test_emit_script_v6():
    entries = [
        ProxyArpEntry(
            address="2001:db8::1", iface="eth1", ext_iface="eth0",
            haveroute=False, persistent=False),
    ]
    script = emit_proxyarp_script(entries, family=6)
    assert "net.ipv6.conf.eth0.proxy_ndp=1" in script
    assert "ip -6 neigh replace proxy 2001:db8::1 dev eth0" in script
    assert "ip -6 route replace 2001:db8::1/128 dev eth1" in script


def test_emit_script_skips_wrong_family():
    entries = [
        ProxyArpEntry(
            address="2001:db8::1", iface="eth1", ext_iface="eth0",
            haveroute=False, persistent=False),
    ]
    # v4 emitter sees a v6 address → empty output
    assert emit_proxyarp_script(entries, family=4) == ""


def test_emit_script_empty_entries():
    assert emit_proxyarp_script([], family=4) == ""
    assert emit_proxyarp_script([], family=6) == ""
