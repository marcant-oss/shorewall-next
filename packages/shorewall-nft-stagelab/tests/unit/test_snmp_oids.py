"""Unit tests for snmp_oids — constants, bundles, and resolve_bundle."""
from __future__ import annotations

import re

import pytest

import shorewall_nft_stagelab.snmp_oids as oids

_OID_RE = re.compile(r"^[0-9]+(\.[0-9]+)+$")

# ---- constants ---------------------------------------------------------------

_TOP_LEVEL_CONSTANTS = [
    "IF_HC_IN_OCTETS",
    "IF_HC_OUT_OCTETS",
    "IF_IN_DISCARDS",
    "IF_OUT_DISCARDS",
    "IF_ALIAS",
    "LA_LOAD",
    "SYS_UPTIME",
    "VRRP_INSTANCE_STATE",
    "VRRP_INSTANCE_NAME",
    "PDNS_EXTEND_OUTPUT",
]


def test_all_constants_are_str() -> None:
    for name in _TOP_LEVEL_CONSTANTS:
        value = getattr(oids, name)
        assert isinstance(value, str), f"{name} must be str, got {type(value)}"


# ---- bundles -----------------------------------------------------------------


def test_all_bundles_non_empty() -> None:
    for name, bundle in oids.BUNDLES.items():
        assert bundle, f"Bundle {name!r} must not be empty"


def test_all_bundle_oids_match_regex() -> None:
    for bundle_name, bundle in oids.BUNDLES.items():
        for oid in bundle:
            assert _OID_RE.match(oid), (
                f"OID {oid!r} in bundle {bundle_name!r} does not match OID pattern"
            )


# ---- resolve_bundle ----------------------------------------------------------


def test_resolve_bundle_returns_correct_list() -> None:
    assert oids.resolve_bundle("node_traffic") is oids.BUNDLE_NODE_TRAFFIC
    assert oids.resolve_bundle("system") is oids.BUNDLE_SYSTEM
    assert oids.resolve_bundle("vrrp") is oids.BUNDLE_VRRP
    assert oids.resolve_bundle("pdns") is oids.BUNDLE_PDNS
    assert oids.resolve_bundle("vrrp_extended") is oids.BUNDLE_VRRP_EXTENDED


def test_vrrp_extended_bundle_present_and_well_formed() -> None:
    assert "vrrp_extended" in oids.BUNDLES
    bundle = oids.BUNDLE_VRRP_EXTENDED
    assert len(bundle) == 6, f"Expected 6 OIDs, got {len(bundle)}"
    for oid in bundle:
        assert _OID_RE.match(oid), f"OID {oid!r} does not match OID pattern"


def test_resolve_bundle_unknown_raises_keyerror_with_valid_names() -> None:
    with pytest.raises(KeyError) as exc_info:
        oids.resolve_bundle("does-not-exist")
    msg = str(exc_info.value)
    assert "node_traffic" in msg, f"Error message should list valid names, got: {msg}"
