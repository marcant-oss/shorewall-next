"""Unit tests for shorewalld nft_worker P-1/P-2 cleanups and dns_set_tracker P-3.

P-1: IPv4 inet_ntop produces correct dotted-decimal output.
P-2: _LIBC is a module-level singleton (same object on repeated import).
P-3: Proposal(slots=True, frozen=True) rejects undeclared attribute writes.
"""

from __future__ import annotations

import importlib
import socket


# ---------------------------------------------------------------------------
# P-1: inet_ntop for IPv4
# ---------------------------------------------------------------------------

def test_inet_ntop_ipv4_round_trip():
    """b"\\xc6\\x33\\x64\\x01" → "198.51.100.1" (RFC 5737 example address)."""
    raw = b"\xc6\x33\x64\x01"
    result = socket.inet_ntop(socket.AF_INET, raw)
    assert result == "198.51.100.1"


def test_inet_ntop_ipv4_matches_old_join():
    """inet_ntop output is identical to the old join-based implementation."""
    raw = b"\xc6\x33\x64\x01"
    old_way = ".".join(str(b) for b in raw)
    new_way = socket.inet_ntop(socket.AF_INET, raw)
    assert new_way == old_way


def test_inet_ntop_ipv4_loopback():
    raw = b"\x7f\x00\x00\x01"
    assert socket.inet_ntop(socket.AF_INET, raw) == "127.0.0.1"


# ---------------------------------------------------------------------------
# P-2: _LIBC is cached at module level
# ---------------------------------------------------------------------------

def test_nft_worker_libc_cached():
    """Importing shorewalld.nft_worker twice returns the same _LIBC object."""
    # Ensure the module is loaded.
    import shorewalld.nft_worker as mod1
    # Reload to get the same module object (importlib returns the cached module).
    mod2 = importlib.import_module("shorewalld.nft_worker")
    assert mod1 is mod2, "module should be the same cached object"
    # The _LIBC attribute must exist and be a single CDLL instance.
    assert hasattr(mod1, "_LIBC"), "_LIBC must be defined at module level"
    assert mod1._LIBC is mod2._LIBC, "_LIBC must be the same object on re-import"


def test_nft_worker_libc_is_cdll():
    """_LIBC is a ctypes.CDLL instance with use_errno semantics."""
    import ctypes
    import shorewalld.nft_worker as mod
    assert isinstance(mod._LIBC, ctypes.CDLL)


# ---------------------------------------------------------------------------
# P-3: Proposal slots — no undeclared attribute writes allowed
# ---------------------------------------------------------------------------

def test_proposal_slots_rejects_undeclared_attribute():
    """Proposal(...).foo = 1 must raise AttributeError or TypeError.

    With frozen=True + slots=True, CPython raises TypeError (the frozen
    __setattr__ intercepts before the slot machinery can raise AttributeError).
    Both signal that undeclared attribute writes are rejected — the key
    assertion is that assignment does NOT silently succeed.
    """
    import pytest
    from shorewalld.dns_set_tracker import Proposal

    p = Proposal(set_id=1, ip=0, ttl=300)
    with pytest.raises((AttributeError, TypeError)):
        p.foo = 1  # type: ignore[attr-defined]


def test_proposal_frozen_rejects_field_mutation():
    """Proposal is frozen — mutating a declared field must raise FrozenInstanceError."""
    import pytest
    from dataclasses import FrozenInstanceError
    from shorewalld.dns_set_tracker import Proposal

    p = Proposal(set_id=1, ip=0, ttl=300)
    with pytest.raises(FrozenInstanceError):
        p.set_id = 99  # type: ignore[misc]


def test_proposal_construction_still_works():
    """slots=True must not break normal Proposal construction."""
    from shorewalld.dns_set_tracker import Proposal

    p = Proposal(set_id=7, ip=int.from_bytes(b"\xc6\x33\x64\x01", "big"), ttl=600)
    assert p.set_id == 7
    assert p.ttl == 600


def test_set_metrics_slots_rejects_undeclared_attribute():
    """SetMetrics(slots=True) rejects writes to undeclared attributes."""
    import pytest
    from shorewalld.dns_set_tracker import SetMetrics

    m = SetMetrics()
    with pytest.raises(AttributeError):
        m.foo = 99  # type: ignore[attr-defined]


def test_set_metrics_declared_fields_mutable():
    """SetMetrics declared fields remain mutable (slots=True, not frozen)."""
    from shorewalld.dns_set_tracker import SetMetrics

    m = SetMetrics()
    m.adds_total += 5
    assert m.adds_total == 5
