"""Tests for DNS-set persistence (shorewalld.state)."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from shorewalld.dns_set_tracker import (
    FAMILY_V4,
    FAMILY_V6,
    DnsSetTracker,
    Proposal,
    Verdict,
)
from shorewalld.state import (
    STATE_FILE_VERSION,
    StateConfig,
    StateFileError,
    StateStore,
    deserialise_state,
    serialise_state,
)
from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsSetSpec


@pytest.fixture
def tracker_with_entries():
    reg = DnsSetRegistry()
    reg.add_spec(DnsSetSpec(
        qname="github.com", ttl_floor=300, ttl_ceil=3600, size=256))
    reg.add_spec(DnsSetSpec(
        qname="api.stripe.com", ttl_floor=60, ttl_ceil=3600, size=64))
    t = DnsSetTracker()
    t.load_registry(reg)
    gh_v4 = t.set_id_for("github.com", FAMILY_V4)
    gh_v6 = t.set_id_for("github.com", FAMILY_V6)
    api_v4 = t.set_id_for("api.stripe.com", FAMILY_V4)
    t.commit([
        Proposal(set_id=gh_v4, ip_bytes=b"\x01\x02\x03\x04", ttl=600),
        Proposal(set_id=gh_v4, ip_bytes=b"\x05\x06\x07\x08", ttl=600),
        Proposal(set_id=gh_v6, ip_bytes=bytes([0xAA] * 16), ttl=600),
        Proposal(set_id=api_v4, ip_bytes=b"\x09\x09\x09\x09", ttl=60),
    ], [Verdict.ADD] * 4)
    return t


@pytest.fixture
def empty_registry():
    reg = DnsSetRegistry()
    reg.add_spec(DnsSetSpec(
        qname="github.com", ttl_floor=300, ttl_ceil=3600, size=256))
    reg.add_spec(DnsSetSpec(
        qname="api.stripe.com", ttl_floor=60, ttl_ceil=3600, size=64))
    return reg


class TestSerialisation:
    def test_round_trip_preserves_entries(
        self, tracker_with_entries, empty_registry
    ):
        text = serialise_state(tracker_with_entries)
        doc = json.loads(text)
        assert doc["version"] == STATE_FILE_VERSION
        assert "saved_at" in doc
        assert len(doc["entries"]) == 4

        # Load into a fresh tracker with the same allowlist.
        t2 = DnsSetTracker()
        t2.load_registry(empty_registry)
        entries, expired = deserialise_state(text)
        assert expired == 0
        installed = t2.import_state(entries)
        assert installed == 4

        # Verify github.com has 2 v4 + 1 v6 entries
        snap = t2.snapshot()
        gh_v4 = t2.set_id_for("github.com", FAMILY_V4)
        gh_v6 = t2.set_id_for("github.com", FAMILY_V6)
        api_v4 = t2.set_id_for("api.stripe.com", FAMILY_V4)
        assert snap.per_set[(gh_v4, FAMILY_V4)].elements == 2
        assert snap.per_set[(gh_v6, FAMILY_V6)].elements == 1
        assert snap.per_set[(api_v4, FAMILY_V4)].elements == 1

    def test_expired_entries_filtered(self, empty_registry):
        # Build a state file where one entry is already in the past.
        doc = {
            "version": STATE_FILE_VERSION,
            "saved_at": time.time() - 7200,
            "hostname": "test",
            "entries": [
                {
                    "qname": "github.com",
                    "family": 4,
                    "ip": "AQIDBA==",  # b"\x01\x02\x03\x04"
                    "deadline": time.time() - 3600,  # expired
                },
                {
                    "qname": "github.com",
                    "family": 4,
                    "ip": "BQYHCA==",  # b"\x05\x06\x07\x08"
                    "deadline": time.time() + 3600,  # live
                },
            ],
        }
        text = json.dumps(doc)
        entries, expired = deserialise_state(text)
        assert expired == 1
        assert len(entries) == 1

    def test_version_mismatch_raises(self):
        doc = {"version": 99, "entries": []}
        with pytest.raises(StateFileError):
            deserialise_state(json.dumps(doc))

    def test_bad_json_raises(self):
        with pytest.raises(StateFileError):
            deserialise_state("{not valid")

    def test_malformed_entry_skipped(self, empty_registry):
        doc = {
            "version": STATE_FILE_VERSION,
            "saved_at": time.time(),
            "entries": [
                # Missing 'ip' field
                {"qname": "github.com", "family": 4,
                 "deadline": time.time() + 3600},
                # Wrong family
                {"qname": "github.com", "family": 99,
                 "ip": "AQIDBA==", "deadline": time.time() + 3600},
                # Wrong ip length for v4
                {"qname": "github.com", "family": 4,
                 "ip": "AAAAAAAAAAAA", "deadline": time.time() + 3600},
                # Valid entry
                {"qname": "github.com", "family": 4,
                 "ip": "AQIDBA==", "deadline": time.time() + 3600},
            ],
        }
        entries, _expired = deserialise_state(json.dumps(doc))
        assert len(entries) == 1


class TestStateStoreSync:
    def test_save_and_load_round_trip(
        self, tracker_with_entries, empty_registry, tmp_path
    ):
        cfg = StateConfig(state_dir=tmp_path)
        store = StateStore(tracker_with_entries, cfg)
        store.save_sync()
        assert cfg.dns_sets_path.exists()
        assert store.metrics.saves_total == 1

        # Fresh tracker, load the file.
        t2 = DnsSetTracker()
        t2.load_registry(empty_registry)
        store2 = StateStore(t2, cfg)
        installed = store2.load()
        assert installed == 4
        assert store2.metrics.load_entries_total == 4

    def test_load_missing_file_is_noop(self, empty_registry, tmp_path):
        cfg = StateConfig(state_dir=tmp_path)
        t = DnsSetTracker()
        t.load_registry(empty_registry)
        store = StateStore(t, cfg)
        assert store.load() == 0
        assert store.metrics.load_entries_total == 0

    def test_flush_on_start_deletes_file(
        self, tracker_with_entries, tmp_path
    ):
        cfg = StateConfig(state_dir=tmp_path)
        store = StateStore(tracker_with_entries, cfg)
        store.save_sync()
        assert cfg.dns_sets_path.exists()

        # Second store with flush_on_start=True
        cfg2 = StateConfig(state_dir=tmp_path, flush_on_start=True)
        store2 = StateStore(DnsSetTracker(), cfg2)
        store2.load()
        assert not cfg.dns_sets_path.exists()

    def test_load_on_start_disabled(self, tmp_path, empty_registry):
        cfg = StateConfig(state_dir=tmp_path, load_on_start=False)
        t = DnsSetTracker()
        t.load_registry(empty_registry)
        store = StateStore(t, cfg)
        # Even if a file exists, --no-state-load skips it.
        cfg.dns_sets_path.parent.mkdir(parents=True, exist_ok=True)
        cfg.dns_sets_path.write_text(json.dumps({
            "version": STATE_FILE_VERSION,
            "entries": [{
                "qname": "github.com", "family": 4,
                "ip": "AQIDBA==", "deadline": time.time() + 3600,
            }],
        }))
        assert store.load() == 0

    def test_disabled_config_skips_save(
        self, tracker_with_entries, tmp_path
    ):
        cfg = StateConfig(state_dir=tmp_path, enabled=False)
        store = StateStore(tracker_with_entries, cfg)
        store.save_sync()
        assert not cfg.dns_sets_path.exists()
        assert store.metrics.saves_total == 0

    def test_atomic_write_replaces_existing(
        self, tracker_with_entries, tmp_path
    ):
        cfg = StateConfig(state_dir=tmp_path)
        # Pre-create the file with garbage
        cfg.dns_sets_path.parent.mkdir(parents=True, exist_ok=True)
        cfg.dns_sets_path.write_text("STALE CONTENT")
        store = StateStore(tracker_with_entries, cfg)
        store.save_sync()
        text = cfg.dns_sets_path.read_text()
        assert "STALE" not in text
        assert "github.com" in text


class TestStateStoreAsync:
    def test_start_and_stop_runs_final_save(
        self, tracker_with_entries, tmp_path
    ):
        cfg = StateConfig(
            state_dir=tmp_path, persist_interval=0.05)
        store = StateStore(tracker_with_entries, cfg)
        loop = asyncio.new_event_loop()
        try:
            async def run():
                await store.start(loop)
                await asyncio.sleep(0.15)
                await store.stop()

            loop.run_until_complete(run())
            assert store.metrics.saves_total >= 1
            assert cfg.dns_sets_path.exists()
        finally:
            loop.close()

    def test_periodic_save_ticks(
        self, tracker_with_entries, tmp_path
    ):
        cfg = StateConfig(
            state_dir=tmp_path, persist_interval=0.02)
        store = StateStore(tracker_with_entries, cfg)
        loop = asyncio.new_event_loop()
        try:
            async def run():
                await store.start(loop)
                await asyncio.sleep(0.1)
                await store.stop()

            loop.run_until_complete(run())
            # stop() also triggers one sync save. Periodic loop
            # should have fired at least twice in 100ms at 20ms interval.
            assert store.metrics.saves_total >= 3
        finally:
            loop.close()
