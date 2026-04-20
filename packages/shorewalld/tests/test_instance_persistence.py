"""Unit tests for InstanceCache nfsets_payload persistence (Wave 3 Step 10).

Verifies that nfsets_payload round-trips correctly through InstanceCache
update() → _save() → load() without data loss.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shorewalld.instance import InstanceConfig
from shorewalld.state import InstanceCache


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def cache(state_dir: Path) -> InstanceCache:
    return InstanceCache(state_dir)


def _make_config(
    name: str = "fw",
    netns: str = "fw",
    config_dir: str = "/etc/shorewall",
    nfsets_payload: dict | None = None,
) -> InstanceConfig:
    cfg = InstanceConfig(
        name=name,
        netns=netns,
        config_dir=Path(config_dir),
        allowlist_path=Path(config_dir) / "dnsnames.compiled",
        nfsets_payload=nfsets_payload,
    )
    return cfg


# ---------------------------------------------------------------------------
# Tests — nfsets_payload round-trip
# ---------------------------------------------------------------------------


class TestNfsetsPayloadPersistence:
    def test_nfsets_payload_stored_and_loaded(self, cache: InstanceCache):
        """Non-trivial nfsets_payload is persisted and loaded back intact."""
        payload = {
            "entries": [
                {
                    "name": "blocklist",
                    "hosts": ["aws"],
                    "backend": "ip-list",
                    "options": {"filter": ["region=us-east-1"]},
                    "refresh": 3600,
                    "dns_servers": [],
                    "inotify": False,
                    "dnstype": None,
                }
            ]
        }
        cfg = _make_config(nfsets_payload=payload)
        cache.update(cfg, nfsets_payload=payload)

        rows = cache.load()
        assert len(rows) == 1
        # Unpack — new 6-tuple format.
        name, netns, config_dir, allowlist_path, dns_payload, loaded_nfsets = rows[0]
        assert name == "fw"
        assert loaded_nfsets == payload
        assert loaded_nfsets["entries"][0]["name"] == "blocklist"
        assert loaded_nfsets["entries"][0]["options"]["filter"] == ["region=us-east-1"]

    def test_no_nfsets_payload_returns_none(self, cache: InstanceCache):
        """When nfsets_payload is None, the loaded tuple also has None."""
        cfg = _make_config(nfsets_payload=None)
        cache.update(cfg, nfsets_payload=None)

        rows = cache.load()
        assert len(rows) == 1
        *_, loaded_nfsets = rows[0]
        assert loaded_nfsets is None

    def test_dns_and_nfsets_both_stored(self, cache: InstanceCache):
        """Both dns_payload and nfsets_payload survive round-trip together."""
        dns_payload = {"dns": ["host.example.com"]}
        nfsets_payload = {"entries": [{"name": "bl", "hosts": ["bogon"], "backend": "ip-list",
                                        "options": {}, "refresh": None, "dns_servers": [],
                                        "inotify": False, "dnstype": None}]}
        cfg = _make_config()
        cache.update(cfg, dns_payload=dns_payload, nfsets_payload=nfsets_payload)

        rows = cache.load()
        assert len(rows) == 1
        name, netns, config_dir, allowlist_path, loaded_dns, loaded_nfsets = rows[0]
        assert loaded_dns == dns_payload
        assert loaded_nfsets == nfsets_payload

    def test_multiple_instances_independent_payloads(self, cache: InstanceCache):
        """Multiple instances can carry different nfsets_payloads independently."""
        payload_a = {"entries": [{"name": "a", "hosts": ["aws"], "backend": "ip-list",
                                   "options": {}, "refresh": None, "dns_servers": [],
                                   "inotify": False, "dnstype": None}]}
        payload_b = {"entries": [{"name": "b", "hosts": ["azure"], "backend": "ip-list",
                                   "options": {}, "refresh": None, "dns_servers": [],
                                   "inotify": False, "dnstype": None}]}

        cfg_a = _make_config(name="fw_a", netns="fw_a")
        cfg_b = _make_config(name="fw_b", netns="fw_b")
        cache.update(cfg_a, nfsets_payload=payload_a)
        cache.update(cfg_b, nfsets_payload=payload_b)

        rows = cache.load()
        assert len(rows) == 2
        by_name = {r[0]: r for r in rows}
        assert by_name["fw_a"][-1] == payload_a
        assert by_name["fw_b"][-1] == payload_b

    def test_remove_clears_entry(self, cache: InstanceCache):
        """Removing an instance removes it from the persisted file."""
        payload = {"entries": []}
        cfg = _make_config()
        cache.update(cfg, nfsets_payload=payload)

        rows_before = cache.load()
        assert len(rows_before) == 1

        cache.remove("fw")
        rows_after = cache.load()
        assert len(rows_after) == 0

    def test_complex_nfsets_payload_round_trips(self, cache: InstanceCache):
        """A rich payload with mixed backends round-trips without data loss."""
        from shorewall_nft.nft.nfsets import NfSetEntry, NfSetRegistry, nfset_registry_to_payload

        reg = NfSetRegistry()
        for entry in [
            NfSetEntry(name="tap", hosts=["a.example.com"], backend="dnstap"),
            NfSetEntry(name="rsv", hosts=["b.example.com"], backend="resolver",
                       dns_servers=["198.51.100.53"]),
            NfSetEntry(name="bl", hosts=["bogon"], backend="ip-list", refresh=1800),
            NfSetEntry(name="plain", hosts=["/etc/shorewall/plain.txt"],
                       backend="ip-list-plain", inotify=True),
        ]:
            reg.entries.append(entry)
            reg.set_names.add(entry.name)

        payload = nfset_registry_to_payload(reg)
        cfg = _make_config()
        cache.update(cfg, nfsets_payload=payload)

        rows = cache.load()
        *_, loaded = rows[0]
        assert loaded is not None
        names = {e["name"] for e in loaded["entries"]}
        assert names == {"tap", "rsv", "bl", "plain"}
