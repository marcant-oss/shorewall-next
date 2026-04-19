"""Phase 3 shorewalld netns-profile unit tests.

Exercises :mod:`shorewalld.discover` without touching
``/run/netns`` or real nftables sockets. A ``FakeNftInterface``
plus a temporary directory posing as ``/run/netns`` is enough to
cover:

* explicit netns list resolution
* ``auto`` mode walks the temp dir
* ``build()`` registers the always-on Link+Ct collectors
* ``reprobe()`` adds/removes the NftCollector as tables come+go
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from shorewalld.discover import (
    ProfileBuilder,
    list_named_netns,
    resolve_netns_list,
)
from shorewalld.exporter import (
    ConntrackStatsCollector,
    CtCollector,
    LinkCollector,
    NftCollector,
    NftScraper,
    QdiscCollector,
    ShorewalldRegistry,
)
from shorewall_nft.nft.netlink import NftError

# ── FakeNftInterface ─────────────────────────────────────────────────


class FakeNftInterface:
    """Minimal stand-in for NftInterface covering the calls that
    ProfileBuilder + NftScraper actually make.

    ``present`` is the set of netns names (``""`` for own NS) where
    the ``inet shorewall`` table is considered present. Toggling
    entries between reprobe calls lets a test simulate an operator
    loading or unloading a ruleset.
    """

    def __init__(self, present: set[str] | None = None) -> None:
        self.present = set(present or [])
        self.cmd_calls: list[tuple[str, str | None]] = []
        self.list_table_calls = 0

    def cmd(self, command: str, *, netns: str | None = None) -> dict[str, Any]:
        self.cmd_calls.append((command, netns))
        key = netns or ""
        if command.startswith("list table"):
            if key in self.present:
                return {"nftables": []}
            raise NftError(f"table not in netns={key!r}")
        return {}

    def list_table(self, family: str = "inet", table: str = "shorewall",
                   *, netns: str | None = None) -> dict[str, Any]:
        self.list_table_calls += 1
        key = netns or ""
        if key in self.present:
            return {"nftables": []}
        raise NftError(f"table not in netns={key!r}")

    def list_rule_counters(self, family: str = "inet", table: str = "shorewall",
                           *, netns: str | None = None) -> list[dict[str, Any]]:
        return []

    def list_counters(self, family: str = "inet", table: str = "shorewall",
                      *, netns: str | None = None) -> dict[str, dict[str, int]]:
        return {}


# ── list_named_netns / resolve_netns_list ────────────────────────────


def test_list_named_netns_empty_when_dir_missing(tmp_path: Path):
    assert list_named_netns(tmp_path / "nonexistent") == []


def test_list_named_netns_sorted(tmp_path: Path):
    (tmp_path / "rns2").touch()
    (tmp_path / "fw").touch()
    (tmp_path / "rns1").touch()
    assert list_named_netns(tmp_path) == ["fw", "rns1", "rns2"]


def test_resolve_netns_list_explicit_list():
    assert resolve_netns_list(["fw", "rns1"]) == ["fw", "rns1"]


def test_resolve_netns_list_empty_means_own_ns_only():
    assert resolve_netns_list([""]) == [""]


def test_resolve_netns_list_auto_prepends_own_ns(tmp_path: Path):
    (tmp_path / "fw").touch()
    (tmp_path / "rns1").touch()
    result = resolve_netns_list("auto", netns_dir=tmp_path)
    assert result == ["", "fw", "rns1"]


def test_resolve_netns_list_auto_empty_dir(tmp_path: Path):
    assert resolve_netns_list("auto", netns_dir=tmp_path) == [""]


# ── ProfileBuilder ───────────────────────────────────────────────────


def _make_builder(fake: FakeNftInterface) -> tuple[ProfileBuilder,
                                                   ShorewalldRegistry]:
    registry = ShorewalldRegistry()
    scraper = NftScraper(fake, ttl_s=60.0)  # type: ignore[arg-type]
    builder = ProfileBuilder(fake, registry, scraper)  # type: ignore[arg-type]
    return builder, registry


def test_builder_always_registers_link_qdisc_ctstats_and_ct():
    fake = FakeNftInterface(present=set())
    builder, registry = _make_builder(fake)

    builder.build(["fw", "rns1"])
    assert len(registry) == 8  # 2 × (Link + Qdisc + CtStats + Ct)

    # fw profile should have exactly one of each.
    fw = builder.profiles["fw"]
    assert isinstance(fw.link_collector, LinkCollector)
    assert isinstance(fw.qdisc_collector, QdiscCollector)
    assert isinstance(fw.ct_stats_collector, ConntrackStatsCollector)
    assert isinstance(fw.ct_collector, CtCollector)
    assert fw.nft_collector is None


def test_builder_is_idempotent_on_double_build():
    fake = FakeNftInterface(present=set())
    builder, registry = _make_builder(fake)

    builder.build(["fw"])
    builder.build(["fw"])
    # Still just Link + Qdisc + CtStats + Ct — not double.
    assert len(registry) == 4


def test_reprobe_adds_nft_collector_when_table_appears():
    fake = FakeNftInterface(present=set())
    builder, registry = _make_builder(fake)
    builder.build(["fw"])
    builder.reprobe()

    fw = builder.profiles["fw"]
    assert fw.nft_collector is None
    assert fw.has_table is False

    # Operator loads the ruleset.
    fake.present.add("fw")
    builder.reprobe()

    assert fw.nft_collector is not None
    assert fw.has_table is True
    assert isinstance(fw.nft_collector, NftCollector)
    assert len(registry) == 5  # Link + Qdisc + CtStats + Ct + Nft


def test_reprobe_removes_nft_collector_when_table_vanishes():
    fake = FakeNftInterface(present={"fw"})
    builder, registry = _make_builder(fake)
    builder.build(["fw"])
    builder.reprobe()

    fw = builder.profiles["fw"]
    assert fw.nft_collector is not None

    # Operator unloads.
    fake.present.discard("fw")
    builder.reprobe()

    assert fw.nft_collector is None
    assert fw.has_table is False
    assert len(registry) == 4  # Back to Link + Qdisc + CtStats + Ct


def test_reprobe_ignores_netns_without_table():
    fake = FakeNftInterface(present={"fw"})
    builder, _ = _make_builder(fake)
    builder.build(["fw", "rns1", "rns2"])
    builder.reprobe()

    assert builder.profiles["fw"].has_table is True
    assert builder.profiles["rns1"].has_table is False
    assert builder.profiles["rns2"].has_table is False
    assert builder.profiles["fw"].nft_collector is not None
    assert builder.profiles["rns1"].nft_collector is None


def test_close_all_removes_everything_from_registry():
    fake = FakeNftInterface(present={"fw"})
    builder, registry = _make_builder(fake)
    builder.build(["fw", "rns1"])
    builder.reprobe()
    assert len(registry) > 0

    builder.close_all()
    assert len(registry) == 0
    assert builder.profiles == {}
