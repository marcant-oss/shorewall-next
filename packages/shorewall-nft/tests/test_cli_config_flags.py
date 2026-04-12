"""Tests for CLI config-dir override flags and _resolve_config_paths."""

from __future__ import annotations

import click
import pytest

from shorewall_nft.runtime.cli import (
    _derive_v4_sibling,
    _resolve_config_paths,
)


@pytest.fixture
def dirs(tmp_path):
    """Create v4, v6, merged and isolated dirs."""
    v4 = tmp_path / "shorewall"
    v6 = tmp_path / "shorewall6"
    merged = tmp_path / "shorewall46"
    orphan = tmp_path / "other-v6"
    for d in (v4, v6, merged, orphan):
        d.mkdir()
    return {"v4": v4, "v6": v6, "merged": merged, "orphan": orphan}


# ── _derive_v4_sibling ────────────────────────────────────────────────

class TestDeriveV4Sibling:
    def test_sibling_exists(self, dirs):
        assert _derive_v4_sibling(dirs["v6"]) == dirs["v4"]

    def test_no_sibling(self, dirs):
        assert _derive_v4_sibling(dirs["orphan"]) is None

    def test_not_ending_in_6(self, tmp_path):
        d = tmp_path / "foo"
        d.mkdir()
        assert _derive_v4_sibling(d) is None


# ── _resolve_config_paths ─────────────────────────────────────────────

class TestResolvePaths:
    def test_explicit_merged(self, dirs):
        primary, secondary, skip = _resolve_config_paths(
            None, dirs["merged"], None, None, False, False)
        assert primary == dirs["merged"]
        assert secondary is None
        assert skip is True

    def test_explicit_dual(self, dirs):
        primary, secondary, skip = _resolve_config_paths(
            None, None, dirs["v4"], dirs["v6"], False, False)
        assert primary == dirs["v4"]
        assert secondary == dirs["v6"]
        assert skip is True

    def test_v4_only_with_auto_sibling(self, dirs):
        """--config-dir4 alone lets the parser auto-detect v6 sibling."""
        primary, secondary, skip = _resolve_config_paths(
            None, None, dirs["v4"], None, False, False)
        assert primary == dirs["v4"]
        assert secondary is None
        assert skip is False  # parser will auto-detect

    def test_v4_with_no_auto_v6(self, dirs):
        """--config-dir4 + --no-auto-v6 = v4-only."""
        primary, secondary, skip = _resolve_config_paths(
            None, None, dirs["v4"], None, False, True)
        assert primary == dirs["v4"]
        assert secondary is None
        assert skip is True

    def test_v6_finds_v4_sibling(self, dirs):
        """--config6-dir alone finds v4 sibling manually."""
        primary, secondary, skip = _resolve_config_paths(
            None, None, None, dirs["v6"], False, False)
        assert primary == dirs["v4"]
        assert secondary == dirs["v6"]
        assert skip is True

    def test_v6_only(self, dirs):
        """--config6-dir + --no-auto-v4 = v6-only."""
        primary, secondary, skip = _resolve_config_paths(
            None, None, None, dirs["v6"], True, False)
        assert primary == dirs["v6"]
        assert secondary is None
        assert skip is True

    def test_v6_orphan_no_sibling(self, dirs):
        """--config6-dir on a dir with no v4 sibling → v6-only."""
        primary, secondary, skip = _resolve_config_paths(
            None, None, None, dirs["orphan"], False, False)
        assert primary == dirs["orphan"]
        assert secondary is None
        assert skip is True

    def test_positional(self, dirs):
        """Positional arg uses legacy behavior (parser auto-detects sibling)."""
        primary, secondary, skip = _resolve_config_paths(
            dirs["v4"], None, None, None, False, False)
        assert primary == dirs["v4"]
        assert secondary is None
        assert skip is False

    def test_positional_with_no_auto_v6(self, dirs):
        primary, secondary, skip = _resolve_config_paths(
            dirs["v4"], None, None, None, False, True)
        assert skip is True

    def test_conflict_config_dir_plus_dir4(self, dirs):
        with pytest.raises(click.UsageError):
            _resolve_config_paths(
                None, dirs["merged"], dirs["v4"], None, False, False)

    def test_conflict_config_dir_plus_dir6(self, dirs):
        with pytest.raises(click.UsageError):
            _resolve_config_paths(
                None, dirs["merged"], None, dirs["v6"], False, False)

    def test_conflict_positional_plus_flags(self, dirs):
        with pytest.raises(click.UsageError):
            _resolve_config_paths(
                dirs["v4"], None, dirs["v4"], None, False, False)
