"""Tests for config directory resolution rules.

When /etc/shorewall46 exists (from merge-config), it becomes the
authoritative source, ignoring /etc/shorewall and /etc/shorewall6.
CLI arguments always override.
"""

from __future__ import annotations

from unittest.mock import patch

from shorewall_nft.config.parser import load_config
from shorewall_nft.runtime.cli import _get_config_dir


class TestConfigResolution:
    def test_explicit_directory_wins(self, tmp_path):
        """Passing a directory bypasses all other resolution."""
        d = tmp_path / "custom"
        d.mkdir()
        assert _get_config_dir(d) == d

    def test_merged_dir_preferred_over_default(self, tmp_path):
        """When /etc/shorewall46 exists, it is used instead of /etc/shorewall."""
        merged = tmp_path / "shorewall46"
        merged.mkdir()
        with patch("shorewall_nft.runtime.cli.MERGED_CONFIG_DIR", merged):
            result = _get_config_dir(None)
            assert result == merged

    def test_fallback_to_legacy_default(self, tmp_path):
        """Without merged dir, falls back to /etc/shorewall."""
        # Point MERGED_CONFIG_DIR to a non-existent path
        missing = tmp_path / "nonexistent"
        with patch("shorewall_nft.runtime.cli.MERGED_CONFIG_DIR", missing):
            result = _get_config_dir(None)
            # Legacy default is returned (may or may not exist)
            from shorewall_nft.runtime.cli import DEFAULT_CONFIG_DIR
            assert result == DEFAULT_CONFIG_DIR

    def test_explicit_overrides_merged(self, tmp_path):
        """Even when merged dir exists, explicit arg wins."""
        merged = tmp_path / "shorewall46"
        merged.mkdir()
        custom = tmp_path / "custom"
        custom.mkdir()
        with patch("shorewall_nft.runtime.cli.MERGED_CONFIG_DIR", merged):
            assert _get_config_dir(custom) == custom


class TestParserMergedDir:
    """Loading a shorewall46 directory must NOT auto-merge a sibling."""

    def test_load_shorewall46_skips_automerge(self, tmp_path):
        """When loading /some/path/shorewall46, the parser should NOT look for
        /some/path/shorewall466 or /some/path/shorewall46/shorewall6."""
        merged = tmp_path / "shorewall46"
        merged.mkdir()
        # Minimal valid config
        (merged / "zones").write_text("fw\tfirewall\nnet\tipv4\n")
        (merged / "interfaces").write_text("net\teth0\t-\t-\n")
        (merged / "policy").write_text("all\tall\tACCEPT\n")
        (merged / "rules").write_text("")
        (merged / "shorewall.conf").write_text("STARTUP_ENABLED=Yes\n")
        (merged / "params").write_text("")

        # Create a sibling that SHOULD be ignored
        sibling = tmp_path / "shorewall466"
        sibling.mkdir()
        (sibling / "zones").write_text("fw\tfirewall\nextra\tipv6\n")
        (sibling / "policy").write_text("")
        (sibling / "rules").write_text("")
        (sibling / "shorewall.conf").write_text("")
        (sibling / "interfaces").write_text("")
        (sibling / "params").write_text("")

        cfg = load_config(merged)
        # Only "fw" and "net" from the merged dir, no "extra" from sibling
        zone_names = {z.columns[0] for z in cfg.zones if z.columns}
        assert "extra" not in zone_names
        assert {"fw", "net"}.issubset(zone_names)

    def test_load_legacy_shorewall_still_automerges(self, tmp_path):
        """When loading /some/path/shorewall, sibling /some/path/shorewall6
        IS auto-detected and merged (legacy behavior)."""
        v4 = tmp_path / "shorewall"
        v4.mkdir()
        (v4 / "zones").write_text("fw\tfirewall\nnet\tipv4\n")
        (v4 / "interfaces").write_text("net\teth0\t-\t-\n")
        (v4 / "policy").write_text("all\tall\tACCEPT\n")
        (v4 / "rules").write_text("")
        (v4 / "shorewall.conf").write_text("STARTUP_ENABLED=Yes\n")
        (v4 / "params").write_text("")

        v6 = tmp_path / "shorewall6"
        v6.mkdir()
        (v6 / "zones").write_text("fw\tfirewall\nextra6\tipv6\n")
        (v6 / "interfaces").write_text("")
        (v6 / "policy").write_text("")
        (v6 / "rules").write_text("")
        (v6 / "shorewall6.conf").write_text("")
        (v6 / "params").write_text("")

        cfg = load_config(v4)
        zone_names = {z.columns[0] for z in cfg.zones if z.columns}
        # extra6 should be merged in from the sibling
        assert "extra6" in zone_names
