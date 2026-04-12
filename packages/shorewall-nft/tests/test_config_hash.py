"""Tests for config directory hashing and drift detection."""

from __future__ import annotations

from shorewall_nft.config.hash import (
    compute_config_hash,
    extract_hash_from_ruleset,
    format_hash_marker,
)


class TestComputeHash:
    def test_empty_dir(self, tmp_path):
        h = compute_config_hash(tmp_path)
        assert isinstance(h, str)
        assert len(h) == 16

    def test_missing_dir(self, tmp_path):
        assert compute_config_hash(tmp_path / "nonexistent") == "missing"

    def test_deterministic(self, tmp_path):
        (tmp_path / "zones").write_text("fw\tfirewall\nnet\tipv4\n")
        (tmp_path / "rules").write_text("ACCEPT\tnet\t$FW\n")
        h1 = compute_config_hash(tmp_path)
        h2 = compute_config_hash(tmp_path)
        assert h1 == h2

    def test_content_change_changes_hash(self, tmp_path):
        (tmp_path / "rules").write_text("ACCEPT\tnet\t$FW\n")
        h1 = compute_config_hash(tmp_path)
        (tmp_path / "rules").write_text("ACCEPT\tnet\t$FW\nDROP\tnet\tall\n")
        h2 = compute_config_hash(tmp_path)
        assert h1 != h2

    def test_new_file_changes_hash(self, tmp_path):
        (tmp_path / "rules").write_text("")
        h1 = compute_config_hash(tmp_path)
        (tmp_path / "policy").write_text("all\tall\tACCEPT\n")
        h2 = compute_config_hash(tmp_path)
        assert h1 != h2

    def test_ignored_files_dont_change_hash(self, tmp_path):
        (tmp_path / "rules").write_text("")
        h1 = compute_config_hash(tmp_path)
        # .bak files should be ignored
        (tmp_path / "rules.bak").write_text("ACCEPT\tnet\tall\n")
        (tmp_path / "rules~").write_text("weird editor backup")
        h2 = compute_config_hash(tmp_path)
        assert h1 == h2

    def test_subdirectory_contents_counted(self, tmp_path):
        (tmp_path / "rules").write_text("")
        h1 = compute_config_hash(tmp_path)
        (tmp_path / "rules.d").mkdir()
        (tmp_path / "rules.d" / "extra.rules").write_text("ACCEPT net fw\n")
        h2 = compute_config_hash(tmp_path)
        assert h1 != h2


class TestHashMarker:
    def test_format(self):
        assert format_hash_marker("abc123") == "config-hash:abc123"

    def test_extract_from_ruleset(self):
        ruleset = """
table inet shorewall {
    comment "config-hash:abc1234567890def"
    chain input { }
}
"""
        assert extract_hash_from_ruleset(ruleset) == "abc1234567890def"

    def test_extract_with_debug_flag(self):
        ruleset = 'comment "config-hash:deadbeefcafebabe debug"'
        assert extract_hash_from_ruleset(ruleset) == "deadbeefcafebabe"

    def test_extract_missing(self):
        ruleset = "table inet other { chain input { } }"
        assert extract_hash_from_ruleset(ruleset) is None

    def test_extract_wrong_format(self):
        ruleset = 'comment "config-hash:not-a-valid-hash"'
        assert extract_hash_from_ruleset(ruleset) is None
