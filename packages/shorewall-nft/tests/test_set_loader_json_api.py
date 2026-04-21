"""Tests for SetLoader JSON API path.

Covers:
- bulk_add_elements with prefer_json=True uses cmd_json (not cmd)
- prefer_json=True but _use_lib=False falls back to text cmd path
- Chunking: 100k elements / default JSON chunk 50k → exactly 2 cmd_json calls
- Chunking: 1200 elements / text fallback chunk 500 → exactly 3 cmd calls
- prefer_json=False always uses text path
- Bench sketch (skipped unless SHOREWALL_NFT_BENCH=1)
"""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock

import pytest

from shorewall_nft.nft.set_loader import SetLoader, _JSON_CHUNK_DEFAULT, _TEXT_CHUNK_DEFAULT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_loader(use_lib: bool = True) -> tuple[SetLoader, MagicMock]:
    """Return (loader, mock_nft) with nft.cmd and nft.cmd_json stubbed."""
    loader = SetLoader(table="shorewall", family="inet")
    mock_nft = MagicMock()
    mock_nft._use_lib = use_lib
    mock_nft.cmd.return_value = {}
    mock_nft.cmd_json.return_value = {}
    loader.nft = mock_nft
    return loader, mock_nft


def _elements(n: int) -> list[str]:
    """Generate n distinct IPv4 /32 strings (RFC 5737 space, looping)."""
    out = []
    for i in range(n):
        a = 192
        b = 0
        c = (i >> 8) & 0xFF
        d = i & 0xFF
        out.append(f"{a}.{b}.{c}.{d}")
    return out


# ---------------------------------------------------------------------------
# JSON API path
# ---------------------------------------------------------------------------

class TestBulkAddElementsJsonApi:
    def test_uses_cmd_json_not_cmd(self):
        """When libnftables is available, cmd_json must be called, not cmd."""
        loader, mock_nft = _make_loader(use_lib=True)
        elems = _elements(10)
        loader.bulk_add_elements("myset", elems, prefer_json=True)

        assert mock_nft.cmd_json.called, "cmd_json should be called"
        assert not mock_nft.cmd.called, "cmd (text mode) must not be called"

    def test_json_payload_shape(self):
        """Verify the JSON payload matches the nft JSON schema for add element."""
        loader, mock_nft = _make_loader(use_lib=True)
        elems = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
        loader.bulk_add_elements("testset", elems, prefer_json=True)

        assert mock_nft.cmd_json.call_count == 1
        payload = mock_nft.cmd_json.call_args[0][0]

        assert "nftables" in payload
        assert len(payload["nftables"]) == 1
        add_obj = payload["nftables"][0]
        assert "add" in add_obj
        elem_obj = add_obj["add"]["element"]
        assert elem_obj["family"] == "inet"
        assert elem_obj["table"] == "shorewall"
        assert elem_obj["name"] == "testset"
        assert elem_obj["elem"] == elems

    def test_single_chunk_for_small_list(self):
        """A list smaller than chunk_size must produce exactly one call."""
        loader, mock_nft = _make_loader(use_lib=True)
        elems = _elements(100)
        loader.bulk_add_elements("myset", elems, prefer_json=True)

        assert mock_nft.cmd_json.call_count == 1

    def test_chunking_100k_default_yields_two_calls(self):
        """100 000 elements with default chunk (50k) must produce exactly 2 calls."""
        assert _JSON_CHUNK_DEFAULT == 50_000
        loader, mock_nft = _make_loader(use_lib=True)
        elems = _elements(100_000)
        loader.bulk_add_elements("bigset", elems, prefer_json=True)

        assert mock_nft.cmd_json.call_count == 2
        # First chunk: 50k, second: 50k
        first_payload = mock_nft.cmd_json.call_args_list[0][0][0]
        second_payload = mock_nft.cmd_json.call_args_list[1][0][0]
        first_elem = first_payload["nftables"][0]["add"]["element"]["elem"]
        second_elem = second_payload["nftables"][0]["add"]["element"]["elem"]
        assert len(first_elem) == 50_000
        assert len(second_elem) == 50_000

    def test_custom_chunk_size_json(self):
        """Explicit chunk_size overrides the default for JSON path."""
        loader, mock_nft = _make_loader(use_lib=True)
        elems = _elements(1_000)
        loader.bulk_add_elements("myset", elems, prefer_json=True, chunk_size=400)

        # 1000 / 400 → 3 calls (400, 400, 200)
        assert mock_nft.cmd_json.call_count == 3

    def test_empty_list_no_calls(self):
        """An empty element list must not call cmd_json or cmd."""
        loader, mock_nft = _make_loader(use_lib=True)
        loader.bulk_add_elements("myset", [], prefer_json=True)

        assert not mock_nft.cmd_json.called
        assert not mock_nft.cmd.called

    def test_custom_family_table_in_payload(self):
        """family and table from SetLoader init must appear in JSON payload."""
        loader = SetLoader(table="mytable", family="ip")
        mock_nft = MagicMock()
        mock_nft._use_lib = True
        mock_nft.cmd_json.return_value = {}
        loader.nft = mock_nft

        loader.bulk_add_elements("myset", ["198.51.100.1"])
        payload = mock_nft.cmd_json.call_args[0][0]
        elem_obj = payload["nftables"][0]["add"]["element"]
        assert elem_obj["family"] == "ip"
        assert elem_obj["table"] == "mytable"


# ---------------------------------------------------------------------------
# Text fallback path
# ---------------------------------------------------------------------------

class TestBulkAddElementsTextFallback:
    def test_falls_back_to_cmd_when_no_lib(self):
        """When _use_lib=False and prefer_json=True, must use text cmd."""
        loader, mock_nft = _make_loader(use_lib=False)
        elems = _elements(10)
        loader.bulk_add_elements("myset", elems, prefer_json=True)

        assert mock_nft.cmd.called, "cmd (text) must be called when lib absent"
        assert not mock_nft.cmd_json.called

    def test_prefer_json_false_always_text(self):
        """prefer_json=False must use text even when libnftables is available."""
        loader, mock_nft = _make_loader(use_lib=True)
        elems = _elements(10)
        loader.bulk_add_elements("myset", elems, prefer_json=False)

        assert mock_nft.cmd.called
        assert not mock_nft.cmd_json.called

    def test_chunking_1200_text_default_yields_three_calls(self):
        """1200 elements with default text chunk (500) → 3 cmd calls."""
        assert _TEXT_CHUNK_DEFAULT == 500
        loader, mock_nft = _make_loader(use_lib=False)
        elems = _elements(1_200)
        loader.bulk_add_elements("myset", elems, prefer_json=True)

        assert mock_nft.cmd.call_count == 3

    def test_text_cmd_contains_element_strings(self):
        """Text mode cmd must include the element strings in the command."""
        loader, mock_nft = _make_loader(use_lib=False)
        elems = ["198.51.100.1", "198.51.100.2"]
        loader.bulk_add_elements("myset", elems, prefer_json=True)

        assert mock_nft.cmd.call_count == 1
        cmd_str = mock_nft.cmd.call_args[0][0]
        assert "198.51.100.1" in cmd_str
        assert "198.51.100.2" in cmd_str
        assert "myset" in cmd_str
        assert "add element" in cmd_str

    def test_custom_chunk_size_text(self):
        """Explicit chunk_size overrides default for text path."""
        loader, mock_nft = _make_loader(use_lib=False)
        elems = _elements(1_000)
        loader.bulk_add_elements("myset", elems, prefer_json=False, chunk_size=250)

        # 1000 / 250 → exactly 4 calls
        assert mock_nft.cmd.call_count == 4

    def test_positional_chunk_size_backward_compat(self):
        """chunk_size=500 passed as kwarg must work (backward compat)."""
        loader, mock_nft = _make_loader(use_lib=False)
        elems = _elements(1_000)
        # Old callers might pass chunk_size=500 explicitly
        loader.bulk_add_elements("myset", elems, chunk_size=500, prefer_json=False)
        assert mock_nft.cmd.call_count == 2  # 1000/500=2


# ---------------------------------------------------------------------------
# Regression: old _add_elements alias still works
# ---------------------------------------------------------------------------

class TestAddElementsAlias:
    def test_alias_delegates_to_bulk(self):
        """_add_elements (deprecated alias) must still call cmd_json or cmd."""
        loader, mock_nft = _make_loader(use_lib=True)
        loader._add_elements("myset", ["198.51.100.1"])
        # Should have called cmd_json (via bulk_add_elements JSON path)
        assert mock_nft.cmd_json.called or mock_nft.cmd.called

    def test_alias_text_path(self):
        """_add_elements falls back to text when lib absent."""
        loader, mock_nft = _make_loader(use_lib=False)
        loader._add_elements("myset", ["198.51.100.1"])
        assert mock_nft.cmd.called


# ---------------------------------------------------------------------------
# _ensure_set JSON path
# ---------------------------------------------------------------------------

class TestEnsureSetJsonApi:
    def test_ensure_set_uses_cmd_json(self):
        """When lib available, _ensure_set must issue a JSON add-set payload."""
        loader, mock_nft = _make_loader(use_lib=True)
        loader._ensure_set("myset", "ipv4_addr", ["interval"])

        assert mock_nft.cmd_json.called
        payload = mock_nft.cmd_json.call_args[0][0]
        assert "nftables" in payload
        set_obj = payload["nftables"][0]["add"]["set"]
        assert set_obj["name"] == "myset"
        assert set_obj["type"] == "ipv4_addr"
        assert set_obj["flags"] == ["interval"]

    def test_ensure_set_text_fallback(self):
        """When lib absent, _ensure_set must use text cmd."""
        loader, mock_nft = _make_loader(use_lib=False)
        loader._ensure_set("myset", "ipv4_addr", ["interval"])
        assert mock_nft.cmd.called
        assert not mock_nft.cmd_json.called


# ---------------------------------------------------------------------------
# Benchmark sketch (off by default)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    os.environ.get("SHOREWALL_NFT_BENCH") != "1",
    reason="Set SHOREWALL_NFT_BENCH=1 to run benchmarks",
)
class TestBenchmark:
    def test_1m_elements_json(self):
        """1 000 000 elements via JSON path should complete quickly."""
        loader, mock_nft = _make_loader(use_lib=True)
        elems = [f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"
                 for i in range(1_000_000)]
        start = time.monotonic()
        loader.bulk_add_elements("bigset", elems, prefer_json=True)
        elapsed = time.monotonic() - start
        # The mock is instant, so we're really testing overhead, not libnftables.
        assert elapsed < 5.0, f"Took {elapsed:.2f}s — check for O(n²) behaviour"
        assert mock_nft.cmd_json.call_count == 20  # 1M / 50k = 20 chunks
