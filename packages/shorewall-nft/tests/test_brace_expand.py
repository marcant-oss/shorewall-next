"""Unit tests for shorewall_nft.util.brace_expand.expand_brace."""

from __future__ import annotations

import pytest

from shorewall_nft.util.brace_expand import expand_brace


class TestExpandBrace:
    def test_three_alternatives(self):
        result = expand_brace("{a,b,c}.host.org")
        assert result == ["a.host.org", "b.host.org", "c.host.org"]

    def test_no_braces_returns_single_element(self):
        """When there are no braces, the pattern is returned unchanged."""
        result = expand_brace("www.example.com")
        assert result == ["www.example.com"]
        assert len(result) == 1

    def test_empty_braces(self):
        """Empty braces ``{}`` produce a single entry with an empty substitution.

        Design decision: we do not raise on empty braces — we return a
        single-element list whose only entry has the empty string substituted
        in.  Callers that consider empty substitutions invalid should inspect
        the result.

        ``{}.example.org`` → ``[".example.org"]``
        """
        result = expand_brace("{}.example.org")
        assert result == [".example.org"]

    def test_multiple_brace_groups_only_first_expanded(self):
        """Multiple brace groups: only the first (left-most) group is expanded.

        Nested / multiple brace groups are out of scope per the plan.  The
        function expands the first group and leaves any remaining brace
        syntax in the suffix un-expanded.

        ``{a,b}.{x,y}.org`` → ``["a.{x,y}.org", "b.{x,y}.org"]``
        """
        result = expand_brace("{a,b}.{x,y}.org")
        # First group expanded; second group left as literal text.
        assert result == ["a.{x,y}.org", "b.{x,y}.org"]

    def test_two_alternatives(self):
        result = expand_brace("{ns1,ns2}.example.com")
        assert result == ["ns1.example.com", "ns2.example.com"]

    def test_prefix_only(self):
        result = expand_brace("{www,api}")
        assert result == ["www", "api"]

    def test_with_suffix_only(self):
        result = expand_brace("{}.suffix")
        assert result == [".suffix"]

    def test_empty_alternative_in_group(self):
        """An empty slot in ``{a,,b}`` produces an empty-substitution entry.

        ``{a,,b}.example.org`` → ``["a.example.org", ".example.org", "b.example.org"]``
        """
        result = expand_brace("{a,,b}.example.org")
        assert result == ["a.example.org", ".example.org", "b.example.org"]

    def test_single_alternative_in_braces(self):
        """A single alternative in braces is not an error — returns one element."""
        result = expand_brace("{only}.example.org")
        assert result == ["only.example.org"]

    @pytest.mark.parametrize("pattern,expected", [
        ("{a,b,c}.example.com", ["a.example.com", "b.example.com", "c.example.com"]),
        ("plain.example.com", ["plain.example.com"]),
        ("{x}.example.org", ["x.example.org"]),
    ])
    def test_parametrized(self, pattern, expected):
        assert expand_brace(pattern) == expected
