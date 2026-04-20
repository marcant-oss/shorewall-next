"""Unit tests for PlainListProvider/PlainListConfig (shorewalld.iplist.plain).

Mocks fetcher, filesystem, and subprocess so tests run offline and without
root / inotify_simple installed.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


from shorewalld.iplist.plain import PlainListConfig, _parse_lines


# ---------------------------------------------------------------------------
# _parse_lines
# ---------------------------------------------------------------------------


class TestParseLines:
    def test_ipv4_host(self):
        v4, v6 = _parse_lines("198.51.100.1\n")
        assert "198.51.100.1/32" in v4

    def test_ipv4_cidr(self):
        v4, v6 = _parse_lines("198.51.100.0/24\n")
        assert "198.51.100.0/24" in v4
        assert not v6

    def test_ipv6_host(self):
        v4, v6 = _parse_lines("2001:db8::1\n")
        assert not v4
        assert "2001:db8::1/128" in v6

    def test_ipv6_cidr(self):
        v4, v6 = _parse_lines("2001:db8::/32\n")
        assert "2001:db8::/32" in v6

    def test_blank_lines_ignored(self):
        v4, v6 = _parse_lines("\n\n198.51.100.1\n\n")
        assert len(v4) == 1

    def test_comment_lines_ignored(self):
        v4, v6 = _parse_lines("# this is a comment\n198.51.100.1\n")
        assert len(v4) == 1

    def test_inline_comment_stripped(self):
        v4, v6 = _parse_lines("198.51.100.1  # some note\n")
        assert len(v4) == 1

    def test_unparseable_entry_skipped(self):
        v4, v6 = _parse_lines("not-an-ip\n198.51.100.1\n")
        assert len(v4) == 1

    def test_mixed_v4_v6(self):
        text = "198.51.100.0/24\n2001:db8::/32\n203.0.113.1\n"
        v4, v6 = _parse_lines(text)
        assert len(v4) == 2
        assert len(v6) == 1

    def test_empty_input(self):
        v4, v6 = _parse_lines("")
        assert not v4
        assert not v6

    def test_cidr_host_bit_normalised(self):
        """198.51.100.1/24 should be normalised to 198.51.100.0/24."""
        v4, v6 = _parse_lines("198.51.100.1/24\n")
        assert "198.51.100.0/24" in v4


# ---------------------------------------------------------------------------
# PlainListConfig
# ---------------------------------------------------------------------------


class TestPlainListConfig:
    def test_defaults(self):
        cfg = PlainListConfig(
            name="test",
            source="https://example.com/list.txt",
        )
        assert cfg.refresh == 3600
        assert cfg.inotify is False
        assert cfg.set_v4 == ""
        assert cfg.set_v6 == ""

    def test_custom_values(self):
        cfg = PlainListConfig(
            name="mylist",
            source="/var/lib/list.txt",
            refresh=600,
            inotify=True,
            set_v4="nfset_mylist_v4",
            set_v6="nfset_mylist_v6",
        )
        assert cfg.refresh == 600
        assert cfg.inotify is True
        assert cfg.set_v4 == "nfset_mylist_v4"
        assert cfg.set_v6 == "nfset_mylist_v6"


# ---------------------------------------------------------------------------
# HTTP source
# ---------------------------------------------------------------------------


class TestHttpSource:
    def test_url_fetch_and_parse(self):
        """URL source: mock _fetch_url and verify parsed result."""
        from shorewalld.iplist.plain import PlainListTracker

        text = "198.51.100.0/24\n# comment\n203.0.113.1\n"
        cfg = PlainListConfig(
            name="http_test",
            source="https://example.org/bl.txt",
            set_v4="nfset_http_test_v4",
            set_v6="nfset_http_test_v6",
        )

        # Build a tracker with a fake nft interface and no profiles.
        fake_nft = MagicMock()
        tracker = PlainListTracker([cfg], fake_nft, {})
        state = tracker._states["http_test"]

        with patch("shorewalld.iplist.plain._fetch_url", return_value=text):
            asyncio.run(tracker._do_refresh(state))

        assert "198.51.100.0/24" in state.current_v4
        assert "203.0.113.1/32" in state.current_v4
        assert state.consecutive_errors == 0

    def test_url_fetch_error_increments_counter(self):
        from shorewalld.iplist.plain import PlainListTracker

        cfg = PlainListConfig(
            name="http_err",
            source="https://example.org/bl.txt",
        )
        fake_nft = MagicMock()
        tracker = PlainListTracker([cfg], fake_nft, {})
        state = tracker._states["http_err"]

        with patch("shorewalld.iplist.plain._fetch_url", side_effect=OSError("timeout")):
            asyncio.run(tracker._do_refresh(state))

        assert state.consecutive_errors == 1


# ---------------------------------------------------------------------------
# File source
# ---------------------------------------------------------------------------


class TestFileSource:
    def test_file_read_and_parse(self, tmp_path):
        from shorewalld.iplist.plain import PlainListTracker

        list_file = tmp_path / "list.txt"
        list_file.write_text("198.51.100.0/24\n2001:db8::/32\n")

        cfg = PlainListConfig(
            name="file_test",
            source=str(list_file),
            set_v4="nfset_file_test_v4",
            set_v6="nfset_file_test_v6",
        )
        fake_nft = MagicMock()
        tracker = PlainListTracker([cfg], fake_nft, {})
        state = tracker._states["file_test"]

        asyncio.run(tracker._do_refresh(state))

        assert "198.51.100.0/24" in state.current_v4
        assert "2001:db8::/32" in state.current_v6
        assert state.consecutive_errors == 0

    def test_file_not_found_increments_counter(self):
        from shorewalld.iplist.plain import PlainListTracker

        cfg = PlainListConfig(
            name="file_missing",
            source="/nonexistent/path/list.txt",
        )
        fake_nft = MagicMock()
        tracker = PlainListTracker([cfg], fake_nft, {})
        state = tracker._states["file_missing"]

        asyncio.run(tracker._do_refresh(state))

        assert state.consecutive_errors == 1


# ---------------------------------------------------------------------------
# exec: source
# ---------------------------------------------------------------------------


class TestExecSource:
    def test_exec_stdout_parsed(self):
        from shorewalld.iplist.plain import PlainListTracker

        cfg = PlainListConfig(
            name="exec_test",
            source="exec:/usr/local/bin/my-blocklist",
            set_v4="nfset_exec_test_v4",
            set_v6="nfset_exec_test_v6",
        )
        fake_nft = MagicMock()
        tracker = PlainListTracker([cfg], fake_nft, {})
        state = tracker._states["exec_test"]

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        # communicate() returns (stdout, stderr)
        script_output = b"198.51.100.1\n203.0.113.0/24\n"
        mock_proc.communicate = AsyncMock(return_value=(script_output, b""))
        mock_proc.kill = MagicMock()

        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=mock_proc),
        ):
            asyncio.run(tracker._do_refresh(state))

        assert "198.51.100.1/32" in state.current_v4
        assert "203.0.113.0/24" in state.current_v4
        assert state.consecutive_errors == 0

    def test_exec_nonzero_exit_increments_counter(self):
        from shorewalld.iplist.plain import PlainListTracker

        cfg = PlainListConfig(
            name="exec_fail",
            source="exec:/usr/local/bin/bad-script",
        )
        fake_nft = MagicMock()
        tracker = PlainListTracker([cfg], fake_nft, {})
        state = tracker._states["exec_fail"]

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))
        mock_proc.kill = MagicMock()

        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=mock_proc),
        ):
            asyncio.run(tracker._do_refresh(state))

        assert state.consecutive_errors == 1

    def test_exec_no_shell_expansion(self):
        """create_subprocess_exec must receive just the path, not a shell string."""
        from shorewalld.iplist.plain import _exec_source

        captured: list = []

        async def mock_exec(*args, **kwargs):
            captured.extend(args)
            raise FileNotFoundError("not found")  # fail fast

        with patch("asyncio.create_subprocess_exec", new=mock_exec):
            try:
                asyncio.run(_exec_source("/usr/local/bin/script", 30))
            except RuntimeError:
                pass

        # First positional arg to create_subprocess_exec must be exactly the path.
        assert captured[0] == "/usr/local/bin/script"
        # Only one positional arg (no shell, no extra args injected).
        assert len(captured) == 1


# ---------------------------------------------------------------------------
# inotify fallback
# ---------------------------------------------------------------------------


class TestInotifyFallback:
    def test_missing_inotify_simple_logs_warning_and_returns(self, caplog):
        """When inotify_simple is not importable, _inotify_watch logs a warning
        and exits cleanly (no exception)."""
        from shorewalld.iplist.plain import PlainListConfig, PlainListTracker

        cfg = PlainListConfig(
            name="inotify_test",
            source="/etc/shorewall/list.txt",
            inotify=True,
        )
        fake_nft = MagicMock()
        tracker = PlainListTracker([cfg], fake_nft, {})
        state = tracker._states["inotify_test"]

        # Patch the import inside _inotify_watch to raise ImportError.
        original_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "inotify_simple":
                raise ImportError("No module named 'inotify_simple'")
            return real_import(name, *args, **kwargs)

        import logging
        with patch.object(builtins, "__import__", side_effect=fake_import):
            with caplog.at_level(logging.WARNING, logger="shorewalld.iplist.plain"):
                asyncio.run(tracker._inotify_watch(state))

        assert any("inotify_simple" in r.message for r in caplog.records)
