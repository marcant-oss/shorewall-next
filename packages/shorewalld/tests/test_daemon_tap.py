"""Tests for the ``shorewalld tap`` operator CLI.

The live socket path is exercised in the manual smoke run against
a real recursor. Here we focus on the pieces that are pure
functions: frame decode, filter logic, three output formats,
summary rendering, allowlist loader.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest

from shorewalld.proto import dnstap_pb2
from shorewalld.tap import (
    Frame,
    TapStats,
    _load_allowlist,
    _passes_filter,
    decode_frame,
    format_frame,
    print_summary,
)
from shorewall_nft.nft.dns_sets import (
    DnsSetRegistry,
    DnsSetSpec,
    write_compiled_allowlist,
)


def _build_wire(qname: str, rcode: int = 0) -> bytes:
    """Build a minimal DNS response wire format buffer."""
    wire = bytearray(12)
    wire[0] = 0x12
    wire[1] = 0x34
    wire[2] = 0x81           # QR=1
    wire[3] = rcode & 0x0F
    wire[5] = 1              # qdcount=1
    for label in qname.rstrip(".").split("."):
        wire.append(len(label))
        wire.extend(label.encode("ascii"))
    wire.append(0)
    wire.extend((1).to_bytes(2, "big"))   # QTYPE=A
    wire.extend((1).to_bytes(2, "big"))   # QCLASS=IN
    return bytes(wire)


def _build_dnstap(
    msg_type: int = 6, qname: str = "github.com", rcode: int = 0
) -> bytes:
    """Produce a real dnstap protobuf frame."""
    msg = dnstap_pb2.Dnstap()
    msg.type = dnstap_pb2.Dnstap.MESSAGE
    msg.message.type = msg_type
    msg.message.response_message = _build_wire(qname, rcode)
    return msg.SerializeToString()


class TestDecodeFrame:
    def test_valid_client_response(self):
        buf = _build_dnstap(6, "github.com", 0)
        frame = decode_frame(buf)
        assert frame is not None
        assert frame.dnstap_type == 6
        assert frame.qname == "github.com"
        assert frame.rcode == 0

    def test_nxdomain(self):
        buf = _build_dnstap(6, "nonesuch.example.invalid", 3)
        frame = decode_frame(buf)
        assert frame is not None
        assert frame.rcode == 3

    def test_malformed_returns_none(self):
        assert decode_frame(b"\x00\x00\xff\xff") is None


class TestPassesFilter:
    def _make(self, qname="github.com", rcode=0, dtype=6):
        return Frame(
            ts_mono=0.0, dnstap_type=dtype, rcode=rcode,
            qname=qname, wire_len=30,
        )

    def test_queries_hidden_by_default(self):
        q = self._make(dtype=5)
        assert _passes_filter(
            q, qname_re=None, rcode_filter=None,
            show_queries=False) is False

    def test_queries_shown_when_flag_set(self):
        q = self._make(dtype=5)
        assert _passes_filter(
            q, qname_re=None, rcode_filter=None,
            show_queries=True) is True

    def test_qname_regex_hit(self):
        r = self._make(qname="api.stripe.com")
        assert _passes_filter(
            r, qname_re=re.compile(r"stripe"),
            rcode_filter=None, show_queries=False) is True

    def test_qname_regex_miss(self):
        r = self._make(qname="unrelated.example")
        assert _passes_filter(
            r, qname_re=re.compile(r"stripe"),
            rcode_filter=None, show_queries=False) is False

    def test_rcode_filter_hit(self):
        r = self._make(rcode=3)
        assert _passes_filter(
            r, qname_re=None, rcode_filter="NXDOMAIN",
            show_queries=False) is True

    def test_rcode_filter_miss(self):
        r = self._make(rcode=0)
        assert _passes_filter(
            r, qname_re=None, rcode_filter="NXDOMAIN",
            show_queries=False) is False

    def test_rcode_filter_case_insensitive(self):
        r = self._make(rcode=3)
        assert _passes_filter(
            r, qname_re=None, rcode_filter="nxdomain",
            show_queries=False) is True


class TestFormatFrame:
    def _frame(self, rcode=0, qname="github.com"):
        return Frame(
            ts_mono=0.123, dnstap_type=6, rcode=rcode,
            qname=qname, wire_len=47,
        )

    def test_pretty_contains_qname_and_type(self):
        out = format_frame(self._frame(), fmt="pretty", use_colour=False)
        assert "CLIENT_RESPONSE" in out
        assert "github.com" in out
        assert "NOERROR" in out
        assert "len=47" in out

    def test_pretty_truncates_long_qnames(self):
        long = "verylong." * 10 + "example.com"
        f = self._frame(qname=long)
        out = format_frame(f, fmt="pretty", use_colour=False)
        # Exactly one ellipsis representing the truncation
        assert "…" in out

    def test_pretty_allowlist_tag(self):
        f = self._frame()
        f.in_allowlist = True
        out = format_frame(f, fmt="pretty", use_colour=False)
        assert "allowlist" in out

    def test_structured_key_value(self):
        out = format_frame(self._frame(), fmt="structured", use_colour=False)
        assert "type=CLIENT_RESPONSE" in out
        assert "qname=github.com" in out
        assert "rcode=NOERROR" in out
        assert "len=47" in out

    def test_json_is_valid(self):
        import json
        out = format_frame(self._frame(), fmt="json", use_colour=False)
        doc = json.loads(out)
        assert doc["qname"] == "github.com"
        assert doc["rcode"] == "NOERROR"
        assert doc["wire_len"] == 47

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError):
            format_frame(self._frame(), fmt="yaml", use_colour=False)


class TestLoadAllowlist:
    def test_missing_path_returns_none(self):
        assert _load_allowlist(None) is None

    def test_reads_compiled_file(self, tmp_path: Path):
        reg = DnsSetRegistry()
        reg.add_spec(DnsSetSpec(
            qname="github.com", ttl_floor=300,
            ttl_ceil=3600, size=256))
        path = tmp_path / "compiled"
        write_compiled_allowlist(reg, path)
        loaded = _load_allowlist(path)
        assert loaded == {"github.com"}


class TestPrintSummary:
    def test_summary_shows_counts(self):
        stats = TapStats()
        stats.total = 10
        stats.by_type[6] = 10
        stats.by_rcode[0] = 8
        stats.by_rcode[3] = 2
        stats.by_qname["github.com"] = 5
        stats.by_qname["api.stripe.com"] = 3
        stats.allowlist_hits = 6
        stats.allowlist_misses = 4
        buf = io.StringIO()
        print_summary(stats, stream=buf)
        text = buf.getvalue()
        assert "total frames" in text
        assert "allowlist hit rate" in text
        assert "github.com" in text
        assert "NOERROR" in text
        assert "NXDOMAIN" in text


class TestTapCliArgParser:
    def test_help_lists_key_flags(self):
        from shorewalld.tap import build_parser
        parser = build_parser()
        help_text = parser.format_help()
        assert "--socket" in help_text
        assert "--format" in help_text
        assert "--filter-qname" in help_text
        assert "--allowlist" in help_text

    def test_reject_unknown_format(self):
        from shorewalld.tap import build_parser
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--socket", "/tmp/x", "--format", "yaml"])
