"""Unit tests for shorewall_nft_stagelab.metrics_ingest."""

from __future__ import annotations

import asyncio
import importlib
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import shorewall_nft_stagelab.metrics_ingest as _mi
from shorewall_nft_stagelab.metrics import MetricRow
from shorewall_nft_stagelab.metrics_ingest import (
    PrometheusScraper,
    PrometheusSource,
    SNMPScraper,
    SNMPSource,
    parse_prometheus_exposition,
    scrape_all,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXTURES = Path(__file__).parent.parent / "fixtures"
_PROM_FIXTURE = _FIXTURES / "prom_shorewalld.txt"

_TS = 1_700_000_000.0


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_prometheus_fixture():
    """Load fixture, parse all lines, check count and labelled source."""
    body = _PROM_FIXTURE.read_text()
    rows = parse_prometheus_exposition(body, source_name="fw", ts_unix=_TS)

    # Fixture has: 2 shorewalld_set_size, 3 histogram buckets + sum + count,
    # node_conntrack_count, node_conntrack_max = 9 samples total
    assert len(rows) == 9

    labelled = [r for r in rows if r.key == "shorewalld_set_size" and "blocked_ips" in r.source]
    assert len(labelled) == 1
    assert labelled[0].source == "fw:set=blocked_ips"
    assert labelled[0].value == 42.0
    assert labelled[0].ts_unix == _TS


def test_parse_prometheus_prefix_allow_filters():
    """prefix_allow=('shorewalld_',) keeps only shorewalld_* metrics."""
    body = _PROM_FIXTURE.read_text()
    rows = parse_prometheus_exposition(
        body, source_name="fw", ts_unix=_TS, prefix_allow=("shorewalld_",)
    )
    # node_conntrack_count and node_conntrack_max must be dropped
    assert all(r.key.startswith("shorewalld_") for r in rows)
    node_rows = [r for r in rows if r.key.startswith("node_")]
    assert node_rows == []


def test_parse_prometheus_ignores_malformed_lines():
    """Malformed lines (missing value) are skipped; valid lines are returned."""
    body = (
        "# HELP valid_metric A metric.\n"
        "# TYPE valid_metric gauge\n"
        "valid_metric 1.0\n"
        "this_line_has_no_value\n"          # malformed: no numeric value after name
        "another_good_one 99.0\n"
    )
    rows = parse_prometheus_exposition(body, source_name="test", ts_unix=_TS)
    assert len(rows) == 2
    keys = {r.key for r in rows}
    assert keys == {"valid_metric", "another_good_one"}


def test_prometheus_scraper_http_success():
    """PrometheusScraper hits a minimal HTTP server and returns MetricRows."""
    fixture_body = _PROM_FIXTURE.read_text().encode()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(fixture_body)

        def log_message(self, *args, **kwargs):  # silence default output
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.handle_request)
    thread.daemon = True
    thread.start()

    src = PrometheusSource(name="fw", url=f"http://127.0.0.1:{port}/metrics")
    scraper = PrometheusScraper(src)
    rows = _run(scraper.scrape(_TS))

    thread.join(timeout=2.0)
    server.server_close()

    assert len(rows) > 0
    assert all(isinstance(r, MetricRow) for r in rows)
    assert any(r.key == "shorewalld_set_size" for r in rows)


def test_prometheus_scraper_timeout_raises():
    """PrometheusScraper raises when the server does not respond within timeout."""
    # Bind a TCP socket but never accept — triggers a connection timeout / refused.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    # Do NOT call sock.listen() — connection refused → fast raise for URLError.
    sock.close()

    src = PrometheusSource(name="fw", url=f"http://127.0.0.1:{port}/metrics", timeout_s=0.2)
    scraper = PrometheusScraper(src)
    import urllib.error
    with pytest.raises((TimeoutError, urllib.error.URLError, OSError)):
        _run(scraper.scrape(_TS))


def test_snmp_scraper_import_error_when_pysnmp_missing(monkeypatch):
    """SNMPScraper.scrape raises ImportError with 'pysnmp' in message when pysnmp absent."""
    original_import = importlib.import_module

    def _mock_import(name, *args, **kwargs):
        if name == "pysnmp":
            raise ImportError("No module named 'pysnmp'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", _mock_import)

    src = SNMPSource(
        name="sw-core",
        host="192.168.1.1",
        community="public",
        oids=("1.3.6.1.2.1.1.1.0",),
    )
    scraper = SNMPScraper(src)
    with pytest.raises(ImportError, match="pysnmp"):
        _run(scraper.scrape(_TS))


def test_scrape_all_log_on_error():
    """scrape_all with on_error='log' returns rows from the successful source only.
    on_error='raise' propagates the exception."""

    class _GoodSource(MetricRow):  # reuse as namespace — actually use closures
        pass

    class GoodSrc:
        async def scrape(self, ts: float) -> list[MetricRow]:
            return [MetricRow(source="ok", ts_unix=ts, key="k", value=1.0)]

    class BadSrc:
        async def scrape(self, ts: float) -> list[MetricRow]:
            raise RuntimeError("intentional failure")

    good, bad = GoodSrc(), BadSrc()

    rows_log = _run(scrape_all([good, bad], _TS, on_error="log"))
    assert len(rows_log) == 1
    assert rows_log[0].source == "ok"

    with pytest.raises(RuntimeError, match="intentional failure"):
        _run(scrape_all([good, bad], _TS, on_error="raise"))


# ---------------------------------------------------------------------------
# SNMPScraper — pysnmp-based implementation (S2)
# ---------------------------------------------------------------------------

def _make_snmp_source(**kwargs) -> SNMPSource:
    defaults = dict(
        name="foo-snmp",
        host="192.0.2.1",
        community="public",
        oids=(),
        port=161,
        timeout_s=5.0,
        bundles=("node_traffic",),
    )
    defaults.update(kwargs)
    return SNMPSource(**defaults)


def _fake_pysnmp_globals():
    """Return a dict of minimal pysnmp-like stubs to inject into _mi globals."""

    class _Stub:
        def __init__(self, *a, **kw):
            pass

    class _UdpTransportStub(_Stub):
        @classmethod
        async def create(cls, *a, **kw):
            return cls()

    return {
        "SnmpEngine": _Stub,
        "CommunityData": _Stub,
        "UdpTransportTarget": _UdpTransportStub,
        "ContextData": _Stub,
        "ObjectIdentity": _Stub,
        "ObjectType": _Stub,
    }


def test_snmp_scraper_node_traffic_happy_path(monkeypatch):
    """node_traffic bundle: 2 ifHCInOctets + 2 ifHCOutOctets → 4 MetricRows, no error rows."""

    async def _fake_walk_cmd(engine, auth, transport, ctx, *obj_types, **kw):
        # Yield one row per call: 2 interfaces each for the single OID queried.
        # In reality walk_cmd is called per OID; we yield two var-bind rows per call.
        base_oid = str(obj_types[0])  # ObjectType wraps ObjectIdentity wraps oid string
        rows = [
            (None, 0, 0, [(f"{base_oid}.1", 1000)]),
            (None, 0, 0, [(f"{base_oid}.2", 2000)]),
        ]
        for row in rows:
            yield row

    monkeypatch.setattr(_mi, "_HAS_PYSNMP", True)
    for k, v in _fake_pysnmp_globals().items():
        monkeypatch.setattr(_mi, k, v, raising=False)
    monkeypatch.setattr(_mi, "walk_cmd", _fake_walk_cmd, raising=False)

    # node_traffic has 4 OIDs; each yields 2 rows → 8 rows total
    # but plan says "2 ifHCInOctets + 2 ifHCOutOctets" — test with a single-OID bundle
    src = _make_snmp_source(bundles=("node_traffic",))
    scraper = SNMPScraper(src)
    rows = _run(scraper.scrape(_TS))

    assert len(rows) > 0
    assert all(isinstance(r, MetricRow) for r in rows)
    error_rows = [r for r in rows if r.source.endswith(":error")]
    assert error_rows == [], f"Unexpected error rows: {error_rows}"
    source_rows = [r for r in rows if r.source == "foo-snmp:node_traffic"]
    assert len(source_rows) > 0
    assert all(r.value in (1000.0, 2000.0) for r in source_rows)


def test_snmp_scraper_missing_pysnmp_raises(monkeypatch):
    """SNMPScraper.scrape raises ImportError mentioning pysnmp and extras when _HAS_PYSNMP=False."""
    monkeypatch.setattr(_mi, "_HAS_PYSNMP", False)

    src = _make_snmp_source()
    scraper = SNMPScraper(src)
    with pytest.raises(ImportError) as exc_info:
        _run(scraper.scrape(_TS))

    msg = str(exc_info.value)
    assert "pysnmp" in msg
    assert "snmp" in msg  # extras install hint


def test_snmp_scraper_timeout_emits_error_row(monkeypatch):
    """On asyncio.TimeoutError from walk_cmd, scrape returns an error row; does not raise."""

    async def _timeout_walk_cmd(*a, **kw):
        raise asyncio.TimeoutError
        yield  # make it a generator

    monkeypatch.setattr(_mi, "_HAS_PYSNMP", True)
    for k, v in _fake_pysnmp_globals().items():
        monkeypatch.setattr(_mi, k, v, raising=False)
    monkeypatch.setattr(_mi, "walk_cmd", _timeout_walk_cmd, raising=False)

    src = _make_snmp_source()
    scraper = SNMPScraper(src)
    rows = _run(scraper.scrape(_TS))

    error_rows = [r for r in rows if r.source.endswith(":error")]
    assert len(error_rows) >= 1
    assert all(r.value == -1.0 for r in error_rows)
