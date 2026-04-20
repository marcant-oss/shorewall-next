"""Unit tests for shorewall_nft_stagelab.metrics_ingest."""

from __future__ import annotations

import asyncio
import importlib
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

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
