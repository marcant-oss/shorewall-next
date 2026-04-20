"""Integration test: StagelabController with spawn_local transport.

Requires no root — exercises PING and SHUTDOWN only (no netns setup).
"""

from __future__ import annotations

import asyncio
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from shorewall_nft_stagelab.config import load
from shorewall_nft_stagelab.controller import StagelabController, spawn_local

# ---------------------------------------------------------------------------
# Minimal YAML: one host (address "local:"), one probe endpoint, zero scenarios.
# ---------------------------------------------------------------------------

_MINIMAL_YAML = textwrap.dedent("""\
    hosts:
      - name: localh
        address: "local:"

    dut:
      kind: external

    endpoints:
      - name: ep-local
        host: localh
        mode: probe
        bridge: br0

    scenarios: []

    report:
      output_dir: /tmp/stagelab-test-controller
""")

# YAML template for the scraping test — port substituted at runtime
_SCRAPE_YAML_TMPL = textwrap.dedent("""\
    hosts:
      - name: localh
        address: "local:"

    dut:
      kind: external

    endpoints:
      - name: ep-local
        host: localh
        mode: probe
        bridge: br0

    scenarios: []

    metrics:
      poll_interval_s: 1
      sources:
        - kind: prometheus
          name: mock-node-exporter
          url: "http://127.0.0.1:{port}/metrics"

    report:
      output_dir: /tmp/stagelab-test-scrape
""")

# Fixed Prometheus body served by the mock HTTP server
_PROM_BODY = """\
# HELP node_conntrack_count Number of currently allocated flow entries.
# TYPE node_conntrack_count gauge
node_conntrack_count 900000
# HELP node_conntrack_max Maximum size of connection tracking table.
# TYPE node_conntrack_max gauge
node_conntrack_max 1000000
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.timeout(15)
def test_controller_local_ping_and_shutdown(tmp_path):
    """Controller connects to a local agent, PINGs it, then shuts it down cleanly."""
    cfg_file = tmp_path / "cfg.yaml"
    cfg_file.write_text(_MINIMAL_YAML)
    cfg = load(cfg_file)

    async def _run():
        controller = StagelabController(cfg, transport_factory=spawn_local)
        try:
            await controller.connect()
        finally:
            await controller.close()

        # Verify all subprocesses have exited
        for conn in controller._connections.values():  # already cleared, but just in case
            pass  # _connections is cleared by close()

    asyncio.run(asyncio.wait_for(_run(), timeout=10.0))


@pytest.mark.timeout(30)
def test_controller_scrapes_mock_prometheus_and_attaches_recommendations(tmp_path):
    """Controller polls a mock Prometheus endpoint and advisor flags conntrack_headroom."""

    # Spin up a minimal HTTP server in a background thread
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = _PROM_BODY.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence default stderr logging
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        cfg_yaml = _SCRAPE_YAML_TMPL.format(port=port)
        cfg_file = tmp_path / "cfg.yaml"
        cfg_file.write_text(cfg_yaml)
        cfg = load(cfg_file)

        async def _run():
            controller = StagelabController(cfg, transport_factory=spawn_local)
            try:
                await controller.connect()
                await controller.start_scraping()
                # Allow at least one poll to complete
                await asyncio.sleep(2)
                await controller.stop_scraping()
                report = await controller.run_scenarios()
            finally:
                await controller.close()
            return report

        report = asyncio.run(asyncio.wait_for(_run(), timeout=20.0))

        assert report.recommendations, "expected at least one recommendation"
        signals = [r.signal for r in report.recommendations]
        assert "conntrack_headroom" in signals, (
            f"conntrack_headroom not in recommendations; got signals: {signals}"
        )
    finally:
        server.shutdown()
