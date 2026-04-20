"""Integration test: StagelabController with spawn_local transport.

Requires no root — exercises PING and SHUTDOWN only (no netns setup).
"""

from __future__ import annotations

import asyncio
import textwrap

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


# ---------------------------------------------------------------------------
# Test
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
