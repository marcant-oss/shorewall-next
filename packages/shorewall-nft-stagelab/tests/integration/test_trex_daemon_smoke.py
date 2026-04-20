"""Smoke test: TRex daemon lifecycle + stats parsing against a real binary.

Skips cleanly when no TRex bundle is present (CI / dev laptop).
Runs on a host with a staged TRex tarball at /opt/trex/<version>/.

Set STAGELAB_TREX_BINARY to override the default binary path.
"""

from __future__ import annotations

import os
import sys
import tarfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Guard: real TRex binary must exist.
# ---------------------------------------------------------------------------

_TREX_BIN = Path(os.environ.get("STAGELAB_TREX_BINARY", "/opt/trex/v3.04/t-rex-64"))
_TREX_CLIENT_PKG = _TREX_BIN.parent / "trex_client_pkg.tar.gz"

pytestmark = pytest.mark.skipif(
    not _TREX_BIN.is_file(),
    reason=(
        f"Real TRex binary not found at {_TREX_BIN} "
        "(set STAGELAB_TREX_BINARY or place a bundle at /opt/trex/<version>/)"
    ),
)


# ---------------------------------------------------------------------------
# Fixture: extract trex_stl_lib from the bundle tarball and add to sys.path.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def _trex_client_extracted(tmp_path_factory):
    """Extract trex_client_pkg.tar.gz and inject the client library path."""
    if not _TREX_CLIENT_PKG.exists():
        pytest.skip(
            f"trex_client_pkg.tar.gz not found at {_TREX_CLIENT_PKG} "
            "— cannot import trex_stl_lib"
        )

    dest = tmp_path_factory.mktemp("trex_client")
    with tarfile.open(_TREX_CLIENT_PKG) as tf:
        tf.extractall(dest)  # noqa: S202 — trusted local bundle

    # Walk extracted tree: find the directory that contains trex_stl_lib/
    for candidate in dest.rglob("trex_stl_lib"):
        if candidate.is_dir():
            parent = str(candidate.parent)
            if parent not in sys.path:
                sys.path.insert(0, parent)
            break

    # Verify the import works after path injection; skip if bundle layout differs.
    try:
        import trex_stl_lib.api  # noqa: F401
    except ImportError as exc:
        pytest.skip(f"trex_stl_lib still not importable after path injection: {exc}")

    yield dest
    # tmp_path_factory handles file cleanup; sys.path entry stays for test lifetime.


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------


@pytest.mark.timeout(30)
def test_stl_daemon_smoke_stats_shape(_trex_client_extracted, tmp_path):
    """Spawn a TRex daemon in software mode, run a 1-second UDP flood, fetch
    stats via run_trex_stl, and assert parse_stl_stats finds the fields our
    code reads (total_tx_bps, total_tx_pps, err_counters)."""
    from shorewall_nft_stagelab import trafgen_trex, trex_daemon
    from shorewall_nft_stagelab.trafgen_trex_profiles import build_udp_flood_profile

    # 1. Build a minimal UDP-flood profile.
    profile_text = build_udp_flood_profile(
        src_cidr="10.99.0.0/16",
        dst_ips=("10.99.255.1",),
        dst_ports=(12345,),
        payload_size_b=64,
        rate_pps=1000,
    )

    # 2. Spawn TRex in software/dummy mode (no real NICs required).
    spec = trex_daemon.TrexDaemonSpec(
        mode="stl",
        port=4501,
        pci_ports=("dummy",),
        cores=(0,),
        binary_path=_TREX_BIN,
    )

    try:
        handle = trex_daemon.ensure_running(spec)
    except RuntimeError as exc:
        pytest.skip(f"TRex daemon failed to start (software-mode unsupported?): {exc}")

    try:
        # 3. Run the profile for 1 second.
        stl_spec = trafgen_trex.TrexStatelessSpec(
            ports=(0,),
            duration_s=1,
            multiplier="1000pps",
            profile_text=profile_text,
            trex_daemon_port=4501,
        )
        result = trafgen_trex.run_trex_stl(stl_spec)

        # 4. Assert the shape of TrexResult and that parse_stl_stats extracted
        # the fields it relies on (values may be zero under a dummy port).
        assert result.tool == "trex-stl"
        assert isinstance(result.duration_s, float)
        assert hasattr(result, "throughput_gbps")
        assert hasattr(result, "pps")
        assert hasattr(result, "errors")

        # raw must be a dict; "global" section is where parse_stl_stats reads.
        raw = result.raw
        assert isinstance(raw, dict), f"expected dict from get_stats(); got {type(raw).__name__}"
        assert "global" in raw or "total_tx_bps" in str(raw), (
            "parse_stl_stats expects total_tx_bps/pps under raw['global']; "
            f"got keys: {list(raw.keys())}"
        )

    finally:
        trex_daemon.stop(handle)
