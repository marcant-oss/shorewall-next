"""Unit tests for shorewall_nft_simlab.report.write_json."""

from __future__ import annotations

import argparse
import json
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from shorewall_nft_simlab.report import write_json

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_spec(
    probe_id: int,
    inject_iface: str,
    expect_iface: str,
    verdict: str,
    payload: bytes = b"",
    elapsed_ms: int = 1,
) -> MagicMock:
    spec = MagicMock()
    spec.probe_id = probe_id
    spec.inject_iface = inject_iface
    spec.expect_iface = expect_iface
    spec.verdict = verdict
    spec.payload = payload
    spec.elapsed_ms = elapsed_ms
    return spec


def _make_probe(
    cat: str,
    expected: str,
    verdict: str,
    probe_id: int = 1,
    oracle_reason: str = "",
) -> tuple:
    spec = _make_spec(probe_id, "eth0", "eth1", verdict)
    meta: dict = {"desc": f"probe-{probe_id}", "oracle_reason": oracle_reason}
    return (cat, expected, spec, meta)


# ---------------------------------------------------------------------------
# 1. write_json round-trip
# ---------------------------------------------------------------------------


def test_write_json_roundtrip(tmp_path: Path) -> None:
    """write_json writes a valid JSON file; parse it and check invariants."""
    probes = [
        _make_probe("tcp", "ACCEPT", "ACCEPT", probe_id=1),
        _make_probe("tcp", "DROP",   "DROP",   probe_id=2),
        _make_probe("udp", "ACCEPT", "DROP",   probe_id=3),  # fail_drop
        _make_probe("udp", "DROP",   "ACCEPT", probe_id=4),  # fail_accept
    ]
    out = tmp_path / "simlab.json"
    result = write_json(probes, out, run_name="smoke", run_ts="2026-04-20T00:00:00+00:00")

    assert result == out
    assert out.exists()

    data = json.loads(out.read_text())

    # Top-level schema
    assert data["schema_version"] == 1
    assert data["kind"] == "simlab-correctness"
    assert data["run_name"] == "smoke"

    # Summary counters
    summary = data["summary"]
    assert summary["pass_accept"] == 1
    assert summary["pass_drop"] == 1
    assert summary["fail_drop"] == 1
    assert summary["fail_accept"] == 1
    assert summary["total"] == 4
    assert summary["mismatch_rate"] == pytest.approx(0.5, rel=1e-4)

    # Scenarios: must have exactly 2 entries
    scenarios = data["scenarios"]
    assert len(scenarios) == 2

    ids = {s["scenario_id"] for s in scenarios}
    assert ids == {"simlab-fail-accept", "simlab-fail-drop"}

    fa = next(s for s in scenarios if s["scenario_id"] == "simlab-fail-accept")
    assert fa["ok"] is False                   # fail_accept == 1, not 0
    assert fa["raw"]["count"] == 1
    assert fa["source"] == "simlab"
    assert "cc-iso-15408-fdp-iff-1" in fa["standard_refs"]

    fd = next(s for s in scenarios if s["scenario_id"] == "simlab-fail-drop")
    # fail_drop=1 <= 2 tolerance → ok is True
    assert fd["ok"] is True
    assert fd["raw"]["count"] == 1


def test_write_json_all_pass(tmp_path: Path) -> None:
    """All-pass run: fail_accept=0, fail_drop=0 → both scenarios ok=True."""
    probes = [
        _make_probe("tcp", "ACCEPT", "ACCEPT", probe_id=1),
        _make_probe("tcp", "DROP",   "DROP",   probe_id=2),
    ]
    out = tmp_path / "simlab.json"
    write_json(probes, out, run_name="smoke")

    data = json.loads(out.read_text())
    scenarios = data["scenarios"]
    for s in scenarios:
        assert s["ok"] is True, f"Expected ok=True for {s['scenario_id']}"

    assert data["summary"]["mismatch_rate"] == 0.0


def test_write_json_zero_probes(tmp_path: Path) -> None:
    """Empty probe list: totals zero, mismatch_rate zero, scenarios ok=True."""
    out = tmp_path / "simlab.json"
    write_json([], out)

    data = json.loads(out.read_text())
    assert data["summary"]["total"] == 0
    assert data["summary"]["mismatch_rate"] == 0.0
    # Both scenarios pass vacuously
    for s in data["scenarios"]:
        assert s["ok"] is True


def test_write_json_failures_capped_at_50(tmp_path: Path) -> None:
    """Failures list is capped at 50 entries regardless of input size."""
    probes = [
        _make_probe("tcp", "ACCEPT", "DROP", probe_id=i)
        for i in range(100)
    ]
    out = tmp_path / "simlab.json"
    write_json(probes, out)

    data = json.loads(out.read_text())
    assert len(data["failures"]) == 50


# ---------------------------------------------------------------------------
# 2. smoketest --output-json produces the file
# ---------------------------------------------------------------------------


def test_smoketest_output_json_flag(tmp_path: Path, monkeypatch) -> None:
    """cmd_smoke honours --output-json and writes a valid simlab.json."""
    from shorewall_nft_simlab import smoketest

    out_path = tmp_path / "simlab.json"

    # Build a minimal fake probes list (the static probes returned by
    # _build_static_probes after _smoke_one fills in verdicts).
    probes = [
        _make_probe("tcp", "ACCEPT", "ACCEPT", probe_id=1),
        _make_probe("tcp", "DROP",   "DROP",   probe_id=2),
    ]

    # Patch out all the heavy infrastructure.
    fake_ctl = MagicMock()
    fake_ctl.workers = {"eth0": MagicMock()}
    fake_ctl.topo = MagicMock()
    fake_ctl.topo.tun_mac = {}
    fake_ctl.state = MagicMock()
    fake_ctl.state.interfaces = []
    fake_ctl.state.routes4 = []
    fake_ctl.state.routes6 = []

    monkeypatch.setattr(smoketest, "_apply_sysctls", lambda: [])
    monkeypatch.setattr(smoketest, "_resource_counts", lambda ns_name="simlab-fw": {})
    monkeypatch.setattr(smoketest, "_compile_ruleset", lambda cfg, nft: None)
    # SimController is imported lazily with `from .controller import SimController`
    # so we patch the name in the smoketest module's namespace directly via
    # sys.modules injection before cmd_smoke runs the import.
    import sys
    import types as _types
    fake_controller_mod = _types.SimpleNamespace(SimController=lambda **kwargs: fake_ctl)
    monkeypatch.setitem(sys.modules, "shorewall_nft_simlab.controller", fake_controller_mod)
    monkeypatch.setattr(smoketest, "_build_static_probes", lambda mac_map: probes)

    async def _fake_smoke_one(ctl, specs):  # noqa: ANN001
        pass

    monkeypatch.setattr(smoketest, "_smoke_one", _fake_smoke_one)
    monkeypatch.setattr(smoketest, "asyncio", types.SimpleNamespace(run=lambda coro: None))

    args = argparse.Namespace(
        data=tmp_path,
        config=tmp_path,
        no_auto_sysctl=True,
        no_dump_config=False,
        pcap_dir=None,
        output_json=out_path,
    )

    ret = smoketest.cmd_smoke(args)

    assert ret == 0
    assert out_path.exists(), "simlab.json should have been written"
    data = json.loads(out_path.read_text())
    assert data["schema_version"] == 1
    assert len(data["scenarios"]) == 2


def test_smoketest_no_output_json_flag(tmp_path: Path, monkeypatch) -> None:
    """cmd_smoke without --output-json does NOT create any JSON file."""
    from shorewall_nft_simlab import smoketest

    probes = [_make_probe("tcp", "ACCEPT", "ACCEPT", probe_id=1)]

    fake_ctl = MagicMock()
    fake_ctl.workers = {"eth0": MagicMock()}
    fake_ctl.topo = MagicMock()
    fake_ctl.topo.tun_mac = {}
    fake_ctl.state = MagicMock()
    fake_ctl.state.interfaces = []
    fake_ctl.state.routes4 = []
    fake_ctl.state.routes6 = []

    monkeypatch.setattr(smoketest, "_apply_sysctls", lambda: [])
    monkeypatch.setattr(smoketest, "_resource_counts", lambda ns_name="simlab-fw": {})
    monkeypatch.setattr(smoketest, "_compile_ruleset", lambda cfg, nft: None)
    import sys
    import types as _types
    fake_controller_mod = _types.SimpleNamespace(SimController=lambda **kwargs: fake_ctl)
    monkeypatch.setitem(sys.modules, "shorewall_nft_simlab.controller", fake_controller_mod)
    monkeypatch.setattr(smoketest, "_build_static_probes", lambda mac_map: probes)

    async def _fake_smoke_one(ctl, specs):
        pass

    monkeypatch.setattr(smoketest, "_smoke_one", _fake_smoke_one)
    monkeypatch.setattr(smoketest, "asyncio", types.SimpleNamespace(run=lambda coro: None))

    args = argparse.Namespace(
        data=tmp_path,
        config=tmp_path,
        no_auto_sysctl=True,
        no_dump_config=False,
        pcap_dir=None,
        output_json=None,
    )

    ret = smoketest.cmd_smoke(args)
    assert ret == 0
    # No simlab.json should be present
    json_files = list(tmp_path.glob("*.json"))
    assert not json_files, f"Unexpected json files: {json_files}"
