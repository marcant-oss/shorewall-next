"""Fuzz tests: random config generation + compile + kernel-load.

Generates random Shorewall configs and verifies:
1. They compile without errors
2. The nft output is valid syntax (nft -c -f)
3. They load in a test namespace

Uses sudo /usr/local/bin/run-netns for namespace operations.
"""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path

import pytest

from shorewall_nft.tools.config_gen import ConfigGenerator

RUN_NETNS = ["sudo", "/usr/local/bin/run-netns"]
NS = "shorewall-next-sim-fuzz"
import sys as _sys; SWNFT = str(Path(_sys.executable).parent / "shorewall-nft")


def _kill_ns_pids(ns: str) -> None:
    # See tests/test_cli_integration.py — `ip netns exec NS kill -9 -1` is
    # UNSAFE because ip netns does not isolate PIDs from the host.
    r = subprocess.run([*RUN_NETNS, "pids", ns],
                       capture_output=True, text=True, timeout=5)
    for tok in r.stdout.split():
        if tok.isdigit():
            try:
                os.kill(int(tok), signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.fixture(scope="module")
def fuzz_netns():
    """Create namespace for fuzz testing."""
    subprocess.run([*RUN_NETNS, "add", NS], capture_output=True)
    yield NS
    _kill_ns_pids(NS)
    import time
    time.sleep(0.2)
    subprocess.run([*RUN_NETNS, "delete", NS], capture_output=True)


@pytest.mark.parametrize("seed", range(20))
def test_random_config_compiles(seed, tmp_path):
    """Random configs must compile without errors."""
    gen = ConfigGenerator(seed=seed)
    num_zones = (seed % 8) + 2  # 2-9 zones
    num_rules = (seed % 50) + 10  # 10-59 rules
    features = {"macros", "rfc1918"}
    if seed % 3 == 0:
        features.add("nat")

    cfg_dir = tmp_path / f"fuzz-{seed}"
    gen.generate(cfg_dir, num_zones=num_zones, num_rules=num_rules,
                 features=features)

    r = subprocess.run([SWNFT, "compile", str(cfg_dir)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"Seed {seed}: {r.stderr[:200]}"
    assert "table inet shorewall" in r.stdout


@pytest.mark.parametrize("seed", range(10))
def test_random_config_loads_in_netns(seed, tmp_path, fuzz_netns):
    """Random configs must load in a test namespace."""
    gen = ConfigGenerator(seed=seed + 100)  # Different seeds from compile test
    num_zones = (seed % 5) + 2
    num_rules = (seed % 30) + 10
    features = {"macros", "rfc1918", "nat"}

    cfg_dir = tmp_path / f"fuzz-load-{seed}"
    gen.generate(cfg_dir, num_zones=num_zones, num_rules=num_rules,
                 features=features)

    # Compile to file
    nft_file = tmp_path / f"fuzz-{seed}.nft"
    r = subprocess.run([SWNFT, "compile", str(cfg_dir), "-o", str(nft_file)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"Compile failed: {r.stderr[:200]}"

    # Validate syntax
    r = subprocess.run([*RUN_NETNS, "exec", NS, "nft", "-c", "-f", str(nft_file)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"nft -c failed: {r.stderr[:200]}"

    # Load
    r = subprocess.run([*RUN_NETNS, "exec", NS, "nft", "-f", str(nft_file)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"nft -f failed: {r.stderr[:200]}"

    # Verify loaded
    r = subprocess.run([*RUN_NETNS, "exec", NS, "nft", "list", "table", "inet", "shorewall"],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 0


@pytest.mark.parametrize("seed", range(5))
def test_dual_stack_config(seed, tmp_path):
    """Dual-stack configs must compile."""
    gen = ConfigGenerator(seed=seed + 200)
    cfg_dir = tmp_path / f"fuzz-ds-{seed}"
    gen.generate(cfg_dir, num_zones=3, num_rules=20,
                 dual_stack=True, features={"macros"})

    r = subprocess.run([SWNFT, "compile", str(cfg_dir)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"Dual-stack compile failed: {r.stderr[:200]}"
    assert "table inet shorewall" in r.stdout
    # Dual-stack output has nfproto and/or NDP rules
    assert "nfproto" in r.stdout or "icmpv6" in r.stdout


def test_extreme_zones(tmp_path):
    """Config with many zones must compile."""
    gen = ConfigGenerator(seed=999)
    cfg_dir = tmp_path / "fuzz-extreme"
    gen.generate(cfg_dir, num_zones=25, num_rules=200,
                 features={"macros", "rfc1918", "nat"})

    r = subprocess.run([SWNFT, "compile", str(cfg_dir)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"Extreme compile failed: {r.stderr[:200]}"


def test_minimal_config(tmp_path):
    """Config with 2 zones and 0 rules must compile."""
    gen = ConfigGenerator(seed=0)
    cfg_dir = tmp_path / "fuzz-minimal"
    gen.generate(cfg_dir, num_zones=2, num_rules=0, features=set())

    r = subprocess.run([SWNFT, "compile", str(cfg_dir)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0
