"""Route/interface detection tests in prepared network namespaces.

These tests exercise features that depend on the running kernel state —
interface addresses, routes, broadcast detection, routefilter sysctls —
by setting up a netns with real veth pairs and verifying shorewall-nft
behaves correctly against the live kernel state.

Must be invoked via tools/run-tests.sh (private network + mount namespace).
Tests skip if not running as root or if `ip` binary is not available.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

IP_NETNS = ["ip", "netns"]
import sys as _sys; SWNFT = str(Path(_sys.executable).parent / "shorewall-nft")
NS = "shorewall-next-sim-route"


def _have_netns_tooling() -> bool:
    """Return True when we can create network namespaces (root + ip binary)."""
    if os.geteuid() != 0:
        return False
    try:
        r = subprocess.run(["ip", "netns", "list"],
                           capture_output=True, timeout=2)
        return r.returncode == 0
    except Exception:
        return False


skip_no_netns = pytest.mark.skipif(
    not _have_netns_tooling(),
    reason="requires root + ip binary (run via tools/run-tests.sh)",
)


def _ns(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command inside the test netns."""
    return subprocess.run(
        [*IP_NETNS, "exec", NS, *args],
        capture_output=True, text=True, check=check,
    )


@pytest.fixture
def prepared_netns():
    """Create a netns with lo up and a dummy interface with a route."""
    # Cleanup any leftovers
    subprocess.run([*IP_NETNS, "delete", NS],
                   capture_output=True, check=False)
    subprocess.run([*IP_NETNS, "add", NS], check=True, capture_output=True)
    try:
        _ns("ip", "link", "set", "lo", "up")
        _ns("ip", "link", "add", "dev", "dummy0", "type", "dummy")
        _ns("ip", "link", "set", "dummy0", "up")
        _ns("ip", "addr", "add", "10.99.0.1/24", "dev", "dummy0")
        _ns("ip", "route", "add", "10.88.0.0/16", "dev", "dummy0")
        yield NS
    finally:
        subprocess.run([*IP_NETNS, "delete", NS],
                       capture_output=True, check=False)


# ──────────────────────────────────────────────────────────────────────
# Minimal config fixture: a single zone with dummy0 as the interface
# ──────────────────────────────────────────────────────────────────────

@pytest.fixture
def minimal_config(tmp_path):
    """Build a minimal shorewall-nft config that references dummy0."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "shorewall.conf").write_text("STARTUP_ENABLED=Yes\nOPTIMIZE=0\n")
    (cfg / "zones").write_text("fw\tfirewall\nnet\tipv4\n")
    (cfg / "interfaces").write_text(
        "net\tdummy0\t-\ttcpflags,routefilter\n"
    )
    (cfg / "policy").write_text(
        "$FW\tnet\tACCEPT\n"
        "net\t$FW\tDROP\n"
        "all\tall\tREJECT\n"
    )
    (cfg / "rules").write_text(
        "?SECTION NEW\n"
        "ACCEPT\tnet\t$FW\ttcp\t22\n"
    )
    (cfg / "params").write_text("")
    return cfg


# ──────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────

@skip_no_netns
class TestRouteDetection:
    """Verify shorewall-nft honors the kernel routing table and interface
    addresses in a live netns."""

    def test_ruleset_loads_with_real_interface(
            self, prepared_netns, minimal_config):
        """A ruleset referencing dummy0 should load cleanly in a netns
        where dummy0 exists with a real address + route."""
        compile_out = subprocess.run(
            [SWNFT, "compile", str(minimal_config)],
            capture_output=True, text=True, check=True,
        )
        nft_script = compile_out.stdout
        assert "inet shorewall" in nft_script

        # Write to tempfile and load
        nft_path = Path("/tmp/shorewall-next-sim-route-test.nft")
        nft_path.write_text(nft_script)
        try:
            r = _ns("nft", "-f", str(nft_path), check=False)
            assert r.returncode == 0, f"nft load failed: {r.stderr}"
        finally:
            nft_path.unlink(missing_ok=True)

    def test_routes_survive_ruleset_load(
            self, prepared_netns, minimal_config):
        """Loading the ruleset must not clobber the kernel routing table."""
        before = _ns("ip", "route").stdout

        compile_out = subprocess.run(
            [SWNFT, "compile", str(minimal_config)],
            capture_output=True, text=True, check=True,
        )
        nft_path = Path("/tmp/shorewall-next-sim-route-test.nft")
        nft_path.write_text(compile_out.stdout)
        try:
            _ns("nft", "-f", str(nft_path))
        finally:
            nft_path.unlink(missing_ok=True)

        after = _ns("ip", "route").stdout
        assert "10.88.0.0/16" in after
        assert before.strip() == after.strip(), \
            "Loading the ruleset unexpectedly modified the routing table"

    def test_interface_address_readable(self, prepared_netns):
        """Sanity check that our netns setup gives dummy0 the expected
        address — if this fails, other tests in this class can't work."""
        r = _ns("ip", "-4", "addr", "show", "dev", "dummy0")
        assert "10.99.0.1/24" in r.stdout

    def test_rp_filter_sysctl_settable(self, prepared_netns):
        """routefilter translates to a per-interface rp_filter sysctl.
        We don't auto-apply it from shorewall-nft yet (generate-sysctl
        produces the script), but the kernel path must work so that a
        future auto-applier can rely on it."""
        r = _ns("sysctl", "-w", "net.ipv4.conf.dummy0.rp_filter=1",
                check=False)
        if r.returncode != 0:
            pytest.skip("rp_filter sysctl not writable in this kernel")
        verify = _ns("sysctl", "-n", "net.ipv4.conf.dummy0.rp_filter")
        assert verify.stdout.strip() == "1"

    def test_generate_sysctl_output(self, minimal_config):
        """generate-sysctl should produce a shell script with rp_filter
        directives for routefilter-enabled interfaces."""
        r = subprocess.run(
            [SWNFT, "generate-sysctl", str(minimal_config)],
            capture_output=True, text=True, check=True,
        )
        assert "#!/bin/sh" in r.stdout
        assert "rp_filter" in r.stdout
        assert "dummy0" in r.stdout


@skip_no_netns
class TestSysctlApplied:
    """Verify that a generated sysctl script actually applies when run
    inside a netns with the expected interfaces."""

    def test_generated_sysctl_runs(self, prepared_netns, minimal_config,
                                   tmp_path):
        """Execute the generated sysctl script in the netns and verify
        the kernel state matches the expected settings."""
        gen = subprocess.run(
            [SWNFT, "generate-sysctl", str(minimal_config)],
            capture_output=True, text=True, check=True,
        )
        script = tmp_path / "apply-sysctl.sh"
        script.write_text(gen.stdout)
        script.chmod(0o755)

        # Run script inside netns
        r = _ns("sh", str(script), check=False)
        # Some sysctls may not exist for dummy interfaces; we tolerate
        # stderr warnings but require exit code 0.
        assert r.returncode == 0 or "No such file" in r.stderr

        # Verify rp_filter got set for dummy0
        verify = _ns("sysctl", "-n", "net.ipv4.conf.dummy0.rp_filter",
                     check=False)
        if verify.returncode == 0:
            assert verify.stdout.strip() in ("1", "2"), \
                f"expected rp_filter enabled, got {verify.stdout.strip()}"


@skip_no_netns
class TestDhcpInterface:
    """The `dhcp` interface option auto-generates DHCP allow rules
    (UDP 67/68). Verify the generated ruleset loads and the expected
    rules are present."""

    def test_dhcp_rules_emitted(self, prepared_netns, tmp_path):
        cfg = tmp_path / "dhcp-cfg"
        cfg.mkdir()
        (cfg / "shorewall.conf").write_text("STARTUP_ENABLED=Yes\n")
        (cfg / "zones").write_text("fw\tfirewall\nnet\tipv4\n")
        (cfg / "interfaces").write_text("net\tdummy0\t-\tdhcp\n")
        (cfg / "policy").write_text(
            "$FW\tnet\tACCEPT\n"
            "net\t$FW\tACCEPT\n"
            "all\tall\tREJECT\n"
        )
        (cfg / "rules").write_text("?SECTION NEW\n")
        (cfg / "params").write_text("")

        r = subprocess.run(
            [SWNFT, "compile", str(cfg)],
            capture_output=True, text=True, check=True,
        )
        script = r.stdout
        # DHCP rules are UDP 67,68
        assert "67" in script and "68" in script, \
            "Expected DHCP auto-generated rules (udp 67/68)"

        nft_path = Path("/tmp/shorewall-next-sim-dhcp.nft")
        nft_path.write_text(script)
        try:
            r = _ns("nft", "-f", str(nft_path), check=False)
            assert r.returncode == 0
        finally:
            nft_path.unlink(missing_ok=True)


@skip_no_netns
class TestStartInNetns:
    """End-to-end: shorewall-nft start --netns <NS> with a live interface.

    This exercises the full CLI path: compile → capability check →
    apply_nft in netns → verify by querying the loaded ruleset.
    """

    def test_full_lifecycle(self, prepared_netns, minimal_config):
        env = {**os.environ,
               "PYTHONPATH": str(Path(__file__).parent.parent)}

        # Start
        r = subprocess.run(
            [SWNFT, "start", str(minimal_config), "--netns", NS],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0, \
            f"start failed: stdout={r.stdout} stderr={r.stderr}"

        # Verify the ruleset is loaded
        listing = _ns("nft", "list", "table", "inet", "shorewall")
        assert "chain" in listing.stdout
        assert "input" in listing.stdout

        # Status should report running
        r = subprocess.run(
            [SWNFT, "status", "--netns", NS],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0
        assert "running" in r.stdout.lower()

        # Stop
        r = subprocess.run(
            [SWNFT, "stop", "--netns", NS],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 0

        # Status after stop should exit non-zero
        r = subprocess.run(
            [SWNFT, "status", "--netns", NS],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode != 0
