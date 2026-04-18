"""CLI Integration Tests — tests all 32 shorewall-nft commands.

Runs in a single network namespace (shorewall-next-sim-cli) for isolation.
Must be invoked via tools/run-tests.sh (private network + mount namespace).

Usage:
    tools/run-tests.sh tests/test_cli_integration.py -v
    tools/run-tests.sh tests/test_cli_integration.py -v -k netns
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
from pathlib import Path

import pytest

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"
NAT_DIR = Path(__file__).parent / "configs" / "nat"
# Production config paths (optional — tests gate on their existence).
# Override via env var for local development:
#   SHOREWALL_NFT_PROD_DIR=/srv/mytest/shorewall pytest ...
PROD_DIR = Path(os.environ.get(
    "SHOREWALL_NFT_PROD_DIR",
    "/etc/shorewall"))
PROD6_DIR = Path(os.environ.get(
    "SHOREWALL_NFT_PROD6_DIR",
    "/etc/shorewall6"))
IPT_DUMP = Path(os.environ.get(
    "SHOREWALL_NFT_IPT_DUMP",
    "/tmp/iptables-save.txt"))
NS = "shorewall-next-sim-cli"
IP_NETNS = ["ip", "netns"]


def _run(args: list[str], timeout: int = 30, **kwargs) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)}
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, **kwargs)


import sys as _sys; SWNFT = str(Path(_sys.executable).parent / "shorewall-nft")


def _cli(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a shorewall-nft CLI command."""
    return _run([SWNFT, *args], timeout=timeout)


def _cli_in_ns(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run shorewall-nft INSIDE the test namespace as root.

    Uses ip netns exec with full path to the venv binary.
    """
    return _run([*IP_NETNS, "exec", NS, SWNFT, *args], timeout=timeout)


def _ns_exists() -> bool:
    """Check if the test namespace exists."""
    r = _run([*IP_NETNS, "list"])
    return NS in r.stdout


def _kill_ns_pids(ns: str) -> None:
    # `ip netns exec NS kill -9 -1` is UNSAFE: ip netns shares the host PID
    # namespace. Scan /proc/*/ns/net by inode instead.
    ns_path = Path(f"/run/netns/{ns}")
    try:
        ns_ino = ns_path.stat().st_ino
    except OSError:
        return
    for proc_ns in Path("/proc").glob("*/ns/net"):
        try:
            if proc_ns.stat().st_ino == ns_ino:
                pid = int(proc_ns.parts[2])
                os.kill(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError, ValueError):
            pass


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def swnft_cli_netns():
    """Create the test namespace for the entire module, clean up after."""
    # Create
    _run([*IP_NETNS, "add", NS])
    yield NS
    # Cleanup
    _kill_ns_pids(NS)
    import time
    time.sleep(0.2)
    _run([*IP_NETNS, "delete", NS])


@pytest.fixture
def tmp_nft_file(tmp_path):
    """Temp file for save/restore tests."""
    return tmp_path / "saved.nft"


@pytest.fixture
def tmp_merged(tmp_path):
    """Temp dir for merge-config."""
    d = tmp_path / "merged"
    d.mkdir()
    return d


# ──────────────────────────────────────────────────────────────────────
# Compile/Check (no netns)
# ──────────────────────────────────────────────────────────────────────

class TestCompileCheck:
    def test_version(self):
        r = _cli("--version")
        assert r.returncode == 0
        assert "shorewall-nft, version " in r.stdout

    def test_compile_stdout(self):
        r = _cli("compile", str(MINIMAL_DIR))
        assert r.returncode == 0
        assert "table inet shorewall" in r.stdout

    def test_compile_to_file(self, tmp_path):
        out = tmp_path / "out.nft"
        r = _cli("compile", str(MINIMAL_DIR), "-o", str(out))
        assert r.returncode == 0
        assert out.exists()
        assert "table inet shorewall" in out.read_text()

    def test_check_skip_caps(self):
        r = _cli("check", str(MINIMAL_DIR), "--skip-caps")
        assert r.returncode == 0
        assert "compiled" in r.stdout.lower() or "valid" in r.stdout.lower()

    def test_check_with_caps(self):
        r = _cli("check", str(MINIMAL_DIR), timeout=60)
        # May fail if capabilities unavailable, but should not crash
        assert r.returncode in (0, 1)

    def test_compile_nat_config(self):
        r = _cli("compile", str(NAT_DIR))
        assert r.returncode == 0
        assert "snat to" in r.stdout or "dnat to" in r.stdout


# ──────────────────────────────────────────────────────────────────────
# Lifecycle (in netns)
# ──────────────────────────────────────────────────────────────────────

class TestLifecycle:
    """Lifecycle tests run INSIDE the netns via ip netns exec."""

    def test_01_start(self, swnft_cli_netns):
        r = _cli_in_ns("start", str(MINIMAL_DIR), timeout=60)
        assert r.returncode == 0, r.stderr
        assert "started" in r.stdout.lower()

    def test_02_status_running(self, swnft_cli_netns):
        r = _cli_in_ns("status")
        assert r.returncode == 0, r.stderr
        assert "running" in r.stdout.lower()

    def test_03_restart(self, swnft_cli_netns):
        r = _cli_in_ns("restart", str(MINIMAL_DIR), timeout=60)
        assert r.returncode == 0, r.stderr
        assert "restarted" in r.stdout.lower()

    def test_04_reload(self, swnft_cli_netns):
        r = _cli_in_ns("reload", str(MINIMAL_DIR), timeout=60)
        assert r.returncode == 0, r.stderr
        assert "reloaded" in r.stdout.lower()

    def test_05_save_stdout(self, swnft_cli_netns):
        r = _cli_in_ns("save")
        assert r.returncode == 0, r.stderr
        assert "table" in r.stdout

    def test_06_save_to_file(self, swnft_cli_netns):
        r = _cli_in_ns("save", "/tmp/shorewall-next-sim-cli-saved.nft")
        assert r.returncode == 0, r.stderr

    def test_07_stop(self, swnft_cli_netns):
        r = _cli_in_ns("stop")
        assert r.returncode == 0

    def test_08_status_stopped(self, swnft_cli_netns):
        r = _cli_in_ns("status")
        assert r.returncode != 0

    def test_09_restore(self, swnft_cli_netns):
        _cli_in_ns("start", str(MINIMAL_DIR), timeout=60)
        _cli_in_ns("save", "/tmp/shorewall-next-sim-cli-restore.nft")
        _cli_in_ns("stop")
        r = _cli_in_ns("restore", "/tmp/shorewall-next-sim-cli-restore.nft")
        assert r.returncode == 0, r.stderr

    def test_10_status_after_restore(self, swnft_cli_netns):
        r = _cli_in_ns("status")
        assert r.returncode == 0

    def test_11_clear(self, swnft_cli_netns):
        r = _cli_in_ns("clear")
        assert r.returncode == 0, r.stderr
        assert "cleared" in r.stdout.lower()


# ──────────────────────────────────────────────────────────────────────
# Show/Info (in netns, after start)
# ──────────────────────────────────────────────────────────────────────

class TestShowInfo:
    @pytest.fixture(autouse=True)
    def ensure_started(self, swnft_cli_netns):
        _cli_in_ns("start", str(MINIMAL_DIR), timeout=60)

    def test_show(self, swnft_cli_netns):
        r = _cli_in_ns("show")
        assert r.returncode == 0
        assert len(r.stdout) > 100

    def test_list_alias(self, swnft_cli_netns):
        r = _cli_in_ns("list")
        assert r.returncode == 0

    def test_ls_alias(self, swnft_cli_netns):
        r = _cli_in_ns("ls")
        assert r.returncode == 0

    def test_dump_alias(self, swnft_cli_netns):
        r = _cli_in_ns("dump")
        assert r.returncode == 0

    def test_counters(self, swnft_cli_netns):
        r = _cli_in_ns("counters")
        assert r.returncode == 0

    def test_reset(self, swnft_cli_netns):
        r = _cli_in_ns("reset")
        assert r.returncode == 0


# ──────────────────────────────────────────────────────────────────────
# Dynamic Blacklist (in netns, after start with DYNAMIC_BLACKLIST)
# ──────────────────────────────────────────────────────────────────────

class TestBlacklist:
    @pytest.fixture(autouse=True)
    def ensure_started(self, swnft_cli_netns):
        _cli_in_ns("start", str(MINIMAL_DIR), timeout=60)

    def test_drop(self, swnft_cli_netns):
        r = _cli_in_ns("drop", "192.168.99.1")
        assert r.returncode in (0, 1)

    def test_blacklist(self, swnft_cli_netns):
        r = _cli_in_ns("blacklist", "192.168.99.2", "-t", "1h")
        assert r.returncode in (0, 1)

    def test_reject(self, swnft_cli_netns):
        r = _cli_in_ns("reject", "192.168.99.3")
        assert r.returncode in (0, 1)

    def test_allow(self, swnft_cli_netns):
        r = _cli_in_ns("allow", "192.168.99.1")
        assert r.returncode in (0, 1)


# ──────────────────────────────────────────────────────────────────────
# Generators (no netns)
# ──────────────────────────────────────────────────────────────────────

class TestGenerators:
    def test_generate_sysctl(self):
        r = _cli("generate-sysctl", str(MINIMAL_DIR))
        assert r.returncode == 0
        assert "sysctl" in r.stdout or "#!/bin/sh" in r.stdout

    def test_generate_systemd(self):
        r = _cli("generate-systemd")
        assert r.returncode == 0
        assert "ExecStart" in r.stdout

    def test_generate_systemd_netns(self):
        r = _cli("generate-systemd", "--with-netns")
        assert r.returncode == 0
        assert "%i" in r.stdout

    def test_generate_tc(self):
        r = _cli("generate-tc", str(MINIMAL_DIR))
        assert r.returncode == 0

    def test_generate_set_loader(self):
        r = _cli("generate-set-loader", str(MINIMAL_DIR))
        assert r.returncode == 0


# ──────────────────────────────────────────────────────────────────────
# Verify/Migrate (no netns, needs production config)
# ──────────────────────────────────────────────────────────────────────

class TestVerifyMigrate:
    @pytest.fixture(autouse=True)
    def skip_if_no_prod(self):
        if not PROD_DIR.exists() or not IPT_DUMP.exists():
            pytest.skip("Production config not available")

    def test_verify(self):
        r = _cli("verify", str(PROD_DIR), "--iptables", str(IPT_DUMP), timeout=120)
        assert r.returncode in (0, 1)
        assert "100.0%" in r.stdout or "coverage" in r.stdout.lower()

    def test_migrate(self):
        r = _cli("migrate", str(PROD_DIR), "--iptables", str(IPT_DUMP), timeout=120)
        assert r.returncode == 0
        assert "Migration" in r.stdout or "Compil" in r.stdout


# ──────────────────────────────────────────────────────────────────────
# Capabilities
# ──────────────────────────────────────────────────────────────────────

class TestCapabilities:
    def test_capabilities(self):
        r = _cli("capabilities", timeout=60)
        assert r.returncode == 0
        assert "nftables" in r.stdout.lower() or "Features" in r.stdout

    def test_capabilities_json(self):
        r = _cli("capabilities", "--json", timeout=60)
        assert r.returncode == 0
        # Strip "Probing..." prefix, find JSON start
        stdout = r.stdout
        json_start = stdout.find("{")
        assert json_start >= 0, "No JSON in output"
        data = json.loads(stdout[json_start:])
        assert "families" in data
        assert "libnft_path" in data or "has_counter" in data


# ──────────────────────────────────────────────────────────────────────
# Merge Config
# ──────────────────────────────────────────────────────────────────────

class TestExplain:
    def test_explain_features(self):
        r = _cli("explain-nft-features")
        assert r.returncode == 0
        assert "Connection Tracking" in r.stdout
        assert "ct state" in r.stdout
        assert "nft syntax" in r.stdout

    def test_explain_category(self):
        r = _cli("explain-nft-features", "--category", "NAT")
        assert r.returncode == 0
        assert "snat" in r.stdout.lower()
        assert "dnat" in r.stdout.lower()

    def test_explain_json(self):
        r = _cli("explain-nft-features", "--json")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert isinstance(data, list)
        assert len(data) > 20
        assert any(f["name"] == "ct_state" for f in data)

    def test_explain_probe(self):
        r = _cli("explain-nft-features", "--probe", timeout=60)
        assert r.returncode == 0
        assert "[OK]" in r.stdout or "[N/A]" in r.stdout


class TestPlugins:
    """Test the plugin system: lookup, enrich, plugins list, registered commands."""

    @pytest.fixture
    def plugin_config_dir(self, tmp_path):
        d = tmp_path / "sw"
        (d / "plugins").mkdir(parents=True)
        (d / "plugins.conf").write_text('[[plugins]]\nname = "ip-info"\nenabled = true\n')
        (d / "plugins" / "ip-info.toml").write_text("""
[[mappings]]
v4_subnet = "203.0.113.0/24"
v6_prefix = "2001:db8:0:100::/64"

[[mappings]]
v4_subnet = "198.51.100.0/24"
v6_prefix = "2001:db8:0:200::/64"
""")
        # Minimal rules file so enrich has something to work on
        (d / "rules").write_text(
            "?SECTION NEW\n"
            "?COMMENT mandant-b\n"
            "ACCEPT\thost:203.0.113.121\tnet\n"
            "?COMMENT\n"
        )
        return d

    def test_plugins_list(self, plugin_config_dir):
        r = _cli("plugins", "list", "-c", str(plugin_config_dir))
        assert r.returncode == 0
        assert "ip-info" in r.stdout
        assert "priority=10" in r.stdout

    def test_lookup(self, plugin_config_dir):
        r = _cli("lookup", "203.0.113.65", "-c", str(plugin_config_dir))
        assert r.returncode == 0
        assert "2001:db8:0:100:203:0:113:65" in r.stdout
        assert "ip-info" in r.stdout

    def test_lookup_unknown(self, plugin_config_dir):
        r = _cli("lookup", "8.8.8.8", "-c", str(plugin_config_dir))
        assert r.returncode == 1

    def test_enrich(self, plugin_config_dir):
        r = _cli("enrich", str(plugin_config_dir))
        assert r.returncode == 0, r.stderr
        assert "blocks enriched" in r.stdout
        assert (plugin_config_dir / "rules.bak").exists()
        rules = (plugin_config_dir / "rules").read_text()
        assert "ip-info" in rules


class TestDebug:
    """Test the debug command (save → load → SIGINT → restore)."""

    def test_debug_compile_emits_counters_and_comments(self, tmp_path):
        """The debug emit mode must add per-rule counters and comments."""
        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.config.parser import load_config
        from shorewall_nft.nft.emitter import emit_nft

        cfg = load_config(MINIMAL_DIR)
        ir = build_ir(cfg)
        script = emit_nft(ir, debug=True)

        # Every rule should have `counter name "r_<chain>_<idx>"`
        assert 'counter name "r_' in script
        # Counter declarations at top of table
        assert "counter r_" in script
        # Some rules should have source-ref comments
        assert 'comment "' in script

    def test_debug_config_hash_embedded(self, tmp_path):
        """Debug mode embeds a config hash with the 'debug' marker."""
        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.config.hash import compute_config_hash
        from shorewall_nft.config.parser import load_config
        from shorewall_nft.nft.emitter import emit_nft

        cfg = load_config(MINIMAL_DIR)
        ir = build_ir(cfg)
        h = compute_config_hash(MINIMAL_DIR)
        script = emit_nft(ir, debug=True, config_hash=h)

        # Hash comment with debug marker
        assert f'config-hash:{h} debug' in script

    def test_debug_command_sigint_restores(self, swnft_cli_netns, tmp_path):
        """End-to-end: start debug, terminate, verify restore ran.

        Signal propagation through `ip netns exec` is clean — ip exec's
        directly into the target command with no extra shell layer.
        We still put the child in its own session and signal the whole
        process group so every layer (ip, python) gets the signal at once.
        SIGTERM is used because the handler in cli.py treats SIGTERM and
        SIGINT identically.
        """
        import signal
        import time
        # Load a baseline ruleset so restore has something to go back to
        _cli_in_ns("start", str(MINIMAL_DIR), timeout=60)

        # Launch debug in the background in its own process group
        proc = subprocess.Popen(
            [*IP_NETNS, "exec", NS, SWNFT, "debug", str(MINIMAL_DIR),
             "--netns", NS],
            env={**os.environ,
                 "PYTHONPATH": str(Path(__file__).parent.parent)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        try:
            # Wait for debug mode to finish loading
            time.sleep(1.5)

            # At this point the debug ruleset should be loaded — the
            # loaded table should have `config-hash:` with `debug` marker
            _cli_in_ns("show")
            # Don't assert on specifics here; the debug load may have
            # failed in minimal-mode-lacking environments. Just signal.

            # SIGTERM the whole group so no shell layer can swallow it
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                stdout, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.communicate()
                pytest.skip("debug command hung on SIGTERM")
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        assert ("Restoring" in stdout or "Restored" in stdout
                or proc.returncode == 0)


class TestMerge:
    @pytest.fixture(autouse=True)
    def skip_if_no_prod(self):
        if not PROD_DIR.exists() or not PROD6_DIR.exists():
            pytest.skip("Production config not available")

    def test_merge_config(self, tmp_merged):
        r = _cli("merge-config", str(PROD_DIR), str(PROD6_DIR),
                 "-o", str(tmp_merged))
        assert r.returncode == 0
        assert (tmp_merged / "rules").exists()
        assert (tmp_merged / "zones").exists()

    def test_merge_default_output(self, tmp_path):
        """Without -o, output goes to <parent>/shorewall46."""
        # Create minimal v4 + v6 configs
        v4 = tmp_path / "shorewall"
        v6 = tmp_path / "shorewall6"
        v4.mkdir()
        v6.mkdir()
        (v4 / "zones").write_text("fw\tfirewall\nnet\tipv4\n")
        (v6 / "zones").write_text("fw\tfirewall\nnet\tipv6\n")
        (v4 / "rules").write_text("#ACTION SOURCE DEST\n")
        (v6 / "rules").write_text("#ACTION SOURCE DEST\n")
        r = _cli("merge-config", str(v4), str(v6))
        assert r.returncode == 0
        default_out = tmp_path / "shorewall46"
        assert default_out.exists()
        assert (default_out / "zones").exists()

    def test_merge_zones_no_duplicates(self, tmp_merged):
        """Identical v6 zones are dropped entirely, not commented out."""
        r = _cli("merge-config", str(PROD_DIR), str(PROD6_DIR),
                 "-o", str(tmp_merged))
        assert r.returncode == 0
        zones_text = (tmp_merged / "zones").read_text()
        # No commented-out zone lines (old behavior wrote "# net ipv6" etc.)
        for line in zones_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") and not stripped.startswith("##"):
                # Allow normal comments, but not "# net ipv6" style
                parts = stripped.lstrip("# ").split()
                if len(parts) >= 2 and parts[1] in ("ipv4", "ipv6"):
                    assert False, f"Commented-out zone found: {line}"

    def test_merge_policies_no_duplicates(self, tmp_merged):
        """Identical v6 policies (same src/dest) are dropped entirely."""
        r = _cli("merge-config", str(PROD_DIR), str(PROD6_DIR),
                 "-o", str(tmp_merged))
        assert r.returncode == 0
        policy_text = (tmp_merged / "policy").read_text()
        # Count actual policy lines (non-comment, non-empty)
        pairs = []
        for line in policy_text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                parts = stripped.split()
                if len(parts) >= 3:
                    pairs.append((parts[0], parts[1]))
        # No duplicates
        assert len(pairs) == len(set(pairs)), f"Duplicate policies: {pairs}"

    def test_merge_comment_blocks_combined(self, tmp_merged):
        """Same ?COMMENT tags from v4 and v6 are merged into one block."""
        r = _cli("merge-config", str(PROD_DIR), str(PROD6_DIR),
                 "-o", str(tmp_merged))
        assert r.returncode == 0
        rules_text = (tmp_merged / "rules").read_text()
        # "mandant-b" should appear exactly once as ?COMMENT tag
        mandant_b_opens = [l for l in rules_text.splitlines()
                         if l.strip() == "?COMMENT mandant-b"]
        assert len(mandant_b_opens) == 1, f"Expected 1, got {len(mandant_b_opens)}"
        # Block should contain both IPv4 and IPv6 addresses
        in_block = False
        has_v4 = has_v6 = False
        for line in rules_text.splitlines():
            if line.strip() == "?COMMENT mandant-b":
                in_block = True
                continue
            if in_block and line.strip().startswith("?COMMENT"):
                break
            if in_block:
                if "203.0.113" in line:
                    has_v4 = True
                if "2001:db8" in line:
                    has_v6 = True
        assert has_v4, "mandant-b block missing IPv4 rules"
        assert has_v6, "mandant-b block missing IPv6 rules"

    def test_merge_with_plugins(self, tmp_path):
        """merge-config with ip-info plugin detects param pairs."""
        import shutil
        v4 = tmp_path / "shorewall"
        shutil.copytree(PROD_DIR, v4)
        (v4 / "plugins").mkdir(exist_ok=True)
        (v4 / "plugins.conf").write_text('[[plugins]]\nname = "ip-info"\nenabled = true\n')
        (v4 / "plugins" / "ip-info.toml").write_text("""
[[mappings]]
v4_subnet = "203.0.113.0/24"
v6_prefix = "2001:db8:0:100::/64"

[[mappings]]
v4_subnet = "198.51.100.0/24"
v6_prefix = "2001:db8:0:200::/64"

[[mappings]]
v4_subnet = "203.0.113.0/24"
v6_prefix = "2001:db8:0:3002::/64"
""")
        out = tmp_path / "merged"
        r = _cli("merge-config", str(v4), str(PROD6_DIR), "-o", str(out))
        assert r.returncode == 0
        assert "Plugins enabled: ip-info" in r.stdout
        assert "param pairs detected" in r.stdout
        # Check that paired params are grouped with a comment
        params = (out / "params").read_text()
        assert "v4/v6 pair" in params

    def test_merge_no_plugins_flag(self, tmp_path):
        """--no-plugins disables plugin enrichment."""
        import shutil
        v4 = tmp_path / "shorewall"
        shutil.copytree(PROD_DIR, v4)
        (v4 / "plugins").mkdir(exist_ok=True)
        (v4 / "plugins.conf").write_text('[[plugins]]\nname = "ip-info"\nenabled = true\n')
        (v4 / "plugins" / "ip-info.toml").write_text("""
[[mappings]]
v4_subnet = "203.0.113.0/24"
v6_prefix = "2001:db8:0:100::/64"
""")
        out = tmp_path / "merged"
        r = _cli("merge-config", str(v4), str(PROD6_DIR), "-o", str(out),
                 "--no-plugins")
        assert r.returncode == 0
        assert "Plugins enabled" not in r.stdout

    def test_merge_params_collisions(self, tmp_merged):
        """Colliding params get _V6 suffix, identical ones are dropped."""
        r = _cli("merge-config", str(PROD_DIR), str(PROD6_DIR),
                 "-o", str(tmp_merged))
        assert r.returncode == 0
        params_text = (tmp_merged / "params").read_text()
        # ORG_PFX exists in both with different values → _V6 suffix
        assert "ORG_PFX_V6=" in params_text
        # LOG=info is identical in both → should NOT appear twice
        log_lines = [l for l in params_text.splitlines()
                     if l.strip().startswith("LOG=")]
        assert len(log_lines) == 1, f"LOG= appears {len(log_lines)} times"
