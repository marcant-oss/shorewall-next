---
title: Test suite reference
description: pytest layout, test file catalog, fixtures, how to run.
---

# Test suite reference

All tests live under `tests/` at the project root. They are grouped
by concern rather than by which module they exercise — a single test
file may cover parser + compiler + emitter if the scenario needs
all three.

## Running

```bash
# All tests
pytest tests/ -v

# Fast unit tests only (skip integration / netns)
pytest tests/ -v --ignore=tests/test_cli_integration.py

# A single file
pytest tests/test_plugins.py -v

# A single test by name
pytest tests/test_optimize.py::TestCombineMatches::test_combine_adjacent_saddr -v

# With coverage
pytest tests/ --cov=shorewall_nft --cov-report=term-missing

# Parallel (if pytest-xdist is installed)
pytest tests/ -n auto
```

Exit codes: pytest returns 0 on success, 1 on test failure, 2 on
internal errors. Suitable for CI.

## Test file catalog

| File | Count | Scope |
|------|-------|-------|
| `test_parser.py` | 24 | Config file parser: columnar format, preprocessor, `?IF`, `?SECTION`, `?COMMENT`, `?FAMILY`, variable expansion |
| `test_compiler.py` | 16 | IR builder: zones, interfaces, rules, macros, actions, policies |
| `test_nat.py` | 15 | SNAT/DNAT/Masquerade/Netmap compilation |
| `test_emitter.py` | 18 | IR → nft script conversion: match syntax, port resolution, IPv6 angle brackets |
| `test_triangle.py` | 17 | Semantic comparison against iptables-save dumps (triangle verifier) |
| `test_plugins.py` | 27 | Plugin base class, manager, ip-info plugin, utils |
| `test_netbox_plugin.py` | 16 | Netbox plugin cache, snapshot mode, tenant parsing, enrichment |
| `test_optimize.py` | 30 | Optimizer levels 1-8 |
| `test_config_hash.py` | 12 | Config hash computation, drift markers |
| `test_config_resolution.py` | 6 | `/etc/shorewall46` precedence, parser auto-merge skipping |
| `test_cli_config_flags.py` | 15 | CLI override flags (all 6 modes + conflict cases) |
| `test_cli_integration.py` | 41 | End-to-end CLI tests (most require netns) |
| `test_config_gen.py` | 37 | Fuzz tests with random config generator |

**Total: 236 tests** (as of v0.11.0).

## Fixtures and helpers

### `tests/configs/minimal/`

A minimal working Shorewall config used by many tests. 2 zones
(`net`, `$FW`), 1 interface, a handful of ACCEPT/DROP rules.

### `tests/configs/nat/`

Minimal NAT config with SNAT + DNAT rules for testing the NAT
compiler path.

### `swnft_cli_netns` fixture (module-scoped)

Creates `shorewall-next-sim-cli` for the entire module, cleans up
after all tests in the module have run. Used by lifecycle tests.

```python
@pytest.fixture(scope="module")
def swnft_cli_netns():
    _run([*RUN_NETNS, "add", NS])
    yield NS
    _run([*RUN_NETNS, "exec", NS, "kill", "-9", "-1"], timeout=5)
    _run([*RUN_NETNS, "delete", NS])
```

### `tmp_path`

Standard pytest fixture — provides a pristine temporary directory
per test. Prefer this over `/tmp/foo` hardcoded paths.

### `PROD_DIR` and `PROD6_DIR` guards

Integration tests that need a full production config gate on
`PROD_DIR.exists()`. Without a `/etc/shorewall` / `/etc/shorewall6`
checkout, those tests skip gracefully:

```python
@pytest.fixture(autouse=True)
def skip_if_no_prod(self):
    if not PROD_DIR.exists() or not PROD6_DIR.exists():
        pytest.skip("Production config not available")
```

## Writing a new test

### Unit test (no netns)

```python
# tests/test_myfeature.py
from shorewall_nft.config.parser import load_config
from shorewall_nft.compiler.ir import build_ir

def test_my_rule_compiles(tmp_path):
    """My new rule type should produce the expected nft output."""
    (tmp_path / "zones").write_text("fw\tfirewall\nnet\tipv4\n")
    (tmp_path / "interfaces").write_text("net\teth0\t-\t-\n")
    (tmp_path / "policy").write_text("all\tall\tACCEPT\n")
    (tmp_path / "rules").write_text("MY_RULE(ACCEPT)\tnet\t$FW\n")
    (tmp_path / "params").write_text("")
    (tmp_path / "shorewall.conf").write_text("")

    cfg = load_config(tmp_path)
    ir = build_ir(cfg)
    assert any("my_match" in str(m) for chain in ir.chains.values()
               for rule in chain.rules for m in rule.matches)
```

### Integration test (netns required)

```python
# tests/test_cli_integration.py
class TestMyFeature:
    def test_my_command(self, swnft_cli_netns):
        """shorewall-nft myfeature command behaves correctly."""
        r = _cli_in_ns("myfeature", "--option", "value")
        assert r.returncode == 0
        assert "expected output" in r.stdout
```

### Plugin test with mocked API

```python
# tests/test_myplugin.py
from unittest.mock import patch

def test_plugin_lookup(tmp_path):
    from shorewall_nft.plugins.builtin.myplugin import MyPlugin
    p = MyPlugin({"opt": "val"}, tmp_path)
    with patch.object(p, "_fetch_on_demand",
                      return_value={"hostname": "x"}):
        assert p.lookup_ip("1.2.3.4")["hostname"] == "x"
```

## Pytest configuration

`pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
```

No special fixtures are auto-loaded beyond the built-in ones.

## Continuous integration

Run this on every commit:

```bash
pytest tests/ --ignore=tests/test_cli_integration.py \
              --ignore=tests/test_config_gen.py
```

This covers 180+ tests in under 10s without needing the netns
tooling. The two excluded files are CI-friendly too if the runner
has sudo + `run-netns` installed.

## Machine-readable index

A JSON inventory of all test files + counts is regenerated on
release as [`docs/reference/test-index.json`](../reference/test-index.json).
Use this for dashboards or agent-driven analysis.

## See also

- [Debugging firewall rules](debugging.md) — runtime trace workflow
- [Verification tools](verification.md) — triangle + simulator
- [Setup](setup.md) — if tests fail to run
