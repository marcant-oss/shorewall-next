# CI fix proposals — 2026-04-20

Failing run: https://github.com/marcant-oss/shorewall-next/actions/runs/24685058414
Branch: `main`, triggered 2026-04-20T19:05:19Z.

Two independent root causes, four failing jobs total.

---

## Fix 1 — Unit tests: `.venv/bin/python` hardcoded in test helper

### Affected jobs

- `Unit tests (Python 3.11)` — job 72192107591
- `Unit tests (Python 3.12)` — job 72192107537
- `Unit tests (Python 3.13)` — job 72192107576

### Failing step

`Run unit tests — stagelab`

### Error excerpt

```
FileNotFoundError: [Errno 2] No such file or directory:
  '/home/runner/work/shorewall-next/shorewall-next/.venv/bin/python'
...
FAILED packages/shorewall-nft-stagelab/tests/unit/test_run_security_test_plan.py::test_role_resolution_replaces_source
FAILED packages/shorewall-nft-stagelab/tests/unit/test_run_security_test_plan.py::test_unresolvable_role_skips_scenario
======================== 2 failed, 486 passed in 6.49s =========================
```

### Root cause

`_run_merge_block()` in
`packages/shorewall-nft-stagelab/tests/unit/test_run_security_test_plan.py`
(line 407) constructs the Python interpreter path as:

```python
python = str(_repo_root() / ".venv" / "bin" / "python")
```

CI uses `actions/setup-python` and installs packages directly into the
runner's system Python — no `.venv/` is ever created at the repo root. The
path does not exist, so `subprocess.run` raises `FileNotFoundError`.

### Fix

Replace the hardcoded `.venv/bin/python` with `sys.executable`, which always
refers to the Python that is currently running the test suite — correct both
in CI (system Python) and locally (venv Python).

**File:** `packages/shorewall-nft-stagelab/tests/unit/test_run_security_test_plan.py`

```diff
-from pathlib import Path
+import sys
+from pathlib import Path
 
 [...]
 
 def _run_merge_block(tmp_path: Path, base_cfg: Path, fragment: Path) -> tuple[int, str, str, Path]:
     """Run the Python inline merge block from run-security-test-plan.sh."""
     import subprocess
     from pathlib import Path as _Path
 
-    python = str(_repo_root() / ".venv" / "bin" / "python")
+    python = sys.executable
     sh_text = _Path(_script()).read_text()
```

No other changes needed in the file or in `build.yaml`.

---

## Fix 2 — Lint: shellcheck SC2034 warnings treated as errors in `setup-remote-test-host.sh`

### Affected job

- `Lint` — job 72192107603

### Failing step

`Run shellcheck on tools/`

### Error excerpt

```
In tools/setup-remote-test-host.sh line 64:
TREX_CDN_BASE="https://trex-tgn.cisco.com/trex/release"
^-----------^ SC2034 (warning): TREX_CDN_BASE appears unused.

In tools/setup-remote-test-host.sh line 65:
TREX_CA_PEM="$SCRIPT_DIR/trex-ca.pem"
^---------^ SC2034 (warning): TREX_CA_PEM appears unused.

In tools/setup-remote-test-host.sh line 113:
REQUIRED_BINS_DEFAULT="python3 ip ss nft conntrack ipset sudo rsync"
^-------------------^ SC2034 (warning): REQUIRED_BINS_DEFAULT appears unused.

In tools/setup-remote-test-host.sh line 115:
REQUIRED_BINS_STAGELAB="iperf3 nmap ethtool tcpdump jq"
^--------------------^ SC2034 (warning): REQUIRED_BINS_STAGELAB appears unused.

In tools/setup-remote-test-host.sh line 117:
REQUIRED_BINS_DPDK="python3-pyelftools"
^----------------^ SC2034 (warning): REQUIRED_BINS_DPDK appears unused.
```

Shellcheck 0.9.0 exits non-zero even on warnings when they include SC2034.
The CI step has no `|| true`, so the workflow fails.

### Root cause — two sub-cases

**Sub-case A (false positive):** `TREX_CDN_BASE` and `TREX_CA_PEM` are
consumed in `tools/lib/trex-install.sh`, which is sourced via `. "$SCRIPT_DIR/lib/trex-install.sh"`. Shellcheck does not follow sourced files
unless invoked with `-x` and the file is specified as an input. Because CI
runs plain `shellcheck`, it cannot see the usage and fires SC2034.

**Sub-case B (genuine dead code):** `REQUIRED_BINS_DEFAULT`,
`REQUIRED_BINS_STAGELAB`, and `REQUIRED_BINS_DPDK` are defined as
documentation/convenience constants at lines 113–117 but are never actually
referenced — `verify_binaries` is called at lines 227, 274, 292, and 305
with the binary names spelled out inline. These are genuinely unused.

### Fix — two independent options (can apply both)

**Option A — suppress the false-positive SC2034s with `# shellcheck disable` directives:**

The most targeted fix for `TREX_CDN_BASE` / `TREX_CA_PEM`: add an inline
disable comment on each assignment line in
`tools/setup-remote-test-host.sh`:

```diff
-TREX_CDN_BASE="https://trex-tgn.cisco.com/trex/release"
-TREX_CA_PEM="$SCRIPT_DIR/trex-ca.pem"
+TREX_CDN_BASE="https://trex-tgn.cisco.com/trex/release"  # shellcheck disable=SC2034
+TREX_CA_PEM="$SCRIPT_DIR/trex-ca.pem"                    # shellcheck disable=SC2034
```

Alternative: add a `# shellcheck source=tools/lib/trex-install.sh` directive
before the `. "$SCRIPT_DIR/lib/trex-install.sh"` lines (already present at
line 94) and also pass `-x` to shellcheck in the CI step:

In `.github/workflows/build.yaml`, change the shellcheck invocation from:
```yaml
run: |
  shellcheck tools/run-tests.sh tools/gen-rpm-spec.sh tools/release.sh tools/setup-remote-test-host.sh
```
to:
```yaml
run: |
  shellcheck -x tools/run-tests.sh tools/gen-rpm-spec.sh tools/release.sh tools/setup-remote-test-host.sh
```

With `-x` shellcheck follows sourced files when they carry a
`# shellcheck source=` directive and will resolve `TREX_CDN_BASE` /
`TREX_CA_PEM` usage, eliminating those SC2034s.

**Option B — eliminate the genuinely unused `REQUIRED_BINS_*` variables:**

Replace the three dead constants with inline comments explaining what each
role requires (the information is already duplicated in the `verify_binaries`
call sites):

```diff
-# ── Required binary sets (for post-install verification) ──────────────────────
-# role=default
-REQUIRED_BINS_DEFAULT="python3 ip ss nft conntrack ipset sudo rsync"
-# role=stagelab-agent adds:
-REQUIRED_BINS_STAGELAB="iperf3 nmap ethtool tcpdump jq"
-# role=stagelab-agent-dpdk adds:
-REQUIRED_BINS_DPDK="python3-pyelftools"   # checked as package; dpdk-devbind.py checked separately
+# Required binaries per role (for reference — passed directly to verify_binaries below):
+#   default:              python3 ip ss nft conntrack ipset sudo rsync
+#   stagelab-agent adds:  iperf3 nmap ethtool tcpdump jq
+#   stagelab-agent-dpdk:  python3-pyelftools (RPM package check, not binary)
```

### Recommended combined fix

Apply Option B (remove dead variables) and Option A's `-x` flag (so future
sourced-variable usage does not need per-line suppression). Both changes are
in `tools/setup-remote-test-host.sh` and the shellcheck step in
`.github/workflows/build.yaml`.

---

## Summary table

| # | Job | Root cause | Fix file | Fix type |
|---|-----|-----------|----------|----------|
| 1 | Unit tests (3.11/3.12/3.13) | `.venv/bin/python` hardcoded; does not exist in CI | `tests/unit/test_run_security_test_plan.py:407` | Replace with `sys.executable` |
| 2a | Lint | `TREX_CDN_BASE`/`TREX_CA_PEM` false-positive SC2034 (used in sourced file) | `tools/setup-remote-test-host.sh:64-65` | Add `-x` to shellcheck CI step + existing `shellcheck source=` directives |
| 2b | Lint | `REQUIRED_BINS_DEFAULT/STAGELAB/DPDK` genuine dead variables, SC2034 | `tools/setup-remote-test-host.sh:113-117` | Remove/convert to comments |
