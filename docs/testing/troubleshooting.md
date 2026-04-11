---
title: Troubleshooting tests
description: Common failures and fixes when running the shorewall-nft test suite.
---

# Troubleshooting tests

Quick index of the most frequent test failures, diagnostics, and fixes.

## Setup failures

### `sudo: a password is required`

Your user is not in the `netns-test` group (or the group change
hasn't taken effect yet).

```bash
# Check current groups
groups | tr ' ' '\n' | grep netns-test

# If missing, add:
sudo usermod -aG netns-test $USER

# Then log out and back in (or open a new terminal with newgrp)
newgrp netns-test
```

### `install-test-tooling.sh: ip binary not found`

Your system is missing `iproute2`. Install it:

- Debian/Ubuntu: `sudo apt install iproute2`
- Fedora/RHEL: `sudo dnf install iproute`
- Arch: `sudo pacman -S iproute2`
- Alpine: `sudo apk add iproute2`

### `ModuleNotFoundError: No module named 'click'`

Python deps aren't installed in the active venv.

```bash
source .venv/bin/activate
pip install -e ".[dev]"
```

### `ModuleNotFoundError: No module named 'scapy'`

Optional scapy extra isn't installed — needed only for `simulate`
and `connstate` tests.

```bash
pip install -e ".[simulate]"
```

## Netns-related failures

### `RTNETLINK answers: File exists` when creating netns

A stale namespace with the same name is still around.

```bash
sudo /usr/local/bin/run-netns list | grep shorewall-next-sim
sudo /usr/local/bin/run-netns delete <stale-name>
```

### Tests pass locally but fail in CI

CI often runs without `/etc/shorewall` — the production-config tests
skip there. If tests **fail** rather than skip, check that the CI
base image has `nftables`, `iproute2`, and sudo configured.

### `nft: Could not process rule: Operation not supported`

Your kernel lacks an nft feature. Check with:

```bash
shorewall-nft capabilities
```

Any `[N/A]` entries are missing. Usually a kernel upgrade fixes it.
See [Setup > Kernel requirements](setup.md#kernel-requirements).

### Debug mode hangs / doesn't restore

`shorewall-nft debug` uses `signal.pause()` to idle. Pressing Ctrl+C
should trigger the SIGINT handler. If that fails (rare, usually due
to an earlier fatal error in the signal handler), restore manually:

```bash
# Saved original path was printed at debug start:
#   "Saved current ruleset to /tmp/shorewall-next-sim-debug-saved-XXXX.nft"

sudo /usr/local/bin/run-netns exec <ns> nft flush ruleset
sudo /usr/local/bin/run-netns exec <ns> \
    nft -f /tmp/shorewall-next-sim-debug-saved-XXXX.nft
```

## Compiler failures

### `ParseError: Not a directory: /etc/shorewall`

The default config dir doesn't exist on this machine. Pass an
explicit path:

```bash
shorewall-nft check /srv/test/shorewall
```

Or install a minimal test config:

```bash
cp -a tests/configs/minimal /etc/shorewall
```

### `Capability check failed: ct_count not available`

Your config uses `CONNLIMIT`, but the kernel module is not loaded
or the kernel is too old. Skip the capability check temporarily to
see compilation output:

```bash
shorewall-nft check /etc/shorewall --skip-caps
```

### `ERROR: unresolved variable $ORG_PFX`

A params file is missing or a variable isn't defined. Check
`<config>/params` and verify the variable is declared.

## Verification failures

### Triangle verifier reports < 100% coverage

List the missing rules:

```bash
shorewall-nft verify /etc/shorewall --iptables /tmp/dump.txt 2>&1 \
    | grep -A1 "missing="
```

Each missing rule is a compiler gap. File it as a bug and include
the minimal reproducer (zone pair + rule).

### Triangle verifier reports order conflicts

Rules are in the output but in a different order than the iptables
baseline. This can change first-match semantics. Investigate with:

```bash
shorewall-nft compile /etc/shorewall -o /tmp/new.nft
diff <(grep -A1 "conflicting-chain" /tmp/dump.txt) \
     <(grep -A1 "conflicting-chain" /tmp/new.nft)
```

Usually it's a cosmetic difference (e.g. sort by comma-separated
source addresses) — rare to be a real bug.

### Simulator: "Expected ACCEPT, got DROP"

See [Debugging](debugging.md) for the full workflow. Quick version:
the simulator saves the failing trace to
`/tmp/shorewall-next-sim-trace.log` — open that and follow the
verdict chain.

## Plugin failures

### `plugins: No plugins loaded`

`plugins.conf` is missing or empty. Copy from `examples/`:

```bash
cp examples/plugins.conf /etc/shorewall/
cp -r examples/plugins /etc/shorewall/
```

### `netbox plugin: API token not configured`

Set `token` or `token_file` in `/etc/shorewall/plugins/netbox.toml`.
See [Plugins doc](../shorewall-nft/plugins.md#netbox-priority-100--authoritative).

### Netbox: `urllib.error.HTTPError: 403 Forbidden`

Your API token is read-only — that's fine — but the Netbox instance
might reject GET on some endpoints. Test the token manually:

```bash
curl -H "Authorization: Token $TOKEN" https://netbox/api/status/
```

If that works but `netbox refresh` still fails, the plugin is hitting
a different endpoint. Check with a `--verbose` curl.

## Reporting a bug

When a test reproduces a bug, include in the bug report:

1. **shorewall-nft version**: `shorewall-nft --version`
2. **Python version**: `python3 --version`
3. **Kernel + distro**: `uname -r` and `/etc/os-release`
4. **The failing command** verbatim
5. **Full output** up to the failure
6. **A minimal config** that reproduces (strip everything you can)

Template:

```
### Bug report

**Version**: shorewall-nft 0.11.0
**Python**: 3.11.2
**Kernel**: 6.1.0-13-amd64
**Distro**: Debian 12

**Command**:
    shorewall-nft compile /tmp/repro

**Output**:
    Traceback (most recent call last):
    ...

**Minimal repro**:
    (contents of /tmp/repro/zones, rules, etc.)

**Expected**: successful compile
**Got**: ValueError in parser.py line 123
```

## See also

- [Setup](setup.md) — initial installation
- [Test suite](test-suite.md) — how tests are organized
- [Debugging](debugging.md) — runtime investigation
