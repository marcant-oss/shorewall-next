---
title: Test tooling setup
description: Install the shorewall-nft test tooling, distro package reference, troubleshooting.
---

# Test tooling setup

## One-shot install

From a freshly cloned checkout:

```bash
sudo tools/install-test-tooling.sh
```

The installer is idempotent and does all of the following:

1. Installs [`tools/run-netns`](../../tools/run-netns) to
   `/usr/local/bin/run-netns` (root:root, 0755)
2. Creates a system group `netns-test` if it does not exist
3. Installs [`tools/sudoers.d-shorewall-nft`](../../tools/sudoers.d-shorewall-nft)
   to `/etc/sudoers.d/shorewall-nft-tests` (validated via `visudo -c`)
4. Adds the invoking user (`$SUDO_USER`) to the `netns-test` group
5. Runs a smoke test: `run-netns list` as root

Log out and back in for the group membership to take effect.

Verify:

```bash
groups | grep netns-test
sudo /usr/local/bin/run-netns list
```

Both should succeed without prompting for a password.

### Options

```bash
# Install but add a different user
sudo tools/install-test-tooling.sh --user alice

# Install without adding anyone to the group
sudo tools/install-test-tooling.sh --no-user

# Uninstall (removes wrapper + sudoers file; keeps the group intact)
sudo tools/install-test-tooling.sh --uninstall

# Show help
tools/install-test-tooling.sh --help
```

## Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,simulate]"
```

Dependencies pulled in:

- `click` ≥ 8.0 — CLI framework
- `pyroute2` ≥ 0.9 — libnl bindings for nft state reading
- `pytest` ≥ 8.0 — test runner (dev extra)
- `pytest-cov` — coverage (dev extra)
- `scapy` ≥ 2.5 — packet crafting for `simulate` and `connstate` (simulate extra)

Python 3.11+ is required (uses stdlib `tomllib`).

## System packages

Runtime dependencies for testing, by distro:

=== "Debian / Ubuntu"

    ```bash
    sudo apt install python3 python3-venv python3-pip \
                     nftables iproute2 sudo \
                     python3-nftables  # optional, for libnftables bindings
    ```

=== "Fedora / RHEL"

    ```bash
    sudo dnf install python3 python3-pip \
                     nftables iproute sudo \
                     python3-nftables  # optional
    ```

=== "Arch Linux"

    ```bash
    sudo pacman -S python python-pip \
                   nftables iproute2 sudo
    ```

=== "Alpine"

    ```bash
    sudo apk add python3 py3-pip nftables iproute2 sudo
    ```

**`python3-nftables` is required** — without it, all namespace-entering
operations (`--netns`, capability probing, start/stop/status inside a netns)
fall back to spawning `sudo run-netns exec` subprocesses instead of using
in-process `setns()` + libnftables. On production root systems, install it:

=== "Debian / Ubuntu"

    ```bash
    sudo apt install python3-nftables
    ```

=== "Fedora / RHEL"

    ```bash
    sudo dnf install python3-nftables
    ```

Verify after install:

```bash
python3 -c "import nftables; n = nftables.Nftables(); print('libnft OK')"
```

Other optional tools:

| Package | Purpose | Used by |
|---------|---------|---------|
| `tcpdump` | capture packets in netns for debugging | ad-hoc |
| `ipset` | userspace ipset tool | `load-sets` command |
| `pandoc` | DocBook → Markdown conversion | docs build only |
| `mkdocs-material` | HTML documentation site | docs preview only |

## Kernel requirements

- Kernel ≥ 5.8 for the full nftables feature set used by shorewall-nft
  (`nft_connlimit`, `nft_objref`, `nft_numgen`, flowtables, etc.)
- `CONFIG_NET_NS=y` for network namespaces (standard in all modern distros)
- Kernel modules `nf_tables`, `nf_tables_inet`, `nft_counter`,
  `nft_ct`, `nft_limit`, `nft_log`, `nft_nat`, `nft_reject_inet`,
  `nft_set_hash`, `nft_set_rbtree` (usually auto-loaded by `nft`)

Check kernel capabilities:

```bash
shorewall-nft capabilities
```

This probes the running kernel and reports which features are
available. Any missing feature that your config uses will be
flagged at compile time with a helpful error pointing to the source
line.

## Distro package summary (for future packaging)

When we eventually ship `.deb` / `.rpm` / `pacman` packages, these
are the dependencies each package type will declare:

**Required runtime:**

- `python3` (≥ 3.11)
- `python3-click` (≥ 8.0)
- `python3-pyroute2` (≥ 0.9)
- `nftables`
- `iproute2`

**Recommended runtime:**

- `python3-nftables` (libnftables bindings)
- `ipset` (for legacy ipset loading)

**Test / dev extras:**

- `python3-pytest` (≥ 8.0)
- `python3-pytest-cov`
- `python3-scapy` (for `simulate`, `connstate` tests)
- `sudo` (for `run-netns`)

**Doc extras:**

- `python3-mkdocs-material`
- `pandoc`

The installer `tools/install-test-tooling.sh` is **not** intended to
run from a distro package — distro packages should provide the
`run-netns` wrapper + sudoers snippet via their own `postinst` /
`%post` scriptlets, honoring `/etc/group` conventions.

## Troubleshooting

### `sudo: a password is required`

You're not in the `netns-test` group yet (group changes apply on
login). Log out and back in, or `newgrp netns-test` in the current
shell.

### `ip: Peer netns reference is invalid`

Something left a stale netns behind. Clean up:

```bash
sudo /usr/local/bin/run-netns list
sudo /usr/local/bin/run-netns delete <stale-name>
```

Project-owned namespaces are prefixed `shorewall-next-sim-*` — you
can safely delete any of those between test runs.

### `nft: Could not process rule: Operation not supported`

Your kernel is missing a feature. Run `shorewall-nft capabilities`
to see the full list. Upgrading to a recent mainline kernel
(5.15+ for LTS) resolves this on all known-good distros.

### Tests hang at `signal.pause()`

The `debug` command is supposed to wait for Ctrl+C. If a test invokes
it and deadlocks, the test is missing a `SIGINT` send. See
`TestDebug` in `tests/test_cli_integration.py` for the pattern.

### Integration tests skipped: `no /etc/shorewall`

Production-config tests skip when `/etc/shorewall` isn't present.
Either install a test config there, or run only the tests that don't
require it:

```bash
pytest tests/ -v -k "not TestMerge and not TestVerifyMigrate"
```

## See also

- [Testing index](index.md) — overview and bugfix workflow
- [Test suite](test-suite.md) — pytest layout and fixtures
- [Debugging firewall rules](debugging.md) — live packet tracing
