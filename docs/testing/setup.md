---
title: Test tooling setup
description: Install the shorewall-nft test tooling, distro package reference, troubleshooting.
---

# Test tooling setup

## Running tests

Tests run as **root** via `tools/run-tests.sh`. No helper binaries,
sudoers rules, or group membership needed.

```bash
# Bootstrap a remote host once:
tools/setup-remote-test-host.sh root@<host>

# Run the full suite via systemd-run (survives SSH disconnect):
ssh root@<host> systemd-run --unit=shorewall-pytest --collect \
  --property=StandardOutput=file:/tmp/pytest.log \
  --property=StandardError=file:/tmp/pytest.log \
  /root/shorewall-nft/tools/run-tests.sh \
    packages/shorewall-nft/tests/ \
    packages/shorewalld/tests/ \
    packages/shorewall-nft-simlab/tests/ -v

# Follow: systemctl is-active shorewall-pytest; tail -f /tmp/pytest.log
```

`tools/run-tests.sh` uses `unshare --mount --net` to create a private
network + mount namespace before pytest starts. nft rules, sysctl
changes, and `ip netns add` bind-mounts inside tests are invisible to
the host. Loopback (`lo`) is brought up automatically.

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
                     nftables iproute2 util-linux \
                     python3-nftables  # optional, for libnftables bindings
    ```

=== "Fedora / RHEL"

    ```bash
    sudo dnf install python3 python3-pip \
                     nftables iproute util-linux \
                     python3-nftables  # optional
    ```

=== "Arch Linux"

    ```bash
    sudo pacman -S python python-pip \
                   nftables iproute2 util-linux
    ```

=== "Alpine"

    ```bash
    sudo apk add python3 py3-pip nftables iproute2 util-linux
    ```

**`python3-nftables` is recommended** — without it, operations like
`shorewall-nft status --netns NS` use `ip netns exec` subprocesses
for libnftables calls. On production root systems, install it:

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
- `util-linux` (`unshare` for test namespace isolation)

**Doc extras:**

- `python3-mkdocs-material`
- `pandoc`

`tools/run-tests.sh` is the only test entry-point — it handles
namespace isolation automatically. No sudoers rules, helper binaries,
or group membership needed.

## Troubleshooting

### `ip: Peer netns reference is invalid`

Something left a stale netns behind. Clean up:

```bash
ip netns list
ip netns delete <stale-name>
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
