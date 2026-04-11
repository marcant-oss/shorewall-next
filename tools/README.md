# tools/ — in-project test tooling

This directory contains the scripts and config snippets needed to
run the shorewall-nft test suite (and debug firewall rules) on any
development or CI machine. Everything here is self-contained — no
external downloads, no vendor-specific scripts.

## Files

| File | Type | Installs to |
|------|------|-------------|
| [`run-netns`](run-netns) | POSIX shell script | `/usr/local/bin/run-netns` |
| [`sudoers.d-shorewall-nft`](sudoers.d-shorewall-nft) | sudoers snippet | `/etc/sudoers.d/shorewall-nft-tests` |
| [`install-test-tooling.sh`](install-test-tooling.sh) | POSIX shell installer | (not installed, run from checkout) |

## Quick install

```bash
sudo tools/install-test-tooling.sh
```

What it does:

1. Installs `run-netns` to `/usr/local/bin/run-netns` (root:root 0755)
2. Creates system group `netns-test` if missing
3. Installs the sudoers snippet (validated via `visudo -c`)
4. Adds `$SUDO_USER` to the `netns-test` group
5. Runs a smoke test: `run-netns list` as root

Log out and back in so the group membership takes effect. Verify:

```bash
groups | grep netns-test
sudo /usr/local/bin/run-netns list
```

Both should succeed without a password prompt.

## What `run-netns` does

One line:

```sh
exec /sbin/ip netns "$@"
```

It forwards every argument to `ip netns` and is the single entry
point for all network-namespace operations in the test suite and
the debug/simulate/trace commands. The wrapper exists so operators
can grant `NOPASSWD` sudo access on exactly one auditable tool
instead of all of `ip`.

Usage pattern:

```bash
sudo /usr/local/bin/run-netns add my-test-ns
sudo /usr/local/bin/run-netns exec my-test-ns ip link set lo up
sudo /usr/local/bin/run-netns exec my-test-ns nft list ruleset
sudo /usr/local/bin/run-netns delete my-test-ns
```

## Security

The `netns-test` group grants root-level namespace creation. **Only
install this on development and CI machines.** It is not for
production firewall hosts — an unprivileged user in that group can
create network namespaces, bind-mount filesystems, and create
interfaces with arbitrary addresses. That's a local privilege
surface.

The sudoers file hardcodes the wrapper by absolute path, so a
user cannot substitute a different script with the same name.

## Uninstall

```bash
sudo tools/install-test-tooling.sh --uninstall
```

Removes the wrapper and sudoers file. The `netns-test` group and
its members are **not** touched — remove them manually if desired:

```bash
sudo gpasswd -d <user> netns-test
sudo groupdel netns-test
```

## Distro packaging

Distro packages should ship the wrapper and sudoers snippet via
their own post-install scripts (Debian: `postinst`, RPM: `%post`)
rather than running `install-test-tooling.sh` at package time.
The installer is for checkout-based use by developers.

See [`docs/reference/dependencies.md`](../docs/reference/dependencies.md)
for the full package dependency catalog.

## Agent-friendly usage

For scripted (LLM agent) setup, the installer honors flags for
non-interactive runs:

```bash
# Install for a specific user without asking
sudo tools/install-test-tooling.sh --user alice

# Install without adding anyone to the group
sudo tools/install-test-tooling.sh --no-user

# Uninstall
sudo tools/install-test-tooling.sh --uninstall

# Help
tools/install-test-tooling.sh --help
```

Exit codes:

- `0` — success
- `1` — any error (missing `ip`, validation failure, etc.)

The installer is idempotent — safe to re-run from automation.
