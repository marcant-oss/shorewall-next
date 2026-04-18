# tools/ — operator and test scripts

| File | Purpose |
|------|---------|
| [`run-tests.sh`](run-tests.sh) | Run pytest in an isolated private namespace |
| [`setup-remote-test-host.sh`](setup-remote-test-host.sh) | Bootstrap a remote test host over SSH |
| [`release.sh`](release.sh) | Bump version, update changelogs, commit, tag |
| [`gen-rpm-spec.sh`](gen-rpm-spec.sh) | Generate the RPM spec from `.spec.in` |

## Running tests

Tests must run as **root** on a dedicated host (not on a production firewall).
No extra tooling needs to be installed — `run-tests.sh` handles isolation.

```bash
# Bootstrap a remote host once:
tools/setup-remote-test-host.sh root@<host>

# Run the full test suite via systemd-run (survives SSH disconnect):
ssh root@<host> systemd-run --unit=shorewall-pytest --collect \
  --property=StandardOutput=file:/tmp/pytest.log \
  --property=StandardError=file:/tmp/pytest.log \
  /root/shorewall-nft/tools/run-tests.sh \
    packages/shorewall-nft/tests/ \
    packages/shorewalld/tests/ \
    packages/shorewall-nft-simlab/tests/ -v

# Follow progress:
ssh root@<host> 'systemctl is-active shorewall-pytest; tail -f /tmp/pytest.log'
```

### How `run-tests.sh` isolates tests

On first invocation it re-execs itself via `unshare --mount --net`, creating:

- **Private network namespace** — nft rules and sysctl changes cannot escape.
- **Private mount namespace** — `ip netns add/delete` bind-mounts go to a
  private `tmpfs` overlay on `/run/netns`, invisible to the host.
- **Loopback up** — `ip link set lo up` so UDP-based tests work.

This means tests cannot crash the test host's networking, even if a test
loads a broken nftables ruleset or kills a namespace badly.

No sudoers rules, no helper binary, no group membership needed.

## Releasing

```bash
tools/release.sh [--dry-run] [--push] vX.Y.Z "Short summary"
```

Updates version in all `pyproject.toml` files, `__init__.py`,
`CHANGELOG.md`, and `packaging/debian/changelog`, then creates a release
commit and an annotated tag.  With `--push` it also pushes the branch and
tag to trigger CI (builds wheels + .deb + .rpm → GitHub Release).
