# CLAUDE.md — monorepo overview

`shorewall-nft` — nftables-native firewall compiler with a
Shorewall-compatible configuration surface.

## Repo layout

```
packages/
  shorewall-nft/          Core: compiler, emitter, config, runtime
  shorewalld/             Prometheus exporter + DNS-based dynamic sets
  shorewall-nft-simlab/   Packet-level simulation lab (netns + scapy)
docs/                     User-facing docs; docs/testing/ for simlab
tools/                    Operator scripts (setup-remote-test-host.sh …)
packaging/                .deb / .rpm / systemd units
```

Each package has its own `CLAUDE.md` — open it before touching that code.

## Bootstrap

```bash
# Install all three (editable, dev extras):
pip install -e 'packages/shorewall-nft[dev]' \
            -e 'packages/shorewalld[dev]' \
            -e 'packages/shorewall-nft-simlab[dev]'

# Run core tests:
cd packages/shorewall-nft && python -m pytest tests/ -q

# Run daemon tests:
cd packages/shorewalld && python -m pytest tests/ -q
```

## Release state

Branch `shorewall-nft-release`. Versions in sync across all three
`pyproject.toml` files and `packages/shorewall-nft/shorewall_nft/__init__.py`.
Latest released: **v1.4.0** (DNS nft-set population + Prometheus metrics beta).

When bumping a version, update all of these in one commit:
- `packages/shorewall-nft/pyproject.toml`
- `packages/shorewalld/pyproject.toml`
- `packages/shorewall-nft-simlab/pyproject.toml`
- `packages/shorewall-nft/shorewall_nft/__init__.py`
- `packaging/rpm/shorewall-nft.spec` (Version: field + %changelog entry)
- `packaging/debian/changelog`
- `CHANGELOG.md` (new `## [X.Y.Z]` section at the top)

Tag with `git tag -a vX.Y.Z` and push the tag — the release workflow fires
on `refs/tags/v*` and publishes wheels + .deb + .rpm to a GitHub Release.

## Sister projects

Located at `/home/avalentin/projects/marcant-fw/`:

- **shorewall2foomuuri** — Shorewall → foomuuri DSL → nft translator.
  Useful as nft syntax reference and iptables↔nft equivalence checker.
- **netns-routing** — production environment: 16 zones, ~3300 rules,
  HA with VRRP across two nodes / three namespaces, real flowtables.
  Best "what does the reference config really look like" reference.

## CI (.github/workflows/test.yml)

Jobs: Lint (ruff + shellcheck) → Unit tests (3.11/3.12/3.13) →
Integration tests (netns) + Build wheels + Build .deb + Build .rpm →
GitHub Release (tag pushes only).

**RPM build notes** (`rpm-build` job, Fedora 40 container):

- Do **not** install `pyproject-rpm-macros` — it injects `pyproject_wheel.py`
  and malformed install/save-files steps against the monorepo root via
  `%__spec_install_pre` / `%___build_pre`. The injection cannot be suppressed
  with macro overrides; removing the package is the only clean fix.
- Do install `python3-rpm-macros` explicitly — it provides `%{python3_sitelib}`
  and was previously a transitive dep of `pyproject-rpm-macros`.
- The root `pyproject.toml` is a buildable stub (empty wheel, no packages)
  so that other tools don't trip on its absence; it is safe to include in
  the source tarball.
- Wheels are built with `pip3 wheel --no-deps --no-build-isolation` from
  a subshell `cd` into each sub-package directory, then installed in one
  `pip3 install --root=%{buildroot}` pass from the pre-built `.whl` files.

**Deb build notes** (`deb-build` job, Debian trixie container):

- `dh-python` / `pybuild-plugin-pyproject` handle the main `shorewall-nft`
  package; `shorewalld` and `shorewall-nft-simlab` are installed with
  `python3 -m build --wheel` + `python3 -m installer` in
  `override_dh_auto_install`.
- After installer runs, any files landing in `usr/local/bin/` (Debian
  sysconfig patches Python to write entry-points there even with
  `--prefix=/usr`) must be moved to `usr/bin/` before `dh_usrlocal` runs.

## Key rules (all packages)

- Commit messages / CHANGELOG / release notes **never name the
  deployment** — say "the reference HA firewall" / "the reference config".
- Test reports must split **false-drop** vs **false-accept** and explain
  random-probe mismatches with the oracle reason.
- Point of truth for verification: `old/iptables.txt` +
  `old/ip6tables.txt` (2026-04-07). simlab is the weakest signal.
