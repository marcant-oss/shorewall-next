# RPM packaging

The `.spec` files in this directory are **generated**, not hand-edited.
Two independent packages are built here:

1. **shorewall-nft** — the firewall compiler (Python, noarch)
2. **keepalived-marcant** — upstream keepalived with all server-grade features
   enabled; `Conflicts: keepalived` / `Provides: keepalived` so only one
   can be installed at a time

## Files

| File | Role |
| --- | --- |
| `shorewall-nft.spec.in` | Template with `@@PLACEHOLDERS@@`. Checked in. |
| `shorewall-nft.spec` | Generated artifact. `.gitignore`d. |
| `../../tools/gen-rpm-spec.sh` | Generator for shorewall-nft. Substitutes version, release, distro-specific Requires, and a changelog entry. |
| `keepalived-marcant.spec.in` | Template for keepalived-marcant. Checked in. |
| `keepalived-marcant.spec` | Generated artifact. `.gitignore`d. |
| `../../tools/gen-keepalived-spec.sh` | Generator for keepalived-marcant. Pins `KEEPALIVED_VERSION`; release derives from git like gen-rpm-spec.sh. |

## Generating a spec locally

```bash
# shorewall-nft — Fedora 40 profile
./tools/gen-rpm-spec.sh --distro fedora

# shorewall-nft — AlmaLinux 10 profile (different protobuf / pytest / python minimums)
./tools/gen-rpm-spec.sh --distro almalinux10

# keepalived-marcant (AL10 only for now; version pinned in the script)
./tools/gen-keepalived-spec.sh
```

The script reads git to pick the version:

- **HEAD is on a `v*` tag** → `Version=<tag>` and `Release=1%{?dist}`.
  Example: tag `v1.4.3` → `Version: 1.4.3`, `Release: 1%{?dist}`.
- **HEAD is after the last `v*` tag** → `Version=<last-tag>` and
  `Release=0.<commits_since>.g<sha>%{?dist}`. The leading `0.` keeps dev
  builds sorted strictly below numbered releases (RPM verrev compares
  `0.5.g1a2b3c4` as older than `1`).
- **No tags at all** (brand-new clone without history) →
  `Version=<pyproject.toml version>` + `Release=0.0.g<sha>%{?dist}`.

## Distro profiles

The generator carries one profile per supported target. If you add a new
profile, update the `case "$DISTRO"` block in `tools/gen-rpm-spec.sh` with:

- `BUILD_REQUIRES` — a multi-line block of `BuildRequires:` lines.
- `DISTRO_REQUIRES` — the runtime `Requires:` block (including
  `Recommends:` / `Suggests:`).
- `TESTS_PYTEST_REQ` — the single `Requires: python3-pytest >= X` line
  for the `-tests` subpackage.

### Fedora 40

- `python3 >= 3.11`
- `python3-protobuf >= 4.25` (Fedora ships 4.25+)
- `python3-pytest >= 8.0`
- All Python deps in base repos.

### AlmaLinux 10

- `python3 >= 3.12`
- `python3-protobuf >= 3.19` — **AL10 AppStream ships only 3.19.6**;
  neither AppStream nor EPEL 10 carry a newer major. This is a real
  downgrade of the Fedora floor.
- `python3-pytest >= 7.4` — CRB ships 7.4.3.
- `python3-dns >= 2.6` (BaseOS: 2.6.1).
- **EPEL 10 required** for: `python3-click`, `python3-pyroute2`,
  `python3-prometheus_client`.
- **CRB required** for: `python3-pytest`.

When running the CI `rpm-build` matrix job with the `almalinux10`
profile, the container enables EPEL 10 and CRB before installing build
deps.

## CI integration

### shorewall-nft

`.github/workflows/build.yaml` → `rpm-build` is a matrix over
`{fedora40, almalinux10}`. Each entry:

1. Installs per-distro build deps (+ EPEL/CRB for AL10).
2. Runs `./tools/gen-rpm-spec.sh --distro <profile>`.
3. Tarballs the tree, runs `rpmbuild -bb`.
4. Uploads RPMs to an artifact named `shorewall-nft-rpm-<distro-name>`.

### keepalived-marcant

`.github/workflows/build.yaml` → `build-keepalived-rpm-al10` (separate job,
runs in parallel to the shorewall-nft build). Steps:

1. Enables EPEL 10 + CRB on the `almalinux:10` container.
2. Installs C build deps (gcc, libnftnl-devel, net-snmp-devel, libbpf-devel …).
3. Downloads the pinned upstream tarball from GitHub releases.
4. Runs `./tools/gen-keepalived-spec.sh` to produce the spec.
5. `rpmbuild -ba` (binary + source RPMs).
6. Uploads `.rpm` + `.src.rpm` to artifact `keepalived-marcant-rpm-al10`.

The `release` job (tag pushes only) also downloads
`keepalived-marcant-rpm-al10` (`continue-on-error: true`) and attaches all
RPMs to the GitHub Release alongside the shorewall-nft artifacts.

## What the old checked-in spec looked like

Pre-2026-04-17 the spec was a static file with a hard-coded `Version:`
line, bumped by hand on each release. The version and release
information now live in git; `tools/gen-rpm-spec.sh` is the single
source of truth at build time.
