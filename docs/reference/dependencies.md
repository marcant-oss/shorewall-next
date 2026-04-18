---
title: Dependencies
description: Runtime, test, and documentation dependencies by distro package name. Used for future .deb/.rpm/pacman packaging.
---

# Dependencies

Reference catalog of every external dependency shorewall-nft pulls
in, with the distro package names, versions, and purposes. Used for
future Debian/RPM/Arch packaging.

## Python (required)

| Python package | Min version | Purpose | Debian | Fedora | Arch | Alpine |
|----------------|-------------|---------|--------|--------|------|--------|
| Python | 3.11 | stdlib `tomllib`, modern `match` | `python3` | `python3` | `python` | `python3` |
| click | 8.0 | CLI framework | `python3-click` | `python3-click` | `python-click` | `py3-click` |
| pyroute2 | 0.9 | libnl bindings for nft state reading | `python3-pyroute2` | `python3-pyroute2` | `python-pyroute2` | `py3-pyroute2` |

## Python (optional)

| Python package | Extra | Purpose | Debian | Fedora | Arch | Alpine |
|----------------|-------|---------|--------|--------|------|--------|
| scapy | `simulate` | Packet crafting in `simulate` and `connstate` | `python3-scapy` | `python3-scapy` | `scapy` | `py3-scapy` |

## Python (dev / test)

| Python package | Extra | Purpose | Debian | Fedora | Arch | Alpine |
|----------------|-------|---------|--------|--------|------|--------|
| pytest | `dev` | Test runner | `python3-pytest` | `python3-pytest` | `python-pytest` | `py3-pytest` |
| pytest-cov | `dev` | Coverage plugin | `python3-pytest-cov` | `python3-pytest-cov` | `python-pytest-cov` | `py3-pytest-cov` |

## System binaries (required at runtime)

| Tool | Purpose | Debian | Fedora | Arch | Alpine |
|------|---------|--------|--------|------|--------|
| `nft` | nftables userspace | `nftables` | `nftables` | `nftables` | `nftables` |
| `ip` | iproute2 — needed for netns, interfaces | `iproute2` | `iproute` | `iproute2` | `iproute2` |
| libnftables Python bindings | In-process `setns(2)` + libnftables path for same-namespace operations. Without it every netns call forks `ip netns exec` as a subprocess. | `python3-nftables` | `python3-nftables` | `nftables` (includes bindings) | `py3-nftables` |

## System binaries (optional at runtime)

| Tool | Purpose | Debian | Fedora | Arch | Alpine |
|------|---------|--------|--------|------|--------|
| `ipset` | Legacy ipset loading from `init` scripts | `ipset` | `ipset` | `ipset` | `ipset` |
## System binaries (test only)

| Tool | Purpose | Debian | Fedora | Arch | Alpine |
|------|---------|--------|--------|------|--------|
| `unshare` | Isolate test network + mount namespace | `util-linux` | `util-linux` | `util-linux` | `util-linux` |
| `tcpdump` | Ad-hoc netns packet capture for debugging | `tcpdump` | `tcpdump` | `tcpdump` | `tcpdump` |

## Documentation tooling (optional)

| Tool | Purpose | Debian | Fedora | Arch | Alpine |
|------|---------|--------|--------|------|--------|
| `pandoc` | DocBook → Markdown conversion (one-off) | `pandoc` | `pandoc` | `pandoc` | `pandoc` |
| `mkdocs` | Build the docs site locally | `mkdocs` (backports) or pip | pip | `mkdocs` | pip |
| `mkdocs-material` | Material theme | pip | pip | pip (AUR) | pip |

## Kernel features

Minimum kernel: **5.8** for the full feature set. Required modules:

- `nf_tables`
- `nf_tables_inet`
- `nft_counter`
- `nft_ct`
- `nft_limit`
- `nft_log`
- `nft_nat`
- `nft_reject_inet`
- `nft_set_hash`
- `nft_set_rbtree`

Optional but frequently used:

- `nft_objref` (for CT helper references)
- `nft_connlimit` (for `CONNLIMIT=`)
- `nft_numgen` (for random probability matches)
- `nft_flow_offload` (flowtables)
- `nft_synproxy` (SYNPROXY targets)

Most of these auto-load when `nft` invokes the first rule that uses
them. Check with `shorewall-nft capabilities`.

## Future packaging plan

### Debian package

```
Package: shorewall-nft
Depends:
  python3 (>= 3.11),
  python3-click (>= 8.0),
  python3-pyroute2 (>= 0.9),
  python3-nftables,
  nftables,
  iproute2
Recommends:
  ipset
Suggests:
  python3-scapy,
  sudo
```

Separate package for test tooling:

```
Package: shorewall-nft-tests
Depends:
  shorewall-nft,
  python3-pytest (>= 8.0),
  sudo
Recommends:
  python3-scapy,
  python3-pytest-cov
```

Separate package for docs:

```
Package: shorewall-nft-doc
Depends:
  shorewall-nft
Description: HTML + Markdown documentation for shorewall-nft
```

### RPM spec

```spec
Name:     shorewall-nft
Version:  0.11.0
Requires: python3 >= 3.11
Requires: python3-click >= 8.0
Requires: python3-pyroute2 >= 0.9
Requires: python3-nftables
Requires: nftables
Requires: iproute
Recommends: ipset
Suggests: python3-scapy
```

### Arch PKGBUILD

```bash
depends=(
    'python>=3.11'
    'python-click>=8.0'
    'python-pyroute2>=0.9'
    'nftables'     # includes python-nftables libnftables bindings on Arch
    'iproute2'
)
optdepends=(
    'ipset: legacy ipset support'
    'python-scapy: simulate and connstate tests'
    'util-linux: unshare for isolated test namespace'
)
```

## Versioning policy

Shorewall-nft follows [Semantic Versioning](https://semver.org):

- **Major** (e.g. 1.0): breaking config syntax or compiler output changes
- **Minor** (e.g. 0.11 → 0.12): new features, backward-compatible
- **Patch** (e.g. 0.11.0 → 0.11.1): bug fixes only

Python stdlib floor is Python 3.11 (tomllib, PEP 604 unions). We
don't currently support Python 3.10.

## See also

- [Setup](../testing/setup.md) — install instructions for developers
- [Troubleshooting](../testing/troubleshooting.md) — missing deps
