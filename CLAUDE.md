# CLAUDE.md — monorepo overview

`shorewall-nft` — nftables-native firewall compiler with a
Shorewall-compatible configuration surface.

## Repo layout

```
packages/
  shorewall-nft/          Core: compiler, emitter, config, runtime
  shorewalld/             Prometheus exporter + DNS-based dynamic sets
  shorewall-nft-simlab/   Packet-level simulation lab (netns + scapy)
docs/
  quick-start.md          Onboarding guide (beginner + migration paths)
  index.md                Doc entry point with 3-package overview
  shorewall-nft/          Extensions unique to shorewall-nft
  shorewalld/             shorewalld operator reference
  testing/                Test infrastructure, simlab, verification
  concepts/ features/     Shorewall config-language reference
  cli/ reference/         CLI reference, setup guides, FAQ
tools/                    Operator scripts (setup-remote-test-host.sh …)
packaging/                .deb / .rpm / systemd units
```

Each package has its own `CLAUDE.md` — open it before touching that code.
`HOWTO-CLAUDE.md` in the repo root maps problem types to starting directories.

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
Latest released: **v1.4.1** (monorepo tooling fix, docs restructure, shorewalld man page).

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
  `nft_parser.py`: nft-syntax reference (matchers, actions, table/family
  hierarchy). `iptables_parser.py`: iptables↔nft semantic equivalence.
  `verify.py`: multi-stage verification framework.
- **netns-routing** — production environment: 16 zones, ~3300 rules,
  HA with VRRP across two nodes / three namespaces, real flowtables.
  Best "what does the reference config really look like" reference.
  nft features in production: named counters, anonymous sets, flow
  offloading, flowtables.

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

## Reference HA firewall stack

The primary test target is an **active/passive HA pair**:

- **keepalived** — VRRP for virtual-IP failover. IP proto 112,
  multicast 224.0.0.18. Rules must permit VRRP between the two
  firewall nodes (and block it from anywhere else).
- **conntrackd** — replicates kernel conntrack state between nodes
  so existing connections survive failover. UDP/3780 by default.
  Rules must permit the sync traffic between firewall nodes.
- **bird** — BGP/OSPF routing daemon. BGP = tcp/179, OSPF = proto 89.

**Rule implications:**
- Always sanity-check that VRRP (proto 112), conntrackd (udp 3780
  between peers), and bird (tcp 179 / proto 89) are explicitly allowed
  between firewall nodes.
- Do NOT emit `ct state invalid drop` without the standard
  `ct state established,related accept` prefix — a reload could kill
  in-flight flows on the active node during VRRP failover.
- systemd unit ordering: keepalived must start `After=shorewall-nft.service`.
- The current 3-netns simlab topology does NOT model a second firewall
  peer → conntrackd sync rules and VRRP exchange cannot be simlab-tested.
  Use `verify --iptables` for rule-level coverage; manual failover drill
  for behavioural coverage.

## Point of truth for verification

When a tool (simlab, simulate, triangle) reports a mismatch, the
tiebreaker ranking is:

1. **`/home/avalentin/projects/marcant-fw/old/iptables.txt`** and
   **`ip6tables.txt`** — `iptables-save`/`ip6tables-save` from the
   production primary node. Last captured **2026-04-07 18:56 UTC**.
   This is what the firewall is *actually doing*.
2. **`/home/avalentin/projects/marcant-fw/old/etc/shorewall{,6}/`** —
   the Shorewall config that, compiled by classic Shorewall, produces
   those iptables files. Use when the dump looks stale vs the source.
3. **`/home/avalentin/projects/marcant-fw/old/{ip4add,ip4routes,ip6add,ip6routes}`**
   — `ip addr show`/`ip route show` dumps; topology ground truth for
   simlab's NS_FW namespace.

**Conflict rules:**
- iptables.txt / ip6tables.txt wins over compiled nft output. If
  compiled disagrees, the emit is wrong — unless the diff is an
  intentional 1.1+ feature (flowtable, vmap, CT zone tag, concat-map
  DNAT, plugin enrichment) documented as such.
- simlab is the **weakest** signal. When simlab disagrees with
  iptables.txt, assume simlab is wrong and investigate: probe
  generator → topology → emit in that order.
- Canonical doc: `docs/testing/point-of-truth.md`.
- Refresh procedure: on the primary, capture iptables-save, ip6tables-save,
  ip addr, ip route; rsync to `old/`; bump the date in that doc.

## Key rules (all packages)

- Commit messages / CHANGELOG / release notes **never name the
  deployment** — say "the reference HA firewall" / "the reference
  config". Internal files (`CLAUDE.md`, operator runbooks, `tools/`)
  may use the real name; published git history must not.
- Test reports must split **false-drop** vs **false-accept** and
  explain random-probe mismatches with the oracle reason (which rule
  fired, which chain matched) — never just "N mismatches".
- Point of truth for verification: `old/iptables.txt` +
  `old/ip6tables.txt` (2026-04-07). simlab is the weakest signal.
