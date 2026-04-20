# CLAUDE.md — monorepo overview

`shorewall-nft` — nftables-native firewall compiler with a
Shorewall-compatible configuration surface.

## Project principles (read this first)

`docs/PRINCIPLES.md` is the load-bearing rulebook. Summary of the
non-negotiables:

1. **AI-discoverable tooling** — any AI agent must be able to determine
   from the docs alone: what the tool can do, how to instruct it, what
   it can't do, and how to verify success. If you have to `grep` a
   Python file to know a CLI flag, the docs are incomplete — fix the
   docs.
2. **No secrets in git** — `${ENV_VAR}` placeholders only.
3. **Deployment names are scoped** — public history (commits, CHANGELOG)
   uses "reference HA firewall"; node-specific paths may use real names.
4. **Point-of-truth ranking** — old/iptables.txt wins over compiler
   output wins over simlab.
5. **Test reports split false-drop vs false-accept** — never just
   "N mismatches".
6. **Two-scope edits**: core-first, then consumer.
7. **Versions stay in sync** across all pyproject.toml + spec + changelog.

See `docs/PRINCIPLES.md` for full text + practical PR checklist.

## Repo layout

```
packages/
  shorewall-nft/              Core: compiler, emitter, config, runtime
  shorewalld/                 Prometheus exporter + DNS-based dynamic sets
  shorewall-nft-simlab/       Packet-level simulation lab (netns + scapy)
  shorewall-nft-stagelab/     Distributed bridge-lab: perf, DPDK, advisor, review (NEW)
  shorewall-nft-netkit/       Shared primitives (tundev, nsstub, packet builders) (NEW)
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

`shorewall-nft-stagelab` is the performance/readiness side of validation:
kernel-stack (iperf3/nmap), DPDK/TRex line-rate (stateless + ASTF),
Prometheus/SNMP ingest, a rule-based advisor that emits tiered optimization
hints. It shares `shorewall-nft-netkit` with simlab for TUN/TAP + netns
primitives.

## Bootstrap

**Project venv lives at the repo root: `.venv/` (Python 3.13).**
Always activate or invoke it directly — every package expects this one venv,
no per-package venvs. Re-use across sessions; don't create new ones.

```bash
# From the repo root:
source .venv/bin/activate          # or call .venv/bin/python / .venv/bin/pytest directly

# Install all sub-packages editably (first-time bootstrap):
# Install order is load-bearing: netkit must come before simlab and stagelab.
pip install -e 'packages/shorewall-nft-netkit[dev]' \
            -e 'packages/shorewall-nft[dev]' \
            -e 'packages/shorewalld[dev]' \
            -e 'packages/shorewall-nft-simlab[dev]' \
            -e 'packages/shorewall-nft-stagelab[dev]'
# `pip install -e .` in the repo root installs the empty monorepo stub only.

# Run tests (per package):
pytest packages/shorewall-nft/tests -q
pytest packages/shorewalld/tests -q
pytest packages/shorewall-nft-simlab/tests -q
pytest packages/shorewall-nft-stagelab/tests/unit -q
```

## Release state

Branch `master`. Versions stay in sync across all three `pyproject.toml`
files and `packages/shorewall-nft/shorewall_nft/__init__.py`. Latest
released version: see `CHANGELOG.md` top-most `## [X.Y.Z]` heading and
`git tag --sort=-v:refname | head -1`.

When bumping a version, update all of these in one commit:
- `packages/shorewall-nft/pyproject.toml`
- `packages/shorewalld/pyproject.toml`
- `packages/shorewall-nft-simlab/pyproject.toml`
- `packages/shorewall-nft/shorewall_nft/__init__.py`
- `packaging/rpm/shorewall-nft.spec` (Version: field + %changelog entry)
- `packaging/debian/changelog`
- `CHANGELOG.md` (new `## [X.Y.Z]` section at the top)
- `tools/man/*.8` and `tools/man/*.5` — update `.TH` version strings to match the new version.

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

## CI (.github/workflows/build.yaml)

Jobs: Lint (ruff + shellcheck) → Unit tests (3.11/3.12/3.13) →
Integration tests (netns) + Build wheels + Build .deb + Build .rpm →
GitHub Release (tag pushes only).

**RPM build notes** (`rpm-build` matrix job — Fedora 40 + AlmaLinux 10):

- The spec file is **generated** from `packaging/rpm/shorewall-nft.spec.in`
  by `tools/gen-rpm-spec.sh` at build time. The generated `shorewall-nft.spec`
  is git-ignored. Per distro, Requires/BuildRequires are substituted in from
  a distro profile inside the generator.
- Version/Release derivation: on a `v*` tag → `Version=<tag>` + `Release=1`.
  Otherwise → `Version=<last-tag>` + `Release=0.<commits_since>.g<sha>` (the
  leading `0.` keeps dev builds sorted below numbered releases in RPM).
- **AlmaLinux 10 profile** reflects what AL10 actually ships: `python3-protobuf`
  caps at **3.19.6** in AppStream (no newer version in AL10/EPEL 10), so the
  AL10 `Requires:` line is `python3-protobuf >= 3.19`, not `>= 4.25` as on
  Fedora. Similarly `python3-pytest` in AL10 CRB is 7.4.x — Tests subpackage
  requires `>= 7.4` for AL10. `python3-click`, `python3-pyroute2`,
  `python3-prometheus_client`, and `python3-pytest` come from EPEL 10 (+ CRB
  for pytest) — the AL10 build job enables both repos before install.
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

## nft emit architecture (match Shorewall iptables layout)

The compiled nft ruleset must mirror the Shorewall iptables chain
architecture. Deviations cause IPv6 breakage. Key invariants:

- **Base chains** (input/forward/output): `policy drop`. Contain
  only FASTACCEPT `ct state established,related accept` (if enabled),
  NDP accept (input/output only), and dispatch jumps. **No** `ct state
  invalid drop`, **no** `dropNotSyn` — these belong in zone-pair chains.
- **Zone-pair chains**: Carry `ct state established,related accept`
  (always) and `ct state invalid drop` (always) at the top, then
  explicit rules, then `jump sw_Reject` / policy verdict at the end.
- **Raw chains** (priority < 0): NOTRACK rules only. **Never** dispatch
  to zone-pair chains — that routes NDP into chains that drop it.
- **Dispatch ordering**: Rules with `iifname + oifname` (specific)
  first, catch-all rules (zones without interfaces, e.g. `rsr ipv6`)
  last. Without this, a catch-all `meta nfproto ipv6 iifname X jump
  src-rsr` swallows all IPv6 before the specific jump fires.
- **Dual-stack zone type**: When merging shorewall + shorewall6, zones
  in both configs must be type `ip` (not `ipv4`). Otherwise dispatch
  rules get `meta nfproto ipv4` and IPv6 is never dispatched.

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
