# CLAUDE.md — orientation for future Claude Code sessions

This file lives in the repo root so every new session has the same
map of "what matters here" without having to rediscover it from
chat history or commit messages.

## What this repository is

`shorewall-nft` — an nftables-native firewall compiler with a
Shorewall-compatible configuration surface. It's the production
firewall builder for the **marcant-fw** deployment (active/passive
HA pair with keepalived, conntrackd, and bird).

Key directories:

- `shorewall_nft/compiler/` — config → IR (`build_ir()` in
  `ir.py`) and optimisations (`optimize.py`).
- `shorewall_nft/nft/` — emitter (IR → nft script), plus
  flowtable, sets, capabilities probe, explain engine.
- `shorewall_nft/runtime/` — CLI commands (`runtime/cli.py`),
  netlink glue, sysctl generator, systemd unit generator,
  conntrackd fragment generator.
- `shorewall_nft/verify/` — post-compile verification:
  - `triangle.py` — static rule-coverage fingerprint compare
    against an iptables-save baseline
  - `simulate.py` — older packet-level simulate (single-pair
    netns topology; deprecated in favour of simlab)
  - `simlab/` — the **current** packet-level test lab; see
    [`docs/testing/simlab.md`](docs/testing/simlab.md)
- `tests/` — pytest; `test_emitter_features.py` covers the
  1.1-era knobs (flowtable, vmap dispatch, ct zone tag,
  concat-map DNAT, ct mask).
- `docs/` — user-facing docs. `docs/testing/` for test-harness
  docs, `docs/roadmap/` for post-1.0 feature plans.
- `tools/` — operator scripts (`setup-remote-test-host.sh`,
  `simulate-all.sh`, `simulate-all-zones.sh`, `install-test-tooling.sh`).

## Release state

Shipping on branch `shorewall-nft-release`. Latest **tagged**
release is **1.0.0** (`shorewall_nft/__init__.py:__version__`).
The `1.1.0` line of features (flowtable, vmap dispatch, ct zone
tag, concat-map DNAT) is committed but **not tagged** — waiting
on the simlab validation run that's currently in progress.

Already committed on this branch since 1.0.0:

- `aa45f78ca` kill -9 -1 host-wide process genocide fix
- `4f6999327` triangle OPT=4/8 + v6 verify auto-detect
- `e17531949` simulate dual-stack v4+v6 topology + conntrack probe
- `c9ec97bd8` triangle extras informational, ipt base-chain symmetry
- `e1669fd54` 1.1.0 — flowtable, vmap dispatch, ct zone tag
- `273f46d26` OPTIMIZE_DNAT_MAP concat-map DNAT
- `547d0901c` DNS filter roadmap refinement (RPZ + protobuf)
- `dbe5be363` flowtable tuning knobs + capability probe
- `4a011a088` pytest feature tests
- `702c39b72` ct zone tag mask + conntrackd generator
- `7e977f70e` simulate multi-zone + CT mask fix + strict nft load
- `4970b3f38` simlab: real-FW reproduction via TUN/TAP + dump parsing
- `ef84d87bd` simlab: asyncio workers, nsstub, stress harness
- `81aeaa460` simlab: oracle, random probes, categories, archive

## Test host

- **192.0.2.83** — grml trixie/sid live, RAM-only.
- Passwordless ssh as root.
- Bootstrap: `tools/setup-remote-test-host.sh root@192.0.2.83`
  rsyncs the repo, creates a venv, runs `install-test-tooling.sh`,
  and stages simulate ground-truth data at `/root/simulate-data`.
- Long-running tests must go via `systemd-run --unit=NAME --collect`.
  The earlier test host crashed because `kill -9 -1` inside an
  `ip netns exec` reaches host processes (ip netns provides no
  PID isolation) — the fix in commit `aa45f78ca` is load-bearing.

## Debug lessons (do not re-learn these the hard way)

- **If `nft monitor trace` shows nothing**, the cause is
  routing / source routing / RPF / ARP, not the firewall
  rules. nft trace only sees packets that entered the matching
  table.
- **TUN/TAP devices** should be created with a temp name in the
  host NS and renamed **inside** the target namespace. Never
  let the canonical bond0.X name appear in the host NS, even
  briefly, or it can collide with real host interfaces.
- **`pyroute2.NetNS` forks a helper process** at first use. Any
  file descriptors you want the helper to inherit must be open
  in the parent **before** the first `ns()` call. See
  `netns_topology.refresh_handles()`.
- **`netns.create(name)` leaves a bind mount at
  `/run/netns/<name>`** which survives a controller SIGKILL.
  Use `simlab.nsstub.spawn_nsstub()` instead — it holds the
  netns alive via a stub process that cleans up on parent
  death via `PR_SET_PDEATHSIG`.
- **systemd-run units** that need to manage named netns must
  set `PrivateMounts=false` or the bind-mount the stub installs
  won't be visible to `ip netns exec` outside the unit.
- **FASTACCEPT=No** in shorewall.conf requires the emitter to
  put `ct state established,related accept` inside every
  zone-pair chain, not at the top of the base forward chain.
  The 1.1 emitter did this wrong and every return flow was
  rejected — fix in commit `7e977f70e`.
- **CT mask emit** cannot use `ct mark and C or iifname map {…}`
  because nft rejects `or` with a map on the right. Use
  per-iface rules `iifname "bond1" ct mark set ct mark and INV or ZONE`.
- **Triangle verifier** skips "pure ct state" rules when
  comparing fingerprints, so a missing `established accept`
  shows up as 100% rule coverage (misleading). Rely on simlab
  for packet-level validation of stateful paths.

## Dringende Ideen / offene Punkte (Reihenfolge = Priorität)

1. **Full simlab run ins Archiv flushen** — smoketest `full` auf
   der VM, warten bis Ergebnisse in `docs/testing/simlab-reports/`
   landen. Belastungstest für das gesamte 1.1-Feature-Set gegen
   den echten marcant-Ruleset. Start der verlässlichen
   Regressions-Historie.
2. **simlab → pytest integration tests** — sobald der `full`-Run
   reproducible grün ist, einen pytest-Wrapper bauen der in CI
   ein minimales simlab-Szenario (single probe) fährt. Gate
   für künftige Emitter-Änderungen.
3. **1.1.0 taggen** — nach dem ersten grünen archivierten
   simlab-Run: `git tag -a v1.1.0`, CHANGELOG eintrag
   abschließen, release notes schreiben.
4. **DNS-based filtering feature** (roadmap: `docs/roadmap/
   post-1.0-nft-features.md` → "Tier 2+") — RPZ + protobuf
   stream sidecar statt naïver postresolve Lua hook. Jede
   FW-Node konsultiert **beide** pdns_recursor-Instanzen. Design
   in memory `project_dns_filtering.md`.
5. ~~pcap-on-failure~~ ✅ (erste Iteration): report.py::_write_fail_pcaps
   schreibt pro failed probe eine .pcap mit dem injizierten
   Frame nach `<run_dir>/fail-pcaps/<id>-<inject>-<expect>-
   <dir>.pcap` + grep'barer Index `fail-pcaps.txt`. Nächste
   Iteration: auch die Worker-Ring-Buffer (tatsächlich beobachtete
   Frames, nicht nur der Injizierte) reinpacken, sobald der Worker
   sie beim `trace_dump` mitliefert.
6. **VRRP/BGP/RADIUS probe injection** — die builders
   existieren in `simlab/packets.py`, aber es gibt noch keine
   controller-side Abfrage die sie automatisch aus dem
   ruleset generiert. Für HA-Validierung essentiell
   (keepalived + bird).
7. **Flowtable offload probe** — NIC offload ist in 1.1 aktiv
   über `FLOWTABLE_FLAGS=offload`, aber noch nicht in simlab
   validiert. Braucht entweder offload-capable mock NIC oder
   software-fastpath check via conntrack counters.
8. **Full HA-pair simulation** — einen zweiten NS_FW aufbauen
   (simlab-peer) mit VRRP + conntrackd sync zwischen den zwei,
   dann failover-Szenarios durchspielen. Dafür braucht die
   simlab ein Mehrfach-NS-Konzept (bisher nur eins).
9. **Compiler/emitter für neue Config-Files** — parser +
   exporter kennen seit dem structured-io groundwork commit
   die folgenden Files, aber IR/emitter ignorieren sie noch:
   - **`arprules`** — ARP anti-spoof-Regeln (arp table chain)
   - **`proxyarp`** — proxy-arp Adresstabelle
   - **`proxyndp`** — proxy-ndp Adresstabelle
   - **`ecn`** — ECN-Disable pro Interface/Host-Paar
   - **`nfacct`** — named conntrack accounting objects
   - **`rawnat`** — raw-table NAT (early DNAT vor conntrack)
   - **`stoppedrules`** — Regeln die aktiv bleiben wenn FW
     gestoppt ist (Nachfolger von `routestopped`)
   - **`scfilter`** — source CIDR sanity filter
   Jedes Item = eigener Commit mit emitter-Pass + pytest-case.
   Reihenfolge nach Häufigkeit in echten Configs:
   stoppedrules > proxyarp > rawnat > arprules > nfacct >
   proxyndp > scfilter > ecn.
10. **Flame graph for simlab runs** — profile the controller
    during a ``full`` scan and export a flame graph (via
    ``py-spy record --format flamegraph`` or ``perf record``
    with ``perf-folded``) for the hot path. **Scope: inside
    NS_FW only**, and covering every interface that carries
    probe traffic — including parent interfaces in the root
    netns (e.g. ``bond0`` carrying ``bond0.18`` vlan, the
    underlying physical NICs, veth endpoints). Goal: find
    whatever takes > 5 % of run wall time so we can target
    it for the next round of optimisation. Post-flamegraph
    artifact under ``docs/testing/simlab-reports/<ts>/
    flamegraph.svg`` alongside ``report.json``.
11. **Prometheus exporter (port from foomuuri)** — take the
    prometheus exporter shape from the
    ``../shorewall2foomuuri`` sister repo and port it to
    shorewall-nft. **Hard requirements:**
    - **Multi-netns aware.** One exporter instance serves N
      namespaces at once (one scrape endpoint, per-netns
      label on every metric, or one port per netns —
      configurable). Production HA stacks run 2–3 namespaces
      per box (primary/backup/mgmt) and one exporter per
      netns is wasteful.
    - **Efficient.** Read counters directly from the kernel
      via libnftables / ``nft_ct`` / pyroute2.netlink, not
      by shelling out to ``nft list ruleset`` and parsing
      text. The existing ``shorewall_nft.nft.netlink``
      already prefers libnftables; extend it with a
      ``list_counters(netns=N)`` path that's a single
      netlink round-trip.
    - **Per-chain + per-rule counters** exported as
      ``shorewall_nft_packets_total{table,chain,rule_idx,
      netns,…}`` and ``..._bytes_total``, plus ct table
      size / ct state breakdown / per-zone-pair chain totals.
    - **Cheap scrape.** Scraping should cost <50 ms at the
      reference config's ruleset size (1600+ rules × 3
      netns). Amortise netlink dumps across scrapes so a
      30 s scrape interval has <5 % CPU cost.
    - **No subprocess per scrape.** The worst way to run a
      counter exporter is to fork ``nft list ruleset`` every
      30 s. Direct netlink only.
    Reference implementation: ``../shorewall2foomuuri``
    (sister repo) has the metric shape and the Prometheus
    registry already — the port is mostly replacing its
    counter-read path with the shorewall-nft netlink one.
12. **routefilter / rp_filter parity with Shorewall.** Today
    ``simlab/topology.py`` writes ``net.ipv4.conf.{all,default}.
    rp_filter = 0`` and the compiler does nothing with the
    ``routefilter`` interface option — both ends are rigid.
    Shorewall's behaviour is per-interface and three-state:
    no option (kernel default, usually loose), ``routefilter``
    (strict), ``routefilter=1`` (strict), ``routefilter=2``
    (loose). The setting maps to
    ``net.ipv4.conf.<iface>.rp_filter`` AND interacts with
    ``net.ipv4.conf.all.rp_filter`` (kernel uses ``max(all,
    iface)``). Implement: (1) compiler reads ``routefilter``
    from ``interfaces`` and emits a sysctl line per iface in
    the generated systemd unit / start script (already have
    ``runtime/sysctl_gen.py``); (2) simlab topology stops
    forcing rp_filter=0 globally and instead replays the
    per-iface values from the parsed ``interfaces`` file so
    the test environment matches what production would see;
    (3) shorewall.conf ``ROUTE_FILTER`` global setting honoured
    as the default for unset interfaces. Cross-check with the
    upstream Shorewall ``Compiler::*`` perl module for the
    exact mapping table.

## Release checklist (carry-forward from pre-1.0 work)

These items were must-haves for tagging 1.0 and most still
apply to the pending 1.1 tag. Before the next `git tag`:

1. **Version bump** in `pyproject.toml` and
   `shorewall_nft/__init__.py` (currently 1.1.0).
2. **CHANGELOG.md** entry closed (1.1.0 section exists but will
   need the simlab bits appended once the archived run is in).
3. **`/etc/shorewall46` precedence note** — when both `/etc/
   shorewall` and `/etc/shorewall46` exist, the latter wins.
   Backward-incompatible for operators who have both. Documented
   already but worth a release-notes line every time.
4. **`?FAMILY` directive** — it's a shorewall-nft extension, a
   merged `/etc/shorewall46` config will crash stock upstream
   Shorewall. README calls this out; don't drop the warning.
5. **Example plugin configs** under `examples/plugins/` — keep
   them in sync with whatever `plugins/builtin/*.py` actually
   expects.
6. **`generate-systemd --netns` template** — has to honour
   `/etc/shorewall46` as default when present.
7. **Packaging** — `python -m build` run, verify the wheel
   actually includes `plugins/builtin/` and the new
   `simlab/` subpackage.

Deeper open items (not release-blockers, track in issues):

- Pre-existing host-r compiler bug: chain name
  `linux,vpn-voice` from a zone list with a comma. Surfaces on
  the host-r corpus config.
- Debug-mode edge cases: fresh netns with no loaded ruleset
  during `debug` save → restore; SIGINT during `apply_nft`;
  unrelated tables (docker, fail2ban) in the save file.

## Packaging (future .deb/.rpm/pacman/apk)

Authoritative list: `docs/reference/dependencies.md`. Short form:

**Required runtime:**
- Python ≥ 3.11 (stdlib tomllib, PEP 604 unions)
- python3-click ≥ 8.0, python3-pyroute2 ≥ 0.9
- `nft`, `ip` binaries (nftables, iproute2)

**Recommended:**
- python3-nftables (libnftables bindings; subprocess fallback
  exists but slower)
- ipset (legacy `init`-script ipset loading)

**Optional (Suggests):**
- python3-scapy (only for `simulate` and `simlab`)
- sudo (only when shipping `tools/run-netns` + sudoers)

**Test subpackage `shorewall-nft-tests`:**
Depends: shorewall-nft, python3-pytest ≥ 8.0, sudo
Recommends: python3-scapy, python3-pytest-cov

**Kernel module floor:** Linux ≥ 5.8. Needs nf_tables,
nf_tables_inet, nft_counter/ct/limit/log/nat/reject_inet,
nft_set_hash/rbtree. Soft deps: nft_objref, nft_connlimit,
nft_numgen, nft_flow_offload, nft_synproxy.

Packagers: do NOT run `tools/install-test-tooling.sh` from
postinst — use the underlying `install`, `install-m`, `visudo
-c` steps directly so dpkg/rpm file ownership stays clean.

## Sister projects for nft context

Two neighbouring repos at `/home/avalentin/projects/marcant-fw/`
that provide prior art and production reference:

- **shorewall2foomuuri** (`…/shorewall2foomuuri`) — Python
  translator: Shorewall → foomuuri DSL → nft. Useful as nft
  syntax reference (`nft_parser.py`) and for the
  iptables↔nft semantic equivalence checker (`iptables_parser.py`,
  `verify.py`).
- **netns-routing** (`…/netns-routing`) — the actual production
  environment using foomuuri/nftables in netns. 16 zones, ~3300
  rules, HA with VRRP across two nodes / three namespaces, real
  flowtables + flow offload. This is the single best
  "what does marcant-fw really look like" reference.

## Operator quickstart

```bash
# Local tests (hostside venv)
.venv/bin/python -m pytest tests/ -q

# Bootstrap the VM (RAM-only grml)
tools/setup-remote-test-host.sh root@192.0.2.83

# Deploy merged marcant config + dumps, run simlab smoke
ssh root@192.0.2.83 \
    "cd /root/shorewall-nft && \
     PYTHONUNBUFFERED=1 .venv/bin/python \
         -m shorewall_nft.verify.simlab.smoketest full \
         --random 50 --max-per-pair 30 --seed 42"

# Results land under docs/testing/simlab-reports/<UTC>/
```
