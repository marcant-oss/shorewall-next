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
5. **pcap-on-failure** in simlab — jede gefailte probe dumpt
   die worker trace-buffers via `packets.export_trace_pcap()`
   in `docs/testing/simlab-reports/<ts>/fail-<probe_id>.pcap`.
   Gehört in den `cmd_full` post-run path.
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
