# nfsets — Deferred Features and Open Items

**Audience**: developers
**Scope**: Backlog of planned but not-yet-implemented nfsets capabilities and the shorewalld metric-surface audit items deferred from W7b (2026-04-19). Use this file as the entry point when picking up follow-on nfsets work.

---

## Table of contents

- [N1 — SRV record resolution (`dnstype=srv`)](#n1--srv-record-resolution-dnstypesrv)
- [N2 — Inline `dns:` → `dnst:` rename](#n2--inline-dns--dnst-rename)
- [N3 — `nfset:` in Masq and tcrules](#n3--nfset-in-masq-and-tcrules)
- [N4 — `zone:dnst:` pseudo-zone behaviour](#n4--zonednst-pseudo-zone-behaviour)
- [N5 — Per-set nft flags optimisation](#n5--per-set-nft-flags-optimisation)
- [M1 — Metric unsafe-rename backlog (P1 security audit)](#m1--metric-unsafe-rename-backlog-p1-security-audit)
- [M2 — shorewalld security hardening (P1 audit)](#m2--shorewalld-security-hardening-p1-audit)
- [M3 — shorewalld extensibility (P3 audit)](#m3--shorewalld-extensibility-p3-audit)
- [M4 — shorewalld simplification (P4 audit)](#m4--shorewalld-simplification-p4-audit)

---

## N1 — SRV record resolution (`dnstype=srv`)

**Rationale**: SRV records encode service endpoints (host + port). Resolving them into an nft set
requires a different data model — sets would need to carry port numbers, which nft `type ipv4_addr`
sets cannot hold directly. A concrete use case (e.g. filtering XMPP federation or Kubernetes
service endpoints) should drive this before adding the complexity.

**Acceptance criteria**:
- `dnstype=srv` parses without error and emits a set of type `ipv4_addr . inet_service` (concat set).
- shorewalld's `DnsSetTracker` resolves SRV targets and populates the combined set.
- Man page and `docs/features/nfsets.md` document the concat-set syntax.
- At least one unit test covers SRV resolution and set population.

**Current state**: Option keyword is documented as "tracked, not implemented". No code exists.

---

## N2 — Inline `dns:` → `dnst:` rename

**Rationale**: The inline `dns:hostname` syntax predates nfsets. The intended rename to `dnst:`
would make it unambiguous (dnstap-backed inline set) and free `dns:` as a future generic prefix.
Deferred because the rename is a breaking change for any user of inline DNS sets in rules files.

**Acceptance criteria**:
- `dnst:hostname` is accepted everywhere `dns:hostname` is accepted.
- `dns:hostname` continues to work (backwards-compatible alias) with a deprecation warning in the
  compiler output.
- `docs/features/nfsets.md` updated; `CHANGELOG.md` notes the alias.
- A future wave can remove `dns:` support after a stated deprecation period.

**Current state**: Not started. The zone-token parser in `shorewall_nft/config/parser.py` would be
the primary touch point.

---

## N3 — `nfset:` in Masq and tcrules

**Rationale**: The `MASQUERADE` and `tcrules` address-parsing code was not updated when `nfset:`
support was added to `rules`. Operators writing masquerade exclusions or traffic-class rules
cannot currently reference named sets there.

**Acceptance criteria**:
- `nfset:<name>` parses without error in the `SOURCE` and `DEST` columns of `masq` and `tcrules`.
- The compiler emits correct nft `@nfset_<name>_v4` / `@nfset_<name>_v6` references in the
  appropriate chains.
- Simlab test covering a masquerade exclusion via nfset.

**Current state**: Not started. Use inline `dns:hostname` as a workaround.

---

## N4 — `zone:dnst:` pseudo-zone behaviour

**Rationale**: `zone:dnsr:` is implemented (resolves to the resolver-backend set namespace).
`zone:dnst:` was reserved for the dnstap-backed inline-set namespace but has not been fully
documented or stabilised.

**Acceptance criteria**:
- `zone:dnst:hostname` resolves in rules to the `dns_<sanitized>_v4/v6` sets populated via
  dnstap, parallel to how `zone:dnsr:` resolves for resolver-backed sets.
- Documented in `docs/features/nfsets.md` under "Referencing sets in rules".
- Unit test confirms the zone-token expands to the correct set name.

**Current state**: Token reserved; do not use in production configs until this item is closed.
See also [N2](#n2--inline-dns--dnst-rename) — the two items share the same naming cleanup.

---

## N5 — Per-set nft flags optimisation

**Rationale**: The current compiler selects nft flags (`timeout` vs `interval` vs both) at the
registry level — all sets sharing an nfset name get the same flags. A pure DNS set only needs
`flags timeout`; mixed DNS+ip-list sets need both. Per-set selection would allow tighter kernel
set declarations and is noted as a `TODO` in `shorewall_nft/nft/nfsets.py`.

**Acceptance criteria**:
- Each emitted nft set carries only the flags its backend mix requires.
- Regression test: a registry with one DNS-only and one ip-list-only entry emits two sets with
  different flags.

**Current state**: `TODO` comment in `nfsets.py:447`. Low priority — the current behaviour is
correct, just slightly over-declared for pure-DNS sets.

---

## M1 — Metric unsafe-rename backlog (P1 security audit)

From the W7b 13-row audit (2026-04-19): a set of existing metric names that use inconsistent or
legacy prefixes (`shorewall_nft_` vs `shorewalld_`) and could benefit from normalisation. All
were classified as "unsafe to rename" because renaming breaks existing dashboards and alerts.

**Rationale for deferral**: renaming Prometheus metric names is a breaking change. Any rename
requires a coordinated version bump, a deprecation period with both old and new names, and
consumer updates.

**Acceptance criteria for closing**:
- A migration guide is published (CHANGELOG section + docs/shorewalld/metrics.md note).
- Both old and new metric names are emitted for one release cycle.
- All internal dashboards / alert rules in this repo use the new names.
- The old names are removed in the following release.

**Current state**: Deferred indefinitely until a concrete consumer migration plan exists.

---

## M2 — shorewalld security hardening (P1 audit)

Source: `project_shorewalld_audit_todo.md` memory, 2026-04-19.

### M2-1: Read-RPC path allowlist (`nft_worker.py`)

The worker's `_handle_read` accepts any path from the parent. Adding a `ALLOWED_READ_PATHS`
frozenset (permitted `/proc/net/*` + `/proc/sys/net/*` entries) prevents accidental submission
of sensitive paths by a future collector.

**Effort**: ~3 h. **Acceptance**: negative test in `tests/test_daemon_read_rpc.py` asserting
`/etc/passwd` is rejected.

### M2-2: Peer UDP source-IP pinning (`peer.py`)

HMAC prevents tampering; an IP-address gate in `datagram_received` also defeats trivial floods.
Drop silently when `addr[0] != self._link._peer_host` and increment a
`peer_frames_dropped_src_mismatch_total` counter. Provide a config override for asymmetric-NAT
operators.

**Effort**: ~3 h incl. test.

### M2-3: PBDNS TCP + control-socket security docs (`docs/shorewalld/index.md`)

Add a **Security notes** section covering: PBDNS TCP has no transport auth (bind loopback or
restrict via firewall); control socket must be 0660/0600; peer HMAC is the only peer-link auth
(share secret out-of-band); recommended systemd sandboxing.

**Effort**: ~2 h.

### M2-4: systemd capability guidance (`docs/shorewalld/index.md`, `packaging/`)

Document minimum capabilities (`CAP_NET_ADMIN` + `CAP_SYS_ADMIN` for `setns`) plus
`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes` snippet. Verify the shipped unit
in `packaging/` matches.

**Effort**: ~2 h.

---

## M3 — shorewalld extensibility (P3 audit)

Source: `project_shorewalld_audit_todo.md` memory, 2026-04-19.

### M3-1: Control-socket handler registry (`core.py`, `control.py`)

Replace the ad-hoc verb dispatch in `core.py` with a `ControlHandlerRegistry` so subsystems
register their own verbs. Pattern: `iplist/providers/__init__.py`.  **Effort**: ~4 h.

### M3-2: Collector registry via entry points

Expose a `shorewalld.collectors` entry-point group so third parties can ship BPF / ipvs
collectors without patching. Depends on the new `collectors/` subpackage (landed in P2-1).
**Effort**: ~2 h.

---

## M4 — shorewalld simplification (P4 audit)

Source: `project_shorewalld_audit_todo.md` memory, 2026-04-19.

### M4-1: Drop custom Histogram / `_MetricFamily` fallbacks (`exporter.py`)

Make `prometheus_client` a hard `[daemon]` dep; delete the ~100-LOC fallback implementations.

### M4-2: Share socket-perm kwargs helper (`core.py`, `dnstap.py`)

Extract `Daemon._socket_perm_kwargs()` to eliminate the duplicated `{owner, group, mode}`
construction in two places.

### M4-3: Sanitise qnames on log emission

Strip `\x00-\x1f\x7f` from qnames before including them in log lines to prevent log-injection
when an attacker can influence DNS response data.  **Effort**: ~2 h.

---

## Cross-links

- [docs/features/nfsets.md](../features/nfsets.md) — operator reference for nfsets
- [docs/shorewalld/metrics.md](../shorewalld/metrics.md) — full Prometheus metric reference
- [docs/roadmap/index.md](index.md) — roadmap entry point
- `packages/shorewalld/CLAUDE.md` — shorewalld doctrine (performance, fork-after-load, element-refresh-expires)
