# nfsets — Roadmap (Shipped + Deferred Items)

**Audience**: developers
**Scope**: Backlog of planned nfsets capabilities and the shorewalld metric-surface audit items deferred from W7b (2026-04-19). N1–N5 and N6 are now fully shipped (W12–W21, 2026-04-21). Use this file as the entry point when picking up follow-on nfsets work.

---

## Table of contents

- [Shipped items (N1–N6)](#shipped-items-n1n6)
- [M1 — Metric unsafe-rename backlog (P1 security audit)](#m1--metric-unsafe-rename-backlog-p1-security-audit)
- [M2 — shorewalld security hardening (P1 audit)](#m2--shorewalld-security-hardening-p1-audit)
- [M3 — shorewalld extensibility (P3 audit)](#m3--shorewalld-extensibility-p3-audit)
- [M4 — shorewalld simplification (P4 audit)](#m4--shorewalld-simplification-p4-audit)

---

## Shipped items (N1–N6)

All N-items from the original deferred list are now implemented. History preserved below for roadmap readers.

| Item | Description | Commit |
|------|-------------|--------|
| N1 | SRV record resolution (`dnstype=srv`) | `0555dba54` |
| N2 | Inline `dns:` → `dnst:` rename (alias + deprecation) | `fad2459be` |
| N3 | `nfset:` / `dns:` / `dnst:` tokens in Masq, tcrules, and all per-table files | `fad2459be` |
| N4 | `<zone>:dnst:` pseudo-zone (clarified as part of dnst: alias rollout) | `fad2459be` |
| N5 | Per-set nft flags optimisation (per-group, not registry-wide) | `0555dba54` |
| N6 | Additive multi-backend per nfset name (same name, different backend coexist) | `0555dba54` |

---

### N1 — SRV record resolution (`dnstype=srv`) — SHIPPED `0555dba54`

**What shipped**: `DnsrGroup.dnstype` field; `PullResolver._resolve_qname` dispatches `"srv"` queries,
extracts `.target` dnames, recursively resolves A+AAAA. TTL = min(srv_ttl, child_ttl).
`MAX_SRV_TARGETS = 32` hard cap per RRset. 30 new tests (12 bridge + 18 pull-resolver SRV scenarios).

---

### N2 — Inline `dns:` → `dnst:` rename — SHIPPED `fad2459be`

**What shipped**: `dnst:` accepted everywhere `dns:` is accepted. `dns:` continues to work
as a deprecated alias with a compile-time `WARNING` logged once per config file.
Zone-prefixed `<zone>:dnst:name` and negated `!dnst:name` forms inherit automatically.

---

### N3 — `nfset:` in Masq and tcrules — SHIPPED `fad2459be`

**What shipped**: `nfset:` / `dns:` / `dnsr:` / `dnst:` tokens accepted in SOURCE column of
`masq` and `dnat`; SOURCE + DEST columns of `tcrules` / `mangle`; all of `blrules`,
`stoppedrules`, `notrack`, `conntrack`, `rawnat`, `ecn`, `arprules`, `accounting`.
Explicitly rejected on Masq ADDRESS and DNAT TARGET columns (with a clear `ValueError`).

---

### N4 — `zone:dnst:` pseudo-zone behaviour — SHIPPED `fad2459be`

**What shipped**: `<zone>:dnst:hostname` resolves in rules to the `dns_<sanitized>_v4/v6`
sets populated via dnstap — parallel to `zone:dnsr:` for resolver-backed sets.
Documented in `shorewall-nft-rules.5` as part of the `dnst:` alias rollout.

---

### N5 — Per-set nft flags optimisation — SHIPPED `0555dba54`

**What shipped**: `emit_nfset_declarations` groups entries by `(name, family)` and computes
flags per group. Pure-DNS → `flags timeout`. Pure-iplist → `flags interval`.
Mixed → `flags timeout, interval`. The `TODO` comment in `nfsets.py` is removed.

---

### N6 — Additive multi-backend per nfset name — SHIPPED `0555dba54`

**What shipped**: `build_nfset_registry` merge key changed from `name` to `(name, backend)`.
Same-name rows with different backends coexist in `registry.entries`; `set_names` deduplicates.
Each backend-specific tracker feeds its own pipeline; all write to the same nft set name.

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
