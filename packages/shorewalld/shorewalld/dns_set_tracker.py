"""In-memory single source of truth for DNS-backed nft set contents.

The tracker owns three things:

1. **The compiled allowlist** — a stable integer ID per ``(qname, family)``
   so every downstream code path (batch builder, worker IPC, state file)
   can key on small integers instead of sanitised strings. IDs are
   assigned deterministically in ``qname + family`` sort order so two
   processes with the same allowlist agree on the mapping without
   explicit synchronisation.

2. **Live set state** — for each known ``(set_id, ip_bytes)`` the
   monotonic deadline when the entry expires. Writes go through
   :meth:`propose`, which returns one of three verdicts:

   * ``ADD`` — new entry or significant extension, push to the worker
   * ``REFRESH`` — existing entry got a longer TTL, push to the worker
   * ``DEDUP`` — existing entry still has ≥50% of the new TTL left,
     skip the write entirely

3. **Metric counters** — per ``(set_id, family)`` running totals for
   adds/dedup_hits/dedup_misses/refreshes/expiries. The exporter
   reads these via lock-free :meth:`snapshot` so the Prometheus
   scrape thread never touches the hot write path.

Design notes:

* The tracker is **thread-safe**. Decoder threads call :meth:`propose`
  concurrently; the SetWriter coroutine calls :meth:`commit` after the
  worker acknowledges a batch. Both paths share one
  :class:`threading.Lock` whose critical section is a handful of dict
  lookups — microseconds at realistic rates.
* The tracker does **not** talk to libnftables. It is pure state. The
  SetWriter decides when to emit batches and whose job it is to
  actually mutate the kernel. On worker-ack, SetWriter calls
  :meth:`commit` to confirm the writes. If a worker crashes mid-flight
  the SetWriter reverts its pending list and propose() is free to
  re-emit the same entries.
* IP addresses are stored as raw ``bytes`` — 4 bytes for v4, 16 for
  v6. Never as Python strings. That keeps the dict keys compact and
  comparable without conversion.
"""

from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable

from shorewall_nft.nft.dns_sets import DnsSetRegistry, DnsSetSpec

from .exporter import CollectorBase, _MetricFamily

# Family constants — used as wire values in the batch codec too, so
# they must stay stable. 4 and 6 read obviously in hex dumps.
FAMILY_V4 = 4
FAMILY_V6 = 6

# How much of the existing deadline must remain for a new answer to
# be considered a duplicate. 0.5 means "if the current entry still
# has >=50% of the proposed TTL left, skip the write". Operators can
# tune via the ``DNS_DEDUP_REFRESH_THRESHOLD`` shorewall.conf knob.
DEFAULT_REFRESH_THRESHOLD = 0.5


class Verdict(enum.IntEnum):
    """What the SetWriter should do with a proposed element."""
    ADD = 1       # New entry → push to worker
    REFRESH = 2   # Existing entry needs longer timeout → push to worker
    DEDUP = 3     # Skip, cached deadline is good enough


@dataclass
class SetMetrics:
    """Counter bundle for one managed set, one family.

    All counters are monotonic within the daemon's lifetime. The
    exporter emits them as Prometheus counters (``_total`` suffix)
    and the ``size`` / ``last_update_age_seconds`` as gauges.
    """
    elements: int = 0              # current live element count
    adds_total: int = 0            # real writes (ADD verdicts)
    refreshes_total: int = 0       # real writes (REFRESH verdicts)
    dedup_hits_total: int = 0      # DEDUP verdicts
    dedup_misses_total: int = 0    # ADD + REFRESH verdicts combined
    expiries_total: int = 0        # entries that aged out naturally
    last_update_mono: float = 0.0  # monotonic clock at last write


@dataclass
class _SetState:
    """Per-set tracking data, keyed on the compiled set_id."""
    spec: DnsSetSpec
    family: int
    # Raw ip bytes → monotonic expiry deadline
    elements: dict[bytes, float] = field(default_factory=dict)
    metrics: SetMetrics = field(default_factory=SetMetrics)


@dataclass(frozen=True)
class Proposal:
    """A single ``(set_id, ip_bytes, ttl)`` update being considered.

    Decoder threads build these straight from protobuf frames.
    ``ip_bytes`` is 4 bytes for v4, 16 for v6 — the caller is
    responsible for passing the right length for the target set's
    family. The tracker does not convert.
    """
    set_id: int
    ip_bytes: bytes
    ttl: int


@dataclass(frozen=True)
class TrackerSnapshot:
    """Point-in-time view of the tracker for the metric exporter.

    Copied under the lock so readers get a consistent image even
    if writes race. Light enough (< a few hundred ints) that the
    copy cost is negligible at Prometheus scrape frequency.
    """
    per_set: dict[tuple[int, int], SetMetrics]
    per_set_names: dict[int, str]
    totals: SetMetrics
    sets_declared: int
    unknown_qname_total: int
    allowlist_generation: int


class DnsSetTracker:
    """Central state + dedup + metrics owner.

    Lifetime is the whole daemon process. Thread-safe — the decoder
    pool propose()s from N threads, the SetWriter coroutine
    commit()s from the event loop, the exporter snapshot()s from
    the prometheus scrape thread. One lock guards them all; its
    critical section is a few dict lookups.
    """

    def __init__(
        self,
        *,
        refresh_threshold: float = DEFAULT_REFRESH_THRESHOLD,
        clock: "callable[[], float]" = time.monotonic,
    ) -> None:
        self._refresh_threshold = float(refresh_threshold)
        self._clock = clock
        self._lock = threading.Lock()
        self._states: dict[int, _SetState] = {}
        # Reverse lookup: (qname, family) → set_id
        self._by_name: dict[tuple[str, int], int] = {}
        # Forward lookup: set_id → (qname, family) for state file export
        self._by_id: dict[int, tuple[str, int]] = {}
        self._next_id = 1
        self._allowlist_generation = 0
        self._unknown_qname_total = 0
        self._dropped_oversize_total = 0

    # ── allowlist management ─────────────────────────────────────────

    def load_registry(self, registry: DnsSetRegistry) -> bool:
        """Install (or replace) the compiled allowlist.

        Called at startup from the compiled-allowlist file and again
        on control-socket reload. Assigns a stable integer
        set_id per ``(effective_set_name, family)`` group in deterministic
        sort order so two shorewalld processes serving the same compiled
        file agree on the mapping without explicit negotiation.

        **N→1 grouping**: when a :class:`~shorewall_nft.nft.dns_sets.DnsSetSpec`
        carries a non-``None`` ``set_name``, multiple qnames that share the
        same ``(set_name, family)`` are mapped to a single ``set_id``.  Their
        resolved IPs all flow into the same nft set.  Qnames whose ``set_name``
        is ``None`` each get their own ``set_id`` (identical to the old
        behaviour).

        Any prior state for hostnames still in the registry is
        preserved — only removed hostnames lose their cached entries.

        Returns ``True`` if any new set_ids were allocated (i.e. qnames
        were added that weren't in the previous registry).  Callers that
        maintain a forked worker whose set-name lookup table was snapshotted
        at fork time must respawn that worker so it sees the new names.
        """
        from shorewall_nft.nft.dns_sets import qname_to_set_name

        with self._lock:
            desired: dict[tuple[str, int], DnsSetSpec] = {}
            for spec in registry.iter_sorted():
                desired[(spec.qname, FAMILY_V4)] = spec
                desired[(spec.qname, FAMILY_V6)] = spec

            # Build the mapping: (effective_set_name, family) → representative
            # spec. Used to assign one set_id per group.  For qnames without a
            # set_name override the effective name is the auto-derived
            # qname_to_set_name(), which is unique per qname — exactly the old
            # behaviour.
            # group_key → (representative_spec, sorted list of (qname, family) keys)
            group_key_to_spec: dict[tuple[str, int], DnsSetSpec] = {}
            group_key_to_members: dict[tuple[str, int], list[tuple[str, int]]] = {}
            for (qname, family), spec in sorted(desired.items()):
                if spec.set_name is not None:
                    eff_name = spec.set_name
                else:
                    fam_str = "v4" if family == FAMILY_V4 else "v6"
                    eff_name = qname_to_set_name(qname, fam_str)
                gk = (eff_name, family)
                if gk not in group_key_to_spec:
                    group_key_to_spec[gk] = spec
                    group_key_to_members[gk] = []
                group_key_to_members[gk].append((qname, family))

            # Evict (qname, family) keys that are no longer desired.
            to_evict = [
                (qn, fam) for (qn, fam) in list(self._by_name)
                if (qn, fam) not in desired
            ]
            for key in to_evict:
                set_id = self._by_name.pop(key)
                # Only drop the _SetState if NO remaining (qname, family)
                # entries still point to this set_id (N→1 sharing).
                still_used = any(
                    sid == set_id for sid in self._by_name.values()
                )
                if not still_used:
                    self._by_id.pop(set_id, None)
                    self._states.pop(set_id, None)

            # Assign / reuse set_ids for each group in deterministic order.
            new_names_added = False
            for gk in sorted(group_key_to_spec):
                rep_spec = group_key_to_spec[gk]
                members = group_key_to_members[gk]
                eff_name, family = gk

                # Find an existing set_id for this group (any member that is
                # already tracked).
                existing_sid: int | None = None
                for member_key in members:
                    sid = self._by_name.get(member_key)
                    if sid is not None:
                        existing_sid = sid
                        break

                if existing_sid is not None:
                    # Reuse the existing set_id; refresh the spec.
                    state = self._states.get(existing_sid)
                    if state is not None:
                        state.spec = rep_spec
                    # Wire any new members that aren't yet in _by_name.
                    for member_key in members:
                        if member_key not in self._by_name:
                            self._by_name[member_key] = existing_sid
                            new_names_added = True
                else:
                    # New group — allocate a fresh set_id and wire all members.
                    set_id = self._next_id
                    self._next_id += 1
                    # Use the first member as the canonical _by_id entry so
                    # snapshot() / name_for() returns a stable qname.
                    canonical_member = members[0]
                    self._by_id[set_id] = canonical_member
                    self._states[set_id] = _SetState(
                        spec=rep_spec,
                        family=family,
                    )
                    for member_key in members:
                        self._by_name[member_key] = set_id
                    new_names_added = True

            self._allowlist_generation += 1
            return new_names_added

    def set_id_for(self, qname: str, family: int) -> int | None:
        """Look up the compiled ID for a qname + family, or ``None``
        if the name is not in the allowlist."""
        with self._lock:
            return self._by_name.get((qname, family))

    def set_ids_for_qnames(self, qnames: Iterable[str]) -> list[int]:
        """Return every set_id currently mapped to any of *qnames*
        (both families). Used by InstanceManager to scope element-cache
        invalidation to one instance's qnames without touching others."""
        with self._lock:
            out: list[int] = []
            for qname in qnames:
                for family in (FAMILY_V4, FAMILY_V6):
                    sid = self._by_name.get((qname, family))
                    if sid is not None:
                        out.append(sid)
            return out

    def clear_elements(self, set_ids: Iterable[int]) -> int:
        """Drop every cached ``(ip_bytes, deadline)`` for the given set_ids.

        Called when we know the kernel's copy of these sets has been
        wiped (typically on ``shorewall-nft restart`` → table deleted +
        recreated).  Without this, ``propose()`` would keep returning
        ``DEDUP`` for IPs whose cached deadline is still in the future,
        leaving the fresh kernel set empty until the TTL elapses.

        Set-state (spec, family, metrics counters) is preserved — only
        the live-element dict is cleared.  Returns the number of elements
        dropped (handy for the caller's log line)."""
        dropped = 0
        with self._lock:
            for sid in set_ids:
                state = self._states.get(sid)
                if state is None:
                    continue
                dropped += len(state.elements)
                state.elements.clear()
                state.metrics.elements = 0
        return dropped

    def name_for(self, set_id: int) -> tuple[str, int] | None:
        """Reverse lookup: ``set_id`` → ``(qname, family)`` or ``None``."""
        with self._lock:
            return self._by_id.get(set_id)

    def add_qname_alias(
        self,
        alias_qname: str,
        primary_qname: str,
        family: int,
    ) -> bool:
        """Map ``alias_qname`` to the same set_id as ``primary_qname``.

        Called after :meth:`load_registry` to wire secondary hostnames
        from ``dnsr:`` groups into the tap pipeline.  When the dnstap or
        pbdns decoder sees a DNS answer for ``alias_qname``, it resolves
        it to ``set_id_for(alias_qname, family)`` which now points at the
        primary's set — so the answer populates the same nft set without
        any changes to the decoder hot path.

        Returns ``True`` if the alias was installed, ``False`` if the
        primary is not (yet) in the allowlist.
        """
        with self._lock:
            primary_id = self._by_name.get((primary_qname, family))
            if primary_id is None:
                return False
            self._by_name[(alias_qname, family)] = primary_id
            return True

    def note_unknown_qname(self) -> None:
        """Counter bump for decoder pre-filter rejections.

        Exposed as ``shorewalld_dns_unknown_qname_total``. Called
        from the decoder's two-pass filter when a qname is not in
        the allowlist — very hot path, so just an int increment.
        """
        with self._lock:
            self._unknown_qname_total += 1

    # ── hot-path: propose + commit ───────────────────────────────────

    def propose(self, prop: Proposal) -> Verdict:
        """Consult the cache and decide the verdict for a proposal.

        * Unknown ``set_id`` → returns ``DEDUP`` (drop silently —
          happens during reload windows before load_registry has
          caught up).
        * TTL clamped to the spec's floor/ceil before comparison.
        * Deadline comparison decides ``ADD`` vs ``REFRESH`` vs
          ``DEDUP``.

        Verdict is advisory — the SetWriter still decides batching.
        The tracker only updates its own state when the SetWriter
        confirms success via :meth:`commit`.
        """
        now = self._clock()
        with self._lock:
            state = self._states.get(prop.set_id)
            if state is None:
                return Verdict.DEDUP

            spec = state.spec
            ttl = max(spec.ttl_floor, min(prop.ttl, spec.ttl_ceil))
            new_deadline = now + ttl
            existing = state.elements.get(prop.ip_bytes)

            if existing is None:
                return Verdict.ADD
            # Existing — decide refresh vs dedup.
            remaining = existing - now
            if remaining >= self._refresh_threshold * ttl:
                state.metrics.dedup_hits_total += 1
                return Verdict.DEDUP
            if new_deadline <= existing:
                # Proposed TTL would shorten the entry; never do that.
                state.metrics.dedup_hits_total += 1
                return Verdict.DEDUP
            return Verdict.REFRESH

    def commit(
        self,
        proposals: Iterable[Proposal],
        verdicts: Iterable[Verdict],
    ) -> None:
        """Mark the given proposals as successfully applied.

        Called by the SetWriter after the worker acks a batch.
        Updates the in-memory cache and metric counters in one
        critical section. Iterables are consumed together in lock-step.
        """
        now = self._clock()
        with self._lock:
            for prop, verdict in zip(proposals, verdicts):
                state = self._states.get(prop.set_id)
                if state is None:
                    continue
                spec = state.spec
                ttl = max(
                    spec.ttl_floor, min(prop.ttl, spec.ttl_ceil))
                deadline = now + ttl
                if verdict == Verdict.ADD:
                    state.elements[prop.ip_bytes] = deadline
                    state.metrics.elements = len(state.elements)
                    state.metrics.adds_total += 1
                    state.metrics.dedup_misses_total += 1
                    state.metrics.last_update_mono = now
                elif verdict == Verdict.REFRESH:
                    state.elements[prop.ip_bytes] = deadline
                    state.metrics.refreshes_total += 1
                    state.metrics.dedup_misses_total += 1
                    state.metrics.last_update_mono = now
                # DEDUP: nothing to do, propose() already bumped
                # dedup_hits_total under the same lock.

    def prune_expired(self) -> int:
        """Drop entries whose deadline has passed.

        Called periodically by the SetWriter (or on state-file save)
        so the in-memory cache stays bounded. Returns the number of
        entries removed. The kernel-side nft set already expires them
        autonomously via its ``flags timeout``; this is just the
        in-process shadow copy catching up.
        """
        now = self._clock()
        removed = 0
        with self._lock:
            for state in self._states.values():
                dead = [
                    ip for ip, deadline in state.elements.items()
                    if deadline <= now
                ]
                for ip in dead:
                    del state.elements[ip]
                state.metrics.elements = len(state.elements)
                state.metrics.expiries_total += len(dead)
                removed += len(dead)
        return removed

    # ── exporter read path ───────────────────────────────────────────

    def shared_qname_counts(self) -> dict[tuple[str, str], int]:
        """Return count of qnames feeding each ``(set_name, family)`` group.

        Keyed by ``(canonical_set_name, family_str)`` where *family_str* is
        ``"ipv4"`` or ``"ipv6"``.  The canonical set name is the qname of
        the first member assigned to that set_id (as stored in ``_by_id``).

        Value is the number of ``(qname, family)`` pairs in ``_by_name``
        that map to the same set_id.  A value > 1 indicates active N→1
        grouping — multiple qnames feeding one nft set.

        Called by :class:`~shorewalld.collectors.nfsets.NfsetsCollector`
        at scrape time to emit ``shorewalld_dns_set_shared_qnames``.  Using
        this method avoids direct access to private attributes.

        Returns an empty dict when no registry has been loaded.
        """
        with self._lock:
            counts_by_sid: dict[tuple[int, str], int] = {}
            for (_, family), sid in self._by_name.items():
                fam_str = "ipv4" if family == FAMILY_V4 else "ipv6"
                key = (sid, fam_str)
                counts_by_sid[key] = counts_by_sid.get(key, 0) + 1

            result: dict[tuple[str, str], int] = {}
            for (sid, fam_str), count in counts_by_sid.items():
                canonical = self._by_id.get(sid)
                if canonical is None:
                    continue
                set_name = canonical[0]
                result[(set_name, fam_str)] = count
        return result

    def snapshot(self) -> TrackerSnapshot:
        """Return a copy of the metric state for the Prometheus scrape.

        Lock-held copy — O(number of managed sets), typically tiny.
        The copy is a detached dict so the scrape thread never holds
        the lock while serialising metric families.
        """
        with self._lock:
            per_set: dict[tuple[int, int], SetMetrics] = {}
            per_set_names: dict[int, str] = {}
            totals = SetMetrics()
            for set_id, state in self._states.items():
                m = state.metrics
                # Return a copy so callers can't mutate our state.
                per_set[(set_id, state.family)] = SetMetrics(
                    elements=m.elements,
                    adds_total=m.adds_total,
                    refreshes_total=m.refreshes_total,
                    dedup_hits_total=m.dedup_hits_total,
                    dedup_misses_total=m.dedup_misses_total,
                    expiries_total=m.expiries_total,
                    last_update_mono=m.last_update_mono,
                )
                entry = self._by_id.get(set_id)
                if entry is not None:
                    per_set_names[set_id] = entry[0]
                totals.elements += m.elements
                totals.adds_total += m.adds_total
                totals.refreshes_total += m.refreshes_total
                totals.dedup_hits_total += m.dedup_hits_total
                totals.dedup_misses_total += m.dedup_misses_total
                totals.expiries_total += m.expiries_total
            return TrackerSnapshot(
                per_set=per_set,
                per_set_names=per_set_names,
                totals=totals,
                sets_declared=len(self._states),
                unknown_qname_total=self._unknown_qname_total,
                allowlist_generation=self._allowlist_generation,
            )

    # ── seed support ─────────────────────────────────────────────────

    def snapshot_qnames(
        self, qnames: Iterable[str]
    ) -> list[tuple[str, int, bytes, int]]:
        """Return live entries for *qnames* as ``(qname, family, ip_bytes, ttl_remaining)``.

        ``ttl_remaining`` is in whole seconds; entries whose deadline has
        already passed are omitted.  Used read-only by SeedCoordinator —
        does not mutate any state.
        """
        now = self._clock()
        out: list[tuple[str, int, bytes, int]] = []
        with self._lock:
            for qname in qnames:
                for family in (FAMILY_V4, FAMILY_V6):
                    set_id = self._by_name.get((qname, family))
                    if set_id is None:
                        continue
                    state = self._states.get(set_id)
                    if state is None:
                        continue
                    for ip_bytes, deadline in state.elements.items():
                        remaining = deadline - now
                        if remaining > 0:
                            out.append((qname, family, ip_bytes, int(remaining)))
        return out

    # ── state-file persistence support ───────────────────────────────

    def export_state(self) -> list[tuple[str, int, bytes, float]]:
        """Serialise live entries for the persistence file.

        Returns a flat list of ``(qname, family, ip_bytes, deadline)``
        tuples ordered by ``(qname, family, ip_bytes)``. Deadlines are
        monotonic timestamps — Phase 6 converts them to absolute wall
        time before writing so the loader can compensate for monotonic
        clock resets on reboot.
        """
        out: list[tuple[str, int, bytes, float]] = []
        with self._lock:
            for set_id, state in self._states.items():
                key = self._by_id.get(set_id)
                if key is None:
                    continue
                qname, family = key
                for ip_bytes, deadline in state.elements.items():
                    out.append((qname, family, ip_bytes, deadline))
        out.sort(key=lambda x: (x[0], x[1], x[2]))
        return out

    def import_state(
        self,
        entries: Iterable[tuple[str, int, bytes, float]],
        now: float | None = None,
    ) -> int:
        """Populate the tracker from a Phase 6 state-file snapshot.

        Entries with ``deadline <= now`` are silently dropped (they
        would expire immediately anyway). Returns the number of
        entries actually installed.
        """
        if now is None:
            now = self._clock()
        installed = 0
        with self._lock:
            for qname, family, ip_bytes, deadline in entries:
                if deadline <= now:
                    continue
                set_id = self._by_name.get((qname, family))
                if set_id is None:
                    # Hostname dropped from allowlist since save —
                    # skip, Phase 6 will count it as an "expired"
                    # load entry for the metric.
                    continue
                state = self._states[set_id]
                state.elements[ip_bytes] = deadline
                state.metrics.elements = len(state.elements)
                installed += 1
        return installed


# ── Prometheus collector ─────────────────────────────────────────────


class DnsSetMetricsCollector(CollectorBase):
    """Per-(set, family) metrics for DNS-backed nft sets.

    Reads :class:`DnsSetTracker` state via :meth:`snapshot` — lock-held
    copy, O(n_sets), safe for the Prometheus scrape thread. Emits one
    sample per ``(qname, family)`` for each declared set:

    * ``shorewalld_dns_set_elements`` — current live element count
    * ``shorewalld_dns_set_adds_total`` / ``_refreshes_total`` —
      real writes split by verdict
    * ``shorewalld_dns_set_dedup_hits_total`` / ``_misses_total`` —
      dedup ratio numerator / denominator (misses == adds+refreshes)
    * ``shorewalld_dns_set_expiries_total`` — entries aged out naturally
    * ``shorewalld_dns_set_last_update_age_seconds`` — ``now -
      last_update_mono`` (omitted for sets that never saw a write)

    The tracker is daemon-global (one instance per process) so metrics
    carry no ``netns`` label — a single qname's totals aggregate all
    netns it routes to. For per-netns volume breakdown, correlate with
    ``shorewalld_worker_batches_applied_total`` (labelled by netns).
    """

    _LABELS = ["set", "family"]

    def __init__(self, tracker: "DnsSetTracker") -> None:
        super().__init__(netns="")
        self._tracker = tracker
        # Share the tracker's clock source so unit tests that inject
        # a fake monotonic see deterministic age values.
        self._clock = tracker._clock

    def collect(self) -> list[_MetricFamily]:
        elements = _MetricFamily(
            "shorewalld_dns_set_elements",
            "Current live element count per DNS-backed nft set",
            self._LABELS)
        adds = _MetricFamily(
            "shorewalld_dns_set_adds_total",
            "ADD verdicts: new IP inserted into the set",
            self._LABELS, mtype="counter")
        refreshes = _MetricFamily(
            "shorewalld_dns_set_refreshes_total",
            "REFRESH verdicts: existing IP's TTL extended",
            self._LABELS, mtype="counter")
        dedup_hits = _MetricFamily(
            "shorewalld_dns_set_dedup_hits_total",
            "DEDUP verdicts: proposal skipped, existing TTL still covers",
            self._LABELS, mtype="counter")
        dedup_misses = _MetricFamily(
            "shorewalld_dns_set_dedup_misses_total",
            "Proposals that became real writes (ADD + REFRESH combined)",
            self._LABELS, mtype="counter")
        expiries = _MetricFamily(
            "shorewalld_dns_set_expiries_total",
            "Entries evicted from the set because their deadline passed",
            self._LABELS, mtype="counter")
        last_age = _MetricFamily(
            "shorewalld_dns_set_last_update_age_seconds",
            "Seconds since the last write to this set (omitted if never written)",
            self._LABELS)

        snap = self._tracker.snapshot()
        now = self._clock()
        for (set_id, family), m in snap.per_set.items():
            qname = snap.per_set_names.get(set_id)
            if qname is None:
                # Set was evicted between snapshot build and name lookup
                # — skip rather than emit an unresolvable set_id.
                continue
            fam_label = "ipv4" if family == FAMILY_V4 else (
                "ipv6" if family == FAMILY_V6 else f"af{family}")
            labels = [qname, fam_label]
            elements.add(labels, float(m.elements))
            adds.add(labels, float(m.adds_total))
            refreshes.add(labels, float(m.refreshes_total))
            dedup_hits.add(labels, float(m.dedup_hits_total))
            dedup_misses.add(labels, float(m.dedup_misses_total))
            expiries.add(labels, float(m.expiries_total))
            if m.last_update_mono > 0.0:
                last_age.add(labels, float(now - m.last_update_mono))

        return [
            elements, adds, refreshes, dedup_hits, dedup_misses,
            expiries, last_age,
        ]
