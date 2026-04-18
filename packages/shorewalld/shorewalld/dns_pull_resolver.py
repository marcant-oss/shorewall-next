"""Active DNS pull resolver for ``dnsr:`` rule groups.

Resolves hostnames from the ``[dnsr]`` compiled-allowlist section
periodically, respecting TTL, and feeds results through the existing
tracker + setwriter pipeline so they land in the same ``dns_*`` nft sets
as tap-acquired entries.

Design constraints (from CLAUDE.md performance doctrine):
* Pure asyncio — no extra threads; runs on the daemon's event loop.
* Min-heap of ``(next_resolve_at, primary_qname)`` entries, ordered
  by earliest deadline. ``_primaries`` is the source of truth for
  which groups are active; heap entries for removed groups are
  silently dropped when popped.
* Sleep is interruptible via ``asyncio.Event`` so manual refresh() takes
  effect immediately without waiting for the current sleep to expire.
* A + AAAA queries for all qnames in a group are issued in parallel
  (``asyncio.gather``). Multiple due groups are resolved concurrently
  under a semaphore so the startup burst doesn't serialise.
* SetWriter.submit() handles dedup — no separate pre-check needed here.
* Error paths: NXDOMAIN → log.info, timeout/SERVFAIL → log.warning,
  both rate-limited per-qname, and reschedule at ``min_retry`` so a
  transient failure doesn't stall the heap entry indefinitely.
* All logging is per-group-resolve or per-error, never per-IP, and
  recurring NXDOMAIN/failure lines go through the shared RateLimiter.
* In-flight resolves are tracked so refresh()/update_registry() never
  silently miss or duplicate a group that is currently being resolved.
"""

from __future__ import annotations

import asyncio
import heapq
import ipaddress
import logging
import random
import time
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver
from shorewall_nft.nft.dns_sets import DnsrGroup, DnsrRegistry

from .dns_set_tracker import FAMILY_V4, FAMILY_V6, DnsSetTracker, Proposal
from .exporter import CollectorBase, _MetricFamily
from .logsetup import get_rate_limiter
from .setwriter import SetWriter


@dataclass
class PullResolverMetrics:
    resolves_total: int = 0
    resolve_errors_total: int = 0
    nxdomain_total: int = 0
    entries_submitted_total: int = 0

log = logging.getLogger(__name__)

DEFAULT_MAX_TTL = 3600          # cap: never sleep longer than 1 hour
DEFAULT_MIN_RETRY = 30          # floor on retry after NXDOMAIN / error
DEFAULT_RESOLVE_FRACTION = 0.8  # re-resolve at 80% of min-TTL expiry
DEFAULT_JITTER = 0.1            # ±10% jitter on re-resolve deadline
DEFAULT_CONCURRENCY = 8         # max in-flight resolves
DEFAULT_DNS_TIMEOUT = 3.0       # per-query DNS lifetime (seconds)


@dataclass(order=True)
class _Entry:
    """Min-heap entry — ordered by next resolve deadline."""
    next_at: float
    primary_qname: str = field(compare=False)


class PullResolver:
    """Asyncio task that keeps ``dnsr:`` nft sets populated via active DNS.

    One instance per daemon; shared tracker and writer with the tap pipeline.
    Lifetime is managed by :class:`~shorewalld.core.Daemon` which calls
    :meth:`start` and :meth:`shutdown`.
    """

    def __init__(
        self,
        dnsr_registry: DnsrRegistry,
        tracker: DnsSetTracker,
        writer: SetWriter,
        *,
        default_netns: str = "",
        max_ttl: int = DEFAULT_MAX_TTL,
        min_retry: int = DEFAULT_MIN_RETRY,
        nameservers: list[str] | None = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        dns_timeout: float = DEFAULT_DNS_TIMEOUT,
        jitter: float = DEFAULT_JITTER,
    ) -> None:
        self._tracker = tracker
        self._writer = writer
        self._netns = default_netns
        self._max_ttl = max_ttl
        self._min_retry = min_retry
        self._jitter = max(0.0, jitter)
        self._stopping = False
        self._task: asyncio.Task | None = None

        # Source of truth for which groups are active. Heap entries for
        # primaries not in this dict are dropped on pop. Tap-only groups
        # (pull_enabled=False, created by multi-host ``dns:`` tokens)
        # are handled by the tracker alias path alone — we never pull
        # them.
        self._primaries: dict[str, DnsrGroup] = {
            g.primary_qname: g
            for g in dnsr_registry.iter_sorted()
            if g.pull_enabled
        }
        # Primaries currently mid-resolve. refresh()/update_registry()
        # coordinate with the run loop via this set and _refresh_pending.
        self._in_flight: set[str] = set()
        # Primaries whose resolve was requested while in-flight — the
        # run loop re-queues them at next_at=now as soon as their
        # current pass completes.
        self._refresh_pending: set[str] = set()

        # Min-heap: resolve every group immediately on startup.
        now = time.monotonic()
        self._heap: list[_Entry] = [
            _Entry(next_at=now, primary_qname=name)
            for name in self._primaries
        ]
        heapq.heapify(self._heap)

        # Interrupt the current sleep on refresh() calls.
        self._wake = asyncio.Event()

        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = dns_timeout
        self._resolver.timeout = dns_timeout
        if nameservers:
            self._resolver.nameservers = nameservers

        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._rate_limiter = get_rate_limiter()
        self.metrics = PullResolverMetrics()

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Spawn the resolver loop as a background asyncio task."""
        self._task = asyncio.ensure_future(self._run())

    async def shutdown(self) -> None:
        """Stop the resolver loop and await task completion."""
        self._stopping = True
        self._wake.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None

    # ── control socket handler ────────────────────────────────────────────

    async def refresh(self, primary_qname: str | None = None) -> int:
        """Reschedule one or all groups for immediate re-resolve.

        Called from the control socket ``refresh-dns`` handler.
        Returns the number of entries rescheduled (heap + in-flight).
        In-flight groups are marked via ``_refresh_pending`` so they
        are re-queued as soon as their current pass completes, rather
        than silently missing the refresh.
        """
        now = time.monotonic()
        if primary_qname is not None:
            targets = {primary_qname} & (
                set(self._primaries) | self._in_flight
            )
        else:
            targets = set(self._primaries) | self._in_flight

        count = 0
        seen_in_heap: set[str] = set()
        new_heap: list[_Entry] = []
        for entry in self._heap:
            if entry.primary_qname in targets:
                new_heap.append(_Entry(
                    next_at=now, primary_qname=entry.primary_qname,
                ))
                seen_in_heap.add(entry.primary_qname)
                count += 1
            else:
                new_heap.append(entry)
        heapq.heapify(new_heap)
        self._heap = new_heap

        for name in targets - seen_in_heap:
            if name in self._in_flight:
                self._refresh_pending.add(name)
                count += 1

        self._wake.set()
        log.info("pull_resolver: refresh triggered (%d group(s))", count)
        return count

    async def update_registry(self, dnsr_registry: DnsrRegistry) -> None:
        """Replace active groups with those from *dnsr_registry*.

        Preserves existing heap entries' ``next_at`` for unchanged
        primaries (no thundering-herd re-resolve on reload). New
        primaries are scheduled immediately. Removed primaries are
        dropped from ``_primaries`` — their heap entry (if any) is
        silently skipped when popped, and an in-flight resolve for a
        removed primary is not rescheduled. Asyncio single-threaded —
        no lock needed.
        """
        new_primaries = {
            g.primary_qname: g
            for g in dnsr_registry.iter_sorted()
            if g.pull_enabled
        }
        now = time.monotonic()

        # Schedule primaries that aren't already in the heap or in-flight.
        in_heap = {e.primary_qname for e in self._heap}
        known = in_heap | self._in_flight
        for name in new_primaries:
            if name not in known:
                heapq.heappush(
                    self._heap, _Entry(next_at=now, primary_qname=name),
                )

        self._primaries = new_primaries
        # Drop refresh-pending markers for primaries that no longer
        # exist so the run loop doesn't re-queue ghost entries.
        self._refresh_pending &= set(new_primaries)
        self._wake.set()
        log.info(
            "pull_resolver: registry updated (%d group(s))",
            len(new_primaries),
        )

    @property
    def group_count(self) -> int:
        return len(self._primaries)

    # ── internal loop ────────────────────────────────────────────────────

    async def _run(self) -> None:
        while not self._stopping:
            if not self._heap:
                # No work — wait on _wake so refresh()/update_registry
                # wakes us immediately when a group appears.
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=60.0)
                except asyncio.TimeoutError:
                    pass
                continue

            now = time.monotonic()
            wait = self._heap[0].next_at - now
            if wait > 0:
                self._wake.clear()
                try:
                    await asyncio.wait_for(
                        self._wake.wait(), timeout=wait)
                except asyncio.TimeoutError:
                    pass

            if self._stopping:
                break

            now = time.monotonic()
            due: list[_Entry] = []
            while self._heap and self._heap[0].next_at <= now:
                entry = heapq.heappop(self._heap)
                # Drop entries for primaries that are no longer active
                # (removed via update_registry since this entry was
                # scheduled).
                if entry.primary_qname not in self._primaries:
                    continue
                # Skip if already in-flight; a concurrent refresh may
                # have duplicated the entry.
                if entry.primary_qname in self._in_flight:
                    continue
                self._in_flight.add(entry.primary_qname)
                due.append(entry)

            if not due:
                continue

            # Resolve due groups concurrently but bounded by the
            # semaphore so we never hammer the upstream resolver.
            await asyncio.gather(
                *(self._resolve_and_requeue(e) for e in due),
                return_exceptions=True,
            )

    async def _resolve_and_requeue(self, entry: _Entry) -> None:
        """Resolve one group and re-push its heap entry.

        The semaphore bounds concurrent in-flight resolves. Always
        clears ``_in_flight`` and honours ``_refresh_pending`` even on
        exception so a broken group can't wedge the run loop.
        """
        try:
            async with self._sem:
                group = self._primaries.get(entry.primary_qname)
                if group is None:
                    return
                next_at = await self._resolve_group(group)
        except Exception:
            log.exception(
                "pull_resolver: group %s resolve crashed",
                entry.primary_qname,
            )
            next_at = time.monotonic() + self._min_retry
        finally:
            self._in_flight.discard(entry.primary_qname)

        # Only reschedule if the group is still active. If a refresh
        # came in while we were resolving, re-queue immediately.
        if entry.primary_qname not in self._primaries:
            return
        if entry.primary_qname in self._refresh_pending:
            self._refresh_pending.discard(entry.primary_qname)
            next_at = time.monotonic()
        heapq.heappush(
            self._heap,
            _Entry(next_at=next_at, primary_qname=entry.primary_qname),
        )
        self._wake.set()

    async def _resolve_group(self, group: DnsrGroup) -> float:
        """Resolve all qnames in group; submit IPs to tracker+writer.

        Returns the monotonic timestamp for the next resolve.
        """
        tasks = [
            self._resolve_qname(q, group.ttl_floor, group.ttl_ceil)
            for q in group.qnames
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        min_ttl = group.ttl_ceil
        has_results = False

        for qname, result in zip(group.qnames, results):
            if isinstance(result, Exception):
                self._rate_limiter.warn(
                    log, ("resolve_crash", qname),
                    "pull_resolver: %s → %s: %s",
                    group.primary_qname, qname, result,
                )
                continue
            for ip_bytes, ttl in result:
                has_results = True
                min_ttl = min(min_ttl, ttl)
                family = FAMILY_V4 if len(ip_bytes) == 4 else FAMILY_V6
                # All qnames in the group feed the primary's set.
                set_id = self._tracker.set_id_for(group.primary_qname, family)
                if set_id is None:
                    continue
                prop = Proposal(set_id=set_id, ip_bytes=ip_bytes, ttl=ttl)
                self._writer.submit(
                    netns=self._netns, family=family, proposal=prop)
                self.metrics.entries_submitted_total += 1

        self.metrics.resolves_total += 1
        if not has_results:
            self.metrics.resolve_errors_total += 1
            wait = self._min_retry
        else:
            wait = max(
                self._min_retry,
                int(min_ttl * DEFAULT_RESOLVE_FRACTION),
            )
        wait = min(wait, self._max_ttl)
        # ±jitter on the deadline so many groups with the same TTL
        # don't all fire simultaneously at the recursor.
        if self._jitter > 0 and wait > 0:
            wait += random.uniform(-self._jitter * wait, self._jitter * wait)
            wait = max(1.0, wait)
        log.debug(
            "pull_resolver: group %s resolved, next in %.1fs",
            group.primary_qname, wait)
        return time.monotonic() + wait

    async def _resolve_qname(
        self,
        qname: str,
        ttl_floor: int,
        ttl_ceil: int,
    ) -> list[tuple[bytes, int]]:
        """Resolve A and AAAA; return ``[(ip_bytes, clamped_ttl), …]``."""
        results: list[tuple[bytes, int]] = []
        for rdtype, af in (("A", 4), ("AAAA", 6)):
            try:
                answer = await self._resolver.resolve(qname, rdtype)
                raw_ttl = answer.rrset.ttl if answer.rrset else ttl_floor
                ttl = max(ttl_floor, min(raw_ttl, ttl_ceil))
                for rdata in answer:
                    if af == 4:
                        ip_bytes = ipaddress.IPv4Address(rdata.address).packed
                    else:
                        ip_bytes = ipaddress.IPv6Address(rdata.address).packed
                    results.append((ip_bytes, ttl))
            except dns.resolver.NXDOMAIN:
                self.metrics.nxdomain_total += 1
                self._rate_limiter.info(
                    log, ("nxdomain", qname, rdtype),
                    "pull_resolver: %s NXDOMAIN (%s)", qname, rdtype,
                )
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.DNSException as exc:
                self._rate_limiter.warn(
                    log, ("dns_exception", qname, rdtype),
                    "pull_resolver: %s %s query failed: %s",
                    qname, rdtype, exc,
                )
        return results


class PullResolverMetricsCollector(CollectorBase):
    """Prometheus collector for the active DNS pull resolver."""

    def __init__(self, resolver: PullResolver) -> None:
        super().__init__(netns="")
        self._resolver = resolver

    def collect(self) -> list[_MetricFamily]:
        m = self._resolver.metrics
        fams: list[_MetricFamily] = []

        def gauge(name: str, help_text: str, value: float) -> None:
            fam = _MetricFamily(name, help_text, [])
            fam.add([], value)
            fams.append(fam)

        def counter(name: str, help_text: str, value: int) -> None:
            fam = _MetricFamily(name, help_text, [], mtype="counter")
            fam.add([], float(value))
            fams.append(fam)

        gauge("shorewalld_pull_resolver_groups_active",
              "Number of dnsr: groups currently managed by the pull resolver",
              float(self._resolver.group_count))
        gauge("shorewalld_pull_resolver_in_flight",
              "dnsr: groups currently mid-resolve",
              float(len(self._resolver._in_flight)))
        counter("shorewalld_pull_resolver_resolves_total",
                "Completed group resolve passes (success + NXDOMAIN/error)",
                m.resolves_total)
        counter("shorewalld_pull_resolver_resolve_errors_total",
                "Group resolves that returned no usable A/AAAA records",
                m.resolve_errors_total)
        counter("shorewalld_pull_resolver_nxdomain_total",
                "NXDOMAIN responses received during qname resolution",
                m.nxdomain_total)
        counter("shorewalld_pull_resolver_entries_submitted_total",
                "Individual (ip, ttl) entries submitted to SetWriter",
                m.entries_submitted_total)
        return fams
