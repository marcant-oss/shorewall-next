"""Active DNS pull resolver for ``dnsr:`` rule groups.

Resolves hostnames from the ``[dnsr]`` compiled-allowlist section
periodically, respecting TTL, and feeds results through the existing
tracker + setwriter pipeline so they land in the same ``dns_*`` nft sets
as tap-acquired entries.

Design constraints (from CLAUDE.md performance doctrine):
* Pure asyncio — no extra threads; runs on the daemon's event loop.
* Single min-heap of ``(next_resolve_at, primary_qname, group)`` entries;
  one coroutine sleeps until the earliest entry is due.
* Sleep is interruptible via ``asyncio.Event`` so manual refresh() takes
  effect immediately without waiting for the current sleep to expire.
* A + AAAA queries for all qnames in a group are issued in parallel
  (``asyncio.gather``).
* SetWriter.submit() handles dedup — no separate pre-check needed here.
* Error paths: NXDOMAIN → log.info, timeout/SERVFAIL → log.warning,
  both reschedule at ``min_retry`` so a transient failure doesn't stall
  the heap entry indefinitely.
* All logging is per-group-resolve or per-error, never per-IP.
"""

from __future__ import annotations

import asyncio
import heapq
import ipaddress
import logging
import time
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

from shorewall_nft.nft.dns_sets import DnsrGroup, DnsrRegistry

from .dns_set_tracker import FAMILY_V4, FAMILY_V6, DnsSetTracker, Proposal
from .setwriter import SetWriter

log = logging.getLogger(__name__)

DEFAULT_MAX_TTL = 3600          # cap: never sleep longer than 1 hour
DEFAULT_MIN_RETRY = 30          # floor on retry after NXDOMAIN / error
DEFAULT_RESOLVE_FRACTION = 0.8  # re-resolve at 80% of min-TTL expiry


@dataclass(order=True)
class _Entry:
    """Min-heap entry — ordered by next resolve deadline."""
    next_at: float
    primary_qname: str = field(compare=False)
    group: DnsrGroup = field(compare=False)


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
    ) -> None:
        self._tracker = tracker
        self._writer = writer
        self._netns = default_netns
        self._max_ttl = max_ttl
        self._min_retry = min_retry
        self._stopping = False
        self._task: asyncio.Task | None = None

        # Min-heap: resolve every group immediately on startup.
        now = time.monotonic()
        self._heap: list[_Entry] = [
            _Entry(next_at=now, primary_qname=g.primary_qname, group=g)
            for g in dnsr_registry.iter_sorted()
        ]
        heapq.heapify(self._heap)

        # Interrupt the current sleep on refresh() calls.
        self._wake = asyncio.Event()

        self._resolver = dns.asyncresolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers

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

        Called from the control socket ``REFRESH_DNS`` handler.
        Returns the number of entries rescheduled.
        """
        now = time.monotonic()
        new_heap: list[_Entry] = []
        count = 0
        for entry in self._heap:
            if primary_qname is None or entry.primary_qname == primary_qname:
                new_heap.append(_Entry(
                    next_at=now,
                    primary_qname=entry.primary_qname,
                    group=entry.group,
                ))
                count += 1
            else:
                new_heap.append(entry)
        heapq.heapify(new_heap)
        self._heap = new_heap
        self._wake.set()
        log.info("pull_resolver: refresh triggered (%d group(s))", count)
        return count

    @property
    def group_count(self) -> int:
        return len(self._heap)

    # ── internal loop ────────────────────────────────────────────────────

    async def _run(self) -> None:
        while not self._stopping:
            if not self._heap:
                await asyncio.sleep(60)
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
                due.append(heapq.heappop(self._heap))

            for entry in due:
                next_at = await self._resolve_group(entry.group)
                heapq.heappush(self._heap, _Entry(
                    next_at=next_at,
                    primary_qname=entry.primary_qname,
                    group=entry.group,
                ))

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
                log.warning(
                    "pull_resolver: %s → %s: %s",
                    group.primary_qname, qname, result)
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

        if not has_results:
            wait = self._min_retry
        else:
            wait = max(
                self._min_retry,
                int(min_ttl * DEFAULT_RESOLVE_FRACTION),
            )
        wait = min(wait, self._max_ttl)
        log.debug(
            "pull_resolver: group %s resolved, next in %ds",
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
                log.info("pull_resolver: %s NXDOMAIN (%s)", qname, rdtype)
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.DNSException as exc:
                log.warning(
                    "pull_resolver: %s %s query failed: %s", qname, rdtype, exc)
        return results
