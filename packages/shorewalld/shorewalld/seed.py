"""Seed coordinator — serves ``request-seed`` commands from shorewall-nft.

On cold-start (or after table recreation) all ``dns_*`` sets are empty.
shorewall-nft sends a ``request-seed`` request *before* loading the nft
script so the daemon can return pre-warmed IP addresses that are injected
directly into the initial ``nft -f`` transaction.

This module is **read-only**: no state mutations, no SetWriter calls, no
respawn.  Those remain the responsibility of the subsequent
``register-instance`` command.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from .exporter import CollectorBase, _MetricFamily

log = logging.getLogger("shorewalld.seed")

_HARD_TIMEOUT_CAP_MS = 30_000
_MAX_IN_FLIGHT = 8
_PASSIVE_POLL_INTERVAL = 0.25   # seconds between tracker polls during passive wait


@dataclass
class SeedMetrics:
    requests_total: int = 0
    timeout_hit_total: int = 0
    entries_served: dict[str, int] = field(default_factory=dict)

    def add_entries(self, source: str, n: int) -> None:
        self.entries_served[source] = self.entries_served.get(source, 0) + n


class SeedCoordinator:
    """Collect DNS + IP-list seed data for shorewall-nft start/restart."""

    def __init__(
        self,
        tracker: Any | None = None,
        pull_resolver: Any | None = None,
        peer_link: Any | None = None,
        iplist_tracker: Any | None = None,
        dnstap_active: bool = False,
        pbdns_active: bool = False,
    ) -> None:
        self._tracker = tracker
        self._pull_resolver = pull_resolver
        self._peer_link = peer_link
        self._iplist_tracker = iplist_tracker
        self._dnstap_active = dnstap_active
        self._pbdns_active = pbdns_active
        self._in_flight = 0
        self.metrics = SeedMetrics()

    async def handle(self, req: dict) -> dict:
        """Handle a ``request-seed`` command from the control socket."""
        if self._in_flight >= _MAX_IN_FLIGHT:
            return {"ok": False, "error": "too many concurrent seed requests"}

        self._in_flight += 1
        self.metrics.requests_total += 1
        t0 = time.monotonic()

        timeout_ms = min(int(req.get("timeout_ms") or 10_000), _HARD_TIMEOUT_CAP_MS)
        qnames: list[str] = list(req.get("qnames") or [])
        iplist_sets: list[str] = list(req.get("iplist_sets") or [])
        wait_for_passive: bool = bool(req.get("wait_for_passive", True))
        netns: str = req.get("netns", "")
        name: str = req.get("name", "")

        deadline = t0 + timeout_ms / 1000.0

        try:
            seeds, sources, timeout_hit, dnstap_waited = await self._collect(
                qnames=qnames,
                iplist_sets=iplist_sets,
                wait_for_passive=wait_for_passive,
                deadline=deadline,
            )
        except Exception:
            log.exception("seed: collection crashed for %s/%s", netns, name)
            seeds = {"dns": {}, "iplist": {}}
            sources = []
            timeout_hit = False
            dnstap_waited = False
        finally:
            self._in_flight -= 1

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        if timeout_hit:
            self.metrics.timeout_hit_total += 1

        dns_entries = sum(
            len(v.get("v4", [])) + len(v.get("v6", []))
            for v in seeds["dns"].values()
        )
        log.info(
            "seed: %s/%s → %d dns entries [%s] in %d ms%s",
            netns, name, dns_entries,
            ",".join(sources) if sources else "-",
            elapsed_ms,
            " (timeout)" if timeout_hit else "",
        )

        return {
            "ok": True,
            "elapsed_ms": elapsed_ms,
            "complete": not timeout_hit,
            "timeout_hit": timeout_hit,
            "dnstap_waited": dnstap_waited,
            "sources_contributed": sources,
            "seeds": seeds,
        }

    # ── collection ───────────────────────────────────────────────────

    async def _collect(
        self,
        qnames: list[str],
        iplist_sets: list[str],
        wait_for_passive: bool,
        deadline: float,
    ) -> tuple[dict, list[str], bool, bool]:
        """Gather seed data from all sources.

        Returns ``(seeds, sources_contributed, timeout_hit, dnstap_waited)``.
        """
        passive_active = (
            (self._dnstap_active or self._pbdns_active) and wait_for_passive
        )
        merged: dict[tuple[str, int], dict[bytes, int]] = {}
        sources: set[str] = set()

        # Step 1: tracker snapshot — always, synchronous, < 1 ms.
        if self._tracker is not None and qnames:
            data = self._tracker_snapshot(qnames)
            if data:
                _merge(merged, data)
                sources.add("tracker")
                self.metrics.add_entries(
                    "tracker", sum(len(v) for v in data.values()))

        # Step 2: pull resolver + peer in parallel (with deadline).
        active_results = await self._run_active_tasks(qnames, deadline)
        for source, data in active_results:
            if data:
                _merge(merged, data)
                sources.add(source)
                self.metrics.add_entries(
                    source, sum(len(v) for v in data.values()))

        # Step 3: if passive sources active, poll tracker until deadline.
        # Skip if active sources (pull/peer/tracker) already covered every
        # requested qname — no value in waiting for dnstap in that case.
        dnstap_waited = False
        timeout_hit = False
        if passive_active:
            _covered = {k[0] for k in merged}
            _all_covered = bool(qnames) and _covered >= set(qnames)
            if not _all_covered:
                dnstap_waited = True
                timeout_hit = True
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    await asyncio.sleep(min(_PASSIVE_POLL_INTERVAL, remaining))
                    if self._tracker is not None and qnames:
                        snap = self._tracker_snapshot(qnames)
                        if snap:
                            _merge(merged, snap)
                            sources.add("tracker")
                    # Stop early once every qname has at least one entry.
                    _covered = {k[0] for k in merged}
                    if _covered >= set(qnames):
                        timeout_hit = False
                        break

        # Step 4: IP-list snapshot — synchronous.
        iplist_data: dict[str, list[str]] = {}
        if self._iplist_tracker is not None and iplist_sets:
            iplist_data = self._snapshot_iplist(iplist_sets)
            if iplist_data:
                sources.add("iplist")
                self.metrics.add_entries(
                    "iplist", sum(len(v) for v in iplist_data.values()))

        seeds = {
            "dns": _merged_to_response(merged),
            "iplist": iplist_data,
        }
        return seeds, sorted(sources), timeout_hit, dnstap_waited

    async def _run_active_tasks(
        self, qnames: list[str], deadline: float
    ) -> list[tuple[str, dict[tuple[str, int], dict[bytes, int]]]]:
        """Run pull + peer collectors in parallel; cancel on deadline."""
        coros: list[tuple[str, Any]] = []
        if self._pull_resolver is not None and qnames:
            coros.append(("pull", self._collect_pull(qnames, deadline)))
        if self._peer_link is not None and qnames:
            coros.append(("peer", self._collect_peer(qnames, deadline)))

        if not coros:
            return []

        tasks = [(src, asyncio.ensure_future(coro)) for src, coro in coros]
        remaining = max(0.0, deadline - time.monotonic())
        done, pending = await asyncio.wait(
            [t for _, t in tasks],
            timeout=remaining,
        )
        for task in pending:
            task.cancel()

        results: list[tuple[str, dict]] = []
        for src, task in tasks:
            if task in done:
                try:
                    results.append((src, task.result()))
                except Exception:
                    log.debug("seed: %s task failed", src, exc_info=True)
        return results

    def _tracker_snapshot(
        self, qnames: list[str]
    ) -> dict[tuple[str, int], dict[bytes, int]]:
        """Read tracker state for *qnames*; return {(qname, family): {ip: ttl}}."""
        out: dict[tuple[str, int], dict[bytes, int]] = {}
        for qname, family, ip_bytes, ttl in self._tracker.snapshot_qnames(qnames):
            if ttl <= 0:
                continue
            key = (qname, family)
            if key not in out:
                out[key] = {}
            out[key][ip_bytes] = max(out[key].get(ip_bytes, 0), ttl)
        return out

    async def _collect_pull(
        self, qnames: list[str], deadline: float
    ) -> dict[tuple[str, int], dict[bytes, int]]:
        """Resolve pull-enabled qnames and collect IPs."""
        if self._pull_resolver is None:
            return {}
        primaries: set[str] = set(getattr(self._pull_resolver, "_primaries", {}))
        out: dict[tuple[str, int], dict[bytes, int]] = {}
        sub_tasks: list[tuple[str, asyncio.Task]] = []
        for qname in qnames:
            if qname not in primaries:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sub_tasks.append((qname, asyncio.ensure_future(
                asyncio.wait_for(
                    self._pull_resolver.resolve_now(qname),
                    timeout=max(0.1, remaining),
                )
            )))
        for qname, task in sub_tasks:
            try:
                entries = await task
                for family, ip_bytes, ttl in entries:
                    key = (qname, family)
                    if key not in out:
                        out[key] = {}
                    out[key][ip_bytes] = max(out[key].get(ip_bytes, 0), ttl)
            except Exception:
                pass
        return out

    async def _collect_peer(
        self, qnames: list[str], deadline: float
    ) -> dict[tuple[str, int], dict[bytes, int]]:
        """Trigger a peer snapshot and read from tracker after a brief wait."""
        if self._peer_link is None or self._tracker is None:
            return {}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {}
        try:
            self._peer_link.request_snapshot(qname_filter=qnames)
            # Peer responses arrive via async UDP handling; sleeping lets
            # the event loop process incoming chunks before we snapshot.
            await asyncio.sleep(min(remaining * 0.5, 2.0))
        except Exception:
            log.debug("seed: peer snapshot request failed", exc_info=True)
        return self._tracker_snapshot(qnames)

    def _snapshot_iplist(self, set_names: list[str]) -> dict[str, list[str]]:
        """Snapshot current IP-list prefixes for the requested set names."""
        result: dict[str, list[str]] = {}
        states = getattr(self._iplist_tracker, "_states", {})
        for _list_name, state in states.items():
            cfg = getattr(state, "cfg", None)
            if cfg is None:
                continue
            if cfg.set_v4 and cfg.set_v4 in set_names and state.current_v4:
                result[cfg.set_v4] = sorted(state.current_v4)
            if cfg.set_v6 and cfg.set_v6 in set_names and state.current_v6:
                result[cfg.set_v6] = sorted(state.current_v6)
        return result


# ── helper functions ─────────────────────────────────────────────────────────


def _merge(
    target: dict[tuple[str, int], dict[bytes, int]],
    source: dict[tuple[str, int], dict[bytes, int]],
) -> None:
    """Merge *source* into *target* keeping max TTL per (qname, family, ip)."""
    for key, ips in source.items():
        if key not in target:
            target[key] = dict(ips)
        else:
            for ip_bytes, ttl in ips.items():
                existing = target[key].get(ip_bytes, 0)
                if ttl > existing:
                    target[key][ip_bytes] = ttl


def _merged_to_response(
    merged: dict[tuple[str, int], dict[bytes, int]],
) -> dict:
    """Convert merged internal representation to the wire-format DNS seed dict.

    Wire format: ``{qname: {"v4": [{"ip": "1.2.3.4", "ttl": 60}, …], "v6": […]}}``
    TTL values are remaining seconds, ready to use as ``timeout Xs`` in nft.
    """
    from .dns_set_tracker import FAMILY_V4
    result: dict[str, dict] = {}
    for (qname, family), ips in merged.items():
        if not ips:
            continue
        if qname not in result:
            result[qname] = {"v4": [], "v6": []}
        key = "v4" if family == FAMILY_V4 else "v6"
        for ip_bytes, ttl in ips.items():
            try:
                if family == FAMILY_V4:
                    ip_str = str(ipaddress.IPv4Address(ip_bytes))
                else:
                    ip_str = str(ipaddress.IPv6Address(ip_bytes))
            except ValueError:
                continue
            result[qname][key].append({"ip": ip_str, "ttl": ttl})
    return result


# ── Prometheus collector ──────────────────────────────────────────────────────


class SeedMetricsCollector(CollectorBase):
    """Prometheus collector for the seed coordinator."""

    def __init__(self, coord: SeedCoordinator) -> None:
        super().__init__(netns="")
        self._coord = coord

    def collect(self) -> list[_MetricFamily]:
        m = self._coord.metrics
        fams: list[_MetricFamily] = []

        req_fam = _MetricFamily(
            "shorewalld_seed_requests_total",
            "Total seed requests received",
            [], mtype="counter")
        req_fam.add([], float(m.requests_total))
        fams.append(req_fam)

        to_fam = _MetricFamily(
            "shorewalld_seed_timeout_hit_total",
            "Seed requests that exhausted their timeout",
            [], mtype="counter")
        to_fam.add([], float(m.timeout_hit_total))
        fams.append(to_fam)

        srv_fam = _MetricFamily(
            "shorewalld_seed_entries_served_total",
            "Seed entries served, by source",
            ["source"], mtype="counter")
        for source, count in m.entries_served.items():
            srv_fam.add([source], float(count))
        fams.append(srv_fam)

        return fams
