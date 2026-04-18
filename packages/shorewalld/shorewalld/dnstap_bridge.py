"""Adapter between the dnstap/pbdns decoder and the Phase 2 pipeline.

The existing :mod:`shorewalld.dnstap` module has its own
decode workers that yield :class:`DnsUpdate` records. Rather than
rewriting that module twice (once for Phase 3's Phase 2 wiring,
once for Phase 4's real protobuf swap) we add a thin bridge here
that:

* turns each ``DnsUpdate`` into ``Proposal`` objects keyed on the
  compiled ``set_id`` from :class:`DnsSetTracker`,
* submits them to the Phase 2 :class:`SetWriter`,
* keeps a small set of per-qname metric counters for early-filter
  effectiveness.

Thread affinity: every entry point here is called from a decoder
worker thread, not from the asyncio loop. All state mutation is
through :meth:`DnsSetTracker.propose` and :meth:`SetWriter.submit`,
both of which are thread-safe by design.

Phase 4 rewrites :mod:`dnstap` around a real protobuf decoder and
adds :mod:`pbdns` as a second ingestion path. Both will call
:class:`TrackerBridge.apply` — so this bridge is the long-term
interface between ingestion and the write pipeline, not a
temporary shim.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from shorewall_nft.nft.dns_sets import canonical_qname

from .exporter import CollectorBase, _MetricFamily
from .dns_set_tracker import (
    FAMILY_V4,
    FAMILY_V6,
    DnsSetTracker,
    Proposal,
)
from .dns_wire import extract_qname
from .logsetup import get_logger
from .setwriter import SetWriter

log = get_logger("decoder")


@dataclass
class BridgeMetrics:
    """Counters owned by the bridge itself.

    Distinct from :class:`DnstapMetrics` / :class:`PbdnsMetrics`
    because those describe the *transport/decoder* stage. The
    bridge sits one layer up and measures effectiveness of the
    early-filter + allowlist.
    """
    updates_total: int = 0              # DnsUpdate records seen
    updates_empty_total: int = 0        # no RRs, skipped
    early_filter_miss_total: int = 0    # qname not in allowlist
    early_filter_pass_total: int = 0    # qname in allowlist, proposed
    proposals_total: int = 0            # individual (qname,ip) tuples
    submit_dropped_queue_full_total: int = 0


class TrackerBridge:
    """Shim that routes decoded DNS updates into the Phase 2 pipeline.

    Instantiated once by the :class:`Daemon` during startup and
    handed to :class:`DnstapServer` / :class:`PbdnsServer` as the
    ``on_update`` callback. Uses the tracker's integer ``set_id``
    lookup so the hot path never touches strings after the initial
    qname normalisation.
    """

    def __init__(
        self,
        tracker: DnsSetTracker,
        writer: SetWriter,
        *,
        default_netns: str = "",
    ) -> None:
        self._tracker = tracker
        self._writer = writer
        self._default_netns = default_netns
        self._lock = threading.Lock()
        self.metrics = BridgeMetrics()

    def set_default_netns(self, netns: str) -> None:
        """Change the target netns for subsequent submits.

        The worker-router currently dispatches per-netns; the
        decoder doesn't know which netns a frame belongs to (it
        only sees the recursor socket). For the default HA shape
        the answer is "all netns with a loaded shorewall table",
        which :class:`WorkerRouter` fans out to automatically.
        """
        self._default_netns = netns

    def early_filter_from_wire(
        self, wire: memoryview | bytes
    ) -> str | None:
        """Check if the qname in a raw DNS wire response is allowlisted.

        Returns the canonical qname on a hit, ``None`` on a miss
        (which bumps the early-filter-miss counter — the caller
        should drop the frame without running dnspython on it).
        """
        result = extract_qname(wire)
        if result is None:
            return None
        qname, _ = result
        qn = canonical_qname(qname)
        if (self._tracker.set_id_for(qn, FAMILY_V4) is None
                and self._tracker.set_id_for(qn, FAMILY_V6) is None):
            with self._lock:
                self.metrics.early_filter_miss_total += 1
                self._tracker.note_unknown_qname()
            return None
        with self._lock:
            self.metrics.early_filter_pass_total += 1
        return qn

    def apply(
        self,
        qname: str,
        a_rrs: list[bytes] | list[str],
        aaaa_rrs: list[bytes] | list[str],
        ttl: int,
    ) -> None:
        """Submit a decoded update to the Phase 2 pipeline.

        Callers (dnstap decoder, pbdns decoder, later peer
        replicator) hand raw RRs. ``a_rrs`` / ``aaaa_rrs`` may be
        pre-packed ``bytes`` (preferred, zero-parse) or ``str``
        (backward compat with the existing dnspython-based path;
        converted once via :func:`_inet_pton`).
        """
        with self._lock:
            self.metrics.updates_total += 1
        if not a_rrs and not aaaa_rrs:
            with self._lock:
                self.metrics.updates_empty_total += 1
            return
        qn = canonical_qname(qname)

        sid_v4 = self._tracker.set_id_for(qn, FAMILY_V4)
        if sid_v4 is not None:
            for rr in a_rrs:
                ip = _coerce_ip4(rr)
                if ip is None:
                    continue
                self._submit(
                    Proposal(set_id=sid_v4, ip_bytes=ip, ttl=ttl),
                    family=FAMILY_V4,
                )

        sid_v6 = self._tracker.set_id_for(qn, FAMILY_V6)
        if sid_v6 is not None:
            for rr in aaaa_rrs:
                ip = _coerce_ip6(rr)
                if ip is None:
                    continue
                self._submit(
                    Proposal(set_id=sid_v6, ip_bytes=ip, ttl=ttl),
                    family=FAMILY_V6,
                )

    def _submit(self, proposal: Proposal, *, family: int) -> None:
        with self._lock:
            self.metrics.proposals_total += 1
        ok = self._writer.submit(
            netns=self._default_netns,
            family=family,
            proposal=proposal,
        )
        if not ok:
            with self._lock:
                self.metrics.submit_dropped_queue_full_total += 1


def _coerce_ip4(rr: bytes | str) -> bytes | None:
    if isinstance(rr, (bytes, bytearray, memoryview)) and len(rr) == 4:
        return bytes(rr)
    if isinstance(rr, str):
        import socket
        try:
            return socket.inet_pton(socket.AF_INET, rr)
        except OSError:
            return None
    return None


def _coerce_ip6(rr: bytes | str) -> bytes | None:
    if isinstance(rr, (bytes, bytearray, memoryview)) and len(rr) == 16:
        return bytes(rr)
    if isinstance(rr, str):
        import socket
        try:
            return socket.inet_pton(socket.AF_INET6, rr)
        except OSError:
            return None
    return None


class BridgeMetricsCollector(CollectorBase):
    """Prometheus collector for the decoder → tracker bridge."""

    def __init__(self, bridge: TrackerBridge) -> None:
        super().__init__(netns="")
        self._bridge = bridge

    def collect(self) -> list[_MetricFamily]:
        m = self._bridge.metrics
        fams: list[_MetricFamily] = []

        def counter(name: str, help_text: str, value: int) -> None:
            fam = _MetricFamily(name, help_text, [], mtype="counter")
            fam.add([], float(value))
            fams.append(fam)

        counter("shorewalld_bridge_updates_total",
                "DNS answer records seen by the tracker bridge",
                m.updates_total)
        counter("shorewalld_bridge_updates_empty_total",
                "DNS records skipped — no A/AAAA RRs",
                m.updates_empty_total)
        counter("shorewalld_bridge_early_filter_miss_total",
                "Records dropped — qname not in compiled allowlist",
                m.early_filter_miss_total)
        counter("shorewalld_bridge_early_filter_pass_total",
                "Records forwarded to the tracker",
                m.early_filter_pass_total)
        counter("shorewalld_bridge_proposals_total",
                "Individual (qname, ip) proposals submitted to SetWriter",
                m.proposals_total)
        counter("shorewalld_bridge_dropped_queue_full_total",
                "Proposals dropped — SetWriter queue saturated",
                m.submit_dropped_queue_full_total)
        return fams
