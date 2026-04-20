"""NfsetsCollector — Prometheus metrics for the W1–W4 nfsets features.

Covers:

* :class:`~shorewalld.nfsets_manager.NfSetsManager` instance registration
  (per-instance entry counts, host counts, payload size).
* :class:`~shorewalld.dns_set_tracker.DnsSetTracker` N→1 shared-set qname
  counts.  Delegates per-set element counts to the existing
  :class:`~shorewalld.dns_set_tracker.DnsSetMetricsCollector` — this
  collector only adds the *sharing* gauge that shows how many qnames feed
  one logical set.
* :class:`~shorewalld.iplist.plain.PlainListTracker` refresh counters,
  duration histograms, current entry sizes, last-success staleness, and
  inotify-active status.

**ip-list backend** (existing :class:`~shorewalld.iplist.tracker.IpListTracker`):
The manager produces standard ``IpListConfig`` objects whose ``name`` field
is prefixed with ``"nfset_"`` (e.g. ``"nfset_blocklist"``).  The existing
``shorewalld_iplist_*`` metrics pick these up automatically because
``IpListMetrics`` is keyed on the ``name`` field.  No additional label or
duplicate metric is needed — the ``nfset_`` prefix in the ``name`` label
value is sufficient to distinguish nfset-sourced lists from standalone
config-sourced lists.  See the Wave 6 report for rationale.

**resolver backend**: The resolver backend flows through ``DnsSetTracker``
via the same ``DnsSetMetricsCollector`` that covers inline ``dns:`` / ``dnsr:``
references.  No separate metric is emitted here — it would duplicate coverage.
The ``shorewalld_nfsets_entries`` / ``shorewalld_nfsets_hosts`` gauges
already account for resolver-backend entries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from shorewalld.exporter import CollectorBase, Histogram, _MetricFamily

if TYPE_CHECKING:
    from shorewalld.dns_set_tracker import DnsSetTracker
    from shorewalld.iplist.plain import PlainListTracker
    from shorewalld.nfsets_manager import NfSetsManager

# Histogram buckets for refresh duration (seconds).
# Most local file reads finish in < 1 ms; HTTP feeds may take a few seconds.
# The +Inf bucket catches hung feeds so staleness alerts still fire.
_REFRESH_DURATION_BUCKETS = [
    0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0,
]


class NfsetsCollector(CollectorBase):
    """Prometheus collector for the W1–W4 nfsets runtime observability.

    Parameters
    ----------
    instance:
        Logical instance label (typically the netns name or ``""``).
    manager:
        The :class:`~shorewalld.nfsets_manager.NfSetsManager` for this
        instance.  May be ``None`` if no nfsets payload was registered
        (metrics are declared but empty so dashboards stay stable).
    tracker:
        The global :class:`~shorewalld.dns_set_tracker.DnsSetTracker`.
        Used to derive the N→1 shared-qname count per set.  May be ``None``
        when the DNS pipeline is not running.
    plain_tracker:
        The :class:`~shorewalld.iplist.plain.PlainListTracker` for this
        daemon.  May be ``None`` when no ``ip-list-plain`` entries are
        configured.
    """

    def __init__(
        self,
        instance: str,
        manager: "NfSetsManager | None" = None,
        tracker: "DnsSetTracker | None" = None,
        plain_tracker: "PlainListTracker | None" = None,
    ) -> None:
        super().__init__(netns=instance)
        self._instance = instance
        self._manager = manager
        self._tracker = tracker
        self._plain_tracker = plain_tracker
        # Histogram objects — one per (list_name, source_type) pair, created
        # lazily on first observation so we don't pay for sources that never
        # refresh successfully.  Keyed on list_name for simplicity (source_type
        # is stable per list).
        self._duration_hists: dict[str, Histogram] = {}

    def collect(self) -> list[_MetricFamily]:
        families: list[_MetricFamily] = []
        families.extend(self._collect_manager())
        families.extend(self._collect_dns_shared())
        families.extend(self._collect_plain())
        return families

    # ── NfSetsManager metrics ──────────────────────────────────────────────

    def _collect_manager(self) -> list[_MetricFamily]:
        """Emit per-instance, per-backend entry/host counts and payload size."""
        entries_fam = _MetricFamily(
            "shorewalld_nfsets_entries",
            "Number of nfset entries registered per instance and backend",
            ["instance", "backend"],
        )
        hosts_fam = _MetricFamily(
            "shorewalld_nfsets_hosts",
            "Total host/qname/source count per instance and backend",
            ["instance", "backend"],
        )
        payload_fam = _MetricFamily(
            "shorewalld_nfsets_payload_bytes",
            "Approximate serialised nfsets payload size per instance (bytes)",
            ["instance"],
        )

        if self._manager is not None:
            inst = self._instance
            for backend, count in self._manager.entries_by_backend().items():
                entries_fam.add([inst, backend], float(count))
            for backend, count in self._manager.hosts_by_backend().items():
                hosts_fam.add([inst, backend], float(count))
            payload_fam.add([inst], float(self._manager.payload_bytes()))

        return [entries_fam, hosts_fam, payload_fam]

    # ── DnsSetTracker N→1 sharing metrics ─────────────────────────────────

    def _collect_dns_shared(self) -> list[_MetricFamily]:
        """Emit shared-qname count per logical nft set.

        The existing ``DnsSetMetricsCollector`` already emits
        ``shorewalld_dns_set_elements`` labelled by ``(set, family)`` where
        ``set`` is the canonical qname.  When multiple qnames share one nft
        set (N→1 grouping via ``set_name``), all their IPs flow into the same
        set_id but the exporter only shows the canonical qname.

        This metric adds ``shorewalld_dns_set_shared_qnames`` which counts
        how many ``_by_name`` keys point at each set_id — an operator can
        use ``> 1`` as the alert threshold for "N→1 grouping active".
        """
        shared_qnames_fam = _MetricFamily(
            "shorewalld_dns_set_shared_qnames",
            "Number of qnames feeding one shared nft set (>1 means N:1 grouping active)",
            ["set_name", "family"],
        )

        tracker = self._tracker
        if tracker is None:
            return [shared_qnames_fam]

        # Build set_id → list[(qname, family)] under the tracker's lock.
        # We replicate just enough of the internal structure we need.
        with tracker._lock:  # noqa: SLF001
            # Invert _by_name: set_id → count of keys pointing at it.
            counts_v4: dict[int, int] = {}
            counts_v6: dict[int, int] = {}
            for (qname, family), sid in tracker._by_name.items():  # noqa: SLF001
                if family == 4:
                    counts_v4[sid] = counts_v4.get(sid, 0) + 1
                else:
                    counts_v6[sid] = counts_v6.get(sid, 0) + 1

            # Emit per set_id using the canonical qname as the set_name label.
            for sid, count in counts_v4.items():
                canonical = tracker._by_id.get(sid)  # noqa: SLF001
                if canonical is None:
                    continue
                set_name = canonical[0]  # qname
                shared_qnames_fam.add([set_name, "ipv4"], float(count))
            for sid, count in counts_v6.items():
                canonical = tracker._by_id.get(sid)  # noqa: SLF001
                if canonical is None:
                    continue
                set_name = canonical[0]
                shared_qnames_fam.add([set_name, "ipv6"], float(count))

        return [shared_qnames_fam]

    # ── PlainListTracker metrics ───────────────────────────────────────────

    def _collect_plain(self) -> list[_MetricFamily]:
        """Emit per-list plain-list refresh and entry metrics."""
        refresh_total_fam = _MetricFamily(
            "shorewalld_plainlist_refresh_total",
            "Total plain-list refresh attempts (success + failure)",
            ["name", "source_type", "outcome"],
            mtype="counter",
        )
        duration_fam = _MetricFamily(
            "shorewalld_plainlist_refresh_duration_seconds",
            "Fetch latency for successful plain-list refreshes",
            ["name", "source_type"],
            mtype="histogram",
        )
        entries_fam = _MetricFamily(
            "shorewalld_plainlist_entries",
            "Current number of IP/CIDR prefixes in a plain-list set",
            ["name", "family"],
        )
        last_success_fam = _MetricFamily(
            "shorewalld_plainlist_last_success_timestamp_seconds",
            "Unix timestamp of the last successful plain-list refresh (0 if never)",
            ["name"],
        )
        inotify_fam = _MetricFamily(
            "shorewalld_plainlist_inotify_active",
            "1 if an inotify watch is active for this plain-list source, else 0",
            ["name"],
        )
        errors_fam = _MetricFamily(
            "shorewalld_plainlist_errors_total",
            "Plain-list refresh errors by type",
            ["name", "source_type", "error_type"],
            mtype="counter",
        )

        if self._plain_tracker is None:
            return [
                refresh_total_fam, duration_fam, entries_fam,
                last_success_fam, inotify_fam, errors_fam,
            ]

        snapshots = self._plain_tracker.metrics_snapshot()
        for snap in snapshots:
            name = snap.name
            src_type = snap.source_type

            # refresh_total split by outcome
            if snap.refresh_success_total > 0 or snap.refresh_failure_total > 0:
                refresh_total_fam.add(
                    [name, src_type, "success"],
                    float(snap.refresh_success_total),
                )
                refresh_total_fam.add(
                    [name, src_type, "failure"],
                    float(snap.refresh_failure_total),
                )

            # duration histogram — build lazily, observe cumulative
            hist = self._duration_hists.get(name)
            if hist is None:
                hist = Histogram(_REFRESH_DURATION_BUCKETS)
                self._duration_hists[name] = hist
            # We store the cumulative sum/count in the snapshot and build
            # a synthetic histogram for the scrape.  Since the Histogram
            # object tracks bucket observations from birth, we can't
            # replay individual observations.  Instead we emit a
            # "summary-as-histogram" by creating a fresh Histogram per
            # scrape that records one synthetic observation equal to
            # (sum / count) — this keeps per-bucket precision at zero but
            # correctly surfaces the average latency as the mean bucket.
            # A proper solution would require storing per-bucket counts
            # in the state, which is deferred to W7.
            #
            # For now emit the raw sum/count as a counter pair so PromQL
            # `rate(sum) / rate(count)` works correctly.
            # This is emitted as two separate gauge families below;
            # the HistogramMetricFamily path is skipped.
            _ = hist  # unused here; kept for future per-bucket tracking

            entries_fam.add([name, "ipv4"], float(snap.v4_entries))
            entries_fam.add([name, "ipv6"], float(snap.v6_entries))

            last_success_fam.add([name], snap.last_success_ts)
            inotify_fam.add([name], float(snap.inotify_active))

            for error_type, count in snap.refresh_error_counts.items():
                errors_fam.add([name, src_type, error_type], float(count))

        # Emit refresh duration as counter sum/count (rate-able in PromQL).
        duration_sum_fam = _MetricFamily(
            "shorewalld_plainlist_refresh_duration_seconds_sum",
            "Cumulative seconds spent in successful plain-list fetches",
            ["name", "source_type"],
            mtype="counter",
        )
        duration_count_fam = _MetricFamily(
            "shorewalld_plainlist_refresh_duration_seconds_count",
            "Number of successful plain-list fetches measured",
            ["name", "source_type"],
            mtype="counter",
        )
        if self._plain_tracker is not None:
            for snap in snapshots:
                duration_sum_fam.add(
                    [snap.name, snap.source_type],
                    snap.refresh_duration_sum,
                )
                duration_count_fam.add(
                    [snap.name, snap.source_type],
                    float(snap.refresh_duration_count),
                )

        return [
            refresh_total_fam, duration_fam, entries_fam,
            last_success_fam, inotify_fam, errors_fam,
            duration_sum_fam, duration_count_fam,
        ]
