"""WorkerRouterMetricsCollector — per-netns nft worker pool metrics.

Lives under :mod:`shorewalld.collectors` so it sits alongside every
other Prometheus collector; the worker_router module re-exports the
class for back-compat.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from shorewalld.exporter import CollectorBase, _MetricFamily

if TYPE_CHECKING:
    from shorewalld.worker_router import WorkerRouter


class WorkerRouterMetricsCollector(CollectorBase):
    """Prometheus collector for per-netns nft worker pool metrics."""

    def __init__(self, router: "WorkerRouter") -> None:
        super().__init__(netns="")
        self._router = router

    def collect(self) -> list[_MetricFamily]:
        spawned   = _MetricFamily("shorewalld_worker_spawned_total",
                                  "nft worker forks since daemon start",
                                  ["netns"], mtype="counter")
        restarts  = _MetricFamily("shorewalld_worker_restarts_total",
                                  "nft worker crash-respawns",
                                  ["netns"], mtype="counter")
        alive     = _MetricFamily("shorewalld_worker_alive",
                                  "1 if the nft worker process is running",
                                  ["netns"])
        sent      = _MetricFamily("shorewalld_worker_batches_sent_total",
                                  "Batches dispatched to worker",
                                  ["netns"], mtype="counter")
        applied   = _MetricFamily("shorewalld_worker_batches_applied_total",
                                  "Batches acknowledged OK by worker",
                                  ["netns"], mtype="counter")
        failed    = _MetricFamily("shorewalld_worker_batches_failed_total",
                                  "Batches that returned a worker error",
                                  ["netns"], mtype="counter")
        ipc_err   = _MetricFamily("shorewalld_worker_ipc_errors_total",
                                  "IPC transport errors (SEQPACKET)",
                                  ["netns"], mtype="counter")
        ack_to    = _MetricFamily("shorewalld_worker_ack_timeout_total",
                                  "Batches that timed out waiting for worker ack",
                                  ["netns"], mtype="counter")
        latency   = _MetricFamily(
            "shorewalld_worker_batch_latency_seconds",
            "End-to-end batch dispatch latency (send to reply)",
            ["netns"], mtype="histogram")
        size_hist = _MetricFamily(
            "shorewalld_worker_batch_size_ops",
            "Batch size in ops observed at dispatch",
            ["netns"], mtype="histogram")
        tx_bytes  = _MetricFamily(
            "shorewalld_worker_transport_send_bytes_total",
            "Bytes sent over the parent→worker SEQPACKET",
            ["netns"], mtype="counter")
        rx_bytes  = _MetricFamily(
            "shorewalld_worker_transport_recv_bytes_total",
            "Bytes received from the worker over SEQPACKET",
            ["netns"], mtype="counter")
        send_err  = _MetricFamily(
            "shorewalld_worker_transport_send_errors_total",
            "SEQPACKET send errors (retries counted once per event)",
            ["netns"], mtype="counter")

        for w in self._router.iter_workers():
            ns = w.netns or "(own)"
            m = w.metrics
            spawned.add([ns],  float(m.spawned_total))
            restarts.add([ns], float(m.restarts_total))
            alive.add([ns],    float(m.alive))
            sent.add([ns],     float(m.batches_sent_total))
            applied.add([ns],  float(m.batches_applied_total))
            failed.add([ns],   float(m.batches_failed_total))
            ipc_err.add([ns],  float(m.ipc_errors_total))
            ack_to.add([ns],   float(m.ack_timeout_total))
            latency.add_histogram([ns], m.batch_latency_hist)
            size_hist.add_histogram([ns], m.batch_size_hist)
            # LocalWorker has no SEQPACKET transport — skip its
            # byte counters so the metric never emits zero-forever
            # samples that would drown out the real ones.
            transport = getattr(w, "_transport", None)
            if transport is not None:
                s = transport.stats
                tx_bytes.add([ns], float(s.send_bytes_total))
                rx_bytes.add([ns], float(s.recv_bytes_total))
                send_err.add([ns], float(s.send_errors_total))

        return [
            spawned, restarts, alive, sent, applied, failed, ipc_err, ack_to,
            latency, size_hist, tx_bytes, rx_bytes, send_err,
        ]
