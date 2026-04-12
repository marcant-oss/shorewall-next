# shorewalld — design history

> **Status 2026-04-12 (v1.4.0):** All phases shipped.
> The definitive operator reference is
> [`docs/reference/shorewalld.md`](../reference/shorewalld.md).
> This file is preserved as design history only.

## What shipped in v1.4.0

All five phases from the original design are complete:

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Daemon skeleton — asyncio loop, CLI, signal handling, graceful shutdown | ✓ |
| 2 | Prometheus exporter — `NftCollector`, `LinkCollector`, `CtCollector`, per-netns TTL cache | ✓ |
| 3 | Multi-netns support — auto-discovery, per-netns `NetnsProfile`, reprobe loop | ✓ |
| 4 | DNS API socket — dnstap (FrameStream) + PBDNSMessage (protobuf), `DnsSetTracker`, `SetWriter`, `StateStore`, `ReloadMonitor` | ✓ |
| 5 | Packaging — systemd units, RPM/deb packages, optional deps via `[daemon]` extra | ✓ |

Additional items beyond the original plan that also shipped:

- **HA peer-link replication** — incremental + snapshot sync over
  authenticated UDP between two shorewalld nodes.
- **`shorewalld tap`** — operator inspection tool for live dnstap
  streams.
- **TCP dnstap listener** — for cross-host or cross-netns recursors
  that can't reach a unix socket.
- **PBDNSMessage over TCP** — pdns_recursor's `protobufServer()`
  is TCP-only; shorewalld handles both transports.
- **Two-pass decode filter** — qname allowlist check before full
  protobuf parse; drops >95 % of frames at high QPS.
- **WorkerRouter** — persistent-fork worker pool for GIL-bound
  decode, bounded `queue.Queue`, drop-and-count overflow.

## Original design sketch

The original design assumed a simple length-prefixed JSON API socket
for Phase 4. The actual implementation uses dnstap FrameStream and
PBDNSMessage protobuf, which turned out to be the natural fit for
production pdns_recursor deployments. The dnstap path is now the
recommended default; PBDNSMessage is the opt-in alternative for
operators who have existing protobuf pipelines.

The performance targets from the original design:

- < 50 ms scrape latency per netns (met: single `list table`
  netlink round-trip, no subprocess)
- 20 000 DNS answers/s sustained ingest (met: two-pass filter
  + threaded decode + batched netlink writes)
- Zero-fork in the hot path (met: libnftables in-process,
  pyroute2 direct netlink, `/proc` for conntrack)

For the full current reference see
[`docs/reference/shorewalld.md`](../reference/shorewalld.md).
