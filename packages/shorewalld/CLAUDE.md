# CLAUDE.md — shorewalld

Prometheus exporter + DNS-based dynamic nft-set daemon for shorewall-nft.
Python package: `shorewalld`. Entry point: `shorewalld`.

## Key modules

- `cli.py` — Click entry point; wires all subsystems.
- `core.py` — `Daemon.run()`: asyncio event loop, subsystem lifecycle.
- `exporter.py` — Prometheus metrics scraper (`NftScraper`).
- `discover.py` — netns auto-discovery (`/run/netns/`).
- `dnstap.py` — FrameStream unix socket server + frame decoder.
- `pbdns.py` — PowerDNS protobuf stream server.
- `worker_router.py` — persistent-fork `WorkerRouter` for GIL-bound decode.
- `worker_transport.py` + `batch_codec.py` — IPC framing between router
  and workers.
- `dns_set_tracker.py` — `(set_name, ip) → expiry` LRU + proposal/verdict.
- `setwriter.py` — coalescing `SetWriter` (batched netlink writes).
- `dnstap_bridge.py` — routes dnstap answers through tracker or direct-nft.
- `state.py` — persistent set state across daemon restarts.
- `peer.py` — HA peer-link UDP (snapshot + incremental sync).
- `tap.py` + `logsetup.py` — live trace output + rate-limited logging.
- `proto/` — hand-compiled protobuf (`dnstap_pb2.py`, `peer_pb2.py`,
  `dnsmessage_pb2.py`).

Config: `shorewalld.conf` — searched at `/etc/shorewall/shorewalld.conf`
then `/etc/shorewalld.conf`. CLI flags always override.

## Performance doctrine

Every code path here is hot. Target: 20 000 DNS answers/s across dnstap
+ PBDNSMessage + HA peer UDP ingestion.

- **Don't copy data, pass pointers.** memoryview/slices over the original
  frame buffer all the way through decode. No intermediate `bytes(...)`
  copies, no f-string reassembly of qnames thrown away a microsecond later.
- **Filter before decode.** Two-pass decoder: walk varint stream far enough
  to read discriminator fields (message type, qname), consult the allowlist,
  *only then* do the full parse. 99 % of frames are waste.
- **Batch at the netlink boundary.** Every `add element` is a round-trip.
  Coalesce per `(set, netns)` in a short window. Single updates at 20 k/s
  melt the scheduler.
- **Dedup aggressively.** `(set_name, ip) → expiry` LRU; skip write if
  existing timeout covers > 50 % of the new TTL.
- **Threading: match the work type.** Decode is GIL-bound →
  `threading.Thread` workers sized to `os.cpu_count()`, bounded
  `queue.Queue`. SetWriter + nft mutations on the single asyncio event
  loop (libnftables is not thread-safe). Sockets are asyncio readers.
  No thread-pools for IO, no asyncio for CPU-bound work.
- **Zero-fork.** Never shell out. libnftables in-process via
  `NftInterface`, pyroute2 for link stats, direct `/proc` reads for ct
  counters.
- **Bounded everything.** Every queue, cache, retry counter has an
  explicit cap. Drops are counted as metrics. Growing RSS is not
  acceptable.
- **Measure before optimising.** Scrape-duration histograms, per-stage
  queue depths, batch-size histograms are first-class metrics.
- **Peer-link UDP: never fragment at IP.** `IP_MTU_DISCOVER=IP_PMTUDISC_DO`
  on the peer socket. Cap every envelope at 1400 bytes before
  serialisation. Large payloads (`SnapshotResponse`) split at app level
  via `chunk_index`/`total_chunks`. No IP fragments.
- **Logging discipline in the hot path.** Never emit a log line per
  frame. Allowed: per-batch-commit, per-reload, per-peer-heartbeat,
  per-config-load. Persistent warnings from a hot loop go through
  `logsetup.RateLimiter.warn(category)`.

If you're touching daemon code and can't explain which principle your
change respects, you're probably making it slower.

## DNS architecture (shipped v1.4.0)

Full pipeline shipped: compiler declares `dns_<qname>_v4/v6` sets,
daemon populates them from dnstap/PBDNSMessage. Operator reference:
`docs/shorewalld/index.md`.

Key decisions recorded here to avoid re-debating them:

- **dnstap over unix socket is the preferred default**, not RPZ+protobuf.
  dnstap is multi-vendor (unbound, knot-resolver, dnsdist), unix socket
  crosses mount namespaces cleanly, no port management.
- **PBDNSMessage over TCP** is the opt-in alternative for operators with
  existing protobuf pipelines. pdns refuses unix sockets for
  `protobufServer()`.
- **Do NOT poll `rec_control`** — `dump-cache` stalls the recursor;
  no `get-rrset` API exists; HTTP endpoint is flush-only.
- **`flags timeout` on every dns set** — stale entries auto-expire if
  shorewalld dies. TTL = `max(dns_ttl, 300s)`.
- **Both HA nodes run their own daemon** — conntrackd does not replicate
  nft set contents; each node maintains its own sets independently.
- **`CLIENT_RESPONSE` frames only**, not `RESOLVER_RESPONSE` — cache hits
  are included, TTL is already clamped to remaining cache lifetime.

## Open items

1. **dnstap smoke harness on the test VM** — script modelled on
   `tools/setup-remote-test-host.sh` that installs `pdns-recursor`,
   drops in `packaging/pdns-recursor/shorewalld.lua.template`,
   starts `shorewalld` + recursor, drives with `dig`, asserts nft sets
   populate within one TTL. Target host: `192.0.2.83`.
2. **Flame graph for scrape hot path** — `py-spy record --format
   flamegraph` during a load test; save artifact locally (not committed).

## Testing and Developement
Use project venv: /home/avalentin/projects/marcant-fw/shorewall/.venv
