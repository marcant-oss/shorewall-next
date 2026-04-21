# CLAUDE.md — shorewalld

Prometheus exporter + DNS-based dynamic nft-set daemon for shorewall-nft.
Python package: `shorewalld`. Entry point: `shorewalld`.

**Development: use the repo-root venv at `../../.venv/` (Python 3.13).**
No per-package venv. See root `CLAUDE.md` for bootstrap.

## Key modules

- `cli.py`, `ctl.py`, `iplist_cli.py` — Click entry points (`shorewalld`,
  `shorewalld-ctl`, `shorewalld-iplist`).
- `core.py` — `Daemon.run()`: asyncio event loop, subsystem lifecycle.
- `config.py` — `shorewalld.conf` + allowlist loader.
- `control.py` — control unix socket (`register-instance`,
  `reload-instance`, status queries from `shorewall-nft`).
- `instance.py` — `InstanceManager`: per-netns allowlist state,
  register-resync wiring.
- `exporter.py` — shared Prometheus infrastructure: `NftScraper`,
  `ShorewalldRegistry`, `CollectorBase`, `Histogram`, `_MetricFamily`.
  Concrete collectors live under `collectors/`; this module re-exports
  them for back-compat.
- `collectors/` — one module per Prometheus collector:
  `nft.py`, `flowtable.py`, `link.py`, `qdisc.py`, `conntrack.py`
  (CTNETLINK — proxied via `READ_KIND_CTNETLINK` worker RPC, no setns), `ct.py`, `snmp.py`,
  `netstat.py`, `sockstat.py`, `softnet.py`, `neighbour.py`,
  `address.py`, `worker_router.py` (`WorkerRouterMetricsCollector`).
  Shared helpers in `_shared.py` (`_AF_NAMES`, `_read_int_via_router`).
- `discover.py` — netns auto-discovery (`/run/netns/`).
- `dnstap.py` + `framestream.py` — FrameStream unix socket server +
  frame decoder.
- `pbdns.py` — PowerDNS protobuf stream server.
- `dns_pull_resolver.py` — periodic forward-resolve fallback
  (per-`(qname, netns)` scheduling).
- `dns_wire.py` — DNS wire-format parsing (qname / RR extraction).
- `worker_router.py` — persistent-fork `WorkerRouter` for per-netns
  nft writes AND `/proc`-file reads (`LocalWorker` for default netns,
  `ParentWorker` for named netns with auto-respawn). Sync wrappers
  `read_file_sync` / `count_lines_sync` bridge the scrape thread to
  the asyncio loop via `run_coroutine_threadsafe`.
- `worker_test_helpers.py` — `inproc_worker_pair`, a threaded in-process
  stand-in for the fork/SEQPACKET path used by unit tests.
- `nft_worker.py` — forked-child entry point; dispatches on datagram
  magic to build an nft script from batched proposals (`MAGIC_REQUEST`)
  or to serve `/proc` reads via `_handle_read` (`MAGIC_READ_REQ`).
- `worker_transport.py` + `batch_codec.py` + `read_codec.py` — IPC
  framing between router and workers (set-mutation batches vs file
  reads; one SEQPACKET pair carries both).
- `dns_set_tracker.py` — `(set_name, ip) → expiry` LRU + proposal/verdict.
- `setwriter.py` — coalescing `SetWriter` (batched netlink writes).
- `dnstap_bridge.py` — routes dnstap answers through tracker or direct-nft.
- `state.py` — persistent set state across daemon restarts.
- `peer.py` — HA peer-link UDP (snapshot + incremental sync).
- `sockperms.py` — unix-socket permission helpers.
- `tap.py` + `logsetup.py` — live trace output + rate-limited logging.
- `iplist/` — static IP-list backend.
- `proto/` — hand-compiled protobuf (`dnstap_pb2.py`, `peer_pb2.py`,
  `dnsmessage_pb2.py`).  `__init__.py` injects `_builder_compat.py`
  into `sys.modules['google.protobuf.internal.builder']` when the real
  module is absent (protobuf < 3.20, e.g. AlmaLinux 10 ships 3.19.6).
  `_builder_compat.py` re-implements `BuildMessageAndEnumDescriptors` /
  `BuildTopDescriptorsAndMessages` via `message_factory.MessageFactory`
  which exists in protobuf 3.x.  Do **not** modify the generated
  `*_pb2.py` files to work around this — the shim is transparent.

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
  *only then* do the full parse. 99 % of frames are waste.  Both passes are
  active in both ingestion paths:
  ``_peek_message_type()`` in ``dnstap.py`` walks the outer Dnstap varint
  stream to field 14 (``Message``), then the inner stream to field 1
  (``type``), and returns the enum int without calling ``ParseFromString``.
  ``DecodeWorkerPool._decode_one()`` calls the peek first; only frames whose
  type is in ``RESPONSE_MESSAGE_TYPES`` reach the full parse.  Skipped frames
  are counted in ``shorewalld_dnstap_frames_skipped_by_type_total``.
  ``_peek_type_and_qname()`` in ``pbdns.py`` walks the PBDNSMessage varint
  stream to field 1 (``type``) and field 12 (``question``), descends into
  the DNSQuestion sub-message to extract field 1 (``qName``), and returns
  ``(type_int, qname_bytes)`` without calling ``ParseFromString``.
  ``decode_pbdns_frame()`` calls the peek first; non-response types are
  dropped (``shorewalld_pbdns_frames_skipped_by_type_total``) and RESPONSE
  frames with an unregistered qname are dropped before the full parse
  (``shorewalld_pbdns_frames_skipped_by_qname_total``).
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
- **Zero-fork for new work; one persistent fork per netns.** Never
  shell out. libnftables in-process via `NftInterface`, pyroute2 for
  link / qdisc / neighbour / address dumps (pyroute2 forks internally
  to bind each netlink socket to the target netns). `/proc` and
  `/sys` reads run inside the already-forked nft worker that owns
  the target netns — see the file-read RPC under `read_codec.py` and
  the "Read RPC: netns-pinned /proc reads" section below. The scrape
  thread itself never calls `setns(2)`. `ConntrackStatsCollector` WAS
  the lone remaining direct `_in_netns()` hop; it has been converted to
  use `READ_KIND_CTNETLINK` via the worker RPC — the scrape thread is
  now entirely free of `setns(2)` calls.
- **pyroute2 handles cached per netns.** Four collectors (`LinkCollector`,
  `QdiscCollector`, `NeighbourCollector`, `AddressCollector`) share one
  `IPRoute` per managed netns via `collectors._shared.get_rtnl`. A single
  pyroute2 fork happens on first use; all subsequent scrapes reuse the
  live netlink socket.  Handles are evicted on `NetlinkError` (stale
  netns) and closed cleanly on daemon shutdown via `close_all_rtnl()`.
  Current cache size is reported as `shorewalld_rtnl_handles_cached`.
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

## nft worker architecture

One `ParentWorker` per managed netns, owned by `WorkerRouter`.

**Default netns (`""`)** → `LocalWorker`: no fork, runs nft via
`NftInterface` in a dedicated `ThreadPoolExecutor` thread. Looks up
set names via the live `DnsSetTracker` (direct reference, always
current).

**Named netns (e.g. `"fw"`)** → `ParentWorker._start_forked()`:
forks a child, calls `setns(CLONE_NEWNET)`, creates `NftInterface`
bound to that netns, then loops on `recv_into` (blocking, no timeout).
The fork inherits a copy-on-write snapshot of the parent's tracker;
the lookup closure is built from that snapshot and passed to
`nft_worker_entrypoint`. **Critical: the fork must happen after
`tracker.load_registry()` has run**, otherwise the child's snapshot
is empty and all ops are silently dropped.

**Lazy spawn rule**: in `_start_empty_dns_pipeline` workers are NOT
pre-started. `WorkerRouter.dispatch()` calls `add_netns()` on first
use, which fires after `InstanceManager` has loaded the allowlist and
populated the tracker. Do NOT add eager `add_netns` calls back to
`_start_empty_dns_pipeline` — they break the fork-after-load
invariant.

**`SO_SNDTIMEO` only** (not `socket.settimeout`): `WorkerTransport`
applies send timeout via `SO_SNDTIMEO` so the parent times out if
the worker stops draining, while leaving `SO_RCVTIMEO` unset so
workers block indefinitely on recv waiting for the first batch.

**Per-group netns routing in `PullResolver`**: `PullResolver._group_netns`
maps `primary_qname → [netns, ...]`. `InstanceManager._apply_merged()`
builds this map from instance configs and passes it to
`PullResolver.update_registry(qname_netns=...)` on every merge. A
single qname shared by two instances in different netns gets submitted
to both. Falls back to `_default_netns` for qnames not in the map.

**Register-resync rule**: every `register-instance` on the control
socket is an explicit restart signal from shorewall-nft — the
`inet shorewall` table in that netns may have just been deleted and
recreated. `InstanceManager.register()` therefore, after the allowlist
load, unconditionally:

1. Calls `tracker.clear_elements(set_ids_for_qnames(instance qnames))`
   so `propose()` doesn't DEDUP against deadlines describing kernel
   state that no longer exists.
2. Calls `router.respawn_netns(cfg.netns)` for non-default netns so
   the worker re-forks with the current tracker + a fresh libnftables
   handle inside the (possibly just-recreated) table.
3. Calls `pull_resolver.refresh(primary_qname)` for each pull-enabled
   group so the kernel sets repopulate within ~1 s instead of waiting
   for the next scheduled resolve (up to `ttl_floor * 0.8`).

Do NOT extend `_apply_merged` to cover this case — its "new-names ⇒
respawn" path only exists for operator-invoked `reload-instance` where
the table is assumed unchanged.  Register and reload have deliberately
different semantics.

**Element refresh requires explicit `expires`**: `nft_worker.build_nft_script`
emits `add element ... { ip timeout Ts expires Ts }` — both keywords. The
Linux nft kernel does NOT reset an existing element's countdown when
`add element` is re-issued with the same `timeout`; it silently keeps
the original deadline. Setting `expires` populates `NFTA_SET_ELEM_EXPIRATION`
which the kernel always honours. Do not drop the `expires` keyword to "save
bytes" — the `dns_*_v4/v6` sets will silently age out between pull cycles
even though every metric reports success.

**Auto-respawn on transport loss**: `ParentWorker._drain_replies` no longer
just nullifies the transport on EOF — it also reaps the dead child and
schedules `_auto_respawn()`. Backoff: 0 → 1 → 2 → … → 30 s; resets after
`_RESPAWN_HEALTHY_AFTER` (30 s) of liveness. Covers worker crashes, OOM
kills, and the "named netns is briefly absent during ip-netns-del/add"
window. Without this, `dispatch()` would fail forever with
`ParentWorker not started or already stopped` once the worker died.

## Read RPC: netns-pinned /proc reads

The nft worker now serves a second RPC family in parallel with batch
set-mutations. Collectors that scrape `/proc/net/*` or
`/proc/sys/net/netfilter/*` no longer `setns(2)` themselves — they
route the read through the worker that is already pinned to the
target netns. The scrape thread stays in the default netns; no
thread-level `setns` race window, no `CAP_SYS_ADMIN` requirement on
the scrape path.

Three message kinds (`read_codec.py`):

- `READ_KIND_FILE` → worker `open(path).read(MAX_FILE_BYTES + 1)`,
  reply carries raw bytes. `TOO_LARGE` returned if file exceeds
  60 KiB — callers fall back to `count_lines`.
- `READ_KIND_COUNT_LINES` → worker streams line by line, reply
  carries an 8-byte big-endian u64. Used for `/proc/net/route` and
  `/proc/net/ipv6_route` (would otherwise blow the 64 KiB datagram
  cap on a full-BGP v6 table).
- `READ_KIND_CTNETLINK` → worker opens (or reuses) an `NFCTSocket`
  already bound to the child's netns, calls `stat()` to get per-CPU
  counters, sums across CPUs, and returns a fixed 64-byte
  `CtNetlinkStats` struct. Replaces the last `_in_netns()` hop that
  `ConntrackStatsCollector` previously used on the scrape thread.
  `WorkerRouter.ctnetlink_stats_sync(netns)` is the scrape-thread
  entry point; it mirrors `read_file_sync` / `count_lines_sync`.

Wire format: 18-byte request header + UTF-8 path; 20-byte response
header + payload. Dispatched by peeking the first four bytes of each
datagram (`SWNF` = batch, `SWRR` = read) — keeps the decoder
branch-free and makes ``strace`` output human-readable.

Dispatch is asymmetric per worker type:

- **Default netns (`netns=""`)** → `LocalWorker._dispatch_read`: no
  fork, no IPC. Runs `_handle_read` on the default thread pool via
  `loop.run_in_executor(None, ...)` — keeps a potentially long read
  (a full-BGP `/proc/net/ipv6_route` line-count is ~100 ms of work)
  off the event-loop thread.
- **Named netns** → `ParentWorker._dispatch_read`: allocates a
  `req_id`, sends the request through the shared SEQPACKET pair,
  awaits the reply via a dedicated `_pending_reads` dict keyed on
  `req_id`. `_drain_replies` peeks the reply magic and routes to
  either the batch or the read pending table.

Scrape-thread adapter: `WorkerRouter.read_file_sync` /
`count_lines_sync` wrap the async path in
`asyncio.run_coroutine_threadsafe(..., self.loop).result(timeout=5.0)`.
Timeout → the collector returns `None` and skips the sample rather
than stalling the whole scrape. Exceptions are logged at DEBUG and
swallowed — no scrape should ever fail because a single file read
hiccuped.

**Tracker attach ordering**: `WorkerRouter` is created early in
`Daemon.run()` with `tracker=None` so collectors can delegate reads
from the first scrape onwards. When the DNS-set pipeline bootstraps
later it calls `router.attach_tracker(tracker)` and *respawns* any
workers that were already forked for scrape-only traffic, because
the set-name lookup closure was captured at fork time with the
(None) tracker reference and will not otherwise see the newly-
attached tracker.

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

1. **Flame graph for scrape hot path** — `py-spy record --format
   flamegraph` during a load test; save artifact locally (not committed).
   (The dnstap smoke harness is shipped as
   `tools/setup-shorewalld-dnstap-smoke.sh`; target host 192.0.2.83.)
