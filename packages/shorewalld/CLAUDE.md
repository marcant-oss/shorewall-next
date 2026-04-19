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
