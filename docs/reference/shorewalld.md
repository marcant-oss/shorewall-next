# shorewalld — monitoring + DNS-set API daemon

`shorewalld` is the long-running companion process to `shorewall-nft`.
It serves two jobs:

1. **Prometheus exporter** — scrapes per-rule packet/byte counters out
   of every `inet shorewall` table on the box, across multiple network
   namespaces, via a single libnftables round-trip per scrape.
2. **DNS-set API** *(opt-in)* — accepts a dnstap FrameStream from
   `pdns_recursor` and populates nft sets named `dns_<qname>_v4` /
   `dns_<qname>_v6` from DNS responses, so firewall rules can filter
   on hostname without runtime resolution.

Both jobs are off by default for the second one. Running `shorewalld`
with no flags starts a pure exporter bound to `:9748`.

## Install

Ships as part of the `shorewall-nft` package. The daemon itself is the
`shorewalld` script entry point:

```sh
# Pip install with optional deps.
pip install 'shorewall-nft[daemon]'

# Distro install — the binary is in the main shorewall-nft package.
apt install shorewall-nft
```

Runtime dependencies beyond `shorewall-nft` itself:

- `prometheus_client>=0.20` — scrape HTTP endpoint
- `dnspython>=2.4` — DNS wire parse (only needed when `--listen-api`
  is used)

Both live under the `[daemon]` extra in `pyproject.toml`. Debian and
RPM packages declare them as recommends, not hard depends, so the
main firewall compiler can still install on a minimal box.

## CLI

```
shorewalld [OPTIONS]

  --listen-prom HOST:PORT     Prometheus scrape endpoint (default :9748)
  --listen-api PATH           Unix socket for the dnstap consumer (off
                              by default; set e.g. /run/shorewalld/dnstap.sock
                              to enable)
  --netns SPEC                Namespace selection:
                                 (empty)        → daemon's own netns
                                 auto           → walk /run/netns/
                                 fw,rns1,rns2   → explicit comma list
  --scrape-interval SECS      Per-netns ruleset cache TTL (default 30)
  --reprobe-interval SECS     How often to re-check which netns have a
                              loaded inet shorewall table (default 300)
  --log-level LEVEL           debug, info, warning, error
```

## Metrics

All metrics carry a `netns` label (empty string = the daemon's own
namespace). Scrape endpoint is Prometheus plain-text at
`http://HOST:PORT/metrics`.

### Rule and set metrics (one per netns with a loaded ruleset)

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_packets_total` | Counter | `netns,table,chain,rule_handle,comment` |
| `shorewall_nft_bytes_total` | Counter | `netns,table,chain,rule_handle,comment` |
| `shorewall_nft_named_counter_packets_total` | Counter | `netns,name` |
| `shorewall_nft_named_counter_bytes_total` | Counter | `netns,name` |
| `shorewall_nft_set_elements` | Gauge | `netns,set` |

The `comment` label carries the rule's `?COMMENT` tag verbatim, so you
can identify rules from the Shorewall config even though nft handles
are opaque.

### Per-interface metrics (one per netns, always emitted)

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_iface_rx_packets_total` | Counter | `netns,iface` |
| `shorewall_nft_iface_rx_bytes_total` | Counter | `netns,iface` |
| `shorewall_nft_iface_tx_packets_total` | Counter | `netns,iface` |
| `shorewall_nft_iface_tx_bytes_total` | Counter | `netns,iface` |
| `shorewall_nft_iface_oper_state` | Gauge | `netns,iface` — 1=UP, 0=DOWN, 0.5=UNKNOWN |

### Conntrack metrics (one per netns)

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_ct_count` | Gauge | `netns` |
| `shorewall_nft_ct_max` | Gauge | `netns` |

### dnstap pipeline metrics (only when `--listen-api` is set)

| Metric | Type |
|---|---|
| `shorewalld_dnstap_frames_accepted_total` | Counter |
| `shorewalld_dnstap_frames_decode_error_total` | Counter |
| `shorewalld_dnstap_frames_dropped_queue_full_total` | Counter |
| `shorewalld_dnstap_frames_dropped_not_client_response_total` | Counter |
| `shorewalld_dnstap_frames_dropped_not_a_or_aaaa_total` | Counter |
| `shorewalld_dnstap_connections` | Gauge |
| `shorewalld_dnstap_workers_busy` | Gauge |
| `shorewalld_dnstap_queue_depth` | Gauge |
| `shorewalld_dnstap_queue_capacity` | Gauge |

Watch `queue_depth / queue_capacity` — if it climbs toward 1.0 the
decoder is falling behind the recursor and you should increase
`--scrape-interval`-equivalent tuning or throw hardware at it.

## Multi-netns operation

On a box with `fw`, `rns1`, `rns2` namespaces (the reference HA stack
shape), start with:

```sh
shorewalld --listen-prom :9748 --netns auto
```

`auto` walks `/run/netns/` and creates one collector profile per named
namespace, plus one for the daemon's own netns. Each profile always
includes a `LinkCollector` and a `CtCollector`; the `NftCollector` is
added only when `list table inet shorewall` succeeds in that netns,
and a periodic reprobe (default every 5 minutes) picks up tables that
appear or disappear after the daemon started.

This means you can run `shorewall-nft start` inside any netns
*after* shorewalld is already up, and the new ruleset shows up on the
next reprobe without a daemon restart.

## dnstap / DNS-set API

To enable the DNS-set machinery:

1. Start the daemon with `--listen-api /run/shorewalld/dnstap.sock`
   (the default path used in the systemd unit; pick any path writeable
   from the recursor's mount namespace).
2. Install the pdns_recursor Lua config from
   `packaging/pdns-recursor/shorewalld.lua.template` into
   `/etc/powerdns/recursor.d/shorewalld.lua` (adjust the socket path
   if different).
3. Reload the recursor: `systemctl reload pdns-recursor`.

shorewalld's unix socket is created with mode `0660`. The recursor
needs to be in the shorewall group, or chmod the socket `0666` at
daemon startup via a drop-in.

### How the pipeline works

```
  pdns_recursor
       │
       ▼  CLIENT_RESPONSE frame (FrameStream + protobuf)
  /run/shorewalld/dnstap.sock
       │
       ▼  reader coroutine (one per connection)
  bounded queue (default 10 000 frames)
       │
       ▼  os.cpu_count() decode threads
  dnstap.Dnstap → Message → response_message (DNS wire)
       │
       ▼  dnspython A/AAAA/TTL extraction
  DnsUpdate(qname, a_rrs, aaaa_rrs, ttl)
       │
       ▼  call_soon_threadsafe → SetWriter coroutine
  nft add element inet shorewall dns_github_com_v4 { 140.82.121.3 timeout 300s }
```

### Non-blocking guarantees

Three-stage backpressure chain:

1. **Recursor → socket**. pdns_recursor's dnstap writer is a bounded
   queue with drop-on-overflow. Resolver latency is never affected.
2. **Socket → shorewalld**. Kernel unix-socket recv buffer absorbs
   bursts.
3. **In-process queue → decode workers**. Bounded Python `queue.Queue`.
   On overflow we drop the frame and bump
   `shorewalld_dnstap_frames_dropped_queue_full_total`.

Drops only start at stage 3 if shorewalld can't keep up with the
recursor's sustained rate. Drops at stage 1 only start if shorewalld
is hung and the kernel socket buffer is also full. Either way, the
recursor hot path is untouched.

### Filtering

Two places you can filter qnames:

1. **Shorewalld-side** (recommended): use `QnameFilter` with an
   allowlist in the daemon's code, or accept everything and let the
   nft set lookup fail silently for qnames that don't have a set
   configured. Zero recursor impact.
2. **Producer-side**: uncomment the `postresolve` block in the Lua
   template. Runs a hash lookup inside the recursor's query thread —
   cheap (<1 µs per query) but it IS in the hot path, so benchmark it
   on a busy recursor before turning it on.

### Event type

shorewalld consumes `CLIENT_RESPONSE` only. This means every answer
the recursor sends to a client is seen — including cache hits — with
the TTL already clamped to the remaining cache lifetime. This is the
correct event: `RESOLVER_QUERY`/`RESOLVER_RESPONSE` would miss cache
hits entirely and produce stale/doubled updates.

## systemd units

Two units ship under `packaging/systemd/`:

- **`shorewalld.service`** — single process serving all namespaces
  (`--netns auto`). Recommended for most deployments.
- **`shorewalld@.service`** — templated, one instance per netns
  (`systemctl enable shorewalld@rns1`). Use this if you want per-netns
  process isolation or distinct Prometheus ports per netns.

Both require `CAP_NET_ADMIN` + `CAP_SYS_PTRACE` for the setns hop and
create `/run/shorewalld` via `RuntimeDirectory=`.

Override the command line with a drop-in, not by editing the unit:

```sh
mkdir -p /etc/systemd/system/shorewalld.service.d
cat >/etc/systemd/system/shorewalld.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/shorewalld \
    --listen-prom 0.0.0.0:9748 \
    --listen-api /run/shorewalld/dnstap.sock \
    --netns auto \
    --scrape-interval 15
EOF
systemctl daemon-reload
systemctl restart shorewalld
```

## Troubleshooting

- **Metrics endpoint returns 500 or nothing** — check
  `systemctl status shorewalld` and the journal. If
  `prometheus_client` is missing, the exporter logs a warning and
  returns cleanly — install it via `pip install shorewall-nft[daemon]`.
- **`netns="fw"` has no nft metrics** — either the table isn't loaded
  in that netns (`ip netns exec fw nft list table inet shorewall`) or
  the daemon lacks `CAP_SYS_PTRACE` to enter the target namespace.
- **Queue depth climbing toward capacity** — the decode workers can't
  keep up. Check `workers_busy` gauge; if it stays at `cpu_count`, the
  bottleneck is nft set writes, not decoding. Consider tightening the
  Lua-side filter or reducing the set churn.
- **dnstap frames dropped as `not_client_response`** — your recursor
  config has `logQueries=true` or is sending non-client events. Set
  `logQueries=false` in the Lua config.
- **`Failed to add element: …`** — the nft set doesn't exist yet;
  the rule compiler has to declare `set dns_<name>_v4 { type ipv4_addr;
  flags timeout; }` before shorewalld can populate it.

## Design notes

Full design memory lives at `docs/roadmap/shorewalld.md`. Source
docstrings:

- `shorewall_nft/daemon/core.py` — daemon lifecycle
- `shorewall_nft/daemon/exporter.py` — collector and scraper cache
- `shorewall_nft/daemon/discover.py` — netns profile builder
- `shorewall_nft/daemon/framestream.py` — fstrm reader
- `shorewall_nft/daemon/dnstap.py` — the whole dnstap pipeline
