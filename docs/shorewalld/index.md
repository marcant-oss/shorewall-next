# shorewalld — monitoring + DNS-set API daemon

`shorewalld` is the long-running companion process to `shorewall-nft`.
It serves three jobs:

1. **Prometheus exporter** — scrapes per-rule packet/byte counters out
   of every `inet shorewall` table on the box, across multiple network
   namespaces, via a single libnftables round-trip per scrape.
2. **DNS-set API** *(opt-in)* — accepts a dnstap FrameStream from
   `pdns_recursor` and populates nft sets named `dns_<qname>_v4` /
   `dns_<qname>_v6` from DNS responses, so firewall rules can filter
   on hostname without runtime resolution.
3. **IP-list sets** *(opt-in)* — periodically fetches public prefix
   lists from cloud providers, CDNs, IX route servers, and RFC bogon
   definitions, and writes them into nft `flags interval` sets so
   firewall rules can match on cloud service, ASN, or IX membership.

Running `shorewalld` with no flags starts a pure exporter bound to `:9748`.

## Configuration file

Operator settings live in `shorewalld.conf`, searched at these
locations in order (first hit wins):

1. `--config-file PATH` on the CLI
2. `/etc/shorewall/shorewalld.conf`
3. `/etc/shorewalld.conf`

A missing file is a silent no-op; the daemon falls back entirely
to CLI flags + built-in defaults. **Precedence** is always:
explicit CLI flag > config-file value > built-in default, so an
operator can temporarily override a file value without editing
the file.

Shell-flavoured `KEY=value` lines, `#` comments, optional `'`/`"`
quoting:

```
# /etc/shorewall/shorewalld.conf

LISTEN_PROM=:9748
NETNS=fw,rns1,rns2
SCRAPE_INTERVAL=30
REPROBE_INTERVAL=300

# Multi-instance (repeat INSTANCE= for each directory)
INSTANCE=fw:/etc/shorewall
INSTANCE=rns1:/etc/shorewall-rns1
MONITOR=no                     # set yes to enable inotify watching

# Control socket
CONTROL_SOCKET=/run/shorewalld/control.sock
# CONTROL_SOCKET_NETNS=fw      # optional: bind inside netns

# IP-list sets (one block per set; see "IP-list sets" section)
IPLIST_BOGON_PROVIDER=bogon
IPLIST_BOGON_SET_V4=bogon_v4
IPLIST_BOGON_SET_V6=bogon_v6

# Legacy — use INSTANCE= instead
# ALLOWLIST_FILE=/var/lib/shorewalld/dns-allowlist.tsv
LISTEN_API=/run/shorewalld/dnstap.sock
PBDNS_SOCKET=/run/shorewalld/pbdns.sock
PBDNS_TCP=127.0.0.1:9999       # pdns protobufServer() is TCP-only

# Unix socket ownership applied to every daemon-owned socket
# (LISTEN_API, PBDNS_SOCKET). Typical production shape: 0660
# with SOCKET_GROUP=pdns so the recursor can connect as its
# normal non-root user. Owner defaults to the shorewalld
# process UID (usually root); group defaults to unchanged.
SOCKET_MODE=0660
SOCKET_OWNER=root
SOCKET_GROUP=pdns

PEER_LISTEN=0.0.0.0:9749
PEER_ADDRESS=10.0.0.2:9749
PEER_SECRET_FILE=/etc/shorewall/peer.key
PEER_HEARTBEAT_INTERVAL=5

STATE_DIR=/var/lib/shorewalld
RELOAD_POLL_INTERVAL=2

LOG_LEVEL=info
LOG_TARGET=syslog
LOG_FORMAT=structured
LOG_LEVEL_peer=debug   # per-subsystem override
```

Unknown keys are silently ignored so adding future knobs doesn't
break older deployments. Malformed lines or unparseable values
(e.g. `STATE_ENABLED=maybe`) raise an error at startup — the
daemon refuses to run with a broken config rather than silently
falling back.

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

  --listen-prom HOST:PORT          Prometheus scrape endpoint (default :9748)
  --listen-api PATH                Unix socket for the dnstap consumer
  --netns SPEC                     Namespace selection:
                                      (empty)       → daemon's own netns
                                      auto          → walk /run/netns/
                                      fw,rns1,rns2  → explicit comma list
  --instance [NETNS:]DIR           shorewall-nft config directory (repeat
                                   for multiple instances). Replaces
                                   --allowlist-file.
  --monitor                        Watch instance dirs with inotify; reload
                                   dnsnames.compiled on change.
  --control-socket PATH            Unix socket for the control API
                                   (refresh-iplist, reload-instance, …)
  --control-socket-netns NETNS     Bind the control socket inside this netns
  --scrape-interval SECS           Per-netns ruleset cache TTL (default 30)
  --reprobe-interval SECS          How often to re-check netns tables (default 300)
  --log-level LEVEL                debug, info, warning, error

Subcommands:
  shorewalld tap [OPTIONS]         Live dnstap inspection (see below)
  shorewalld ctl [OPTIONS] CMD     Control socket client
  shorewalld iplist [OPTIONS] CMD  IP-list provider explorer
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

## Multi-instance operation (`--instance`)

A single `shorewalld` process can manage multiple independent
`shorewall-nft` config directories — one per network namespace. Each
directory is called an *instance*.

```sh
shorewalld \
    --instance fw:/etc/shorewall \
    --instance rns1:/etc/shorewall-rns1 \
    --instance /etc/shorewall6          # root ns, colon optional
```

Format: `[netns:]<dir>`. Omitting the netns (or the colon entirely)
means the daemon's own (root) namespace. The instance name is derived
from the netns name, or from the directory basename when no netns is
given.

For each instance shorewalld expects a compiled DNS allowlist at
`<dir>/dnsnames.compiled` — the file produced by `shorewall-nft start`.
On startup (and on every explicit reload), shorewalld reads that file
and updates its in-memory DNS tracker.

`--instance` replaces the legacy `--allowlist-file` flag.
`--allowlist-file <path>` is still accepted but logs a deprecation
warning and is treated as `--instance <path>`.

### Instance reload

```sh
# Reload all instances (re-read dnsnames.compiled from every dir).
shorewalld ctl reload-instance

# Reload a single instance by name.
shorewalld ctl reload-instance --name fw
```

Typically called from the post-start hook of `shorewall-nft.service`
so the DNS tracker always reflects the current compiled config:

```ini
# /etc/systemd/system/shorewall-nft.service.d/shorewalld-notify.conf
[Service]
ExecStartPost=-/usr/bin/shorewalld ctl \
    --socket /run/shorewalld/control.sock \
    reload-instance --name fw
```

### File-watching (`--monitor`)

`--monitor` (or `MONITOR=yes` in `shorewalld.conf`) enables inotify
watching on every instance's `dnsnames.compiled` file. When the file
is atomically replaced by `shorewall-nft start`, shorewalld detects
the write and reloads the instance immediately — no hook needed.

**Caution:** `--monitor` conflicts with the explicit reload-hook
approach because both paths fire independently on a `shorewall-nft
start`. Use one or the other, not both. For most deployments the
explicit hook (`ExecStartPost`) is safer because it serialises the
reload.

```
# shorewalld.conf
MONITOR=yes
```

Uses `watchfiles` if installed, otherwise falls back to 5-second polling.

---

## IP-list sets

shorewalld can periodically fetch public prefix lists and write them
into nft `flags interval` sets. The sets are populated in every
network namespace that has a loaded `inet shorewall` table, diffed
against the current kernel state so only deltas are written.

### Declaring the sets (compiler side)

The operator declares the nft sets in their shorewall-nft config (the
same way `dns_*` sets are declared). shorewalld populates them; it
never creates or destroys sets.

Example set declaration in a shorewall-nft `nft-extras` snippet:

```nft
set cloud_aws_ec2_eu_v4 {
    type ipv4_addr
    flags interval
    comment "AWS EC2 eu-* — managed by shorewalld"
}
set cloud_cf_v4 {
    type ipv4_addr
    flags interval
    comment "Cloudflare CDN — managed by shorewalld"
}
set bogon_v4 {
    type ipv4_addr
    flags interval
    comment "RFC bogons — managed by shorewalld"
}
```

### Configuration

In `shorewalld.conf`, one block per set. Each block is identified by a
unique name (the middle part of the key: `IPLIST_<NAME>_…`).

```ini
# AWS EC2, EU regions only
IPLIST_AWS_EC2_EU_PROVIDER=aws
IPLIST_AWS_EC2_EU_FILTERS=service:EC2,region:eu-*
IPLIST_AWS_EC2_EU_SET_V4=cloud_aws_ec2_eu_v4
IPLIST_AWS_EC2_EU_REFRESH=3600

# Cloudflare (no filters — one global range)
IPLIST_CF_PROVIDER=cloudflare
IPLIST_CF_SET_V4=cloud_cf_v4
IPLIST_CF_SET_V6=cloud_cf_v6
IPLIST_CF_REFRESH=3600

# Azure Active Directory
IPLIST_AZURE_AD_PROVIDER=azure
IPLIST_AZURE_AD_FILTERS=tag:AzureActiveDirectory
IPLIST_AZURE_AD_SET_V4=cloud_azure_ad_v4
IPLIST_AZURE_AD_REFRESH=3600

# GCP europe-west3 and global
IPLIST_GCP_EU_PROVIDER=gcp
IPLIST_GCP_EU_FILTERS=scope:europe-west3,scope:global
IPLIST_GCP_EU_SET_V4=cloud_gcp_eu_v4
IPLIST_GCP_EU_REFRESH=3600

# GitHub Actions runners
IPLIST_GH_ACTIONS_PROVIDER=github
IPLIST_GH_ACTIONS_FILTERS=group:actions
IPLIST_GH_ACTIONS_SET_V4=cloud_github_v4
IPLIST_GH_ACTIONS_REFRESH=3600

# RFC bogons (offline, no HTTP)
IPLIST_BOGON_PROVIDER=bogon
IPLIST_BOGON_SET_V4=bogon_v4
IPLIST_BOGON_SET_V6=bogon_v6
IPLIST_BOGON_REFRESH=86400

# DE-CIX Frankfurt peering prefixes
IPLIST_DECIX_PROVIDER=peeringdb
IPLIST_DECIX_FILTERS=ix:DE-CIX Frankfurt
IPLIST_DECIX_SET_V4=ix_decix_v4
IPLIST_DECIX_SET_V6=ix_decix_v6
IPLIST_DECIX_REFRESH=86400
```

Keys per block:

| Key | Required | Description |
|---|---|---|
| `PROVIDER` | yes | Provider name (see below) |
| `FILTERS` | no | Comma-separated `dimension:value` pairs |
| `SET_V4` | no | nft set name for IPv4 prefixes |
| `SET_V6` | no | nft set name for IPv6 prefixes |
| `REFRESH` | no | Refresh interval in seconds (default 3600) |
| `MAX_PREFIXES` | no | Safety cap — skip write if exceeded (default 100 000) |

### Providers and filters

#### `aws` — AWS ip-ranges.json

Source: `https://ip-ranges.amazonaws.com/ip-ranges.json`

| Dimension | Values | Example |
|---|---|---|
| `service` | `EC2`, `S3`, `CLOUDFRONT`, `ROUTE53`, `GLOBALACCELERATOR`, `API_GATEWAY`, `AMAZON` (all), … | `service:EC2` |
| `region` | `eu-central-1`, `us-east-1`, `GLOBAL`, … — **glob patterns supported** | `region:eu-*` |

#### `azure` — Azure Service Tags

Source: Azure Service Tags weekly JSON (Microsoft CDN).

| Dimension | Values | Example |
|---|---|---|
| `tag` | `AzureCloud`, `Storage`, `Sql`, `AzureActiveDirectory`, `ActionGroup`, `AzureDevOps`, `AppService`, `AzureMonitor`, … (~200 tags) — **glob + region suffix** (`Storage.WestEurope`) | `tag:AzureActiveDirectory` |
| `url` | Override the source URL (Microsoft rotates it weekly) | `url:https://…` |

#### `gcp` — Google Cloud

Source: `https://www.gstatic.com/ipranges/cloud.json`

| Dimension | Values | Example |
|---|---|---|
| `service` | `Google Cloud` (coarse) | `service:Google Cloud` |
| `scope` | Region name or `global` | `scope:europe-west3` |

#### `cloudflare`

Sources: `https://www.cloudflare.com/ips-v4` and `ips-v6`

No filter dimensions. Both URLs are fetched and combined.

#### `github` — GitHub meta API

Source: `https://api.github.com/meta`

| Dimension | Values |
|---|---|
| `group` | `actions`, `api`, `copilot`, `dependabot`, `git`, `hooks`, `packages`, `pages`, `web` — **glob supported** |

#### `bogon` — RFC special-use ranges

No HTTP fetch — fully offline. Hardcoded from RFCs 1122, 1918, 6598,
5737, 3927, 2544, 4291, 6052, 3849, 4193.

| Dimension | Values |
|---|---|
| `type` | `bogon` (v4+v6, default), `ipv4_only`, `ipv6_only` |

IPv4: `0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15
198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
255.255.255.255/32`

IPv6: `::/128 ::1/128 ::ffff:0:0/96 64:ff9b::/96 100::/64 2001::/32
2001:2::/48 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8`

#### `peeringdb` — PeeringDB IX prefixes

Source: `https://www.peeringdb.com/api/ixpfx`

| Dimension | Values | Example |
|---|---|---|
| `ix` | Internet Exchange name (case-insensitive substring) | `ix:DE-CIX Frankfurt` |
| `asn` | Numeric ASN | `asn:1299` |

### Exploring available filters

```sh
# List all providers and their filter dimensions (no network).
shorewalld iplist providers

# Show available values for a filter dimension (live fetch).
shorewalld iplist filters aws --dimension service
shorewalld iplist filters aws --dimension region
shorewalld iplist filters azure --dimension tag
shorewalld iplist filters github --dimension group
shorewalld iplist filters peeringdb --dimension ix

# Preview what a filter configuration would yield.
shorewalld iplist show aws --filters service:EC2,region:eu-* --family v4
```

### Manual refresh

```sh
# Immediate full refresh (all lists) via SIGUSR1.
kill -USR1 $(pidof shorewalld)
systemctl kill --signal=USR1 shorewalld

# Selective refresh via control socket.
shorewalld ctl --socket /run/shorewalld/control.sock refresh-iplist
shorewalld ctl --socket /run/shorewalld/control.sock refresh-iplist --name aws_ec2_eu

# Status of all lists.
shorewalld ctl --socket /run/shorewalld/control.sock iplist-status
```

### Metrics

```
shorewalld_iplist_prefixes_total{name,family}        # gauge — current prefix count
shorewalld_iplist_last_refresh_timestamp{name}       # gauge — unix timestamp
shorewalld_iplist_fetch_duration_seconds{name}       # summary
shorewalld_iplist_fetch_errors_total{name,reason}    # counter
shorewalld_iplist_updates_total{name,op}             # counter — op=add|remove
```

### Log output

Every refresh logs one `INFO` line:

```
iplist aws_ec2_eu: refresh complete — 312 v4 + 0 v6 prefixes
  (+5 added, -2 removed) across 3 netns [2.1s, ETag hit]
```

Level guide:

| Situation | Level |
|---|---|
| Refresh complete (delta or no-op) | `INFO` / `DEBUG` |
| Filter matched 0 prefixes | `WARNING` (rate-limited) |
| HTTP error, entering backoff | `WARNING` |
| max_prefixes exceeded, write skipped | `ERROR` |

---

## Control socket (`--control-socket`)

An optional Unix socket for operator control commands. Line-oriented
JSON protocol.

```ini
# shorewalld.conf
CONTROL_SOCKET=/run/shorewalld/control.sock
CONTROL_SOCKET_NETNS=fw        # optional: bind inside netns "fw"
```

Or via CLI: `--control-socket /run/shorewalld/control.sock`.

The socket is always created with `root:root 0660`. Only root can
connect by default; add the socket to a group via a drop-in if needed.

### `shorewalld ctl` — control client

```sh
shorewalld ctl --socket PATH <command> [options]

Commands:
  ping                         Verify the daemon is alive.
  refresh-iplist [--name N]    Force immediate IP-list refresh.
  iplist-status                Show status of all IP-list configs.
  reload-instance [--name N]   Reload DNS allowlist from disk.
  instance-status              Show status of all instances.
```

The `--socket` flag defaults to `/run/shorewalld/control.sock`.

Example:

```sh
$ shorewalld ctl ping
{"ok": true, "version": "1"}

$ shorewalld ctl iplist-status
[
  {"name": "aws_ec2_eu", "prefixes_v4": 312, "prefixes_v6": 0,
   "last_refresh": "2026-04-18T14:23:01Z", "status": "ok"},
  {"name": "bogon", "prefixes_v4": 15, "prefixes_v6": 12,
   "last_refresh": "2026-04-18T14:20:00Z", "status": "ok"}
]
```

---

## sysconfig / defaults file

The systemd units read an optional `EnvironmentFile` before starting
the daemon. This is the standard way to pass multi-value flags (like
multiple `--instance`) that can't easily go in `shorewalld.conf`.

Locations (first present wins):

- RPM-based distros: `/etc/sysconfig/shorewalld`
- Debian-based distros: `/etc/default/shorewalld`

The file sets a single shell variable:

```bash
# /etc/sysconfig/shorewalld   (or /etc/default/shorewalld)
SHOREWALLD_ARGS="--instance fw:/etc/shorewall \
                 --instance rns1:/etc/shorewall-rns1 \
                 --control-socket /run/shorewalld/control.sock"
```

`$SHOREWALLD_ARGS` is appended to `ExecStart` in the systemd unit.
All existing `shorewalld.conf` knobs still work alongside it —
the two files serve different purposes: `shorewalld.conf` for
scalar settings, `SHOREWALLD_ARGS` for flags that repeat or that
are awkward in KEY=VALUE form.

A template is installed at `packaging/sysconfig/shorewalld`.

`systemctl reload shorewalld` sends `SIGUSR1` (refreshes all IP
lists without restarting the daemon).

---

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

## DNS-backed nft sets (`dns:` rule syntax)

shorewalld can populate nftables sets with the answers to DNS
queries so a Shorewall rule can match on hostname instead of
literal IP. The compiler declares the sets, the daemon populates
them from the local recursor, and the result looks like a
first-class rule to the user:

```
# /etc/shorewall46/rules
ACCEPT      fw      net:dns:github.com           tcp     443
DROP        fw      net:!dns:badhost.example     -       -
```

The `dns:` prefix is recognised in the SOURCE/DEST columns and
triggers three things at compile time:

1. The hostname is registered with `FirewallIR.dns_registry`.
2. Two sets are declared in the generated nft script —
   `dns_github_com_v4` (type `ipv4_addr`) and `dns_github_com_v6`
   (type `ipv6_addr`), both with `flags timeout` and the
   configured size.
3. The rule is emitted twice, once per family, matching against
   the respective set with `ip daddr @dns_github_com_v4` /
   `ip6 daddr @dns_github_com_v6`.

Name sanitisation is deterministic: `qname_to_set_name()` in
`shorewall_nft/nft/dns_sets.py` is the single source of truth and
both the compiler and shorewalld import it, so there is no room
for naming drift between compile-time and runtime.

### `dnsnames` config file (optional)

If you want per-host overrides for the TTL floor/ceil or set
size, drop a `dnsnames` file in `/etc/shorewall46/`:

```
# NAME            TTL_FLOOR  TTL_CEIL  SIZE   COMMENT
github.com        300        86400     256    GitHub web+API
api.stripe.com    60         3600      32     Payment webhooks
cdn.example.com   -          -         -      Uses defaults
```

Columns: hostname, TTL floor seconds, TTL ceiling seconds, set
size, free-text comment. `-` means "inherit the global default
from shorewall.conf". Any hostname not listed falls back to the
defaults too.

Hostnames seen only in `rules` (without an explicit `dnsnames`
entry) still get registered with default settings, so the file
is purely for operators who want fine-grained control.

### Global defaults (shorewall.conf)

```
DNS_SET_TTL_FLOOR=300        # clamp minimum TTL (s)
DNS_SET_TTL_CEIL=86400       # clamp maximum TTL (s)
DNS_SET_SIZE=512             # element capacity per set
```

### Compiled allowlist

After `shorewall-nft start`, the compiler writes the resolved
set of hostnames + per-name overrides to
`/etc/shorewall/dnsnames.compiled`. shorewalld reads that file
at startup to build its in-memory allowlist. It's the contract
between compile-time and runtime — if you want to know whether a
hostname made it past the compiler, grep the compiled file.

## `shorewalld tap` — operator inspection tool

`shorewalld tap` is a `tcpdump`-for-DNS-answers CLI that binds a
dnstap unix socket and pretty-prints every frame it sees. Useful
for:

* verifying pdns_recursor is actually sending frames before
  anyone looks at Prometheus
* tuning the `dnsnames` allowlist (shows in-allowlist / not tags)
* debugging per-rcode filtering without grepping journald

```sh
shorewalld tap --socket /tmp/shorewalld-test.sock \
               --format pretty \
               --allowlist /etc/shorewall/dnsnames.compiled \
               --filter-rcode NXDOMAIN
```

Flags:

| Flag | Purpose |
|---|---|
| `--socket PATH` | required — unix socket path to listen on |
| `--format pretty\|structured\|json` | pretty (TTY default), key=value for grep, JSON for `jq` |
| `--filter-qname REGEX` | show only matching qnames |
| `--filter-rcode NAME` | filter by rcode (`NOERROR`, `NXDOMAIN`, ...) |
| `--show-queries` | include CLIENT_QUERY frames (default: responses only) |
| `--allowlist PATH` | path to `dnsnames.compiled` — frames are tagged with `[allowlist ✓]` / `[unknown]` |
| `--count N` | exit after N matching frames |
| `--no-color` | force plain output even on a TTY |

Pretty output example:

```
TIME           TYPE            RCODE      QNAME                         LEN   TAG
20:58:12.123   CLIENT_RESPONSE NOERROR    github.com                    47    [allowlist ✓]
20:58:12.201   CLIENT_RESPONSE NXDOMAIN   nonexistent.example.invalid   52    [unknown]
20:58:12.301   CLIENT_RESPONSE NOERROR    api.stripe.com                44    [allowlist ✓]
```

On exit (Ctrl-C or `--count`), a summary lists totals by type,
rcode, top-10 qnames, and the allowlist hit rate — the fastest
way to tell if your allowlist covers the real traffic.

Tap runs as its own *listener* on the configured path; point
pdns_recursor at that same path if you want to observe the live
stream without stopping shorewalld itself.

## Ingestion path: dnstap vs PBDNSMessage

shorewalld ships with two DNS answer ingestion paths. **dnstap
is the recommended default** and the only path activated by the
smoke test (`tools/setup-shorewalld-dnstap-smoke.sh`); the
PBDNSMessage path stays in-tree as an opt-in alternative.

### Why dnstap is preferred

| Property | dnstap | PBDNSMessage |
|---|---|---|
| Standard | fstrm / dnstap (multi-vendor) | pdns-specific |
| Producers | pdns-recursor, unbound, dnsdist, knot-resolver | pdns-recursor only |
| Transports | **unix socket + TCP** | **TCP only** (pdns refuses unix) |
| Wire format | raw DNS bytes in envelope | pre-decomposed DNSRR records |
| Consumer cost | ~100 µs dnspython parse per frame | ~20 µs skip-parse per frame |
| Framing | fstrm FrameStream (handshake) | 2-byte length prefix |
| Netns story | unix socket crosses mount NS cleanly | loopback TCP port per netns |

The ~80 µs per-frame difference in shorewalld's decoder is well
within the latency budget at realistic DNS QPS (< 20 k/s), so
the performance advantage of PBDNSMessage rarely matters in
practice. Meanwhile dnstap's unix-socket support, multi-vendor
reach, and zero-port-management story win on every operational
dimension. Prefer dnstap unless you have a specific reason to
pick PBDNSMessage.

### dnstap (recommended)

```
# /etc/shorewall/shorewalld.conf
LISTEN_API=/run/shorewalld/dnstap.sock
```

pdns-recursor side, in a file loaded via `lua_config_file`:

```lua
dnstapFrameStreamServer({"/run/shorewalld/dnstap.sock"},
    {logQueries = false, logResponses = true})
```

Or via the pdns 5.x YAML config (`logging.dnstap_framestream_servers`)
if you prefer the native path — but not alongside `lua_config_file`,
pdns refuses that combination.

### PBDNSMessage (opt-in alternative)

```
# /etc/shorewall/shorewalld.conf
PBDNS_TCP=127.0.0.1:9999
```

pdns-recursor side:

```lua
protobufServer("127.0.0.1:9999",
    {logQueries = false, logResponses = true})
```

Note the TCP-only restriction: pdns-recursor's `protobufServer()`
and the YAML `protobuf_servers` field both refuse unix sockets
(`Unable to convert presentation address 'unix:/...'`). If an
out-of-tree producer speaks the PBDNSMessage wire format over a
unix socket, shorewalld can still consume it via
`PBDNS_SOCKET=/run/shorewalld/pbdns.sock`; the two transports
can be enabled simultaneously on the same PbdnsServer instance.

Both ingestion paths feed the same Phase 2 pipeline:
`DnsSetTracker.propose → SetWriter → WorkerRouter → nft worker →
libnftables`. Metrics are mirrored (`shorewalld_pbdns_*` vs
`shorewalld_dnstap_*`) so a Grafana dashboard can compare them
side-by-side during a migration.

## TCP dnstap listener

For cases where the recursor is on a different host, in a
different mount namespace, or inside a container that can't
reach a unix socket, shorewalld's dnstap listener also accepts
TCP connections:

```sh
shorewalld ... --dnstap-tcp 10.0.0.1:9900
```

The TCP listener runs alongside the unix listener, not instead
of it — operators can receive local recursor frames via unix and
replicated frames from a remote recursor via TCP simultaneously.
Same FrameStream handshake, same decoder, same metrics labels.

## State persistence across restarts

Without persistence, a `systemctl restart shorewalld` or a reboot
would leave the DNS sets empty until the recursor happens to
re-answer for each name — which for a fail-closed rule is a
TTL-sized deny window. The `StateStore` (in `state.py`) fixes
that by:

1. Saving the tracker's live entries as atomic JSON every
   `STATE_PERSIST_INTERVAL` seconds (default 30 s) and once more
   synchronously at shutdown.
2. On startup, loading that file, pruning expired entries, and
   asking the tracker to replay the surviving ones.

Deadlines are stored as wall-clock absolute timestamps in the
file so a monotonic clock reset (which happens on every reboot)
doesn't throw off the TTL remaining.

### Directory management

`/var/lib/shorewalld` is created and owned by the systemd units via
`StateDirectory=shorewalld` (mode `0750`). No manual `mkdir` is needed;
the directory appears before the first `ExecStart`. Distro packages
declare it as `%dir %{_sharedstatedir}/shorewalld` (RPM) or
`install -d debian/shorewall-nft/var/lib/shorewalld` (Debian).

### Config (shorewalld.conf)

```
STATE_DIR=/var/lib/shorewalld           # default
STATE_PERSIST_INTERVAL=30               # seconds between periodic saves
```

### CLI flags

```
shorewalld --state-flush        # ignore and delete state file on start
shorewalld --no-state-load      # ignore state file but keep it
shorewalld --state-dir /tmp/x   # alternative directory (tests)
```

### Metrics

```
shorewalld_state_dns_sets_saves_total
shorewalld_state_dns_sets_save_errors_total
shorewalld_state_dns_sets_load_entries_total
shorewalld_state_dns_sets_load_expired_total
shorewalld_state_last_save_age_seconds
shorewalld_state_file_bytes
```

## Reload monitor (ruleset change detection)

When `shorewall-nft start` replaces the running ruleset, every
DNS-managed set is wiped (they are part of the old `inet
shorewall` table instance). The `ReloadMonitor` detects this
within `poll_interval` (default 2 s) and repopulates the new
table directly from the tracker's shadow state — no waiting for
the recursor to re-answer every name.

Detection is poll-based: a fingerprint probe checks
`list table inet shorewall` periodically. Transitions (absent →
present, or changed fingerprint) trigger a repopulate. A future
phase can replace the poll with a real `NFNLGRP_NFTABLES`
multicast listener; the interface already hides the
implementation detail.

Metrics:

```
shorewalld_reload_events_total{reason}       # initial|table_appeared|table_replaced|manual
shorewalld_reload_repopulate_batches_total
shorewalld_reload_repopulate_entries_total
shorewalld_reload_repopulate_last_seconds
shorewalld_reload_errors_total
```

Operators can also force a repopulate via `PeerLink.request_...`
or a future SIGHUP/API handler — the manual path exists even
though the poll usually catches it on its own.

## HA peer replication (two-node cluster)

In an active/passive HA setup, both boxes run shorewalld and
both talk to their own local pdns_recursor. The peer link
replicates every DNS set update from whichever side saw it
first to the other side, so both boxes have identical set
contents without each box needing to independently resolve
every qname.

### Protocol

* **Transport**: UDP with `IP_MTU_DISCOVER=IP_PMTUDISC_DO` set
  so the kernel refuses fragmentation — oversized sends fail
  loudly rather than getting silently fragmented.
* **Framing**: one `PeerEnvelope` protobuf per datagram, capped
  at 1400 bytes before serialisation.
* **Auth**: HMAC-SHA256 trailer, keyed from a shared-secret
  file. The auth interface is pluggable behind a `PeerAuth`
  protocol so AEAD or Ed25519 can drop in later without
  touching the sender or receiver.
* **Loop prevention**: every envelope carries `origin_node` —
  receivers drop their own frames in case of any misconfigured
  routing.
* **Sequence tracking**: monotonic per-sender sequence numbers,
  gaps are counted into `shorewalld_peer_frames_lost_total` but
  not retransmitted — the TTL-cache on both sides converges
  organically.
* **Heartbeat**: every `PEER_HEARTBEAT_INTERVAL` seconds
  (default 5 s) a Heartbeat envelope carries the sender's
  counter snapshot. Receivers publish them as
  `shorewalld_peer_*` gauges, so scraping either node's
  `/metrics` endpoint shows *both* nodes' health.

### Config (shorewalld.conf)

```
PEER_LISTEN=0.0.0.0:9749
PEER_ADDRESS=10.0.0.2:9749
PEER_SECRET_FILE=/etc/shorewall/peer.key
PEER_HEARTBEAT_INTERVAL=5
```

Ingestion from the local recursor is *never* authenticated
(both dnstap and pbdns are local unix sockets, protected by
filesystem permissions). Only the peer-to-peer network traffic
carries HMAC.

### Cold-boot snapshot resync

When a node boots and its state file is stale (or
`--state-flush` was used), it can ask its peer for the current
DNS set contents via a `SnapshotRequest`. The peer replies with
a `SnapshotResponse` stream split into chunks (each
`SNAPSHOT_CHUNK_SIZE = 20` entries, ≤ 1400 bytes per envelope).
The receiving side applies chunks incrementally via the local
`SetWriter` — convergence is immediate, not "next TTL".

Chunking uses **app-level** splitting, not IP fragmentation —
stateful middleboxes on the HA interlink can't accidentally
drop chunks due to reassembly state loss.

Operators don't need to trigger this explicitly; it fires once
at daemon startup after the StateStore load completes.

## Performance doctrine

shorewalld follows the hot-path discipline documented in
`CLAUDE.md`. Key principles:

* **Preallocated buffers everywhere.** Every `BatchBuilder`,
  every worker's receive buffer, every SEQPACKET transport gets
  a single `bytearray` allocated at startup and reused forever.
  No per-frame allocations in the steady state.
* **Zero-copy decode.** `memoryview` aliases the original frame
  buffer through the entire decode path. Qname extraction via
  `dns_wire.extract_qname()` reads bytes directly without
  building intermediate string objects.
* **Two-pass filter.** Decoders peel off just enough of a frame
  to check the qname against the allowlist before running the
  full parse. At typical deployment rates this drops >95% of
  frames before they touch dnspython.
* **Batch at the netlink boundary.** `SetWriter` accumulates
  `(netns, family)`-keyed updates in a 10 ms window and fires
  one `add element` per batch via the `WorkerRouter`. Single
  updates at 10 k fps would melt the scheduler.
* **Dedup via tracker.** `DnsSetTracker.propose()` returns
  `DEDUP` for entries whose current deadline covers the proposed
  TTL — 95%+ of cache-hit DNS answers never become nft writes.
* **Threading matched to workload.** Decode is GIL-bound Python,
  so the decoder pool uses real `threading.Thread` × cpu_count.
  Sockets are asyncio. libnftables runs on a dedicated
  single-thread executor inside the LocalWorker (or in a forked
  subprocess for target netns via `nft_worker.py` + `WorkerRouter`).
* **Zero-fork in the hot path.** Never shell out. libnftables
  in-process via `NftInterface`, direct netlink for scrape-time
  stats, `/proc` for conntrack counters.
* **Logging rate-limited on hot paths.** The `logsetup.RateLimiter`
  dedups repeated warnings within a configurable window so a
  broken upstream can't flood journald.

## Design notes

Full design memory lives at `docs/roadmap/shorewalld.md`. Source
docstrings:

- `shorewall_nft/daemon/logsetup.py` — logging foundation
- `shorewall_nft/daemon/core.py` — daemon lifecycle
- `shorewall_nft/daemon/exporter.py` — collector and scraper cache
- `shorewall_nft/daemon/discover.py` — netns profile builder
- `shorewall_nft/daemon/framestream.py` — fstrm reader
- `shorewall_nft/daemon/dnstap.py` — unix + tcp dnstap server
- `shorewall_nft/daemon/dns_wire.py` — zero-alloc DNS wire helpers
- `shorewall_nft/daemon/dnstap_bridge.py` — ingestion → SetWriter adapter
- `shorewall_nft/daemon/pbdns.py` — PBDNSMessage ingestion
- `shorewall_nft/daemon/dns_set_tracker.py` — central state of truth
- `shorewall_nft/daemon/batch_codec.py` — parent↔worker binary wire codec
- `shorewall_nft/daemon/worker_transport.py` — SEQPACKET transport
- `shorewall_nft/daemon/nft_worker.py` — per-netns forked worker
- `shorewall_nft/daemon/worker_router.py` — worker pool management
- `shorewall_nft/daemon/setwriter.py` — batching coroutine
- `shorewall_nft/daemon/state.py` — persistence store
- `shorewall_nft/daemon/reload_monitor.py` — reload detection + repopulate
- `shorewall_nft/daemon/peer.py` — HA peer replication link
- `shorewall_nft/daemon/tap.py` — operator inspection CLI
- `shorewall_nft/nft/dns_sets.py` — shared qname/set helpers
