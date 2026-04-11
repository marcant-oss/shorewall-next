# shorewalld — async daemon for monitoring + DNS-set API

> **Status 2026-04-11:** All five phases shipped on
> ``shorewall-nft-release``. Phase 4's original sketch assumed a
> length-prefixed JSON placeholder — the actual implementation uses
> **dnstap** (FrameStream + PBDNSMessage protobuf) with a bounded
> queue and a worker pool of ``os.cpu_count()`` decode threads. An
> operator template for the producer-side pdns_recursor config lives
> at ``packaging/pdns-recursor/shorewalld.lua.template``. Everything
> below the "Phase 4 — DNS API socket" heading is the old design;
> the real contract is documented in
> ``shorewall_nft/daemon/dnstap.py``'s module docstring.

## Context

The reference HA deployment is targeted for migration to
**shorewall-next** (this project, `shorewall-nft`, `inet shorewall` table)
inside its `fw` namespace. `shorewalld` ships as part of shorewall-nft and
is designed for that target state — it does NOT carry coexistence logic
for the legacy foomuuri ruleset that lives there today. Migration
sequencing is "remove foomuuri table → load shorewall table → start
shorewalld" — the operator does the swap atomically. Eventually
`netns-routing` itself will be taught to ship shorewall-nft configs;
shorewalld is the canonical exporter for that future state.

CLAUDE.md TODO #11 ("Prometheus exporter — port from foomuuri") and TODO #4
("DNS-based filtering via pdns_recursor RPZ + protobuf sidecar") both need a
long-running process that lives next to a loaded shorewall-nft ruleset and:

1. Scrapes per-rule / per-chain counters out of the running ruleset and
   exposes them as Prometheus metrics — multi-netns aware (one daemon serves
   primary + backup + mgmt namespaces on the same box, < 50 ms scrape budget,
   no `nft list ruleset` subprocess per scrape).
2. Will later accept incoming `PBDNSMessage` frames from a powerdns recursor
   sidecar over a unix socket and translate them into `nft add element …
   dns_<name> { ip timeout … }` updates against named sets.

We do not have a daemon process today — `shorewall-nft` is a one-shot
compiler/runtime CLI and the simlab `SimController` is the only piece of
async/threaded infrastructure that matches the shape we need. Building
`shorewalld` as a separate executable that **reuses** the SimController
patterns lands TODO #11 in shippable form and lays the groundwork for TODO #4
without making the DNS plumbing part of the 1.x release line.

The user explicitly asked for the highest possible efficiency on the nft
counter export path: libnftables in-process, **not** subprocess — and
direct-netlink (pyroute2 / netfilter library) if libnftables is still too
slow.

## Recommended approach

### Architecture overview

```
                      ┌────────────────────────────────────────┐
                      │ shorewalld (one process, asyncio loop) │
                      │                                        │
  prom client  ─HTTP─▶│  PromHTTPServer (aiohttp/asyncio)      │
                      │       │                                │
                      │       ▼                                │
                      │  CounterScraper                        │
                      │   per-netns: NftInterface +            │
                      │   per-rule cache (handle→labels)       │
                      │                                        │
  pdns sidecar ─UNIX─▶│  DnsSetServer (asyncio.start_unix_     │
                      │     server, length-prefixed protobuf)  │
                      │       │                                │
                      │       ▼                                │
                      │  SetWriter (NftInterface.add_set_      │
                      │     element with timeout)              │
                      │                                        │
                      │  signal handlers + shutdown sequence   │
                      └────────────────────────────────────────┘
```

The whole daemon is **one asyncio process**. No worker threads in Phase 1 —
the SimController's reader/writer thread pool exists because TUN/TAP fds need
synchronous `os.read`/`os.write` outside the event loop, which we don't need
here. We DO mirror the SimController's signal handling + idempotent
`_shutdown()` discipline (single source of truth, atexit + SIGTERM + SIGINT
all funnel into one place).

### Phase 1 — daemon skeleton

**New file: `shorewall_nft/daemon/__init__.py`** — entry point.

```python
def main() -> int:
    """shorewalld CLI entry. Parses args, builds the Daemon, runs forever."""
```

CLI flags:

* `--listen-prom 0.0.0.0:9748` — Prometheus scrape endpoint
* `--listen-api /run/shorewalld.sock` — unix socket for the DNS sidecar
  (Phase 4; off by default)
* `--netns SPEC` — namespace selection. Accepts:
  - empty / unset → only the daemon's own netns
  - `auto` → walk `/run/netns/` and serve every entry plus the
    daemon's own netns
  - `fw,rns1,rns2` → explicit comma list (production mode for the
    reference HA stack — three production namespaces per box)
* `--scrape-interval 30` — minimum age for cached counters before a fresh
  scrape fires
* `--reprobe-interval 300` — how often to re-check whether a previously
  shorewall-less netns has acquired a loaded `inet shorewall` table
  (so an `nft load` in a recursor netns becomes visible without
  restarting the daemon)
* `--log-level info|debug`

**New file: `shorewall_nft/daemon/core.py`** — `class Daemon`:

```python
class Daemon:
    def __init__(self, *, prom_addr, api_socket, netns_list,
                 scrape_interval, log_level): ...

    async def run(self) -> int:
        """Build subsystems, install signal handlers, run forever."""

    async def shutdown(self): ...   # idempotent, mirrors SimController
```

Reuses (do NOT reimplement):

* **Signal handling pattern** from
  `shorewall_nft/verify/simlab/controller.py:653–729`
  (`_register_cleanup`, `_sig_handler`, idempotent `_shutdown` guard).
  Lift the structure verbatim, drop the thread-pool join section since
  Phase 1 has no threads.
* **Resource sampler** `shorewall_nft/verify/simlab/smoketest.py:71–118`
  `_PeakSampler` is a candidate to expose its own metrics
  (`shorewalld_peak_fds`, `shorewalld_loadavg`) — but cleaner is to just
  read these on every scrape rather than maintain a peak. **Skip the peak
  sampler for now.**
* `pyproject.toml` `[project.scripts]` already has the pattern; add one
  more line `shorewalld = "shorewall_nft.daemon:main"`.

**Tests**: `tests/test_daemon_skeleton.py` — instantiate `Daemon(...)`,
verify shutdown is idempotent, verify CLI argparse round-trips. Pure
unit-level, no socket binding.

### Phase 2 — Prometheus exporter (the meat)

**New file: `shorewall_nft/daemon/exporter.py`** — Prometheus collector.

Two collectors registered with `prometheus_client.REGISTRY`:

```python
class CounterCollector(Collector):
    """Per-chain + per-rule counter export. One scrape = one libnftables
    netlink round-trip per netns, dump format only (no per-chain probe)."""

    def __init__(self, scraper: CounterScraper): ...

    def collect(self):
        """Yield CounterMetricFamily for packets/bytes."""
```

```python
class SetCollector(Collector):
    """Set element count gauge — useful for the dynamic blacklist + later
    the dns_<name> sets the API server will populate."""
```

**Metrics emitted** (matching the TODO #11 spec):

| Metric | Type | Labels | Source |
|---|---|---|---|
| `shorewall_nft_packets_total` | Counter | `{table, chain, rule_idx, comment, netns}` | NftCollector |
| `shorewall_nft_bytes_total` | Counter | `{table, chain, rule_idx, comment, netns}` | NftCollector |
| `shorewall_nft_set_elements` | Gauge | `{set, netns}` | NftCollector |
| `shorewall_nft_iface_rx_packets_total` | Counter | `{iface, netns}` | LinkCollector |
| `shorewall_nft_iface_rx_bytes_total` | Counter | `{iface, netns}` | LinkCollector |
| `shorewall_nft_iface_tx_packets_total` | Counter | `{iface, netns}` | LinkCollector |
| `shorewall_nft_iface_tx_bytes_total` | Counter | `{iface, netns}` | LinkCollector |
| `shorewall_nft_iface_oper_state` | Gauge | `{iface, netns, state}` | LinkCollector |
| `shorewall_nft_ct_count` | Gauge | `{netns}` | CtCollector |
| `shorewall_nft_scrape_duration_seconds` | Gauge | `{netns, collector}` | core |
| `shorewall_nft_scrape_errors_total` | Counter | `{netns, collector, kind}` | core |
| `shorewall_nft_build_info` | Gauge | `{version, has_lib}` | core |
| `shorewall_nft_netns_up` | Gauge | `{netns, has_nft}` | core (per-profile heartbeat) |

The `comment` label is what makes per-rule counters scrape-able by humans
— a rule with `?COMMENT Sophos UTM Administration` shows up labelled.

**New: `shorewall_nft/nft/netlink.py:list_rule_counters(family, table,
netns=None) -> list[dict]`**

The current `list_counters()` only returns named **counter objects**
(the `nfacct`-style ones). For TODO #11 we need every rule's inline
`counter` expression too. The libnftables call is still single-trip:
`list table inet shorewall` returns the entire ruleset JSON in one
round-trip. We walk the JSON once and extract:

```python
for chain_obj in nftables['nftables']:
    if 'rule' in chain_obj:
        rule = chain_obj['rule']
        for expr in rule['expr']:
            if 'counter' in expr:
                yield {
                    'table': rule['table'],
                    'chain': rule['chain'],
                    'rule_idx': rule['handle'],
                    'comment': rule.get('comment', ''),
                    'packets': expr['counter']['packets'],
                    'bytes':   expr['counter']['bytes'],
                }
```

This is one libnftables `cmd("list table inet shorewall")` per netns =
one netlink dump per netns. Far below the 50 ms scrape budget for the
1600-rule reference config (production foomuuri exporter does the same
thing via subprocess and stays under 100 ms).

**`CounterScraper`** maintains per-netns caches keyed on `(handle, table,
chain)`. Cache TTL = `--scrape-interval`. If Prometheus scrapes faster
than the TTL, the cached snapshot is reused — amortises the netlink
round-trip across rapid scrapes.

**Phase 2.5 (deferred)** — the user mentioned "evtl direkt netlink
socket". Pyroute2 0.9.5's high-level `NFTables.get_rules()` was removed
between 0.7 and 0.9; only the low-level `nlm_request` remains. We can
build a `dump_table_counters_via_netlink()` against the low-level API
later if libnftables isn't fast enough — but that's a Phase 2.5 patch,
not an initial-ship requirement. Sketch the API now, profile after
shipping, only commit the netlink path if a real scrape exceeds the
50 ms budget.

**Tests**: `tests/test_daemon_exporter.py` — feed a hand-built
`nftables` dict (no real netlink) into `CounterCollector.collect()` and
assert the metric families come back with the right labels and values.
Reuses the same fixture style as `tests/test_emitter_features.py`.

### Phase 3 — multi-netns support (heterogeneous)

The reference deployment runs **three** namespaces per box (per
`../netns-routing/etc/netns.cfg/`):

* **`fw`** — main firewall netns. Has the loaded `inet shorewall`
  table, conntrackd, keepalived. **Full counter scrape applies here.**
* **`rns1`** / **`rns2`** — pdns_recursor namespaces. NO shorewall
  table — only pdns_recursor + keepalived for the VIP. Per-iface link
  counters and conntrack table size are still interesting; the
  ruleset collector just emits zero rules.
* **root netns** — host plumbing. Per-iface counters only.

To handle this heterogeneity, each netns gets a **scraper profile** —
a list of `Collector` instances rather than a single hardcoded
exporter. The `Daemon` builds the profile per netns at startup based
on what's there:

```python
class NetnsProfile:
    name: str                       # "fw", "rns1", "rns2", or "" (root)
    collectors: list[Collector]     # ordered, all share the netns label
    nft_table_present: bool         # cached on first scrape
```

Discovery:

* `--netns fw,rns1,rns2` — explicit comma list (production mode)
* `--netns auto` — walk `/run/netns/` and instantiate one profile per
  entry, plus one for the daemon's own netns
* `--netns ""` — only the daemon's own netns

For each profile we always add:

* `LinkCollector(netns)` — `pyroute2.IPRoute(netns=…).get_links()`
  yields per-iface RX/TX packets+bytes (cheap netlink dump). Emits
  `shorewall_nft_iface_rx_bytes_total{iface,netns}` etc.
* `CtCollector(netns)` — reads
  `/proc/sys/net/netfilter/nf_conntrack_count` from inside the netns
  via the existing `_in_netns()` setns hop. Emits
  `shorewall_nft_ct_count{netns}`.

For each profile we conditionally add (probed once at startup,
re-probed every `--reprobe-interval` to pick up an `nft load` /
`shorewall-nft start` that happens after the daemon has started):

* `NftCollector(netns)` — instantiated when `list table inet
  shorewall` returns successfully in that netns. The full per-rule
  + named-counter + set-element export goes here. For namespaces
  without a loaded shorewall ruleset (e.g. the `rns*` recursor
  namespaces) the collector is simply absent and the metrics list
  is just `[LinkCollector, CtCollector]` — no error spam.
  Also wired up: `inet shorewall_stopped` (when present) and
  `arp filter` (the arprules table) — both are sibling tables the
  shorewall-nft compiler emits.

Future profile entries (out of scope for the first ship, sketched here
so the architecture survives them):

* `PdnsCollector(netns)` — probes `/etc/powerdns/recursor.conf` for the
  Carbon endpoint or webserver stats; only added when
  `pdns_recursor.service` is up in that netns. Useful in `rns1`/`rns2`.
* `KeepalivedCollector(netns)` — parses `/run/keepalived/<inst>.json`
  if the keepalived in that netns is configured to dump it.
* `ConntrackdCollector(netns)` — reads conntrackd cache stats via the
  unix socket conntrackd ships.

Every metric carries a `netns` label so a single Prometheus scrape
endpoint serves all profiles. Empty `netns=""` means the daemon's own
namespace.

For listening sockets the daemon ALWAYS binds in its OWN netns (the
host root netns, typically). It does NOT need to enter target
namespaces to listen — only to read counters. The `_in_netns()`
context manager from `shorewall_nft/nft/netlink.py:56–91` already
handles the setns hop and is reused as-is for every collector that
needs to enter a target netns.

`pyroute2.IPRoute(netns=name)` opens a netlink socket bound to the
target netns directly — no setns hop needed for link counters. Two
syscall paths:

* libnftables nft commands → setns hop via `_in_netns()` (the
  library's netlink socket lives in the daemon's netns)
* pyroute2 link/route/neigh dumps → `IPRoute(netns=name)` constructor
  (opens a fresh socket bound to the target netns)

Both are zero-fork.

### Phase 4 — DNS API socket (placeholder for TODO #4)

**New file: `shorewall_nft/daemon/api_server.py`** — asyncio unix
socket listener.

```python
class DnsSetServer:
    async def start(self, socket_path: str): ...  # asyncio.start_unix_server
    async def _handle_client(self, reader, writer):
        """Decode length-prefixed PBDNSMessage frames, push (name → IPs)
        into the SetWriter."""
```

```python
class SetWriter:
    """Translates DNS responses into nft set add commands.

    For each (qname, [ip…]) pair: hash qname → set name (sanitised),
    call NftInterface.add_set_element() with the ttl-derived timeout.
    """
```

**Phase 4 ships ONLY the listener + the wire format hook — NOT actual
PBDNSMessage parsing**. We define a simple length-prefixed JSON message
shape for the daemon's first ship so we can integration-test it without
needing a powerdns recursor. The protobuf decoder can be bolted on
later (TODO #4 work) without changing the listener or the SetWriter.

The protobuf schema lives at
`docs/roadmap/post-1.0-nft-features.md` Tier 2+ and the design memory
`memory/project_dns_filtering.md` — neither needs editing here.

**Off by default.** `--listen-api PATH` is opt-in; without it the
daemon is a pure exporter and the unix socket is never bound.

### Phase 5 — packaging

* **`packaging/systemd/shorewalld.service`** — root-namespace exporter,
  `ExecStart=/usr/bin/shorewalld --listen-prom :9748 --netns simlab-fw`
  shape, `Restart=on-failure`, `User=root`,
  `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`.
* **`packaging/systemd/shorewalld@.service`** — templated variant for
  setups that prefer one daemon per netns (the user can pick).
* `pyproject.toml`:
  - Add `prometheus_client>=0.20` to `[project.optional-dependencies]`
    under a new `daemon` extra (don't bloat the base install).
  - Add `shorewalld = "shorewall_nft.daemon:main"` under
    `[project.scripts]`.

### Critical files (new + modified)

| Path | Action | Why |
|---|---|---|
| `shorewall_nft/daemon/__init__.py` | NEW | CLI entry + `main()` |
| `shorewall_nft/daemon/core.py` | NEW | `Daemon` lifecycle (signals, shutdown) |
| `shorewall_nft/daemon/exporter.py` | NEW | core registry + `Collector` base + `NftCollector` + `LinkCollector` + `CtCollector` + per-netns `NetnsProfile` orchestration |
| `shorewall_nft/daemon/discover.py` | NEW | netns discovery: explicit list / `auto` walker over `/run/netns/` / re-probe loop |
| `shorewall_nft/daemon/api_server.py` | NEW | Phase 4 placeholder (off by default) |
| `shorewall_nft/nft/netlink.py` | EDIT | new `list_rule_counters(netns=)` walker (extract counter expressions from `list table` JSON) |
| `pyproject.toml` | EDIT | `prometheus_client` extra, `shorewalld` entry |
| `packaging/systemd/shorewalld.service` | NEW | systemd unit |
| `packaging/systemd/shorewalld@.service` | NEW | per-netns templated unit |
| `tests/test_daemon_skeleton.py` | NEW | unit-level Daemon lifecycle |
| `tests/test_daemon_exporter.py` | NEW | collector unit tests with hand-built nftables JSON fixture |
| `CLAUDE.md` | EDIT | mark TODO #11 as in-progress / "see shorewalld" |

### Reused (do not reimplement)

* `shorewall_nft/nft/netlink.py:56–91` — `_in_netns()` setns context manager
* `shorewall_nft/nft/netlink.py:101–157` — `NftInterface` libnftables path (`_run_text` / `cmd`)
* `shorewall_nft/nft/netlink.py:258–274` — `list_counters()` (named counter objects — kept for `shorewall_nft_named_counter_*` metrics)
* `shorewall_nft/nft/netlink.py:296–317` — `add_set_element()` / `delete_set_element()` for the SetWriter
* `shorewall_nft/verify/simlab/controller.py:653–729` — signal/shutdown discipline (lift the shape; drop the thread-pool join sections)

### Verification

After Phase 1 + 2 + 3:

```bash
# Tests (unit-level, no netlink sockets)
.venv/bin/python -m pytest tests/test_daemon_skeleton.py \
                          tests/test_daemon_exporter.py \
                          tests/test_daemon_discover.py -v

# Single-netns smoke run on the VM (only the daemon's own netns)
ssh root@192.0.2.83 \
    "cd /root/shorewall-nft && \
     systemd-run --unit=shorewalld-smoke --collect \
       .venv/bin/shorewalld --listen-prom :9748 \
                            --scrape-interval 5"
sleep 2
ssh root@192.0.2.83 "curl -s http://localhost:9748/metrics | \
    grep shorewall_nft_ | head -20"
ssh root@192.0.2.83 "systemctl stop shorewalld-smoke"

# Multi-netns smoke run — auto-discover every entry under
# /run/netns/. On the simlab VM that's `simlab-fw`; on a real
# production box it would be `fw`, `rns1`, `rns2`.
ssh root@192.0.2.83 \
    "systemd-run --unit=shorewalld-multi --collect \
       .venv/bin/shorewalld --listen-prom :9748 --netns auto"
sleep 2
ssh root@192.0.2.83 "curl -s http://localhost:9748/metrics | \
    grep -E 'shorewall_nft_(packets_total|netns_up)' | head -20"
# Expected:
#   shorewall_nft_netns_up{netns=\"\",has_nft=\"false\"} 1
#   shorewall_nft_netns_up{netns=\"simlab-fw\",has_nft=\"true\"} 1
#   shorewall_nft_packets_total{netns=\"simlab-fw\",chain=\"forward\",rule_idx=\"…\"} N
ssh root@192.0.2.83 "systemctl stop shorewalld-multi"

# Scrape latency check (TODO #11 budget = <50 ms per netns).
# Three production namespaces × <50 ms = <150 ms total scrape budget.
ssh root@192.0.2.83 \
    "time curl -s http://localhost:9748/metrics > /dev/null"
```

After Phase 4:

```bash
# Bind the API socket and feed a fake JSON frame
shorewalld --listen-api /tmp/shorewalld.sock --listen-prom :9748 &
echo '{"qname":"github.com","ips":["140.82.121.4"],"ttl":300}' \
    | python3 -c "import sys,struct,os; m=sys.stdin.read().encode(); s=os.open('/tmp/shorewalld.sock', …)"
nft list set inet shorewall dns_github_com  # should show 140.82.121.4
```

### NftCollector lifecycle

For each `--reprobe-interval` tick, every `NetnsProfile` runs:

```
try:
    libnft.cmd("list table inet shorewall", netns=netns)
    has_nft = True
except NftError:
    has_nft = False
```

* `has_nft == False` → no NftCollector for this netns (just
  `LinkCollector + CtCollector`). Quiet, no error spam.
* `has_nft == True` and no collector yet → instantiate
  `NftCollector(netns)`.
* `has_nft == False` and a collector exists → tear it down
  (the ruleset got `shorewall-nft stop`'d while the daemon was
  running).
* `has_nft == True` and a collector exists → no-op, just
  refresh.

The reprobe loop also picks up `inet shorewall_stopped` and
`arp filter` independently (separate one-line nft commands)
when the operator has those tables loaded.

When `netns-routing` later learns shorewall-nft, the daemon
needs ZERO config changes — the new ruleset just shows up under
`table="shorewall"` automatically.

### What this plan deliberately does NOT do

* **No coexistence with foomuuri.** The reference HA stack will be
  migrated by atomically swapping the table (drop `inet foomuuri`,
  load `inet shorewall`); shorewalld only ever looks for the
  shorewall table and never tries to monitor foomuuri counters. The
  TODO #11 phrase "port from foomuuri" refers only to lifting the
  collector shape (Prometheus registry, metric naming style),
  NOT to running against a foomuuri ruleset.
* **No protobuf decoding in Phase 4.** Length-prefixed JSON only — the
  protobuf wire format ships with TODO #4 implementation later.
* **No direct netlink read path.** libnftables `cmd("list table …")` is
  one netlink round-trip per scrape and meets the budget. The
  pyroute2-low-level path is sketched for Phase 2.5 if profiling later
  shows libnftables is the bottleneck.
* **No DNS RPZ generation.** TODO #4 design says shorewall-nft writes
  the RPZ + recursor config; the daemon only consumes the recursor's
  output. RPZ generation is a separate compiler-time pass.
* **No worker threads.** SimController has them because TUN/TAPs need
  blocking syscalls; counter scrape + socket reads are pure asyncio.
  If a netns scrape goes slow we can switch a single CounterScraper
  call to `asyncio.to_thread(...)` rather than carrying a thread pool.
* **No HA failover logic.** Each daemon binds to its own box; nothing
  to coordinate cross-node. The DNS-set-replication concern is already
  handled by running the recursor sidecar on both nodes (per
  `memory/project_dns_filtering.md`).

### Open questions for the user (if any)

* Whether `shorewalld` lives in `shorewall_nft/daemon/` (sub-package)
  or `shorewall_nft/daemon.py` (single module). Sub-package wins for
  the multi-file plan above.
* Whether the Prometheus extra ships under
  `[project.optional-dependencies] daemon = […]` or as a hard
  dependency. Soft is friendlier to packagers.
* Whether the `--listen-api` socket should be 0600 root-owned or
  0660 root:shorewall — relevant for packaging and the powerdns
  sidecar's runtime user.
