# nfsets — Named Dynamic nft Sets

**Audience**: operators  
**Requires**: shorewall-nft + shorewalld  
**Status**: Wave 4 — compiler + emitter + shorewalld wiring complete

---

## Overview

The `nfsets` config file lets you declare **named dynamic nft sets** once and
reference them from rules by name.  Each set is backed by one of four provider
backends that populate it at runtime:

| Backend | How it populates the set |
|---------|--------------------------|
| `dnstap` | shorewalld intercepts DNS answers from a dnstap/pbdns stream |
| `resolver` | shorewalld actively resolves hostnames on a TTL-driven schedule |
| `ip-list` | shorewalld fetches a cloud provider prefix list (AWS, GCP, …) |
| `ip-list-plain` | shorewalld reads an HTTP URL, local file, or script output |

**Why use `nfsets` instead of inline `dns:hostname`?**

- **Reuse** — one named set, referenced from any number of rules.
- **Multi-host grouping** — multiple DNS names resolved into a single set.
- **Non-DNS backends** — URL/file-backed interval sets for blocklists.
- **Clean separation** — declaration in `nfsets`, reference in `rules`.

---

## Config file format

File: `/etc/shorewall/nfsets` (or inside a merged `/etc/shorewall46/` tree)

```
#NAME     HOSTS                         OPTIONS
web       {a,b}.cdn.example.com         dnstap
cdn       api.example.com               resolver,dns=198.51.100.53,refresh=5m
edge      /var/lib/lists/edge.txt       ip-list-plain,inotify
blocklist https://example.org/list.txt  ip-list-plain,refresh=1h
aws-ec2   aws                           ip-list,filter=region=us-east-1
```

**Columns** (whitespace-separated, `#` for comments):

| Column | Required | Description |
|--------|----------|-------------|
| `NAME` | yes | Logical set name; used in `nfset:<name>` rule syntax |
| `HOSTS` | yes | One or more entries (space-separated within row); brace-expanded |
| `OPTIONS` | yes | Backend keyword + options; see below |

Multiple rows with the **same** `NAME` are merged: their `HOSTS` lists are
concatenated and the backend must be identical.

---

## Brace expansion

The `HOSTS` column supports simple brace expansion (no nesting):

```
{a,b,c}.cdn.example.com  →  a.cdn.example.com  b.cdn.example.com  c.cdn.example.com
```

Each expanded token becomes a separate entry in the set.

---

## Backends

### `dnstap` — DNS tap intercept

shorewalld intercepts DNS answers flowing past the resolver (via
a dnstap or PowerDNS protobuf stream) and installs the resolved IPs
into the nft set with the answer's TTL.

**Entries**: one or more DNS hostnames (qnames).

**Options**: `refresh=` is not applicable — the set is populated reactively
from the tap stream.  Use `dnstype=a` or `dnstype=aaaa` to restrict to one
address family.

**Example**:

```
web   {cdn,static}.example.com   dnstap
```

Emitted set:

```
set nfset_web_v4 { type ipv4_addr; flags timeout; size 512; }
set nfset_web_v6 { type ipv6_addr; flags timeout; size 512; }
```

### `resolver` — Active pull resolver

shorewalld actively resolves each hostname on a TTL-driven schedule and
installs the resolved IPs with the answer's TTL as a timeout.  Useful
when you cannot deploy dnstap (e.g. an upstream resolver you don't
control).

**Options**:

| Option | Description |
|--------|-------------|
| `dns=<ip>` | Use this DNS server (can repeat for multiple servers) |
| `refresh=<duration>` | Minimum re-resolve interval (e.g. `5m`, `1h`) |
| `dnstype=a` / `dnstype=aaaa` | Resolve only one address family |

**Example**:

```
cdn  api.example.com www.example.com  resolver,dns=198.51.100.53,refresh=5m
```

### `ip-list` — Cloud provider prefix lists

shorewalld fetches a structured prefix list from a registered cloud
provider and installs the IPs/CIDRs into an interval set.

**Options**:

| Option | Description |
|--------|-------------|
| `filter=dim=val` | Filter the list (e.g. `filter=region=us-east-1`) |
| `refresh=<duration>` | Re-fetch interval (default: 1 h) |

**Example**:

```
aws-ec2  aws  ip-list,filter=region=us-east-1,refresh=6h
```

Emitted set uses `flags interval` (CIDR blocks) with `size 65536`.

### `ip-list-plain` — URL, file, or exec

shorewalld reads one IP/CIDR per line from an HTTP(S) URL, an absolute
file path, or a script invocation.

**Entries**: exactly one source — a URL (`http://…`), absolute path
(`/var/lib/…`), or `exec:` prefix (`exec:/path/to/script`).

**Options**:

| Option | Description |
|--------|-------------|
| `refresh=<duration>` | Re-fetch interval (default: 1 h) |
| `inotify` | For file paths: trigger reload on file change via inotify |

**Examples**:

```
# URL-backed blocklist, refreshed every hour (default)
blocklist   https://example.org/blocklist.txt   ip-list-plain

# Local file with immediate reload on change
localblock  /var/lib/lists/blocked.txt          ip-list-plain,inotify

# Script whose stdout is a list of CIDRs
dynblock    exec:/usr/local/bin/gen-list         ip-list-plain,refresh=15m
```

---

## Options reference

| Option | Backends | Description |
|--------|----------|-------------|
| `dnstap` | — | Backend keyword (bare) |
| `resolver` | — | Backend keyword (bare) |
| `ip-list` | — | Backend keyword (bare) |
| `ip-list-plain` | — | Backend keyword (bare) |
| `dns=<ip>` | `resolver` | DNS server to query; can repeat |
| `filter=<dim>=<val>` | `ip-list` | Provider-specific filter dimension |
| `refresh=<duration>` | `resolver`, `ip-list`, `ip-list-plain` | Re-fetch / re-resolve interval |
| `inotify` | `ip-list-plain` | Watch file via inotify for immediate reload |
| `dnstype=a` / `dnstype=aaaa` | `dnstap`, `resolver` | Restrict to one address family |

**Duration syntax**: integer seconds, or numeric + unit suffix `s` / `m` / `h` / `d`.
Examples: `300`, `5m`, `1h`, `2d`.

> **Deferred**: `dnstype=srv` (SRV record resolution) is tracked but not implemented.

---

## nft set naming

Each named set produces two nft sets — one for IPv4 and one for IPv6:

```
nfset_<sanitized_name>_v4
nfset_<sanitized_name>_v6
```

Sanitisation: lowercase, non-alphanumeric characters → `_`, consecutive `_`
collapsed, body truncated to 22 characters with a SHA-1 collision guard.
Maximum total identifier length: 31 characters.

The sanitisation algorithm is shared between the compiler and shorewalld —
both packages import it from `shorewall_nft.nft.nfsets.nfset_to_set_name`.
Do not duplicate it.

---

## Referencing sets in rules

### Basic reference

```
#ACTION   SOURCE              DEST    PROTO   PORT
ACCEPT    net:nfset:web       loc
ACCEPT    loc                 net:nfset:cdn
```

The `nfset:<name>` token can appear in the `SOURCE` or `DEST` column,
with an optional zone prefix (`zone:nfset:<name>`).

### Negation

```
DROP      net:!nfset:blocklist  loc
```

### Multi-set comma expansion

A comma-separated list expands into one rule per set:

```
ACCEPT    net:nfset:cdn,edge    loc
```

is equivalent to:

```
ACCEPT    net:nfset:cdn    loc
ACCEPT    net:nfset:edge   loc
```

### Inline `dns:` / `dnsr:` vs `nfset:`

`dns:hostname` and `dnsr:hostname` (inline syntax, one set per hostname)
remain supported. Use `nfset:` when you need:

- multiple hostnames sharing one set
- non-DNS backends
- explicit set naming for tooling / monitoring

> See also: [shorewalld index](../shorewalld/index.md) for the runtime daemon
> that populates both `dns:` sets and `nfset:` sets.

---

## nft set flags

The compiler selects flags based on the mix of backends across all entries:

| Backend mix | nft flags |
|-------------|-----------|
| All `dnstap` / `resolver` | `flags timeout` |
| All `ip-list` / `ip-list-plain` | `flags interval` |
| Mixed DNS + ip-list | `flags timeout, interval` |

## nft set sizing

The compiler emits a `size N` line for every nft set. Defaults:

| Backend | Default size |
|---------|--------------|
| DNS-only (`dnstap` / `resolver`) | `4096` |
| ip-list (`ip-list` / `ip-list-plain`) | `262144` |

Override per entry with `size=N` in the `options:` column. Accepts plain
integers (`size=1000000`), `k` suffix (`size=512k` → 524288), or `M`
suffix (`size=10M` → 10485760). Range: `1` – `67108864` (64M).

Upgrade caveat: the kernel keeps an already-loaded set at its originally
allocated capacity until a full ruleset reload. After bumping sizes,
`shorewall-nft restart` (not just `reload`) is required to pick up the
new capacity.

## Large-set operational tuning (shorewalld)

For sets approaching or exceeding 100k elements, shorewalld exposes five
environment variables that govern the apply path. All have sensible
defaults; operators only tune them if the Prometheus metrics indicate a
bottleneck or capacity concern.

| Env var | Default | Purpose |
|---------|---------|---------|
| `SHOREWALLD_IPLIST_CHUNK_SIZE` | `2000` | Elements per `add element` script (libnftables parser batch). Clamp `[100, 10000]`. |
| `SHOREWALLD_IPLIST_SWAP_RENAME` | `0` | Master gate for the atomic swap-rename path. Set to `1` after validating the pre-flight checklist below. |
| `SHOREWALLD_IPLIST_SWAP_ABS` | `50000` | Trigger swap-rename when `len(new) ≥ N`. |
| `SHOREWALLD_IPLIST_SWAP_FRAC` | `0.50` | Trigger swap-rename when `(added + removed) / current ≥ frac`. |
| `SHOREWALLD_IPLIST_AUTOSIZE_HEADROOM` | `0.90` | Trigger autosize (swap with doubled capacity) when `len(new) / declared_size ≥ ratio`. |

**Swap-rename** replaces incremental `add element` / `delete element` with a
single libnftables transaction that declares `<name>_new`, fills it, deletes
the old set, and renames. The whole block is atomic at the kernel level —
rules referencing the set continue to match across the swap.

**Autosize** fires when an incoming list approaches declared capacity. The
tracker probes the current set via `list set … -j`, recomputes a
`next_pow2(max(len × 2, declared × 2))` target capped at 64M, and executes
the swap with the larger size. A WARN log is emitted so the operator can
raise `size:` in the nfsets config on the next push (autosize is a safety
net, not a config).

**Capacity warning**: when any list hits `≥ 80 %` of its declared size a
WARN log is emitted (`"iplist.NAME: set … at N% capacity (used/declared)"`)
regardless of whether autosize is enabled.

### Metrics

All five metric families below are labelled by `list` + `family` (v4/v6):

- `shorewalld_iplist_apply_duration_seconds_{sum,count}` — wall-clock per
  apply (counter pair for histogram averaging).
- `shorewalld_iplist_apply_path_total{path}` — `diff` (incremental),
  `swap` (atomic), `fallback-from-swap` (probe/transaction failure →
  diff), `saturated` (kernel reported "Set is full").
- `shorewalld_iplist_set_capacity{kind}` — `used` / `declared` counts.
- `shorewalld_iplist_set_headroom_ratio` — `used / declared` as a gauge.

### Pre-flight checklist before `SHOREWALLD_IPLIST_SWAP_RENAME=1`

1. `shorewalld_iplist_apply_path_total{path="diff"}` baseline observed.
2. Managed sets live in `table inet shorewall` (swap script hard-codes).
3. No named `map` references the managed sets as values (`rename set`
   fails under a live map reference).
4. nft ≥ 0.9.3 / Linux ≥ 5.10 on the firewall (needed for `rename set`).
5. After enable, verify `path="swap"` appears without
   `path="fallback-from-swap"` over a couple of refresh cycles.
6. If `autosize` WARN fires, update the entry's `size:` in the nfsets
   config to match the observed capacity — autosize is a safety net, not
   a replacement for explicit sizing.

---

## Relationship to shorewalld

The compiler:

1. Declares the nft sets in the emitted ruleset (type, flags, size).
2. Serialises the registry as `{"nfsets": {…}}` inside the
   `register-instance` control-socket payload that `shorewall-nft start`
   sends to shorewalld.

shorewalld's `NfSetsManager`:

1. Receives the payload and splits entries by backend.
2. Routes `dnstap` / `resolver` entries into the `DnsSetTracker` pipeline.
3. Starts a `PlainListTracker` for `ip-list-plain` sources.
4. Passes `ip-list` configs to `IpListTracker`.

Multiple instances (multiple network namespaces) can each declare
`nfset:web` — shorewalld routes each instance's DNS answers into the
correct nft set in the correct netns.

**N→1 sharing**: multiple DNS hostnames that declare the same logical
set name share one nft set.  The `DnsSetTracker` assigns one
`set_id` per `(set_name, family)` group, so answers for any of the
hostnames flow into the single shared nft set.

---

## Deferred features

The following are planned but not yet implemented:

- **SRV record resolution** (`dnstype=srv`) — tracked as a future extension.
- **Renaming inline `dns:` → `dnst:`** — a syntax alias for inline dnstap-style
  sets; deferred to a future wave.
- **`nfset:` support in Masq/tcrules** — the address-parsing logic in those
  sections has not been updated; use `dns:` inline for now.
- **`zone:dnsr:` / `zone:dnst:` pseudo-zones** — inline alternative syntax;
  if they exist in the codebase, they are not documented here yet.

---

## Verification recipe

```bash
# 1. Compile the config and inspect the emitted nft script.
shorewall-nft build --dry-run 2>/dev/null | grep -A5 "nfset_"

# 2. Apply the config.
shorewall-nft start

# 3. Confirm the sets are declared in the running kernel ruleset.
nft list table inet shorewall | grep "set nfset_"

# 4. Check shorewalld is populating them.
journalctl -u shorewalld --since "5 minutes ago" | grep nfset

# 5. List current elements.
nft list set inet shorewall nfset_web_v4
```

---

## Cross-links

- [shorewalld operator reference](../shorewalld/index.md)
- [dynamic sets (ipset-based)](dynamic.md)
- [ipsets](ipsets.md)
- [docs/index.md](../index.md)
