# nfsets — Named Dynamic nft Sets

**Audience**: operators  
**Requires**: shorewall-nft + shorewalld  
**Status**: Feature complete — all N1–N6 capabilities shipped

---

## Overview

The `nfsets` config file lets you declare **named dynamic nft sets** once and
reference them from rules by name. Each set is backed by one or more provider
backends that populate it at runtime:

| Backend | How it populates the set |
|---------|--------------------------|
| `dnstap` | shorewalld intercepts DNS answers from a dnstap/pbdns stream |
| `resolver` | shorewalld actively resolves hostnames on a TTL-driven schedule |
| `ip-list` | shorewalld fetches a cloud provider prefix list (AWS, GCP, …) |
| `ip-list-plain` | shorewalld reads an HTTP URL, local file, or script output |

**Why use `nfsets` instead of inline `dnst:hostname`?**

- **Reuse** — one named set, referenced from any number of rules.
- **Multi-host grouping** — multiple DNS names resolved into a single set.
- **Non-DNS backends** — URL/file-backed interval sets for blocklists or cloud
  prefix lists.
- **Additive backends** — the same set name can be fed by multiple backends
  simultaneously (e.g. resolver + ip-list-plain for a hybrid CDN set).
- **Clean separation** — declaration in `nfsets`, reference in `rules`.

---

## Config file format

File: `/etc/shorewall/nfsets` (or inside a merged `/etc/shorewall46/` tree)

```
#NAME       HOSTS                            OPTIONS
web         {cdn,static}.example.com         dnstap
cdn         api.example.com                  resolver,dns=198.51.100.53,refresh=5m
sip         _sip._udp.example.org            resolver,dnstype=srv,refresh=10m
edge        /var/lib/lists/edge.txt          ip-list-plain,inotify
blocklist   https://example.org/list.txt     ip-list-plain,refresh=1h
aws-ec2     aws                              ip-list,filter=region=us-east-1
```

**Columns** (whitespace-separated, `#` for comments):

| Column | Required | Description |
|--------|----------|-------------|
| `NAME` | yes | Logical set name; used in `nfset:<name>` rule syntax |
| `HOSTS` | yes | One or more entries (space-separated within row); brace-expanded |
| `OPTIONS` | yes | Backend keyword + options; see [Options reference](#options-reference) |

Multiple rows with the **same** `NAME` and the **same** backend are merged:
their `HOSTS` lists are concatenated. Multiple rows with the **same** `NAME`
but **different** backends are stored additively — both backends populate the
same nft sets simultaneously (see [Multiple backends for one set](#multiple-backends-for-one-set)).

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

shorewalld intercepts DNS answers flowing past the resolver via a dnstap or
PowerDNS protobuf stream and installs the resolved IPs into the nft set with
the answer's TTL as the element timeout.

**Entries**: one or more DNS hostnames (qnames).

**Options**: `refresh=` is not applicable — the set is populated reactively
from the tap stream. Use `dnstype=a` or `dnstype=aaaa` to restrict to one
address family.

**Example**:

```
web   {cdn,static}.example.com   dnstap
web   api.example.com            dnstap,dnstype=a
```

Emitted sets:

```
set nfset_web_v4 { type ipv4_addr; flags timeout; size 4096; }
set nfset_web_v6 { type ipv6_addr; flags timeout; size 4096; }
```

**Verify population**:

```bash
nft list set inet shorewall nfset_web_v4
journalctl -u shorewalld --since "5 minutes ago" | grep nfset_web
```

---

### `resolver` — Active pull resolver

shorewalld actively resolves each hostname on a TTL-driven schedule and
installs the resolved IPs with the answer's TTL as an element timeout. Use
this backend when you cannot deploy dnstap (e.g. an upstream resolver you do
not control).

**Options**:

| Option | Description |
|--------|-------------|
| `dns=<ip>` | DNS server to query; can repeat for multiple servers |
| `refresh=<duration>` | Minimum re-resolve interval (e.g. `5m`, `1h`) |
| `dnstype=a` / `dnstype=aaaa` | Resolve only one address family |
| `dnstype=srv` | Query SRV; resolve each target's A+AAAA into the set |

**Example** (standard A/AAAA):

```
cdn  api.example.com www.example.com  resolver,dns=198.51.100.53,refresh=5m
```

#### SRV records (`dnstype=srv`)

When `dnstype=srv` is set, shorewalld queries the SRV RRset for the hostname
instead of A/AAAA directly. For each `Target` hostname in the SRV answer,
shorewalld resolves both A and AAAA records and writes the resulting IPs into
the nft sets with a TTL equal to `min(srv_ttl, child_ttl)` clamped to
`[ttl_floor, ttl_ceil]`.

**Port information from the SRV record is discarded** — the set is IP-only;
port matching must be done separately in the `rules` file.

**Example** (allow traffic to SIP servers discovered via SRV):

```
# nfsets
# name    hosts                           options
sip       _sip._udp.example.org           resolver,dnstype=srv,refresh=10m
```

shorewalld queries `_sip._udp.example.org SRV`, extracts target hostnames
(e.g. `sip1.example.org`, `sip2.example.org`), resolves their A and AAAA
records, and writes the IPs into `nfset_sip_v4` and `nfset_sip_v6`.

**Hard cap**: at most 32 SRV targets are processed per RRset. If a RRset is
larger, a rate-limited warning is logged and only the first 32 targets are
resolved.

**No recursive SRV**: if an SRV target's A/AAAA lookup encounters a CNAME,
dnspython resolves the chain transparently. A second SRV query is never
issued on any target — resolution is exactly one level deep.

---

### `ip-list` — Cloud provider prefix lists

shorewalld fetches a structured prefix list from a registered cloud provider
and installs the IPs/CIDRs into an interval set.

**Options**:

| Option | Description |
|--------|-------------|
| `filter=<dim>=<val>` | Provider-specific filter dimension (e.g. `filter=region=us-east-1`) |
| `refresh=<duration>` | Re-fetch interval (default: 1 h) |

**Example**:

```
aws-ec2  aws  ip-list,filter=region=us-east-1,refresh=6h
```

Emitted sets use `flags interval` (CIDR blocks) with `size 65536` by default.

**Verify population**:

```bash
nft list set inet shorewall nfset_aws_ec2_v4
```

---

### `ip-list-plain` — URL, file, or exec

shorewalld reads one IP/CIDR per line from an HTTP(S) URL, an absolute file
path, or a script invocation.

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
| `dnstype=srv` | `resolver` | Query SRV; resolve each target's A+AAAA into the set |
| `size=N` | all | Override nft set size (integer; `k`/`M` suffix accepted). Range 1–67108864. |

**Duration syntax**: integer seconds, or numeric + unit suffix `s` / `m` / `h` / `d`.
Examples: `300`, `5m`, `1h`, `2d`.

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

## nft set flags

The compiler selects flags **per logical set name** based on the mix of
backends feeding that name:

| Backend mix for the name | nft flags |
|--------------------------|-----------|
| Only `dnstap` / `resolver` | `flags timeout` |
| Only `ip-list` / `ip-list-plain` | `flags interval` |
| Mix of DNS + ip-list backends | `flags timeout, interval` |

When only one backend type feeds a name, the set is declared with the minimal
correct flags — no over-allocation. When multiple backends feed the same name
(additive model), the union flags are used.

---

## nft set sizing

The compiler emits a `size N` line for every nft set. Defaults:

| Backend | Default size |
|---------|--------------|
| DNS-only (`dnstap` / `resolver`) | `4096` |
| ip-list (`ip-list` / `ip-list-plain`) | `262144` |

Override per entry with `size=N` in the `OPTIONS` column. Accepts plain
integers (`size=1000000`), `k` suffix (`size=512k` → 524288), or `M` suffix
(`size=10M` → 10485760). Range: `1` – `67108864` (64M).

**Upgrade caveat**: the kernel keeps an already-loaded set at its originally
allocated capacity until a full ruleset reload. After bumping sizes,
`shorewall-nft restart` (not just `reload`) is required to pick up the new
capacity.

---

## Multiple backends for one set

Two or more `nfsets` rows with the **same** `NAME` but **different** backends
are stored additively. shorewalld routes each row to its own tracker; all
trackers write to the same pair of nft sets simultaneously.

**Example**: a web-CDN set populated by both active resolver lookups and a
static plain-text allowlist:

```
# name    hosts                              options
web       cdn.example.org,edge.example.org   resolver,refresh=5m
web       /etc/shorewall46/web-extra.txt     ip-list-plain,refresh=1h
```

Emitted nft set (one declaration, union flags):

```nft
set nfset_web_v4 {
    type ipv4_addr;
    flags timeout, interval;
    size 262144;
}
set nfset_web_v6 {
    type ipv6_addr;
    flags timeout, interval;
    size 262144;
}
```

shorewalld routes the `resolver` row to `PullResolver` and the
`ip-list-plain` row to `PlainListTracker`; both write IPs into
`nfset_web_v4` and `nfset_web_v6`.

**Size when multiple backends are present**: the ip-list default (262144) is
used unless overridden. If multiple rows specify `size=N`, the largest value
wins.

---

## Referencing sets in rules

### `nfset:` token

```
#ACTION   SOURCE              DEST    PROTO   PORT
ACCEPT    net:nfset:web       loc
ACCEPT    loc                 net:nfset:cdn
```

The `nfset:<name>` token can appear in the `SOURCE` or `DEST` column, with
an optional zone prefix (`<zone>:nfset:<name>`).

### Negation

```
DROP      net:!nfset:blocklist  fw
```

### Multi-set comma expansion (OR-clone)

A comma-separated list expands into one rule per set:

```
ACCEPT    net:nfset:cdn,edge    loc
```

This is equivalent to:

```
ACCEPT    net:nfset:cdn    loc
ACCEPT    net:nfset:edge   loc
```

Each original rule is cloned once per set name. This is an **OR** semantic —
a packet matching either set is accepted.

### Inline `dnst:` / `dnsr:` / `dns:` tokens

For single-hostname inline sets without a named `nfsets` declaration:

| Token | Mechanism | Notes |
|-------|-----------|-------|
| `dnst:hostname` | dnstap-backed inline set | **Preferred** |
| `dnsr:hostname` | pull-resolver-backed inline set | Use when dnstap unavailable |
| `dns:hostname` | alias for `dnst:` | **Deprecated** — emits a compile-time `WARNING` once per config file; migrate to `dnst:` |

All three accept zone prefixes and negation:

```
ACCEPT    fw   net:dnst:api.example.org    tcp    443
DROP      net  !dnst:trusted.example.com
```

Multi-host inline form: `dnst:host1,host2,host3` — all hosts are merged into
one nft set (the first hostname is used as the set key).

Use `nfset:` when you need:

- multiple hostnames sharing one set
- non-DNS backends
- explicit set naming for tooling and monitoring

### Classic ipsets bracket syntax

shorewall-nft accepts the legacy `+setname` bracket notation for
compatibility with existing configurations. The referenced set must exist in
`table inet shorewall` at apply time (declare it via `nfsets` or load it
externally).

| Syntax | Semantics |
|--------|-----------|
| `+setname[src]` | Match source address against `setname` |
| `+setname[dst]` | Match destination address against `setname` |
| `+setname[src,dst]` | Match both src and dst against `setname` |
| `!+setname[dst]` | Negated match |
| `<zone>:+setname[src]` | Zone-prefixed bracket form |

**AND-multi-set**: `+[a,b,c]` — packet must match **all** listed sets
simultaneously. This is distinct from the `nfset:a,b` comma expansion, which
is an OR-clone:

```
# AND: packet must be in both 'trusted' AND 'vpn' sets
ACCEPT    +[trusted,vpn]    fw    tcp    22

# OR: one rule per set (cloned)
ACCEPT    nfset:cdn,edge    fw
```

### Per-table token support

The following table shows which config files accept `nfset:` / `dnst:` /
`dnsr:` / `dns:` / `+setname[...]` tokens:

| Config file | SOURCE column | DEST / ADDRESS column |
|-------------|---------------|-----------------------|
| `rules` | yes | yes |
| `blrules` | yes | yes |
| `stoppedrules` | yes | yes |
| `masq` | yes (SOURCE only) | **no** — ADDRESS column not supported |
| `dnat` | yes (SOURCE only) | **no** — TARGET column not supported |
| `tcrules` | yes | yes |
| `mangle` | yes | yes |
| `notrack` | yes | yes |
| `conntrack` | yes | yes |
| `rawnat` | yes | yes |
| `ecn` | yes | yes |
| `arprules` | yes | yes |
| `accounting` | yes | yes |
| `policies` | **no** — zone-based, no address columns | — |
| `nfacct` | **no** — no address columns | — |
| `scfilter` | **no** — compile-time allowlist | — |

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

**N→1 sharing**: multiple DNS hostnames that declare the same logical set
name share one nft set. The `DnsSetTracker` assigns one `set_id` per
`(set_name, family)` group, so answers for any of the hostnames flow into
the single shared nft set.

---

## Large-set performance (shorewalld)

Very large set payloads — including `ip-list-plain` sources with millions of
entries — are transferred to the target netns via zero-copy
`memfd_create(2)` IPC (Linux ≥ 3.17). Payloads above 4 MiB (configurable
via the `large_payload_threshold` kwarg) are routed through an anonymous,
sealed memfd region rather than the inline pickle pipe; no operator tuning
is required to handle multi-hundred-MB scripts safely.

For sets approaching or exceeding 100k elements, shorewalld exposes
environment variables that govern the apply path. All have sensible defaults;
operators only tune them if the Prometheus metrics indicate a bottleneck or
capacity concern.

| Env var | Default | Purpose |
|---------|---------|---------|
| `SHOREWALLD_IPLIST_CHUNK_SIZE` | `2000` | Elements per `add element` batch. Clamp `[100, 10000]`. |
| `SHOREWALLD_IPLIST_SWAP_RENAME` | `0` | Enable atomic swap-rename path. Set to `1` after validating. |
| `SHOREWALLD_IPLIST_SWAP_ABS` | `50000` | Trigger swap-rename when `len(new) ≥ N`. |
| `SHOREWALLD_IPLIST_SWAP_FRAC` | `0.50` | Trigger swap-rename when `(added + removed) / current ≥ frac`. |
| `SHOREWALLD_IPLIST_AUTOSIZE_HEADROOM` | `0.90` | Trigger autosize when `len(new) / declared_size ≥ ratio`. |

**Swap-rename** replaces incremental `add element` / `delete element` with a
single libnftables transaction: declare `<name>_new`, fill it, delete the
old set, rename. The whole block is atomic at the kernel level — rules
referencing the set continue to match across the swap. Requires nft ≥ 0.9.3
and Linux ≥ 5.10.

**Autosize** fires when an incoming list approaches declared capacity. The
tracker probes the current set, recomputes `next_pow2(max(len × 2, declared × 2))`
capped at 64M, and executes a swap with the larger size. A WARN log is
emitted so the operator can raise `size=` in the nfsets config on the next
push.

**Capacity warning**: when any list hits ≥ 80% of its declared size, a WARN
log is emitted regardless of whether autosize is enabled.

### Large-set Prometheus metrics

All metric families are labelled by `list` + `family` (v4/v6):

- `shorewalld_iplist_apply_duration_seconds_{sum,count}` — wall-clock per apply.
- `shorewalld_iplist_apply_path_total{path}` — `diff`, `swap`, `fallback-from-swap`, `saturated`.
- `shorewalld_iplist_set_capacity{kind}` — `used` / `declared` counts.
- `shorewalld_iplist_set_headroom_ratio` — `used / declared` as a gauge.

---

## Verification recipe

```bash
# 1. Compile the config and inspect the emitted nft set declarations.
shorewall-nft build --dry-run 2>/dev/null | grep -A5 "nfset_"

# 2. Apply the config.
shorewall-nft start

# 3. Confirm the sets are declared in the running kernel ruleset.
nft list table inet shorewall | grep "set nfset_"

# 4. Check shorewalld is populating them.
journalctl -u shorewalld --since "5 minutes ago" | grep nfset

# 5. List current elements of a specific set.
nft list set inet shorewall nfset_web_v4

# 6. Prometheus: verify entry counts.
curl -s http://localhost:9748/metrics | grep shorewalld_nfsets_entries
```

---

## Cross-references

- [shorewall-nft-nfsets(5)](../../tools/man/shorewall-nft-nfsets.5) — man page for the `nfsets` config file
- [shorewall-nft-rules(5)](../../tools/man/shorewall-nft-rules.5) — bracket syntax and `dnst:` token reference
- [shorewalld operator reference](../shorewalld/index.md) — the runtime daemon that populates sets
- [shorewalld metrics](../shorewalld/metrics.md) — full Prometheus metric reference
- [ipsets migration](ipsets.md) — classic `+setname` bracket syntax and migration guide
