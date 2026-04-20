# shorewalld Prometheus metrics reference

Scrape endpoint: `http://HOST:PORT/metrics` (default `:9748`, Prometheus
text format, UTF-8).

This document lists every metric exposed by shorewalld.

---

## Rule and set metrics

Emitted when the `inet shorewall` table is loaded.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewall_nft_packets_total` | counter | `netns`, `table`, `chain`, `rule_handle`, `comment` | Per-rule packet counter |
| `shorewall_nft_bytes_total` | counter | `netns`, `table`, `chain`, `rule_handle`, `comment` | Per-rule byte counter |
| `shorewall_nft_named_counter_packets_total` | counter | `netns`, `name` | Named nft counter object packets |
| `shorewall_nft_named_counter_bytes_total` | counter | `netns`, `name` | Named nft counter object bytes |
| `shorewall_nft_set_elements` | gauge | `netns`, `set` | Live element count per nft set |

## Flowtable metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewall_nft_flowtable_devices` | gauge | `netns`, `flowtable` | Number of devices attached to a flowtable |
| `shorewall_nft_flowtable_exists` | gauge | `netns`, `flowtable`, `hook` | 1 if the flowtable is present, 0 if absent |

## Interface metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewall_nft_iface_rx_packets_total` | counter | `netns`, `iface` | Interface Rx packets |
| `shorewall_nft_iface_rx_bytes_total` | counter | `netns`, `iface` | Interface Rx bytes |
| `shorewall_nft_iface_tx_packets_total` | counter | `netns`, `iface` | Interface Tx packets |
| `shorewall_nft_iface_tx_bytes_total` | counter | `netns`, `iface` | Interface Tx bytes |
| `shorewall_nft_iface_oper_state` | gauge | `netns`, `iface` | 1=UP, 0=DOWN |

## Conntrack metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewall_nft_ct_count` | gauge | `netns` | Current conntrack table entries |
| `shorewall_nft_ct_max` | gauge | `netns` | Maximum conntrack table capacity |
| `shorewall_nft_ct_buckets` | gauge | `netns` | Conntrack hash table buckets |
| `shorewall_nft_fib_routes` | gauge | `netns`, `family` | FIB route count (ipv4 / ipv6) |
| `shorewall_nft_ct_drop_total` | counter | `netns` | Packets dropped by conntrack |
| `shorewall_nft_ct_early_drop_total` | counter | `netns` | Early-drop events (ct table full) |
| `shorewall_nft_ct_insert_failed_total` | counter | `netns` | Conntrack insert failures |
| `shorewall_nft_ct_invalid_total` | counter | `netns` | Invalid packet events |

## SNMP / network stack metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewall_nft_ip_forwarded_total` | counter | `netns`, `family` | IP datagrams forwarded |
| `shorewall_nft_ip_out_no_routes_total` | counter | `netns`, `family` | Packets dropped: no route |
| `shorewall_nft_tcp_curr_estab` | gauge | `netns` | Current ESTABLISHED TCP connections |
| `shorewall_nft_tcpext_listen_overflows_total` | counter | `netns` | TCP listen queue overflows |
| `shorewall_nft_tcpext_syn_retrans_total` | counter | `netns` | SYN retransmissions |

## Qdisc metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewall_nft_qdisc_bytes_total` | counter | `netns`, `iface`, `kind`, `handle`, `parent` | Bytes through qdisc |
| `shorewall_nft_qdisc_drops_total` | counter | `netns`, `iface`, `kind`, `handle`, `parent` | Drops at qdisc |
| `shorewall_nft_qdisc_qlen` | gauge | `netns`, `iface`, `kind`, `handle`, `parent` | Qdisc queue length |
| `shorewall_nft_qdisc_backlog_bytes` | gauge | `netns`, `iface`, `kind`, `handle`, `parent` | Queued bytes |
| `shorewall_nft_qdisc_rate_bps` | gauge | `netns`, `iface`, `kind`, `handle`, `parent` | Bits/s through qdisc |

## nft worker pool metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewalld_worker_spawned_total` | counter | `netns` | Total worker forks since start |
| `shorewalld_worker_restarts_total` | counter | `netns` | Crash-respawn count |
| `shorewalld_worker_alive` | gauge | `netns` | 1 if worker process is running |
| `shorewalld_worker_batches_sent_total` | counter | `netns` | Batches dispatched |
| `shorewalld_worker_batches_applied_total` | counter | `netns` | Batches ack'd OK by worker |
| `shorewalld_worker_batches_failed_total` | counter | `netns` | Batches returning error |
| `shorewalld_worker_ipc_errors_total` | counter | `netns` | SEQPACKET transport errors |
| `shorewalld_worker_ack_timeout_total` | counter | `netns` | Batches that timed out |
| `shorewalld_worker_batch_latency_seconds` | histogram | `netns` | End-to-end dispatch latency |
| `shorewalld_worker_batch_size_ops` | histogram | `netns` | Batch size in ops |
| `shorewalld_worker_transport_send_bytes_total` | counter | `netns` | Bytes sent over SEQPACKET |
| `shorewalld_worker_transport_recv_bytes_total` | counter | `netns` | Bytes received over SEQPACKET |
| `shorewalld_worker_transport_send_errors_total` | counter | `netns` | SEQPACKET send errors |

## DNS-set pipeline metrics

Emitted when `--listen-api` is set.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewalld_dnstap_frames_accepted_total` | counter | — | dnstap frames accepted for decode |
| `shorewalld_dnstap_frames_decode_error_total` | counter | — | dnstap frames that failed decode |
| `shorewalld_dnstap_frames_dropped_queue_full_total` | counter | — | Frames dropped due to full decoder queue |
| `shorewalld_dnstap_connections` | gauge | — | Active dnstap connections |
| `shorewalld_dnstap_workers_busy` | gauge | — | Decoder worker threads busy |
| `shorewalld_dnstap_queue_depth` | gauge | — | Decoder queue depth |

### Per-set DNS metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewalld_dns_set_elements` | gauge | `set`, `family` | Live element count per DNS-backed nft set |
| `shorewalld_dns_set_adds_total` | counter | `set`, `family` | ADD verdicts (new IP) |
| `shorewalld_dns_set_refreshes_total` | counter | `set`, `family` | REFRESH verdicts (TTL extended) |
| `shorewalld_dns_set_dedup_hits_total` | counter | `set`, `family` | DEDUP verdicts (skipped, TTL still valid) |
| `shorewalld_dns_set_dedup_misses_total` | counter | `set`, `family` | Proposals that became real writes |
| `shorewalld_dns_set_expiries_total` | counter | `set`, `family` | Entries aged out |
| `shorewalld_dns_set_last_update_age_seconds` | gauge | `set`, `family` | Seconds since last write |
| `shorewalld_dns_set_shared_qnames` | gauge | `set_name`, `family` | Number of qnames feeding one shared nft set; >1 means N:1 grouping active |

**Example alert** — alert if an nfset shared-set has not been updated in 10 minutes:

```promql
(time() - shorewalld_dns_set_last_update_age_seconds{set="example.com"}) > 600
```

### Resolver (pull-resolver) per-set counters

Emitted by `PullResolverMetricsCollector` when at least one `resolver`-backend
nfset entry is registered.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewalld_dns_resolver_refresh_total` | counter | `set_name`, `outcome` | DNS resolver refresh cycles per nfset; `outcome` ∈ `success` \| `failure` |
| `shorewalld_dns_resolver_refresh_duration_seconds_sum` | counter | `set_name` | Cumulative seconds spent in successful refresh cycles per nfset |
| `shorewalld_dns_resolver_refresh_duration_seconds_count` | counter | `set_name` | Count of successful timed refresh cycles per nfset |

Note: `set_name` is the logical nfset name (base name, no `_v4`/`_v6` suffix)
and corresponds to the `NAME` column in the `nfsets` config file.
The `qname` label is intentionally absent to avoid unbounded cardinality.

**PromQL rate for resolver latency per set:**

```promql
rate(shorewalld_dns_resolver_refresh_duration_seconds_sum[5m])
  / rate(shorewalld_dns_resolver_refresh_duration_seconds_count[5m])
```

---

## ip-list backend metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewalld_iplist_prefixes_total` | gauge | `name`, `family` | Current prefixes in the iplist set |
| `shorewalld_iplist_last_refresh_timestamp` | gauge | `name` | Unix timestamp of last successful refresh |
| `shorewalld_iplist_fetch_errors_total` | counter | `name`, `reason` | Fetch errors by reason |
| `shorewalld_iplist_updates_total` | counter | `name`, `op` | nft set element add/remove counts |
| `shorewalld_iplist_apply_duration_seconds_sum` | counter | `list`, `family` | Cumulative apply duration |
| `shorewalld_iplist_apply_duration_seconds_count` | counter | `list`, `family` | Apply invocation count |
| `shorewalld_iplist_apply_path_total` | counter | `list`, `family`, `path` | Apply code path (`diff`/`swap`/`fallback-from-swap`) |
| `shorewalld_iplist_set_capacity` | gauge | `list`, `family`, `kind` | Set capacity (`used`/`declared`) |
| `shorewalld_iplist_set_headroom_ratio` | gauge | `list`, `family` | Fraction of declared capacity in use |

> **nfsets ip-list note**: When an nfset `ip-list` entry is registered, the
> manager produces an `IpListConfig` with `name="nfset_<entryname>"`.  All
> `shorewalld_iplist_*` metrics surface these entries automatically — the
> `nfset_` prefix in the `name` label distinguishes nfset-sourced lists
> from standalone config-sourced ones.

## nfsets instance metrics

Emitted per registered nfsets instance.

### NfSetsManager registration

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewalld_nfsets_entries` | gauge | `instance`, `backend` | Number of nfset entries per backend (`dnstap`, `resolver`, `ip-list`, `ip-list-plain`) |
| `shorewalld_nfsets_hosts` | gauge | `instance`, `backend` | Total qname/host/source count per backend |
| `shorewalld_nfsets_payload_bytes` | gauge | `instance` | Approximate serialised payload size in bytes |

**Example alert** — alert if nfsets payload grows unexpectedly:

```promql
shorewalld_nfsets_payload_bytes > 1048576
```

### Plain-list tracker

Each `ip-list-plain` source gets its own per-list metrics:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewalld_plainlist_refresh_total` | counter | `name`, `source_type`, `outcome` | Refresh attempts; `outcome` ∈ `success` \| `failure`; `source_type` ∈ `http` \| `file` \| `exec` |
| `shorewalld_plainlist_refresh_duration_seconds_sum` | counter | `name`, `source_type` | Cumulative fetch latency (successful refreshes) |
| `shorewalld_plainlist_refresh_duration_seconds_count` | counter | `name`, `source_type` | Number of timed successful refreshes |
| `shorewalld_plainlist_entries` | gauge | `name`, `family` | Current IP/CIDR count; `family` ∈ `ipv4` \| `ipv6` |
| `shorewalld_plainlist_last_success_timestamp_seconds` | gauge | `name` | Unix timestamp of last successful refresh (0 if never — alert on `time() - metric > threshold`) |
| `shorewalld_plainlist_inotify_active` | gauge | `name` | 1 if inotify watch is active; 0 if polling fallback |
| `shorewalld_plainlist_errors_total` | counter | `name`, `source_type`, `error_type` | Errors by type; `error_type` ∈ `http_status` \| `dns` \| `timeout` \| `parse` \| `exec_exit` \| `inotify_missing` \| `other` |

**Example alert** — alert if a plain-list source has not refreshed successfully in 2 hours:

```promql
(time() - shorewalld_plainlist_last_success_timestamp_seconds) > 7200
  and shorewalld_plainlist_last_success_timestamp_seconds > 0
```

**Example alert** — alert on sustained fetch errors:

```promql
increase(shorewalld_plainlist_errors_total[30m]) > 5
```

**Example alert** — alert if inotify watch fell back to polling:

```promql
shorewalld_plainlist_inotify_active == 0
  and on(name) shorewalld_plainlist_entries > 0
```

**PromQL rate for fetch latency**:

```promql
rate(shorewalld_plainlist_refresh_duration_seconds_sum[5m])
  / rate(shorewalld_plainlist_refresh_duration_seconds_count[5m])
```

### Cardinality notes

| Label | Upper bound | Notes |
|-------|-------------|-------|
| `instance` | # managed netns | Typically 1–5 |
| `backend` | 4 | Fixed: `dnstap`, `resolver`, `ip-list`, `ip-list-plain` |
| `set_name` | # qnames in allowlist | Low (< 100 in typical deployments) |
| `name` | # `ip-list-plain` configs | Low (< 20 in typical deployments) |
| `source_type` | 3 | Fixed: `http`, `file`, `exec` |
| `outcome` | 2 | Fixed: `success`, `failure` |
| `error_type` | 7 | Fixed enum |
| `family` | 2 | Fixed: `ipv4`, `ipv6` |

---

## VRRP (keepalived D-Bus + SNMP augmentation)

Enabled with `--enable-vrrp-collector`.  Requires `jeepney>=0.8`
(`pip install shorewalld[vrrp]`).  Degrades silently when jeepney is absent
or keepalived is not running.

### Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shorewalld_vrrp_state` | gauge | `bus_name`, `instance`, `vr_id`, `nic`, `family` | VRRP instance state: 1=BACKUP, 2=MASTER, 3=FAULT (D-Bus); 0=init also possible via SNMP |
| `shorewalld_vrrp_priority` | gauge | `bus_name`, `instance`, `vr_id` | Effective priority (filled by SNMP; 0 if SNMP unavailable) |
| `shorewalld_vrrp_effective_priority` | gauge | `bus_name`, `instance`, `vr_id` | Effective priority after track-script adjustments (SNMP; 0 if unavailable) |
| `shorewalld_vrrp_last_transition_timestamp_seconds` | gauge | `bus_name`, `instance`, `vr_id` | Unix timestamp of last observed state change (0 — not exposed by D-Bus or SNMP) |
| `shorewalld_vrrp_vip_count` | gauge | `bus_name`, `instance`, `vr_id`, `family` | `vrrpInstanceVipsStatus` proxy: 1=allSet, 2=notAllSet (SNMP; 0 if unavailable) |
| `shorewalld_vrrp_master_transitions_total` | counter | `bus_name`, `instance`, `vr_id` | Cumulative transitions-to-MASTER (`vrrpInstanceBecomeMaster`; 0 if SNMP unavailable) |
| `shorewalld_vrrp_scrape_errors_total` | counter | `reason` | Scrape errors by reason |

`reason` values: `dbus_unavailable`, `timeout`, `properties_get`, `parse`,
`snmp_timeout`, `snmp_parse`.

### SNMP augmentation

Add `--vrrp-snmp-enable` to query the KEEPALIVED-MIB sub-agent alongside (or
instead of) D-Bus.  This fills in the fields that D-Bus cannot expose.

**Requirements:**
- `pysnmp>=7.0`: `pip install shorewalld[snmp]`
- keepalived built with `--enable-snmp-vrrp`
- `snmpd` with the keepalived pass-through sub-agent (`agentXSocket`
  or direct sub-agent) running

**OIDs queried** from KEEPALIVED-MIB root `.1.3.6.1.4.1.9586.100.5`:

| OID suffix | Column name | Metric field |
|------------|-------------|--------------|
| `.2.3.1.2` | `vrrpInstanceName` | correlation key (`vrrp_name`) |
| `.2.3.1.4` | `vrrpInstanceState` | `state` (SNMP-only mode) |
| `.2.3.1.6` | `vrrpInstanceVirtualRouterId` | `vr_id` (SNMP-only mode) |
| `.2.3.1.7` | `vrrpInstanceEffectivePriority` | `priority` + `effective_priority` |
| `.2.3.1.8` | `vrrpInstanceVipsStatus` | `vip_count` |
| `.2.3.1.9` | `vrrpInstanceBecomeMaster` | `master_transitions` |

**SNMP state mapping:**

| SNMP value | Meaning |
|------------|---------|
| 0 | `init` — keepalived starting up (not seen via D-Bus) |
| 1 | `backup` |
| 2 | `master` |
| 3 | `fault` |

The D-Bus interface exposes only 1/2/3; SNMP can also return 0.  When both
paths succeed, D-Bus state takes precedence; SNMP fills in numeric fields only.

**Configuration flags** (see `shorewalld --help` for full descriptions):

```
--vrrp-snmp-enable                (boolean)
--vrrp-snmp-host HOST             (default: 127.0.0.1)
--vrrp-snmp-port PORT             (default: 161)
--vrrp-snmp-community STR         (default: public)
--vrrp-snmp-timeout SECS          (default: 1.0)
```

Or in `shorewalld.conf`:

```
VRRP_SNMP_ENABLED=yes
VRRP_SNMP_HOST=127.0.0.1
VRRP_SNMP_PORT=161
VRRP_SNMP_COMMUNITY=public
VRRP_SNMP_TIMEOUT=1.0
```

### Cardinality

| Label | Upper bound | Notes |
|-------|-------------|-------|
| `bus_name` | # keepalived processes | `""` in SNMP-only mode (AL10) |
| `instance` | # VRRP instances | Typically 2–8 (one per VR per family) |
| `vr_id` | 255 (VRRP spec) | Typically < 10 in practice |
| `nic` | # firewall NICs | `""` in SNMP-only mode |
| `family` | 2 | Fixed: `ipv4`, `ipv6`; `""` in SNMP-only mode |

Total label combinations: bounded by operator config.  Typically < 20.

### D-Bus property contract

keepalived exposes only two properties per instance via
`org.keepalived.Vrrp1.Instance.GetAll`:

- **`Name`** `(s)` — instance name (`vrrp->iname`)
- **`State`** `(us)` — `(uint_state, string_label)` where 1=BACKUP, 2=MASTER,
  3=FAULT

Object path format: `/org/keepalived/Vrrp1/Instance/<nic>/<vrid>/IPv4|IPv6`.
The collector derives `nic`, `vr_id`, and `family` from the path.
`priority`, `effective_priority`, `last_transition`, and `vip_count` are not
available from the D-Bus interface and remain 0 unless SNMP augmentation is
enabled.

### Example PromQL alerts

```promql
# Alert if any VRRP instance is not in MASTER state for more than 30s
# (adjust for your topology — only alert on the active node).
ALERT VrrpNotMaster
  IF shorewalld_vrrp_state{instance="fw_master_v4"} != 2
  FOR 30s
  LABELS { severity="critical" }
  ANNOTATIONS { summary="VRRP instance not MASTER" }

# Alert on frequent VRRP failovers (>2 transitions in 5 min).
ALERT VrrpFlapping
  IF rate(shorewalld_vrrp_master_transitions_total[5m]) > 0.4
  LABELS { severity="warning" }
  ANNOTATIONS { summary="VRRP instance flapping" }

# Alert on SNMP scrape failures.
ALERT VrrpSnmpErrors
  IF increase(shorewalld_vrrp_scrape_errors_total{reason=~"snmp.*"}[5m]) > 3
  LABELS { severity="warning" }
```

### CAVEATS

**AlmaLinux 10 / RHEL 10 / CentOS Stream 10**: `keepalived 2.2.8-6.el10`
is built **without** `--enable-dbus`.  The D-Bus objects are not registered
and the D-Bus path will report `dbus_unavailable` and emit no instances.

**The SNMP path is the only option that produces non-zero `priority`,
`effective_priority`, `vip_count`, and `master_transitions` on AL10.**
Enable it with `--vrrp-snmp-enable` (and ensure keepalived is built with
`--enable-snmp-vrrp`).  In SNMP-only mode the collector falls back to full
SNMP-based discovery: `bus_name`, `nic`, and `family` labels are `""` because
the KEEPALIVED-MIB does not expose the NIC or IP-family per instance.

If keepalived on AL10 cannot be rebuilt with SNMP support either, the only
remaining option is to monitor via the peer nodes (Debian/Fedora) where
keepalived ships with D-Bus or SNMP support enabled.
