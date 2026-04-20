# shorewalld Prometheus metrics reference

Scrape endpoint: `http://HOST:PORT/metrics` (default `:9748`, Prometheus
text format, UTF-8).

This document lists every metric exposed by shorewalld.  Metrics added in
Wave 6 (nfsets observability) are marked **(W6)**.

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
| `shorewalld_dns_set_shared_qnames` | gauge | `set_name`, `family` | **(W6)** Number of qnames feeding one shared nft set; >1 means N:1 grouping active |

**Example alert** — alert if an nfset shared-set has not been updated in 10 minutes:

```promql
(time() - shorewalld_dns_set_last_update_age_seconds{set="example.com"}) > 600
```

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

## nfsets instance metrics **(W6)**

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

### Plain-list tracker **(W6)**

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
