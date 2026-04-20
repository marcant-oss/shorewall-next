---
title: shorewall-nft v1.9.0 release notes
description: nfsets, full man-page coverage, Prometheus nfsets metrics, VrrpCollector
---

# shorewall-nft v1.9.0 — Release Notes

> **Release date**: see CHANGELOG.md for the confirmed date.
> These notes cover the W1–W9 delivery: nfsets config file, full man-page
> suite, Prometheus observability for nfsets/DNS/VRRP, and VrrpCollector.

---

## Highlights

- **Named dynamic nft sets via `nfsets`** — declare sets once, reference
  them from rules by name. Four backends: passive DNS tap (`dnstap`),
  active resolver (`resolver`), cloud prefix lists (`ip-list`), and
  arbitrary URL/file/script sources (`ip-list-plain`).
- **Full man-page suite** — 5 section-8 and 35 section-5 man pages,
  one per CLI tool and one per active config table. `man shorewalld` and
  `man shorewall-nft-nfsets` are the fast-path references for operators.
- **VRRP observability** — `VrrpCollector` scrapes keepalived D-Bus state
  and optionally augments it via SNMP, providing per-instance state,
  priority, VIP status, and master-transition counters in Prometheus.

---

## Upgrading

**No configuration changes are required.** All new features are opt-in:

- `nfsets` support is inactive unless you create an `nfsets` file in your
  config directory.
- `VrrpCollector` is disabled unless you pass `--enable-vrrp-collector` to
  `shorewalld`.
- Optional package extras (`[inotify]`, `[vrrp]`, `[snmp]`) are not
  installed by default.

### Version sync checklist

When cutting the release tag, update all of the following in one commit
(see root `CLAUDE.md` for the full list):

- `packages/shorewall-nft/pyproject.toml`
- `packages/shorewalld/pyproject.toml`
- `packages/shorewall-nft-simlab/pyproject.toml`
- `packages/shorewall-nft/shorewall_nft/__init__.py`
- `packaging/rpm/shorewall-nft.spec` (Version: field + %changelog entry)
- `packaging/debian/changelog`
- `CHANGELOG.md` (move `[Unreleased]` W1–W9 block to a new `[1.9.0]` heading)
- `tools/man/*.8` and `tools/man/*.5` — update `.TH` version strings

---

## nfsets quickstart

Create `/etc/shorewall/nfsets`:

```
#NAME      HOSTS                          OPTIONS
cdn        {api,static}.example.com       resolver,dns=198.51.100.53,refresh=5m
blocklist  https://example.org/block.txt  ip-list-plain,refresh=1h
```

Reference in `/etc/shorewall/rules`:

```
#ACTION  SOURCE              DEST   PROTO  DPORT
ACCEPT   net:nfset:cdn       loc
DROP     net:nfset:blocklist fw
```

Apply and verify:

```bash
# Compile (shorewall-nft emits the set declarations)
shorewall-nft compile /etc/shorewall | grep nfset_

# Apply
sudo shorewall-nft start /etc/shorewall

# Confirm sets are present in the running kernel
nft list table inet shorewall | grep "set nfset_"

# Confirm shorewalld is populating them (after starting shorewalld)
journalctl -u shorewalld --since "2 minutes ago" | grep nfset

# Inspect live elements
nft list set inet shorewall nfset_cdn_v4
nft list set inet shorewall nfset_blocklist_v4
```

In `shorewalld` Prometheus metrics you should see:
- `shorewalld_nfsets_entries{instance="...", backend="resolver"}` — count of entries per backend
- `shorewalld_dns_resolver_refresh_total{set_name="cdn", outcome="success"}` — per-set resolver activity
- `shorewalld_plainlist_entries{name="blocklist", family="ipv4"}` — live element count

For the full reference see [`docs/features/nfsets.md`](../features/nfsets.md) and
`man shorewall-nft-nfsets` (section 5).

---

## Metrics appendix

All new nfsets and VRRP metrics are documented in
[`docs/shorewalld/metrics.md`](../shorewalld/metrics.md). Key sections to
review after upgrading:

- **nfsets instance metrics** (`shorewalld_nfsets_*`) — registration
  health, payload size.
- **Plain-list tracker** (`shorewalld_plainlist_*`) — per-source refresh
  latency, error counts, inotify status. Useful for alerting on stale
  blocklists.
- **Resolver per-set counters** (`shorewalld_dns_resolver_*`) — per-set
  refresh success/failure rates and latency.
- **VRRP metrics** (`shorewalld_vrrp_*`) — instance state, priority,
  master-transition counts.

If you maintain Grafana dashboards against shorewalld, refresh them:
the new metric families are not back-ported and will appear as empty
series on older daemon versions.

---

## VRRP observability

The `VrrpCollector` is enabled with `--enable-vrrp-collector` (or
`ENABLE_VRRP_COLLECTOR=yes` in `shorewalld.conf`). It scrapes every
keepalived process on the D-Bus system bus and emits per-instance state,
priority, VIP count, and transition counters.

D-Bus exposes only state (BACKUP/MASTER/FAULT). To get priority, effective
priority, VIP count, and master-transition totals, also enable SNMP
augmentation:

```bash
shorewalld --enable-vrrp-collector --vrrp-snmp-enable \
           --vrrp-snmp-community public --vrrp-snmp-timeout 1.0
```

Or in `shorewalld.conf`:

```
ENABLE_VRRP_COLLECTOR=yes
VRRP_SNMP_ENABLED=yes
VRRP_SNMP_HOST=127.0.0.1
```

Optional dependency: `pip install 'shorewalld[vrrp]'` (jeepney for D-Bus)
and `pip install 'shorewalld[snmp]'` (pysnmp for SNMP). Both extras are
absent by default; the daemon degrades silently when they are not installed.

**AlmaLinux 10 / RHEL 10 caveat**: keepalived 2.2.8-6.el10 is built
without `--enable-dbus`. On those hosts, enable `--vrrp-snmp-enable`
for any non-zero VRRP metrics; D-Bus discovery will log
`dbus_unavailable` errors and report no instances.

See [`docs/shorewalld/metrics.md`](../shorewalld/metrics.md#vrrp-keepalived-d-bus--snmp-augmentation-w8w9)
for the full metric reference and PromQL alert examples.

---

## Compatibility

| Platform | Python | Status |
|----------|--------|--------|
| Debian trixie | 3.11/3.12/3.13 | Supported; keepalived with D-Bus |
| Fedora 40–43 | 3.11/3.12/3.13 | Supported; keepalived with D-Bus |
| AlmaLinux 10 | 3.11/3.12/3.13 | Supported; SNMP-only VRRP mode |
| Ubuntu 24.04 LTS | 3.12 | Supported; keepalived with D-Bus |

Minimum runtime: Python 3.11, Linux kernel ≥ 5.8, nftables ≥ 0.9.3.

---

## Known issues

- `keepalived 2.2.8-6.el10` on RHEL 10 / AlmaLinux 10 / CentOS Stream 10
  is built without `--enable-dbus`; the VrrpCollector requires
  `--vrrp-snmp-enable` for non-zero metrics on those hosts.
- `shorewalld_plainlist_refresh_duration_seconds` is emitted as an empty
  `HistogramMetricFamily` alongside the populated `_sum`/`_count` pair —
  visible in scrape output but benign. Will be cleaned up post-release.
- `nfset:` syntax is not yet supported in `Masq` or `tcrules` sections;
  use inline `dns:` syntax there for now.
