# simlab run — 20260411T131137Z

## Environment
- **kernel**: 6.11.7-amd64
- **python**: 3.12.7
- **nft**: nftables v1.1.1 (Commodore Bullmoose #2)
- **scapy**: 2.7.0
- **shorewall_nft**: 1.1.0
- **git_head**: n/a

## Topology
- interfaces: 25
- v4 routes installed: 224
- v6 routes installed: 238

## Timings
- build: 1.035s
- nft_load: 2.371s
- probe_build: 11.513s
- run: 272.975s

## Peaks
- peak_fds: 33
- peak_procs: 1
- peak_load: 0.38
- samples: 1027
- throttle_s: 0.0

## Resource delta (after − before)
- open_fds: +0
- all_netns: +0
- simlab_procs: +0
- fw_iface_count: +0
- loadavg_x100: +32

## sysctl warnings
- ✓ none

## Category results

Columns: **fail_drop** = should have had access but was DROPPED. **fail_accept** = should have been blocked but was ACCEPTED. pass_acc/pass_drp are the two correct outcomes.

| Category | Total | ok | pass_acc | pass_drp | **fail_drop** | **fail_accept** | unknown | err | avg | p50 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| negative | 1137 | 1133 | 0 | 1133 | 0 | 4 | 0 | 0 | 2059ms | 2059ms | 2166ms | 2187ms |
| positive | 31788 | 14789 | 14789 | 0 | 16999 | 0 | 0 | 0 | 1112ms | 2016ms | 2164ms | 2209ms |
| random | 64 | 51 | 18 | 33 | 5 | 0 | 8 | 0 | 1460ms | 2016ms | 2032ms | 2032ms |

