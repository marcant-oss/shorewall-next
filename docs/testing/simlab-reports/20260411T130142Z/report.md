# simlab run — 20260411T130142Z

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
- build: 1.054s
- nft_load: 2.988s
- probe_build: 7.235s
- run: 265.566s

## Peaks
- peak_fds: 33
- peak_procs: 1
- peak_load: 0.92
- samples: 996
- throttle_s: 0.0

## Resource delta (after − before)
- open_fds: +0
- all_netns: +1
- simlab_procs: +0
- fw_iface_count: +0
- loadavg_x100: -59

## sysctl warnings
- ✓ none

## Category results

Columns: **fail_drop** = should have had access but was DROPPED. **fail_accept** = should have been blocked but was ACCEPTED. pass_acc/pass_drp are the two correct outcomes.

| Category | Total | ok | pass_acc | pass_drp | **fail_drop** | **fail_accept** | unknown | err | avg | p50 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| negative | 8274 | 5900 | 0 | 5900 | 0 | 2374 | 0 | 0 | 1482ms | 2039ms | 2181ms | 2212ms |
| positive | 24370 | 12294 | 12294 | 0 | 12076 | 0 | 0 | 0 | 1033ms | 117ms | 2168ms | 2204ms |
| random | 64 | 45 | 17 | 28 | 10 | 1 | 8 | 0 | 1471ms | 2019ms | 2037ms | 2037ms |

