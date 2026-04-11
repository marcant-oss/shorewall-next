# simlab run — 20260411T131833Z

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
- build: 1.163s
- nft_load: 2.388s
- probe_build: 11.497s
- run: 76.860s

## Peaks
- peak_fds: 33
- peak_procs: 0
- peak_load: 0.5
- samples: 280
- throttle_s: 0.0

## Resource delta (after − before)
- open_fds: +0
- all_netns: +0
- simlab_procs: +0
- fw_iface_count: +0
- loadavg_x100: +50

## sysctl warnings
- ✓ none

## Category results

Columns: **fail_drop** = should have had access but was DROPPED. **fail_accept** = should have been blocked but was ACCEPTED. pass_acc/pass_drp are the two correct outcomes.

| Category | Total | ok | pass_acc | pass_drp | **fail_drop** | **fail_accept** | unknown | err | avg | p50 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| negative | 20 | 16 | 0 | 16 | 0 | 4 | 0 | 0 | 575ms | 708ms | 784ms | 784ms |
| positive | 25673 | 14789 | 14789 | 0 | 10884 | 0 | 0 | 0 | 333ms | 32ms | 847ms | 898ms |
| random | 63 | 50 | 18 | 32 | 5 | 0 | 8 | 0 | 518ms | 712ms | 727ms | 727ms |

