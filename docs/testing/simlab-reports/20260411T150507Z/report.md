# simlab run — 20260411T150507Z

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
- build: 1.038s
- nft_load: 2.214s
- probe_build: 1.811s
- run: 0.909s

## Peaks
- peak_fds: 42
- peak_procs: 1
- peak_load: 0.09
- samples: 4
- throttle_s: 0.0

## Resource delta (after − before)
- open_fds: +0
- all_netns: +0
- simlab_procs: +1
- fw_iface_count: +0
- loadavg_x100: +15

## sysctl warnings
- ✓ none

## Category results

Columns: **fail_drop** = should have had access but was DROPPED. **fail_accept** = should have been blocked but was ACCEPTED. pass_acc/pass_drp are the two correct outcomes.

| Category | Total | ok | pass_acc | pass_drp | **fail_drop** | **fail_accept** | unknown | err | avg | p50 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| positive | 626 | 626 | 626 | 0 | 0 | 0 | 0 | 0 | 41ms | 48ms | 52ms | 52ms |
| random | 64 | 64 | 20 | 44 | 0 | 0 | 0 | 0 | 111ms | 151ms | 154ms | 154ms |

