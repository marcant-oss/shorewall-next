# simlab run — 20260411T102443Z

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
- build: 1.139s
- nft_load: 6.893s
- probe_build: 1.769s
- run: 89.026s

## Peaks
- peak_fds: 81
- peak_procs: 1
- peak_load: 2.77
- samples: 344
- throttle_s: 0.0

## Resource delta (after − before)
- open_fds: +0
- all_netns: +0
- simlab_procs: +1
- fw_iface_count: +0
- loadavg_x100: -36

## sysctl warnings
- ⚠ sysctl /proc/sys/net/netfilter/nf_conntrack_max unreadable (conntrack table size — probe flows)

## Category results

| Category | Total | Match | Mismatch | Unknown | ACCEPT | DROP | avg | p50 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| negative | 146 | 146 | 0 | 0 | 0 | 146 | 2014ms | 2015ms | 2024ms | 2025ms |
| positive | 1816 | 1336 | 480 | 0 | 1336 | 480 | 541ms | 3ms | 2023ms | 2027ms |
| random | 50 | 20 | 30 | 0 | 20 | 30 | 1209ms | 2011ms | 2013ms | 2013ms |

