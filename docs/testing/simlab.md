# simlab — packet-level firewall test harness

`shorewall_nft.verify.simlab` is a TUN/TAP-based test lab that
rebuilds the target firewall's network namespace from on-disk
dumps of the real box, loads the compiled nft ruleset into it,
and injects + observes packets to verify forwarding behaviour.
It supersedes the older `simulate.py` runtime for packet-level
testing of production configs.

## Why a new runtime

The legacy `simulate.py` uses a fixed three-namespace topology
(src + fw + dst), a single veth pair per side, and shells out to
`nc`/`ping` for probe generation. That gave us enough fidelity
for 1.0's smoke tests, but the production marcant-fw box has:

- 24 network interfaces in 15 zones
- A real multi-homed routing table (224 v4 routes + 238 v6)
- FASTACCEPT=No (established traffic returns through the
  per-zone-pair chain)
- Rules that inspect iifname / oifname literally

The fixed-topology simulate couldn't route return traffic
through the correct interface pair, so any zone-pair beyond
the hard-coded net→host path reported spurious drops. simlab
fixes this by **reproducing the real interface topology**.

## Architecture

### Namespaces

- **host namespace** — where the controller lives. Owns every
  TUN/TAP file descriptor directly.
- **NS_FW** — named netns (default `simlab-fw`). Holds the
  emulated interfaces and the loaded shorewall nft ruleset.
  Kept alive via a stub process (see below) so the kernel
  reclaims it automatically if the controller crashes.

### Components

```
         ┌───────────────── host NS ─────────────────────┐
         │                                               │
         │   ┌──────────────────────────────────────┐    │
         │   │  SimController (asyncio)             │    │
         │   │                                      │    │
         │   │   ┌─ _iface_fds ─────────────────┐   │    │
         │   │   │  bond1    → fd1 ────────────┼───┼──┐ │
         │   │   │  bond0.20 → fd2 ────────────┼───┼──┤ │
         │   │   │  bond0.18 → fd3 ────────────┼───┼──┤ │
         │   │   │  …                          │   │  │ │
         │   │   └─────────────────────────────┘   │  │ │
         │   │                                      │  │ │
         │   │   add_reader(fdN, _on_tap_read)      │  │ │
         │   │   → inline ARP reply / NDP NA /      │  │ │
         │   │     observed-packet dispatch         │  │ │
         │   └──────────────────────────────────────┘  │ │
         │                                              │ │
         └──────────────────────────────────────────────┘ │
                                                          │
 ┌───────────────── NS_FW (netns pinned by nsstub) ───────┘
 │                                                        │
 │     bond1 (TAP)    bond0.20 (TAP)   bond0.18 (TAP) ... │
 │        │                │                │             │
 │        └───── nft shorewall ruleset ─────┘             │
 │                 + full routing table                   │
 │                                                        │
 └────────────────────────────────────────────────────────┘
```

- **Single-process design.** The controller owns every TUN/TAP
  fd directly in its own address space. No worker subprocesses,
  no multiprocessing pipes, no fork. One Python interpreter,
  one asyncio event loop, one ~200 MB RSS footprint regardless
  of how many interfaces the target firewall has.
- **Asyncio reader per fd.** On `run_probes`, the controller
  registers one `add_reader(fd, _on_tap_read, iface_name)` per
  TUN/TAP. Inject is `os.write(fd, payload)` directly — one
  syscall, no pipe roundtrip.
- **Inline ARP / NDP handling.** `_on_tap_read` parses every
  incoming frame via scapy. ARP who-has gets an immediate
  reply from `_WORKER_MAC = 02:00:00:5e:00:01` pretending to
  own the requested IP. IPv6 NDP Neighbor Solicitation gets a
  Neighbor Advertisement from a synthetic link-local. All of
  this runs inside the controller's event loop — no IPC.
- **Probe correlation in-process.** Observed IP packets go
  straight into `self._probes` / `self._probe_futures`. The
  primary match key is the probe id stashed in the IPv4 `id`
  field / IPv6 flow label; fallback is the per-probe
  `match()` closure for NAT-rewritten packets.

> **Why single-process?** Earlier versions spun up one worker
> subprocess per interface (24 workers on the reference VM).
> Each worker shipped ~80 MB of Python interpreter / stdlib /
> scapy — ~2 GB of RAM purely for interpreter overhead.
> Consolidating to N workers helped; removing workers entirely
> helped more. Single-process is simpler, smaller, and faster:
> on the reference VM the final run fires at **~125 probes/s
> with 215 MB RSS total**, vs ~20 probes/s and ~2 GB RSS under
> the subprocess model — a 6× throughput win and an 8× memory
> win from one architectural change.

### Kernel-level NS lifecycle

`simlab/nsstub.py` forks a tiny stub process that:

1. `unshare(CLONE_NEWNET)` — gets its own net namespace.
2. bind-mounts `/proc/self/ns/net` onto `/run/netns/<name>`
   so `pyroute2.NetNS` and `ip netns exec` can address it.
3. Sets `PR_SET_PDEATHSIG = SIGTERM` so the kernel signals
   the stub if the controller dies.
4. Reads from a keep-alive pipe until EOF or SIGTERM.
5. On exit: `umount` + `unlink` the bind mount → the kernel
   reclaims the netns.

Result: any controller-side crash (clean exit, Python traceback,
signal, SIGKILL) leaves no leftover `/run/netns/<name>` and no
leaked kernel net namespace. Verified on the test VM.

### Packet construction

`simlab/packets.py` builds wire-format bytes via scapy:

| protocol        | builder                              |
|-----------------|--------------------------------------|
| TCP             | `build_tcp`                          |
| UDP             | `build_udp`                          |
| ICMP            | `build_icmp`                         |
| ICMPv6          | `build_icmpv6`                       |
| ARP             | `build_arp_request`, `build_arp_reply` |
| NDP NS/NA       | `build_ndp_ns`, `build_ndp_na`       |
| ESP             | `build_esp`                          |
| GRE             | `build_gre`                          |
| VRRPv2          | `build_vrrp`                         |
| BGP OPEN        | `build_bgp_open`                     |
| OSPFv2 HELLO    | `build_ospf_hello`                   |
| DNS A/AAAA      | `build_dns_query`                    |
| DHCP DISCOVER   | `build_dhcp_discover`                |
| RADIUS          | `build_radius`                       |
| **anything else** | `build_raw_ip(proto=N, payload=…)`  |

Every IP-bearing builder takes an optional `probe_id: int`.
The controller stashes the probe's identifier into the IPv4
`id` field (16 bits) or the IPv6 flow label (20 bits). The
worker's parser reads it back into `PacketSummary.probe_id`,
and the controller correlates observed packets by this single
primary key — resilient to DNAT, SNAT, or any tuple mangling.

### Test categories

| category   | source of expectation |
|------------|-----------------------|
| `POSITIVE` | iptables-save chain rule with target ACCEPT |
| `NEGATIVE` | iptables-save chain rule with target DROP / REJECT |
| `RANDOM`   | routable random (src, dst, proto, port) classified by a ruleset oracle |

`simlab/oracle.py` parses the iptables dump once and answers
`classify(src_zone, dst_zone, src_ip, dst_ip, proto, port)` by
walking the `<src>2<dst>` chain and returning the first rule
that matches. `simlab/random` picks tuples from the routable
FW subnets so no probe is silently dropped by rp_filter.

### Run archive

Every `smoketest full` invocation writes three files under
`docs/testing/simlab-reports/<UTC-timestamp>/`:

- `report.json` — structured dump of environment, topology,
  timings, resource peaks, per-category stats, and every probe
  with its expected/observed verdict. For machine diffing.
- `report.md` — human-readable markdown with the same data
  formatted as a table.
- `mismatches.txt` — one line per probe whose observed verdict
  didn't match expectation. Grep-friendly for "is this
  regression new this week?" queries.

Environment captured includes kernel, Python, scapy, nft,
shorewall-nft version, and the git HEAD at the time of the run.

## Usage

### smoketest CLI

```
python -m shorewall_nft.verify.simlab.smoketest [OPTIONS] COMMAND [CMDOPTIONS]

Global:
  --data       Directory with ip4add/ip4routes/ip6add/ip6routes   (default /root/simulate-data)
  --config     shorewall config directory                         (default /etc/shorewall46)
  --load-limit Pause new cycles while 1-min loadavg >= this       (default 10.0)
  --report-dir Archive directory override                         (default docs/testing/simlab-reports)

Commands:
  smoke           one build, three representative probes, destroy
  stress N        N × (build + destroy) with per-cycle + overall peak sampling
  limit           run cycles until something breaks
  full [opts]     per-rule POSITIVE+NEGATIVE coverage + N random probes,
                  archives a report
    --max-per-pair N   cap probes per <src>2<dst> chain (default 10000 ≈ all)
    --random N         number of random probes (default 50)
    --seed SEED        random seed (default = wall clock)
    -v / --verbose     dump raw sysctl values before the run
```

### Example: full run on the VM

```bash
ssh root@192.0.2.83 "
  cd /root/shorewall-nft && \
  PYTHONUNBUFFERED=1 .venv/bin/python -m shorewall_nft.verify.simlab.smoketest \
    full --random 50 --max-per-pair 30 --seed 42
"
```

Reports land under `/root/shorewall-nft/docs/testing/simlab-reports/<UTC>/`
on the VM. `rsync` them back to the host for git commit.

## Performance baseline (reference VM, 2 cores, 4.9 GB RAM)

Measured on the final run with the single-process asyncio
architecture (no worker subprocesses):

| metric            | value                                          |
|-------------------|------------------------------------------------|
| build time        | ~1.1 s per cycle                               |
| nft ruleset load  | ~3.0 s (24 ifaces, libnftables path)           |
| probe throughput  | **~125 probes/s** (batch-size 256, 2 s timeout)|
| RSS, total        | **~215 MB** (controller) + ~30 MB (nsstub)     |
| peak fd usage     | ~50 during run (24 TUN/TAP + pipes)            |
| peak procs        | 1 controller + 1 stub = **2 processes**        |
| fd leak           | 0                                              |
| netns leak        | 0                                              |
| interface leak    | 0                                              |

For reference, the pre-refactor subprocess-based architecture
measured:

| metric            | subprocess model | single-process model | Δ     |
|-------------------|-----------------:|---------------------:|-------|
| RSS (total)       | ~2 GB            | ~245 MB              | **8×** better |
| probe throughput  | ~20 probes/s     | ~125 probes/s        | **6×** better |
| peak procs        | 24 workers + stub + controller | 1 + 1 | **-24** |
| nft ruleset load  | ~7–9 s           | ~3.0 s               | ~2.5× |

The gains are from removing per-interface Python interpreter
overhead (~80 MB × 24 = ~2 GB) and replacing the
worker/pipe/asyncio indirection with a single event loop + a
direct `os.write(fd, payload)` inject path.

## sysctl health check

Before each `full` run the harness warns on the following:

- `/proc/sys/fs/file-max` below 65536
- `/proc/sys/fs/nr_open` below 65536
- `/proc/sys/kernel/pid_max` below 65536
- `/proc/sys/net/core/somaxconn` below 1024
- `/proc/sys/net/core/rmem_max` / `wmem_max` below 1 MiB
- `/proc/sys/net/netfilter/nf_conntrack_max` below 131072
- CPU governor anything other than `performance`
- `/proc/sys/net/ipv4/ip_forward != 1`
- `/proc/sys/net/ipv4/conf/all/rp_filter != 0`

Warnings are printed at the top of the run and stored in the
archived `report.json` / `report.md` under `sysctl_warnings`
so reviewers can attribute performance anomalies to
configuration rather than code.

## Known limitations

- **IPv4 only for the moment.** IPv6 probes work via the
  builders but the oracle + random generator stick to v4 until
  the second simlab iteration.
- **Single NS_FW.** HA pair simulation (two FW namespaces
  exchanging VRRP + conntrackd sync) is on the roadmap.
- **Flowtable offload** is not exercised by packet tests yet —
  the 1.1 FLOWTABLE directive emits the stanza, and `nft -c`
  validates it, but we don't actually test fastpath traversal.
- **pcap-on-failure** is wired on the packet-builder side
  (`packets.export_trace_pcap`) but not yet attached to the
  controller's post-run cleanup. Top item on the roadmap.
