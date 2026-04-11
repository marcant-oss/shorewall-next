# Multipath routing, metrics, and ECMP

This chapter covers **multipath routing on Linux** from a
shorewall-nft perspective: what kernel knobs matter, how bird
and FRR drive them, how conntrack interacts with it, and the
failure modes that only show up at 3 AM during a partial uplink
failure.

Read it after `dynamic-routing.md` — there's intentional overlap
on the routing-daemon integration points, but this chapter goes
deeper on the kernel side of things.

---

## 1 · Three ways Linux does multipath

The kernel supports three flavours of "more than one next-hop
for the same destination". Different daemons use different ones.
Don't mix them up.

| mechanism         | installed by         | next-hop selection                |
|-------------------|----------------------|-----------------------------------|
| **Classic ECMP**  | `ip route add … nexthop … nexthop …` | kernel hash per flow, 1 entry in FIB |
| **Nexthop objects** (≥ 5.3) | `ip nexthop add … + ip route … nhid N` | named, reusable, updatable without touching routes |
| **Per-provider tables + `ip rule`** | one `table N` per uplink, `ip rule` picks the table | operator-controlled per-flow via fwmark |

shorewall-nft supports all three but the emitter itself only
*directly* drives option 3 (via the `providers` file + rtrules).
ECMP happens below, in the routing table bird installs.

---

## 2 · Classic ECMP

The oldest and simplest. One route with multiple next-hops:

```bash
ip route add default \
    nexthop via 1.2.3.1 dev uplinkA \
    nexthop via 5.6.7.1 dev uplinkB
```

bird ≥ 2.0 emits this shape when you enable `merge paths` in the
kernel protocol:

```bird
protocol kernel kernel4 {
    ipv4 { import all; export all; };
    merge paths;
    graceful restart;
}
```

The kernel picks a next-hop by hashing each new flow's tuple.
Same flow → same next-hop for its entire lifetime (conntrack
pins it). Balance is **per-flow**, not per-packet.

### 2a · Hashing policy

The kernel has two hash policies selected by sysctl:

| sysctl value                          | hashes on                       |
|---------------------------------------|---------------------------------|
| `fib_multipath_hash_policy=0` (default) | src IP + dst IP (L3)           |
| `fib_multipath_hash_policy=1`           | src IP + dst IP + proto + src port + dst port (L4) |
| `fib_multipath_hash_policy=2`           | L3 + flow label (IPv6 only)    |

**Use `=1`.** The L3-only default is stable but degenerate for
firewalls: every flow from a single client goes out the same
uplink. With L4 hashing, different source ports on the same
client balance across uplinks, which is what you usually want.

```
# /etc/sysctl.d/90-multipath.conf
net.ipv4.fib_multipath_hash_policy = 1
net.ipv6.fib_multipath_hash_policy = 1
```

### 2b · Return traffic symmetry

For TCP, L4 hashing is **symmetric** — return traffic from the
server side hits the same hash bucket because we're hashing the
sorted 4-tuple, not a directional one. So in-progress TCP
connections survive next-hop stability.

For UDP there's no such guarantee — some UDP protocols
(DNS, QUIC, wireguard) use long-lived flows where return
traffic symmetry matters, and the hash is actually symmetric
for those too. Short-lived UDP (single DNS query) doesn't care.

### 2c · Why ECMP doesn't balance perfectly

With 2 uplinks and random flow arrival, you'd expect 50/50. In
practice you see 60/40 or 70/30. Reasons:

1. **Hash collisions.** With few flows (< 1000), random walk
   variance dominates. The law of large numbers takes 10k+
   flows to kick in.
2. **Flow duration variance.** Long flows (streaming, backup)
   pin one next-hop for hours, biasing the running balance.
3. **MTU / bandwidth asymmetry.** If one uplink is slower,
   flows on it take longer → more "flow-time-bytes" weighted
   toward the fast one.

If you need true 50/50, you need per-packet load balancing
(route-per-packet) which breaks conntrack and requires the
downstream to deal with reordering. Don't.

---

## 3 · Nexthop objects (kernel ≥ 5.3)

The modern replacement for classic ECMP. Nexthops are
first-class named objects:

```bash
ip nexthop add id 10 via 1.2.3.1 dev uplinkA
ip nexthop add id 20 via 5.6.7.1 dev uplinkB
ip nexthop add id 100 group 10/20
ip route add default nhid 100
```

Benefits over classic ECMP:

1. **Atomic update.** Change the member list of group 100
   without rewriting every route that references it. At scale
   (thousands of routes), this is the difference between
   milliseconds and minutes of churn.
2. **Weighted next-hops.** `group 10,2/20,1` gives uplinkA
   twice the weight. Classic ECMP has no weighting.
3. **Failure handling.** `ip nexthop set id 10 down` takes one
   member out of service without touching the group.

bird 2.13+ supports nexthop objects via the `nexthop` kernel
protocol knob. FRR via `ip nht resolve-via-default`.

shorewall-nft: **we don't emit nexthop objects directly** —
they're a routing daemon concept. We do, however, verify that
the kernel supports them via `capabilities`.

---

## 4 · Per-provider tables (the shorewall way)

This is what the `providers` file drives. Each provider is:

- a **name** (`uplinkA`)
- a **mark** (decoded fwmark slice, see `naming-and-layout.md` §6)
- an **interface** (`bond1`)
- a **gateway** (next-hop IP)
- a **routing table** (auto-assigned, e.g. table 100)
- optional **options** (loose, track, fallback, …)

The emitter (`shorewall_nft/compiler/providers.py`) produces:

1. A per-provider routing table via `ip route add default via
   $GW dev $IFACE table N`.
2. An `ip rule fwmark 0xNN/0xMASK table N` for the mark slice.
3. An `ip rule from $IP table N` when the provider has a
   source-bound rule.
4. nft mangle rules that stamp the mark on ct new, save to
   ct mark, restore on est,related (the save/restore dance
   from `marks-and-connmark.md` §5).

**This is orthogonal to ECMP.** Per-provider tables + fwmark
gives you *operator-controlled* routing per flow. ECMP gives
you *kernel-controlled* routing per flow. You can combine them:
each provider's table contains an ECMP route if the provider
has multiple next-hops behind it.

---

## 5 · Metric and precedence

Linux picks among multiple routes to the same destination in
this order:

1. **Protocol weight** (`rt_priorities`) — which daemon installed it
2. **Metric** (explicit `metric N` on the route)
3. **First-match** (order of insertion)

bird and FRR both use `kernel learn` / `kernel scan time` to
install with a predictable metric. Operators typically assign:

| metric    | purpose                                          |
|-----------|--------------------------------------------------|
| 1–99      | pinned static routes (don't touch from automation) |
| 100       | preferred dynamic route (bird primary)           |
| 200       | fallback dynamic route (bird secondary)          |
| 1024+     | "cold" fallbacks that should only fire if everything else withdraws |

Rule of thumb: **leave room between metrics.** If primary is at
100 and fallback at 101, an operator can't slot a new route
between them without bumping everything.

---

## 6 · Failure modes

### 6a · Uplink flap → every flow resets

An uplink goes down, comes back up 5 seconds later. Without
careful configuration:

1. bird detects down → withdraws routes → kernel removes next-hop
2. Conntrack entries pinned to that next-hop are now stranded —
   their next packet has no route
3. Kernel sends ICMP host-unreachable, TCP RSTs flood, every
   flow resets
4. Uplink comes back → clients reconnect → burst of new flows

Mitigations:

- **Dead Gateway Detection** via BFD (`protocol bfd` in bird)
  so flaps are caught in < 1s instead of the BGP hold-timer
  (180s default).
- **Graceful restart** so withdrawal isn't immediate — bird
  keeps the routes for a grace period.
- **Shorter conntrack TCP est timeout** (1 hour instead of 5
  days) so stranded flows self-clean faster.

### 6b · Hash rebalance on next-hop change

Adding a third uplink forces the kernel to rehash. With 1000
flows, ~330 of them will be assigned to the new uplink — and
**those flows' conntrack entries still point at the old uplink**.
Packets arrive on the wrong interface → rp_filter drops them.

This is the "adding capacity resets connections" phenomenon.
The workaround is either:

1. Accept the reset (most deployments do).
2. Use consistent hashing so adding an uplink only moves 1/N of
   flows, not ~1/N-ish of the old N. Nexthop objects with
   `algo=hash-threshold` (not yet widely supported) do this.

### 6c · Asymmetric costs

Two uplinks, one saturated, one idle. ECMP splits 50/50 by
hash → the saturated one stays saturated, the idle one stays
idle, half your traffic lags.

Fix: **weighted next-hops** via nexthop objects (§3) or a
single-next-hop setup driven by real-time bandwidth telemetry
(not yet in scope for shorewall-nft — this is what commercial
SD-WAN boxes do).

### 6d · Source-address-binding breakage

Some protocols (SIP, FTP, some VPNs) embed the local IP inside
the payload. If ECMP sends a flow out an interface whose IP
isn't what the payload claims, the peer rejects the session.

Mitigations:

- `SNAT` the traffic so the source always matches the outgoing
  interface's IP — shorewall-nft handles this via `masq`.
- Route those protocols via a *dedicated* provider with a
  single next-hop that never changes, even when others do.

### 6e · MTU path differences

Uplink A has 1500 MTU, Uplink B has 1492 (PPPoE). A flow hashed
to B that sends a 1500-byte packet gets fragmented or ICMP
Needs-Frag'd. If PMTU discovery is broken for the client, the
flow hangs.

Fix: **normalise MTU to the minimum** across all ECMP members
via `ip route … mtu 1492`. Shorewall-nft can emit this as a
per-route MTU hint if you set `MSSPREFIX` in shorewall.conf.

---

## 7 · Monitoring

What to watch on a multipath-enabled firewall:

1. **Per-interface throughput** — Grafana panel per uplink's
   rx/tx bps. Imbalance > 30/70 for hours → investigate.
2. **Per-interface conntrack count** — `conntrack -L | awk`
   grouped by output interface. Should roughly match the
   throughput split.
3. **fib_multipath_hash_policy** — assert it's 1 via a
   monitoring check. Operators sometimes reset it to 0 on
   reboot if they forgot the sysctl.d drop-in.
4. **BGP session state** per uplink — obvious but often not
   wired to alerting until a 3 AM page teaches you.
5. **rp_filter drop counter** — `nstat | grep RpFilter`. A
   non-zero counter climbing means asymmetric routing is
   active (bad) or rp_filter is strict on an interface that
   should be loose (config bug).

---

## 8 · Operator checklist

- [ ] `fib_multipath_hash_policy=1` in a sysctl.d drop-in
- [ ] `merge paths` enabled in bird kernel protocol
- [ ] BFD enabled per uplink, not just BGP hold-timer
- [ ] `graceful restart` enabled so flaps don't cascade
- [ ] `nf_conntrack_tcp_timeout_established` tuned down if
      uplink flaps are tolerated
- [ ] `rp_filter=1` strict only on real uplinks, `=2` loose
      elsewhere (see `security-defaults.md` §2a)
- [ ] metric layout documented in the operator runbook
- [ ] MTU normalised across ECMP members if they differ
- [ ] Grafana panels for per-uplink throughput + conntrack
      count + RpFilter drops
- [ ] alert on BGP session state change, not just "uplink down"

---

## 9 · See also

- `docs/concepts/dynamic-routing.md` — bird/FRR config + HA
- `docs/concepts/marks-and-connmark.md` §6a+§6e — fwmark-driven
  policy routing, multi-ISP failover patterns
- `docs/concepts/security-defaults.md` §2a — rp_filter matrix
- `docs/concepts/naming-and-layout.md` §6 — mark bitfield layout
- `shorewall_nft/compiler/providers.py` — the emitter code for
  per-provider tables + fwmark rules
- kernel docs: `Documentation/networking/ip-sysctl.txt`
