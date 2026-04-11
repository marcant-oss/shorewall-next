# Dynamic routing on a shorewall-nft box

Running a routing daemon **on** the firewall is the normal shape
for multi-homed edge deployments. This chapter covers how that
works without fighting the firewall: bird / FRR / keepalived, how
they interact with conntrack, nft, flowtable offload, and ct
mark replication, and the failure modes that bite you at 3 AM.

> **Scope.** Focused on OSPF and BGP via **bird** (what marcant-fw
> runs). FRR ist the other modern option — the config knobs are
> different, the integration points with nft are identical, so
> most of this applies unchanged. Covers IPv4 + IPv6; the two are
> separate protocol instances in both daemons.

---

## 1 · Why run routing on the firewall

Three reasons to co-locate routing with filtering on the same box:

1. **Multi-uplink failover.** Two providers, each with their own
   default route. BGP (on each uplink, from the provider's AS)
   picks the live one automatically; if one withdraws, the other
   keeps the default route installed. Static routes can't do this.
2. **Dynamic internal topology.** OSPF across the LAN backbone
   means the firewall learns new internal prefixes without a
   reconfigure. Essential if you add L3 VLANs or VPN tunnels
   frequently.
3. **HA-pair coordination.** The active node announces uplink
   reachability via BGP; the standby node advertises a higher
   MED. Failover = MED flip, no manual intervention. Pairs with
   conntrackd (§6) so in-flight sessions survive.

What **not** to run on the firewall:

- **RIP.** Dead protocol, no authentication worth the name.
- **Aggregation-heavy BGP** (10k+ routes). Use a real router and
  let the firewall just take a default.
- **IGP for the internal network** if the internal hosts don't
  speak it. OSPF-on-FW talking to a separate internal router is
  fine; OSPF-on-FW trying to be the sole router isn't.

---

## 2 · bird topology on a dual-stack edge

```
                ┌─────────────┐
                │  uplink-A   │──── bond1     ──┐
                │  BGP AS 65A │                 │
                └─────────────┘                 │
                                                │
                ┌─────────────┐                 ▼
                │  uplink-B   │──── bond2    bird
                │  BGP AS 65B │               ipv4/ipv6
                └─────────────┘               instances
                                                │
                ┌──────────────────┐            │
                │ internal OSPF    │─ bond0.17  │
                │ area 0.0.0.0     │            │
                └──────────────────┘            │
                                                │
                                       inst kernel4/6
                                                │
                                       FIB (table main + uplinkA/uplinkB)
```

The four moving pieces:

1. Two **BGP sessions** (one per uplink).
2. One **OSPF area 0.0.0.0** inside the LAN.
3. Two **kernel exporters** (bird's `protocol kernel` for v4 + v6)
   that actually install learned routes into the Linux FIB.
4. Optional **export filters** that decide which routes leave the
   FW via BGP (usually: none; we're a customer, not a transit).

A minimal bird ≥ 2.0 excerpt:

```bird
router id 10.0.0.1;

protocol device { }

protocol kernel kernel4 {
    ipv4 { import all; export all; };
    merge paths;          # ECMP to external gateways
    graceful restart;
}

protocol kernel kernel6 {
    ipv6 { import all; export all; };
    merge paths;
    graceful restart;
}

filter default_only { if net = 0.0.0.0/0 then accept; reject; }

protocol bgp uplinkA {
    local as 65100;
    neighbor 1.2.3.1 as 65000;
    ipv4 { import filter default_only; export none; };
    password "shared-secret";
    gateway recursive;
}

protocol ospf v3 ospf4 {
    ipv4 { import all; export all; };
    area 0.0.0.0 {
        interface "bond0.17" { cost 10; type broadcast; };
        interface "bond0.19" { cost 20; type broadcast; };
    };
}
```

`merge paths` enables ECMP — if both BGP peers advertise the same
default, both next-hops get installed as one multi-path route.
See §4 for how this interacts with conntrack + fwmark.

---

## 3 · Firewall rules the routing stack needs

The rules shorewall-nft must emit to let the routing stack actually
function. Don't assume "allow fw to all" — that's too broad and
usually wrong.

### 3a · OSPF (proto 89)

OSPF uses multicast `224.0.0.5` (AllSPFRouters) and `224.0.0.6`
(AllDRouters), both IP proto 89. For IPv6: `ff02::5` / `ff02::6`.

In shorewall column format (rules file):

```
ACCEPT   $FW    net:224.0.0.0/4   ipv4:89      # OSPF v4
ACCEPT   net:224.0.0.0/4   $FW   ipv4:89
ACCEPT   $FW    net:ff00::/8      ipv6-route   # OSPF v3
ACCEPT   net:ff00::/8   $FW       ipv6-route
```

Do **not** match on source address for OSPF — the sender's
address is the interface's own IP, which changes if you
renumber. Match on the multicast destination and proto only.

### 3b · BGP (tcp/179)

Standard unicast TCP. One rule per neighbor:

```
ACCEPT   $FW       net:1.2.3.1    tcp:179
ACCEPT   net:1.2.3.1   $FW        tcp:179
```

**TTL=255 protection** (GTSM, RFC 5082) is the single most
impactful BGP hardening: a real BGP neighbor is directly
connected, so its packets arrive with TTL=255. Spoofed BGP
packets from farther away can't replicate that. In bird:

```bird
ttl security on;
```

And matching rule (nft extension, not yet in shorewall-nft 1.1 —
has to go into `static.nft` as a preamble stanza):

```nft
tcp dport 179 ip ttl != 255 drop
```

Add a tracking TODO for shorewall-nft to emit this automatically.

### 3c · keepalived VRRP (proto 112)

Between HA peers only — lock the source to the peer's management
address:

```
ACCEPT   $FW    mgmt:$PEER_IP   ipv4:112
ACCEPT   mgmt:$PEER_IP    $FW   ipv4:112
```

Hostile VRRP packets from outside the mgmt zone should never
reach the kernel's keepalived — a single zone-pair match on
`mgmt` is the whole protection.

### 3d · conntrackd sync channel

If the HA pair syncs via a dedicated interface (recommended), the
conntrackd channel is a UDP flow on port 3780 (default) between
the two peer IPs on that interface. Same one-rule-per-peer
pattern as VRRP.

---

## 4 · Interaction with nft / conntrack / flowtable

### 4a · Policy routing + fwmark (§6a of marks-and-connmark.md)

The `ip rule fwmark` mechanism reads `skb->mark`. Bird installs
routes into routing tables (`table 100`, `table 200`, …) but
does **not** set any `meta mark` on incoming packets. You have
to do that yourself in nft's `mangle prerouting`, and then
`ip rule fwmark 0xNN table N` picks the table.

The common pattern: every uplink gets a named provider in
shorewall's `providers` file (`uplinkA`, `uplinkB`), which
translates to a mark, a separate routing table, and a
fwmark-keyed `ip rule`. Bird installs the actual next-hop into
each table. shorewall-nft emits:

```nft
# mangle prerouting — stamp the mark on new flows
ct state new iifname "bond1" meta mark set 0x01
ct state new ct mark set meta mark
ct state established,related meta mark set ct mark
```

Plus the `ip rule fwmark 0x01 table 100` at startup.

### 4b · ECMP (`merge paths`)

When two uplinks both carry a default route, `merge paths`
installs one route with two next-hops. The kernel hashes on
source+dest (or 4-tuple with `fib_multipath_hash_policy=1`) and
picks one. That makes fwmark-less ECMP work out of the box.

But: **conntrack locks in the next-hop for the life of the
flow**. Return traffic comes back via the same uplink only as
long as the other uplink doesn't change. If one withdraws
(BGP hold-timer fires), existing conntrack entries are
*not automatically rebalanced*. In-flight flows keep trying the
dead next-hop → packet loss until conntrack expires them.

Mitigations:

- Lower `net.netfilter.nf_conntrack_tcp_timeout_established`
  from 5 days → 1 hour for traffic that's allowed to be
  interrupted.
- Set `net.ipv4.fib_multipath_hash_policy=1` so return traffic
  on the survivor hashes the same way as the initial flow (L4
  hash keeps 4-tuple stable both ways — for TCP, anyway).
- Use `ct mark` to remember "this flow went out uplinkA" and
  drop it on `oifname != uplinkA` check. Forces the stack to
  create a new conntrack entry on the survivor uplink. Messy
  but effective.

### 4c · Flowtable offload

Flowtable bypasses nft hooks once a flow is offloaded. That
includes `ip rule fwmark` — no, wait, that's wrong: `ip rule`
runs in the routing stack, before the mangle-mark-set in
prerouting. The flow offload only skips the *netfilter* hooks
(forward, mangle, nat). So fwmark-based policy routing keeps
working even for offloaded flows *if the mark was set on the
first packet of the flow*.

This is why the save/restore dance in
`marks-and-connmark.md` §5 is critical: the first packet
sets mark + saves to ct mark, the fastpath is then entered,
and every subsequent packet's `meta mark set ct mark` never
runs — but it doesn't need to, because the routing decision
was made once on the first packet and stays cached.

### 4d · Graceful restart / NSF

Both bird and FRR support graceful restart: when the daemon
restarts, it signals its peer "hold my routes for N seconds".
During that window, the kernel FIB keeps the old routes even
though the control plane is offline. For firewall operators:

- Enable it in bird: `graceful restart` in every protocol block
  and the `kernel` exporter.
- Add `net.ipv4.tcp_tw_reuse=1` so the daemon can rebind on its
  BGP/OSPF port immediately without waiting for TIME_WAIT.
- Don't `shorewall stop; shorewall start` — a real restart
  flushes nft rules and therefore kills the routing session
  transport. Use `shorewall-nft restart` which swaps atomically.

---

## 5 · HA pair: bird + keepalived + conntrackd

Three daemons, one coordination dance:

```
  ┌─ primary ─────────────────┐     ┌─ backup ───────────────┐
  │ keepalived: MASTER        │     │ keepalived: BACKUP     │
  │ bird: BGP advertising     │<--->│ bird: BGP standby      │
  │       MED=100, live peer  │     │       MED=200, passive │
  │ conntrackd: transmit      │<--->│ conntrackd: receive    │
  │ shorewall-nft:            │     │ shorewall-nft:         │
  │  + ct mark replication on │     │  + ct mark replication │
  └───────────────────────────┘     └────────────────────────┘
```

Coordination rules:

1. **VRRP priority** dictates who's MASTER. Lose it = become
   BACKUP on the next VRRP timer.
2. On MASTER→BACKUP transition: **increase BGP MED** so the
   upstream prefers the new MASTER. bird has a `protocol bgp`
   knob for this, but the shorewall way is to ship two
   configs and swap on the transition via a keepalived notify
   script that signals bird.
3. **conntrackd** keeps the conntrack table in sync in both
   directions so the new MASTER has the live flows already in
   its own table when BGP convergence finishes. Without this
   sync, every existing TCP session resets on failover.
4. **ct mark replication** is opt-in in conntrackd.conf — make
   sure it's enabled (see marks-and-connmark.md §6f) or the
   new MASTER loses policy-routing marks on failover.

---

## 6 · Common pitfalls

1. **Forgetting proto 112 for VRRP.** keepalived silently falls
   into both-BACKUP state, both boxes answer ARP, flapping
   from the upstream's perspective. Check with
   `ip -stat netmap show vmac` (keepalived's virtual MAC).

2. **ECMP without L4 hashing.** Default
   `fib_multipath_hash_policy=0` hashes on src+dst only, so
   return traffic from a single client always goes out the
   same uplink. Fine for a single flow but breaks
   symmetric balancing. Set to 1 for L4.

3. **bird restart during `shorewall stop`.** The stop flushes nft
   → drops every forwarding rule → BGP packets to the upstream
   are no longer permitted → session tears down → bird
   withdraws → upstream routes our prefixes elsewhere. By the
   time `shorewall start` comes back, we're off the internet.
   Always use `shorewall-nft restart` (atomic table swap) or,
   if you must stop, have a service-ordering rule that
   suspends bird cleanly first.

4. **Overlapping OSPF cost on parallel paths.** Two equal-cost
   parallel links with the same metric get ECMP'd. If one has
   known-bad MTU or asymmetric loss, the hash policy picks
   between them 50/50 and half your flows limp. Fix: different
   costs, never equal.

5. **MPLS next-hop on kernel FIB.** If the upstream sends
   labeled routes, the kernel FIB rejects them (non-MPLS
   kernel). bird's `protocol kernel` silently skips these
   routes without warning. The fix is either a labelled
   kernel config or (usually) telling the upstream to send
   you non-MPLS via a BGP community.

6. **conntrackd not replicating ct mark.** Replication on, marks
   off = policy routing evaporates on failover. Enable
   `CLONE_MARK` in conntrackd.conf and verify with
   `conntrack -L` on the backup after a sync.

7. **BGP TCP MD5 password mismatch without error.** kernel
   drops mismatched packets silently at L4 — bird sees it as
   "no response", retries forever. Check
   `nstat | grep TCPMD5` to see drop counters.

---

## 7 · Operator checklist

When adding dynamic routing to a shorewall-nft deployment:

- [ ] bird + keepalived installed and autostarted
- [ ] `/etc/shorewall/rules` opens proto 89 / 112 / tcp 179 as needed
- [ ] `ttl security on` for every BGP neighbor + matching
      `tcp dport 179 ip ttl != 255 drop` in static.nft
- [ ] `fib_multipath_hash_policy=1` if ECMP is in play
- [ ] `merge paths` enabled in bird's kernel protocol blocks
- [ ] `graceful restart` enabled everywhere
- [ ] conntrackd replicating ct mark (marks-and-connmark.md §6f)
- [ ] keepalived notify script bumps BGP MED on state change
- [ ] `shorewall-nft restart` used, never `stop; start`
- [ ] tested failover actually shifts traffic without session resets

---

## 8 · See also

- `docs/concepts/marks-and-connmark.md` — fwmark, save/restore,
  conntrackd replication (§5, §6a, §6e–§6f are direct dependencies
  for this chapter)
- `docs/concepts/security-defaults.md` — rp_filter loose default,
  conntrack sizing, sysctls for routing-heavy firewalls
- `docs/features/MultiISP.md` — classic Shorewall multi-ISP
  treatment, useful as migration reference
- bird manual: <https://bird.network.cz/?get_doc&f=bird.html>
- FRR docs: <https://docs.frrouting.org>
