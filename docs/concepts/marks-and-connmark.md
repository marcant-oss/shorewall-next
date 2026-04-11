# Marks, conntrack marks, and what you can do with them

This is the modern reference for all the "`mark`" fields in the Linux
network stack as seen from shorewall-nft. It replaces the
iptables-era treatment in `docs/features/PacketMarking.md` (kept for
historical/migration reference) and only talks nftables / ip(8) /
conntrack(8).

> **TL;DR.** Linux exposes three independent 32-bit integer fields
> you can stamp on a packet or a connection: the **packet mark**
> (`skb->mark`, per-packet scratchpad), the **connection mark**
> (`ct->mark`, lives on the conntrack entry and survives round
> trips), and the **connection zone** (`ct->zone`, a namespace ID
> for conntrack tables, *not* a general-purpose mark but often used
> that way by shorewall-nft `CT_ZONE_TAG`). Everything downstream
> that can act on those fields — policy routing, tc, nft itself,
> conntrackd replication — is about consuming one of the three.

---

## 1 · Mental model

| name              | nft expression      | where it lives          | lifetime                          | visible in `tcpdump` |
|-------------------|--------------------|-------------------------|-----------------------------------|----------------------|
| packet mark       | `meta mark`         | `skb->mark` (kernel sk_buff)     | from hook ingress → hook egress   | no                  |
| connection mark   | `ct mark`           | `nf_conn->mark`                   | entire lifetime of the flow       | no                  |
| connection zone   | `ct zone`           | `nf_conn->zone`                   | entire lifetime of the flow       | no                  |

Two practical consequences:

1. **Packet mark is transient.** You set it on ingress, you use it
   in routing/tc/firewall, you lose it on egress. Next packet of
   the same flow starts at `meta mark == 0` again unless you re-seed
   it — which is why ct mark exists.

2. **Connection mark is sticky.** Set it once (typically in
   PREROUTING on the first packet of a flow), every subsequent
   packet in *either direction* can read it. That's how you
   remember "this is host-r's SSH session" for the full duration.

The conntrack zone is the same shape as ct mark (u32) but the
kernel treats it as a conntrack *table key* — two flows with
identical 5-tuples but different zones don't collide. shorewall-nft
repurposes it for zone tagging (see §6b) because it's a free 32-bit
field that every rule that already does conntrack lookups sees for
free.

---

## 2 · Lifecycle through the network stack

```
            ┌──────────────────────────────────────────────────────┐
  ingress → │ raw → mangle PREROUTING → conntrack (create) → NAT   │ → forward/input
            │   │                           │                      │
            │   │                           └─ ct mark inherited   │
            │   │                              from previous pkt   │
            │   └─ set meta mark here                               │
            └──────────────────────────────────────────────────────┘

  forward → ┌──────────────────────────────────────────────────────┐
            │ mangle FORWARD → filter FORWARD → routing decision   │ → egress
            │     │                │               │               │
            │     │                │               └─ ip rule fwmark
            │     │                │                  reads meta mark
            │     │                └─ filter rules can match/set
            │     │                    both meta mark + ct mark
            │     └─ also the natural spot for ct mark → meta mark
            │        save/restore (see §5)                          │
            └──────────────────────────────────────────────────────┘

  egress ──→ mangle POSTROUTING → NAT (SNAT) → traffic control (tc)
                                                   │
                                                   └─ tc filters
                                                      read meta mark
                                                      for classification
```

Key fact: **marks flow through the stack in this order** —
ingress hook(s) set them, routing and tc and NAT *read* them.
If a consumer runs before the producer, the consumer sees zero.
Classic foot-gun: setting `meta mark` in `filter FORWARD` and
expecting `ip rule fwmark` to honour it — FORWARD is too late, the
routing decision already happened. Set in PREROUTING.

One subtlety the docs often skip: conntrack **creates the entry**
in PREROUTING on the first packet of a flow, and from that point
on every packet of the flow inherits the entry's `ct mark`. So
the pattern "in PREROUTING, copy ct mark back to meta mark" (§5)
is what lets return traffic reach the same policy route as the
original direction.

---

## 3 · Tooling overview

### 3a · nftables primitives

```nft
# read
meta mark 0x10
ct mark and 0xff == 0x05
ct zone == 12

# set
meta mark set 0x10
meta mark set meta mark or 0x10           # set a bit
meta mark set meta mark and 0xffffffef    # clear a bit
meta mark set ct mark                     # restore from conntrack
ct mark set meta mark                     # save to conntrack
ct mark set ct mark and 0xffffff00 or 0x05    # masked write
ct zone set 12
```

Bitwise masking (`and`, `or`, `xor`) is how you pack multiple
independent tags into one 32-bit field without clobbering each
other. shorewall-nft uses this for `CT_ZONE_TAG`: low byte = zone
id, rest = reserved for future use.

### 3b · iproute2 policy routing

```bash
# Add a mark-matched rule routing to table 100
ip rule add fwmark 0x10 table 100 priority 100

# With a mask
ip rule add fwmark 0x10/0xff table 100 priority 100
```

`fwmark` reads `skb->mark`, not `ct mark`. If you want policy
routing by conntrack mark, you have to bounce through meta mark in
PREROUTING first (§5, §6a).

### 3c · tc classification

```bash
tc filter add dev eth0 parent 1:0 protocol ip prio 1 \
    handle 0x10 fw classid 1:10
```

Again, `fw handle` reads `skb->mark`. Same bounce rule applies.

### 3d · conntrackd replication

```conf
Sync {
    # Replicate ct mark across HA peers so the secondary box
    # knows policy/routing decisions made on the primary.
    Options {
        TCPWindowTracking Off
        ExpectationSync On
    }
    # ← key line: without this the ct mark field is zeroed on import
    AcceptL3ProtoFilter { ipv4 ipv6 }
}
```

The HA pair only agrees on policy routing if the secondary peer
sees the same `ct mark` as the primary. That's the single most
common conntrackd misconfiguration — marks get lost on replication
and every failover re-evaluates the path from scratch, which for
long-lived flows (bird BGP, SSH, VPN) means a reset.

---

## 4 · Masking: one bitfield, many tags

Because everyone wants a slice of the same 32-bit integer, the
accepted convention is to carve it up with masks and never write
without one. A typical marcant-fw layout:

| bit range      | width | purpose              | consumer         |
|----------------|-------|----------------------|------------------|
| `0x000000ff`   | 8     | zone id (CT_ZONE_TAG)| shorewall-nft     |
| `0x0000ff00`   | 8     | customer id          | accounting, tc   |
| `0x00ff0000`   | 8     | QoS class            | tc               |
| `0xff000000`   | 8     | routing table id     | ip rule fwmark   |

Setting a slice without clobbering the rest:

```nft
ct mark set ct mark and 0xffffff00 or 0x05       # set zone to 5
meta mark set meta mark and 0xffff00ff or 0x1200  # set customer to 0x12
```

**Pitfall** (we hit this one in this repo, commit `702c39b72`): nft
rejects `and MASK or iifname map { ... }` with "rhs of binary op
must be constant". The `or` operand has to be a literal, not a map
lookup. Solution: emit one rule per interface with the constant
pre-baked in. The `CT_ZONE_TAG` emitter does this.

---

## 5 · The save/restore dance

Because policy routing and tc read `meta mark` only, while you want
the tag to survive for the whole flow (so `ct mark` is the real
home), you end up writing the save/restore pattern on almost every
mark-driven path:

```nft
# PREROUTING (first packet of flow): decide the tag, commit to ct mark
table inet mangle {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        # Decide — e.g. based on inbound interface
        iifname "bond1" meta mark set 0x10
        iifname "bond2" meta mark set 0x20

        # Save to ct mark on ct state new
        ct state new ct mark set meta mark

        # Restore from ct mark on subsequent packets
        ct state established,related meta mark set ct mark
    }
}
```

After PREROUTING finishes, every packet of the flow carries the
right `meta mark` for `ip rule fwmark` and `tc filter` to pick up.

> ⚠️ The `ct state established,related` branch must come *after*
> the NAT hooks for the first packet of the flow but *before* the
> routing decision for every subsequent packet. `mangle prerouting`
> runs before routing — which is exactly why we set it here rather
> than in FORWARD.

---

## 6 · Practical patterns

### 6a · Policy routing per source zone

Goal: traffic from the `adm` zone uses uplink A, traffic from `dmz`
uses uplink B. Both have default routes in separate tables.

```nft
table inet mangle {
    map zone_to_mark {
        type ifname : mark
        elements = { "bond0.18" : 0x01000000, "bond0.14" : 0x02000000 }
    }
    chain pr {
        type filter hook prerouting priority mangle; policy accept;
        ct state new meta mark set iifname map @zone_to_mark
        ct state new ct mark set meta mark
        ct state established,related meta mark set ct mark
    }
}
```

```bash
ip route add default via 1.2.3.1 dev uplinkA table 100
ip route add default via 5.6.7.1 dev uplinkB table 200
ip rule add fwmark 0x01000000/0xff000000 table 100 priority 100
ip rule add fwmark 0x02000000/0xff000000 table 200 priority 100
```

Rule masks (`/0xff000000`) let you reuse the same fwmark field for
unrelated purposes without accidentally matching.

### 6b · Zone tagging via `CT_ZONE_TAG`

shorewall-nft 1.1 can assign one conntrack zone per firewall zone.
The emitter produces per-interface rules of the form:

```nft
ct state new iifname "bond0.18" ct zone set 5
ct state new iifname "bond0.14" ct zone set 6
```

Why not use `ct mark` for this too? Because conntrack zone is a
table key — flows with identical 5-tuples but different zones live
in separate table buckets. You can re-use the same private subnet
on two legs and conntrack sorts them out. `ct mark` can't do that;
it's just an annotation the caller interprets.

See `shorewall_nft/nft/emitter.py::emit_ct_zone_tag_rules` for the
per-interface emit loop. The `0xffffff00` mask on the ct mark
variant (for older kernels without ct zone) is documented in the
same file.

### 6c · QoS gating

tc classifies into HTB classes via `fw handle`:

```nft
ct state new oifname "uplinkA" tcp dport {80, 443} meta mark set (meta mark and 0xff00ffff) | 0x00100000
ct state new oifname "uplinkA" udp dport 53         meta mark set (meta mark and 0xff00ffff) | 0x00200000
```

```bash
tc qdisc add dev uplinkA root handle 1: htb default 99
tc class add dev uplinkA parent 1: classid 1:10 htb rate 900mbit
tc class add dev uplinkA parent 1: classid 1:20 htb rate 100mbit
tc filter add dev uplinkA parent 1: protocol ip prio 1 handle 0x00100000 fw classid 1:10
tc filter add dev uplinkA parent 1: protocol ip prio 1 handle 0x00200000 fw classid 1:20
```

The nft side writes the QoS nibble; the `fw` filters read it back.
Because the writes go through `meta mark` (tc doesn't read ct
mark), the save/restore in §5 applies — otherwise only the first
packet of each flow gets the tag and the classifier stops working
mid-stream.

### 6d · SNAT per egress interface

```nft
table inet nat {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "uplinkA" ct mark and 0x000000ff == 0x05 snat to 1.2.3.4
        oifname "uplinkA" ct mark and 0x000000ff == 0x06 snat to 1.2.3.5
    }
}
```

Useful when multiple customers share the same uplink but each
needs a dedicated public IP for reputation/monitoring reasons.
Works with conntrackd (§6f) because ct mark is authoritative.

### 6e · Multi-ISP failover with bird

Combine §6a (policy routing fwmark) with bird detecting uplink
liveness. When bird withdraws the default from table 100, the
fwmark rule still fires but the table has no default → packet is
dropped by RPF. Fix: install a *backup* default in the same table
at a worse metric, so withdrawal only removes the preferred path:

```bash
ip route add default via 1.2.3.1 dev uplinkA metric 100 table 100
ip route add default via 5.6.7.1 dev uplinkB metric 200 table 100  # fallback
```

bird can then be configured to only install/withdraw the metric
100 route; the metric 200 is a static safety net.

### 6f · conntrackd replicating ct mark across HA pair

Keepalived + conntrackd replicate the full conntrack table so
that a failover doesn't drop active sessions. `ct mark` is part of
that state *if and only if* conntrackd is built with mark support
**and** the internal filter doesn't strip it on import.

The shorewall-nft conntrackd generator (`runtime/conntrackd_gen.py`)
emits a config that preserves marks and zones both. Don't hand-edit
`/etc/conntrackd/conntrackd.conf` on the HA nodes — regenerate it.

### 6g · Per-customer accounting

Set a customer id nibble in PREROUTING, install a counter per id
in a named chain:

```nft
table inet acct {
    chain per_customer {
        meta mark and 0x0000ff00 == 0x00000100 counter
        meta mark and 0x0000ff00 == 0x00000200 counter
        # …one line per customer id
    }
    chain in {
        type filter hook forward priority 0; policy accept;
        jump per_customer
    }
}
```

Counters are per-rule, addressable by id in `nft list counter`.
For larger deployments replace the switch with a `meta mark map
{ ... : counter }` once you know the id set is stable.

---

## 7 · Interaction with shorewall-nft directives

| directive               | what it actually emits (in terms of §3) | notes |
|-------------------------|-----------------------------------------|-------|
| `MARK`                  | `meta mark set …`                      | one shot per rule |
| `SAVE`                  | `ct mark set meta mark`                | in mangle |
| `RESTORE`               | `meta mark set ct mark`                | in mangle |
| `CONNMARK`              | `ct mark set …`                        | one shot per rule |
| `CT_ZONE_TAG` (1.1)     | `ct zone set N` per iface              | §6b |
| `FLOWTABLE`             | marks must be set **before** `flow add` | offload strips changes |
| `FASTACCEPT=No` (forced)| ct state est/rel accept in zone chain  | see commit `7e977f70e` |

**Flowtable interaction:** once a flow is offloaded via `flow add
@ft`, the kernel fastpath bypasses every nft hook. That means any
`meta mark set` / `ct mark set` after the flow add will never run.
If your mark drives anything downstream, install the mark **before**
the offload check in `mangle prerouting`, not in `filter forward`.
The 1.1 emitter already orders it correctly but custom static-nft
stanzas need to respect the order.

**FASTACCEPT=No interaction:** established/related traffic takes
the zone-pair chain path, not a shortcut, which is exactly what
you want if mark-setting lives in `filter FORWARD` (it doesn't,
normally — this is the one path where FORWARD mark writes matter).
The session found this was the root cause of a bunch of phantom
drops in the 1.1 merge config; see commit `7e977f70e`.

---

## 8 · Pitfalls checklist

1. **Forgot the mask.** `ct mark set 0x05` wipes every other
   bit. Always write `ct mark set ct mark and MASK or VALUE`.

2. **Set in FORWARD, expected by routing.** FORWARD is too late.
   Move to PREROUTING.

3. **Forgot save/restore.** First packet is fine, subsequent
   packets of the same flow hit `meta mark == 0` because you
   never copied from ct mark. See §5.

4. **`and MASK or MAP` isn't valid nft.** Per-iface rules only.
   Commit `702c39b72` has the details.

5. **conntrackd strips ct mark on import.** Enable the mark
   option in conntrackd.conf *and* verify `conntrack -L` on the
   secondary shows non-zero marks for replicated flows.

6. **Flowtable offload bypasses mark writes.** Set before the
   offload check. Never in filter forward for a flow that can
   reach the fastpath.

7. **`ip rule fwmark` reads `meta mark`, not `ct mark`.** You
   will see zero on return traffic if you only stamp ct mark.
   Do the restore in §5.

8. **Masked `ip rule` is a must for shared fwmark.** If you pack
   four independent tags into the same field, every `ip rule`
   has to name its own mask or you'll cross-match.

---

## 9 · See also

- `docs/features/PacketMarking.md` — legacy Shorewall-iptables
  treatment, useful for migration.
- `docs/features/Shorewall_and_Routing.md` — the routing-focused
  counterpart to this document.
- `docs/features/MultiISP.md` — multi-uplink patterns, overlaps
  with §6a + §6e.
- `shorewall_nft/nft/emitter.py::emit_ct_zone_tag_rules` — emitter
  reference for §6b.
- `shorewall_nft/runtime/conntrackd_gen.py` — generator for §6f.
- Linux kernel docs: `Documentation/networking/nf_conntrack-sysctl.rst`,
  `Documentation/networking/filter.txt`.
