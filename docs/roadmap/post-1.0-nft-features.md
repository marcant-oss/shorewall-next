# Post-1.0 nftables Feature Roadmap

Wishlist of nft features not yet surfaced by shorewall-nft 1.0.
Ranked by **production impact × implementation cost** for the
target deployment (marcant-fw active/passive HA with conntrackd +
keepalived + bird).

## Tier 1 — High impact, release-worthy

### 1. Flowtable / Fastpath Offload

```nft
flowtable sw_fast {
    hook ingress priority filter
    devices = { bond1, bond0.20 }
    counter
}
chain forward {
    ip protocol { tcp, udp } flow add @sw_fast
    # ...
}
```

Established TCP/UDP flows bypass the full chain walk in the kernel
hot path. On a busy HA firewall doing bird-routed transit, this
is the single biggest throughput multiplier.

**Config surface:**

```
# shorewall.conf (new)
FLOWTABLE=bond1,bond0.20       # comma list of devices, empty=off
FLOWTABLE_COUNTER=Yes          # include counter on the flowtable
```

**Implementation:** small addition to `shorewall_nft.nft.emitter`
to emit the flowtable stanza and prepend the `flow add` rule to
the forward base chain. No IR changes.

### 2. ct mark / ct label Zone Tagging

Tag a connection with its source zone on the first packet,
then match on `ct mark` for subsequent packets instead of
re-running interface/iifname dispatch. conntrackd replicates
ct mark across the HA pair so zone identity survives failover.

```nft
chain sw_zone_tag {
    iifname "bond1"    ct mark set 0x01   # net
    iifname "bond0.18" ct mark set 0x02   # adm
    # ...
}
chain forward {
    ct state new jump sw_zone_tag
    ct mark 0x01 jump net-dispatch
    ct mark 0x02 jump adm-dispatch
}
```

**Config surface:** automatic, no user directive — turn on with
a `CT_ZONE_TAG=Yes` in shorewall.conf.

**Implementation:** `ir.py` assigns a ct-mark value per zone,
emitter prepends the tag chain, the per-zone dispatch chains
match on `ct mark` instead of `iifname`.

### 3. vmap-based Zone Pair Dispatch

Replace cascaded jump chains with a single verdict map:

```nft
# before (one rule per zone pair, O(N) lookups)
iifname "bond1" oifname "bond0.20" jump net-host
iifname "bond1" oifname "bond0.18" jump net-adm
# ... 240 more

# after (single O(log N) hash lookup)
iifname . oifname vmap {
    "bond1" . "bond0.20" : jump net-host,
    "bond1" . "bond0.18" : jump net-adm,
    # ...
}
```

**Implementation:** emitter-only. Hidden behind an `OPTIMIZE_VMAP`
setting so users can diff-verify.

## Tier 2 — Targeted, medium impact

### 4. synproxy for public-facing services

```nft
chain input_synproxy {
    tcp flags syn tcp dport { 80, 443 } \
        synproxy mss 1460 sack-perm timestamp
}
```

Kernel SYN-flood mitigation, offloads TCP state to the kernel
synproxy module so the real listener never sees floods.

**Config surface:** `SYNPROXY_PORTS=80,443` in `shorewall.conf`.

### 5. Named-set files with auto-reload

```nft
set blocklist {
    type ipv4_addr
    flags interval
    auto-merge
    elements = @file "/etc/shorewall46/sets/blocklist.txt"
}
```

Plus a systemd `.path` unit watching the file and issuing
`nft flush set ... ; nft add element ...`. Blocklist updates
without a full ruleset reload.

**Implementation:** small addition to the `sets/` subdir handling
in the parser + a companion systemd unit generator.

### 6. Concat-map for DNAT

Replace `DNAT` rule cascades with a single concat-map lookup:

```nft
chain prerouting {
    ip daddr . tcp dport dnat ip to {
        203.0.113.230 . 80  : 203.0.113.201 . 80,
        203.0.113.230 . 443 : 203.0.113.201 . 443,
        # ...
    }
}
```

**Config surface:** automatic when multiple DNAT rules share the
same origin pattern.

### 7. Meter-based per-source rate limiting

Drop-in replacement for connlimit on brute-force targets:

```nft
tcp dport 22 ct state new \
    meter ssh_bf { ip saddr limit rate 5/minute burst 10 }
```

**Config surface:** extend the existing `?RATELIMIT` directive to
take per-source semantics.

## Tier 2+ — DNS-based filtering with pdns_recursor integration

Rules that target DNS names instead of hardcoded IPs. A sidecar
daemon on each firewall node keeps an nft named set in sync with
the resolved addresses:

```nft
set dns_github_com {
    type ipv4_addr
    flags timeout, interval
    auto-merge
}
chain forward {
    ip daddr @dns_github_com tcp dport 443 accept
}
```

**shorewall rule surface:**

```
ACCEPT  fw      dns:github.com          tcp     443
ACCEPT  net     dns:*.apt.example.com   tcp     80,443
```

**Resolver plumbing:** each node queries BOTH configured
pdns_recursor instances (the marcant deployment runs two for
redundancy). Preferred integration is via the recursor's Lua
hooks — `postresolve_ffi` / `lua-config-file` notifies a local
shorewall-nft sidecar over a unix socket whenever a watched
name is resolved. Fallback: a systemd timer that polls
`getent ahosts` every 30–60 s and diffs the set.

**HA considerations:** conntrackd does not replicate nft named
set contents. The sidecar runs on the active AND passive node
so the passive's set is warm on failover. Set entries use
`timeout max(dns_ttl, 300s)` so a dead sidecar degrades
gracefully instead of instantly revoking access.

Not targeted for 1.1 — ships after the core nft features below
have a full release behind them.

## Tier 3 — Nice-to-have polish

- **Stateful counter/limit objects** for shared accounting pools
- **`reject with tcp reset`** as default for tcp policies (faster client-side close than icmp-admin-prohibited)
- **`jhash` load-balancing** for DNAT to a backend pool
- **`queue num N bypass`** hook for Suricata/Snort integration (plugin)
- **`ct helper` as named object** instead of per-rule declaration
- **`socket cgroupv2`** match — per-systemd-unit egress rules (e.g. only `sshd.service` may egress on 22)
- **`vrf name` match** — when bird populates multiple VRFs
- **`payload @th,0,16` for custom flag masks** — when iptables `--tcp-flags` semantics aren't enough

## Not planned

- Hardware offload (`flowtable offload`) — too NIC-specific, better
  left to operators as a follow-up tuning step
- XDP integration — out of scope for a shorewall compatibility layer
- eBPF classifiers — same reason
