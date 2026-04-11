# Security defaults — modern baseline for shorewall-nft

This chapter is the short opinionated answer to *"I'm setting up a
new firewall, what should be on by default?"* It covers:

1. The shorewall.conf settings we ship with, and why.
2. The sysctl floor every firewall host should meet.
3. The kernel/nftables features we assume are available.
4. The logging defaults and what each level is good for.
5. The things shorewall-nft deliberately does NOT enable by default.

It is **not** a hardening bible — every deployment has its own
threat model. It is a "you will hit fewer footguns if you start
here" baseline derived from production experience on the
marcant-fw HA pair and the bugs we've caught in simlab during
shorewall-nft 1.0 → 1.1.

---

## 1 · shorewall.conf defaults we ship with

| setting                    | default   | why                                                            |
|----------------------------|-----------|----------------------------------------------------------------|
| `FASTACCEPT`               | `No`      | Every packet of an established flow still traverses the zone-pair chain. Costs ~1% CPU for ~100% policy visibility. See §1a. |
| `IMPLICIT_CONTINUE`        | `No`      | An empty sub-zone's rules don't silently fall through to the parent. Forces intent to be explicit. |
| `MARK_IN_FORWARD_CHAIN`    | `No`      | Marks set in PREROUTING (shorewall-nft's mangle hook), not FORWARD. Routing decisions read `meta mark` before FORWARD runs. |
| `AUTOHELPERS`              | `No`      | Conntrack helpers must be named explicitly. Blanket helper attachment was the source of many past CVEs (ALG amplification). |
| `HELPERS`                  | `ftp,snmp,tftp,pptp` | The four most-commonly-needed ALGs, opt-in per zone via `conntrack` file. Everything else off until asked. |
| `LOGALLNEW`                | unset     | Don't log every new connection — it floods `/var/log/messages` and nobody reads it. Log drops/rejects, not accepts. |
| `LOG_MARTIANS`             | `Yes`     | Matches `/proc/sys/net/ipv4/conf/*/log_martians=1`. Catches spoofing attempts + broken neighbours cheaply. |
| `ROUTE_FILTER`             | `Yes`     | Enables per-interface RPF *strict mode* only where we mean it (see §2). |
| `DYNAMIC_BLACKLIST`        | `Yes`     | Opt-in feature; shipping the knob on costs nothing if no entries. Lets `shorewall-nft drop/blacklist` commands do their thing. |
| `REQUIRE_INTERFACE`        | `No`      | Zones with no interface are legal — useful for `fw` and for mgmt overlays defined by host list. |
| `EXPAND_POLICIES`          | `Yes`     | Policy rules materialise to real chains; they're visible in `nft list ruleset` and therefore in `triangle` / `simlab`. |
| `OPTIMIZE`                 | `3`       | Default mid-tier. 4/8 (combine_matches / chain_merge) are enabled once the `triangle` verifier stops flagging false regressions on your specific config. Baseline 3 is a safe starting point. |
| `BLACKLIST_DISPOSITION`    | `DROP`    | Not REJECT: denies an attacker confirmation that a port was listening. |
| `MACLIST_DISPOSITION`      | `REJECT`  | Exception: on L2-adjacent segments where you control the clients, REJECT gives legit devices faster feedback on misconfiguration. |
| `SMURF_DISPOSITION`        | `DROP`    | Broadcast ICMP replies are never legitimate traffic. |
| `TCP_FLAGS_DISPOSITION`    | `DROP`    | Same for obviously broken TCP flag combinations (XMAS / NULL / etc). |
| `INVALID_LOG_LEVEL`        | unset     | Invalid-state packets are dropped silently. Flipping this to `info` for 5 minutes is a great debug tool, but in steady state it's noise. |
| `SFILTER_LOG_LEVEL`        | `info`    | Spoofed-source filter drops ARE worth logging — they indicate routing asymmetry you probably want to know about. |
| `RPFILTER_LOG_LEVEL`       | `info`    | Same rationale. |

### 1a · Why `FASTACCEPT=No` matters

The "fast" in FASTACCEPT means "accept established/related traffic
at the top of FORWARD, bypass all zone-pair chains". That's fine
until you want one of:

- Per-zone-pair counters on return traffic (billing, abuse).
- Per-zone-pair MARK/CONNMARK rewrites (the scenario in §6a of
  `docs/concepts/marks-and-connmark.md`).
- Log levels that differ between zones on the same flow direction.
- Rule-based routing that reads `ct mark` for established flows.

If any of those apply — which they usually do on multi-homed boxes
— FASTACCEPT must be `No` and the zone-pair chain must include its
own `ct state established,related accept`. shorewall-nft 1.1
enforces this via `_prepend_ct_state_to_zone_pair_chains()` in the
IR pass; earlier versions silently broke return traffic when
FASTACCEPT was set to `No` but the chain-local accept wasn't
emitted. See commit `7e977f70e` for the fix and
`docs/testing/simlab.md` for the regression test that would have
caught it.

---

## 2 · Kernel sysctl floor

The sysctls below are the ones shorewall-nft *assumes* are set to
at least these values. The simlab `full` harness warns about every
one of them under `sysctl_warnings` in the archived report, which
is how we notice when they drift on a RAM-only test host.

### 2a · Forwarding + source validation

```
net.ipv4.ip_forward                       = 1
net.ipv6.conf.all.forwarding              = 1
net.ipv4.conf.all.rp_filter               = 2   # loose mode
net.ipv4.conf.default.rp_filter           = 2
net.ipv4.conf.<uplink>.rp_filter          = 1   # strict on real uplinks
net.ipv4.conf.all.accept_source_route     = 0
net.ipv4.conf.all.accept_redirects        = 0
net.ipv4.conf.all.secure_redirects        = 0
net.ipv4.conf.all.send_redirects          = 0
net.ipv4.conf.all.log_martians            = 1
net.ipv6.conf.all.accept_ra               = 0
net.ipv6.conf.all.accept_redirects        = 0
```

**Loose-by-default, strict-on-uplinks** is the important pattern.
A multi-homed box with strict RPF on every interface will drop the
return path of asymmetric routing (which is the normal case with
multiple upstreams). Setting `all.rp_filter=2` and then flipping
individual uplinks to `1` is the only sane middle ground.

### 2b · Conntrack sizing

```
net.netfilter.nf_conntrack_max            = 262144   # or 4× sessions
net.netfilter.nf_conntrack_buckets        = 65536    # quarter of max
net.netfilter.nf_conntrack_tcp_timeout_established = 432000
net.netfilter.nf_conntrack_udp_timeout_stream      = 120
net.netfilter.nf_conntrack_udp_timeout             = 30
```

Too-small conntrack = random DROP on new flows under load. Size
it to 4× your expected steady-state flow count and watch
`nf_conntrack_count` in Grafana. The `nf_conntrack_tcp_loose`
sysctl defaults to `1` (accept unsolicited SYN+ACK) and should
stay there on firewalls that forward — you'll break mid-stream
recovery of long-lived flows otherwise.

### 2c · TCP stack tuning

```
net.core.rmem_max                         = 16777216
net.core.wmem_max                         = 16777216
net.core.somaxconn                        = 1024
net.core.netdev_max_backlog               = 16384
net.ipv4.tcp_syncookies                   = 1
net.ipv4.tcp_timestamps                   = 1
net.ipv4.tcp_sack                         = 1
net.ipv4.tcp_fin_timeout                  = 30
net.ipv4.tcp_max_syn_backlog              = 4096
```

These are conservative defaults for a forwarding box. If you're
running services *on* the firewall (don't), scale `somaxconn`
proportionally.

### 2d · ICMP rate limits

```
net.ipv4.icmp_ratelimit                   = 1000
net.ipv4.icmp_ratemask                    = 6168   # skip echo reply
```

Let the kernel rate-limit ICMP replies before they ever reach the
nftables ruleset. Cheaper than any nft limit expression.

### 2e · IPv6 specifics

```
net.ipv6.conf.all.use_tempaddr            = 0
net.ipv6.conf.all.autoconf                = 0
net.ipv6.conf.all.router_solicitations    = 0
```

Firewalls don't want temporary addresses, don't want to accept
router advertisements, and don't want to solicit upstream
routers. All addressing is static / DHCPv6 / OSPFv3.

`shorewall_nft/runtime/sysctl.py` emits a systemd sysctl drop-in
that sets all of this from a single place. Re-run
`shorewall-nft generate-sysctl > /etc/sysctl.d/90-shorewall-nft.conf`
after an upgrade to pick up new defaults.

---

## 3 · Kernel + nftables feature floor

shorewall-nft assumes Linux ≥ **5.8**. That version is the floor
for everything the 1.1 emitter can emit; older kernels will reject
some of the nft scripts. Concretely:

| feature                                 | kernel ≥ | modules                           |
|-----------------------------------------|----------|-----------------------------------|
| core nf_tables + inet family            | 3.13     | `nf_tables`, `nf_tables_inet`     |
| anonymous sets + maps                    | 4.1      | `nft_set_hash`, `nft_set_rbtree`  |
| stateful objects (counter/limit/quota)   | 4.16     | `nft_objref`, `nft_counter`, `nft_limit`, `nft_quota` |
| flowtable offload                        | 5.3      | `nft_flow_offload`                |
| SYNproxy                                 | 5.4      | `nft_synproxy`                    |
| concat-map NAT (used by OPTIMIZE_DNAT_MAP)| 5.6     | `nf_nat`, `nft_nat`               |
| ct expectations                          | 5.8      | `nft_ct`                          |

The `capabilities` subcommand probes the running kernel and reports
any missing modules:

```bash
shorewall-nft capabilities
```

Run this during bootstrap and fail the deploy if anything required
is `no`. For the marcant-fw test box the systemd unit in the
bootstrap script already does this; see
`tools/setup-remote-test-host.sh`.

---

## 4 · Logging defaults

### 4a · Levels and what they're for

- `info` (default): drop/reject events the operator actually wants
  to see. RPFILTER, SFILTER, MACLIST, TCP_FLAGS, SMURF.
- `debug`: per-rule counters are already visible via
  `shorewall-nft counters`; reach for this level only when
  actively hunting a specific packet.
- unset: silent drops. Use this for INVALID-state packets and any
  high-rate background drop you don't want in syslog.

### 4b · Where logs go

Prefer structured logging:

```
LOGFILE=/var/log/shorewall-nft.log
LOGFORMAT='Shorewall-nft:%s:%s:'
```

Then a rsyslog/journald rule to extract the `Shorewall-nft:` prefix
into a separate stream. If you send to a remote syslog collector,
rate-limit on the *source* — do not rely on the collector to
handle a burst.

### 4c · Anti-patterns

Do not:

- Turn on `LOGALLNEW` permanently. It's a debug aid, not a log source.
- Set `LOGLIMIT` above `d:50/sec:100`. Above that you're logging
  more than a human can read and more than syslog can buffer.
- Send firewall logs to the same file as the application logs;
  rotation policies and retention requirements are different.

---

## 5 · What shorewall-nft does NOT enable by default

These are deliberately off — the operator has to opt in per config.

1. **`flowtable` hw offload (`offload` flag).** Off by default.
   Hardware offload depends on NIC + driver support; silently
   dropping to software fastpath because the NIC doesn't support
   it is confusing. Turn it on explicitly per
   `FLOWTABLE_FLAGS=offload` once `shorewall-nft capabilities`
   confirms the driver supports it.

2. **Symmetric routing enforcement for non-uplink interfaces.**
   RPF strict on every interface breaks asymmetric routing. We
   strict-mode only what you explicitly mark.

3. **`ipv6` zones by default in a merged v4+v6 config.** The
   merge-config step warns on every zone that has an IPv4-only
   definition with no IPv6 sibling. You have to resolve the
   warning before the merged config is considered clean.

4. **Dynamic nft sets fed by external data.** The DNS-based
   filtering proposal (`docs/roadmap/post-1.0-nft-features.md`,
   Tier 2+) is explicitly opt-in because the sidecar process
   becomes part of the firewall's availability calculation.

5. **Blanket SYNproxy.** Useful against specific DDoS patterns,
   harmful as a default because it rewrites the connection
   table in a way that breaks `ct mark` replication.

6. **`ipt_ACCEPT` on `invalid` traffic.** Always dropped.
   Shorewall-legacy users sometimes discover this during
   migration when a broken app starts relying on invalid
   traffic being forwarded; the fix is the app, not the
   firewall.

---

## 6 · Checklist for a new deployment

Copy-paste this and tick:

- [ ] `shorewall-nft capabilities` passes
- [ ] sysctls from §2 applied via systemd sysctl drop-in
- [ ] `FASTACCEPT=No` in `shorewall.conf`
- [ ] `IMPLICIT_CONTINUE=No`
- [ ] `AUTOHELPERS=No`, `HELPERS=` pinned to the minimum
- [ ] RPF loose as default, strict only on real uplinks
- [ ] conntrack sized to 4× expected steady-state sessions
- [ ] `triangle` verifier passes against the merged config
- [ ] `simlab full` archived a green run into
      `docs/testing/simlab-reports/<UTC>/`
- [ ] `generate-sysctl` output committed to the config management repo
- [ ] logs going to a dedicated file with rotation policy
- [ ] flowtable offload explicitly enabled only after NIC capability check
- [ ] no `LOGALLNEW` and no `LOGLIMIT > 50/sec`

---

## 7 · See also

- `docs/concepts/marks-and-connmark.md` — packet / ct marks + ct zone
- `docs/testing/simlab.md` — the packet-level verifier that catches
  regressions of every point above
- `docs/reference/dependencies.md` — kernel module floor, python deps
- `shorewall_nft/runtime/sysctl.py` — the code that emits §2
- `shorewall_nft/nft/capabilities.py` — the code behind `shorewall-nft capabilities`
- `shorewall_nft/compiler/ir.py::_prepend_ct_state_to_zone_pair_chains` — §1a enforcement
