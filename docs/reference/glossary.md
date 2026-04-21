# Glossary

**Audience**: operators, developers
**Scope**: Concise definitions for terms used across shorewall-nft, shorewalld, and the nfsets feature surface.

---

## nfset

A **named dynamic nft set** declared in the `/etc/shorewall/nfsets` config file and referenced from rules
as `nfset:<name>`. Each logical name produces two kernel sets — one for IPv4 (`nfset_<name>_v4`)
and one for IPv6 (`nfset_<name>_v6`). The sets are declared by the compiler and populated at runtime
by shorewalld.

Distinct from **inline dns: sets** (one set per qname, auto-named) and from **named nft set objects**
in raw nft syntax. Use `nfset:` when you need name reuse, multiple hostnames per set, or non-DNS backends.

See [docs/features/nfsets.md](../features/nfsets.md).

---

## named dynamic set / nft set

Generic nftables terminology. A set declared with `set <name> { … }` inside a table. In shorewall-nft
these are always in `table inet shorewall`. Sets backed by shorewalld have `flags timeout` (DNS-backed)
or `flags interval` (CIDR-backed).

---

## backend (nfsets context)

The source-and-update strategy for an nfset entry. One of four values:

| Value | Meaning |
|-------|---------|
| `dnstap` | shorewalld intercepts DNS answers from a dnstap/FrameStream stream and installs IPs with answer TTL |
| `resolver` | shorewalld actively resolves hostnames on a TTL-driven schedule |
| `ip-list` | shorewalld fetches a structured cloud-provider prefix list (AWS, GCP, …) |
| `ip-list-plain` | shorewalld reads one IP/CIDR per line from an HTTP URL, local file, or exec script |

---

## N→1 qname→set

When multiple DNS hostnames (qnames) in the `nfsets` config share the same logical set name, they all
feed into a single nft set. The `DnsSetTracker` assigns one `set_id` per `(set_name, family)` group.
Visible in the metric `shorewalld_dns_set_shared_qnames{set_name, family}` — a value > 1 means N:1
grouping is active.

---

## VRRP

Virtual Router Redundancy Protocol (RFC 5798). Provides IP failover between two firewall nodes.
keepalived implements VRRP: the active node holds the **VIP** and exchanges heartbeats (IP protocol 112,
multicast 224.0.0.18) with the standby node. On failure the standby promotes itself to MASTER and
claims the VIP.

Firewall rules must explicitly permit VRRP (proto 112) between the two firewall nodes; block it from
everywhere else. See root `CLAUDE.md` for the HA rule implications.

---

## VIP (Virtual IP)

The IP address that VRRP floats between active and standby nodes. Clients connect to the VIP; they
experience no interruption if the active node fails and the standby takes over within VRRP hold-time.

---

## keepalived D-Bus

keepalived exposes VRRP instance state via a D-Bus system bus interface
`org.keepalived.Vrrp1.Instance`. shorewalld's `VrrpCollector` reads from this interface using jeepney.
Only two properties are exposed: `Name (s)` and `State (us)`. Priority, VIP count, and transition
counters require SNMP augmentation.

Upstream interface definition:
`https://github.com/acassen/keepalived/blob/master/keepalived/dbus/org.keepalived.Vrrp1.Instance.xml`

**Caveat**: AlmaLinux 10 / RHEL 10 ship keepalived without `--enable-dbus`; use `--vrrp-snmp-enable`
as the alternative.

---

## KEEPALIVED-MIB

The SNMP MIB tree rooted at `.1.3.6.1.4.1.9586.100.5` that exposes keepalived VRRP state, priority,
VIP status, and transition counters. Used by shorewalld's VrrpCollector when `--vrrp-snmp-enable` is
set. Requires keepalived built with `--enable-snmp-vrrp` and an snmpd AgentX pass-through.

Upstream MIB source:
`https://github.com/acassen/keepalived/blob/master/doc/mibs/KEEPALIVED-MIB.txt`

License: see the keepalived project (GPL-2.0).

---

## pseudo-zone (`zone:dnsr:`, `zone:dnst:`)

Zone tokens in rule sources/destinations that refer to the resolver-backed and dnstap-backed dynamic
set namespaces respectively. Current implementation state:

- `zone:dnsr:` — implemented; resolves to the set populated by the `resolver` backend.
- `zone:dnst:` — reserved / not yet documented as shipped; do not rely on this syntax until a release
  note documents it. See `docs/roadmap/nfsets-deferred.md` for the planned rename.

---

## fastaccept

The FASTACCEPT emitter invariant: when `FASTACCEPT=Yes` in `shorewall.conf`, the base chains
(input/forward/output) include a leading `ct state established,related accept` rule before any dispatch
jumps. This is a performance optimisation that short-circuits established connections at the base-chain
level instead of dispatching them to zone-pair chains.

**Invariant**: `ct state invalid drop` belongs in zone-pair chains, **not** in base chains. Placing it
in a base chain before `ct state established,related accept` would drop established connections on
VRRP failover. See root `CLAUDE.md` — "nft emit architecture".
