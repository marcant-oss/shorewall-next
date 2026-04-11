# Naming conventions + structural concepts

This is the meta-chapter: what the things *are called* in a
shorewall-nft deployment and why. Read this first if you're coming
to the project cold — it ties together `marks-and-connmark.md`,
`security-defaults.md`, `dynamic-routing.md`, and `simlab.md` by
naming the objects they all talk about.

---

## 1 · Core object types

Every piece of state in shorewall-nft is one of these six things.
Every line in every config file maps to one of them.

| object       | file               | what it is                                         |
|--------------|--------------------|----------------------------------------------------|
| **zone**     | `zones`            | a named bucket of hosts (by IP or interface)       |
| **interface**| `interfaces`       | a Linux net device bound to exactly one zone       |
| **host**     | `hosts`            | a host list inside a zone, for sub-zones           |
| **policy**   | `policy`           | default verdict for a zone→zone flow direction     |
| **rule**     | `rules`            | exception to a policy, matching specific flows     |
| **mark**     | `mangle` + `rules` | a u32 tag on a packet/flow (see marks-and-connmark.md) |

Everything else is derived. Chains, sets, maps, counters, ct
zones, flowtables — all materialise from the interaction of
these six during IR construction in
`shorewall_nft/compiler/ir.py::build_ir`.

---

## 2 · Zone naming convention

Zones are the top of the namespace. Pick names that are:

- **Lowercase.** nft rejects uppercase in some identifier
  positions, and the emitter lower-cases chain names anyway.
- **Role-descriptive, not topology-descriptive.**
  `dmz` over `bond0.20`, `host` over `vlan23`, `adm` over
  `10.0.10.0/24`. Zones outlive physical topology; rename the
  zone and you edit 80 rules.
- **≤ 8 characters.** Chain names are `<src>2<dst>` which can
  stack another zone-pair suffix (`net2adm_frwd`), and nft's
  chain-name limit is 32 chars. Two 8-char zones + `2` + `_frwd` =
  21 chars, leaving headroom.
- **ASCII only.** Even though nft is UTF-8-clean in 2024, half
  the downstream tooling (conntrack, tc, grep) isn't.

Reserved zone names with special meaning:

| name        | meaning                                                       |
|-------------|---------------------------------------------------------------|
| `fw`        | the firewall itself (type `firewall`). Auto-created if absent.|
| `$FW`       | parameter expansion for `fw` (historical Shorewall syntax)    |
| `all`       | wildcard meaning "every zone" in rules. Expands at compile time.|
| `any`       | synonym for `all` in the rules file (not in zones).           |
| `none`      | the empty zone, used for suppression. Almost never written explicitly. |

Common zone names in real deployments (marcant-fw is the
reference here):

```
net     public internet, via the edge uplink(s)
adm     admin/management VLAN — SSH, monitoring, backup
mgmt    out-of-band management, usually a separate switch
host    customer VMs / physical hosts
dmz     externally reachable services
cdn     internal CDN edge
vpn     IPsec / WireGuard VPN termination
siem    SIEM / log collector VLAN
```

Eight zones is a small deployment. Marcant-fw has ~15.
> 20 and you start hitting readability issues in the
`<src>2<dst>` chain names.

---

## 3 · Interface naming

Interfaces in shorewall-nft are **Linux net device names, verbatim**.
No aliasing, no abstraction. If the kernel calls it `bond0.123`,
that's what goes in the `interfaces` file.

Patterns we see in production:

| prefix       | meaning                                      |
|--------------|----------------------------------------------|
| `eth0`, `eth1`| physical NIC. Rare on modern boxes (renamed by udev to `enpXsY` or bonded). |
| `bond0`, `bond1`| linux bonding aggregate. One per "logical uplink". |
| `bondN.VID`  | 802.1Q VLAN on top of a bond. The common marcant pattern. |
| `tunN`, `gre0`| tunnels. ptp, usually their own zone. |
| `wgN`, `wg0` | WireGuard interfaces. Modern VPN termination. |
| `tap*`, `tun*`| simlab test interfaces. Never on a real firewall. |
| `dummyN`     | loopback-like anchor for a zone that has no real L2 segment. |

**Don't use physical NIC names in rules.** The marcant setup
binds `bondN.VID` to a zone; the physical NIC is an implementation
detail of the bond. If a NIC dies, the bond still has a VLAN.

---

## 4 · Chain naming (auto-generated)

The emitter generates chain names from zones and direction. The
rule: **`<src>2<dst>` with optional suffix.** The emitter's
naming code is `shorewall_nft/compiler/ir.py::_zone_pair_chain_name`.

| chain pattern            | purpose                                         |
|--------------------------|-------------------------------------------------|
| `<src>2<dst>`            | filter-table zone-pair (forward direction)      |
| `<src>2<dst>_frwd`       | forward variant when conntrack pre-classifies   |
| `<src>2<dst>_dnat`       | DNAT pre-hook for this zone pair                |
| `<src>2<dst>_input`      | input path to the firewall itself               |
| `<src>2<dst>_output`     | output path from the firewall itself            |
| `<src>2<dst>_masq`       | masquerade/SNAT for this zone pair              |
| `<src>2<dst>_ctrk`       | conntrack helpers for this zone pair            |

If you see `adm2dmz` in an `nft list ruleset`, that's traffic from
the `adm` zone to the `dmz` zone being evaluated in the filter
table. The name is Shorewall legacy; we keep it because it
round-trips cleanly through the iptables-save oracle in
`simlab/oracle.py::_split_chain_zones`.

Suffix rule: if a chain name parses as `<anything>_<known-suffix>`,
the parser strips the suffix to recover the zone pair. If you
add a new suffix (`_foo`) make sure `_split_chain_zones` knows
about it or you'll silently break triangle + simlab oracle
classification.

---

## 5 · Set and map naming

Named sets and maps in the emitter follow a role-based prefix:

| prefix      | role                                                      |
|-------------|-----------------------------------------------------------|
| `bl_`       | blacklist (static config)                                 |
| `dyn_bl_`   | dynamic blacklist (populated at runtime via `shorewall-nft drop`) |
| `geo_<CC>`  | per-country geoipset (loaded from xt_geoip)               |
| `allow_<role>`| allowlist for a role (e.g. `allow_monitoring`)          |
| `zone_<name>`| subnet membership for a zone (auto-generated)            |
| `helpers_<proto>`| conntrack helper filter sets                          |

Sets are visible via `nft list sets`. Prefix helps operators
grep for "is there a blacklist for X?" without walking the whole
ruleset.

---

## 6 · Mark bitfield layout

This is one bitfield, four slices (also documented in
`marks-and-connmark.md` §4):

```
 bit  31         24 23         16 15          8 7           0
      ┌────────────┬─────────────┬─────────────┬─────────────┐
      │ rtt.table  │ QoS class   │ customer    │ zone id     │
      │ (uplink)   │             │             │ (CT_ZONE_TAG)│
      └────────────┴─────────────┴─────────────┴─────────────┘
       ↑            ↑             ↑             ↑
       ip rule      tc filter     accounting    shorewall-nft
       fwmark       fw handle     per-cust      CT_ZONE_TAG
```

Rule of thumb: **every slice has an operator** (`ip rule`, `tc`,
accounting, CT_ZONE_TAG). If you add a new slice, also add its
operator in the same commit — orphaned marks are a debugging tarpit.

---

## 7 · Parameter naming

Shorewall's `params` file lets you define variables used with
`$NAME` in every other file. Conventions:

- **UPPERCASE + underscores.** Consistent with shell env var style.
- **Prefix by purpose.**
  - `MARCANT_*` for our own deployment constants
  - `NET_*` for network-specific addresses
  - `HOST_*` for role hosts (`HOST_host-r`, `HOST_host-sc`)
  - `CDN_*`, `DMZ_*` for per-zone address groups
- **One thing per param.** Don't pack lists of IPs into one
  param unless they're literally always used together.

The marcant-fw `params` file has 155 entries. That's the upper
end of maintainable — above that, split into per-zone include
files (Shorewall's `?INCLUDE` directive).

---

## 8 · File layout

```
/etc/shorewall46/
├── shorewall.conf          # KEY=VALUE settings
├── params                  # variable definitions
├── zones                   # zone definitions
├── interfaces              # iface → zone bindings
├── hosts                   # sub-zone host lists
├── policy                  # default zone→zone verdicts
├── rules                   # exceptions to policy
├── masq                    # SNAT rules
├── conntrack               # ct helper attachments
├── notrack                 # bypass conntrack
├── providers               # routing providers (see dynamic-routing.md)
├── routes / rtrules        # policy routing tables
├── accounting              # per-class byte counting
├── blrules                 # blacklist rules
├── stoppedrules            # rules active when firewall is stopped
├── secmarks                # SELinux security marks (rare)
├── maclist                 # MAC address filtering
├── netmap                  # 1:1 address translation
├── plugins.conf            # plugin registry
├── plugins/
│   ├── netbox.toml         # per-plugin config
│   └── netbox.token        # credentials (mode 0600)
├── macros/                 # user-defined rule macros
│   └── macro.SSH           # one file per macro
├── rules.d/                # rule file includes
│   └── 10-mandant-*        # per-mandant overlays
└── static.nft              # raw nft snippets inlined at emit time
```

**`/etc/shorewall46` vs `/etc/shorewall`:** when both exist, the
46 directory wins (see CLAUDE.md release notes). This is the
shorewall-nft convention — upstream Shorewall uses
`/etc/shorewall` for v4 and `/etc/shorewall6` for v6 as separate
trees, and shorewall-nft's `merge-config` command produces the
unified `46` tree.

**Merged config produced via:**
```
shorewall-nft merge-config /etc/shorewall /etc/shorewall6 -o /etc/shorewall46
```

The merge step is where plugin enrichment (netbox IPv4↔IPv6
pairing) runs. Once done, the 46 tree is self-contained and the
v4/v6 source trees aren't consulted at compile time.

---

## 9 · Extension scripts

Thirteen extension points, all run as shell snippets at specific
lifecycle events:

| script    | when                                     |
|-----------|------------------------------------------|
| `start`   | before the ruleset is loaded             |
| `started` | after the ruleset is loaded              |
| `stop`    | before the ruleset is flushed            |
| `stopped` | after the ruleset is flushed             |
| `init`    | very first-time setup                    |
| `initdone`| after `init` completes                   |
| `refresh` | before a live reload                     |
| `refreshed`| after a live reload                    |
| `restored`| after a saved ruleset is restored         |
| `findgw`  | called by `shorewall-nft findgw`         |
| `ifup`    | called on interface state up             |
| `isusable`| called to test if a provider is healthy  |
| `savesets`| called when ipsets are serialised        |

These are declared line-based in the structured JSON blob
(`scripts: {name: {lang: sh, lines: [...]}}`, see
`docs/cli/override-json.md`) so they round-trip through
`config export` / `config import`.

---

## 10 · What to name for your deployment

A minimal naming bootstrap:

1. **Zones:** start with `fw`, `net`, and one or two internal
   zones (`lan`, `host`, `dmz`). Add zones only when you need a
   policy distinction, not when you "might want to some day".
2. **Interfaces:** let the kernel name them. Don't rename
   via udev just to make the config prettier.
3. **Parameters:** pick one prefix for your org (3–6 chars),
   stick to it. The marcant convention is `MARCANT_*` for
   deployment constants, `$NAME` for individual hosts.
4. **Macros:** only write one if the same rule pattern shows up
   ≥ 3 times. Don't macro-ize for "generality". See
   `shorewall_nft/compiler/actions.py` for the built-in set.
5. **Plugins:** one per external data source. Don't combine
   multiple data sources into one plugin, even if it looks
   tempting — you lose per-source disable-ability.
6. **Marks:** document the slice layout in your operator runbook
   before you set a single mark. `marks-and-connmark.md` §4 is
   the template.

---

## 11 · See also

- `docs/concepts/marks-and-connmark.md` — mark bitfield details
- `docs/concepts/security-defaults.md` — setting-level defaults
- `docs/concepts/dynamic-routing.md` — providers, routes, rtrules
- `docs/testing/simlab.md` — chain naming as the oracle sees it
- `docs/cli/override-json.md` — structured blob top-level key list
- `shorewall_nft/config/schema.py` — authoritative per-file column schema
- `shorewall_nft/compiler/ir.py::_zone_pair_chain_name` — chain naming code
