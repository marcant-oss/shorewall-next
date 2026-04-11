# sample-fw — generic production-shaped test fixture

A self-contained Shorewall+Shorewall6 config for tests that need a
realistic-but-synthetic dual-stack firewall to operate against. Used
as the default value of `SHOREWALL_NFT_PROD_DIR` when tests gate on
a production-like config.

## Topology

```
    net (eth0) ───┐
                  │
                  ├──[ fw ]──┐
                  │          │
    loc (eth1) ───┤          ├── dmz (eth2)
                  │          │
                  └──────────┘
```

- 4 zones: fw, net, loc, dmz
- 3 interfaces: eth0, eth1, eth2
- Dual-stack (IPv4 + IPv6)
- Addresses use RFC 5737 / RFC 3849 documentation prefixes only

## What's exercised

- Standard macros (SSH, DNS, NTP, Ping, Rfc1918)
- `?COMMENT` mandant blocks (used by `merge-config` tests)
- `?SECTION NEW` directive
- v4/v6 paired parameters (for merge-config transitive rewriting tests)
- `routefilter` + `blacklist` interface options
- Parameter variables (`$ORG_PFX`, `$ORG_ADM`, `$DNS1`, ...)

## Usage

```bash
# Compile
shorewall-nft compile tests/fixtures/sample-fw/shorewall

# Merge into unified /etc/shorewall46-style dir
shorewall-nft merge-config tests/fixtures/sample-fw/shorewall \
                           tests/fixtures/sample-fw/shorewall6 \
                           -o /tmp/sample-merged

# Override test fixtures in pytest
SHOREWALL_NFT_PROD_DIR=tests/fixtures/sample-fw/shorewall \
SHOREWALL_NFT_PROD6_DIR=tests/fixtures/sample-fw/shorewall6 \
    pytest tests/ -v
```

## Not covered by this fixture

- NAT / masquerading (see `tests/configs/nat/`)
- Traffic shaping
- Tunnels
- Very large rule counts (for performance testing)
- Complex `?IF` conditionals
- Custom user actions

If a test needs one of these, add a separate fixture under
`tests/fixtures/` rather than bloating this one.
