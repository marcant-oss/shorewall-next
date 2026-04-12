"""Explain nft features with examples.

Provides human-readable explanations and nft syntax examples
for all supported nftables features. Includes both static
(hardcoded) and dynamic (probed from kernel) features.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FeatureExample:
    name: str
    category: str
    description: str
    nft_syntax: str
    shorewall_equivalent: str = ""
    available: bool = True


# Static feature catalog with examples
_FEATURES: list[FeatureExample] = [
    # ── Table Families ──
    FeatureExample(
        name="inet",
        category="Table Families",
        description="Unified IPv4+IPv6 table. Processes both address families in one ruleset.",
        nft_syntax="# Automatic: shorewall-nft merges /etc/shorewall + /etc/shorewall6\nshorewall-nft start /etc/shorewall\n# Or explicitly:\nshorewall-nft merge-config /etc/shorewall /etc/shorewall6 -o /etc/shorewall-nft",
    ),
    FeatureExample(
        name="netdev",
        category="Table Families",
        description="Ingress/egress filtering at device level. Runs before routing decisions. Use static.nft for raw nft.",
        nft_syntax="# Place in /etc/shorewall/static.nft:\n# flowtable ft { hook ingress priority 0; devices = { eth0 }; }",
    ),

    # ── Connection Tracking ──
    FeatureExample(
        name="ct_state",
        category="Connection Tracking",
        description="Match packets by connection tracking state. Automatic in base chains.",
        nft_syntax="# /etc/shorewall/shorewall.conf:\nFASTACCEPT=Yes    # accept established in base chain (fast)\nFASTACCEPT=No     # let established flow through zone chains (for accounting)",
    ),
    FeatureExample(
        name="ct_helper",
        category="Connection Tracking",
        description="Assign connection tracking helpers for protocols with dynamic ports.",
        nft_syntax="# /etc/shorewall/conntrack:\n?FORMAT 3\n?if __CT_TARGET\nCT:helper:ftp:PO   -           -     tcp   21\nCT:helper:sip:PO   -           -     udp   5060\nCT:helper:tftp:PO  -           -     udp   69\nCT:helper:h323:PO  -           -     tcp   1720\n?endif\n\n# Zone-restricted helper (only for DMZ servers):\nCT:helper:ftp:PO   net         dmz   tcp   21\n\n# Combined with notrack for high-performance DNS:\n?SECTION NOTRACK\nNOTRACK            net         $FW   udp   53\nNOTRACK            $FW         net   udp   -     53",
    ),
    FeatureExample(
        name="ct_count",
        category="Connection Tracking",
        description="Limit concurrent connections per source (connlimit).",
        nft_syntax="# /etc/shorewall/rules — column 11 (CONNLIMIT):\n#ACTION  SOURCE  DEST  PROTO  DPORT  SPORT  ORIGDEST  RATE  USER  MARK  CONNLIMIT\nACCEPT   net     $FW   tcp    22     -      -         -     -     -     s:5",
    ),
    FeatureExample(
        name="notrack",
        category="Connection Tracking",
        description="Bypass connection tracking for specific traffic.",
        nft_syntax="# /etc/shorewall/notrack:\n#SOURCE         DESTINATION      PROTO  DPORT\nnet             203.0.113.1   udp    53\n$FW             0.0.0.0/0        udp    -      53",
    ),

    # ── Matching ──
    FeatureExample(
        name="meta_nfproto",
        category="Matching",
        description="Restrict rules to IPv4 or IPv6 only in merged dual-stack config.",
        nft_syntax="# Automatic: rules from /etc/shorewall/ get 'meta nfproto ipv4'\n# Rules from /etc/shorewall6/ get 'meta nfproto ipv6'\n# Rules with explicit IPv6 addresses (ip6 saddr) need no annotation.",
    ),
    FeatureExample(
        name="fib",
        category="Matching",
        description="Routing table lookups — smurf protection, broadcast detection.",
        nft_syntax="# /etc/shorewall/interfaces — nosmurfs option:\n#ZONE  INTERFACE  BROADCAST  OPTIONS\nnet    eth0       detect     tcpflags,nosmurfs,routefilter",
    ),
    FeatureExample(
        name="negation",
        category="Matching",
        description="Negate source or destination with ! prefix.",
        nft_syntax="# /etc/shorewall/rules:\n#ACTION  SOURCE          DEST  PROTO  DPORT\nACCEPT   !net:10.0.0.0/8  $FW   tcp    22\nDROP     net              all",
    ),

    # ── Rate Limiting ──
    FeatureExample(
        name="limit",
        category="Rate Limiting",
        description="Rate-limit matching packets. Excess packets fall through to next rule.",
        nft_syntax="# /etc/shorewall/rules — column 8 (RATE):\n#ACTION  SOURCE  DEST  PROTO  DPORT  SPORT  ORIGDEST  RATE\n# Per-source rate limit (s: prefix) with burst:\nACCEPT   all     web   tcp    ssh    -      -         s:sshlogin:3/min:5\n\n# Global rate limit (no s: prefix):\nACCEPT   net     $FW   icmp   -      -      -         10/sec:20\n\n# Complex: rate-limit + connlimit combined:\n#ACTION  SRC  DST  PROTO  DPORT  SPORT  ORIG  RATE             USER  MARK  CONNLIMIT\nACCEPT   net  dmz  tcp    smtp   -      -     s:smtp:5/min:10  -     -     s:3\n\n# Graduated response — different limits for different actions:\nACCEPT   net  $FW  tcp    22     -      -     s:ssh-ok:3/min:5\nDROP:info net  $FW  tcp    22     # excess → log + drop",
    ),
    FeatureExample(
        name="quota",
        category="Rate Limiting",
        description="Byte-based quota — not directly in Shorewall config, use static.nft.",
        nft_syntax="# /etc/shorewall/static.nft:\n# quota over 1 gbytes drop",
    ),

    # ── Sets ──
    FeatureExample(
        name="named_sets",
        category="Sets",
        description="Named sets for efficient matching against large IP lists (replaces ipset).",
        nft_syntax="# /etc/shorewall/init (creates ipset → becomes nft set):\n/sbin/ipset create customer-a-ipv4 hash:net -!\nwhile read pfx; do\n    /sbin/ipset add customer-a-ipv4 \"$pfx\" -!\ndone < /etc/shorewall/customer-a-prefixes.txt\n\n# /etc/shorewall/rules — reference with + prefix:\n#ACTION  SOURCE              DEST\nDROP     net:+customer-a-ipv4   all\n\n# Multiple sets in complex rules:\nACCEPT   net:+trusted-nets    dmz:+webservers  tcp  443\nDROP     net:+geoip-block     all\n\n# Set in DNAT (forward to any server in the set):\nDNAT     net:+allowed-mgmt    loc:192.168.1.10:22  tcp  22\n\n# GeoIP blocking — load country sets:\nshorewall-nft generate-set-loader /etc/shorewall\n# Generates script that loads all referenced +sets",
    ),
    FeatureExample(
        name="timeout_sets",
        category="Sets",
        description="Dynamic sets with automatic element expiration for runtime blacklisting.",
        nft_syntax="# /etc/shorewall/shorewall.conf:\nDYNAMIC_BLACKLIST=Yes\n\n# CLI usage:\nshorewall-nft blacklist 1.2.3.4 -t 1h    # block for 1 hour\nshorewall-nft drop 5.6.7.8               # block permanently\nshorewall-nft allow 1.2.3.4              # unblock",
    ),
    FeatureExample(
        name="anonymous_sets",
        category="Sets",
        description="Inline sets for matching multiple values — comma-separated in rules.",
        nft_syntax="# /etc/shorewall/rules:\n#ACTION  SOURCE  DEST  PROTO  DPORT\nACCEPT   net     $FW   tcp    22,80,443,8080\nDROP     net:10.0.0.0/8,172.16.0.0/12,192.168.0.0/16  all",
    ),

    # ── NAT ──
    FeatureExample(
        name="snat",
        category="NAT",
        description="Source NAT — rewrite source address for outbound traffic.",
        nft_syntax="# /etc/shorewall/masq:\n#INTERFACE:DEST  SOURCE          ADDRESS\neth0             192.168.1.0/24  203.0.113.1\neth0             10.0.0.0/8      # masquerade (use interface IP)\n\n# Multi-address SNAT — different subnets via different public IPs:\neth0             192.168.1.0/24  203.0.113.1\neth0             192.168.2.0/24  203.0.113.2\neth0             172.16.0.0/12   203.0.113.3\n\n# SNAT only traffic to a specific destination:\neth0:198.51.100.0/24  10.0.0.0/8  203.0.113.5\n\n# SNAT with protocol/port restriction:\neth0             10.0.0.0/8      203.0.113.10  tcp  25  # only SMTP",
    ),
    FeatureExample(
        name="dnat",
        category="NAT",
        description="Destination NAT — redirect inbound traffic to internal server.",
        nft_syntax="# /etc/shorewall/rules:\n#ACTION  SOURCE  DEST                 PROTO  DPORT  SPORT  ORIGDEST\n# Simple port forward:\nDNAT     net     loc:192.168.1.10:80   tcp    80     -      203.0.113.1\n\n# Port remapping (external 8080 → internal 80):\nDNAT     net     loc:192.168.1.10:80   tcp    8080   -      203.0.113.1\n\n# Multiple ports to different servers:\nDNAT     net     dmz:10.0.0.5:25       tcp    25     -      203.0.113.2\nDNAT     net     dmz:10.0.0.6:443      tcp    443    -      203.0.113.2\nDNAT     net     dmz:10.0.0.7:3389     tcp    13389  -      203.0.113.3\n\n# Port range DNAT:\nDNAT     net     loc:192.168.1.20:5060-5080  udp  5060-5080  -  203.0.113.1\n\n# DNAT with conditional source restriction:\nDNAT     net:198.51.100.0/24  loc:192.168.1.10:22  tcp  22  -  203.0.113.1",
    ),
    FeatureExample(
        name="masquerade",
        category="NAT",
        description="Dynamic SNAT — uses the outgoing interface's current address.",
        nft_syntax="# /etc/shorewall/masq — omit ADDRESS column:\n#INTERFACE  SOURCE\neth0        eth1     # masquerade all traffic from eth1 via eth0\nppp+        eth1     # masquerade via any PPP interface (dynamic IP)\n\n# Masquerade only specific protocols:\neth0        eth1     -    tcp  80,443  # only HTTP/HTTPS\neth0        eth1     -    udp  53      # only DNS",
    ),
    FeatureExample(
        name="netmap",
        category="NAT",
        description="Subnet-to-subnet NAT (1:1 mapping). Symmetric netmap for bidirectional translation.",
        nft_syntax="# /etc/shorewall/rules — DNAT netmap (entire subnet):\n#ACTION   SOURCE  DEST                      PROTO  DPORT  SPORT  ORIGDEST\nDNAT     net     loc:192.168.1.0/24         -      -      -      203.0.113.0/24\n# Maps 203.0.113.x → 192.168.1.x (host part preserved)\n\n# /etc/shorewall/masq — SNAT netmap (reverse direction):\n#INTERFACE  SOURCE           ADDRESS\neth0        192.168.1.0/24   203.0.113.0/24\n# Maps 192.168.1.x → 203.0.113.x (host part preserved)\n\n# Symmetric netmap — use BOTH to create bidirectional 1:1 NAT:\n# /etc/shorewall/masq:\neth0         192.168.1.0/24  203.0.113.0/24\n# /etc/shorewall/rules:\nDNAT         net     loc:192.168.1.0/24  -  -  -  203.0.113.0/24\n# Result: internal 192.168.1.x ↔ external 203.0.113.x in both directions\n\n# Useful for merging networks, VPN overlaps, provider migrations.",
    ),

    # ── Logging ──
    FeatureExample(
        name="log",
        category="Logging",
        description="Log matching packets to kernel log (dmesg/syslog).",
        nft_syntax="# /etc/shorewall/rules — append :loglevel to action:\n#ACTION        SOURCE  DEST  PROTO  DPORT\nDROP:info       net     all\nREJECT:$LOG     loc     net   tcp    25\nACCEPT:debug    adm     $FW   tcp    22\n\n# /etc/shorewall/shorewall.conf:\nLOGFORMAT=\"Shorewall:%s:%s:\"\nLOG=info",
    ),
    FeatureExample(
        name="counter",
        category="Logging",
        description="Count matching packets/bytes per zone pair and per rule. Query with CLI.",
        nft_syntax="# /etc/shorewall/shorewall.conf:\nACCOUNTING=Yes\n\n# /etc/shorewall/accounting:\n#ACTION   CHAIN    SOURCE  DEST   PROTO  DPORT\nCOUNT     -        net     $FW    tcp    22      # SSH attempts\nCOUNT     -        net     $FW    tcp    443     # HTTPS traffic\nCOUNT     -        loc     net    -      -       # all LAN→WAN\nCOUNT:web -        net     dmz    tcp    80,443  # named chain\nDONE      web                                    # end of chain\n\n# CLI:\nshorewall-nft counters              # show all counters\nshorewall-nft counters --netns fw   # in namespace\nshorewall-nft reset                  # reset counters",
    ),

    # ── Performance ──
    FeatureExample(
        name="flowtable",
        category="Performance",
        description="Hardware/software flow offloading. Bypasses nft for high-throughput established flows.",
        nft_syntax="# /etc/shorewall/static.nft:\nflowtable ft {\n    hook ingress priority 0;\n    devices = { eth0, eth1 };\n}\n\n# The forward chain automatically adds:\n# ct state established flow add @ft",
    ),

    # ── Advanced ──
    FeatureExample(
        name="macros",
        category="Advanced",
        description="Reusable rule templates. 149 built-in + custom macros in macros/ directory.",
        nft_syntax="# /etc/shorewall/rules — use macros with () or / syntax:\nSSH(ACCEPT)          loc     $FW\nDNS(ACCEPT)          all     net\nWeb(ACCEPT)          net     dmz\nPing/ACCEPT          all     $FW\nRfc1918/DROP:$LOG    net     all\n\n# Custom macro: /etc/shorewall/macros/macro.MyService\n?FORMAT 2\nPARAM  SOURCE  DEST  tcp  8080\nPARAM  SOURCE  DEST  tcp  8443\n\n# Meta-macro (calls other macros):\n# /etc/shorewall/macros/macro.WebStack\n?FORMAT 2\nWeb(PARAM)    SOURCE  DEST\nDNS(PARAM)    SOURCE  DEST\nPing(PARAM)   SOURCE  DEST\nPARAM         SOURCE  DEST  tcp  8080-8089  # custom app ports\n\n# Macro with port override — calling rule's port wins:\nSSH(ACCEPT)   loc  $FW  tcp  2222   # SSH on non-standard port\n\n# Macro with reverse entries (bidirectional):\n# /etc/shorewall/macros/macro.NTP\n?FORMAT 2\nPARAM  SOURCE  DEST  udp  123\nPARAM  DEST    SOURCE  udp  123   # reverse: allow responses",
    ),
    FeatureExample(
        name="actions",
        category="Advanced",
        description="Complex multi-rule action chains (Drop, Reject, Broadcast, TCPFlags, etc.).",
        nft_syntax="# /etc/shorewall/shorewall.conf:\nDROP_DEFAULT=Drop       # before DROP: filter broadcast/multicast\nREJECT_DEFAULT=Reject   # before REJECT: filter broadcast/multicast\n\n# /etc/shorewall/policy:\n#SOURCE  DEST  POLICY  LOGLEVEL  BURST\nnet      all   DROP    $LOG\nloc      all   REJECT  $LOG\ndmz      net   ACCEPT\n$FW      all   ACCEPT\n\n# Multi-zone with selective overrides:\nnet      dmz   DROP    info\nnet      loc   DROP    $LOG\nloc      dmz   ACCEPT\ndmz      loc   REJECT  $LOG\nall      all   REJECT  info   # catch-all\n\n# Policy with rate-limited logging:\nnet      all   DROP    info    10/sec",
    ),
    FeatureExample(
        name="exthdr",
        category="Advanced",
        description="Match IPv6 extension headers (hop-by-hop, routing, fragment, etc.).",
        nft_syntax="# /etc/shorewall/rules — column 13 (HEADERS):\n#ACTION  SRC  DST  PROTO  DPORT  SPORT  ORIG  RATE  USER  MARK  CONN  TIME  HEADERS\nDROP     net  $FW  -      -      -      -     -     -     -     -     -     frag\nACCEPT   net  $FW  -      -      -      -     -     -     -     -     -     hop",
    ),
    FeatureExample(
        name="meta_mark",
        category="Advanced",
        description="Packet marking for policy routing and traffic classification.",
        nft_syntax="# /etc/shorewall/tcrules:\n#MARK    SOURCE          DEST  PROTO  DPORT\n1        loc             net   tcp    80,443\n2        loc             net   udp    53\nDSCP(46) $FW             net   udp    5060    # VoIP → EF DSCP\n\n# Multi-ISP policy routing with marks:\n#MARK  SOURCE            DEST  PROTO  DPORT\n1      192.168.1.0/24    net   # → ISP1\n2      192.168.2.0/24    net   # → ISP2\n3      0.0.0.0/0         net   tcp    25     # SMTP → ISP3\n\n# /etc/shorewall/rules — match on marks:\n#ACTION  SRC  DST  PROTO  DPORT  SPORT  ORIG  RATE  USER  MARK\nACCEPT   net  $FW  tcp    22     -      -     -     -     0x1/0xff\nDROP     net  all  -      -      -      -     -     -     0x80/0x80",
    ),
    FeatureExample(
        name="user_match",
        category="Advanced",
        description="Match by user/group for OUTPUT rules (traffic from firewall itself).",
        nft_syntax="# /etc/shorewall/rules — column 9 (USER):\n#ACTION  SRC  DST  PROTO  DPORT  SPORT  ORIG  RATE  USER\nACCEPT   $FW  net  tcp    80     -      -     -     www-data\nDROP     $FW  net  tcp    -      -      -     -     nobody",
    ),
    FeatureExample(
        name="time_match",
        category="Advanced",
        description="Time-based rules — allow traffic only during specific hours.",
        nft_syntax="# /etc/shorewall/rules — column 12 (TIME):\n#ACTION  SRC  DST  PROTO  DPORT  ...  TIME\nACCEPT   loc  net  tcp    80     -    -  -  -  -  -  utc&timestart=08:00&timestop=17:00\nDROP     loc  net  tcp    80     # blocked outside work hours",
    ),

    # ── ICMPv6 / NDP ──
    FeatureExample(
        name="ndp",
        category="IPv6",
        description="Neighbor Discovery Protocol — essential for IPv6. Always allowed automatically.",
        nft_syntax="# Automatic: shorewall-nft inserts NDP rules in input/output chains.\n# No configuration needed. IPv6 will not work without NDP.\n# Allowed types: neighbor-solicit, neighbor-advert,\n#                router-solicit, router-advert",
    ),
    FeatureExample(
        name="icmp_translation",
        category="IPv6",
        description="Automatic ICMP type translation between IPv4 and IPv6.",
        nft_syntax="# /etc/shorewall/rules or /etc/shorewall6/rules:\nPing(ACCEPT)   all   $FW\n# shorewall-nft automatically translates:\n#   IPv4: icmp type 8 (echo-request)\n#   IPv6: icmpv6 type 128 (echo-request)",
    ),
    FeatureExample(
        name="dual_stack",
        category="IPv6",
        description="Merge Shorewall + Shorewall6 into one unified ruleset.",
        nft_syntax="# Auto-detect: place configs in sibling directories\n#   /etc/shorewall/     (IPv4 rules)\n#   /etc/shorewall6/    (IPv6 rules)\n# shorewall-nft auto-merges them.\n\n# Or merge manually:\nshorewall-nft merge-config /etc/shorewall /etc/shorewall6 -o /etc/shorewall-nft\n\n# IPv6 addresses use angle brackets:\n# /etc/shorewall6/rules:\nSSH(ACCEPT)   net:<2001:db8::/32>              $FW\nACCEPT        net:<2001:db8:1::/48>            dmz  tcp  443\nDROP:info      net:!<2001:db8::/32>             $FW  tcp  22\n\n# Extended mask — match only on host part (last 64 bits), ignoring prefix.\n# The mask ::ffff:ffff:ffff:ffff zeros out the top 64 bits during match.\nACCEPT        net:<::53:55:24/::ffff:ffff:ffff:ffff>     $FW  tcp  22\nACCEPT        net:<::192:168:20:1/::ffff:ffff:ffff:ffff> $FW  tcp  22\n# Compiles to: ip6 saddr & ::ffff:ffff:ffff:ffff == ::53:55:24\n\n# Dual-stack rules that apply to BOTH families go in /etc/shorewall/rules:\nPing(ACCEPT)  all    $FW       # → icmp type 8 + icmpv6 type 128\nDNS(ACCEPT)   loc    net       # works for both A and AAAA lookups",
    ),

    # ── Interface Options ──
    FeatureExample(
        name="interface_options",
        category="Interfaces",
        description="Per-interface security options applied automatically.",
        nft_syntax="# /etc/shorewall/interfaces:\n#ZONE  INTERFACE  BROADCAST  OPTIONS\nnet    eth0       detect     tcpflags,nosmurfs,routefilter,blacklist\nloc    eth1       detect     tcpflags,dhcp,routeback\ndmz    eth2       detect     tcpflags,nosmurfs\nvpn    wg0        -          routeback\n\n# Wildcard interfaces (any veth):\ndock   veth+      -          routeback,bridge\n\n# Multi-interface zone:\nloc    eth1       detect     tcpflags,dhcp,routeback\nloc    eth3       detect     tcpflags,routeback\n\n# tcpflags:    drop SYN+FIN, SYN+RST (TCP flag attacks)\n# nosmurfs:    drop broadcast source (smurf attacks)\n# routefilter: enable kernel rp_filter (anti-spoofing)\n# dhcp:        allow DHCP (UDP 67,68) automatically\n# routeback:   allow traffic to return to same zone\n# bridge:      bridge port zone\n# blacklist:   enable dynamic blacklist on this interface",
    ),

    # ── Dynamic Blacklist ──
    FeatureExample(
        name="dynamic_blacklist",
        category="Runtime",
        description="Add/remove addresses from the firewall at runtime without recompiling.",
        nft_syntax="# /etc/shorewall/shorewall.conf:\nDYNAMIC_BLACKLIST=Yes\n\n# CLI commands:\nshorewall-nft drop 1.2.3.4              # block immediately\nshorewall-nft blacklist 5.6.7.8 -t 1h   # block for 1 hour\nshorewall-nft reject 9.10.11.12         # reject with ICMP\nshorewall-nft allow 1.2.3.4             # unblock\n\n# Shorewall-compatible:\nshorewall-nft drop 1.2.3.4 5.6.7.8      # block multiple",
    ),

    # ── Lifecycle ──
    FeatureExample(
        name="lifecycle",
        category="Runtime",
        description="Full firewall lifecycle management — Shorewall-compatible commands.",
        nft_syntax="shorewall-nft start [/etc/shorewall]    # compile + apply\nshorewall-nft stop                      # remove all rules\nshorewall-nft restart                   # atomic replace\nshorewall-nft reload                    # same as restart\nshorewall-nft status                    # show if running\nshorewall-nft save [file]               # save current rules\nshorewall-nft restore <file>            # restore saved rules\nshorewall-nft clear                     # accept all traffic\nshorewall-nft check [dir]               # validate config\nshorewall-nft compile [dir] [-o file]   # compile to script",
    ),
    FeatureExample(
        name="netns",
        category="Runtime",
        description="Network namespace support — deploy firewall per namespace.",
        nft_syntax="# Apply to a network namespace:\nshorewall-nft start /etc/shorewall/fw --netns fw\nshorewall-nft status --netns fw\nshorewall-nft stop --netns fw\n\n# Generate systemd template:\nshorewall-nft generate-systemd --netns\n# Creates shorewall-nft@.service with:\n#   JoinsNamespaceOf=netns@%i.service",
    ),

    # ── Optimizer ──
    FeatureExample(
        name="optimize",
        category="Performance",
        description="Post-compile IR optimizer: removes redundant rules and shrinks the ruleset.",
        nft_syntax="# /etc/shorewall/shorewall.conf:\nOPTIMIZE=8   # all optimizations (0-8)\n\n# Levels:\n#  0  no optimization (default)\n#  1  routefilter: drop rules unreachable via rp_filter\n#  2  remove exact-duplicate rules within a chain\n#  3  drop ACCEPT-policy chains that have no user rules\n#  4  combine adjacent rules differing only in saddr/daddr/dport/sport\n#  8  merge chains with identical content (cross-chain dedup)\n\n# Real-world reduction on production configs:\n#   fw-large: 18366 → 12806 nft lines  (30% smaller)\n#   fw-medium:  12075 → 7598 nft lines  (37% smaller)\n#   fw-small:   625 → 546 nft lines   (12% smaller)\n\n# Level 4 example — before:\n#   ip daddr 192.53.103.108 udp dport 123 accept\n#   ip daddr 192.53.103.104 udp dport 123 accept\n# after:\n#   ip daddr { 192.53.103.108, 192.53.103.104 } udp dport 123 accept\n\n# Level 8 example — chain 'mgmt-alpha' merged into 'brs-alpha':\n# The mgmt-alpha chain becomes a single 'jump brs-alpha' because its\n# rules were identical to brs-alpha. Dispatch stays intact.",
    ),
]


def get_all_features() -> list[FeatureExample]:
    """Return all known feature examples."""
    return list(_FEATURES)


def get_features_with_availability(caps=None) -> list[FeatureExample]:
    """Return features with availability status from capability probe."""
    features = get_all_features()

    if caps is None:
        return features

    # Map capability attributes to feature names
    cap_map = {
        "ct_state": "has_ct_state",
        "ct_helper": "has_ct_helper",
        "ct_count": "has_ct_count",
        "fib": "has_fib",
        "socket": "has_socket",
        "osf": "has_osf",
        "limit": "has_limit",
        "quota": "has_quota",
        "counter": "has_counter",
        "log": "has_log",
        "notrack": "has_notrack",
        "named_sets": "has_interval_sets",
        "timeout_sets": "has_timeout_sets",
        "concat_sets": "has_concat_sets",
        "flowtable": "has_flowtable",
        "meta_nfproto": "has_meta_nfproto",
        "snat": "has_nat",
        "dnat": "has_nat",
        "masquerade": "has_nat",
    }

    for f in features:
        cap_attr = cap_map.get(f.name)
        if cap_attr and hasattr(caps, cap_attr):
            f.available = getattr(caps, cap_attr)

    # Add dynamically discovered features from kernel modules
    if hasattr(caps, "kernel_modules"):
        for mod in caps.kernel_modules:
            if mod not in [f.name for f in features]:
                features.append(FeatureExample(
                    name=mod,
                    category="Kernel Module",
                    description=f"nft_{mod} kernel module available.",
                    nft_syntax=f"# Module nft_{mod} is loaded/available",
                    available=True,
                ))

    return features


def format_features(features: list[FeatureExample], *,
                    show_unavailable: bool = True,
                    category: str | None = None) -> str:
    """Format feature list for display."""
    lines: list[str] = []

    if category:
        features = [f for f in features if f.category.lower() == category.lower()]

    # Group by category
    categories: dict[str, list[FeatureExample]] = {}
    for f in features:
        categories.setdefault(f.category, []).append(f)

    for cat, feats in categories.items():
        lines.append(f"\n{'='*60}")
        lines.append(f"  {cat}")
        lines.append(f"{'='*60}")

        for f in feats:
            if not show_unavailable and not f.available:
                continue

            status = "[OK]" if f.available else "[N/A]"
            lines.append(f"\n  {status} {f.name}")
            lines.append(f"  {'-'*40}")
            lines.append(f"  {f.description}")

            if f.nft_syntax:
                lines.append("\n  nft syntax:")
                for sl in f.nft_syntax.splitlines():
                    lines.append(f"    {sl}")

            if f.shorewall_equivalent:
                lines.append("\n  Shorewall equivalent:")
                lines.append(f"    {f.shorewall_equivalent}")

    return "\n".join(lines)
