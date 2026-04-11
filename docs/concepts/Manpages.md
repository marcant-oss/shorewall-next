<div class="warning">

These manpages are for Shorewall 5.0 and later only. They describe features and options not available on earlier releases. The manpages for Shorewall 4.4-4.6 are available [here](Manpages.md).

</div>

# Section 5 — Files and Concepts

> accounting
>
> \- Define IP accounting rules.
>
> actions
>
> \- Declare user-defined actions.
>
> addresses
>
> \- Describes how IP address and ports are specified in Shorewall
>
> arprules
>
> \- (Added in Shorewall 4.5.12) Define arpfilter rules.
>
> blrules
>
> \- shorewall Blacklist file.
>
> conntrack
>
> \- Specify helpers for connections or exempt certain traffic from netfilter connection tracking.
>
> ecn
>
> \- Disabling Explicit Congestion Notification
>
> exclusion
>
> \- Excluding hosts from a network or zone
>
> files
>
> \- Describes the shorewall configuration files
>
> hosts
>
> \- Define multiple zones accessed through a single interface
>
> interfaces
>
> \- Define the interfaces on the system and optionally associate them with zones.
>
> ipsets
>
> \- Describes how to specify set names in Shorewall configuration files.
>
> logging
>
> \- Provides an overview of Shorewall packet logging facilities
>
> maclist
>
> \- Define MAC verification.
>
> mangle
>
> \- Supersedes tcrules and describes packet/connection marking.
>
> masq
>
> \- Define Masquerade/SNAT (deprecated)
>
> modules
>
> \- Specify which kernel modules to load (Removed in Shorewall 5.2.3)
>
> names
>
> \- Describes object naming in Shorewall configuration files
>
> nat
>
> \- Define one-to-one NAT.
>
> nesting
>
> \- How to define nested zones.
>
> netmap
>
> \- How to map addresses from one net to another.
>
> params
>
> \- Assign values to shell variables used in other files.
>
> policy
>
> \- Define high-level policies for connections between zones.
>
> providers
>
> \- Define routing tables, usually for multiple Internet links.
>
> proxyarp
>
> \- Define Proxy ARP (IPv4)
>
> proxyndp
>
> \- Define Proxy NDP (IPv6)
>
> rtrules
>
> \- Define routing rules.
>
> routes
>
> \- (Added in Shorewall 4.4.15) Add additional routes to provider routing tables.
>
> rules
>
> \- Specify exceptions to policies, including DNAT and REDIRECT.
>
> secmarks
>
> \- Attach an SELinux context to a packet.
>
> snat
>
> \- Define Masquerade/SNAT
>
> tcclasses
>
> \- Define htb classes for traffic shaping.
>
> tcdevices
>
> \- Specify speed of devices for traffic shaping.
>
> tcfilters
>
> \- Classify traffic for shaping; often used with an IFB to shape ingress traffic.
>
> tcinterfaces
>
> \- Specify devices for simplified traffic shaping.
>
> tcpri
>
> \- Classify traffic for simplified traffic shaping.
>
> tunnels
>
> \- Define VPN connections with endpoints on the firewall.
>
> shorewall.conf
>
> \- Specify values for global Shorewall options.
>
> shorewall6.conf
>
> \- Specify values for global Shorewall6 options.
>
> shorewall-lite.conf
>
> \- Specify values for global Shorewall Lite options.
>
> shorewall6-lite.conf
>
> \- Specify values for global Shorewall6 Lite options.
>
> vardir
>
> \- Redefine the directory where Shorewall keeps its state information.
>
> vardir-lite
>
> \- Redefine the directory where Shorewall Lite keeps its state information.
>
> zones
>
> \- Declare Shorewall zones.

# Section 8 — Administrative Commands

> shorewall
>
> \- /sbin/shorewall, /sbin/shorewall6/, /sbin/shorewall-lite and /sbin/shorewall6-lite command syntax and semantics.
