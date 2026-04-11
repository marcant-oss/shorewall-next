# Why use Network Mapping

Network Mapping is most often used to resolve IP address conflicts. Suppose that two organizations, A and B, need to be linked and that both organizations have allocated the 192.168.1.0/24 subnetwork. There is a need to connect the two networks so that all systems in A can access the 192.168.1.0/24 network in B and vice versa without any re-addressing.

# Solution

Shorewall NETMAP support is designed to supply a solution. The basic situation is as shown in the following diagram.

While the link between the two firewalls is shown here as a VPN, it could be any type of interconnection that allows routing of [RFC 1918](../reference/shorewall_setup_guide.md#RFC1918) traffic.

The systems in the top cloud will access the 192.168.1.0/24 subnet in the lower cloud using addresses in another unused /24. Similarly, the systems in the bottom cloud will access the 192.168.1.0/24 subnet in the upper cloud using a second unused /24.

In order to apply this solution:

- You must be running Shorewall 2.0.1 Beta 2 or later.

- Your kernel must have NETMAP support. 2.6 Kernels have NETMAP support without patching while 2.4 kernels must be patched using Patch-O-Matic from [netfilter.org](http://www.netfilter.org).

- NETMAP support must be enabled in your kernel (CONFIG_IP_NF_TARGET_NETMAP=m or CONFIG_IP_NF_TARGET_NETMAP=y).

- Your iptables must have NETMAP support. NETMAP support is available in iptables 1.2.9 and later.

Network mapping is defined using the `/etc/shorewall/netmap` file. Columns in this file are:

TYPE  
Must be DNAT or SNAT.

If DNAT, traffic entering INTERFACE and addressed to NET1 has its destination address rewritten to the corresponding address in NET2.

If SNAT, traffic leaving INTERFACE with a source address in NET1 has its source address rewritten to the corresponding address in NET2.

NET1  
Must be expressed in CIDR format (e.g., 192.168.1.0/24). Beginning with Shorewall 4.4.24, [exclusion](https://shorewall.org/manpages/shorewall-exclusion.html) is supported.

INTERFACE  
A firewall interface. This interface must have been defined in [`/etc/shorewall/interfaces`](https://shorewall.org/manpages/shorewall-interfaces.html).

NET2  
A second network expressed in CIDR format.

**NET3 (Optional)** - *network-address*  
Added in Shorewall 4.4.11. If specified, qualifies INTERFACE. It specifies a SOURCE network for DNAT rules and a DESTINATON network for SNAT rules.

**PROTO (Optional - Added in Shorewall 4.4.23.2)** - *protocol-number-or-name*  
Only packets specifying this protocol will have their IP header modified.

**DPORT (Optional - Added in Shorewall 4.4.23.2)** - *port-number-or-name-list*  
Destination Ports. A comma-separated list of Port names (from services(5)), *port number*s or *port range*s; if the protocol is **icmp**, this column is interpreted as the destination icmp-type(s). ICMP types may be specified as a numeric type, a numberic type and code separated by a slash (e.g., 3/4), or a typename. See <https://shorewall.org/configuration_file_basics.htm#ICMP>.

If the protocol is **ipp2p**, this column is interpreted as an ipp2p option without the leading "--" (example **bit** for bit-torrent). If no PORT is given, **ipp2p** is assumed.

An entry in this field requires that the PROTO column specify icmp (1), tcp (6), udp (17), sctp (132) or udplite (136). Use '-' if any of the following field is supplied.

**SPORT (Optional - Added in Shorewall 4.4.23.2)** - *port-number-or-name-list*  
Source port(s). If omitted, any source port is acceptable. Specified as a comma-separated list of port names, port numbers or port ranges.

An entry in this field requires that the PROTO column specify tcp (6), udp (17), sctp (132) or udplite (136). Use '-' if any of the following fields is supplied.

Referring to the figure above, lets suppose that systems in the top cloud are going to access the 192.168.1.0/24 network in the bottom cloud using addresses in 10.10.10.0/24 and that systems in the bottom could will access 192.168.1.0/24 in the top could using addresses in 10.10.11.0.

<div class="important">

You must arrange for routing as follows:

- Traffic from the top cloud to 10.10.10.0/24 must be routed to eth0 on firewall 1.

- Firewall 1 must route traffic to 10.10.10.0/24 through firewall 2.

- Traffic from the bottom cloud to 10.10.11.0/24 must be routed to eth0 on firewall 2.

- Firewall 2 must route traffic to 10.10.11.0/24 through firewall 1.

</div>

## If you are running Shorewall 4.4.22 or Earlier

The entries in `/etc/shorewall/netmap` in firewall1 would be as follows:

    #TYPE NET1           INTERFACE        NET2
    SNAT  192.168.1.0/24 vpn              10.10.11.0/24        #RULE 1A
    DNAT  10.10.11.0/24  vpn              192.168.1.0/24       #RULE 1B

The entry in `/etc/shorewall/netmap` in firewall2 would be:

    #TYPE NET1           INTERFACE        NET2
    DNAT  10.10.10.0/24  vpn              192.168.1.0/24       #RULE 2A
    SNAT  192.168.1.0/24 vpn              10.10.10.0/24        #RULE 2B

In order to make this connection, the client attempts a connection to 10.10.10.27. The following table shows how the source and destination IP addresses are modified as requests are sent and replies are returned. The RULE column refers to the above `/etc/shorewall/netmap` entries and gives the rule which transforms the source and destination IP addresses to those shown on the next line.

| FROM                            | TO                          | SOURCE IP ADDRESS | DESTINATION IP ADDRESS | RULE |
|---------------------------------|-----------------------------|-------------------|------------------------|------|
| 192.168.1.4 in upper cloud      | Firewall 1                  | 192.168.1.4       | 10.10.10.27            | 1A   |
| Firewall 1                      | Firewall 2                  | 10.10.11.4        | 10.10.10.27            | 2A   |
| Firewall 2                      | 192.168.1.27 in lower cloud | 10.10.11.4        | 192.168.1.27           |      |
| 192.168.1.27 in the lower cloud | Firewall 2                  | 192.168.1.27      | 10.10.11.4             | 2B   |
| Firewall 2                      | Firewall 1                  | 10.10.10.27       | 10.10.11.4             | 1B   |
| Firewall 1                      | 192.168.1.4 in upper cloud  | 10.10.10.27       | 192.168.1.4            |      |

See the [OpenVPN documentation](OPENVPN.md) for a solution contributed by Nicola Moretti for resolving duplicate networks in a roadwarrior VPN environment.

## If you are running Shorewall 4.4.23 or Later

Beginning with Shorewall 4.4.23, you *can* bridge two duplicate networks with one router, provided that your kernel and iptables include *Rawpost Table Support*. That support is used to implement Stateless NAT which allows for performing DNAT in the rawpost table POSTROUTING and OUTPUT chains and for performing SNAT in the raw table PREROUTING chain. Using this support, only firewall1 requires `/etc/shorewall/netmap`. Two additional entries are added.

    #TYPE NET1            INTERFACE        NET2
    SNAT   192.168.1.0/24 vpn              10.10.11.0/24
    DNAT   10.10.11.0/24  vpn              192.168.1.0/24
    SNAT:P 192.168.1.0/24 vpn              10.10.10.0/24
    DNAT:T 10.10.10.0/24  vpn              192.168.1.0/24

The last two entries define Stateless NAT by specifying a chain designator (:P for PREROUTING and :T for POSTROUTING respectively). See [shorewall-netmap](https://shorewall.org/manpages/shorewall-netmap.html) (5) for details.

# IPv6

Beginning with Shorewall6 4.4.24, IPv6 support for Netmap is included. This provides a way to use private IPv6 addresses internally and still have access to the IPv6 internet.

<div class="warning">

IPv6 netmap is stateless which means that there are no Netfilter helpers for applications that need them. As a consequence, applications that require a helper (FTP, IRC, etc.) may experience issues.

</div>

For IPv6, the chain designator (:P for PREROUTING or :T for POSTROUTING) is required in the TYPE column. Normally SNAT rules are placed in the POSTROUTING chain while DNAT rules are placed in PREROUTING.

To use IPv6 Netmap, your kernel and iptables must include *Rawpost Table Support*.

IPv6 Netmap has been verified at shorewall.net using the configuration shown below.

IPv6 support is supplied from Hurricane Electric; the IPv6 address block is 2001:470:b:227::/64.

Because of the limitations of IPv6 NETMAP (no Netfilter helpers), the servers in the DMZ have public addresses in the block 2001:470:b:227::/112. The local LAN uses the private network fd00:470:b:227::/64 with the hosts autoconfigured using radvd. This block is allocated from the range (fc00::/7) reserved for [Unique Local Addresses](http://en.wikipedia.org/wiki/Unique_local_address).

The /etc/shorewall6/netmap file is as follows:

    #TYPE   NET1            INTERFACE   NET2        NET3        PROTO   DEST    SOURCE
    #                                               PORT(S) PORT(S)
    SNAT:T  fd00:470:b:227::/64 HE_IF       2001:470:b:227::/64
    DNAT:P  2001:470:b:227::/64!2001:470:b:227::/112\
                    HE_IF       fd00:470:b:227::/64

HE_IF is the logical name for interface sit1. On output, the private address block is mapped to the public block. Because autoconfiguration is used, none of the local addresses falls into the range fd00:470:b:227::/112. That range can therefore be excluded from DNAT.

<div class="note">

While the site local network that was used is very similar to the public network (only the first word is different), that isn't a requirement. We could have just as well used fd00:bad:dead:beef::/64

</div>

<div class="note">

The MacBook Pro running OS X Lion refused to autoconfigure when radvd advertised a [site-local](http://tools.ietf.org/html/rfc3513) network (fec0:470:b:227/64) but worked fine with the unique-local network (fd00:470:b:227::/64). Note that site-local addresses were deprecated in [RFC3879](http://tools.ietf.org/html/rfc3879).

</div>

<div class="note">

This whole scheme isn't quite as useful as it might appear. Many IPv6-enabled applications (web browsers, for example) are smart enough to recognize unique local addresses and will only use IPv6 to communicate with other such local addresses.

</div>
