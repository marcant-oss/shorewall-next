# Routing vs. Firewalling.

One of the most misunderstood aspects of Shorewall is its relationship with routing. This article attempts to clear some of the fog that surrounds this issue.

As a general principle:

1.  Routing determines where packets are to be sent.

2.  Once routing determines where the packet is to go, the firewall (Shorewall) determines if the packet is allowed to go there.

There are ways that Shorewall can affect routing which are described in the following sections.

# Routing and Netfilter

The following diagram shows the relationship between routing decisions and Netfilter.

The light blue boxes indicate where routing decisions are made. Upon exit from one of these boxes, if the packet is being sent to another system then the interface and the next hop have been uniquely determined.

The green boxes show where Netfilter processing takes place (as directed by Shorewall). You will notice that there are two different paths through this maze, depending on where the packet originates. We will look at each of these separately.

## Packets Entering the Firewall from Outside

When a packet arrives from outside, it first undergoes Netfilter PREROUTING processing. In Shorewall terms:

1.  Packets may be marked using entries in the [/etc/shorewall/mangle](https://shorewall.org/manpages/shorewall-mangle.html) ([/etc/shorewall/tcrules](https://shorewall.org/manpages/shorewall-tcrules.html)) file. Entries in that file containing ":P" in the mark column are applied here as are rules that default to the MARK_IN_FORWARD_CHAIN=No setting in `/etc/shorewall/shorewall.conf`. These marks may be used to specify that the packet should be routed using an alternate routing table; see the [Shorewall Squid documentation](Shorewall_Squid_Usage.md) for examples.

    <div class="caution">

    Marking packets then using the *fwmark* selector in your "**ip rule add**" commands should NOT be your first choice. In most cases, you can use the *from* or *dev* selector instead.

    </div>

2.  The destination IP address may be rewritten as a consequence of:

    - DNAT\[-\] rules.

    - REDIRECT\[-\] rules.

    - Entries in `/etc/shorewall/nat`.

So the only influence that Shorewall has over where these packets go is via NAT or by marking them so that they may be routed using an alternate routing table.

## Packets Originating on the Firewall

Processing of packets that originate on the firewall itself are initially routed using the default routing table then passed through the OUTPUT chains. Shorewall can influence what happens here:

1.  Packets may be marked using entries in the [/etc/shorewall/mangle](https://shorewall.org/manpages/shorewall-tcrules.html) ([/etc/shorewall/tcrules](https://shorewall.org/manpages/shorewall-tcrules.html)) file (rules with "\$FW" in the SOURCE column). These marks may be used to specify that the packet should be re-routed using an alternate routing table.

2.  The destination IP address may be rewritten as a consequence of:

    - DNAT\[-\] rules that specify \$FW as the SOURCE.

    - Entries in `/etc/shorewall/nat` that have "Yes" in LOCAL column.

So again in this case, the only influence that Shorewall has over the packet destination is NAT or marking.

# Alternate Routing Table Configuration

The Shorewall 2.x [Shorewall Squid documentation](https://shorewall.org/2.0/Shorewall_Squid_Usage.html#Local) shows how alternate routing tables can be created and used. That documentation shows how you can use logic in `/etc/shorewall/init` to create and populate an alternate table and to add a routing rule for its use. It is fine to use that technique so long as you understand that you are basically just using the Shorewall init script (`/etc/init.d/shorewall`) to configure your alternate routing table at boot time and that **other than as described in the previous section, there is no connection between Shorewall and routing when using Shorewall versions prior to 2.3.2.**

# Routing and Proxy ARP

There is one instance where Shorewall creates main routing table entries. When an entry in `/etc/shorewall/proxyarp` contains "No" in the HAVEROUTE column then Shorewall will create a host route to the IP address listed in the ADDRESS column through the interface named in the INTERFACE column. **This is the only case where Shorewall directly manipulates the main routing table**.

Example:

`/etc/shorewall/proxyarp`:

    #ADDRESS        INTERFACE       EXTERNAL        HAVEROUTE       PERSISTENT
    206.124.146.177 eth1            eth0            No

The above entry will cause Shorewall to execute the following command:

    ip route add 206.124.146.177 dev eth1

# Multiple Internet Connection Support in Shorewall 2.4.2 and Later

Beginning with Shorewall 2.3.2, support is included for multiple Internet connections. If you wish to use this feature, we recommend strongly that you upgrade to version 2.4.2 or later.

Shorewall multi-ISP support is now covered in a [separate article](MultiISP.md).
