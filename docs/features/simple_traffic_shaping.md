# Introduction

Traffic shaping and control was originally introduced into Shorewall in version 2.2.5. That facility was based on Arne Bernin's tc4shorewall and is generally felt to be complex and difficult to use.

In Shorewall 4.4.6, a second traffic shaping facility that is simple to understand and to configure was introduced. This newer facility is described in this document while the original facility is documented in [Complex Traffic Shaping/Control](traffic_shaping.md).

In the absense of any traffic shaping, interfaces are configured automatically with the pfifo_fast queuing discipline (qdisc). From tc-pfifo_fast (8):

> The algorithm is very similar to that of the classful tc-prio(8) qdisc. pfifo_fast is like three tc-pfifo(8) queues side by side, where packets can be enqueued in any of the three bands based on their Type of Service bits or assigned priority.
>
> Not all three bands are dequeued simultaneously - as long as lower bands have traffic, higher bands are never dequeued. This can be used to prioritize interactive traffic or penalize ’lowest cost’ traffic.
>
> Each band can be txqueuelen packets long, as configured with ifconfig(8) or ip(8). Additional packets coming in are not enqueued but are instead dropped.
>
> See tc-prio(8) for complete details on how TOS bits are translated into bands.

In other words, if all you want is strict priority queuing, then do nothing.

Shorewall's Simple Traffic Shaping configures the prio qdisc(rx-prio(8)) on the designated interface then adds a Stochastic Fair Queuing sfq (tc-sfq (8)) qdisc to each of the classes that are implicitly created for the prio qdisc. The sfq qdisc ensures fairness among packets queued in each of the classes such that each flow (session) gets its turn to send packets. The definition of flows can be altered to include all traffic being sent *by* a given IP address (normally defined for an external interface) or all traffic being sent *to* a given IP address (internal interface).

Finally, Simple Traffic Shaping allows you to set a limit on the total bandwidth allowed out of an interface. It does this by inserting a Token Bucket Filter (tbf) qdisc ahead of the prio qdisc. Note that this can have the effect of defeating the priority queuing provided by the prio qdisc but seems to provide a benefit when the actual link output temporarily drops below the limit imposed by tbf or when tbf allows a burst of traffic to be released.

<div class="caution">

IPSec traffic passes through traffic shaping twice - once en clair and once encrypted and encapsulated. As a result, throughput may be significantly less than configured if IPSEC packets form a significant percentage of the traffic being shaped.

</div>

# Enabling Simple Traffic Shaping

Simple traffic shaping is enabled by setting TC_ENABLED=Simple in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5). You then add an entry for your external interface to [shorewall-tcinterfaces](https://shorewall.org/manpages/shorewall-tcinterfaces.html)(5) (`/etc/shorewall/tcinterfaces`).

Assuming that your external interface is eth0:

    #INTERFACE             TYPE          IN-BANDWIDTH        OUT-BANDWIDTH
    eth0                   External

<div class="note">

If you experience an error such as the following during `shorewall start` or `shorewall restart`, your kernel and iproute do not support the **flow** classifier. In that case, you must leave the TYPE column empty (or specify '-').

    Unknown filter "flow", hence option "hash" is unparsable
       ERROR: Command "tc filter add dev eth0 protocol all prio 1 parent 11: handle 11 flow hash keys nfct-src divisor 1024" Failed

RHEL5-based systems such as CentOS 5 and Foobar 5 are known to experience this error.

**Update**: Beginning with Shorewall 4.4.7, Shorewall can determine that some environments, such as RHEL5 and derivatives, are incapable of using the TYPE parameter and simply ignore it.

</div>

With this simple configuration, packets to be sent through interface eth0 will be assigned to a priority band based on the value of their TOS field:

    TOS     Bits  Means                    Linux Priority    BAND
    ------------------------------------------------------------
    0x0     0     Normal Service           0 Best Effort     2
    0x2     1     Minimize Monetary Cost   1 Filler          3
    0x4     2     Maximize Reliability     0 Best Effort     2
    0x6     3     mmc+mr                   0 Best Effort     2
    0x8     4     Maximize Throughput      2 Bulk            3
    0xa     5     mmc+mt                   2 Bulk            3
    0xc     6     mr+mt                    2 Bulk            3
    0xe     7     mmc+mr+mt                2 Bulk            3
    0x10    8     Minimize Delay           6 Interactive     1
    0x12    9     mmc+md                   6 Interactive     1
    0x14    10    mr+md                    6 Interactive     1
    0x16    11    mmc+mr+md                6 Interactive     1
    0x18    12    mt+md                    4 Int. Bulk       2
    0x1a    13    mmc+mt+md                4 Int. Bulk       2
    0x1c    14    mr+mt+md                 4 Int. Bulk       2
    0x1e    15    mmc+mr+mt+md             4 Int. Bulk       2

When dequeueing, band 1 is tried first and only if it did not deliver a packet does the system try band 2, and so onwards. Maximum reliability packets should therefore go to band 1, minimum delay to band 2 and the rest to band 3.

<div class="note">

If you run both an IPv4 and an IPv6 firewall on your system, you should define each interface in only one of the two configurations.

</div>

# Customizing Simple Traffic Shaping

The default mapping of TOS to bands can be changed using the TC_PRIOMAP setting in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5). The default setting of this option is:

    TC_PRIOMAP="2 3 3 3 2 3 1 1 2 2 2 2 2 2 2 2"

These entries map Linux Priority to priority BAND. So only entries 0, 1, 2, 4 and 6 in the map are relevant to TOS-\>BAND mapping.

Further customizations can be defined in [shorewall-tcpri](https://shorewall.org/manpages/shorewall-tcpri.html)(5) (`/etc/shorewall/tcpri`). Using that file, you can:

1.  Assign traffic entering the firewall on a particular interface to a specific priority band:

        ?FORMAT 2
        #BAND         PROTO         DPORT    SPORT     ADDRESS             INTERFACE        HELPER
        2               -             -        -          -                eth1

    In this example, traffic from eth1 will be assigned to priority band 2.

    <div class="note">

    When an INTERFACE is specified, the PROTO, DPORT and ADDRESS column must contain '-'.

    </div>

2.  Assign traffic from a particular IP address to a specific priority band:

        ?FORMAT 2
        #BAND         PROTO         DPORT    SPORT     ADDRESS             INTERFACE        HELPER

        1               -             -        -       192.168.1.44

    In this example, traffic from 192.168.1.44 will be assigned to priority band 1.

    <div class="note">

    When an ADDRESS is specified, the PROTO, DPORT, SPORT and INTERFACE columns must be empty.

    </div>

3.  Assign traffic to/from a particular application to a specific priority band:

        #BAND         PROTO         PORT            ADDRESS             INTERFACE        HELPER
        1             udp           1194

    In that example, SSH traffic is assigned to priority band 1. In file format 2, the above would be as follows:

        #BAND         PROTO         DPORT       SPORT     ADDRESS             INTERFACE        HELPER
        1             tcp           22
        1             tcp             -         22

    In other words, in file format 1, the compiler generates rules for traffic from client to server and from server to client. In format 2, separate tcpri rules are required.

4.  Assign traffic that uses a particular Netfilter helper to a particular priority band:

        #BAND         PROTO         DPORT           ADDRESS             INTERFACE        HELPER
        1               -             -             -                   -                sip

    In this example, SIP and associated RTP traffic will be assigned to priority band 1 (assuming that the nf_conntrack_sip helper is loaded).

It is suggested that entries specifying an INTERFACE be placed at the top of the file. That way, the band assigned to a particular packet will be the **last** entry matched by the packet. Packets which match no entry in [shorewall-tcpri](https://shorewall.org/manpages/shorewall-tcpri.html)(5) are assigned to priority bands using their TOS field as previously described.

One cause of high latency on interactive traffic can be that queues are building up at your ISP's gateway router. If you suspect that is happening in your case, you can try to eliminate the problem by using the IN-BANDWIDTH setting in [shorewall-tcinterfaces](https://shorewall.org/manpages/shorewall-tcinterfaces.html)(5). The contents of the column are a \<rate\>. For defining the rate, use **kbit** or **kbps** (for Kilobytes per second) and make sure there is NO space between the number and the unit (it is 100kbit not 100 kbit). **mbit**, **mbps** or a raw number (which means bytes) can be used, but note that before Shorewall 4.4.13 only integer numbers were supported (0.5 was not valid). To pick an appropriate setting, we recommend that you start by setting IN-BANDWIDTH significantly below your measured download bandwidth (20% or so). While downloading, measure the ping response time from the firewall to the upstream router as you gradually increase the setting. The optimal setting is at the point beyond which the ping time increases sharply as you increase the setting.

Simple Traffic Shaping is only appropriate on interfaces where output queuing occurs. As a consequence, you usually only use it on external interfaces. There are cases where you may need to use it on an internal interface (a VPN interface, for example). If so, just add an entry to [shorewall-tcinterfaces](https://shorewall.org/manpages/shorewall-tcinterfaces.html)(5):

    #INTERFACE             TYPE          IN-BANDWIDTH
    tun0                   Internal

For fast lines, the actual download rate may be significantly less than the specified IN-BANDWIDTH. Beginning with Shoreall 4.4.13, you can specify an optional burst

Also beginning with Shorewall 4.4.13, an OUT-BANDWIDTH column is available in [shorewall-tcpri](https://shorewall.org/manpages/shorewall-tcpri.html)(5). Limiting to outgoing bandwidth can have a positive effect on latency for applications like VOIP. We recommend that you begin with a setting that is at least 20% less than your measured upload rate and then gradually increase it until latency becomes unacceptable. Then reduce it back to the point where latency is acceptable.

# Combined IPv4/IPv6 Simple TC Configuration

Beginning with Shorewall 4.4.19, a combined configuration is possible. To do that:

- Set TC_ENABLED=Simple in both `/etc/shorewall/shorewall.conf` and `/etc/shorewall6/shorewall6.conf`.

- Configure your interface(s) in `/etc/shorewall/tcinterfaces`.

- Add entries to `/etc/shorewall/tcpri` and `/etc/shorewall6/tcpri` as desired. Entries in the former classify IPv4 traffic and entries in the latter classify IPv6 traffic.

Example:

`/etc/shorewall/tcinterfaces`

    #INTERFACE    TYPE        IN_BANDWIDTH            OUT_BANDWIDTH
    eth0        External    50mbit:200kb            6.0mbit:100kb:200ms:100mbit:1516   

etc/shorewall/tcpri:

    #BAND   PROTO       DPORT       ADDRESS     INTERFACE   HELPER
    COMMENT  All DMZ traffic in band 3 by default
    3   -       -       70.90.191.124/31
    COMMENT Bit Torrent is in band 3
    3   ipp2p:all   bit
    COMMENT But give a boost to DNS queries
    2   udp     53
    COMMENT And place echo requests in band 1 to avoid false line-down reports
    1   icmp            8

etc/shorewall6/tcpri:

    #BAND   PROTO       DPORT       ADDRESS     INTERFACE   HELPER
    COMMENT  All DMZ traffic in band 3 by default
    3   -       -       2001:470:b:227::40/124
    COMMENT But give a boost to DNS queries
    2   udp     53
    COMMENT And place echo requests in band 1 to avoid false line-down reports
    1   icmp            8

# Additional Reading

The PRIO(8) (tc-prio) manpage has additional information on the facility that Shorewall Simple Traffic Shaping is based on.

<div class="caution">

Please note that Shorewall numbers the bands 1-3 whereas PRIO(8) refers to them as bands 0-2.

</div>

If you encounter performance problems after enabling simple traffic shaping, check out [FAQ 97](../reference/FAQ.md#faq97) and [FAQ97a](../reference/FAQ.md#faq97a)
