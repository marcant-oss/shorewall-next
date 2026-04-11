# Overview

Proxy ARP (RFC 1027) is a way to make a machine physically located on one network appear to be logically part of a different physical network connected to the same router/firewall. Typically it allows us to hide a machine with a public IP address on a private network behind a router, and still have the machine appear to be on the public network "in front of" the router. The router "proxys" ARP requests and all network traffic to and from the hidden machine to make this fiction possible.

Consider a router with two interface cards, one connected to a public network PUBNET and one connected to a private network PRIVNET. We want to hide a server machine on the PRIVNET network but have it accessible from the PUBNET network. The IP address of the server machine lies in the PUBNET network, even though we are placing the machine on the PRIVNET network behind the router.

By enabling proxy ARP on the router, any machine on the PUBNET network that issues an ARP "who has" request for the server's MAC address will get a proxy ARP reply from the router containing the router's MAC address. This tells machines on the PUBNET network that they should be sending packets destined for the server via the router. The router forwards the packets from the machines on the PUBNET network to the server on the PRIVNET network.

Similarly, when the server on the PRIVNET network issues a "who has" request for any machines on the PUBNET network, the router provides its own MAC address via proxy ARP. This tells the server to send packets for machines on the PUBNET network via the router. The router forwards the packets from the server on the PRIVNET network to the machines on the PUBNET network.

The proxy ARP provided by the router allows the server on the PRIVNETnetwork to appear to be on the PUBNET network. It lets the router pass ARP requests and other network packets in both directions between the server machine and the PUBNET network, making the server machine appear to be connected to the PUBNET network even though it is on the PRIVNET network hidden behind the router.

Before you try to use this technique, I strongly recommend that you read the [Shorewall Setup Guide](../reference/shorewall_setup_guide.md).

# Example

The following figure represents a Proxy ARP environment.

Proxy ARP can be used to make the systems with addresses 130.252.100.18 and 130.252.100.19 appear to be on the upper (130.252.100.\*) subnet. Assuming that the upper firewall interface is eth0 and the lower interface is eth1, this is accomplished using the following entries in `/etc/shorewall/proxyarp`:

    #ADDRESS          INTERFACE   EXTERNAL  HAVEROUTE  PERSISTENT
    130.252.100.18    eth1        eth0      no         yes
    130.252.100.19    eth1        eth0      no         yes  

**Be sure that the internal systems (130.242.100.18 and 130.252.100.19 in the above example) are not included in any specification in `/etc/shorewall/masq` (/etc/shorewall/snat on Shorewall 5.0.14 or later) or `/etc/shorewall/nat`.**

<div class="note">

I've used an RFC1918 IP address for eth1 - that IP address is largely irrelevant (see below).

</div>

The lower systems (130.252.100.18 and 130.252.100.19) **should have their subnet mask and default gateway configured exactly the same way that the Firewall system's eth0 is configured. In other words, they should be configured just like they would be if they were parallel to the firewall rather than behind it.**

<div class="warning">

Do not add the Proxy ARP'ed address(es) (130.252.100.18 and 130.252.100.19 in the above example) to the external interface (eth0 in this example) of the firewall.

</div>

<div class="note">

It should be stressed that entries in the proxyarp file do not automatically enable traffic between the external network and the internal host(s) — such traffic is still subject to your policies and rules.

</div>

While the address given to the firewall interface is largely irrelevant, one approach you can take is to make that address the same as the address of your external interface!

In the diagram above, `eth1` has been given the address 130.252.100.17, the same as `eth0`. Note though that the VLSM is 32 so there is no network associated with this address. This is the approach [that I take with my DMZ](../legacy/XenMyWay.md).

To permit Internet hosts to connect to the local systems, you use ACCEPT rules. For example, if you run a web server on 130.252.100.19 which you have configured to be in the **loc** zone then you would need this entry in /etc/shorewall/rules:

    #ACTION SOURCE          DEST                    PROTO   DPORT
    ACCEPT  net             loc:130.252.100.19      tcp     80

<div class="warning">

Your distribution's network configuration GUI may not be capable of configuring a device in this way. It may complain about the duplicate address or it may configure the address incorrectly. Here is what the above configuration should look like when viewed using `ip` (the line "inet 130.252.100.17/32 scope global eth1" is the most important):

    gateway:~# ip addr ls eth1
    3: eth1: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast qlen 1000
        link/ether 00:a0:cc:d1:db:12 brd ff:ff:ff:ff:ff:ff
        inet 130.252.100.17/32 scope global eth1
    gateway:~#

Note in particular that there is no broadcast address. Here is an `ifcfg-eth-id-00:a0:cc:d1:db:12` file from SUSE that produces this result (Note: SUSE ties the configuration file to the card by embedding the card's MAC address in the file name):

    BOOTPROTO='static'
    BROADCAST='130.252.100.17'
    IPADDR='130.252.100.17'
    MTU=''
    NETMASK='255.255.255.255'
    NETWORK='130.252.100.17'
    REMOTE_IPADDR=''
    STARTMODE='onboot'
    UNIQUE='8otl.IPwRm6bNMRD'
    _nm_name='bus-pci-0000:00:04.0'

Here is an excerpt from a Debian /etc/network/interfaces file that does the same thing:

    ...
    auto eth1
    iface eth1 inet static
            address 130.252.100.17
            netmask 255.255.255.255
            broadcast 0.0.0.0
    ...

</div>

# ARP cache

A word of warning is in order here. ISPs typically configure their routers with a long ARP cache timeout. If you move a system from parallel to your firewall to behind your firewall with Proxy ARP, it will probably be **HOURS** before that system can communicate with the Internet.

If you sniff traffic on the firewall's external interface, you can see incoming traffic for the internal system(s) but the traffic is never sent out the internal interface.

You can determine if your ISP's gateway ARP cache is stale using ping and tcpdump. Suppose that we suspect that the gateway router has a stale ARP cache entry for 130.252.100.19. On the firewall, run tcpdump as follows:

    tcpdump -nei eth0 icmp

Now from 130.252.100.19, ping the ISP's gateway (which we will assume is 130.252.100.254):

    ping 130.252.100.254

We can now observe the tcpdump output:

    13:35:12.159321 0:4:e2:20:20:33 0:0:77:95:dd:19 ip 98: 130.252.100.19 > 130.252.100.254: icmp: echo request (DF)
    13:35:12.207615 0:0:77:95:dd:19 0:c0:a8:50:b2:57 ip 98: 130.252.100.254 > 130.252.100.19 : icmp: echo reply

Notice that the source MAC address in the echo request is different from the destination MAC address in the echo reply!! In this case 0:4:e2:20:20:33 was the MAC of the firewall's eth0 NIC while 0:c0:a8:50:b2:57 was the MAC address of the system on the lower left. In other words, the gateway's ARP cache still associates 130.252.100.19 with the NIC in that system rather than with the firewall's eth0.

If you have this problem, there are a couple of things that you can try:

1.  A reading of TCP/IP Illustrated, Vol 1 by Stevens reveals[^1] that a “gratuitous” ARP packet should cause the ISP's router to refresh their ARP cache (section 4.7). A gratuitous ARP is simply a host requesting the MAC address for its own IP; in addition to ensuring that the IP address isn't a duplicate...

    > if the host sending the gratuitous ARP has just changed its hardware address..., this packet causes any other host...that has an entry in its cache for the old hardware address to update its ARP cache entry accordingly.

    Which is, of course, exactly what you want to do when you switch a host from being exposed to the Internet to behind Shorewall using proxy ARP (or one-to-one NAT for that matter). Happily enough, recent versions of Redhat's iputils package include “arping”, whose “-U” flag does just that:

        arping -U -I <net if> <newly proxied IP>
        arping -U -I eth0 66.58.99.83             # for example

    Stevens goes on to mention that not all systems respond correctly to gratuitous ARPs, but googling for “arping -U” seems to support the idea that it works most of the time.

    To use arping with Proxy ARP in the above example, you would have to:

        shorewall clear
        ip addr add 130.252.100.18 dev eth0
        ip addr add 130.252.100.19 dev eth0
        arping -U -c 10 -I eth0 130.252.100.18
        arping -U -c 10 -I eth0 130.252.100.19
        ip addr del 130.252.100.18 dev eth0
        ip addr del 130.252.100.19 dev eth0
        shorewall start

2.  You can call your ISP and ask them to purge the stale ARP cache entry but many either can't or won't purge individual entries.

<div class="warning">

There are two distinct versions of `arping` available:

1.  `arping` by Thomas Habets (Debian package *arping*).

2.  `arping` as part of the iputils package by Alexey Kuznetsov (Debian package *iputils-arping*).

You want the second one by Alexey Kuznetsov.

</div>

# IPv6 - Proxy NDP

The IPv6 analog of Proxy ARP is Proxy NDP (Neighbor Discovery Protocol). Beginning with Shorewall 4.4.16, Shorewall6 supports Proxy NDP in a manner similar to Proxy ARP support in Shorewall:

- The configuration file is /etc/shorewall6/proxyndp (see [shorewall6-proxyndp](https://shorewall.org/manpages/shorewall-proxyndp.html) (5)).

- The ADDRESS column of that file contains an IPv6 address.

It should be noted that IPv6 implements a "strong host model" whereas Linux IPv4 implements a "weak host model". In the strong model, IP addresses are associated with interfaces; in the weak model, they are associated with the host. This is relevant with respect to Proxy NDP in that a multi-homed Linux IPv6 host will only respond to neighbor discoverey requests for IPv6 addresses configured on the interface receiving the request. So if eth0 has address 2001:470:b:227::44/128 and eth1 has address 2001:470:b:227::1/64 then in order for eth1 to respond to neighbor discoverey requests for 2001:470:b:227::44, the following entry in /etc/shorewall6/proxyndp is required:

    #ADDRESS              INTERFACE    EXTERNAL    HAVEROUTE    PERSISTENT
    2001:470:b:227::44        -            eth1        Yes

A practical application is shown in the Linux [Vserver article](../legacy/Vserver.md#NDP).

[^1]: Courtesy of Bradey Honsinger
