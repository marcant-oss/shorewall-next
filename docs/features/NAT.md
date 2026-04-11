<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

# One-to-one NAT

<div class="important">

**If all you want to do is forward ports to servers behind your firewall, you do NOT want to use one-to-one NAT. Port forwarding can be accomplished with simple entries in the [rules file](https://shorewall.org/manpages/shorewall-rules.html).**

</div>

One-to-one NAT is a way to make systems behind a firewall and configured with private IP addresses (those reserved for private use in RFC 1918) appear to have public IP addresses. Before you try to use this technique, I strongly recommend that you read the [Shorewall Setup Guide](../reference/shorewall_setup_guide.md).

The following figure represents a one-to-one NAT environment.

One-to-one NAT can be used to make the systems with the 10.1.1.\* addresses appear to be on the upper (130.252.100.\*) subnet. If we assume that the interface to the upper subnet is eth0, then the following `/etc/shorewall/nat` file would make the lower left-hand system appear to have IP address 130.252.100.18 and the right-hand one to have IP address 130.252.100.19. It should be stressed that these entries in the `/etc/shorewall/nat` file do not automatically enable traffic between the external network and the internal host(s) — such traffic is still subject to your policies and rules.

`/etc/shorewall/nat`

    #EXTERNAL       INTERFACE         INTERNAL      ALLINTS            LOCAL
    130.252.100.18  eth0              10.1.1.2      no                 no
    130.252.100.19  eth0              10.1.1.3      no                 no

Be sure that the internal system(s) (10.1.1.2 and 10.1.1.3 in the above example) is (are) not included in any specification in `/etc/shorewall/masq` (`/etc/shorewall/snat`) or `/etc/shorewall/proxyarp`.

<div class="note">

The “ALL INTERFACES” column is used to specify whether access to the external IP from all firewall interfaces should undergo NAT (Yes or yes) or if only access from the interface in the INTERFACE column should undergo NAT. If you leave this column empty, “No” is assumed . **Specifying “Yes” in this column will not by itself allow systems on the lower LAN to access each other using their public IP addresses.** For example, the lower left-hand system (10.1.1.2) cannot connect to 130.252.100.19 and expect to be connected to the lower right-hand system. [See FAQ 2a](../reference/FAQ.md#faq2a).

</div>

<div class="note">

Shorewall will automatically add the external address to the specified interface unless you specify [ADD_IP_ALIASES](https://shorewall.org/manpages/shorewall.conf.html)=“no” (or “No”) in `/etc/shorewall/shorewall.conf`; If you do not set ADD_IP_ALIASES or if you set it to “Yes” or “yes” then you must NOT configure your own alias(es).

</div>

<div class="note">

The contents of the “LOCAL” column determine whether packets originating on the firewall itself and destined for the EXTERNAL address are redirected to the internal ADDRESS. If this column contains “yes” or “Yes” (and the ALL INTERFACES COLUMN also contains “Yes” or “yes”) then such packets are redirected; otherwise, such packets are not redirected. This feature requires that you enabled CONFIG_IP_NF_NAT_LOCAL in your kernel.

</div>

Entries in `/etc/shorewall/nat` only arrange for address translation; they do not allow traffic to pass through the firewall in violation of your policies. In the above example, suppose that you wish to run a web server on 10.1.1.2 (a.k.a. 130.252.100.18). You would need the following entry in `/etc/shorewall/rules`:

    #ACTION     SOURCE     DEST            PROTO       DPORT       SPORT          ORIGDEST
    ACCEPT      net        loc:10.1.1.2    tcp         80          -              130.252.100.18

# ARP cache

A word of warning is in order here. ISPs typically configure their routers with a long ARP cache timeout. If you move a system from parallel to your firewall to behind your firewall with one-to-one NAT, it will probably be HOURS before that system can communicate with the Internet.

If you sniff traffic on the firewall's external interface, you can see incoming traffic for the internal system(s) but the traffic is never sent out the internal interface.

You can determine if your ISP's gateway ARP cache is stale using ping and tcpdump. Suppose that we suspect that the gateway router has a stale ARP cache entry for 130.252.100.19. On the firewall, run tcpdump as follows:

    tcpdump -nei eth0 icmp

Now from 10.1.1.3, ping the ISP's gateway (which we will assume is 130.252.100.254):

    ping 130.252.100.254

We can now observe the tcpdump output:

    13:35:12.159321 0:4:e2:20:20:33 0:0:77:95:dd:19 ip 98: 130.252.100.19 > 130.252.100.254: icmp: echo request (DF)
    13:35:12.207615 0:0:77:95:dd:19 0:c0:a8:50:b2:57 ip 98: 130.252.100.254 > 130.252.100.177 : icmp: echo reply

Notice that the source MAC address in the echo request is different from the destination MAC address in the echo reply!! In this case 0:4:e2:20:20:33 was the MAC of the firewall's eth0 NIC while 0:c0:a8:50:b2:57 was the MAC address of the system on the lower right. In other words, the gateway's ARP cache still associates 130.252.100.19 with the NIC in that system rather than with the firewall's eth0.

If you have this problem, there are a couple of things that you can try:

1.  A reading of TCP/IP Illustrated, Vol 1 by Stevens reveals[^1] that a “gratuitous” ARP packet should cause the ISP's router to refresh their ARP cache (section 4.7). A gratuitous ARP is simply a host requesting the MAC address for its own IP; in addition to ensuring that the IP address isn't a duplicate...

    > if the host sending the gratuitous ARP has just changed its hardware address..., this packet causes any other host...that has an entry in its cache for the old hardware address to update its ARP cache entry accordingly.

    Which is, of course, exactly what you want to do when you switch a host from being exposed to the Internet to behind Shorewall using one-to-one NAT (or Proxy ARP for that matter). Happily enough, recent versions of Redhat's iputils package include “arping”, whose “-U” flag does just that:

        arping -U -I <net if> <newly proxied IP>
        arping -U -I eth0 66.58.99.83             # for example

    Stevens goes on to mention that not all systems respond correctly to gratuitous ARPs, but googling for “arping -U” seems to support the idea that it works most of the time.

    To use arping with one-to-one NAT in the above example, you would have to:

        shorewall clear
        ip addr add 130.252.100.18 dev eth0     # You need to add the addresses only if Shorewall clear
        ip addr add 130.252.100.19 dev eth0     # deletes them
        arping -U -c 10 -I eth0 130.252.100.18
        arping -U -c 10 -I eth0 130.252.100.19
        ip addr del 130.252.100.18 dev eth0     # You need to delete the addresses only if you added
        ip addr del 130.252.100.19 dev eth0     # them above
        shorewall start

2.  You can call your ISP and ask them to purge the stale ARP cache entry but many either can't or won't purge individual entries.

<div class="warning">

There are two distinct versions of `arping` available:

1.  `arping` by Thomas Habets (Debian package *arping*).

2.  `arping` as part of the iputils package by Alexey Kuznetsov (Debian package *iputils-arping*).

You want the second one by Alexey Kuznetsov.

</div>

[^1]: Courtesy of Bradey Honsinger
