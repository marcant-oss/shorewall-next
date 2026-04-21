All traffic from an interface or from a subnet on an interface can be verified to originate from a defined set of MAC addresses. Furthermore, each MAC address may be optionally associated with one or more IP addresses.

<div class="important">

**MAC addresses are only visible within an Ethernet segment so all MAC addresses used in verification must belong to devices physically connected to one of the LANs to which your firewall is connected.**

**This means what it says! MAC addresses are only used within a LAN and never go outside of that LAN so please don't post on the mailing list asking how to use MAC addresses of computers connected to remote networks. The only MAC address that your firewall is going to see from these hosts is the MAC address of your upstream router.**

</div>

<div class="important">

**Your kernel must include MAC match support (CONFIG_IP_NF_MATCH_MAC - module name ipt_mac.o).**

</div>

<div class="important">

**MAC verification is only applied to new incoming connection requests.**

</div>

<div class="important">

**DO NOT use MAC verification as your only security measure . MAC addresses can be easily spoofed. You can use it in combination with either [IPSEC](IPSEC.md) or [OpenVPN](OPENVPN.md).**

</div>

# Components

There are six components to this facility.

1.  The **maclist** interface option in [/etc/shorewall/interfaces](https://shorewall.org/manpages/shorewall-interfaces.html). When this option is specified, all new connection requests arriving on the interface are subject to MAC verification.

2.  The **maclist** option in [/etc/shorewall/hosts](https://shorewall.org/manpages/shorewall-hosts.html). When this option is specified for a subnet, all new connection requests from that subnet are subject to MAC verification.

3.  The /etc/shorewall/maclist file. This file is used to associate MAC addresses with interfaces and to optionally associate IP addresses with MAC addresses.

4.  The **MACLIST_DISPOSITION** and **MACLIST_LOG_LEVEL** variables in [/etc/shorewall/shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html). The MACLIST_DISPOSITION variable has the value DROP, REJECT or ACCEPT and determines the disposition of connection requests that fail MAC verification. The MACLIST_LOG_LEVEL variable gives the syslogd level at which connection requests that fail verification are to be logged. If set the empty value (e.g., MACLIST_LOG_LEVEL="") then failing connection requests are not logged.

5.  The **MACLIST_TTL** variable in [/etc/shorewall/shorewall.conf](???). The performance of configurations with a large numbers of entries in /etc/shorewall/maclist can be improved by setting the MACLIST_TTL variable.

    If your iptables and kernel support the "Recent Match" (see the output of "shorewall check" near the top), you can cache the results of a 'maclist' file lookup and thus reduce the overhead associated with MAC Verification.

    When a new connection arrives from a 'maclist' interface, the packet passes through the list of entries for that interface in /etc/shorewall/maclist. If there is a match then the source IP address is added to the 'Recent' set for that interface. Subsequent connection attempts from that IP address occurring within \$MACLIST_TTL seconds will be accepted without having to scan all of the entries. After \$MACLIST_TTL from the first accepted connection request from an IP address, the next connection request from that IP address will be checked against the entire list.

    If MACLIST_TTL is not specified or is specified as empty (e.g, MACLIST_TTL="" or is specified as zero then 'maclist' lookups will not be cached).

6.  The **MACLIST_TABLE** variable in [/etc/shorewall/shorewall.conf](???). Normally, MAC verification occurs in the filter table (INPUT and FORWARD) chains. When forwarding a packet from an interface with MAC verification to a bridge interface, that doesn't work.

    This problem can be worked around by setting MACLIST_TABLE=mangle which will cause MAC verification to occur out of the PREROUTING chain. Because REJECT isn't available in that environment, you may not specify MACLIST_DISPOSITION=REJECT with MACLIST_TABLE=mangle.

# /etc/shorewall/maclist

See [shorewall-maclist](https://shorewall.org/manpages/shorewall-maclist.html)(5).

# Examples

/etc/shorewall/shorewall.conf:

    MACLIST_DISPOSITION=REJECT
    MACLIST_LOG_LEVEL=info

/etc/shorewall/interfaces:

    #ZONE   INTERFACE       OPTIONS
    net     $EXT_IF         dhcp,routefilter,logmartians,blacklist,tcpflags,nosmurfs
    loc     $INT_IF         dhcp
    dmz     $DMZ_IF         
    vpn     tun+            
    Wifi    $WIFI_IF        maclist,dhcp

etc/shorewall/maclist:

    #DISPOSITION            INTERFACE               MAC                     IP ADDRESSES (Optional)
    ACCEPT                  $WIFI_IF                00:04:5e:3f:85:b9                       #WAP11
    ACCEPT                  $WIFI_IF                00:06:25:95:33:3c                       #WET11
    ACCEPT                  $WIFI_IF                00:0b:4d:53:cc:97       192.168.3.8     #TIPPER
    ACCEPT                  $WIFI_IF                00:1f:79:cd:fe:2e       192.168.3.6     #Work Laptop

As shown above, I used MAC Verification on my wireless zone that was served by a Linksys WET11 wireless bridge.

<div class="note">

While marketed as a wireless bridge, the WET11 behaves like a wireless router with DHCP relay. When forwarding DHCP traffic, it uses the MAC address of the host (TIPPER) but for other forwarded traffic it uses its own MAC address. Consequently, I listd the IP addresses of both devices in /etc/shorewall/maclist.

</div>

Suppose now that I had added a second wireless segment to my wireless zone and gateway that segment via a router with MAC address 00:06:43:45:C6:15 and IP address 192.168.3.253. Hosts in the second segment have IP addresses in the subnet 192.0.2.0/24. I would have added the following entry to my /etc/shorewall/maclist file:

    ACCEPT                  $WIFI_IF                    00:06:43:45:C6:15       192.168.3.253,192.0.2.0/24

This entry would accommodate traffic from the router itself (192.168.3.253) and from the second wireless segment (192.0.2.0/24). Remember that all traffic being sent to my firewall from the 192.0.2.0/24 segment will be forwarded by the router so that traffic's MAC address will be that of the router (00:06:43:45:C6:15) and not that of the host sending the traffic.
