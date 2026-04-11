# Introduction

Formal support for Linux-vserver was added in Shorewall 4.4.11 Beta2. The centerpiece of that support is the vserver zone type. Vserver zones have the following characteristics:

- They are defined on the Linux-vserver host.

- The \$FW zone is their implicit parent.

- Their contents must be defined using the [shorewall-hosts](https://shorewall.org/manpages/shorewall-hosts.html) (5) file. The **ipsec** option may not be specified.

- They may not appear in the ZONE column of the [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html) (5) file.

Note that you don't need to run Vservers to use vserver zones; they may also be used to create a firewall sub-zone for each [aliased interface](Shorewall_and_Aliased_Interfaces.md).

If you use these zones, keep in mind that Linux-vserver implements a very weak form of network virtualization:

- From a networking point of view, vservers live on the host system. So if you don't use care, Vserver traffic to/from zone z will be controlled by the fw-\>z and z-\>fw rules and policies rather than by vserver-\>z and z-\>vserver rules and policies.

- Outgoing connections from a vserver will not use the Vserver's address as the SOURCE IP address unless you configure applications running in the Vserver properly. This is especially true for IPv6 applications. Such connections will appear to come from the \$FW zone rather than the intended Vserver zone.

- While you can define the vservers to be associated with the network interface where their IP addresses are added at vserver startup time, Shorewall internally associates all vservers with the loopback interface (**lo**). Here's an example of how that association can show up:

      gateway:~# shorewall show zones
      Shorewall 4.4.11-Beta2 Zones at gateway - Fri Jul  2 12:26:30 PDT 2010

      fw (firewall)
      drct (ipv4)
         eth4:+drct_eth4
      loc (ipv4)
         eth4:0.0.0.0/0
      net (ipv4)
         eth1:0.0.0.0/0
      vpn (ipv4)
         tun+:0.0.0.0/0
      dmz (vserver)
         lo:70.90.191.124/31

      gateway:~#

# Vserver Zones

This is a diagram of the network configuration here at Shorewall.net during the summer of 2010:

I created a zone for the vservers as follows:

`/etc/shorewall/zones`:

    #ZONE           TYPE            OPTIONS            ...
    fw              firewall
    loc             ip              #Local Zone
    drct:loc        ipv4            #Direct internet access
    net             ipv4            #Internet
    vpn             ipv4            #OpenVPN clients
    dmz             vserver         #Vservers

`/etc/shorewall/interfaces`:

    ?FORMAT 2
    #ZONE   INTERFACE     OPTIONS
    net     eth1          routeback,dhcp,optional,routefilter=0,logmartians,proxyarp=0,nosmurfs,upnp
    ...

`/etc/shorewall/hosts`:

    #ZONE   HOST(S)                                 OPTIONS
    drct    eth4:dynamic
    dmz     eth1:70.90.191.124/31                   routeback

While the IP addresses 70.90.191.124 and 70.90.191.125 are configured on eth1, the actual interface name is irrelevant so long as the interface is defined in [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html) (5). Shorewall will consider all vserver zones to be associated with the loopback interface (**lo**). Note that the **routeback** option is required if the vservers are to be able to communicate with each other.

Once a vserver zone is defined, it can be used like any other zone type.

Here is the corresponding IPv6 configuration.

`/etc/shorewall6/zones`

    #ZONE   TYPE    OPTIONS         IN_OPTIONS          OUT_OPTIONS
    fw  firewall
    net ipv6
    loc ipv6
    vpn ipv6
    dmz   vserver

`/etc/shorewall6/interfaces`:

    ?FORMAT 2
    #ZONE   INTERFACE     OPTIONS
    net     sit1          tcpflags,forward=1,nosmurfs,routeback
    ...

`/etc/shorewall6/hosts`:

    #ZONE   HOST(S)                                 OPTIONS
    dmz     sit1:[2001:470:e857:1::/64]

Note that I choose to place the Vservers on sit1 (the IPv6 net interface) rather than on eth1. Again, it really doesn't matter much.

# Sharing an IPv6 /64 between Vservers and a LAN

I have both a /64 (2001:470:b:227::/64) and a /48 (2001:470:e857::/48) from [Hurricane Electric](http://www.tunnelbroker.net). When I first set up my Vserver configuration, I assigned addresses from the /48 to the Vservers as shown above.

Given that it is likely that when native IPv6 is available from my ISP, I will only be able to afford a single /64, in February 2011 I decided to migrate my vservers to the /64. This was possible because of Proxy NDP support in Shorewall 4.4.16 and later. The new network diagram is as shown below:

This change was accompanied by the following additions to `/etc/shorewall6/proxyndp`:

    #ADDRESS        INTERFACE   EXTERNAL    HAVEROUTE   PERSISTENT
    2001:470:b:227::2   -       eth4        Yes     Yes
    2001:470:b:227::3   -       eth4        Yes     Yes

These two entries allow the firewall to respond to NDP requests for the two Vserver IPv6 addresses received on interface eth4.

As part of this change, the **Lists** vserver (OpenSuSE 10.3 was retired in favor of **Mail** (Debian Squeeze).
