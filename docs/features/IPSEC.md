<div class="caution">

**This article applies to Shorewall 3.0 and later. If you are running a version of Shorewall earlier than Shorewall 3.0.0 then please see the documentation for that release.**

</div>

<div class="important">

The information in this article is only applicable if you plan to have IPSEC end-points on the same system where Shorewall is used.

</div>

<div class="warning">

This documentation is incomplete regarding using IPSEC and the 2.6 Kernel. Netfilter currently lacks full support for the 2.6 kernel's implementation of IPSEC. Until that implementation is complete, only a simple network-network tunnel is described for 2.6.

UPDATE: Some distributions such as SUSE are now shipping Kernels and iptables with the IPSEC-Netfilter patches and policy match support. The IPSEC-2.6 article was not ported to shorewall-nft documentation.

</div>

# Preliminary Reading

I recommend reading the [VPN Basics](VPNBasics.md) article if you plan to implement any type of VPN.

# Configuring FreeS/Wan and Derivatives Such as OpenS/Wan

There is an excellent guide to configuring IPSEC tunnels at <http://jixen.tripod.com/>. I highly recommend that you consult that site for information about configuring FreeS/Wan.

<div class="important">

The documentation below assumes that you have disabled opportunistic encryption feature in FreeS/Wan 2.0 using the following additional entries in ipsec.conf:

    conn block
            auto=ignore

    conn private
            auto=ignore

    conn private-or-clear
            auto=ignore

    conn clear-or-private
            auto=ignore

    conn clear
            auto=ignore

    conn packetdefault
            auto=ignore

For further information see <http://www.freeswan.org/freeswan_trees/freeswan-2.03/doc/policygroups.html>.

</div>

# IPSec Gateway on the Firewall System

Suppose that we have the following situation:

We want systems in the 192.168.1.0/24 sub-network to be able to communicate with systems in the 10.0.0.0/8 network. We assume that on both systems A and B, eth0 is the Internet interface.

To make this work, we need to do two things:

1.  Open the firewall so that the IPSEC tunnel can be established (allow the ESP and AH protocols and UDP Port 500).

2.  Allow traffic through the tunnel.

Opening the firewall for the IPSEC tunnel is accomplished by adding an entry to the /etc/shorewall/tunnels file.

In /etc/shorewall/tunnels on system A, we need the following

    #TYPE      ZONE        GATEWAY          GATEWAY ZONE
    ipsec      net         134.28.54.2

In /etc/shorewall/tunnels on system B, we would have:

    #TYPE      ZONE        GATEWAY          GATEWAY ZONE
    ipsec      net         206.161.148.9

<div class="note">

If either of the endpoints is behind a NAT gateway then the tunnels file entry on the **other** endpoint should specify a tunnel type of ipsecnat rather than ipsec and the GATEWAY address should specify the external address of the NAT gateway.

</div>

You need to define a zone for the remote subnet or include it in your local zone. In this example, we'll assume that you have created a zone called “vpn” to represent the remote subnet. Note that you should define the vpn zone before the net zone.

/etc/shorewall/zones (both systems):

    #ZONE          TYPE         OPTIONS
    vpn            ipv4
    net            ipv4

**If you are running kernel 2.4:**

> At both systems, ipsec0 would be included in /etc/shorewall/interfaces as a “vpn” interface:
>
>     #ZONE         INTERFACE         BROADCAST       OPTIONS
>     vpn           ipsec0

**If you are running kernel 2.6:**

> **It is essential that the *vpn* zone be declared before the *net* zone in `/etc/shorewall/zones`.**
>
> Remember the assumption that both systems A and B have eth0 as their Internet interface.
>
> You must define the vpn zone using the /etc/shorewall/hosts file.
>
> /etc/shorewall/hosts - System A
>
>     #ZONE        HOSTS                  OPTIONS
>     vpn          eth0:10.0.0.0/8
>
> /etc/shorewall/hots - System B
>
>     #ZONE        HOSTS                  OPTIONS
>     vpn          eth0:192.168.1.0/24
>
> In addition, **if you are using Masquerading or SNAT** on your firewalls, you need to eliminate the remote network from Masquerade/SNAT. These entries **replace** your current masquerade/SNAT entries for the local networks.
>
> /etc/shorewall/masq - System A
>
>     #INTERFACE            SOURCE                ADDRESS
>     eth0:!10.0.0.0/8      192.168.1.0/24
>
> /etc/shorewall/masq - System B
>
>     #INTERFACE            SOURCE                ADDRESS
>     eth0:!192.168.1.0/24  10.0.0.0/8

You will need to allow traffic between the “vpn” zone and the “loc” zone -- if you simply want to admit all traffic in both directions, you can use the policy file:

    #SOURCE       DEST        POLICY       LOG LEVEL
    loc           vpn         ACCEPT
    vpn           loc         ACCEPT

Once you have these entries in place, restart Shorewall (type shorewall restart); you are now ready to configure the tunnel in [FreeS/WAN](http://www.xs4all.nl/%7Efreeswan/).

# VPN Hub using Kernel 2.4

Shorewall can be used in a VPN Hub environment where multiple remote networks are connected to a gateway running Shorewall. This environment is shown in this diagram.

We want systems in the 192.168.1.0/24 sub-network to be able to communicate with systems in the 10.0.0.0/16 and 10.1.0.0/16 networks and we want the 10.0.0.0/16 and 10.1.0.0/16 networks to be able to communicate.

To make this work, we need to do several things:

1.  Open the firewall so that two IPSEC tunnels can be established (allow the ESP and AH protocols and UDP Port 500).

2.  Allow traffic through the tunnels two/from the local zone (192.168.1.0/24).

3.  Deny traffic through the tunnels between the two remote networks.

Opening the firewall for the IPSEC tunnels is accomplished by adding two entries to the /etc/shorewall/tunnels file.

In /etc/shorewall/tunnels on system A, we need the following

    #TYPE         ZONE         GATEWAY         GATEWAY ZONE
    ipsec         net          134.28.54.2
    ipsec         net          130.252.100.14

In /etc/shorewall/tunnels on systems B and C, we would have:

    #TYPE         ZONE         GATEWAY         GATEWAY ZONE
    ipsec         net          206.161.148.9

<div class="note">

If either of the endpoints is behind a NAT gateway then the tunnels file entry on the **other** endpoint should specify a tunnel type of *ipsecnat* rather than ipsec and the GATEWAY address should specify the external address of the NAT gateway.

</div>

On each system, we will create a zone to represent the remote networks. On System A:

    #ZONE       TYPE         OPTIONS
    vpn1        ipv4
    vp2         ipv4

On systems B and C:

    #ZONE       TYPE         OPTIONS
    vpn         ipv4

At system A, ipsec0 represents two zones so we have the following in /etc/shorewall/interfaces:

    #ZONE       INTERFACE    BROADCAST       OPTIONS
    -           ipsec0

The /etc/shorewall/hosts file on system A defines the two VPN zones:

    #ZONE       HOSTS                        OPTIONS
    vpn1        ipsec0:10.0.0.0/16
    vpn2        ipsec0:10.1.0.0/16

At systems B and C, ipsec0 represents a single zone so we have the following in /etc/shorewall/interfaces:

    #ZONE       INTERFACE       BROADCAST    OPTIONS
    vpn         ipsec0

On systems A, you will need to allow traffic between the “vpn1” zone and the “loc” zone as well as between “vpn2” and the “loc” zone -- if you simply want to admit all traffic in both directions, you can use the following policy file entries on all three gateways:

    #SOURCE      DEST       POLICY           LOG LEVEL
    loc          vpn1       ACCEPT
    vpn1         loc        ACCEPT
    loc          vpn2       ACCEPT
    vpn2         loc        ACCEPT

On systems B and C, you will need to allow traffic between the “vpn” zone and the “loc” zone -- if you simply want to admit all traffic in both directions, you can use the following policy file entries on all three gateways:

/etc/shorewall/policy -- Systems B & C

    #SOURCE      DEST       POLICY           LOG LEVEL
    loc          vpn        ACCEPT
    vpn          loc        ACCEPT

Once you have the Shorewall entries added, restart Shorewall on each gateway (type shorewall restart); you are now ready to configure the tunnels in [FreeS/WAN](http://www.xs4all.nl/%7Efreeswan/).

<div class="note">

to allow traffic between the networks attached to systems B and C, it is necessary to simply add two additional entries to the /etc/shorewall/policy file on system A.

    #SOURCE      DEST       POLICY           LOG LEVEL
    vpn1         vpn2       ACCEPT
    vpn2         vpn1       ACCEPT

</div>

<div class="note">

If you find traffic being rejected/dropped in the OUTPUT chain, place the names of the remote VPN zones as a comma-separated list in the GATEWAY ZONE column of the /etc/shorewall/tunnels file entry.

</div>

# Mobile System (Road Warrior) Using Kernel 2.4

Suppose that you have a laptop system (B) that you take with you when you travel and you want to be able to establish a secure connection back to your local network.

You need to define a zone for the laptop or include it in your local zone. In this example, we'll assume that you have created a zone called “vpn” to represent the remote host.

/etc/shorewall/zones - System A

    #ZONE      TYPE        OPTIONS
    vpn        ipv4

In this instance, the mobile system (B) has IP address 134.28.54.2 but that cannot be determined in advance. In the /etc/shorewall/tunnels file on system A, the following entry should be made:

    #TYPE       ZONE       GATEWAY        GATEWAY ZONE
    ipsec       net        0.0.0.0/0

<div class="note">

the GATEWAY ZONE column contains the name of the zone corresponding to peer subnetworks. This indicates that the gateway system itself comprises the peer subnetwork; in other words, the remote gateway is a standalone system.

</div>

You will need to configure /etc/shorewall/interfaces and establish your “through the tunnel” policy as shown under the first example above.

# Dynamic RoadWarrior Zones

Beginning with Shorewall release 1.3.10, you can define multiple VPN zones and add and delete remote endpoints dynamically using /sbin/shorewall. With Shorewall 2.0.2 Beta 1 and later versions, this capability must be enabled by setting DYNAMIC_ZONES=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html).

<div class="important">

DYNAMIC_ZONES=Yes is not supported by Shorewall-perl 4.2.0 or later versions. Use [dynamic zones defined by ipsets](ipsets.md#Dynamic) instead.

</div>

In /etc/shorewall/zones:

    #ZONE       TYPE       OPTIONS
    vpn1        ipv4
    vpn2        ipv4
    vpn3        ipv4

In /etc/shorewall/tunnels:

    #TYPE       ZONE       GATEWAY         GATEWAY ZONE
    ipsec       net        0.0.0.0/0       vpn1,vpn2,vpn3

When Shorewall is started, the zones vpn\[1-3\] will all be empty and Shorewall will issue warnings to that effect. These warnings may be safely ignored. FreeS/Wan may now be configured to have three different Road Warrior connections with the choice of connection being based on X-509 certificates or some other means. Each of these connections will utilize a different updown script that adds the remote station to the appropriate zone when the connection comes up and that deletes the remote station when the connection comes down. For example, when 134.28.54.2 connects for the vpn2 zone the “up” part of the script will issue the command:

    /sbin/shorewall add ipsec0:134.28.54.2 vpn2

and the “down” part will:

    /sbin/shorewall delete ipsec0:134.28.54.2 vpn2
