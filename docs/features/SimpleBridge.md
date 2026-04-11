# Background

Systems where Shorewall runs normally function as routers. In the context of the Open System Interconnect (OSI) reference model, a router operates at layer 3. Shorewall may also be deployed on a GNU Linux System that acts as a bridge. Bridges are layer-2 devices in the OSI model (think of a bridge as an Ethernet switch).

Some differences between routers and bridges are:

1.  Routers determine packet destination based on the destination IP address while bridges route traffic based on the destination MAC address in the Ethernet frame.

2.  As a consequence of the first difference, routers can be connected to more than one IP network while a bridge may be part of only a single network.

3.  A router cannot forward broadcast packets while a bridge can.

# Application

There are cases where you want to create a bridge to join two or more LAN segments and you don't need to restrict the traffic between those segments. This is the environment that is described in this article.

If you do need to restrict traffic through the bridge, please refer to the [Shorewall Bridge/Firewall documentation](../legacy/bridge-Shorewall-perl.md). Also please refer to that documentation for information about how to create a bridge.

The following diagram shows a firewall for two bridged LAN segments.

This is fundamentally the Two-interface Firewall described in the [Two-interface Quickstart Guide](../reference/two-interface.md). The bridge-specific changes are restricted to the `/etc/shorewall/interfaces` file.

<div class="note">

Older configurations that specify an interface name in the SOURCE column of `/etc/shorewall/masq` will also need to change that file.

</div>

This example illustrates the bridging of two Ethernet devices but the types of the devices really isn't important. What is shown here would apply equally to bridging an Ethernet device to an [OpenVPN](OPENVPN.md) tap device (e.g., `tap0`) or to a wireless device (`ath0` or `wlan0`).

`/etc/shorewall/interfaces`:

    ?FORMAT 2
    #ZONE          INTERFACE       OPTIONS
    net            eth0            ...
    loc            br0             routeback,bridge,...

So the key points here are:

- The **loc** interface is `br0`.

- Neither `eth1` nor `eth2` have IP addresses and neither are mentioned in the Shorewall configuration.

- The **routeback** and **bridge** options is specified for `br0`.

- The default gateway for hosts in the local segments will be 10.0.1.254 — the IP address of the bridge itself.

Your entry in `/etc/shorewall/masq` should be unchanged:

    #INTERFACE     SOURCE          ADDRESS
    eth0           10.0.1.0/24     ...            # 10.0.1.0/24 is the local network on LAN A and LAN B

When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

    #ACTION                SOURCE          DEST                PROTO   PORT
    MASQUERADE             10.0.1.0/24     eth0
