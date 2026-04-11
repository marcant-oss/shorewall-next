# UPnP

Shorewall includes support for UPnP (Universal Plug and Play) using linux-igd (<http://linux-igd.sourceforge.net>). UPnP is required by a number of popular applications including MSN IM.

<div class="warning">

From a security architecture viewpoint, UPnP is a disaster. It assumes that:

1.  All local systems and their users are completely trustworthy.

2.  No local system is infected with any worm or trojan.

If either of these assumptions are not true then UPnP can be used to totally defeat your firewall and to allow incoming connections to arbitrary local systems on any port whatsoever. In short: USE UPnP **AT YOUR OWN RISK.**

</div>

<div class="important">

Shorewall and linux-igd implement a UPnP Internet Gateway Device. It will not allow clients on one LAN subnet to access a UPnP Media Server on another subnet.

</div>

# linux-igd Configuration

In /etc/upnpd.conf, you will want:

    create_forward_rules = yes
    prerouting_chain_name = UPnP
    forward_chain_name = forwardUPnP

# Shorewall Configuration

In `/etc/shorewall/interfaces`, you need the 'upnp' option on your external interface.

Example:

    #ZONE   INTERFACE       OPTIONS
    net     eth1            dhcp,routefilter,tcpflags,upnp

If your loc-\>fw policy is not ACCEPT then you need this rule:

    #ACTION            SOURCE  DEST
    allowinUPnP        loc     $FW

You MUST have this rule:

    #ACTION            SOURCE  DEST
    forwardUPnP        net     loc

You must also ensure that you have a route to 224.0.0.0/4 on your internal (local) interface as described in the linux-igd documentation.

<div class="note">

The init script included with the Debian linux-idg package adds this route during `start` and deletes it during `stop`.

</div>

<div class="caution">

Shorewall versions prior to 4.4.10 do not retain the dynamic rules added by linux-idg over a `shorewall restart`.

</div>

If your firewall-\>loc policy is not ACCEPT, then you also need to allow UDP traffic from the fireawll to the local zone.

    ACCEPT      $FW          loc        udp            -         <dynamic port range>

The dynamic port range is obtained by **cat /proc/sys/net/ip_local_port_range**.

# Shorewall on a UPnP Client

It is sometimes desirable to run UPnP-enabled client programs like [Transmission](http://www.transmissionbt.com/) (BitTorrent client) on a Shorewall-protected system. Shorewall provides support for UPnP client access in the form of the **upnpclient** option in [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html) (5).

The **upnpclient** option causes Shorewall to detect the default gateway through the interface and to accept UDP packets from that gateway. Note that, like all aspects of UPnP, this is a security hole so use this option at your own risk.

Note that when multiple clients behind the firewall use UPnP, they must configure their applications to use unique ports.
