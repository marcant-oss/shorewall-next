<div class="warning">

GRE and IPIP Tunnels are insecure when used over the Internet; use them at your own risk

</div>

GRE and IPIP tunneling with Shorewall can be used to bridge two masqueraded networks.

The simple scripts described in the [Linux Advanced Routing and Shaping HOWTO](http://ds9a.nl/lartc) work fine with Shorewall. Shorewall also includes a tunnel script for automating tunnel configuration. If you have installed the RPM, the tunnel script may be found in the Shorewall documentation directory (usually /usr/share/doc/shorewall-\<version\>/).

# Bridging two Masqueraded Networks

Suppose that we have the following situation:

We want systems in the 192.168.1.0/24 subnetwork to be able to communicate with the systems in the 10.0.0.0/8 network. This is accomplished through use of the /etc/shorewall/tunnels file, the /etc/shorewall/policy file and the /etc/shorewall/tunnel script that is included with Shorewall.

The “tunnel” script is not installed in /etc/shorewall by default -- If you install using the tarball, the script is included in the tarball; if you install using the RPM, the file is in your Shorewall documentation directory (normally /usr/share/doc/shorewall-\<version\>).

In the /etc/shorewall/tunnel script, set the “tunnel_type” parameter to the type of tunnel that you want to create.

    tunnel_type=gre

<div class="warning">

If you use the PPTP connection tracking modules from Netfilter Patch-O-Matic (ip_conntrack_proto_gre ip_conntrack_pptp, ip_nat_proto_gre and ip_nat_pptp) then you cannot use GRE tunnels.

</div>

On each firewall, you will need to declare a zone to represent the remote subnet. We'll assume that this zone is called “vpn” and declare it in /etc/shorewall/zones on both systems as follows.

    #ZONE        TYPE           OPTIONS
    vpn          ipv4

On system A, the 10.0.0.0/8 will comprise the **vpn** zone. In /etc/shorewall/interfaces:

    #ZONE        INTERFACE      OPTIONS
    vpn          tosysb

In /etc/shorewall/tunnels on system A, we need the following:

    #TYPE         ZONE          GATEWAY          GATEWAY_ZONE
    ipip          net           134.28.54.2

This entry in /etc/shorewall/tunnels, opens the firewall so that the IP encapsulation protocol (4) will be accepted to/from the remote gateway.

In the tunnel script on system A:

    tunnel=tosysb
    myrealip=206.161.148.9 (for GRE tunnel only)
    myip=192.168.1.1
    hisip=10.0.0.1
    gateway=134.28.54.2
    subnet=10.0.0.0/8

Similarly, On system B the 192.168.1.0/24 subnet will comprise the **vpn** zone. In /etc/shorewall/interfaces:

    #ZONE        INTERFACE
    vpn          tosysa

In /etc/shorewall/tunnels on system B, we have:

    #TYPE        ZONE           GATEWAY           GATEWAY_ZONE
    ipip         net            206.191.148.9

And in the tunnel script on system B:

    tunnel=tosysa
    myrealip=134.28.54.2 (for GRE tunnel only)
    myip=10.0.0.1
    hisip=192.168.1.1
    gateway=206.191.148.9
    subnet=192.168.1.0/24

You can rename the modified tunnel scripts if you like; be sure that they are secured so that root can execute them.

You will need to allow traffic between the “vpn” zone and the “loc” zone on both systems -- if you simply want to admit all traffic in both directions, you can use the policy file:

    #SOURCE          DEST          POLICY         LOG LEVEL
    loc              vpn           ACCEPT
    vpn              loc           ACCEPT

On both systems, restart Shorewall and run the modified tunnel script with the “start” argument on each system. The systems in the two masqueraded subnetworks can now talk to each other
