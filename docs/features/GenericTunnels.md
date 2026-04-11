Shorewall includes built-in support for a wide range of VPN solutions. If you have need for a tunnel type that does not have explicit support, you can generally describe the tunneling software using “generic tunnels”.

# Bridging two Masqueraded Networks

Suppose that we have the following situation:

We want systems in the 192.168.1.0/24 subnetwork to be able to communicate with the systems in the 10.0.0.0/8 network. This is accomplished through use of the /etc/shorewall/tunnels file, the /etc/shorewall/policy file and the /etc/shorewall/tunnel script that is included with Shorewall.

Suppose that you have tunneling software that uses two different protocols:

1.  TCP port 1071

2.  GRE (Protocol 47)

3.  The tunnel interface on system A is “tun0” and the tunnel interface on system B is also “tun0”.

On each firewall, you will need to declare a zone to represent the remote subnet. We'll assume that this zone is called “vpn” and declare it in /etc/shorewall/zones on both systems as follows.

    #ZONE        TYPE          OPTIONS
    vpn          ipv4

On system A, the 10.0.0.0/8 will comprise the **vpn** zone. In /etc/shorewall/interfaces:

    #ZONE      INTERFACE       BROADCAST        OPTIONS
    vpn        tun0            10.255.255.255

In /etc/shorewall/tunnels on system A, we need the following:

    #TYPE            ZONE           GATEWAY         GATEWAY_ZONE
    generic:tcp:1071 net            134.28.54.2
    generic:47       net            134.28.54.2

These entries in /etc/shorewall/tunnels, opens the firewall so that TCP port 1071 and the Generalized Routing Encapsulation Protocol (47) will be accepted to/from the remote gateway.

    #ZONE        INTERFACE        BROADCAST         OPTIONS
    vpn          tun0             192.168.1.255

In /etc/shorewall/tunnels on system B, we have:

    #TYPE            ZONE           GATEWAY         GATEWAY_ZONE
    generic:tcp:1071 net            206.191.148.9
    generic:47       net            206.191.148.9

You will need to allow traffic between the “vpn” zone and the “loc” zone on both systems -- if you simply want to admit all traffic in both directions, you can use the policy file:

    #SOURCE      DEST        POLICY        LOG LEVEL
    loc          vpn         ACCEPT
    vpn          loc         ACCEPT

On both systems, restart Shorewall and start your VPN software on each system. The systems in the two masqueraded subnetworks can now talk to each other
