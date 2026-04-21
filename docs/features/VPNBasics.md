# Gateway-to-gateway traffic vs. Host-to-host traffic.

The purpose of a Virtual Private Network (VPN) is to provide for secure communication between a set of hosts. Communication between a pair of hosts connected by a VPN occurs in stages:

1.  **Local-host-to-local-gateway**. This communication is not encrypted; in the case where the traffic originates on the gateway itself, the communication is local to that system.

2.  **Local-gateway-to-remote-gateway**. This communication is encrypted and can use a tunneling protocol such as GRE, AH or ESP or a standard protocol such as UDP or TCP. Some VPNs use multiple protocols; for example PPTP uses TCP port 1723 and GRE while IPSEC uses UDP port 500 together with ESP or AH.

3.  **Remote-gateway-to-remote-host**. This is just the unencrypted traffic described in the first item as it is delivered to its destination.

Of course, one-way communication generally isn't useful so we need traffic in the other direction as well.

1.  **Remote-host-to-remote-gateway**.

2.  **Remote-gateway-to-local-gateway**.

3.  **Local-gateway-to-local-host**.

# Relationship to Netfilter

When Netfilter is configured on a VPN gateway, each VPN packet goes through Netfilter twice! Let's first consider outbound traffic:

1.  **Local-host-to-local-gateway**. This traffic has a source address in the local network or on the gateway itself. The destination IP address is that of a remote host; either the remote gateway itself or a host behind that gateway.

2.  **Local-gateway-to-remote-gateway.** This (encrypted) traffic has a source IP address on the gateway and is addressed to the remote gateway.

Incoming traffic is similar.

# What does this mean with Shorewall?

When Shorewall is installed on a VPN gateway system, it categorizes the VPN-related traffic slightly differently:

1.  **Local-host-to-remote-host** — same as **Local-host-to-local-gateway** above.

2.  **Local-gateway-to-remote-gateway**.

3.  **Remote-gateway-to-local-gateway**.

4.  **Remote-host-to-local-host** — same as **Local-gateway-to-local-host** above.

Shorewall implements a set of features for dealing with VPN.

1.  The `/etc/shorewall/tunnels` file. This file is used to define remote gateways and the type of encrypted traffic that will be passed between the Shorewall system and those remote gateways. In other words, the tunnels file deals with **Local-gateway-to-remote-gateway** and **Remote-gateway-to-local-gateway** traffic.

2.  The `/etc/shorewall/zones` file. An entry in this file allows you to associated a name with the set of hosts behind the remote gateway (or to the remote gateway itself if it is a standalone system).

3.  The `/etc/shorewall/interfaces` and `/etc/shorewall/hosts` files. These files are used to associate a set of remote hosts with the zone name defined in `/etc/shorewall/zones`.

4.  The `/etc/shorewall/policy`and `/etc/shorewall/rules files`. These files are used to define the connections that are permitted between the remote and local hosts -- in other words, the **Local-host-to-remote-host** and **Remote-host-to-local-host** traffic.

# Defining Remote Zones

Most VPN types are implemented using a virtual network device such as pppN (e.g., ppp0), tunN (e.g., tun0), etc. This means that in most cases, remote zone definition is similar to zones that you have already defined.

`/etc/shorewall/zones`:

    #ZONE           TYPE
    fw              firewall
    net             ipv4
    loc             ipv4
    rem             ipv4

`/etc/shorewall/interfaces`:

    #ZONE           INTERFACE          OPTION
    net             eth0               tcpflags,routefilter
    loc             eth1               -
    rem             ppp0               -

# Allowing Traffic

Normally, you will just allow all traffic between your remote client(s) and the local zone. You can do that with a couple of policies:

    #SOURCE       DESTINATION         POLICY         LOGLEVEL          BURST
    rem           loc                 ACCEPT
    loc           rem                 ACCEPT

Similar policies using \$FW rather than 'loc' can permit traffic from the remote clients to/from the firewall.

# Different Firewall Policies for Different Remote Systems

The /etc/shorewall/hosts file comes into play when:

1.  You have a number of remote networks.

2.  The remote networks have different firewall requirements and you want to divide them into multiple zones.

3.  There is no fixed relationship between the remote networks and virtual network devices (for example, the VPN uses PPTP and remote gateways connect on demand).

In this case, your configuration takes the following approach:

`etc/shorewall/zones`:

    #ZONE           TYPE                 OPTIONS
    net             ipv4
    loc             ipv4
    rem1            ipv4    #Remote LAN 1
    rem2            ipv4    #Remote LAN 2

`/etc/shorewall/interfaces`:

    #ZONE           INTERFACE          OPTION
    net             eth0               tcpflags,routefilter
    loc             eth1               -
    -               tun+               -

/etc/shorewall/hosts:

    #ZONE           HOST(S)            OPTIONS
    rem1            tun+:10.0.0.0/24
    rem2            tun+:10.0.1.0/24

The `/etc/shorewall/hosts` file is also used with kernel 2.6 native IPSEC (see [IPSEC](IPSEC.md)).

# Eliminating the /etc/shorewall/tunnels file

The `/etc/shorewall/tunnels` file provides no functionality that could not be implemented using entries in `/etc/shorewall/rules` and I have elimination of the `/etc/shorewall/tunnels` file as a long-term goal. The following sections show how entries in `/etc/shorewall/tunnels` can be replaced by rules for some common tunnel types.

## IPSEC

/`etc/shorewall/tunnels`:

>     #TYPE           ZONE          GATEWAY          GATEWAY_ZONE
>     ipsec           Z1            1.2.3.4          Z2

`/etc/shorewall/rules`:

>     #ACTION  SOURCE         DEST            PROTO   DPORT   SPORT 
>     ACCEPT   $FW            Z1:1.2.3.4      udp     500
>     ACCEPT   Z1:1.2.3.4     $FW             udp     500
>     ACCEPT   $FW            Z1:1.2.3.4      50
>     ACCEPT   Z1:1.2.3.4     $FW             50
>     ACCEPT   $FW            Z1:1.2.3.4      51
>     ACCEPT   Z1:1.2.3.4     $FW             51
>     ACCEPT   $FW            Z2:1.2.3.4      udp     500
>     ACCEPT   Z2:1.2.3.4     $FW             udp     500

The "noah" option causes the rules for protocol 51 to be eliminated. The "ipsecnat" causes UDP port 4500 to be accepted in both directions. If no GATEWAY ZONE is given then the last two rules above are omitted.

## PPTP

`/etc/shorewall/tunnels`:

>     #TYPE           ZONE          GATEWAY          GATEWAY_ZONE
>     pptpserver      Z1            1.2.3.4

/`etc/shorewall/rules`:

>     #ACTION  SOURCE         DEST            PROTO   DPORT   SPORT 
>
>     ACCEPT   Z1:1.2.3.4     $FW             tcp     1723
>     ACCEPT   $FW            Z1:1.2.3.4      47
>     ACCEPT   Z1:1.2.3.4     $FW             47

Tunnel type "pptpclient" simply reverses the direction of the tcp port 1723 rule.

## OpenVPN

`/etc/shorewall/tunnels`:

>     #TYPE           ZONE          GATEWAY          GATEWAY_ZONE
>     openvpn:port    Z1            1.2.3.4

`/etc/shorewall/rules`:

>     #ACTION  SOURCE         DEST            PROTO   DPORT   SPORT 
>
>     ACCEPT   Z1:1.2.3.4     $FW             udp     port
>     ACCEPT   $FW            Z1:1.2.3.4      udp     port

`/etc/shorewall/tunnels`:

>     #TYPE              ZONE          GATEWAY          GATEWAY_ZONE
>     openvpnclient:port Z1            1.2.3.4

`/etc/shorewall/rules`:

>     #ACTION  SOURCE         DEST            PROTO   DPORT   SPORT 
>
>     ACCEPT   Z1:1.2.3.4     $FW             udp     -       port
>     ACCEPT   $FW            Z1:1.2.3.4      udp     port

`/etc/shorewall/tunnels`:

>     #TYPE              ZONE          GATEWAY          GATEWAY_ZONE
>     openvpnserver:port Z1            1.2.3.4

`/etc/shorewall/rules`:

>     #ACTION  SOURCE         DEST            PROTO   DPORT   SPORT 
>
>     ACCEPT   Z1:1.2.3.4     $FW             udp     port
>     ACCEPT   $FW            Z1:1.2.3.4      udp     -       port

# Links to Other VPN Articles at shorewall.net

- [OpenVPN](OPENVPN.md)

- [IPSEC](IPSEC.md)

- PPTP (PPTP documentation was not ported to shorewall-nft)
