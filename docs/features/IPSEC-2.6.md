<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

<div class="important">

**Shorewall does not configure IPsec for you** -- it rather configures netfilter to accommodate your IPsec configuration.

</div>

<div class="important">

The information in this article is only applicable if you plan to have IPsec end-points on the same system where Shorewall is used.

</div>

<div class="important">

While this **article shows configuration of IPsec using ipsec-tools**, **Shorewall configuration is exactly the same when using OpenSwan** **or any of the other Swan derivatives**.

</div>

<div class="warning">

When running a Linux kernel prior to 2.6.20, the Netfilter+IPsec and policy match support are broken when used with a bridge device. The problem was corrected in Kernel 2.6.20 as a result of the removal of deferred FORWARD/OUTPUT processing of traffic destined for a bridge. See the ["*Shorewall-perl and Bridged Firewalls*"](../legacy/bridge-Shorewall-perl.md) article.

</div>

# Shorwall and Kernel 2.6 IPsec

This is **not** a HOWTO for Kernel 2.6 IPsec -- for that, please see <http://www.ipsec-howto.org/>.

The 2.6 Linux Kernel introduced new facilities for defining encrypted communication between hosts in a network. The network administrator defines a set of Security Policies which are stored in the kernel as a Security Policy Database (SPD). Security policies determine which traffic is subject to encryption. Security Associations are created between pairs of hosts in the network (one SA for traffic in each direction); these SAs define how traffic is to be encrypted. Outgoing traffic that is to be encrypted according to the contents of the SPD requires an appropriate SA to exist. SAs may be created manually using `setkey`(8) but most often, they are created by a cooperative process involving the ISAKMP protocol and a daemon included in your IPsec package (StrongSwan, LibreSwan, ipsec-tools/Racoon, etc.) . Incoming traffic is verified against the SPD to ensure that no unencrypted traffic is accepted in violation of the administrator's policies.

There are three ways in which IPsec traffic can interact with Shorewall policies and rules:

1.  Traffic that is encrypted on the firewall system. The traffic passes through Netfilter twice -- first as unencrypted then encrypted.

2.  Traffic that is decrypted on the firewall system. The traffic passes through Netfilter twice -- first as encrypted then as unencrypted.

3.  Encrypted traffic that is passed through the firewall system. The traffic passes through Netfilter once.

In cases 1 and 2, the encrypted traffic is handled by entries in `/etc/shorewall/tunnels` (don't be mislead by the name of the file -- *transport mode* encrypted traffic is also handled by entries in that file). The unencrypted traffic is handled by normal rules and policies.

Under the 2.4 Linux Kernel, the association of unencrypted traffic and zones was made easy by the presence of IPsec pseudo-interfaces with names of the form `ipsecN` (e.g. `ipsec0`). Outgoing unencrypted traffic (case 1.) was sent through an `ipsecN` device while incoming unencrypted traffic (case 2) arrived from an `ipsecN` device. The 2.6 kernel-based implementation does away with these pseudo-interfaces. Outgoing traffic that is going to be encrypted and incoming traffic that has been decrypted must be matched against policies in the SPD and/or the appropriate SA.

Shorewall provides support for policy matching in three ways:

1.  In `/etc/shorewall/masq` (`/etc/shorewall/snat` when running Shorewall 5.0.14 or later), traffic that will later be encrypted is exempted from MASQUERADE/SNAT using existing entries. If you want to MASQUERADE/SNAT outgoing traffic that will later be encrypted, you must include the appropriate indication in the IPSEC column in that file.

2.  The``[`/etc/shorewall/zones`](https://shorewall.org/manpages/shorewall-zones.html) file allows you to associate zones with traffic that will be encrypted or that has been decrypted.

3.  A new option (**ipsec**) has been provided for entries in `/etc/shorewall/hosts`. When an entry has this option specified, traffic to/from the hosts described in the entry is assumed to be encrypted.

In summary, Shorewall provides the facilities to replace the use of IPsec pseudo-interfaces in zone and MASQUERADE/SNAT definition.

There are two cases to consider:

1.  Encrypted communication is used to/from all hosts in a zone.

    The value **ipsec** is placed in the TYPE column of the `/etc/shorewall/zones` entry for the zone.

2.  By default, encrypted communication is not used to communicate with the hosts in a zone.

    The value **ipv4** is placed in the TYPE column of the `/etc/shorewall/zones` entry for the zone and the new **ipsec** option is specified in `/etc/shorewall/hosts` for any hosts requiring secure communication.

<div class="note">

For simple zones such as are shown in the following examples, the two techniques are equivalent and are used interchangeably.

</div>

<div class="note">

It is redundant to have **ipsec** in the TYPE column of the `/etc/shorewall/zones` entry for a zone and to also have the **ipsec** option in `/etc/shorewall/hosts` entries for that zone.

</div>

Finally, the OPTIONS, IN OPTIONS and OUT OPTIONS columns in /etc/shorewall/zones can be used to match the zone to a particular (set of) SA(s) used to encrypt and decrypt traffic to/from the zone and the security policies that select which traffic to encrypt/decrypt.

<div class="important">

This article provides guidance regarding configuring Shorewall to use with IPsec. For configuring IPsec itself, consult your IPsec product's documentation.

</div>

# IPsec Gateway on the Firewall System

Suppose that we have the following situation:

We want systems in the 192.168.1.0/24 sub-network to be able to communicate with systems in the 10.0.0.0/8 network. We assume that on both systems A and B, eth0 is the Internet interface.

To make this work, we need to do two things:

1.  Open the firewall so that the IPsec tunnel can be established (allow the ESP protocol and UDP Port 500).

2.  Allow traffic through the tunnel.

Opening the firewall for the IPsec tunnel is accomplished by adding an entry to the `/etc/shorewall/tunnels` file.

In `/etc/shorewall/tunnels` on system A, we need the following

> `/etc/shorewall/tunnels` — System A:
>
>     #TYPE         ZONE        GATEWAY             GATEWAY_ZONE
>     ipsec         net         134.28.54.2
>
> `/etc/shorewall/tunnels` — System B:
>
>     #TYPE         ZONE        GATEWAY             GATEWAY_ZONE
>     ipsec         net         206.162.148.9

<div class="note">

If either of the endpoints is behind a NAT gateway then the tunnels file entry on the **other** endpoint should specify a tunnel type of ipsecnat rather than ipsec and the GATEWAY address should specify the external address of the NAT gateway.

</div>

You need to define a zone for the remote subnet or include it in your local zone. In this example, we'll assume that you have created a zone called “vpn” to represent the remote subnet.

> `/etc/shorewall/zones` — Systems A and B:
>
>     #ZONE          TYPE             OPTIONS             IN_OPTIONS   OUT_OPTIONS
>     net            ipv4
>     vpn            ipv4

Remember the assumption that both systems A and B have eth0 as their Internet interface.

You must define the vpn zone using the `/etc/shorewall/hosts` file. The hosts file entries below assume that you want the remote gateway to be part of the vpn zone — If you don't wish the remote gateway included, simply omit its IP address from the HOSTS column.

> `/etc/shorewall/hosts` — System A
>
>     #ZONE             HOSTS                                OPTIONS
>     vpn               eth0:10.0.0.0/8,134.28.54.2          ipsec
>
> `/etc/shorewall/hosts` — System B
>
>     #ZONE             HOSTS                                OPTIONS
>     vpn               eth0:192.168.1.0/24,206.162.148.9    ipsec

If you want to keep things simple, you can simply not restrict the set of addresses in the ipsec zones:

>     #ZONE             HOSTS                                OPTIONS
>     vpn               eth0:0.0.0.0/0                       ipsec

Assuming that you want to give each local network free access to the remote network and vice versa, you would need the following `/etc/shorewall/policy` entries on each system:

>     #SOURCE          DEST            POLICY          LEVEL       BURST:LIMIT
>     loc              vpn             ACCEPT
>     vpn              loc             ACCEPT

If you need access from each firewall to hosts in the other network, then you could add:

>     #SOURCE          DEST            POLICY          LEVEL       BURST:LIMIT
>     $FW              vpn             ACCEPT

If you need access between the firewall's, you should describe the access in your /etc/shorewall/rules file. For example, to allow SSH access from System B, add this rule on system A:

>     #ACTION    SOURCE           DEST      PROTO        POLICY
>     ACCEPT     vpn:134.28.54.2  $FW

<div class="warning">

If you have hosts that access the Internet through an IPsec tunnel, then it is a good idea to set the MSS value for traffic from those hosts explicitly in the `/etc/shorewall/zones` file. For example, if hosts in the **vpn** zone access the Internet through an ESP tunnel then the following entry would be appropriate:

    #ZONE   TYPE    OPTIONS                 IN_OPTIONS              OUT_OPTIONS
    vpn     ipsec   mode=tunnel             mss=1400

Note that if you are using ipcomp, you should omit the mode specification:

    #ZONE   TYPE    OPTIONS                 IN_OPTIONS              OUT_OPTIONS
    vpn     ipsec   -                       mss=1400

You should also set FASTACCEPT=No in shorewall.conf to ensure that both the SYN and SYN,ACK packets have their MSS field adjusted.

Note that CLAMPMSS=Yes in `shorewall.conf` isn't effective with the 2.6 native IPsec implementation because there is no separate IPsec device with a lower mtu as there was under the 2.4 and earlier kernels.

</div>

# Mobile System (Road Warrior)

Suppose that you have a laptop system (B) that you take with you when you travel and you want to be able to establish a secure connection back to your local network.

You need to define a zone for the laptop or include it in your local zone. In this example, we'll assume that you have created a zone called “vpn” to represent the remote host.

> `/etc/shorewall/zones` — System A
>
>     #ZONE          TYPE             OPTIONS             IN_OPTIONS   OUT_OPTIONS
>     net            ipv4
>     vpn            ipsec
>     loc            ipv4

In this instance, the mobile system (B) has IP address 134.28.54.2 but that cannot be determined in advance. In the `/etc/shorewall/tunnels` file on system A, the following entry should be made:

>     #TYPE         ZONE        GATEWAY             GATEWAY_ZONE
>     ipsec         net         0.0.0.0/0           vpn

<div class="note">

the GATEWAY_ZONE column contains the name of the zone corresponding to peer subnetworks. This indicates that the gateway system itself comprises the peer subnetwork; in other words, the remote gateway is a standalone system.

</div>

The VPN zone is defined using the /etc/shorewall/hosts file:

> `/etc/shorewall/hosts` — System A:
>
>     #ZONE             HOSTS                  OPTIONS
>     vpn               eth0:0.0.0.0/0

You will need to configure your “through the tunnel” policy as shown under the first example above.

On the laptop:

> `/etc/shorewall/zones` - System B:
>
>     #ZONE          TYPE             OPTIONS             IN_OPTIONS   OUT_OPTIONS
>     vpn            ipsec
>     net            ipv4
>     loc            ipv4
>
> `/etc/shorewall/tunnels` - System B:
>
>     #TYPE         ZONE        GATEWAY             GATEWAY_ZONE
>     ipsec         net         206.162.148.9       vpn
>
> `/etc/shorewall/hosts` - System B:
>
>     #ZONE             HOSTS                  OPTIONS
>     vpn               eth0:0.0.0.0/0

# Mobile System (Road Warrior) with Layer 2 Tunneling Protocol (L2TP)

This section is based on the previous section. Please make sure that you read it thoroughly and understand it. The setup described in this section is more complex because you are including an additional layer of tunneling. Again, make sure that you have read the previous section and it is highly recommended to have the IPsec-only configuration working first.

Additionally, this section assumes that you are running IPsec, xl2tpd and pppd on the same system that is running shorewall. However, configuration of these additional services is beyond the scope of this document.

Getting layer 2 tunneling to work is an endeavour unto itself. However, if you succeed it can be very convenient. Reasons why you might want configure layer 2 tunneling protocol (L2TP):

1.  You want to give your road warrior an address that is in the same segment as the other hosts on your network.

2.  Your road warriors are using a legacy operating system (such as MS Windows or Mac OS X) and you do not want them to have to install third party software in order to connect to the VPN (both MS Windows and Mac OS X include VPN clients which natively support L2TP over IPsec, but not plain IPsec).

3.  You like a challenge.

Since the target for a VPN including L2TP will (almost) never be a road warrior running Linux, I will not include the client side of the configuration.

The first thing that needs to be done is to create a new zone called “l2tp” to represent the tunneled layer 2 traffic.

> `/etc/shorewall/zones` — System A
>
>     #ZONE          TYPE             OPTIONS             IN_OPTIONS   OUT_OPTIONS
>     et            ipv4
>     vpn            ipsec
>     l2tp           ipv4
>     loc            ipv4

Since the L2TP will require the use of pppd, you will end up with one or more ppp interfaces (each representing an individual road warrior connection) for which you will need to account. This can be done by modifying the interfaces file. (Modify with additional options as needed.)

> `/etc/shorewall/interfaces`:
>
>     #ZONE   INTERFACE       BROADCAST       OPTIONS
>     net     eth0            detect          routefilter
>     loc     eth1            192.168.1.255
>     l2tp    ppp+            -

The next thing that must be done is to adjust the policy so that the traffic can go where it needs to go.

First, you need to decide if you want for hosts in your local zone to be able to connect to your road warriors. You may or may not want to allow this. For example, one reason you might want to allow this is so that your support personnel can use ssh, VNC or remote desktop to fix a problem on the road warrior's laptop.

Second, you need to decide if you want the road warrior to have access to hosts on the local network. You generally want to allow this. For example, if you have DNS servers on your local network that you want the road warrior to use. Or perhaps the road warrior needs to mount NFS shares or needs to access intranet sites which are not visible from the public Internet.

Finally, you need to decide if you want the road warriors to be able to access the public Internet. You probably want to do this, unless you are trying to create a situation where when the road warrior connects to the VPN, it is no longer possible to send traffic from the road warrior's machine to the public Internet. Please note that this not really a strong security measure. The road warrior could trivially modify the routing table on the remote machine to have only traffic destined for systems on the VPN local network go through the secure channel. The rest of the traffic would simply travel over an Ethernet or wireless interface directly to the public Internet. In fact, this latter situation is dangerous, as a simple mistake could easily create a situation where the road warrior's machine is acting as a router between your local network and the public Internet, which you certainly do not want to happen. In short, it is best to allow the road warrior to connect to the public Internet by default.

> `/etc/shorewall/policy`:
>
>     #SOURCE         DEST            POLICY          LOGLEVEL       LIMIT
>     $FW             all             ACCEPT
>     loc             net             ACCEPT
>     loc             l2tp            ACCEPT # Allows local machines to connect to road warriors
>     l2tp            loc             ACCEPT # Allows road warriors to connect to local machines
>     l2tp            net             ACCEPT # Allows road warriors to connect to the Internet
>     net             all             DROP            info
>     # The FOLLOWING POLICY MUST BE LAST
>     all             all             REJECT          info

The final step is to modify your rules file. There are three important components. First, you must allow the l2tp traffic to reach the xl2tpd process running on the firewall machine. Second, you must add rules to open up ports on the firewall to the road warrior for services which are running on the firewall. For example, if you are running a webserver on the firewall that must be accessible to road warriors. The reason for the second step is that the policy does not by default allow unrestricted access to the firewall itself. Finally, you should protect an exploit where an attacker can exploit your LT2P server due to a hole in the way that L2TP interacts with UDP connection tracking.

> `/etc/shorewall/rules`:
>
>     #ACTION         SOURCE  DEST    PROTO   DPORT   SPORT
>     ?SECTION ESTABLISHED
>     # Prevent IPsec bypass by hosts behind a NAT gateway
>     L2TP(REJECT)    net     $FW
>     REJECT          $FW     net     udp     -       1701
>     ?SECTION NEW
>     # l2tp over the IPsec VPN
>     ACCEPT          vpn     $FW     udp     1701
>     # webserver that can only be accessed internally
>     HTTP(ACCEPT)    loc     $FW
>     HTTP(ACCEPT)    l2tp    $FW
>     HTTPS(ACCEPT)   loc     $FW
>     HTTPS(ACCEPT)   l2tp    $FW

# Transport Mode

In today's wireless world, it is often the case that individual hosts in a network need to establish secure connections with the other hosts in that network. In that case, IPsec transport mode is an appropriate solution.

Shorewall configuration goes as follows:

> `/etc/shorewall/interfaces`:
>
>     #ZONE   INTERFACE       OPTIONS
>     net     eth0            routefilter,dhcp,tcpflags
>
> `/etc/shorewall/tunnels`:
>
>     #TYPE          ZONE             GATEWAY         GATEWAY
>     #                                               ZONE
>     ipsec          net              192.168.20.0/24 loc
>
> `/etc/shorewall/zones`:
>
>     #ZONE          TYPE             OPTIONS             IN           OUT
>     #                                                   OPTIONS      OPTIONS
>     loc            ipsec            mode=transport
>     net            ipv4
>
> `/etc/shorewall/hosts`:
>
>     #ZONE           HOST(S)                         OPTIONS
>     loc             eth0:192.168.20.0/24
>
> It is worth noting that although *loc* is a sub-zone of *net*, because *loc* is an IPsec-only zone it does not need to be defined before *net* in */etc/shorewall/zones*.
>
> `/etc/shorewall/policy`:
>
>     #SOURCE         DEST            POLICY          LOGLEVEL       LIMIT
>     $FW             all             ACCEPT
>     loc             $FW             ACCEPT
>     net             loc             NONE
>     loc             net             NONE
>     net             all             DROP            info
>     # The FOLLOWING POLICY MUST BE LAST
>     all             all             REJECT          info
>
> Since there are no cases where net\<-\>loc traffic should occur, NONE policies are used.

# IPCOMP

If your IPsec tunnel or transport mode connection fails to work with Shorewall started and you see log messages like the following when you try to use the connection, the problem is that ip compression is being used.

    Feb 18 23:43:52 vpngw kernel: Shorewall:vpn2fw:REJECT:IN=eth2 OUT= MAC=00:e0:81:32:b3:5e:00:18:de:12:e5:15:08:00
                                  SRC=172.29.59.58 DST=172.29.59.254 LEN=85 TOS=0x00 PREC=0x00 TTL=64 ID=25600 DF PROTO=4

The solution is to add an IPCOMP tunnel to /etc/shorewall/tunnels as follows:

    #TYPE                   ZONE    GATEWAY         GATEWAY
    #                                               ZONE
    ipip                    vpn     0.0.0.0/0

The above assumes that the name of your IPsec vpn zone is *vpn*.

<div class="important">

Note that this protocol 4 (IPIP) traffic appears to originate in the vpn zone, but it's source IP address is that of the remote gateway. As a consequence, that address must be included in the definition of the remote zone. If you haven't done that, the traffic will be dropped in the INPUT chain.

</div>

# Using SNAT to Force Traffic over an IPsec Tunnel

Cases can arise where you need to use an IPsec tunnel to access a remote network, but you have no control over the associated security polices. In such cases, the resulting tunnel is accessible from your firewall but not from your local networks.

Let's take an example:

- Remote gateway 192.0.2.26

- Remote subnet 172.22.4.0/24

- Your public IP address is 192.0.2.199

- Your Internet-facing interface is eth0

- Your local network is 192.168.219.0/24

- You want to access 172.22.4.0/24 from 192.168.219.0/24

- The IPsec tunnel is configured between 172.22.4.0/24 and 192.0.2.199

You need to configure as follows.

/etc/shorewall/zones:

    #ZONE        TYPE       OPTIONS
    ...
    vpn          ip         # Note that the zone cannot be declared as type ipsec
    ...

/etc/shorewall/interfaces:

    #ZONE         INTERFACE                 OPTIONS
    net           eth0                      nets=(!172.22.4.0/24),...   # You must exclude the remote network from the net zone

/etc/shorewall/hosts:

    #ZONE         HOSTS                     OPTIONS
    vpn           eth0:172.22.4.0/24        mss=1380,destonly
    vpn           eth0:0.0.0.0/0            mss=1380,ipsec

/etc/shorewall/snat:

    SNAT(192.0.2.199)    192.168.219.0/24      eth0:172.22.4.0/24

/etc/shorewall/tunnels:

    #TYPE            ZONE      GATEWAY            GATEWAY_ZONE
    ipsec            net       192.0.2.26         vpn
