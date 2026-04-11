<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

# Background

The traditional net-tools contain a program called *ifconfig* which is used to configure network devices. ifconfig introduced the concept of *aliased* or *virtual* interfaces. These virtual interfaces have names of the form *interface:integer* (e.g., `eth0:0`) and ifconfig treats them more or less like real interfaces.

    [root@gateway root]# ifconfig eth0:0
    eth0:0    Link encap:Ethernet  HWaddr 02:00:08:3:FA:55
              inet addr:206.124.146.178  Bcast:206.124.146.255  Mask:255.255.255.0
              UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
              Interrupt:11 Base address:0x2000
    [root@gateway root]# 

The ifconfig utility is being gradually phased out in favor of the ip utility which is part of the *iproute* package. The ip utility does not use the concept of aliases or virtual interfaces but rather treats additional addresses on an interface as objects in their own right. The ip utility does provide for interaction with ifconfig in that it allows addresses to be *labeled* where these labels take the form of ipconfig virtual interfaces.

    [root@gateway root]# ip addr show dev eth0
    2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc htb qlen 100
        link/ether 02:00:08:e3:fa:55 brd ff:ff:ff:ff:ff:ff
        inet 206.124.146.176/24 brd 206.124.146.255 scope global eth0
        inet 206.124.146.178/24 brd 206.124.146.255 scope global secondary eth0:0
    [root@gateway root]# 

<div class="note">

One **cannot** type “`ip addr show dev eth0:0`” because “`eth0:0`” is a label for a particular address rather than a device name.

    [root@gateway root]# ip addr show dev eth0:0
    Device "eth0:0" does not exist.
    [root@gateway root]#

</div>

The iptables program doesn't support virtual interfaces in either its “-i” or “-o” command options; as a consequence, Shorewall does not allow them to be used in the /etc/shorewall/interfaces file or anywhere else except as described in the discussion below.

# Adding Addresses to Interfaces

Most distributions have a facility for adding additional addresses to interfaces. If you have already used your distribution's capability to add your required addresses, you can skip this section.

Shorewall provides facilities for automatically adding addresses to interfaces as described in the following section. It is also easy to add them yourself using the **ip** utility. The above alias was added using:

    ip addr add 206.124.146.178/24 brd 206.124.146.255 dev eth0 label eth0:0

You probably want to arrange to add these addresses when the device is started rather than placing commands like the above in one of the Shorewall extension scripts. For example, on RedHat systems, you can place the commands in /sbin/ifup-local:

    #!/bin/sh

    case $1 in
        eth0)
            /sbin/ip addr add 206.124.146.178 dev eth0 label eth0:0
            ;;
    esac

RedHat systems also allow adding such aliases from the network administration GUI (which only works well if you have a graphical environment on your firewall).

On Debian and LEAF/Bering systems, it is as simple as adding the command to the interface definition as follows:

    # Internet interface
    auto eth0
    iface eth0 inet static
            address 206.124.146.176
            netmask 255.255.255.0
            gateway 206.124.146.254
            up ip addr add 206.124.146.178/24 brd 206.124.146.255 dev eth0 label eth0:0

# So how do I handle more than one address on an interface?

The answer depends on what you are trying to do with the interfaces. In the sub-sections that follow, we'll take a look at common scenarios.

<div class="note">

The examples in the following sub-sections assume that the local network is 192.168.1.0/24.

</div>

## Separate Rules

If you need to make a rule for traffic to/from the firewall itself that only applies to a particular IP address, simply qualify the \$FW zone with the IP address.

\[`/etc/shorewall/rules`\]

    #ACTION   SOURCE     DEST                 PROTO      DPORT
    ACCEPT    net        $FW:206.124.146.178  tcp        22

## DNAT

Suppose that I had set up eth0:0 as above and I wanted to port forward from that virtual interface to a web server running in my local zone at 192.168.1.3. That is accomplished by a single rule in the `/etc/shorewall/rules` file:

    #ACTION   SOURCE     DEST                 PROTO      DPORT          SPORT     ORIGDEST
    DNAT      net        loc:192.168.1.3      tcp        80             -         206.124.146.178    

If I wished to forward tcp port 10000 on that virtual interface to port 22 on local host 192.168.1.3, the rule would be:

    #ACTION   SOURCE     DEST                 PROTO      DPORT          SPORT     ORIGDEST
    DNAT      net        loc:192.168.1.3      tcp        80             -         206.124.146.178    
    DNAT      net        loc:192.168.1.3:22   tcp        10000          -         206.124.146.178    

## SNAT

If you wanted to use eth0:0 as the IP address for outbound connections from your local zone (eth1), then in `/etc/shorewall/masq`:

    #INTERFACE             SUBNET          ADDRESS
    eth0                   192.168.1.0/24  206.124.146.178

When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

    #ACTION                SOURCE          DEST                PROTO   PORT
    SNAT(206.124.146.178)  0.0.0.0/0       eth0

Similarly, you want SMTP traffic from local system 192.168.1.22 to have source IP 206.124.146.178:

    #INTERFACE             SUBNET          ADDRESS             PROTO      DPORT
    eth0                   192.168.1.22    206.124.146.178     tcp        25

When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

    #ACTION                SOURCE          DEST                PROTO   PORT
    SNAT(206.124.146.178)  0.0.0.0/0       eth0                tcp     25

Shorewall can create the alias (additional address) for you if you set ADD_SNAT_ALIASES=Yes in `/etc/shorewall/shorewall.con`f.

<div class="warning">

Addresses added by ADD_SNAT_ALIASES=Yes are deleted and re-added during `shorewall restart`. As a consequence, connections using those addresses may be severed.

</div>

Shorewall can create the “label” (virtual interface) so that you can see the created address using ifconfig. In addition to setting ADD_SNAT_ALIASES=Yes, you specify the virtual interface name in the INTERFACE column as follows.

`/etc/shorewall/masq`

    #INTERFACE              SUBNET         ADDRESS
    eth0:0                  192.168.1.0/24 206.124.146.178

When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

    #ACTION                SOURCE          DEST                PROTO   PORT
    SNAT(206.124.146.178)  192.168.1.0/24  eth0

Shorewall can also set up SNAT to round-robin over a range of IP addresses. To do that, you specify a range of IP addresses in the ADDRESS column. If you specify a label in the INTERFACE column, Shorewall will use that label for the first address of the range and will increment the label by one for each subsequent label.

`/etc/shorewall/masq`

    #INTERFACE               SOURCE         ADDRESS
    eth0:0                   192.168.1.0/24 206.124.146.178-206.124.146.180

When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

    #ACTION                              SOURCE          DEST                PROTO   PORT
    SNAT(206.124.146.178-206.24.146.180)  192.168.1.0/24  eth0

The above would create three IP addresses:

    eth0:0 = 206.124.146.178
    eth0:1 = 206.124.146.179
    eth0:2 = 206.124.146.180

## One-to-one NAT

If you wanted to use one-to-one NAT to link `eth0:0` with local address 192.168.1.3, you would have the following in `/etc/shorewall/nat`:

    #EXTERNAL          INTERFACE         INTERNAL     ALL_INTERFACES    LOCAL
    206.124.146.178    eth0              192.168.1.3  no                no

Shorewall can create the alias (additional address) for you if you set ADD_IP_ALIASES=Yes in /etc/shorewall/shorewall.conf.

<div class="warning">

Addresses added by ADD_IP_ALIASES=Yes are deleted and re-added during `shorewall restart`. As a consequence, connections using those addresses may be severed.

</div>

Shorewall can create the “label” (virtual interface) so that you can see the created address using ifconfig. In addition to setting ADD_IP_ALIASES=Yes, you specify the virtual interface name in the INTERFACE column as follows.

`/etc/shorewall/nat`

    #EXTERNAL          INTERFACE         INTERNAL     ALL_INTERFACES    LOCAL
    206.124.146.178    eth0:0            192.168.1.3  no                no

In either case, to create rules in `/etc/shorewall/rules` that pertain only to this NAT pair, you simply qualify the local zone with the internal IP address.

    #ACTION    SOURCE     DEST              PROTO     DPORT
    ACCEPT     net        loc:192.168.1.3   tcp       22

## MULTIPLE SUBNETS

Sometimes multiple IP addresses are used because there are multiple subnetworks configured on a LAN segment. This technique does not provide for any security between the subnetworks if the users of the systems have administrative privileges because in that case, the users can simply manipulate their system's routing table to bypass your firewall/router. Nevertheless, there are cases where you simply want to consider the LAN segment itself as a zone and allow your firewall/router to route between the two subnetworks.

In `/etc/shorewall/zones`:

    #ZONE        TYPE          OPTIONS
    loc          ipv4

In `/etc/shorewall/interfaces`:

    #ZONE       INTERFACE  OPTIONS
    loc         eth1       routeback   

In `/etc/shorewall/rules`, simply specify ACCEPT rules for the traffic that you want to permit.

In `/etc/shorewall/zones`:

    #ZONE        TYPE                 OPTIONS
    loc          ipv4
    loc2         ipv4

In `/etc/shorewall/interfaces`:

    #ZONE       INTERFACE  OPTIONS
    -           eth1          

In `/etc/shorewall/hosts`:

    #ZONE        HOSTS                    OPTIONS
    loc          eth1:192.168.1.0/24
    loc2         eth1:192.168.20.0/24

In `/etc/shorewall/rules`, simply specify ACCEPT rules for the traffic that you want to permit.

For more information on handling multiple networks through a single interface, see [*Routing on One Interface*](../concepts/Multiple_Zones.md).

## Defining a Zone-per-Address

[Shorewall's support for Linux Vservers](Vserver.md) can (mis-)used to create a separate zone per alias. Note that this results in a *partitioning of the firewall zone*. In this usage, you probably want to define an ACCEPT policy between your vserver zones and the firewall zone.
