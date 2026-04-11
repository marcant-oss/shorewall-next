<div class="caution">

**This article applies to Shorewall 4.4 and later.**

</div>

# Background

Systems where Shorewall runs normally function as routers. In the context of the Open System Interconnect (OSI) reference model, a router operates at layer 3, Shorewall may also be deployed on a GNU Linux System that acts as a bridge. Bridges are layer 2 devices in the OSI model (think of a bridge as an Ethernet switch).

Some differences between routers and bridges are:

1.  Routers determine packet destination based on the destination IP address, while bridges route traffic based on the destination MAC address in the Ethernet frame.

2.  As a consequence of the first difference, routers can be connected to more than one IP network while a bridge/firewall may be part of only a single network (see below).

3.  In most configurations, routers don't forward broadcast packets while bridges do.

    <div class="note">

    Section 4 of RFC 1812 describes the conditions under which a router may or must forward broadcasts.

    </div>

# Requirements

Note that if you need a bridge but do not need to restrict the traffic through the bridge then any version of Shorewall will work. See the [Simple Bridge documentation](../features/SimpleBridge.md) for details.

In order to use Shorewall as a bridging firewall:

- Your kernel must contain bridge support (CONFIG_BRIDGE=m or CONFIG_BRIDGE=y).

- Your kernel must contain bridge/netfilter integration (CONFIG_BRIDGE_NETFILTER=y).

- Your kernel must contain Netfilter physdev match support (CONFIG_IP_NF_MATCH_PHYSDEV=m or CONFIG_IP_NF_MATCH_PHYSDEV=y). Physdev match is standard in the 2.6 and later kernel series but must be patched into the 2.4 kernels (see <http://bridge.sf.net>).

- Your iptables must contain physdev match support and must support multiple instances of '-m physdev' in a single rule. iptables 1.3.6 and later contain this support.

- You must have the bridge utilities (bridge-utils) package installed.

# Application

The following diagram shows a typical application of a bridge/firewall. There is already an existing router in place whose internal interface supports a network, and you want to insert a firewall between the router, and the systems in the local network. In the example shown, the network uses RFC 1918 addresses but that is not a requirement; the bridge would work exactly the same if public IP addresses were used (remember that the bridge doesn't deal with IP addresses).

There are a several key differences in this setup and a normal Shorewall configuration:

- The Shorewall system (the Bridge/Firewall) has only a single IP address even though it has two Ethernet interfaces! The IP address is configured on the bridge itself, rather than on either of the network cards.

- The systems connected to the LAN are configured with the router's IP address (192.168.1.254 in the above diagram) as their default gateway.

- `traceroute` doesn't detect the Bridge/Firewall as an intermediate router.

- If the router runs a DHCP server, the hosts connected to the LAN can use that server without having `dhcrelay` running on the Bridge/Firewall.

<div class="warning">

Inserting a bridge/firewall between a router and a set of local hosts only works if those local hosts form a single IP network. In the above diagram, all of the hosts in the loc zone are in the 192.168.1.0/24 network. If the router is routing between several local networks through the same physical interface (there are multiple IP networks sharing the same LAN), then inserting a bridge/firewall between the router and the local LAN won't work.

</div>

There are other possibilities here -- there could be a hub or switch between the router and the Bridge/Firewall and there could be other systems connected to that switch. All of the systems on the local side of the **router** would still be configured with IP addresses in 192.168.1.0/24 as shown below.

# Configuring the Bridge

Configuring the bridge itself is quite simple and uses the `brctl` utility from the bridge-utils package. Bridge configuration information may be found at <http://bridge.sf.net>.

Unfortunately, many Linux distributions don't have good bridge configuration tools, and the network configuration GUIs don't detect the presence of bridge devices. Here is an excerpt from a Debian `/etc/network/interfaces` file for a two-port bridge with a static IP address:

>     auto br0
>     iface br0 inet static
>             address 192.168.1.253
>             netmask 255.255.255.0
>             network 192.168.1.0
>             broadcast 192.168.1.255
>
>             pre-up /sbin/ip link set eth0 up
>             pre-up /sbin/ip link set eth1 up
>             pre-up /usr/sbin/brctl addbr br0
>             pre-up /usr/sbin/brctl addif br0 eth0
>             pre-up /usr/sbin/brctl addif br0 eth1
>             
>             pre-down /usr/sbin/brctl delif br0 eth0
>             pre-down /sbin/ip link set eth0 down
>             pre-down /usr/sbin/brctl delif br0 eth1
>             pre-down /sbin/ip link set eth1 down
>             
>             post-down /usr/sbin/brctl delbr br0

While it is not a requirement to give the bridge an IP address, doing so allows the bridge/firewall to access other systems and allows the bridge/firewall to be managed remotely. The bridge must also have an IP address for REJECT rules and policies to work correctly — otherwise REJECT behaves the same as DROP. It is also a requirement for bridges to have an IP address if they are part of a [bridge/router](#bridge-router).

<div class="important">

Get your bridge configuration working first, including bridge startup at boot, before you configure and start Shorewall.

</div>

The bridge may have its IP address assigned via DHCP. Here's an example of an /etc/sysconfig/network/ifcfg-br0 file from a SUSE system:

>     BOOTPROTO='dhcp'
>     REMOTE_IPADDR=''
>     STARTMODE='onboot'
>     UNIQUE='3hqH.MjuOqWfSZ+C'
>     WIRELESS='no'
>     MTU=''

Here's an /etc/sysconfig/network-scripts/ifcfg-br0 file for a Mandriva system:

>     DEVICE=br0
>     BOOTPROTO=dhcp
>     ONBOOT=yes

On both the SUSE and Mandriva systems, a separate script is required to configure the bridge itself.

Here are scripts that I used on a SUSE 9.1 system.

> `/etc/sysconfig/network/ifcfg-br0`
>
>     BOOTPROTO='dhcp'
>     REMOTE_IPADDR=''
>     STARTMODE='onboot'
>     UNIQUE='3hqH.MjuOqWfSZ+C'
>     WIRELESS='no'
>     MTU=''
>
> `/etc/init.d/bridge`
>
>     #!/bin/sh
>
>     ################################################################################
>     #   Script to create a bridge
>     #
>     #     (c) 2004 - Tom Eastep (teastep@shorewall.net)
>     #
>     #   Modify the following variables to match your configuration
>     #
>     #### BEGIN INIT INFO
>     # Provides:       bridge
>     # Required-Start: coldplug
>     # Required-Stop:
>     # Default-Start:  2 3 5
>     # Default-Stop:   0 1 6
>     # Description:    starts and stops a bridge
>     ### END INIT INFO
>     #
>     # chkconfig: 2345 05 89
>     # description: GRE/IP Tunnel
>     #
>     ################################################################################
>
>
>     PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
>
>     INTERFACES="eth1 eth0"
>     BRIDGE="br0"
>     MODULES="tulip"
>
>     do_stop() {
>         echo "Stopping Bridge $BRIDGE"
>         brctl delbr $BRIDGE
>         for interface in $INTERFACES; do
>             ip link set $interface down
>         done
>     }
>
>     do_start() {
>
>           echo "Starting Bridge $BRIDGE"
>           for module in $MODULES; do
>               modprobe $module
>           done
>
>           sleep 5
>
>           for interface in $INTERFACES; do
>               ip link set $interface up
>           done
>
>           brctl addbr $BRIDGE
>
>           for interface in $INTERFACES; do
>               brctl addif $BRIDGE $interface
>           done
>     }
>
>     case "$1" in
>       start)
>           do_start
>         ;;
>       stop)
>           do_stop
>         ;;
>       restart)
>           do_stop
>           sleep 1
>           do_start
>         ;;
>       *)
>         echo "Usage: $0 {start|stop|restart}"
>         exit 1
>     esac
>     exit 0

Axel Westerhold has contributed this example of configuring a bridge with a static IP address on a Fedora System (Core 1 and Core 2 Test 1). Note that these files also configure the bridge itself, so there is no need for a separate bridge config script.

> `/etc/sysconfig/network-scripts/ifcfg-br0:`
>
>     DEVICE=br0
>     TYPE=Bridge
>     IPADDR=192.168.50.14
>     NETMASK=255.255.255.0
>     ONBOOT=yes
>
> `/etc/sysconfig/network-scripts/ifcfg-eth0:`
>
>     DEVICE=eth0
>     TYPE=ETHER
>     BRIDGE=br0
>     ONBOOT=yes
>
> `/etc/sysconfig/network-scripts/ifcfg-eth1:`
>
>     DEVICE=eth1
>     TYPE=ETHER
>     BRIDGE=br0
>     ONBOOT=yes

Florin Grad at Mandriva provides this script for configuring a bridge:

>     #!/bin/sh
>     # chkconfig: 2345 05 89
>     # description: Layer 2 Bridge
>     #
>
>     [ -f /etc/sysconfig/bridge ] && . /etc/sysconfig/bridge
>
>     PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
>
>     do_stop() {
>         echo "Stopping Bridge"
>         for i in $INTERFACES $BRIDGE_INTERFACE ; do
>             ip link set $i down
>         done
>         brctl delbr $BRIDGE_INTERFACE
>     }
>
>     do_start() {
>
>        echo "Starting Bridge"
>        for i in $INTERFACES ; do
>             ip link set $i up
>        done
>        brctl addbr br0
>        for i in $INTERFACES ; do
>             ip link set $i up
>             brctl addif br0 $i 
>        done
>        ifup $BRIDGE_INTERFACE 
>     }
>
>     case "$1" in
>       start)
>           do_start
>         ;;
>       stop)
>           do_stop
>         ;;
>       restart)
>           do_stop
>           sleep 1
>           do_start
>         ;;
>       *)
>         echo "Usage: $0 {start|stop|restart}"
>         exit 1
>     esac
>     exit 0
>
> The `/etc/sysconfig/bridge file`:
>
>     BRIDGE_INTERFACE=br0          #The name of your Bridge
>     INTERFACES="eth0 eth1"        #The physical interfaces to be bridged

Andrzej Szelachowski contributed the following.

>     Here is how I configured bridge in Slackware:
>
>     1) I had to compile bridge-utils (It's not in the standard distribution)
>     2) I've created rc.bridge in /etc/rc.d:
>
>     #########################
>     #! /bin/sh
>
>     ifconfig eth0 0.0.0.0
>     ifconfig eth1 0.0.0.0
>     #ifconfig lo 127.0.0.1 #this line should be uncommented if you don't use rc.inet1
>
>     brctl addbr most
>
>     brctl addif most eth0
>     brctl addif most eth1
>
>     ifconfig most 192.168.1.31 netmask 255.255.255.0 up 
>     #route add default gw 192.168.1.1 metric 1 #this line should be uncommented if
>                                                #you don't use rc.inet1
>     #########################
>
>     3) I made rc.bridge executable and added the following line to /etc/rc.d/rc.local
>
>     /etc/rc.d/rc.bridge 

Joshua Schmidlkofer writes:

>     Bridge Setup for Gentoo
>
>     #install bridge-utils
>     emerge bridge-utils
>
>     ## create a link for net.br0
>     cd /etc/init.d
>     ln -s net.eth0 net.br0
>
>     # Remove net.eth*, add net.br0 and bridge.
>     rc-update del net.eth0
>     rc-update del net.eth1
>     rc-update add net.br0 default
>     rc-update add bridge boot
>
>
>
>     /etc/conf.d/bridge:
>
>       #bridge contains the name of each bridge you want created.
>       bridge="br0"
>
>       # bridge_<bridge>_devices contains the devices to use at bridge startup.
>       bridge_br0_devices="eth0 eth1"
>
>     /etc/conf.d/net
>
>        iface_br0="10.0.0.1     broadcast 10.0.0.255 netmask 255.255.255.0"
>        #for dhcp:
>        #iface_br0="dhcp"
>        #comment this out if you use dhcp.
>        gateway="eth0/10.0.0.1" 

Users who successfully configure bridges on other distributions, with static or dynamic IP addresses, are encouraged to send [me](mailto:webmaster@shorewall.net) their configuration so I can post it here.

# Configuring Shorewall

As described above, Shorewall bridge support requires the physdev match feature of Netfilter/iptables. Physdev match allows rules to be triggered based on the bridge port that a packet arrived on and/or the bridge port that a packet will be sent over. The latter has proved to be problematic because it requires that the evaluation of rules be deferred until the destination bridge port is known. This deferral has the unfortunate side effect that it makes IPsec Netfilter filtration incompatible with bridges. To work around this problem, in kernel version 2.6.20 the Netfilter developers decided to remove the deferred processing in two cases:

- When a packet being sent through a bridge entered the firewall on another interface and was being forwarded to the bridge.

- When a packet originating on the firewall itself is being sent through a bridge.

Notice that physdev match was only weakened with respect to the destination bridge port -- it remains fully functional with respect to the source bridge port.

To deal with the asymmetric nature of the new physdev match, Shorewall supports a new type of zone - a Bridge Port (BP) zone. Bridge port zones have a number of restrictions:

- BP zones may only be associated with bridge ports.

- All ports associated with a given BP zone must be on the same bridge.

- Policies from a non-BP zone to a BP are disallowed.

- Rules where the SOURCE is a non-BP zone and the DEST is a BP zone are disallowed.

In /etc/shorewall/zones, BP zones are specified using the **bport** (or **bport4**) keyword. If your version of `shorewall.conf` contains the **BRIDGING** option, it must be set to **No**.

In the scenario pictured above, there would probably be two BP zones defined -- one for the Internet and one for the local LAN so in `/etc/shorewall/zones`:

    #ZONE           TYPE            OPTIONS
    fw              firewall
    world           ipv4  
    net:world       bport
    loc:world       bport

The *world* zone can be used when defining rules whose source zone is the firewall itself (remember that fw-\>\<BP zone\> rules are not allowed).

A conventional two-zone policy file is appropriate here — `/etc/shorewall/policy`:

    #SOURCE     DEST        POLICY        LOGLEVEL       LIMIT
    loc         net         ACCEPT
    net         all         DROP          info
    all         all         REJECT        info

In `/etc/shorewall/shorewall.conf`:

    IMPLICIT_CONTINUE=No

Bridges use a special syntax in `/etc/shorewall/interfaces`. Assuming that the router is connected to `eth0` and the switch to `eth1`:

    #ZONE    INTERFACE      OPTIONS
    world    br0            bridge
    net      br0:eth0
    loc      br0:eth1

The *world* zone is associated with the bridge itself which is defined with the **bridge** option. Bridge port entries may not have any OPTIONS.

<div class="note">

When a bridge is configured without an IP address, the `optional` option must also be specified.

</div>

When Shorewall is stopped, you want to allow only local traffic through the bridge — `/etc/shorewall/routestopped`:

    #INTERFACE      HOST(S)         OPTIONS
    br0             192.168.1.0/24  routeback

The `/etc/shorewall/rules` file from the two-interface sample is a good place to start for defining a set of firewall rules.

# Multiple Bridges with Wildcard Ports

It is sometimes required to configure multiple bridges on a single firewall/gateway. The following seemingly valid configuration results in a compile-time error

ERROR: Duplicate Interface Name (p+)

`/etc/shorewall/zones`:

           #ZONE            TYPE    
           fw               firewall
           world            ipv4
           z1:world         bport4
           z2:world         bport4

`/etc/shorewall/interfaces`:

           #ZONE            INTERFACE       OPTIONS
           world            br0             bridge
           world            br1             bridge
           z1               br0:p+
           z2               br1:p+

The reason is that the Shorewall implementation requires each bridge port to have a unique name. The `physical` interface option was added in Shorewall 4.4.4 to work around this problem. The above configuration may be defined using the following in `/etc/shorewall/interfaces`:

           #ZONE            INTERFACE       OPTIONS
           world            br0             bridge
           world            br1             bridge
           z1               br0:x+          physical=p+
           z2               br1:y+          physical=p+

In this configuration, 'x+' is the logical name for ports p+ on bridge br0 while 'y+' is the logical name for ports p+ on bridge br1.

If you need to refer to a particular port on br1 (for example p1023), you write it as y1023; Shorewall will translate that name to p1023 when needed.

Example from /etc/shorewall/rules:

           #ACTION    SOURCE    DEST       PROTO    DPORT
           REJECT     z1:x1023  z1:x1024   tcp      1234

# Combination Router/Bridge

A system running Shorewall doesn't have to be exclusively a bridge or a router -- it can act as both, which is also know as a brouter. Here's an example:

This is basically the same setup as shown in the [Shorewall Setup Guide](../reference/shorewall_setup_guide.md) with the exception that the DMZ is bridged rather than using Proxy ARP. Changes in the configuration shown in the Setup Guide are as follows:

1.  The `/etc/shorewall/proxyarp` file is empty in this configuration.

2.  The `/etc/shorewall/zones` file is modified:

        #ZONE                   TYPE          OPTIONS
        fw                      firewall
        pub                     ipv4          #zone containing all public addresses
        net:pub                 bport4
        dmz:pub                 bport4
        loc                     ipv4

3.  The `/etc/shorewall/interfaces` file is as follows:

        #ZONE    INTERFACE      OPTIONS
        pub      br0            routefilter,bridge
        net      br0:eth0 
        dmz      br0:eth2
        loc      eth1

4.  The DMZ systems need a route to the 192.168.201.0/24 network via 192.0.2.176 to enable them to communicate with the local network.

5.  This configuration does not support separate fw-\>dmz and fw-\>net policies/rules; similarly, it does not support separate loc-\>dmz and loc-\>net rules. This will make it a bit trickier to configure the rules. I suggest something like the following:

    `/etc/shorewall/params`:

        SERVERS=192.0.2.177,192.0.2.178   #IP Addresses of hosts in the DMZ
        DMZ=pub:$SERVERS                  #Use in place of 'dmz' in rule DEST
        NET=pub:!$SERVERS                 #Use in place of 'net' in rule DEST

    `/etc/shorewall/policy`:

        #SOURCE         DEST            POLICY          LEVEL
        loc             pub             ACCEPT
        loc             $FW             REJECT          info
        loc             all             REJECT          info

        $FW             pub             REJECT          info
        $FW             loc             REJECT          info
        $FW             all             REJECT          info

        dmz             net             REJECT          info
        dmz             $FW             REJECT          info
        dmz             loc             REJECT          info
        dmz             all             REJECT          info

        net             dmz             DROP            info
        net             $FW             DROP            info
        net             loc             DROP            info
        net             all             DROP            info

        # THE FOLLOWING POLICY MUST BE LAST
        all             all             REJECT          info

    `/etc/shorewall/rules`:

        #ACTION           SOURCE           DEST             PROTO            DPORT            SPORT
        ACCEPT            all              all              icmp             8
        ACCEPT            loc              $DMZ             tcp              25,53,80,443,...
        ACCEPT            loc              $DMZ             udp              53
        ACCEPT            loc              $NET
        ACCEPT            $FW              $DMZ             udp              53
        ACCEPT            $FW              $DMZ             tcp              53       

# Using Back-to-back veth Devices to Interface with a Bridge

Beginning with Shorewall 4.4.26, Shorewall has limited support for using back-to-back veth devices to interface with a bridge. This approach has the advantage that traffic between any pair of zones can be filtered. The disadvantage is the complexity of the approach.

This configuration is shown in the following diagram.

In this configuration, veth0 is assigned the internal IP address; br0 does not have an IP address.

Traffic from the **net** and **fw** zones to the **zone*i*** zones goes thru veth0-\>veth1-\>ethN-\>. Traffic from the **zone*i*** zones to the **fw** and **net** zones takes the reverse path: ethN-\>veth1-\>veth0. As a consequence, traffic between **net**,**fw** and **zone*i*** goes through Netfilter twice: once in the routed firewall (eth0,veth0) and once in the bridged firewall (eth1,eth2,eth3,veth1).

The back-to-back veth devices (veth0 and veth1) are created using this command:

    ip link add type veth

If you have veth devices and want to assign specific names to the created devices, use this format:

    ip link add name FOO type veth peer name BAR

Here's an /etc/network/interfaces stanza that configures veth0, veth1 and the bridge:

    auto veth0
    iface veth0 inet static
          address 10.10.10.1
          netmask 255.255.255.0
          network 10.10.10.0
          broadcast 10.10.10.255
          
          pre-up /sbin/ip link add name veth0 type veth peer name veth1
          pre-up /sbin/ip link set eth1  up
          pre-up /sbin/ip link set eth2  up

          pre-up /sbin/ip link set eth3  up
          pre-up /sbin/ip link set veth1 up
          pre-up /usr/sbin/brctl addbr br0
          pre-up /usr/sbin/brctl addif br0  eth1
          pre-up /usr/sbin/brctl addif br0  eth2
          pre-up /usr/sbin/brctl addif br0  eth3
          pre-up /usr/sbin/brctl addif br0  veth1
            
          pre-down /usr/sbin/brctl delif br0 eth1
          pre-down /sbin/ip link set eth2 down
          pre-down /usr/sbin/brctl delif br0 eth2
          pre-down /sbin/ip link set eth2 down
          pre-down /usr/sbin/brctl delif br0 eth3
          pre-down /sbin/ip link set eth3 down
          pre-down /usr/sbin/brctl delif br0 veth1
          pre-down /sbin/ip link set veth1 down
            
          post-down /usr/sbin/brctl delbr br0
          post-down /sbin/ip link del veth0

In [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5), we need this:

    ZONE_BITS=3

This does two things:

1.  It enables automatic packet marking.

2.  It allows up to 7 \<marked\> zones (2\*\*3 - 1). Zones are marked unless they have `nomark` in the OPTIONS column of their entry in [shorewall-zones](https://shorewall.org/manpages/shorewall-zones.html) (5). Packets originating in a marked zone have a mark assigned automatically by Shorewall.

For this configuration, we need several additional zones as shown here:

    #ZONE   TYPE    OPTIONS            IN_OPTIONS            OUT_OPTIONS
    fw      firewall
    net     ipv4
    zone1   bport
    zone2   bport
    zone3   bport
    loc     ipv4     nomark
    col     ipv4     nomark

<div class="note">

**col** is **loc** spelled backward.

</div>

    #ZONE     INTERFACES        BROADCAST       OPTIONS
    net       eth0              ...
    -         br0               ...
    zone1     br0:eth1          ...
    zone2     br0:eth2          ...
    zone3     br0:eth3          ...
    loc       veth0             ...
    col       br0:veth1         ...

Several things to note here

1.  We have defined two unmarked zones: **loc** and **col**. This allows traffic from the **zone*****i*** zones to the fw and net zones to retain the mark of their originating bport zones. It also allows traffic from the **fw** and **net** zones to the **zonei** zones to retain the **fw** and **net** marks respectively.

2.  That means that traffic entering the bridge on veth1 will have a different mark value, depending on whether it originated in the **net** zone or in the **fw** zone.

3.  Similarly, traffic arriving on the veth0 interface will have a mark that indicates which of the **zonei** zones each packet originated on.

The basic idea here is that we want to filter traffic to the **zonei** zones as it leaves veth1 and we want to filter traffic from those zones as it leaves veth0. So we use this type of polices:

    #SOURCE   DEST    POLICY
    fw        loc     ACCEPT
    net       loc     ACCEPT
    net       all     DROP:info
    zone1     col     ACCEPT
    zone2     col     ACCEPT
    zone3     col     ACCEPT
    all       all     REJECT:info

Rules allowing traffic from the net to zone2 look like this:

    #ACTION     SOURCE       DEST         PROTO  DPORT   SPORT      ORIGDEST    RATE    USER    MARK
    ACCEPT      col          zone2        tcp    22      -          -           -       -       net

or more compactly:

    #ACTION     SOURCE       DEST         PROTO  DPORT
    ACCEPT      col          zone2        tcp    22      ; mark=net

Similarly, rules allowing traffic from the firewall to zone3:

    #ACTION     SOURCE       DEST         PROTO  DPORT
    ACCEPT      col          zone3        tcp    22      ; mark=fw

The important point here is that, when ZONE_BITS is non-zero, you are allowed to place zone names in the MARK column. Shorewall will automatically replae the name with the zone's mark value.

Suppose that you want to forward tcp port 80 to 192.0.2.45 in zone3:

    #ACTION     SOURCE       DEST               PROTO  DPORT   SPORT      ORIGDEST    RATE    USER    MARK
    DNAT-       net          loc:172.168.4.45   tcp    80
    ACCEPT      col          zone3:172.168.4.45 tcp    80      -          -           -       -       net

Rules allowing traffic from the **zonei** zones to the **net** zone look like this:

    #ACTION     SOURCE       DEST               PROTO  DPORT   SPORT      ORIGDEST    RATE    USER    MARK
    ACCEPT      loc          net                tcp    21      -          -           -       -       zone1

And to the firewall:

    #ACTION     SOURCE       DEST               PROTO  DPORT   SPORT      ORIGDEST    RATE    USER   MARK
    ACCEPT      zone2        col                tcp          -          -           -       -       zone2

# Limitations

Bridging doesn't work with some wireless cards — see <http://bridge.sf.net>.
