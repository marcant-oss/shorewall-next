<div class="caution">

This article applies to Shorewall 3.0 and later. If you are running a version of Shorewall earlier than Shorewall 3.0.0 then please see the documentation for that release.

</div>

# Xen Network Environment

[Xen](http://www.cl.cam.ac.uk/Research/SRG/netos/xen/) is a paravirtualization tool that allows you to run multiple virtual machines on one physical machine. It is available on a wide number of platforms and is included in recent SUSE distributions.

Xen refers to the virtual machines as Domains. Domains are numbered with the first domain being domain 0, the second domain 1, and so on. Domain 0 (Dom0) is special because that is the domain created when the machine is booted. Additional domains (called DomU's) are created using the `xm create` command from within Domain 0. Additional domains can also be created automatically at boot time by using the `xendomains` service.

Xen virtualizes a network interface named `eth0`[^1]in each domain. In Dom0, Xen also creates a bridge (`xenbr0`) and a number of virtual interfaces as shown in the following diagram.

I use the term Extended Dom0 to distinguish the bridge and virtual interfaces from Dom0 itself. That distinction is important when we try to apply Shorewall in this environment.

The bridge has a number of ports:

- peth0 — This is the port that connects to the physical network interface in your system.

- vif0.0 — This is the bridge port that is used by traffic to/from Domain 0.

- vifX.0 — This is the bridge port that is used by traffic to/from Domain X.

# Before Xen

Prior to adopting Xen, I had a home office crowded with 5 systems, three monitors a scanner and a printer. The systems were:

1.  Firewall

2.  Public Server in a DMZ (mail)

3.  Private Server (wookie)

4.  My personal Linux Desktop (ursa)

5.  My work system (docked laptop running Windows XP).

The result was a very crowded and noisy room.

# After Xen

Xen has allowed me to reduce the noise and clutter considerably. I now have three systems with two monitors. I've also replaced the individual printer and scanner with a Multifunction FAX/Scanner/Printer.

The systems now include:

1.  Combination Firewall/Public Server/Private Server/Wireless Gateway using Xen (created by building out my Linux desktop system).

2.  My work system.

3.  My Linux desktop (wookie, which is actually the old public server box)

Most of the Linux systems run SUSE 10.1; my personal Linux desktop system and our Linux Laptop run Ubuntu "Dapper Drake".

**The configuration described below uses a bridged Xen Networking configuration; if you want to see how to accomplish a similar configuration using a Routed Xen configuration then please see [this article](XenMyWay-Routed.md). I am now using the routed configuration because it results in one fewer domains to administer.**

Here is a high-level diagram of our network.

As shown in this diagram, the Xen system has three physical network interfaces. These are:

- `eth0` -- connected to the switch in my office. That switch is cabled to a second switch in my wife's office where my wife has her desktop and networked printer (I sure wish that there had been wireless back when I strung that CAT-5 cable halfway across the house).

- `eth1` -- connected to our DSL "Modem".

- `eth2` -- connected to a Wireless Access Point (WAP) that interfaces to our wireless network.

There are three Xen domains.

1.  Dom0 (DNS name ursa.shorewall.net) is used as a local file server (NFS and Samba).

2.  The first DomU (Dom name **firewall**, DNS name gateway.shorewall.net) is used as our main firewall and wireless gateway.

3.  The second DomU (Dom name **lists**, DNS name lists.shorewall.net) is used as a public Web/FTP/Mail/DNS server.

Shorewall runs in Dom0 and in the firewall domain.

<div class="caution">

As the developer of Shorewall, I have enough experience to be very comfortable with Linux networking and Shorewall/iptables. I arrived at this configuration after a fair amount of trial and error experimentation. If you are a Linux networking novice, I recommend that you do not attempt a configuration like this one for your first Shorewall installation. You are very likely to frustrate both yourself and the Shorewall support team. Rather I suggest that you start with something simple like a [standalone installation](../reference/standalone.md) in a domU; once you are comfortable with that then you will be ready to try something more substantial.

As Paul Gear says: *Shorewall might make iptables easy, but it doesn't make understanding fundamental networking principles, traffic shaping, or multi-ISP routing any easier*.

The same goes for Xen networking.

</div>

## Domain Configuration

Below are the relevant configuration files for the three domains. I use partitions on my hard drives for DomU storage devices.

> `/boot/grub/menu.lst` — here is the entry that boots Xen in Dom0.
>
>     title XEN
>         root (hd0,1)
>         kernel /boot/xen.gz dom0_mem=458752 sched=bvt
>         module /boot/vmlinuz-xen root=/dev/hda2 vga=0x31a selinux=0    resume=/dev/hda1  splash=silent showopts 
>         module /boot/initrd-xen
>
> `/etc/modprobe.conf.local`
>
> `eth1` (PCI 00:09.0) and `eth2` (PCI 00:0a.0) are delegated to the firewall DomU where they become `eth3` and `eth4` respectively. The SUSE 10.1 Xen kernel compiles pciback as a module so the instructions for PCI delegation in the Xen Users Manual can't be followed directly (see <http://wiki.xensource.com/xenwiki/Assign_hardware_to_DomU_with_PCIBack_as_module>).
>
>     options pciback hide=(00:09.0)(00:0a.0)
>     install tulip /sbin/modprobe pciback ; /sbin/modprobe --first-time --ignore-install tulip
>     options netloop nloopbacks=1
>
> `/etc/xen/auto/01-firewall` — configuration file for the firewall domain
>
>     #  -*- mode: python; -*-
>
>     # configuration name:
>     name     = "firewall"
>
>     # usable ram:
>     memory   = 384
>
>     # kernel and initrd:
>     kernel   = "/xen2/vmlinuz-xen"
>     ramdisk  = "/xen2/initrd-xen"
>
>     # boot device:
>     root     = "/dev/hdb2"
>
>     # boot to run level:
>     extra    = "3"
>
>     # network interface:
>     vif      = [ 'mac=aa:cc:00:00:00:02, bridge=xenbr0', 'mac=aa:cc:00:00:00:03, bridge=xenbr1' ]
>     # Interfaces delegated from Dom0
>     pci=[ '00:09.0' , '00:0a.0' ]
>
>     # storage devices:
>     disk     = [ 'phy:hdb2,hdb2,w' ]
>
> `/etc/xen/auto/02-lists` — configuration file for the lists domain
>
>     #  -*- mode: python; -*-
>
>     # configuration name:
>     name     = "lists"
>
>     # usable ram:
>     memory   = 512
>
>     # kernel and initrd:
>     kernel   = "/xen2/vmlinuz-xen"
>     ramdisk  = "/xen2/initrd-xen"
>
>     # boot device:
>     root     = "/dev/hda3"
>
>     # boot to run level:
>     extra    = "3"
>
>     # network interface:
>     vif      = [ 'mac=aa:cc:00:00:00:01, bridge=xenbr1' ]
>     hostname = name
>
>     # storage devices:
>     disk     = [ 'phy:hda3,hda3,w' ]

With all three Xen domains up and running, the system looks as shown in the following diagram.

The zones correspond to the Shorewall zones in the firewall DomU configuration.

<div class="note">

If you want to run a simple NAT gateway in a Xen DomU, just omit the second bridge (xenbr1), the second delegated interface, and the second DomU from the above configuration. You can then install the [normal Shorewall two-interface sample configuration](../reference/two-interface.md) in the DomU.

</div>

<div class="caution">

Under some circumstances, UDP and/or TCP communication from a domU won't work for no obvious reason. That happened with the **lists** domain in my setup. Looking at the IP traffic with `tcpdump -nvvi eth1` in the **firewall** domU showed that UDP packets from the **lists** domU had incorrect checksums. That problem was corrected by arranging for the following command to be executed in the **lists** domain when its `eth0` device was brought up:

`ethtool -K eth0 tx off`

Under SUSE 10.1, I placed the following in `/etc/sysconfig/network/if-up.d/resettx` (that file is executable):

    #!/bin/sh

    if [ $2 = eth0 ]; then
        ethtool -K eth0 tx off
        echo "TX Checksum reset on eth0"
    fi

Under other distributions, the technique will vary. For example, under Debian or Ubuntu, you can just add a 'post-up' entry to `/etc/network/interfaces` as shown here:

     iface eth0 inet static
             address 206.124.146.177
             netmask 255.255.255.0
             post-up ethtool -K eth0 tx off

</div>

<div class="caution">

Update. Under SUSE 10.2, communication from a domU works okay without running ethtool **but traffic shaping in dom0 doesn't work!** So it's a good idea to run it just to be safe.

</div>

SUSE 10.1 includes Xen 3.0.2 which supports PCI delegation. The network interfaces that connect to the net and wifi zones are delegated to the firewall DomU.

When Shorewall starts during bootup of Dom0, it creates the two bridges using this `/etc/shorewall/init` extension script:

>     for bridge in xenbr0 xenbr1; do
>         if [ -z "$(/sbin/brctl show 2> /dev/null | fgrep $bridge)" ]; then
>              /sbin/brctl addbr $bridge
>              /sbin/ip link set dev $bridge up
>        fi
>     done

## Dom0 Configuration

The goals for the Shorewall configuration in Dom0 are as follows:

- Allow traffic to flow unrestricted through the two bridges. This is done by configuring the hosts connected to each bridge as a separate zone and relying on Shorewall's implicit intra-zone ACCEPT policy to permit traffic through the bridge.

- Ensure that there is no stray traffic between the zones. This is a "belt+suspenders" measure since there should be no routing between the bridges (because they don't have IP addresses).

The configuration is a simple one:

> `/etc/shorewall/zones`:
>
>     #ZONE   TYPE            OPTIONS         IN_OPTIONS              OUT_OPTIONS
>     fw      firewall
>     loc     ipv4
>     dmz     ipv4
>
> `/etc/shorewall/policy` (Note the unusual use of an ACCEPT all-\>all policy):
>
>     #SOURCE         DEST            POLICY          LOGLEVEL             LIMIT
>     dmz             all             REJECT          info
>     all             dmz             REJECT          info
>     all             all             ACCEPT
>
> `/etc/shorewall/interfaces`:
>
>     #ZONE   INTERFACE       BROADCAST       OPTIONS
>     loc     xenbr0          192.168.1.255   dhcp,routeback
>     dmz     xenbr1          -               routeback

## Firewall DomU Configuration

In the firewall DomU, I run a conventional three-interface firewall with Proxy ARP DMZ -- it is very similar to the firewall described in the [Shorewall Setup Guide](../reference/shorewall_setup_guide.md) with the exception that I've added a fourth interface for our wireless network. The firewall runs a routed [OpenVPN server](../features/OPENVPN.md) to provide road warrior access for our two laptops and a bridged OpenVPN server for the wireless network in our home. Here is the firewall's view of the network:

The two laptops can be directly attached to the LAN as shown above or they can be attached wirelessly -- their IP addresses are the same in either case; when they are directly attached, the IP address is assigned by the DHCP server running in Dom0 and when they are attached wirelessly, the IP address is assigned by OpenVPN.

The Shorewall configuration files are shown below. All routing and secondary IP addresses are handled in the SUSE network configuration.

> /etc/shorewall/shorewall.conf:
>
>     STARTUP_ENABLED=Yes
>     VERBOSITY=0
>     LOGFILE=/var/log/firewall
>     LOGFORMAT="Shorewall:%s:%s:"
>     LOGTAGONLY=No
>     LOGRATE=
>     LOGBURST=
>     LOGALLNEW=
>     BLACKLIST_LOGLEVEL=
>     MACLIST_LOG_LEVEL=$LOG
>     TCP_FLAGS_LOG_LEVEL=$LOG
>     SMURF_LOG_LEVEL=$LOG
>     LOG_MARTIANS=No
>     IPTABLES=/usr/sbin/iptables
>     PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin
>     SHOREWALL_SHELL=/bin/bash
>     SUBSYSLOCK=
>     MODULESDIR=
>     CONFIG_PATH=/etc/shorewall:/usr/share/shorewall
>     RESTOREFILE=standard
>     IPSECFILE=zones
>     IP_FORWARDING=On
>     ADD_IP_ALIASES=No
>     ADD_SNAT_ALIASES=No
>     RETAIN_ALIASES=No
>     TC_ENABLED=Internal
>     CLEAR_TC=Yes
>     MARK_IN_FORWARD_CHAIN=Yes
>     CLAMPMSS=Yes
>     ROUTE_FILTER=No
>     DETECT_DNAT_IPADDRS=Yes
>     MUTEX_TIMEOUT=60
>     ADMINISABSENTMINDED=Yes
>     BLACKLISTNEWONLY=Yes
>     DELAYBLACKLISTLOAD=No
>     MODULE_SUFFIX=
>     DISABLE_IPV6=Yes
>     BRIDGING=No
>     DYNAMIC_ZONES=No
>     PKTTYPE=No
>     MACLIST_TTL=60
>     SAVE_IPSETS=No
>     MAPOLDACTIONS=No
>     FASTACCEPT=Yes
>     BLACKLIST_DISPOSITION=DROP
>     MACLIST_TABLE=mangle
>     MACLIST_DISPOSITION=DROP
>     TCP_FLAGS_DISPOSITION=DROP
>
> `/etc/shorewall/zones`:
>
>     #ZONE   TYPE            OPTIONS         IN_OPTIONS              OUT_OPTIONS
>     fw      firewall
>     net     ipv4            #Internet
>     loc     ipv4            #Local wired Zone
>     dmz     ipv4            #DMZ
>     vpn     ipv4            #Open VPN clients
>     wifi    ipv4            #Local Wireless Zone
>
> `/etc/shorewall/policy`:
>
>     #SOURCE         DEST            POLICY          LOGLEVEL        LIMIT
>     $FW             $FW             ACCEPT
>     $FW             net             ACCEPT
>     loc             net             ACCEPT
>     $FW             vpn             ACCEPT
>     vpn             net             ACCEPT
>     vpn             loc             ACCEPT
>     loc             vpn             ACCEPT
>     $FW             loc             ACCEPT
>     wifi            all             REJECT          $LOG
>     loc             $FW             REJECT          $LOG
>     net             $FW             DROP            $LOG            1/sec:2
>     net             loc             DROP            $LOG            2/sec:4
>     net             dmz             DROP            $LOG            8/sec:30
>     net             vpn             DROP            $LOG
>     all             all             REJECT          $LOG
>
> `/etc/shorewall/params (edited)`:
>
>     MIRRORS=<comma-separated list of Shorewall mirrors>
>
>     NTPSERVERS=<comma-separated list of NTP servers I sync with>
>
>     POPSERVERS=<comma-separated list of server IP addresses>
>
>     LOG=info
>
>     INT_IF=eth0
>     DMZ_IF=eth1
>     EXT_IF=eth3
>     WIFI_IF=eth4
>
>     OMAK=<IP address at our second home>
>
> `/etc/shorewall/init`:
>
>     echo 1 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_be_liberal
>
> `/etc/shorewall/interfaces`:
>
>     #ZONE   INTERFACE       BROADCAST               OPTIONS
>     net     $EXT_IF         206.124.146.255         dhcp,logmartians,blacklist,tcpflags,nosmurfs
>     dmz     $DMZ_IF         192.168.0.255           logmartians
>     loc     $INT_IF         192.168.1.255           dhcp,routeback,logmartians
>     wifi    $WIFI_IF        192.168.3.255           dhcp,maclist
>     vpn     tun+            -
>
> `/etc/shorewall/nat`:
>
>     #EXTERNAL               INTERFACE       INTERNAL        ALLINTS         LOCAL
>     206.124.146.178         $EXT_IF         192.168.1.3     No              No     #Wookie
>     206.124.146.180         $EXT_IF         192.168.1.6     No              No     #Work LapTop
>
> `/etc/shorewall/masq (Note the cute trick here and in the following proxyarp file that allows me to access the DSL "Modem" using its default IP address (192.168.1.1))`. The leading "+" is required to place the rule before the SNAT rules generated by entries in `/etc/shorewall/nat` above.
>
>     #INTERFACE              SUBNET          ADDRESS         PROTO   DPORT IPSEC
>     +$EXT_IF:192.168.1.1    0.0.0.0/0       192.168.1.254
>     $EXT_IF                 192.168.0.0/22  206.124.146.179
>
> `/etc/shorewall/proxyarp`:
>
>     #ADDRESS        INTERFACE       EXTERNAL        HAVEROUTE       PERSISTENT
>     192.168.1.1     $EXT_IF         $INT_IF         yes
>     206.124.146.177 $DMZ_IF         $EXT_IF         yes
>
> `/etc/shorewall/tunnels`:
>
>     #TYPE                   ZONE    GATEWAY         GATEWAY_ZONE
>     openvpnserver:udp       net     0.0.0.0/0                 #Routed server for RoadWarrior access
>     openvpnserver:udp       wifi    192.168.3.0/24            #Home wireless network server
>
> `/etc/shorewall/actions`:
>
>     #ACTION
>     Mirrors             # Accept traffic from Shorewall Mirrors
>
> `/etc/shorewall/action.Mirrors`:
>
>     #TARGET SOURCE          DEST            PROTO   PORT    SPORT      ORIGDEST     RATE
>     ACCEPT  $MIRRORS
>
> `/etc/shorewall/rules`:
>
>     ?SECTION NEW
>     ###############################################################################################################################################################################
>     #ACTION         SOURCE                          DEST                    PROTO   DPORT                                   SPORT           ORIGDEST        RATE    USER
>     ###############################################################################################################################################################################
>     REJECT:$LOG     loc                             net                     tcp     25
>     REJECT:$LOG     loc                             net                     udp     1025:1031
>     #
>     # Stop NETBIOS crap
>     #
>     REJECT          loc                             net                     tcp     137,445
>     REJECT          loc                             net                     udp     137:139
>     #
>     # Stop my idiotic work laptop from sending to the net with an HP source/dest IP address
>     #
>     DROP            loc:!192.168.0.0/22             net
>     ###############################################################################################################################################################################
>     # Local Network to Firewall
>     #
>     DROP            loc:!192.168.0.0/22             fw                      # Silently drop traffic with an HP source IP from my XP box
>     ACCEPT          loc                             fw                      tcp     22
>     ACCEPT          loc                             fw                      tcp     time,631,8080
>     ACCEPT          loc                             fw                      udp     161,ntp,631
>     ACCEPT          loc:192.168.1.5                 fw                      udp     111
>     DROP            loc                             fw                      tcp     3185          #SUSE Meta pppd
>     Ping(ACCEPT)    loc                             fw
>     REDIRECT        loc                             3128                    tcp     80                                      -               !206.124.146.177
>     ###############################################################################################################################################################################
>     # Road Warriors to Firewall
>     #
>     ACCEPT            vpn                             fw                      tcp     ssh,time,631,8080
>     ACCEPT            vpn                             fw                      udp     161,ntp,631
>     Ping(ACCEPT)      vpn                             fw
>     ###############################################################################################################################################################################
>     # Road Warriors to DMZ
>     #
>     ACCEPT            vpn                             dmz                     udp     domain
>     ACCEPT            vpn                             dmz                     tcp     www,smtp,smtps,domain,ssh,imap,https,imaps,ftp,10023,pop3       -
>     Ping(ACCEPT)      vpn                             dmz
>     ###############################################################################################################################################################################
>     # Local network to DMZ
>     #
>     ACCEPT          loc                             dmz                     udp     domain
>     ACCEPT          loc                             dmz                     tcp     ssh,smtps,www,ftp,imaps,domain,https    -
>     ACCEPT          loc                             dmz                     tcp     smtp
>     Trcrt(ACCEPT)   loc                             dmz
>     ###############################################################################################################################################################################
>     # Internet to ALL -- drop NewNotSyn packets
>     #
>     dropNotSyn      net             fw              tcp
>     dropNotSyn      net             loc             tcp
>     dropNotSyn      net             dmz             tcp
>     ###############################################################################################################################################################################
>     # Internet to DMZ
>     #
>     ACCEPT          net                             dmz                     udp     domain
>     ACCEPT          net                             dmz                     tcp     smtps,www,ftp,imaps,domain,https        -
>     ACCEPT          net                             dmz                     tcp     smtp                                    -               206.124.146.177,206.124.146.178
>     ACCEPT          net                             dmz                     udp     33434:33454
>     Mirrors         net                             dmz                     tcp     rsync
>     Limit:$LOG:SSHA,3,60\
>                     net                             dmz                     tcp     22
>     Trcrt(ACCEPT)   net                             dmz
>     ##############################################################################################################################################################################
>     #
>     # Net to Local
>     #
>     # When I'm "on the road", the following two rules allow me VPN access back home using PPTP.
>     #
>     DNAT            net                             loc:192.168.1.4         tcp     1729
>     DNAT            net                             loc:192.168.1.4         gre
>     #
>     # Roadwarrior access to Wookie
>     #
>     ACCEPT          net:$OMAK                       loc                     tcp     22
>     Limit:$LOG:SSHA,3,60\
>                     net                             loc                     tcp     22
>
>     #
>     # ICQ
>     #
>     ACCEPT          net                             loc:192.168.1.3         tcp     113,4000:4100
>     #
>     # Bittorrent
>     #
>     ACCEPT          net                             loc:192.168.1.3         tcp     6881:6889,6969
>     ACCEPT          net                             loc:192.168.1.3         udp     6881:6889,6969
>     #
>     # Skype
>     #
>     ACCEPT          net                             loc:192.168.1.6         tcp     1194
>     #
>     # Traceroute
>     #
>     Trcrt(ACCEPT)   net                             loc:192.168.1.3
>     #
>     # Silently Handle common probes
>     #
>     REJECT          net                             loc                     tcp     www,ftp,https
>     DROP            net                             loc                     icmp    8
>     ###############################################################################################################################################################################
>     # DMZ to Internet
>     #
>     ACCEPT          dmz                             net                     udp     domain,ntp
>     ACCEPT          dmz                             net                     tcp     echo,ftp,ssh,smtp,whois,domain,www,81,https,cvspserver,2702,2703,8080
>     ACCEPT          dmz                             net:$POPSERVERS         tcp     pop3
>     Ping(ACCEPT)    dmz                             net
>     #
>     # Some FTP clients seem prone to sending the PORT command split over two packets. This prevents the FTP connection tracking
>     # code from processing the command  and setting up the proper expectation. The following rule allows active FTP to work in these cases
>     # but logs the connection so I can keep an eye on this potential security hole.
>     #
>     ACCEPT:$LOG     dmz                             net                     tcp     1024:                                   20
>     ###############################################################################################################################################################################
>     # Local to DMZ
>     #
>     ACCEPT          loc                             dmz                     udp     domain,xdmcp
>     ACCEPT          loc                             dmz                     tcp     www,smtp,smtps,domain,ssh,imap,rsync,https,imaps,ftp,10023,pop3,3128
>     Trcrt(ACCEPT)   loc                             dmz
>     ###############################################################################################################################################################################
>     # DMZ to Local
>     #
>     ACCEPT          dmz                             loc:192.168.1.5         udp     123
>     ACCEPT          dmz                             loc:192.168.1.5         tcp     21
>     Ping(ACCEPT)    dmz                             loc
>
>     ###############################################################################################################################################################################
>     # DMZ to Firewall -- ntp & snmp, Silently reject Auth
>     #
>     ACCEPT          dmz                             fw                      tcp     161,ssh
>     ACCEPT          dmz                             fw                      udp     161
>     REJECT          dmz                             fw                      tcp     auth
>     Ping(ACCEPT)    dmz                             fw
>     ###############################################################################################################################################################################
>     # Internet to Firewall
>     #
>     REJECT          net                             fw                      tcp     www,ftp,https
>     DROP            net                             fw                      icmp    8
>     ACCEPT          net                             fw                      udp     33434:33454
>     ACCEPT          net:$OMAK                       fw                      udp     ntp
>     ACCEPT          net                             fw                      tcp     auth
>     ACCEPT          net:$OMAK                       fw                      tcp     22
>     Limit:$LOG:SSHA,3,60\
>                     net                             fw                      tcp     22
>     Trcrt(ACCEPT)   net                             fw
>     ###############################################################################################################################################################################
>     # Firewall to DMZ
>     #
>     ACCEPT          fw                              dmz                     tcp     domain,www,ftp,ssh,smtp,https,993,465
>     ACCEPT          fw                              dmz                     udp     domain
>     REJECT          fw                              dmz                     udp     137:139
>     Ping(ACCEPT)    fw                              dmz
>     ##############################################################################################################################################################################
>     # Avoid logging Freenode.net probes
>     #
>     DROP            net:82.96.96.3                          all
>
> `/etc/shorewall/tcdevices`
>
>     #INTERFACE      IN_BANDWITH     OUT_BANDWIDTH
>     $EXT_IF         1300kbit        384kbit
>
> `/etc/shorewall/tcclasses`
>
>     #INTERFACE      MARK    RATE            CEIL            PRIORITY        OPTIONS
>     $EXT_IF         10      5*full/10       full            1               tcp-ack,tos-minimize-delay
>     $EXT_IF         20      3*full/10       9*full/10       2               default
>     $EXT_IF         30      2*full/10       6*full/10       3
>
> `/etc/shorewall/mangle`
>
>     #ACTION           SOURCE          DEST            PROTO   DPORT   SPORT   USER    TEST
>     CLASSIFY(1:110)   192.168.0.0/22  $EXT_IF                                         #Our internal nets get priority
>                                                                                       #over the server
>     CLASSIFY(1:130)   206.124.146.177 $EXT_IF         tcp     -       873             #Throttle rsync traffic to the
>                                                                                       #Shorewall Mirrors.

The tap0 device used by the bridged OpenVPN server is bridged to eth0 using a SUSE-specific SysV init script:

>     #!/bin/sh
>     #
>     #     The Shoreline Firewall (Shorewall) Packet Filtering Firewall - V3.0
>     #
>     #     This program is under GPL [http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt]
>     #
>     #     (c) 1999,2000,2001,2002,2003,2004,2005 - Tom Eastep (teastep@shorewall.net)
>     #
>     #       On most distributions, this file should be called /etc/init.d/shorewall.
>     #
>     #       Complete documentation is available at https://shorewall.org
>     #
>     #       This program is free software; you can redistribute it and/or modify
>     #       it under the terms of Version 2 of the GNU General Public License
>     #       as published by the Free Software Foundation.
>     #
>     #       This program is distributed in the hope that it will be useful,
>     #       but WITHOUT ANY WARRANTY; without even the implied warranty of
>     #       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
>     #       GNU General Public License for more details.
>     #
>     #       You should have received a copy of the GNU General Public License
>     #       along with this program; if not, write to the Free Software
>     #       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
>     #
>     #       If an error occurs while starting or restarting the firewall, the
>     #       firewall is automatically stopped.
>     #
>     #       Commands are:
>     #
>     #          bridge start                   Starts the bridge
>     #          bridge restart                         Restarts the bridge
>     #          bridge reload                          Restarts the bridge
>     #          bridge stop                    Stops the bridge
>     #          bridge status                  Displays bridge status
>     #
>
>     # chkconfig: 2345 4 99
>     # description: Packet filtering firewall
>
>     ### BEGIN INIT INFO
>     # Provides:       bridge
>     # Required-Start: boot.udev
>     # Required-Stop:
>     # Default-Start:  2 3 5
>     # Default-Stop:   0 1 6
>     # Description:    starts and stops the bridge
>     ### END INIT INFO
>
>     ################################################################################
>     # Interfaces to be bridged -- may be listed by device name or by MAC
>     #
>     INTERFACES="eth0"
>
>     #
>     # Tap Devices
>     #
>     TAPS="tap0"
>
>     ################################################################################
>     # Give Usage Information                                                       #
>     ################################################################################
>     usage() {
>         echo "Usage: $0 start|stop|reload|restart|status"
>         exit 1
>     }
>     #################################################################################
>     # Find the interface with the passed MAC address
>     #################################################################################
>     find_interface_by_mac() {
>         local mac
>         mac=$1
>         local first
>         local second
>         local rest
>         local dev
>
>         /sbin/ip link ls | while read first second rest; do
>             case $first in
>                 *:)
>                     dev=$second
>                     ;;
>                 *)
>                     if [ "$second" = $mac ]; then
>                         echo ${dev%:}
>                         return
>                     fi
>             esac
>         done
>     }
>     ################################################################################
>     # Convert MAC addresses to interface names
>     ################################################################################
>     get_interfaces() {
>         local interfaces
>         interfaces=
>         local interface
>
>         for interface in $INTERFACES; do
>             case $interface in
>                 *:*:*)
>                     interface=$(find_interface_by_mac $interface)
>                     [ -n "$interface" ] || echo "WARNING: Can't find an interface with MAC address $mac"
>                     ;;
>             esac
>             interfaces="$interfaces $interface"
>         done
>
>         INTERFACES="$interfaces"
>     }
>     ################################################################################
>     # Start the Bridge
>     ################################################################################
>     do_start()
>     {
>         local interface
>
>         get_interfaces
>
>         for interface in $TAPS; do
>             /usr/sbin/openvpn --mktun --dev $interface
>         done
>
>        /sbin/brctl addbr br0
>
>        for interface in $INTERFACES $TAPS; do
>             /sbin/ip link set $interface up
>             /sbin/brctl addif br0 $interface
>        done
>     }
>     ################################################################################
>     # Stop the Bridge
>     ################################################################################
>     do_stop()
>     {
>         local interface
>
>         get_interfaces
>
>         for interface in $INTERFACES $TAPS; do
>             /sbin/brctl delif br0 $interface
>             /sbin/ip link set $interface down
>         done
>
>         /sbin/ip link set br0 down
>
>         /sbin/brctl delbr br0
>
>         for interface in $TAPS; do
>             /usr/sbin/openvpn --rmtun --dev $interface
>         done
>     }
>     ################################################################################
>     # E X E C U T I O N    B E G I N S   H E R E                                   #
>     ################################################################################
>     command="$1"
>
>     case "$command" in
>         start)
>             do_start
>             ;;
>         stop)
>             do_stop
>             ;;
>         restart|reload)
>             do_stop
>             do_start
>             ;;
>         status)
>             /sbin/brctl show
>             ;;
>         *)
>             usage
>             ;;
>     esac

[^1]: This assumes the default Xen configuration created by `xend`and assumes that the host system has a single Ethernet interface named `eth0`.
