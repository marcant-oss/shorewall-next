# Introduction

[Open Virtuoso (OpenVZ)](http://wiki.openvz.org/) is an open source kernel-based virtualization solution from [Parallels](http://www.parallels.com) (formerly SWSoft). Virtual servers take the form of containers (the OpenVZ documentation calls these Virtual Environments or VEs) which are created via templates. Templates are available for a wide variety of distributions and architectures.

OpenVZ requires a patched kernel. Beginning with Lenny, Debian supplies OpenVZ kernels through the standard stable repository.

# Shorewall on an OpenVZ Host

As with any Shorewall installation involving other software, we suggest that you first install OpenVZ and get it working before attempting to add Shorewall. Alternatively, execute `shorewall clear` while [installing and configuring OpenVZ](http://wiki.openvz.org/Installation_on_Debian).

## Networking

The default OpenVZ networking configuration uses Proxy ARP. You assign containers IP addresses in the IP network from one of your interfaces and you are expected to set the proxy_arp flag on that interface (`/proc/sys/net/ipv4/conf/interface/proxy_arp`).

OpenVZ creates a point-to-point virtual interface in the host with a rather odd configuration.

Example (Single VE with IP address 206.124.146.178):

    gateway:~# ip addr ls dev venet0
    10: venet0: <BROADCAST,POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN 
        link/void 
    gateway:~# ip route ls dev venet0
    206.124.146.178  scope link 
    gateway:~# 

The interface has no IP configuration yet it has a route to 206.124.146.178!

From within the VE with IP address 206.124.146.178, we have the following:

    server:~ # ip addr ls
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 brd 127.255.255.255 scope host lo
        inet 127.0.0.2/8 brd 127.255.255.255 scope host secondary lo
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: venet0: <BROADCAST,POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN 
        link/void 
        inet 127.0.0.1/32 scope host venet0
        inet 206.124.146.178/32 scope global venet0:0
    server:~ # ip route ls
    192.0.2.0/24 dev venet0  scope link 
    127.0.0.0/8 dev lo  scope link 
    default via 192.0.2.1 dev venet0 
    server:~ # 

There are a couple of unique features of this configuration:

- 127.0.0.1/32 is configured on venet0 although the main routing table routes loopback traffic through the `lo` interface as normal.

- There is a route to 192.0.2.0/24 through venet0 even though the interface has no IP address in that network. Note: 192.0.2.0/24 is reserved for use in documentation and for testing.

- The default route is via 192.0.2.1 yet there is no interface on the host with that IP address.

All of this doesn't really affect the Shorewall configuration but it is interesting none the less.

## Shorewall Configuration

We recommend handling the strange OpenVZ configuration in Shorewall as follows:

`/etc/shorewall/zones`:

    ###############################################################################
    #ZONE    TYPE       OPTIONS                IN_OPTION                OUT_OPTIONS
    net      ipv4
    vz       ipv4

`/etc/shorewall/interfaces`:

    ###############################################################################
    #ZONE    INTERFACE          OPTIONS
    net      eth0               proxyarp=1
    vz       venet0             routeback,arp_filter=0

## Multi-ISP

If you run Shorewall Multi-ISP support on the host, you should arrange for traffic to your containers to use the main routing table. In the configuration shown here, this entry in /etc/shorewall/rtrules is appropriate:

    #SOURCE            DEST              PROVIDER          PRIORITY
    -                  206.124.146.178   main              1000

## RFC 1918 Addresses in a Container

You can assign an RFC 1918 address to a VE and use masquerade/SNAT to provide Internet access to the container. This is just a normal simple Shorewall configuration as shown in the [Two-interface Quick Start Guide](../reference/two-interface.md). In this configuration the firewall's internal interface is `venet0`. Be sure to include the options shown above.

# Shorewall in an OpenVZ Virtual Environment

If you have obtained an OpenVZ VE from a hosting service provider, you may find it difficult to configure any type of firewall within your VE. There are two VE parameters that control iptables behavior within the container:

--iptables \<name\>  
Restrict access to iptables modules inside a container (The OpenVZ claims that by default all iptables modules that are loaded in the host system are accessible inside a container; I haven't tried that).

You can use the following values for \<name\>: `iptable_filter`, `iptable_mangle`, `ipt_limit`, `ipt_multiport`, `ipt_tos`, `ipt_TOS`, `ipt_REJECT`, `ipt_TCPMSS`, `ipt_tcpmss`, `ipt_ttl`, `ipt_LOG`, `ipt_length`, `ip_conntrack`, `ip_conntrack_ftp`, `ip_conntrack_irc`, `ipt_conntrack`, `ipt_state`, `ipt_helper`, `iptable_nat`, `ip_nat_ftp`, `ip_nat_irc`, `ipt_REDIRECT`, `xt_mac`, `ipt_owner`.

If your provider is using this option, you may be in deep trouble trying to use Shorewall in your container. Look at the output of `shorewall show capabilities` and weep. Then try to get your provider to remove this restriction on your container.

--numiptent \<num\>  
This parameter limits the number of iptables rules that are allowed within the container. The default is 100 which is too small for a Shorewall configuration. We recommend setting this to at least 200.

if you see annoying error messages as shown below during start/restart, remove the module-init-tools package from the VE.

    server:/etc/shorewall # shorewall restart
    Compiling...
    Compiling /etc/shorewall/zones...
    Compiling /etc/shorewall/interfaces...
    Determining Hosts in Zones...
    Preprocessing Action Files...
       Pre-processing /usr/share/shorewall/action.Drop...
       Pre-processing /usr/share/shorewall/action.Reject...
    Compiling /etc/shorewall/policy...
    Adding Anti-smurf Rules
    Adding rules for DHCP
    Compiling TCP Flags filtering...
    Compiling Kernel Route Filtering...
    Compiling Martian Logging...
    Compiling MAC Filtration -- Phase 1...
    Compiling /etc/shorewall/rules...
    Generating Transitive Closure of Used-action List...
    Processing /usr/share/shorewall/action.Reject for chain Reject...
    Processing /usr/share/shorewall/action.Drop for chain Drop...
    Compiling MAC Filtration -- Phase 2...
    Applying Policies...
    Generating Rule Matrix...
    Creating iptables-restore input...
    Compiling iptables-restore input for chain mangle:...
    Compiling /etc/shorewall/routestopped...
    Shorewall configuration compiled to /var/lib/shorewall/.restart
    Restarting Shorewall....
    Initializing...
    Processing /etc/shorewall/init ...
    Processing /etc/shorewall/tcclear ...
    Setting up Route Filtering...
    Setting up Martian Logging...
    Setting up Proxy ARP...
    Setting up Traffic Control...
    Preparing iptables-restore input...
    Running /usr/sbin/iptables-restore...
    FATAL: Could not load /lib/modules/2.6.26-2-openvz-amd64/modules.dep: No such file or directory
    FATAL: Could not load /lib/modules/2.6.26-2-openvz-amd64/modules.dep: No such file or directory
    FATAL: Could not load /lib/modules/2.6.26-2-openvz-amd64/modules.dep: No such file or directory
    FATAL: Could not load /lib/modules/2.6.26-2-openvz-amd64/modules.dep: No such file or directory
    IPv4 Forwarding Enabled
    Processing /etc/shorewall/start ...
    Processing /etc/shorewall/started ...
    done.

# Working Example

This section presents a working example. This is the configuration at shorewall.net during the summer of 2009.

The network diagram is shown below.

The two systems shown in the green box are OpenVZ Virtual Environments (containers).

## OpenVZ Configuration

In the files below, items in **bold font** are relevant to the networking/Shorewall configuration.

`/etc/vz/conf` (long lines folded for clarity).

    ## Global parameters
    VIRTUOZZO=yes
    LOCKDIR=/var/lib/vz/lock
    DUMPDIR=/var/lib/vz/dump
    VE0CPUUNITS=1000

    ## Logging parameters
    LOGGING=yes
    LOGFILE=/var/log/vzctl.log
    LOG_LEVEL=0
    VERBOSE=0

    ## Disk quota parameters
    DISK_QUOTA=no
    VZFASTBOOT=no

    # The name of the device whose ip address will be used as source ip for VE.
    # By default automatically assigned.
    VE_ROUTE_SRC_DEV="eth3"

    # Controls which interfaces to send ARP requests and modify APR tables on.
    NEIGHBOUR_DEVS=detect

    ## Template parameters
    TEMPLATE=/var/lib/vz/template

    ## Defaults for VEs
    VE_ROOT=/home/vz/root/$VEID
    VE_PRIVATE=/home/vz/private/$VEID
    CONFIGFILE="vps.basic"
    #DEF_OSTEMPLATE="fedora-core-4"
    DEF_OSTEMPLATE="debian"

    ## Load vzwdog module
    VZWDOG="no"

    ## IPv4 iptables kernel modules
    IPTABLES="iptable_filter iptable_mangle ipt_limit ipt_multiport ipt_tos
              ipt_TOS ipt_REJECT ipt_TCPMSS ipt_tcpmss ipt_ttl ipt_LOG ipt_length
              ip_conntrack ip_conntrack_ftp ip_conntrack_irc ipt_conntrack
              ipt_state ipt_helper iptable_nat  ip_nat_ftp  ip_nat_irc ipt_REDIRECT
              xt_mac ipt_owner"

    ## Enable IPv6
    IPV6="no"

`/etc/vz/conf/101.conf`:

    ONBOOT="yes"

    # UBC parameters (in form of barrier:limit)
    KMEMSIZE="574890800:589781600"
    LOCKEDPAGES="256:256"
    PRIVVMPAGES="1073741824:2137483648"
    SHMPAGES="21504:21504"
    NUMPROC="240:240"
    PHYSPAGES="0:9223372036854775807"
    VMGUARPAGES="262144:9223372036854775807"
    OOMGUARPAGES="26112:9223372036854775807"
    NUMTCPSOCK="360:360"
    NUMFLOCK="188:206"
    NUMPTY="16:16"
    NUMSIGINFO="256:256"
    TCPSNDBUF="1720320:2703360"
    TCPRCVBUF="1720320:2703360"
    OTHERSOCKBUF="1126080:2097152"
    DGRAMRCVBUF="262144:262144"
    NUMOTHERSOCK="360:360"
    DCACHESIZE="3409920:3624960"
    NUMFILE="9312:9312"
    AVNUMPROC="180:180"
    NUMIPTENT="200:200"

    # Disk quota parameters (in form of softlimit:hardlimit)
    DISKSPACE="1048576:1153024"
    DISKINODES="200000:220000"
    QUOTATIME="0"

    # CPU fair sheduler parameter
    CPUUNITS="1000"

    VE_ROOT="/home/vz/root/$VEID"
    VE_PRIVATE="/home/vz/private/$VEID"
    OSTEMPLATE="suse-11.1-x86_64"
    ORIGIN_SAMPLE="vps.basic"
    HOSTNAME="lists.shorewall.net"
    IP_ADDRESS="206.124.146.177"
    NAMESERVER="127.0.0.1"
    NAME="lists"
    SEARCHDOMAIN="shorewall.net"

This VE is the main server at shorewall.net. Note that some of the memory parameters are set ridiculously large -- I got tired of out-of-memory issues.

`/etc/vz/conf/102.conf` (nearly default configuration on Debian):

    ONBOOT="yes"

    # UBC parameters (in form of barrier:limit)
    KMEMSIZE="14372700:14790164"
    LOCKEDPAGES="256:256"
    PRIVVMPAGES="65536:69632"
    SHMPAGES="21504:21504"
    NUMPROC="240:240"
    PHYSPAGES="0:9223372036854775807"
    VMGUARPAGES="33792:9223372036854775807"
    OOMGUARPAGES="26112:9223372036854775807"
    NUMTCPSOCK="360:360"
    NUMFLOCK="188:206"
    NUMPTY="16:16"
    NUMSIGINFO="256:256"
    TCPSNDBUF="1720320:2703360"
    TCPRCVBUF="1720320:2703360"
    OTHERSOCKBUF="1126080:2097152"
    DGRAMRCVBUF="262144:262144"
    NUMOTHERSOCK="360:360"
    DCACHESIZE="3409920:3624960"
    NUMFILE="9312:9312"
    AVNUMPROC="180:180"
    NUMIPTENT="200:200"

    # Disk quota parameters (in form of softlimit:hardlimit)
    DISKSPACE="1048576:1153024"
    DISKINODES="200000:220000"
    QUOTATIME="0"

    # CPU fair sheduler parameter
    CPUUNITS="1000"

    VE_ROOT="/home/vz/root/$VEID"
    VE_PRIVATE="/home/vz/private/$VEID"
    OSTEMPLATE="debian-5.0-amd64-minimal"
    ORIGIN_SAMPLE="vps.basic"
    HOSTNAME="server.shorewall.net"
    IP_ADDRESS="206.124.146.178"
    NAMESERVER="206.124.146.177"
    NAME="server"

I really don't use this server for anything currently but I'm planning to eventually splt the services between the two VEs.

## Shorewall Configuration on the Host

Below are excerpts from the configuration files as they pertain to the OpenVZ environment.

`/etc/shorewall/zones`:

    #ZONE           TYPE            OPTIONS         IN_OPTIONS              OUT_OPTIONS
    fw              firewall
    net             ipv4            #Internet
    loc             ipv4            #Local wired Zone
    dmz             ipv4            #DMZ
    ...

`/etc/shorewall/params`:

    NET_IF=eth3
    INT_IF=eth1
    VPS_IF=venet0
    ...

`/etc/shorewall/interfaces`:

    #ZONE   INTERFACE       OPTIONS
    net     $NET_IF         dhcp,blacklist,tcpflags,optional,routefilter=0,nosmurfs,logmartions=0,proxyarp=1
    loc     $INT_IF         dhcp,logmartians=1,routefilter=1,nets=(172.20.1.0/24),tcpflags
    dmz     $VPS_IF         logmartians=0,routefilter=0,nets=(206.124.146.177,206.124.146.178),routeback
    ...

This is a multi-ISP configuration so entries are required in `/etc/shorewall/rtrules`:

    #SOURCE   DEST                 PROVIDER  PRIORITY
    -         172.20.0.0/24        main      1000
    -         206.124.146.177      main      1001
    -         206.124.146.178      main      1001

## Shorewall Configuration on Server

<div class="warning">

If you are running Debian Squeeze, Shorewall will not work in an OpenVZ container. This is a Debian OpenVZ issue and not a Shorewall issue.

</div>

I have set up Shorewall on Server (206.124.146.178) just to have an environment to test with. It is a quite vanilla one-interface configuration.

/etc/shorewall/zones:

    #ZONE       TYPE         OPTIONS           IN_OPTIONS        OUT_OPTIONS
    fw          firewall
    net         ipv4

/etc/shorewall/interfaces:

    #ZONE   INTERFACE       BROADCAST       OPTIONS
    net     venet0          detect          dhcp,tcpflags,logmartians,nosmurfs

# Working Example Using a Bridge

This is the configuration at shorewall.net during the spring of 2010. Rather than using the venet0 configuration shown above, this configuration uses a bridge in preparation for adding IPv6 support in the DMZ. The eth0 interface in each of the containers is statically configured using the distributions' configuration tools (`/etc/network/interfaces` on Debian and Yast on OpenSuSE).

The network diagram is shown below.

The two systems shown in the green box are OpenVZ Virtual Environments (containers).

## Bridge Configuration

The following stanza in /etc/network/interfaces on the host configures the bridge.

    auto vzbr0
    iface vzbr0 inet static
          pre-up /usr/sbin/brctl addbr vzbr0
          address 206.124.146.176
          network 206.124.146.176
          broadcast 206.124.146.176
          netmask 255.255.255.255
          post-down /usr/sbin/brctl delbr br0

## OpenVZ Configuration

In the files below, items in **bold font** show the changes from the preceeding example.

`/etc/vz/conf` (long lines folded for clarity).

    ## Global parameters
    VIRTUOZZO=yes
    LOCKDIR=/var/lib/vz/lock
    DUMPDIR=/var/lib/vz/dump
    VE0CPUUNITS=1000

    ## Logging parameters
    LOGGING=yes
    LOGFILE=/var/log/vzctl.log
    LOG_LEVEL=0
    VERBOSE=0

    ## Disk quota parameters
    DISK_QUOTA=no
    VZFASTBOOT=no

    # The name of the device whose ip address will be used as source ip for VE.
    # By default automatically assigned.
    VE_ROUTE_SRC_DEV="eth3"

    # Controls which interfaces to send ARP requests and modify APR tables on.
    NEIGHBOUR_DEVS=detect

    ## Template parameters
    TEMPLATE=/var/lib/vz/template

    ## Defaults for VEs
    VE_ROOT=/home/vz/root/$VEID
    VE_PRIVATE=/home/vz/private/$VEID
    CONFIGFILE="vps.basic"
    #DEF_OSTEMPLATE="fedora-core-4"
    DEF_OSTEMPLATE="debian"

    ## Load vzwdog module
    VZWDOG="no"

    ## IPv4 iptables kernel modules
    IPTABLES="iptable_filter iptable_mangle ipt_limit ipt_multiport ipt_tos
              ipt_TOS ipt_REJECT ipt_TCPMSS ipt_tcpmss ipt_ttl ipt_LOG ipt_length
              ip_conntrack ip_conntrack_ftp ip_conntrack_irc ipt_conntrack
              ipt_state ipt_helper iptable_nat  ip_nat_ftp  ip_nat_irc ipt_REDIRECT
              xt_mac ipt_owner"

    ## Enable IPv6
    IPV6="no"

`/etc/vz/conf/101.conf`:

    ONBOOT="yes"

    # UBC parameters (in form of barrier:limit)
    KMEMSIZE="574890800:589781600"
    LOCKEDPAGES="256:256"
    PRIVVMPAGES="1073741824:2137483648"
    SHMPAGES="21504:21504"
    NUMPROC="240:240"
    PHYSPAGES="0:9223372036854775807"
    VMGUARPAGES="262144:9223372036854775807"
    OOMGUARPAGES="26112:9223372036854775807"
    NUMTCPSOCK="360:360"
    NUMFLOCK="188:206"
    NUMPTY="16:16"
    NUMSIGINFO="256:256"
    TCPSNDBUF="1720320:2703360"
    TCPRCVBUF="1720320:2703360"
    OTHERSOCKBUF="1126080:2097152"
    DGRAMRCVBUF="262144:262144"
    NUMOTHERSOCK="360:360"
    DCACHESIZE="3409920:3624960"
    NUMFILE="9312:9312"
    AVNUMPROC="180:180"
    NUMIPTENT="200:200"

    # Disk quota parameters (in form of softlimit:hardlimit)
    DISKSPACE="1048576:1153024"
    DISKINODES="200000:220000"
    QUOTATIME="0"

    # CPU fair sheduler parameter
    CPUUNITS="1000"

    VE_ROOT="/home/vz/root/$VEID"
    VE_PRIVATE="/home/vz/private/$VEID"
    OSTEMPLATE="suse-11.1-x86_64"
    ORIGIN_SAMPLE="vps.basic"
    HOSTNAME="lists.shorewall.net"
    NAMESERVER="127.0.0.1"
    NAME="lists"
    SEARCHDOMAIN="shorewall.net"

    NETIF="ifname=eth0,mac=00:18:51:22:24:81,host_ifname=veth101.0,host_mac=00:18:51:B6:1A:F1"

This VE is the mail server at shorewall.net (MX and IMAP). Note that some of the memory parameters are set ridiculously large -- I got tired of out-of-memory issues.

`/etc/vz/conf/102.conf` (nearly default configuration on Debian):

    ONBOOT="yes"

    # UBC parameters (in form of barrier:limit)
    KMEMSIZE="14372700:14790164"
    LOCKEDPAGES="256:256"
    PRIVVMPAGES="65536:69632"
    SHMPAGES="21504:21504"
    NUMPROC="240:240"
    PHYSPAGES="0:9223372036854775807"
    VMGUARPAGES="33792:9223372036854775807"
    OOMGUARPAGES="26112:9223372036854775807"
    NUMTCPSOCK="360:360"
    NUMFLOCK="188:206"
    NUMPTY="16:16"
    NUMSIGINFO="256:256"
    TCPSNDBUF="1720320:2703360"
    TCPRCVBUF="1720320:2703360"
    OTHERSOCKBUF="1126080:2097152"
    DGRAMRCVBUF="262144:262144"
    NUMOTHERSOCK="360:360"
    DCACHESIZE="3409920:3624960"
    NUMFILE="9312:9312"
    AVNUMPROC="180:180"
    NUMIPTENT="200:200"

    # Disk quota parameters (in form of softlimit:hardlimit)
    DISKSPACE="1048576:1153024"
    DISKINODES="200000:220000"
    QUOTATIME="0"

    # CPU fair sheduler parameter
    CPUUNITS="1000"

    VE_ROOT="/home/vz/root/$VEID"
    VE_PRIVATE="/home/vz/private/$VEID"
    OSTEMPLATE="debian-5.0-amd64-minimal"
    ORIGIN_SAMPLE="vps.basic"
    HOSTNAME="server.shorewall.net"
    NAMESERVER="206.124.146.177"
    NAME="server"

    NETIF="ifname=eth0,mac=00:18:51:22:24:80,host_ifname=veth102.0,host_mac=00:18:51:B6:1A:F0"

This server runs the rest of the services for shorewall.net (web server, ftp server, rsyncd, etc.).

With a bridged configuration, the VIF for a VE must be added to the bridge when the VE starts. That is accomplished using mount files.

`/etc/vz/conf/101.mount:`

    #!/bin/bash
    # This script source VPS configuration files in the same order as vzctl does

    # if one of these files does not exist then something is really broken
    [ -f /etc/vz/vz.conf ] || exit 1
    [ -f $VE_CONFFILE ] || exit 1

    # source both files. Note the order, it is important
    . /etc/vz/vz.conf
    . $VE_CONFFILE

    # Add the VIF to the bridge after VE has started
    {
      BRIDGE=vzbr0
      DEV=veth101.0
      while sleep 1; do
        /sbin/ifconfig $DEV 0 >/dev/null 2>&1
        if [ $? -eq 0 ]; then
          /usr/sbin/brctl addif $BRIDGE $DEV
          break
        fi
      done
    } &

`/etc/vz/conf/102.mount:`

    #!/bin/bash
    # This script source VPS configuration files in the same order as vzctl does

    # if one of these files does not exist then something is really broken
    [ -f /etc/vz/vz.conf ] || exit 1
    [ -f $VE_CONFFILE ] || exit 1

    # source both files. Note the order, it is important
    . /etc/vz/vz.conf
    . $VE_CONFFILE

    # Add VIF to bridge after VE has started
    {
      BRIDGE=vzbr0
      DEV=veth102.0
      while sleep 1; do
        /sbin/ifconfig $DEV 0 >/dev/null 2>&1
        if [ $? -eq 0 ]; then
          /usr/sbin/brctl addif $BRIDGE $DEV
          break
        fi
      done
    } &

## Shorewall Configuration on the Host

Below are excerpts from the configuration files as they pertain to the OpenVZ environment. Again, bold font indicates change from the prior configuration.

`/etc/shorewall/zones:`

    #ZONE           TYPE            OPTIONS         IN_OPTIONS              OUT_OPTIONS
    fw              firewall
    net             ipv4            #Internet
    loc             ipv4            #Local wired Zone
    dmz             ipv4            #DMZ
    ...

`/etc/shorewall/params:`

    NET_IF=eth3
    INT_IF=eth1
    VPS_IF=vzbr0
    ...

`/etc/shorewall/interfaces`:

    #ZONE   INTERFACE       OPTIONS
    net     $NET_IF         dhcp,blacklist,tcpflags,optional,routefilter=0,nosmurfs,logmartions=0
    loc     $INT_IF         dhcp,logmartians=1,routefilter=1,nets=(172.20.1.0/24),tcpflags
    dmz     $VPS_IF         logmartians=0,routefilter=0,nets=(206.124.146.177,206.124.146.178),routeback
    ...

`/etc/shorewall/proxyarp:`

    #ADDRESS        INTERFACE     EXTERNAL   HAVEROUTE   PERSISTENT
    206.124.146.177 DMZ_IF        eth2       no          yes
    206.124.146.178 DMZ_IF        eth2       no          yes

This is a multi-ISP configuration so entries are required in `/etc/shorewall/rtrules`:

    #SOURCE   DEST                 PROVIDER  PRIORITY
    -         172.20.0.0/24        main      1000
    -         206.124.146.177      main      1001
    -         206.124.146.178      main      1001

## Shorewall Configuration on Server

I have set up Shorewall on VE 101 (206.124.146.178) just to have an environment to test with. It is a quite vanilla one-interface configuration.

`/etc/shorewall/zones:`

    #ZONE       TYPE         OPTIONS           IN_OPTIONS        OUT_OPTIONS
    fw          firewall
    net         ipv4

`/etc/shorewall/interfaces:`

    #ZONE   INTERFACE      OPTIONS
    net     eth0           dhcp,tcpflags,logmartians,nosmurfs
