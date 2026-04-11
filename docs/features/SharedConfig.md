# Introduction

Iptables separates management of IPv4 and IPv6 configurations. Each address family has its own utility (iptables and ip6tables), and changes made to the configuration of one address family do not affect the other. While Shorewall also separates the address families in this way, it is possible for Shorewall and Shorewall6 to share almost all of the configuration files. This article gives an example.

<div class="caution">

What is shown here currently works best with Debian and derivatives, or when the tarball installer is used and the SPARSE option is enabled when running configure\[.pl\].

</div>

# Environment

In this example, each address family has two Internet interfaces. Both address families share a fast uplink (eth0) that has a single public IPv4 address, but can delegate IPv6 subnets to the Shorewall-based router. Both address families also have a production uplink. For IPv4, Ethernet is used (eth1) and supports the public IPv4 subnet 70.90.191.120/29. For IPv6, a Hurricane Electric 6in4 tunnel is used (sit1), which provides the public IPv6 subnet 2001:470:b:227::/64. The router also has two bridges. A DMZ bridge (br0) provides access to containers running a web server, a mail exchanger, and an IMAPS mail access server. The second bridge (br1) provides access to a container running irssi under screen, allowing constant access to and monitoring of IRC channels.

The firewall's local ethernet interface (eth2) is connected to a Netgear GS108E smart switch with two vlans:

- VLAN 1 (eth2.1) is connected to a wireless access point supporting both IPv4 (172.20.1.0/24) and IPv6 (2601:601:a000:16f2::/64).

- VLAN 2 (eth2.2) is connected to devices located in my office supporting both IPv4 (172.20.1.0/24) and IPv6 (2601:601:a000:16f2::/64).

The switch's management interface is accessed via eth2 (192.168.0.0/24).

<div class="note">

The GS108E does not currently support restricting the management interface to a particular VLAN -- it is accessible from any connected host whose IP configuration allows unrouted access to the switch's IP address.

</div>

Here is a diagram of this installation:

The boxes in the diagram represent the six shorewall zones (The firewall and IPSec vpn zone are not shown).

# Configuration

Here are the contents of /etc/shorewall/ and /etc/shorewal6/:

    root@gateway:~# ls -l /etc/shorewall
    total 132
    -rw-r--r-- 1 root root 1152 May 18 10:51 action.NotSyn
    -rw-r--r-- 1 root root  180 Jun 27 09:24 actions
    -rw-r--r-- 1 root root   60 May 31 17:55 action.SSHLIMIT
    -rw-r--r-- 1 root root   82 Oct  5  2018 arprules
    -rw-r--r-- 1 root root  528 May 25 15:39 blrules
    -rw-r--r-- 1 root root 1797 Sep 16  2019 capabilities
    -rw-r--r-- 1 root root  722 Jul  2 13:49 conntrack
    -rw-r--r-- 1 root root  104 Oct 13  2017 hosts
    -rw-r--r-- 1 root root 1119 Jul  4 14:02 interfaces
    -rw-r--r-- 1 root root  107 Jun 29  2017 isusable
    -rw-r--r-- 1 root root  240 Oct 13  2017 macro.FTP
    -rw-r--r-- 1 root root  773 Jul  2 15:04 mangle
    -rw-r--r-- 1 root root 3108 Jul  3 15:51 params
    -rw-r--r-- 1 root root 1108 Jul  3 16:25 policy
    -rw-r--r-- 1 root root 2098 Apr 23 17:19 providers
    -rw-r--r-- 1 root root  398 Mar 18  2017 proxyarp
    -rw-r--r-- 1 root root  726 Oct 24  2018 routes
    -rw-r--r-- 1 root root  729 Mar  1 11:08 rtrules
    -rw-r--r-- 1 root root 8589 Jul  4 09:34 rules
    -rw-r--r-- 1 root root 5503 Jun  5 17:29 shorewall.conf
    -rw-r--r-- 1 root root 1090 Jul  2 14:32 snat
    -rw-r--r-- 1 root root  180 Jan 30  2018 started
    -rw-r--r-- 1 root root  468 Apr 25 14:42 stoppedrules
    -rw-r--r-- 1 root root  435 Oct 13  2017 tunnels
    -rw-r--r-- 1 root root  978 Jul  3 12:28 zones
    root@gateway:~# ls -l /etc/shorewall6
    total 12
    -rw-r--r-- 1 root root 1786 Sep 16  2019 capabilities
    lrwxrwxrwx 1 root root   19 Jul  6  2017 params -> ../shorewall/params
    -rw-r--r-- 1 root root 5338 Jun  7 16:40 shorewall6.conf

The various configuration files are described in the sections that follow. Note that in all cases, these files use the [alternate format for column specification](../reference/configuration_file_basics.md#Pairs).

## /usr/share/shorewall/shorewallrc

The key setting here is SPARSE=Very

    #
    # Created by Shorewall Core version 5.0.12-RC1 configure.pl - Sep 25 2016 09:30:55
    # rc file: shorewallrc.debian.systemd
    #
    HOST=debian
    PREFIX=/usr
    SHAREDIR=${PREFIX}/share
    LIBEXECDIR=${PREFIX}/share
    PERLLIBDIR=${PREFIX}/share/shorewall
    CONFDIR=/etc
    SBINDIR=/sbin
    MANDIR=${PREFIX}/share/man
    INITDIR=
    INITSOURCE=init.debian.sh
    INITFILE=
    AUXINITSOURCE=
    AUXINITFILE=
    SERVICEDIR=/lib/systemd/system
    SERVICEFILE=$PRODUCT.service.debian
    SYSCONFFILE=default.debian
    SYSCONFDIR=/etc/default
    SPARSE=Very
    ANNOTATED=
    VARLIB=/var/lib
    VARDIR=${VARLIB}/$PRODUCT
    DEFAULT_PAGER=/usr/bin/less

## shorewall.conf and shorewall6.conf

These are the only files that are not shared between the two address families. The key setting is CONFIG_PATH in shorewall6.conf:

    CONFIG_PATH="${CONFDIR}/shorewall6:${CONFDIR}/shorewall:/usr/share/shorewall6:${SHAREDIR}/shorewall"

`/etc/shorewall6/` is only used for processing the `params` and `shorewall6.conf` files.

### shorewall.conf

The contents of /etc/shorewall/shorewall.conf are as follows:

    ###############################################################################
    #
    #  Shorewall Version 5 -- /etc/shorewall/shorewall.conf
    #
    #  For information about the settings in this file, type "man shorewall.conf"
    #
    #  Manpage also online at http://www.shorewall.net/manpages/shorewall.conf.html
    ###############################################################################
    #              S T A R T U P   E N A B L E D
    ###############################################################################
    STARTUP_ENABLED=Yes
    ###############################################################################
    #                V E R B O S I T Y
    ###############################################################################
    VERBOSITY=1
    ###############################################################################
    #                   P A G E R
    ###############################################################################
    PAGER=pager
    ###############################################################################
    #                F I R E W A L L
    ###############################################################################
    FIREWALL=
    ###############################################################################
    #                  L O G G I N G
    ###############################################################################
    LOG_LEVEL="NFLOG(0,64,1)"
    BLACKLIST_LOG_LEVEL="none"
    INVALID_LOG_LEVEL=
    LOG_BACKEND=netlink
    LOG_MARTIANS=Yes
    LOG_VERBOSITY=1
    LOG_ZONE=Src
    LOGALLNEW=
    LOGFILE=/var/log/ulogd/ulogd.syslogemu.log
    LOGFORMAT="%s %s"
    LOGTAGONLY=Yes
    LOGLIMIT="s:5/min"
    MACLIST_LOG_LEVEL="$LOG_LEVEL"
    RELATED_LOG_LEVEL="$LOG_LEVEL:"
    RPFILTER_LOG_LEVEL="$LOG_LEVEL:"
    SFILTER_LOG_LEVEL="$LOG_LEVEL"
    SMURF_LOG_LEVEL="$LOG_LEVEL"
    STARTUP_LOG=/var/log/shorewall-init.log
    TCP_FLAGS_LOG_LEVEL="$LOG_LEVEL"
    UNTRACKED_LOG_LEVEL=
    ###############################################################################
    #   L O C A T I O N   O F   F I L E S   A N D   D I R E C T O R I E S
    ###############################################################################
    ARPTABLES=
    CONFIG_PATH="/etc/shorewall:/usr/share/shorewall:/usr/share/shorewall/Shorewall"
    GEOIPDIR=/usr/share/xt_geoip/LE
    IPTABLES=/sbin/iptables
    IP=/sbin/ip
    IPSET=
    LOCKFILE=/var/lib/shorewall/lock
    MODULESDIR="+extra/RTPENGINE"
    NFACCT=
    PATH="/usr/local/sbin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin"
    PERL=/usr/bin/perl
    RESTOREFILE=
    SHOREWALL_SHELL=/bin/sh
    SUBSYSLOCK=
    TC=
    ###############################################################################
    #       D E F A U L T   A C T I O N S / M A C R O S
    ###############################################################################
    ACCEPT_DEFAULT="none"
    BLACKLIST_DEFAULT="NotSyn(DROP):$LOG_LEVEL"
    DROP_DEFAULT="Broadcast(DROP),Multicast(DROP)"
    NFQUEUE_DEFAULT="none"
    QUEUE_DEFAULT="none"
    REJECT_DEFAULT="Broadcast(DROP),Multicast(DROP)"
    ###############################################################################
    #            R S H / R C P  C O M M A N D S
    ###############################################################################
    RCP_COMMAND='scp ${files} ${root}@${system}:${destination}'
    RSH_COMMAND='ssh ${root}@${system} ${command}'
    ###############################################################################
    #           F I R E W A L L   O P T I O N S
    ###############################################################################
    ACCOUNTING=Yes
    ACCOUNTING_TABLE=filter
    ADD_IP_ALIASES=No
    ADD_SNAT_ALIASES=No
    ADMINISABSENTMINDED=Yes
    AUTOCOMMENT=Yes
    AUTOHELPERS=No
    AUTOMAKE=Yes
    BALANCE_PROVIDERS=No
    BASIC_FILTERS=No
    BLACKLIST="NEW,INVALID,UNTRACKED"
    CLAMPMSS=No
    CLEAR_TC=Yes
    COMPLETE=No
    DEFER_DNS_RESOLUTION=No
    DELETE_THEN_ADD=No
    DETECT_DNAT_IPADDRS=No
    DISABLE_IPV6=No
    DOCKER=No
    DONT_LOAD="nf_nat_sip,nf_conntrack_sip,nf_conntrack_h323,nf_nat_h323"
    DYNAMIC_BLACKLIST="ipset-only,disconnect,timeout=7200,log,noupdate"
    EXPAND_POLICIES=No
    EXPORTMODULES=Yes
    FASTACCEPT=Yes
    FORWARD_CLEAR_MARK=No
    HELPERS="ftp,irc"
    IGNOREUNKNOWNVARIABLES=No
    IMPLICIT_CONTINUE=No
    IPSET_WARNINGS=Yes
    IP_FORWARDING=Yes
    KEEP_RT_TABLES=Yes
    MACLIST_TABLE=filter
    MACLIST_TTL=60
    MANGLE_ENABLED=Yes
    MARK_IN_FORWARD_CHAIN=No
    MINIUPNPD=No
    MULTICAST=No
    MUTEX_TIMEOUT=60
    NULL_ROUTE_RFC1918=unreachable
    OPTIMIZE=All
    OPTIMIZE_ACCOUNTING=No
    PERL_HASH_SEED=12345
    REJECT_ACTION=
    RENAME_COMBINED=No
    REQUIRE_INTERFACE=No
    RESTART=restart
    RESTORE_DEFAULT_ROUTE=No
    RESTORE_ROUTEMARKS=Yes
    RETAIN_ALIASES=No
    ROUTE_FILTER=No
    SAVE_ARPTABLES=No
    SAVE_IPSETS=ipv4
    TC_ENABLED=No
    TC_EXPERT=No
    TC_PRIOMAP="2 3 3 3 2 3 1 1 2 2 2 2 2 2 2 2"
    TRACK_PROVIDERS=Yes
    TRACK_RULES=No
    USE_DEFAULT_RT=Yes
    USE_NFLOG_SIZE=Yes
    USE_PHYSICAL_NAMES=Yes
    USE_RT_NAMES=Yes
    VERBOSE_MESSAGES=No
    WARNOLDCAPVERSION=Yes
    WORKAROUNDS=No
    ZERO_MARKS=No
    ZONE2ZONE=-
    ###############################################################################
    #           P A C K E T   D I S P O S I T I O N
    ###############################################################################
    BLACKLIST_DISPOSITION=DROP
    INVALID_DISPOSITION=CONTINUE
    MACLIST_DISPOSITION=ACCEPT
    RELATED_DISPOSITION=REJECT
    RPFILTER_DISPOSITION=DROP
    SMURF_DISPOSITION=DROP
    SFILTER_DISPOSITION=DROP
    TCP_FLAGS_DISPOSITION=DROP
    UNTRACKED_DISPOSITION=DROP
    ################################################################################
    #           P A C K E T  M A R K  L A Y O U T
    ################################################################################
    TC_BITS=8
    PROVIDER_BITS=2
    PROVIDER_OFFSET=16
    MASK_BITS=8
    ZONE_BITS=0

### shorewall6.conf

The contents of /etc/shorewall6/shorewall6.conf are:

    ###############################################################################
    #
    #  Shorewall Version 5 -- /etc/shorewall6/shorewall6.conf
    #
    #  For information about the settings in this file, type "man shorewall6.conf"
    #
    #  Manpage also online at
    #  http://www.shorewall.net/manpages6/shorewall6.conf.html
    ###############################################################################
    #              S T A R T U P   E N A B L E D
    ###############################################################################
    STARTUP_ENABLED=Yes
    ###############################################################################
    #                V E R B O S I T Y
    ###############################################################################
    VERBOSITY=1
    ###############################################################################
    #                   P A G E R
    ###############################################################################
    PAGER=pager
    ###############################################################################
    #                F I R E W A L L
    ###############################################################################
    FIREWALL=
    ###############################################################################
    #                  L O G G I N G
    ###############################################################################
    LOG_LEVEL="NFLOG(0,64,1)"
    BLACKLIST_LOG_LEVEL="none"
    INVALID_LOG_LEVEL=
    LOG_BACKEND=netlink
    LOG_VERBOSITY=2
    LOG_ZONE=Src
    LOGALLNEW=
    LOGFILE=/var/log/ulogd/ulogd.syslogemu.log
    LOGFORMAT="%s %s"
    LOGLIMIT="s:5/min"
    LOGTAGONLY=Yes
    MACLIST_LOG_LEVEL="$LOG_LEVEL"
    RELATED_LOG_LEVEL="$LOG_LEVEL"
    RPFILTER_LOG_LEVEL="$LOG_LEVEL"
    SFILTER_LOG_LEVEL="$LOG_LEVEL"
    SMURF_LOG_LEVEL="$LOG_LEVEL"
    STARTUP_LOG=/var/log/shorewall6-init.log
    TCP_FLAGS_LOG_LEVEL="$LOG_LEVEL"
    UNTRACKED_LOG_LEVEL=
    ###############################################################################
    #   L O C A T I O N   O F   F I L E S   A N D   D I R E C T O R I E S
    ###############################################################################
    CONFIG_PATH="${CONFDIR}/shorewall6:${CONFDIR}/shorewall:/usr/share/shorewall6:${SHAREDIR}/shorewall"
    GEOIPDIR=/usr/share/xt_geoip/LE
    IP6TABLES=
    IP=
    IPSET=
    LOCKFILE=
    MODULESDIR="+extra/RTPENGINE"
    NFACCT=
    PERL=/usr/bin/perl
    PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin"
    RESTOREFILE=restore
    SHOREWALL_SHELL=/bin/sh
    SUBSYSLOCK=/var/lock/subsys/shorewall6
    TC=
    ###############################################################################
    #       D E F A U L T   A C T I O N S / M A C R O S
    ###############################################################################
    ACCEPT_DEFAULT="none"
    BLACKLIST_DEFAULT="AllowICMPs,Broadcast(DROP),Multicast(DROP),NotSyn(DROP):$LOG_LEVEL,dropInvalid:$LOG_LEVEL,DropDNSrep:$LOG_LEVEL"
    DROP_DEFAULT="AllowICMPs,Broadcast(DROP),Multicast(DROP)"
    NFQUEUE_DEFAULT="none"
    QUEUE_DEFAULT="none"
    REJECT_DEFAULT="AllowICMPs,Broadcast(DROP),Multicast(DROP)"
    ###############################################################################
    #            R S H / R C P  C O M M A N D S
    ###############################################################################
    RCP_COMMAND='scp ${files} ${root}@${system}:${destination}'
    RSH_COMMAND='ssh ${root}@${system} ${command}'
    ###############################################################################
    #           F I R E W A L L   O P T I O N S
    ###############################################################################
    ACCOUNTING=Yes
    ACCOUNTING_TABLE=mangle
    ADMINISABSENTMINDED=Yes
    AUTOCOMMENT=Yes
    AUTOHELPERS=No
    AUTOMAKE=Yes
    BALANCE_PROVIDERS=No
    BASIC_FILTERS=No
    BLACKLIST="NEW,INVALID,UNTRACKED"
    CLAMPMSS=Yes
    CLEAR_TC=No
    COMPLETE=No
    DEFER_DNS_RESOLUTION=Yes
    DELETE_THEN_ADD=No
    DONT_LOAD=
    DYNAMIC_BLACKLIST="ipset-only,disconnect,timeout=7200,log,noupdate"
    EXPAND_POLICIES=No
    EXPORTMODULES=Yes
    FASTACCEPT=Yes
    FORWARD_CLEAR_MARK=No
    HELPERS=ftp
    IGNOREUNKNOWNVARIABLES=No
    IMPLICIT_CONTINUE=No
    IPSET_WARNINGS=Yes
    IP_FORWARDING=Keep
    KEEP_RT_TABLES=Yes
    MACLIST_TABLE=filter
    MACLIST_TTL=
    MANGLE_ENABLED=Yes
    MARK_IN_FORWARD_CHAIN=No
    MINIUPNPD=No
    MUTEX_TIMEOUT=60
    OPTIMIZE=All
    OPTIMIZE_ACCOUNTING=No
    PERL_HASH_SEED=0
    REJECT_ACTION=
    RENAME_COMBINED=No
    REQUIRE_INTERFACE=No
    RESTART=restart
    RESTORE_DEFAULT_ROUTE=No
    RESTORE_ROUTEMARKS=Yes
    SAVE_IPSETS=No
    TC_ENABLED=Shared
    TC_EXPERT=No
    TC_PRIOMAP="2 3 3 3 2 3 1 1 2 2 2 2 2 2 2 2"
    TRACK_PROVIDERS=Yes
    TRACK_RULES=No
    USE_DEFAULT_RT=Yes
    USE_NFLOG_SIZE=Yes
    USE_PHYSICAL_NAMES=Yes
    USE_RT_NAMES=No
    VERBOSE_MESSAGES=No
    WARNOLDCAPVERSION=Yes
    WORKAROUNDS=No
    ZERO_MARKS=No
    ZONE2ZONE=-
    ###############################################################################
    #           P A C K E T   D I S P O S I T I O N
    ###############################################################################
    BLACKLIST_DISPOSITION=DROP
    INVALID_DISPOSITION=CONTINUE
    MACLIST_DISPOSITION=REJECT
    RELATED_DISPOSITION=REJECT
    SFILTER_DISPOSITION=DROP
    RPFILTER_DISPOSITION=DROP
    SMURF_DISPOSITION=DROP
    TCP_FLAGS_DISPOSITION=DROP
    UNTRACKED_DISPOSITION=DROP
    ################################################################################
    #           P A C K E T  M A R K  L A Y O U T
    ################################################################################
    TC_BITS=8
    PROVIDER_BITS=2
    PROVIDER_OFFSET=8
    MASK_BITS=8
    ZONE_BITS=0

## params

Because addresses and interfaces are different between the two address families, they cannot be hard-coded in the configuration files. `/etc/shorewall/params` is used to set shell variables whose contents will vary between Shorewall and Shorewall6. In the `params` file and in run-time extension files, the shell variable **g_family** can be used to determine which address family to use; if IPv4, then \$g_family will expand to 4 and if IPv6, \$g_family will expand to 6.

The contents of /etc/shorewall/params is as follows:

    #
    # Set compile-time variables depending on the address family
    #
    if [ $g_family = 4 ]; then
        #
        # IPv4 compilation
        #
        FALLBACK=Yes           # Make FAST_IF the primary and PROD_IF the fallback interface
                   # See /etc/shorewall/providers
        STATISTICAL=       # Use statistical load balancing
        LISTS=70.90.191.124    # IP address of lists.shorewall.net (MX)
        MAIL=70.90.191.122     # IP address of mail.shorewall.net  (IMAPS)
        SERVER=70.90.191.125   # IP address of www.shorewall.org
        IRSSIEXT=10.2.10.2     # External address of irssi.shorewall.net
        IRSSIINT=172.20.2.44   # Internal IP address of irssi.shorewall.net
        PROXY=Yes          # Use TPROXY for local web access
        ALL=0.0.0.0/0      # Entire address space
        LOC_ADDR=172.20.1.253  # IP address of the local LAN interface
        FAST_GATEWAY=10.2.10.1 # Default gateway through the IF_FAST interface
        FAST_MARK=0x20000      # Multi-ISP mark setting for IF_FAST
        IPSECMSS=1460
        DBL_SET=SW_DBL4
        #
        # Interface Options
        #
        LOC_OPTIONS=dhcp,ignore=1,wait=5,routefilter,tcpflags=0,nodbl,physical=eth2.2
        WLAN_OPTIONS=dhcp,ignore=1,wait=5,routefilter,tcpflags=0,nodbl,physical=eth2.1
        FAST_OPTIONS=optional,dhcp,tcpflags,nosmurfs,sourceroute=0,arp_ignore=1,proxyarp=0,nosmurfs,rpfilter,physical=eth0
        PROD_OPTIONS=optional,dhcp,tcpflags,nosmurfs,sourceroute=0,arp_ignore=1,proxyarp=0,nosmurfs,rpfilter,physical=eth1
        DMZ_OPTIONS=routeback,proxyarp=1,required,wait=30,nets=70.90.191.120/29,nodbl,physical=br0
        IRC_OPTIONS=routeback,proxyarp=1,required,wait=30,nets=172.20.2.0/24,dhcp,nodbl,physical=br1
        SWCH_OPTIONS=dhcp,tcpflags=0,nodbl,physical=eth2
    else
        #
        # IPv6 compilation
        #
        FALLBACK=Yes                  # Make FAST_IF the primary and PROD_IF the fallback interface
                              # See /etc/shorewall/providers
        STATISTICAL=No                # Don't use statistical load balancing
        LISTS=[2001:470:b:227::42]            # IP address of lists.shorewall.net (MX and HTTPS)
        MAIL=[2001:470:b:227::45]             # IP address of mail.shorewall.net  (IMAPS and HTTPS)
        SERVER=[2001:470:b:227::43]           # IP address of server.shorewall.net(FTP)
        IRSSI=[2601:601:a000:16f1::]/64       # IP address of irssi.shorewall.net
        PROXY=Yes                     # Use TPROXY for local web access
        ALL=[::]/0                    # Entire address space
        LOC_ADDR=[2601:601:a000:16f0::1]          # IP address of the local LAN interface
        FAST_GATEWAY=2601:601:a000:1600:22e5:2aff:feb7:f2cf
        FAST_MARK=0x100               # Multi-ISP mark setting for IF_FAST
        IPSECMSS=1440
        DBL_SET=SW_DBL6
        #
        # Interface Options
        #
        PROD_OPTIONS=forward=1,optional,rpfilter,routeback,physical=sit1
        FAST_OPTIONS=forward=1,optional,dhcp,rpfilter,physical=eth0
        LOC_OPTIONS=forward=1,nodbl,routeback,physical=eth2.2
        DMZ_OPTIONS=routeback,forward=1,required,wait=30,nodbl,physical=br0
        IRC_OPTIONS=routeback,forward=1,required,wait=30,nodbl,physical=br1
        WLAN_OPTIONS=forward=1,nodbl,routeback,physical=eth2.1
    fi

## zones

Here is the /etc/shorewall/zones file:

    #ZONE TYPE    OPTIONS         IN          OUT
    #                   OPTIONS         OPTIONS

    #
    # By using the 'ip' type, both Shorewall and Shorewall6 can share this file
    #

    fw  { TYPE=firewall }
    net { TYPE=ip }
    loc { TYPE=ip }
    dmz { TYPE=ip }
    apps    { TYPE=ip }
    vpn { TYPE=ipsec, OPTIONS=mode=tunnel,proto=esp,mss=$IPSECMSS }
    wlan    { TYPE=ip }
    ?if __IPV4
    swch    { TYPE=local }
    ?endif

## interfaces

/etc/shorewall/interfaces makes heavy use of variables set in /etc/shorewall/params:

    ?FORMAT 2
    ###############################################################################
    #ZONE   INTERFACE   OPTIONS

    #
    # The two address families use different production interfaces and different 
    #
    # LOC_IF is the local LAN for both families
    # FAST_IF is a Comcast IPv6 beta uplink which is used for internet access from the local lan for both families
    # PROD_IF is the interface used by shorewall.org servers
    #     For IPv4, it is eth1
    #     For IPv6, it is sit1 (Hurricane Electric 6in4 link)
    # DMZ_IF is a bridge to the production containers
    # IRC_IF is a bridge to a container that currently runs irssi under screen
    # WLAN_IF is a vlan interface that connects to the wireless networks
    # SWCH_IF is the vlan trunk interface used for switch management

    loc  { INTERFACE=LOC_IF,  OPTIONS=$LOC_OPTIONS }
    wlan { INTERFACE=WLAN_IF, OPTIONS=$WLAN_OPTIONS }
    net  { INTERFACE=FAST_IF, OPTIONS=$FAST_OPTIONS }
    net  { INTERFACE=PROD_IF, OPTIONS=$PROD_OPTIONS }
    dmz  { INTERFACE=DMZ_IF,  OPTIONS=$DMZ_OPTIONS }
    apps { INTERFACE=IRC_IF,  OPTIONS=$IRC_OPTIONS }
    ?if __IPV4
    swch { INTERFACE=SWCH_IF, OPTIONS=$SWCH_OPTIONS }
    ?endif

## hosts

/etc/shorewall/hosts is used to define the vpn zone:

    ##ZONE        HOSTS               OPTIONS
    vpn { HOSTS=PROD_IF:$ALL }
    vpn { HOSTS=FAST_IF:$ALL }
    vpn { HOSTS=LOC_IF:$ALL }

## policy

The same set of policies apply to both address families:

    SOURCE           DEST      POLICY                                   LOGLEVEL        RATE

    $FW       { DEST=dmz,net,    POLICY=REJECT,                               LOGLEVEL=$LOG_LEVEL }

    ?if __IPV4
    $FW       { DEST=all,    POLICY=ACCEPT:Broadcast(ACCEPT),Multicast(ACCEPT),           LOGLEVEL=$LOG_LEVEL }
    ?else
    $FW       { DEST=all,    POLICY=ACCEPT:AllowICMPs,Broadcast(ACCEPT),Multicast(ACCEPT)         LOGLEVEL=$LOG_LEVEL }
    ?endif

    loc,apps,wlan { DEST=net,    POLICY=ACCEPT }
    loc,vpn,apps  { DEST=loc,vpn,apps POLICY=ACCEPT }
    loc       { DEST=fw,         POLICY=REJECT,                               LOGLEVEL=$LOG_LEVEL }

    ?if __IPV4
    net       { DEST=net,    POLICY=NONE }
    ?else
    net       { DEST=net,    POLICY=REJECT,                               LOGLEVEL=$LOG_LEVEL }
    ?endif
    net       { DEST=fw,     POLICY=BLACKLIST:+Broadcast(DROP),Multicast(DROP),DropDNSrep:$LOG_LEVEL, LOGLEVEL=$LOG_LEVEL, RATE=8/sec:30 }
    net       { DEST=all,    POLICY=BLACKLIST:+DropDNSrep:$LOG_LEVEL,                 LOGLEVEL=$LOG_LEVEL, RATE=8/sec:30 }

    dmz       { DEST=fw,     POLICY=REJECT,                               LOGLEVEL=$LOG_LEVEL }
    dmz       { DEST=dmz,    POLICY=REJECT,                               LOGLEVEL=$LOG_LEVEL }
    all       { DEST=all,    POLICY=REJECT,                               LOGLEVEL=$LOG_LEVEL }

## providers

The providers file is set up to allow for three different configurations:

1.  FALLBACK -- FAST_IF is the primary interface and PROD_IF is the fallback

2.  STATISTICAL -- Statistical load balancing between FAST_IF and PROD_IF

3.  IPv4 only -- balance between FAST_IF and PROD_IF

<!-- -->

    #NAME     NUMBER   MARK    DUPLICATE  INTERFACE   GATEWAY         OPTIONS               COPY

    #
    # This could be cleaned up a bit, but I'm leaving it as is for now
    #
    #   - The two address families use different fw mark geometry
    #   - The two address families use different fallback interfaces
    #   - The 'balance' option doesn't work as expected in IPv6 so I have no balance configuration for Shorewall6
    #   - IPv4 uses the 'loose' option on PROD_IF
    #
    ?if $FALLBACK
        # FAST_IF is primary, PROD_IF is fallback
        #
        ?if $VERBOSITY > 0
            ?info Compiling with FALLBACK
        ?endif
        IPv6Beta        { NUMBER=1, MARK=$FAST_MARK, INTERFACE=FAST_IF, GATEWAY=$FAST_GATEWAY, OPTIONS=loose,primary,persistent,noautosrc }
        ?if __IPV4
        ComcastB    { NUMBER=4, MARK=0x10000,    INTERFACE=PROD_IF, GATEWAY=10.1.10.1, OPTIONS=loose,fallback,persistent }
        ?else    
        HE      { NUMBER=2, MARK=0x200,  INTERFACE=PROD_IF, OPTIONS=fallback,persistent }
        ?endif
    ?elsif $STATISTICAL
        # Statistically balance traffic between FAST_IF and PROD_IF
        ?if $VERBOSITY > 0
            ?info Compiling with STATISTICAL
        ?endif
        ?if __IPV4
            IPv6Beta    { NUMBER=1, MARK=0x20000, INTERFACE=FAST_IF, GATEWAY=$FAST_GATEWAY, OPTIONS=loose,load=0.66666667,primary,persistent }
        ComcastB    { NUMBER=4, MARK=0x10000, INTERFACE=PROD_IF, GATEWAY=10.1.10.1, OPTIONS=loose,load=0.33333333,fallback,persistent }
        ?else
        HE      { NUMBER=2, MARK=0x200,   INTERFACE=PROD_IF,                        OPTIONS=track,load=0.33333333,persistent }
        ?endif
    ?else
        ?if $VERBOSITY > 0
            ?info Compiling with BALANCE
        ?endif
        IPv6Beta     { NUMBER=1, MARK=$FAST_MARK, INTERFACE=FAST_IF, GATEWAY=$FAST_GATEWAY, OPTIONS=track,balance=2,loose,persistent }
        ?if __IPV4
        ComcastB { NUMBER=4, MARK=0x10000,    INTERFACE=PROD_IF, GATEWAY=10.1.10.1,     OPTIONS=nohostroute,loose,balance,persistent }
        ?else
            ?warning No BALANCE IPv6 configuration
        HE   { NUMBER=2, MARK=0x200,   INTERFACE=PROD_IF,                OPTIONS=fallback,persistent }
        ?endif    
    ?endif

    Tproxy   { NUMBER=3, INTERFACE=lo, OPTIONS=tproxy }

## rtrules

The routing rules are quite dependent on the address family:

    #SOURCE             DEST             PROVIDER  PRIORITY

    #
    # This file ensures that the DMZ is routed out of the IF_PROD interface
    # and that the IPv6 subnets delegated by the Beta router are routed out
    # of the IF_FAST interface.
    #
    ?if __IPV4
        { SOURCE=70.90.191.121,70.90.191.123,10.1.10.1 PROVIDER=ComcastB, PRIORITY=1000! }
        { SOURCE=&FAST_IF,                         PROVIDER=IPv6Beta, PRIORITY=1000! }
        { SOURCE=br0,                      PROVIDER=ComcastB, PRIORITY=11000 }
    ?else
        { SOURCE=2601:601:a000:1600::/64           PROVIDER=IPv6Beta, PRIORITY=1000! }
        { SOURCE=2001:470:B:227::/64,              PROVIDER=HE,       PRIORITY=1000! }
        { SOURCE=2601:601:a000:16f0::/60           PROVIDER=IPv6Beta, PRIORITY=11000 }
    ?endif

## routes

This file is used only for IPv6:

    #PROVIDER     DEST            GATEWAY     DEVICE  OPTIONS
    ?if __IPV6
        #
        # In my version of FOOLSM (1.0.10), the 'sourceip' option doesn't work.
        # As a result, routing rules that specify the source IPv6 address are
        # not effective in routing the 'ping' request packets out of FAST_IF.
        # The following route solves that problem.
        #
        { PROVIDER=main, DEST=2001:558:4082:d3::1/128, GATEWAY=$FAST_GATEWAY, DEVICE=FAST_IF, OPTIONS=persistent }
    ?endif

## actions

/etc/shorewall/actions defines a single action:

    #ACTION      OPTIONS            COMMENT
    SSHLIMIT     proto=tcp,\    # Blacklist overzealous SSHers
             dport=ssh

/etc/shorewall/action.SSHLIMIT:

    ACCEPT { RATE=s:3/min:3 }
    BLACKLIST:$LOG_LEVEL:net_SSHLIMIT

## Macros

/etc/shorewall/macro.FTP:

    ###############################################################################
    #ACTION SOURCE  DEST    PROTO   DPORT   SPORT   ORIGDEST    RATE    USER
    PARAM   -   -   tcp 21

This is just the normal Shorewall FTP macro without the helper logic -- we take care of that in the conntrack file below.

## conntrack

In addition to invoking the FTP helper on TCP port 21, this file notracks some IPv4 traffic:

    ?FORMAT 3
    ######################################################################################################
    #ACTION         SOURCE      DEST        PROTO   DPORT       SPORT   USER    SWITCH

    CT:helper:ftp:P  { PROTO=tcp, DPORT=21 }
    CT:helper:ftp:O  { PROTO=tcp, DPORT=21 }

    ?if __IPV4
        #
        # Don't track IPv4 broadcasts
        #
        NOTRACK:P       { SOURCE=LOC_IF, DEST=172.20.1.255,   PROTO=udp }
        NOTRACK:P       { DEST=255.255.255.255,               PROTO=udp }
        NOTRACK:O       { DEST=255.255.255.255,               PROTO=udp }
        NOTRACK:O       { DEST=LOC_IF:172.20.0.255,       PROTO=udp }
        NOTRACK:O       { DEST=LOC_IF:172.20.1.255,       PROTO=udp }
        NOTRACK:O       { DEST=PROD_IF:70.90.191.127,         PROTO=udp }
    ?endif

## rules

/etc/shorewall/rules has only a couple of rules that are conditional based on address family:

    ##############################################################################################################################################################
    #ACTION     SOURCE      DEST        PROTO   DPORT   SPORT   ORIGDEST    RATE    USER    MARK    CONNLIMIT   TIME    HEADERS SWITCH  HELPER

    ?SECTION ALL

    Ping(ACCEPT)    { SOURCE=net, DEST=all, RATE=d:ping(1024,65536):2/sec:10 }
    Trcrt(ACCEPT)   { SOURCE=net, DEST=all, RATE=d:ping(1024,65536):2/sec:10 }

    ?SECTION ESTABLISHED

    ?SECTION RELATED

    ACCEPT      { SOURCE=all, DEST=dmz:$SERVER, PROTO=tcp,  DPORT=61001:62000,  helper=ftp }
    ACCEPT      { SOURCE=dmz, DEST=all,     PROTO=tcp,  helper=ftp }
    ACCEPT      { SOURCE=all, DEST=net,     PROTO=tcp,  helper=ftp }
    ACCEPT      { SOURCE=$FW, DEST=loc,     PROTO=tcp,  helper=ftp }
    ACCEPT      { SOURCE=loc, DEST=$FW,     PROTO=tcp,  helper=ftp }
    ACCEPT      { SOURCE=all, DEST=all,     PROTO=icmp }
    RST(ACCEPT) { SOURCE=all, DEST=all }
    ACCEPT      { SOURCE=dmz, DEST=dmz }
    ACCEPT      { SOURCE=$FW, DEST=$FW }

    ?SECTION INVALID

    RST(ACCEPT) { SOURCE=all, DEST=all }
    FIN(ACCEPT) { SOURCE=all, DEST=all }
    DROP        { SOURCE=net, DEST=all }

    ?SECTION UNTRACKED

    ?if __IPV4
    Broadcast(ACCEPT) { SOURCE=all, DEST=$FW }
    ACCEPT        { SOURCE=all, DEST=$FW, PROTO=udp }
    CONTINUE      { SOURCE=loc, DEST=$FW }
    CONTINUE      { SOURCE=$FW, DEST=all }
    ?endif

    ?SECTION NEW

    ######################################################################################################
    # Stop certain outgoing traffic to the net
    #
    REJECT:$LOG_LEVEL { SOURCE=loc,vpn,apps DEST=net, PROTO=tcp, DPORT=25 }     #Stop direct loc->net SMTP (Comcast uses submission).
    #REJECT:$LOG_LEVEL { SOURCE=loc,vpn,apps DEST=net, PROTO=udp, DPORT=1025:1031 } #MS Messaging

    REJECT      { SOURCE=all!dmz,apps, DEST=net, PROTO=tcp, DPORT=137,445, comment="Stop NETBIOS Crap" }
    REJECT      { SOURCE=all!dmz,apps, DEST=net, PROTO=udp, DPORT=137:139, comment="Stop NETBIOS Crap" }

    REJECT      { SOURCE=all, DEST=net, PROTO=tcp, DPORT=3333, comment="Disallow port 3333" }

    REJECT      { SOURCE=all, DEST=net, PROTO=udp, DPORT=3544, comment="Stop Teredo" }

    ?if __IPV6
    DROP        { SOURCE=net:PROD_IF, DEST=net:PROD_IF }
    ?endif

    ?COMMENT

    ######################################################################################################
    # SACK
    #
    DROP:$LOG_LEVEL  { SOURCE=net, DEST=all } ;;+ -p tcp -m tcpmss --mss 1:535

    ######################################################################################################
    # 6in4
    #
    ?if __IPV4
        ACCEPT          { SOURCE=net:216.218.226.238, DEST=$FW, PROTO=41 }
        ACCEPT          { SOURCE=$FW, DEST=net:216.218.226.238, PROTO=41 }
    ?endif
    ######################################################################################################
    # Ping
    #
    Ping(ACCEPT)      { SOURCE=all!net, DEST=all }
    Ping(ACCEPT)      { SOURCE=dmz, DEST=dmz }
    ?if __IPV4
    Ping(ACCEPT)      { source=$FW, DEST=swch }
    ?endif
    ######################################################################################################
    # Logging
    #
    Syslog(ACCEPT)    { SOURCE=dmz, DEST=$FW }
    ######################################################################################################
    # SSH
    #
    SSH(DROP)     { SOURCE=net, DEST=dmz:$SERVER }
    SSHLIMIT      { SOURCE=net, DEST=all }
    ?if __IPV4
    SSH(ACCEPT)   { SOURCE=all+!swch, DEST=all+ }
    SSH(DNAT-)    { SOURCE=net,              DEST=172.20.2.44, PROTO=tcp, DPORT=ssh, ORIGDEST=70.90.191.123 }
    ?else
    SSH(ACCEPT)   { SOURCE=all+, DEST=all+ }
    ?endif
    ######################################################################################################
    # DNS
    #
    DNS(ACCEPT)   { SOURCE=loc,dmz,vpn,apps,wlan, DEST=$FW }
    DNS(ACCEPT)   { SOURCE=$FW,  DEST=net }
    ?if $TEST
    DNS(REDIRECT)     loc       53   -  53  -   !&LOC_IF
    DNS(REDIRECT)     fw        53   -  53  -   !::1
    ?endif
    DropDNSrep        { SOURCE=net, DEST=all }
    ######################################################################################################
    # Traceroute
    #
    Trcrt(ACCEPT)     { SOURCE=all, DEST=net }
    Trcrt(ACCEPT)     { SOURCE=net, DEST=$FW,dmz }
    ######################################################################################################
    # Email
    #
    SMTP(ACCEPT)       { SOURCE=net,$FW, DEST=dmz:$LISTS }
    SMTP(ACCEPT)       { SOURCE=dmz:$LISTS, DEST=net:PROD_IF }
    SMTP(ACCEPT)       { SOURCE=dmz, DEST=dmz:$LISTS }
    SMTP(REJECT)       { SOURCE=dmz:$LISTS, DEST=net }
    IMAPS(ACCEPT)      { SOURCE=all, DEST=dmz:$MAIL }
    Submission(ACCEPT) { SOURCE=all, DEST=dmz:$LISTS }
    SMTPS(ACCEPT)      { SOURCE=all, DEST=dmz:$LISTS }
    IMAP(REJECT)       { SOURCE=net, DEST=all }
    ######################################################################################################
    # NTP
    #
    NTP(ACCEPT)    { SOURCE=all, DEST=net }
    ######################################################################################################
    # Squid
    ACCEPT { SOURCE=loc,vpn,wlan, DEST=$FW, PROTO=tcp, DPORT=3128 } 
    ######################################################################################################
    # HTTP/HTTPS
    #
    Web(ACCEPT)    { SOURCE=loc,vpn,wlan DEST=$FW }
    Web(ACCEPT)    { SOURCE=$FW, DEST=net, USER=proxy }
    Web(DROP)      { SOURCE=net, DEST=fw, PROTO=tcp, comment="Do not blacklist web crawlers" }
    HTTP(ACCEPT)       { SOURCE=net,loc,vpn,wlan,$FW DEST=dmz:$SERVER,$LISTS,$MAIL }
    HTTPS(ACCEPT)      { SOURCE=net,loc,vpn,wlan,$FW DEST=dmz:$SERVER,$LISTS,$MAIL }
    Web(ACCEPT)    { SOURCE=dmz,apps,loc,wlan, DEST=net,$FW }
    Web(ACCEPT)    { SOURCE=$FW, DEST=net, USER=root }
    Web(ACCEPT)    { SOURCE=$FW, DEST=net, USER=teastep }
    ?if __IPV4
    Web(ACCEPT)    { SOURCE=$FW, DEST=swch, USER=teastep }
    ?endif
    Web(ACCEPT)    { SOURCE=$FW, DEST=net, USER=_apt }
    ######################################################################################################
    # FTP
    #
    FTP(ACCEPT)    { SOURCE=dmz,               DEST=net }
    FTP(ACCEPT)    { SOURCE=$FW,               DEST=net, USER=root }
    FTP(ACCEPT)    { SOURCE=all,               DEST=dmz:$SERVER }
    #
    # Some FTP clients seem prone to sending the PORT command split over two packets.
    # This prevents the FTP connection tracking code from processing the command and setting
    # up the proper expectation.
    #
    # The following rule allows active FTP to work in these cases
    # but logs the connection so I can keep an eye on this potential security hole.
    #
    ACCEPT:$LOG_LEVEL  { SOURCE=dmz, DEST=net, PROTO=tcp, DPORT=1024:, SPORT=20 }
    ######################################################################################################
    # Git
    #
    Git(ACCEPT)        { source=all, DEST=dmz:$SERVER }
    ######################################################################################################
    # whois
    #
    Whois(ACCEPT)      { SOURCE=all, DEST=net }
    ######################################################################################################
    # SMB
    #
    SMBBI(ACCEPT)       { SOURCE=loc,wlan, DEST=$FW }
    SMBBI(ACCEPT)       { SOURCE=vpn,      DEST=$FW }
    ######################################################################################################
    # IRC
    #
    SetEvent(IRC)                         { SOURCE=loc,apps,wlan, DEST=net, PROTO=tcp, DPORT=6667 }
    IfEvent(IRC,ACCEPT,10,1,dst,reset)    { SOURCE=net, DEST=loc,apps,wlan, PROTO=tcp, DPORT=113 }
    ######################################################################################################
    # AUTH
    Auth(REJECT)    { SOURCE=net, DEST=all }
    ######################################################################################################
    # IPSEC
    #
    ?if __IPV4
    DNAT        { SOURCE=loc,net,wlan, DEST=apps:172.20.2.44, PROTO=udp, DPORT=500,4500, ORIGDEST=70.90.191.123 }
    ?else
    ACCEPT      { SOURCE=loc,net,wlan, DEST=apps, PROTO=udp, DPORT=500,4500 }
    ACCEPT      { SOURCE=loc,net,wlan, DEST=apps, PROTO=esp }
    ?endif
    ACCEPT      { SOURCE=$FW,     DEST=net,  PROTO=udp, SPORT=4500 }
    ######################################################################################################
    # VNC
    ACCEPT      { SOURCE=loc,     DEST=$FW,   PROTO=tcp,        DPORT=5900 }
    ######################################################################################################
    # FIN & RST
    RST(ACCEPT) { SOURCE=all, DEST=all }
    FIN(ACCEPT) { SOURCE=all, DEST=all }
    ######################################################################################################
    # Multicast
    ?if __IPV4
    Multicast(ACCEPT) { SOURCE=all, DEST=$FW }
    ?endif
    ######################################################################################################
    ?if __IPV4
    ACCEPT      { SOURCE=fw, DEST=all, PROTO=icmp, DPORT=host-unreachable }
    ?endif

## mangle

Note that TPROXY can be enabled/disabled via a shell variable setting in /etc/shorewall/params:

    #ACTION       SOURCE      DEST        PROTO   DPORT   SPORT   USER    TEST    LENGTH  TOS CONNBYTES   HELPER  PROBABILITY DSCP

    ?if $VERSION >= 50109
    TCPMSS(pmtu,none) { PROTO=tcp }
    ?endif

    ?if __IPV4
        #
        # I've had a checksum issue with certain IPv4 UDP packets
        #
        CHECKSUM:T { DEST=FAST_IF, PROTO=udp }
        CHECKSUM:T { DEST=DMZ_IF,  PROTO=udp }
    ?endif

    ?if $PROXY
        #
        # Use TPROXY for web access from the local LAN
        #
        DIVERT:R { PROTO=tcp, SPORT=80 }
        DIVERT:R { PROTO=tcp, DPORT=80 }
        TPROXY(3129,$LOC_ADDR) { SOURCE=LOC_IF,  PROTO=tcp, DPORT=80 }
        TPROXY(3129,$LOC_ADDR) { SOURCE=WLAN_IF, PROTO=tcp, DPORT=80 }
    #    DIVERT:R { PROTO=tcp, SPORT=443 }
    #    DIVERT:R { PROTO=tcp, DPORT=443 }
    #    TPROXY(3129,$LOC_ADDR) { SOURCE=LOC_IF, PROTO=tcp, DPORT=443 }
    ?endif

## snat

NAT entries are quite dependent on the address family:

    #ACTION         SOURCE            DEST            PROTO   PORT   IPSEC  MARK   USER    SWITCH  ORIGDEST   PROBABILITY

    ?if __IPV4
        MASQUERADE          { SOURCE=172.20.0.0/22,               DEST=FAST_IF }
        MASQUERADE          { SOURCE=70.90.191.120/29,        DEST=FAST_IF }
        SNAT(70.90.191.121)     { SOURCE=!70.90.191.120/29,       DEST=PROD_IF,  PROBABILITY=0.50, COMMENT="Masquerade Local Network" }
        SNAT(70.90.191.123)     { SOURCE=!70.90.191.120/29,       DEST=PROD_IF,                    COMMENT="Masquerade Local Network" }
        SNAT(172.20.1.253)      { SOURCE=!172.20.1.0/24,          DEST=LOC_IF:172.20.1.100 }
    ?else
        SNAT(&PROD_IF)      { SOURCE=2601:601:a000:16f0::/60,               DEST=PROD_IF }
        SNAT(&FAST_IF)      { SOURCE=2001:470:b:227::/64,2001:470:a:227::2, DEST=FAST_IF }
    ?endif

## tunnels

Both address families define IPsec tunnels:

    #TYPE         ZONE        GATEWAY         GATEWAY_ZONE
    ipsecnat {ZONE=net,  GATEWAY=$ALL, GATEWAY_ZONE=vpn }
    ipsecnat {ZONE=loc,  GATEWAY=$ALL, GATEWAY_ZONE=vpn }
    ipsecnat {ZONE=wlan, GATEWAY=$ALL, GATEWAY_ZONE=vpn }

## proxyarp

    #ADDRESS  INTERFACE   EXTERNAL    HAVEROUTE   PERSISTENT

    70.90.191.122 { INTERFACE=br0, EXTERNAL=eth1, HAVEROUTE=yes, PERSISTENT=no }

## isuable

This is just the standard Shorewall isusable extension script:

    local status
    status=0

    [ -f ${VARDIR}/${1}.status ] && status=$(cat ${VARDIR}/${1}.status)

    return $status

## started

/etc/shorewall/started only does something in the IPv4 configuration, although it gets compiled into both scripts:

    if [ $g_family = 4 ]; then
        qt $IP -4 route replace 70.90.191.122 dev br0
        qt $IP -4 route replace 70.90.191.124 dev br0
        qt $IP -4 route replace 70.90.191.125 dev br0
    fi

## stoppedrules

/etc/shorewall/stoppedrules allow SSH connections into the firewall system when Shorewall\[6\] is in the stopped state.

    #ACTION       SOURCE          DEST        PROTO   DPORT   SPORT
    ACCEPT      -           $FW     tcp 22
