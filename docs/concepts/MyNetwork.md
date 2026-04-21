<div class="caution">

The ruleset shown in this article uses Shorewall features that are not available in Shorewall versions prior to 4.6.11

</div>

# Introduction

The configuration described in this article represents the network at shorewall.org during the summer of 2015. It uses the following Shorewall features:

- [Two Internet Interfaces](../features/MultiISP.md)

- A DMZ with three "systems" using [Proxy ARP](../features/ProxyARP.md) and running in [Linux Containers (LXC)](../legacy/OpenVZ.md)

- IPv6 Access through two 6to4 Tunnels (see [IPv6 Support](../features/IPv6Support.md#6to4))

- [Ipsets](../features/ipsets.md)

- [Transparent proxy using Squid](../features/Shorewall_Squid_Usage.md)

Linux runs the firewall and the servers (although they run in LXC containers on the firewall system). Linux is not used natively on any of our other systems.. I rather run Windows natively (Windows 7 Professional) and run Linux in VMs under [VirtualBox](http://www.sun.com/software/products/virtualbox/). This approach has a number of advantages:

1.  Efficient disk utilization.

    The virtual disks used by Linux are just files in the NTFS file system. There is no need to pre-allocate one or more partitions for use by Linux. Some large applications, like Google Earth, are installed only on Windows.

2.  Avoids proprietary hardware issues.

    The Linux VMs emulate standard hardware that is well-supported by Linux.

3.  Avoids DRM hassles

    All DRM-protected media can be handled under Windows.

VirtualBox is fast (when your processor supports virtualization extensions) and very easy to use. I highly recommend it!

# Network Topology

Our network is diagrammed in the following graphic.

We have two accounts with Comcast:

1.  ComcastC

    This is a high-speed (40mb/8mb) link with a single dynamic IPv4 address. We are not allowed to run servers accessible through this account.

2.  ComcastB

    Comcast Business Class Service with a /29 (70.90.191.120/29).

The wired local network is restricted to my home office. The wireless network is managed by a wireless router which we use only as an access point -- its WAN interface is unused and it is configured to not do NAT. The wireless network uses WPA2 personal security.

# Shorewall Configuration

This section contains excerpts from the Shorewall configuration.

## /etc/shorewall/mirrors

    MIRRORS=62.216.169.37,\
    62.216.184.105,\
    63.229.2.114,\
    ...

Defines the IP addresses of the Shorewall mirror sites.

## /etc/shorewall/params

    INCLUDE mirrors

    LOG="NFLOG(0,0,1)"

    INT_IF=eth0
    TUN_IF=tun+
    COMB_IF=eth2
    COMC_IF=eth1

    MYNET=70.90.191.120/29 #External IP addresses handled by this router
    DMZ_NET=70.90.191.124/31
    FW_NET=70.90.191.120/30
    INT_NET=172.20.1.0/24
    DYN_NET=$(find_first_interface_address_if_any $COMC_IF)
    SMC_ADDR=10.1.10.11

    [ -n "${DYN_NET:=67.170.122.219}" ]

    DYN_NET=${DYN_NET}/32

    DMZ=fw:$DMZ_NET

    LISTS=:70.90.191.124
    SERVER=:70.90.191.125
    MAIL=172.20.1.200

    PROXY=Yes
    STATISTICAL=Yes
    SQUID2=Yes

    [ -n "${EXPERIMENTAL:=0}" ]

As shown, this file defines variables to hold the various lists of IP addresses that I need to maintain. To simplify network reconfiguration, I also use variables to define the log level and the network interfaces.

## /etc/shorewall/shorewall.conf

    ###############################################################################
    #                      S T A R T U P   E N A B L E D
    ###############################################################################

    STARTUP_ENABLED=Yes

    ###############################################################################
    #                            V E R B O S I T Y
    ###############################################################################

    VERBOSITY=1

    ###############################################################################
    #                              L O G G I N G
    ###############################################################################

    BLACKLIST_LOG_LEVEL=none

    INVALID_LOG_LEVEL=

    LOG_BACKEND=ULOG

    LOG_MARTIANS=Yes

    LOG_VERBOSITY=1

    LOGALLNEW=

    LOGFILE=/var/log/ulogd/ulogd.syslogemu.log

    LOGFORMAT=": %s %s"

    LOGTAGONLY=Yes

    LOGLIMIT="s:5/min"

    MACLIST_LOG_LEVEL="$LOG"

    RELATED_LOG_LEVEL="$LOG"

    RPFILTER_LOG_LEVEL=info

    SFILTER_LOG_LEVEL="$LOG"

    SMURF_LOG_LEVEL="$LOG"

    STARTUP_LOG=/var/log/shorewall-init.log

    TCP_FLAGS_LOG_LEVEL="$LOG"

    UNTRACKED_LOG_LEVEL=

    ###############################################################################
    #       L O C A T I O N   O F   F I L E S   A N D   D I R E C T O R I E S
    ###############################################################################

    ARPTABLES=

    CONFIG_PATH="/etc/shorewall:/etc/shorewall-common:/usr/share/shorewall:/usr/share/shorewall/Shorewall"

    GEOIPDIR=/usr/share/xt_geoip/LE

    IPTABLES=/sbin/iptables

    IP=/sbin/ip

    IPSET=

    LOCKFILE=/var/lib/shorewall/lock

    MODULESDIR=

    NFACCT=

    PATH="/usr/local/sbin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin"

    PERL=/usr/bin/perl

    RESTOREFILE=

    SHOREWALL_SHELL=/bin/bash

    SUBSYSLOCK=

    TC=

    ###############################################################################
    #               D E F A U L T   A C T I O N S / M A C R O S
    ###############################################################################

    ACCEPT_DEFAULT=none
    DROP_DEFAULT=Drop
    NFQUEUE_DEFAULT=none
    QUEUE_DEFAULT=none
    REJECT_DEFAULT=Reject

    ###############################################################################
    #                        R S H / R C P  C O M M A N D S
    ###############################################################################

    RCP_COMMAND='scp ${files} ${root}@${system}:${destination}'
    RSH_COMMAND='ssh ${root}@${system} ${command}'

    ###############################################################################
    #                       F I R E W A L L   O P T I O N S
    ###############################################################################

    ACCOUNTING=Yes

    ACCOUNTING_TABLE=mangle

    ADD_IP_ALIASES=No

    ADD_SNAT_ALIASES=No

    ADMINISABSENTMINDED=Yes

    BASIC_FILTERS=No

    IGNOREUNKNOWNVARIABLES=No

    AUTOCOMMENT=Yes

    AUTOHELPERS=Yes

    AUTOMAKE=Yes

    BLACKLIST="NEW,INVALID,UNTRACKED"

    CHAIN_SCRIPTS=No

    CLAMPMSS=Yes

    CLEAR_TC=Yes

    COMPLETE=No

    DEFER_DNS_RESOLUTION=No

    DELETE_THEN_ADD=No

    DETECT_DNAT_IPADDRS=No

    DISABLE_IPV6=No

    DONT_LOAD="nf_nat_sip,nf_conntrack_sip,nf_conntrack_h323,nf_nat_h323"

    DYNAMIC_BLACKLIST=Yes

    EXPAND_POLICIES=Yes

    EXPORTMODULES=Yes

    FASTACCEPT=Yes

    FORWARD_CLEAR_MARK=Yes

    HELPERS="ftp,irc"

    IMPLICIT_CONTINUE=No

    INLINE_MATCHES=Yes

    IPSET_WARNINGS=No

    IP_FORWARDING=Yes

    KEEP_RT_TABLES=Yes

    LEGACY_FASTSTART=Yes

    LOAD_HELPERS_ONLY=Yes

    MACLIST_TABLE=mangle

    MACLIST_TTL=60

    MANGLE_ENABLED=Yes

    MAPOLDACTIONS=No

    MARK_IN_FORWARD_CHAIN=No

    MODULE_SUFFIX="ko ko.xz"

    MULTICAST=No

    MUTEX_TIMEOUT=60

    NULL_ROUTE_RFC1918=unreachable

    OPTIMIZE=All

    OPTIMIZE_ACCOUNTING=No

    REJECT_ACTION=RejectAct

    REQUIRE_INTERFACE=No

    RESTORE_DEFAULT_ROUTE=No

    RESTORE_ROUTEMARKS=Yes

    RETAIN_ALIASES=No

    ROUTE_FILTER=No

    SAVE_ARPTABLES=Yes

    SAVE_IPSETS=ipv4

    TC_ENABLED=No

    TC_EXPERT=No

    TC_PRIOMAP="2 3 3 3 2 3 1 1 2 2 2 2 2 2 2 2"

    TRACK_PROVIDERS=Yes

    TRACK_RULES=No

    USE_DEFAULT_RT=Yes

    USE_PHYSICAL_NAMES=Yes

    USE_RT_NAMES=Yes

    WARNOLDCAPVERSION=Yes

    WORKAROUNDS=No

    ZONE2ZONE=-

    ###############################################################################
    #                       P A C K E T   D I S P O S I T I O N
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
    #                       P A C K E T  M A R K  L A Y O U T
    ################################################################################

    TC_BITS=8

    PROVIDER_BITS=2

    PROVIDER_OFFSET=16

    MASK_BITS=8

    ZONE_BITS=0

    ################################################################################
    #                            L E G A C Y  O P T I O N
    #                      D O  N O T  D E L E T E  O R  A L T E R
    ################################################################################

    IPSECFILE=zones

I don't believe that there is anything remarkable there

## /etc/shorewall/actions

    Mirrors                         # Accept traffic from Shorewall Mirrors
    SSHLIMIT
    SSH_BL
    tarpit       inline             # Wrapper for TARPIT

## /etc/shorewall/action.Mirrors

    #TARGET SOURCE          DEST            PROTO   DPORT   SPORT      ORIGDEST     RATE
    ?COMMENT Accept traffic from Mirrors
    ?FORMAT  2
    DEFAULTS -
    $1      $MIRRORS

I make this into an action so the rather long list of rules go into their own chain. See the [rules](#rules) file -- this action is used for rsync traffic.

## /etc/shorewall/action.tarpit

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT           ORIGDEST        RATE            USER    MARK    CONNLIMIT       TIME         HEADERS         SWITCH        HELPER
    $LOG            { rate=s:1/min }
    TARPIT

## /etc/shorewall/zones

    #ZONE           TYPE
    fw              firewall
    loc             ip                                              #Local Zone
    net             ipv4                                            #Internet
    dmz             ipv4                                            #LXC Containers
    smc:net         ip                                              #10.0.1.0/24

## /etc/shorewall/interfaces

    #ZONE  INTERFACE        OPTIONS
    loc    INT_IF           dhcp,physical=$INT_IF,ignore=1,wait=5,routefilter,nets=172.20.1.0/24,routeback,tcpflags=0
    net    COMB_IF          optional,sourceroute=0,routefilter=0,arp_ignore=1,proxyarp=0,physical=$COMB_IF,upnp,nosmurfs,tcpflags
    net    COMC_IF          optional,sourceroute=0,routefilter=0,arp_ignore=1,proxyarp=0,physical=$COMC_IF,upnp,nosmurfs,tcpflags,dhcp
    dmz    br0              routeback,proxyarp=1,required,wait=30
    -      ifb0             ignore

## /etc/shorewall/hosts

    #ZONE   HOST(S)                                 OPTIONS
    smc     COMB_IF:10.1.10.0/24                    mss=1400
    smc     COMC_IF:10.0.0.0/24

## /etc/shorewall/policy

    #SOURCE         DEST            POLICY                          LOGLEVEL        LIMIT
    $FW             dmz             REJECT                          $LOG
    $FW             net             REJECT                          $LOG
    ?else
    $FW             dmz             REJECT                          $LOG
    $FW             net             REJECT                          $LOG
    $FW             all             ACCEPT
    smc             loc             ACCEPT
    smc             fw              CONTINUE
    smc             net             NONE
    loc             smc             ACCEPT
    loc             net             ACCEPT
    loc             fw              REJECT                          $LOG
    net             net             NONE
    net             smc             NONE
    net             all             DROP:Drop                       $LOG            8/sec:30
    dmz             fw              REJECT:Reject                   $LOG
    all             all             REJECT:Reject                   $LOG

## /etc/shorewall/accounting

    #ACTION                         CHAIN           SOURCE                  DESTINATION     PROTO   DPORT           SPORT   USER     MARK     IPSEC
    ?COMMENT
    ?SECTION PREROUTING
    ?SECTION INPUT
    ACCOUNT(fw-net,$FW_NET)         -               COMB_IF
    COUNT                           -               COMB_IF                 -               tcp     -               80
    COUNT                           -               COMC_IF                 -               tcp     -               80
    COUNT                           -               br0:70.90.191.124       -               tcp     80              =

    ?SECTION OUTPUT
    ACCOUNT(fw-net,$FW_NET)         -               -                       COMB_IF
    COUNT                           -               -                       COMB_IF         tcp     80
    COUNT                           -               -                       COMC_IF         tcp     80

    ?SECTION FORWARD
    ACCOUNT(dmz-net,$DMZ_NET)       -               br0                     COMB_IF
    ACCOUNT(dmz-net,$DMZ_NET)       -               COMB_IF                 br0
    ACCOUNT(loc-net,$INT_NET)       -               COMB_IF                 INT_IF
    ACCOUNT(loc-net,$INT_NET)       -               INT_IF                  COMB_IF

## /etc/shorewall/blrules

    #ACTION         SOURCE                  DEST                    PROTO   DPORT                   SPORT           ORIGDEST        RATE    USER      MARK     CONNLIMIT    TIME      HEADERS SWITCH
    WHITELIST       net:70.90.191.126       all
    BLACKLIST       net:+blacklist          all
    BLACKLIST       net                     all                     udp     1023:1033,1434,5948,23773
    DROP            net                     all                     tcp     57,1433,1434,2401,2745,3127,3306,3410,4899,5554,5948,6101,8081,9898,23773
    DROP            net:63.149.127.103      all
    DROP            net:175.143.53.113      all
    DROP            net:121.134.248.190     all
    REJECT          net:188.176.145.22      dmz                     tcp     25
    DROP            net                     fw                      udp     111
    Invalid(DROP)   net                     all

## /etc/shorewall/findgw

    if [ -f /var/lib/dhcpcd/dhcpcd-eth1.info ]; then
       . /var/lib/dhcpcd/dhcpcd-eth1.info
       echo $GATEWAY
    fi

The Comcast line has a dynamic IP address assigned with the help of dhclient.

## /etc/shorewall/isusable

    local status
    status=0

    [ -f /etc/shorewall/${1}.status ] && status=$(cat /etc/shorewall/${1}.status)

    return $status

For use with [lsm](../features/MultiISP.md#lsm).

## /etc/shorewall/lib.private

    start_lsm() {
       #
       # Kill any existing lsm process(es)
       #
       killall lsm 2> /dev/null
       #
       # Create the Shorewall-specific part of the LSM configuration. This file is
       # included by /etc/lsm/lsm.conf
       #
       # ComcastB has a static gateway while ComcastC's is dynamic
       #
       cat <<EOF > /etc/lsm/shorewall.conf
    connection {
        name=ComcastB
        checkip=76.28.230.1
        device=$COMB_IF
        ttl=2
    }

    connection {
        name=ComcastC
        checkip=76.28.230.188
        device=$COMC_IF
        ttl=3
    }
    EOF

       cat <<EOF > /var/lib/shorewall/eth0.info
    ETH0_GATEWAY=$SW_ETH0_GATEWAY
    ETH0_ADDRESS=$SW_ETH0_ADDRESS
    EOF
       #
       # Clear status on start
       #
       if [ $COMMAND = start ]; then
           for interface in eth0 eth1; do
               echo 0 > ${VARDIR}/$interface.status
           done
       fi
       #
       # Run LSM -- by default, it forks into the background
       #
       /usr/local/sbin/lsm /etc/lsm/lsm.conf >> /var/log/lsm
    }

This function configures and starts [lsm](../features/MultiISP.md#lsm).

## /etc/shorewall/masq

    #INTERFACE                      SOURCE                  ADDRESS                 PROTO

    ?COMMENT Use the SMC's local net address when communicating with that net

    COMB_IF:10.1.10.0/24            0.0.0.0/0               %{SMC_ADDR}

    ?COMMENT Masquerade Local Network

    COMB_IF                         !70.90.191.120/29       70.90.191.121 ; -m statistic --mode random --probability 0.50
    COMB_IF                         !70.90.191.120/29       70.90.191.123
    COMC_IF                         0.0.0.0/0
    #INT_IF:172.20.1.15             172.20.1.0/24           172.20.1.254

    br0                             70.90.191.120/29        70.90.191.121           tcp     80

I split connections out of COMB_IF between the two IP addresses configured on the interface.

## /etc/shorewall/conntrack

    ?FORMAT 2
    #ACTION         SOURCE            DEST             PROTO   DPORT           SPORT
    #
    DROP            net               -                udp     3551
    NOTRACK         net               -                tcp     23
    NOTRACK         loc               172.20.1.255     udp
    NOTRACK         loc               255.255.255.255  udp
    NOTRACK         $FW               255.255.255.255  udp
    NOTRACK         $FW               172.20.1.255     udp
    NOTRACK         $FW               70.90.191.127    udp
    NOTRACK         net:192.88.99.1   -
    NOTRACK         $FW               192.88.99.1

    ?if $AUTOHELPERS
    ?if __CT_TARGET &&  __AMANDA_HELPER
    CT:helper:amanda        all             -               udp     10080
    ?endif
    ?if __CT_TARGET &&  __FTP_HELPER
    CT:helper:ftp           all             -               tcp     21
    ?endif
    ?if __CT_TARGET &&  __H323_HELPER
    CT:helper:RAS           all             -               udp     1719
    CT:helper:Q.931         all             -               tcp     1720
    ?endif
    ?if __CT_TARGET &&  __IRC_HELPER
    CT:helper:irc           all             -               tcp     6667
    ?endif
    ?if __CT_TARGET &&  __NETBIOS_NS_HELPER
    CT:helper:netbios-ns    all             -               udp     137
    ?endif
    ?if __CT_TARGET &&  __PPTP_HELPER
    CT:helper:pptp          all             -               tcp     1729
    ?endif
    ?if __CT_TARGET &&  __SANE_HELPER
    CT:helper:sane          all             -               tcp     6566
    ?endif
    #?if __CT_TARGET &&  __SIP_HELPER
    #CT:helper:sip          all             -               udp     5060
    #?endif
    ?if __CT_TARGET &&  __SNMP_HELPER
    CT:helper:snmp          all             -               udp     161
    ?endif
    ?if __CT_TARGET &&  __TFTP_HELPER
    CT:helper:tftp          all             -               udp     69
    ?endif
    ?endif

This file omits the 6to4 traffic originating from 6to4 relays as well as broadcast traffic (which Netfilter doesn't handle).

## /etc/shorewall/providers

    #NAME           NUMBER   MARK    DUPLICATE  INTERFACE   GATEWAY         OPTIONS               COPY
    ?IF $STATISTICAL
    ComcastB        1        0x10000 -          COMB_IF     70.90.191.126   loose,load=0.66666667,fallback
    ComcastC        2        0x20000 -          COMC_IF     detect          loose,load=0.33333333
    ?ELSE
    ComcastB        1        0x10000 -          COMB_IF     70.90.191.126   nohostroute,loose,balance=2
    ComcastC        2        0x20000 -          COMC_IF     detect          nohostroute,loose,balance
    ?ENDIF
    ?IF $PROXY && ! $SQUID2
    TProxy          3        -       -          lo          -               tproxy
    ?ENDIF
    root@gateway:/etc/shorewall#

See the [Multi-ISP article](???) for an explaination of the multi-ISP aspects of this configuration.

## /etc/shorewall/proxyarp

    <empty>

As mentioned [above](#interfaces), I set the proxyarp on the associated external interface instead of defining proxy ARP in this file.

## /etc/shorewall/restored

    if [ -z "$(ps ax | grep 'lsm ' | grep -v 'grep ' )" ]; then
        start_lsm
    fi

    chmod 744 ${VARDIR}/state

If lsm isn't running then start it. Make the state file world-readable.

## /etc/shorewall/rtrules

    #SOURCE             DEST             PROVIDER  PRIORITY
    70.90.191.121,\
    70.90.191.123       -                ComcastB  1000
    &COMC_IF            -                ComcastC  1000
    br0                 -                ComcastB  11000
    172.20.1.191        -                ComcastB  1000

These entries simply ensure that outgoing traffic uses the correct interface.

## /etc/shorewall/stoppedrules

    #TARGET         HOST(S)                 DEST      PROTO     DPORT       SPORT
    ACCEPT          INT_IF:172.20.1.0/24    $FW
    NOTRACK         COMB_IF                 -         41
    NOTRACK         $FW                     COMB_IF   41
    ACCEPT          COMB_IF                 $FW       41
    ACCEPT          COMC_IF                 $FW       udp       67:68

Keep the lights on while Shorewall is stopped.

## /etc/shorewall/rules

    ################################################################################################################################################################################################
    #ACTION         SOURCE                  DEST                    PROTO   DPORT                   SPORT           ORIGDEST        RATE    USER      MARK     CONNLIMIT    TIME      HEADERS SWITCH
    ?if $VERSION < 40500
    ?SHELL echo "   ERROR: Shorewall version is too low" >&2; exit 1
    ?endif

    ?begin perl
    1;
    ?end perl

    ?SECTION ALL

    #ACCEPT         net:smc.shorewall.net   $FW
    #RST(LOG)       all                     all

    ?SECTION ESTABLISHED

    #SSH(REJECT)    net                     loc:1.2.3.4 { time=timestart=18:48 }

    ?SECTION RELATED
    ACCEPT          all                     dmz:70.90.191.125       tcp     61001:62000 { helper=ftp }
    ACCEPT          dmz                     all                     tcp     { helper=ftp }
    ACCEPT          all                     net                     tcp     { helper=ftp }
    ACCEPT          all                     all                     icmp
    RST(ACCEPT)     all                     all                     tcp
    ACCEPT          dmz                     dmz
    ACCEPT          $FW                     all

    ?SECTION INVALID
    DROP            net                     all
    ?SECTION UNTRACKED

    ACCEPT          net:192.88.99.1         $FW                     41
    tarpit          net                     all                     tcp     23

    Broadcast(ACCEPT)\
                    all                     $FW
    ACCEPT          all                     $FW                     udp
    CONTINUE        loc                     $FW
    CONTINUE        $FW                     all

    ?SECTION NEW

    DNSAmp(ACCEPT)  loc                     fw
    REJECT:$LOG     loc                     net                     tcp     25              #Stop direct loc->net SMTP (Comcast uses submission).
    REJECT:$LOG     loc                     net                     udp     1025:1031       #MS Messaging

    ?COMMENT Stop NETBIOS crap

    REJECT          all                     net                     tcp     137,445
    REJECT          all                     net                     udp     137:139

    ?COMMENT Disallow port 333

    REJECT           all                    net                     tcp     3333

    ?COMMENT Stop Teredo

    REJECT          all                     net                     udp     3544

    ?COMMENT Stop my idiotic work laptop from sending to the net with an HP source IP address

    { action=DROP, source=loc:!172.20.0.0/22, dest=net } #

    ?COMMENT

    #dropInvalid   net                      all             tcp
    ################################################################################################################################################################################################
    # Local network to DMZ
    #
    DNAT            loc                     dmz:70.90.191.125       tcp     www             -               70.90.191.123
    ACCEPT          loc                     dmz                     tcp     ssh,smtp,465,548,587,www,ftp,imaps,https,5901:5903
    ACCEPT          loc                     dmz                     udp     3478:3479,33434:33524
    ################################################################################################################################################################################################
    # SMC network to DMZ
    #
    ACCEPT          smc                     dmz                     tcp     ssh,smtp,465,587,www,ftp,imaps,https,5901:5903
    ACCEPT          smc                     dmz                     udp     33434:33524
    ################################################################################################################################################################################################
    # SMC network to LOC
    #
    ################################################################################################################################################################################################
    # Local Network to Firewall
    #

    ?IF $SQUID2
    REDIRECT        loc                     3128                    tcp     80 {origdest="!172.20.1.0/24,70.90.191.120/29,155.98.64.80,81.19.16.0/21,10.1.10.1"}
    ?ENDIF

    ACCEPT          loc                     fw                      udp     53,111,123,177,192,631,1024:
    SMB(ACCEPT)     loc                     fw
    ACCEPT          loc                     fw                      tcp     22,53,80,111,229,548,2049,3000,32765:61000
    ACCEPT          loc                     fw                      tcp     3128
    mDNS(ACCEPT)    loc                     fw
    ACCEPT          loc                     fw                      tcp     5001

    ACCEPT          loc:172.20.2.149        fw                      tcp     3551    #APCUPSD

    ################################################################################################################################################################################################
    # SMC Network to Firewall
    #
    ACCEPT          smc                     fw                      udp     53,111,123,177,192,631,1024:
    SMB(ACCEPT)     smc                     fw
    ACCEPT          smc                     fw                      tcp     22,53,111,548,2049,3000,3128,32765:32768,49152
    mDNS(ACCEPT)    smc                     fw
    ################################################################################################################################################################################################
    # SMC Network to multiple destinations
    #
    Ping(ACCEPT)    smc                     dmz,fw
    ################################################################################################################################################################################################
    # Local Network to Internet
    #REJECT:info    loc                     net                     tcp     80,443
    ################################################################################################################################################################################################
    # Local Network to multiple destinations
    #
    Ping(ACCEPT)    loc                     dmz,fw
    ################################################################################################################################################################################################
    # Internet to ALL -- drop NewNotSyn packets
    #
    dropNotSyn      net                     fw,loc,smc              tcp
    AutoBL(SSH,60,-,-,-,-,$LOG)\
                    net                     all                     tcp     22
    ################################################################################################################################################################################################
    # Internet to DMZ
    #
    ACCEPT          net                     dmz                     udp     33434:33454
    ACCEPT          net                     dmz                     tcp     25                      -               -               smtp:2/min:4,mail:60/min:100
    DNAT-           net                     70.90.191.125           tcp     https                   -               70.90.191.123
    DNAT-           net                     70.90.191.125           tcp     http                    -               70.90.191.123
    DNAT-           all                     172.20.2.44             tcp     ssh                     -               70.90.191.123
    ACCEPT          net                     dmz:70.90.191.122       tcp     https,imaps
    ACCEPT          net                     dmz:70.90.191.124       tcp     http,https,465,587,imaps
    ACCEPT          net                     dmz:70.90.191.125       tcp     http,ftp
    Mirrors(ACCEPT:none)\   #Continuation test
                    net                     dmz                     tcp     873
    Ping(ACCEPT)    net                     dmz
    DROP            net                     dmz                     tcp     http,https
    ################################################################################################################################################################################################
    #
    # UPnP
    #
    ACCEPT          loc                     fw                      udp     1900
    forwardUPnP     net                     loc
    #
    # Silently Handle common probes
    #
    REJECT          net                     loc                     tcp     www,ftp,https
    DROP            net                     loc                     icmp    8
    ################################################################################################################################################################################################
    # DMZ to DMZ
    #
    ################################################################################################################################################################################################
    DNAT            dmz                     dmz:70.90.191.125:80    tcp     80                      -               70.90.191.121
    # DMZ to Internet
    #
    ACCEPT          dmz                     net                     udp     ntp,domain
    ACCEPT          dmz                     net                     tcp     domain,echo,ftp,ssh,smtp,whois,www,81,nntp,https,993,465,587,2401,2702,2703,5901,8080,9418,11371
    #
    # Some FTP clients seem prone to sending the PORT command split over two packets. This prevents the FTP connection tracking
    # code from processing the command  and setting up the proper expectation
    # The following rule allows active FTP to work in these cases
    # but logs the connection so I can keep an eye on this potential security hole.
    #
    ACCEPT:$LOG     dmz                     net                     tcp     1024:                   20

    Ping(ACCEPT)    dmz                     all
    ################################################################################################################################################################################################
    # DMZ to fw
    #
    DNS(ACCEPT)     dmz                     $FW
    HTTP(ACCEPT)    dmz                     $FW
    Ping(ACCEPT)    dmz                     $FW
    ################################################################################################################################################################################################
    # Internet to Firewall
    #

    REJECT          net                     fw                      tcp     www,ftp,https
    ACCEPT          net                     fw                      udp     3478:3479,33434:33454
    ACCEPT          net                     fw                      tcp     22                      -               -               s:ssh:1/min:3
    ACCEPT          net                     fw                      tcp     51413
    ?COMMENT IPv6 tunnel ping

    ACCEPT          net                     fw:70.90.191.121,70.90.191.122/31\
                                                                    icmp    8
    ACCEPT          net:COMC_IF             fw                      icmp    8

    ?COMMENT

    ################################################################################################################################################################################################
    # Firewall to DMZ
    #
    ACCEPT          fw                      dmz                     tcp     www,ftp,ssh,smtp,https,465,587,993,3128,5901
    REJECT          fw                      dmz                     udp     137:139
    Ping(ACCEPT)    fw                      dmz
    ################################################################################################################################################################################################
    # Firewall to NET
    #
    DNS(ACCEPT)     fw                      net
    NTP(ACCEPT)     fw                      net
    DNAT-           fw                      172.20.1.254:3128       tcp     80                      -               -               -      !:proxy
    ACCEPT+         fw                      net                     tcp     43,80,443,3466          -               -               -      -
    ACCEPT          fw                      net                     tcp     3128                    -               -               -      !:proxy
    FTP(ACCEPT)     fw                      net                     -       -                       -               -               -       proxy
    Git(ACCEPT)     fw                      net                     -       -                       -               -               -       teastep
    ACCEPT          fw                      net                     tcp     22
    NNTP(ACCEPT)    fw                      net
    Ping(ACCEPT)    fw                      net
    ACCEPT          fw                      net                     udp     33434:33524
    #ACCEPT:info    fw                      net                     -       -                       -               -               -       root
    ACCEPT          fw                      net                     tcp     25,143,993              -               -               -       teastep
    ################################################################################################################################################################################################
    #
    ?COMMENT Freenode Probes
    DROP            net:\
                    82.96.96.3,\
                    85.190.0.3              any!loc,smc
    ?COMMENT
    ################################################################################################################################################################################################

## /etc/shorewall/started

    if [ "$COMMAND" = start -o -z "$(ps ax | grep 'lsm ' | grep -v 'grep ' )" ]; then
        start_lsm
    fi

If lsm isn't running then start it.

## /etc/shorewall/stopped

    if [ "$COMMAND" = stop -o "$COMMAND" = clear ]; then
       killall lsm 2> /dev/null
    fi

    chmod 744 ${VARDIR}/state

Kill lsm if the command is stop or clear. Make the state file world-readable.

## /etc/shorewall/tunnels

    #TYPE                   ZONE    GATEWAY         GATEWAY
    #                                               ZONE
    6to4                    net     216.218.226.238
    6to4                    net     192.88.99.1
