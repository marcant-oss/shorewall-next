<div class="warning">

I have not used PPTP in years and as a consequence, this document is no longer maintained (any volunteers?).

As far as I know, the information regarding Shorewall configuration is still valid but the configurations shown for for the other components may no longer work. For the most part, they show configuration files that I used when I worked for Compaq and used PPTP as my work VPN.

</div>

# Preliminary Reading

I recommend reading the [VPN Basics](VPNBasics.md) article if you plan to implement any type of VPN.

# PPTP Server Running on your Firewall

## Configuring Samba

You will need a WINS server (Samba configured to run as a WINS server is fine). Global section from /etc/samba/smb.conf on my WINS server (192.168.1.3) is:

    [global]
         workgroup = TDM-NSTOP
         netbios name = WOOKIE
         server string = GNU/Linux Box
         encrypt passwords = Yes
         log file = /var/log/samba/%m.log
         max log size = 0
         socket options = TCP_NODELAY SO_RCVBUF=8192 SO_SNDBUF=8192
         os level = 65
         domain master = True
         preferred master = True
         dns proxy = No
         wins support = Yes
         printing = lprng

    [homes]
         comment = Home Directories
         valid users = %S
         read only = No
         create mask = 0664
         directory mask = 0775

    [printers]
         comment = All Printers
         path = /var/spool/samba
         printable = Yes

## Configuring pppd

Here is a copy of my /etc/ppp/options.poptop file:

    ipparam PoPToP
    lock
    mtu 1490
    mru 1490
    ms-wins 192.168.1.3
    ms-dns 206.124.146.177
    multilink
    proxyarp
    auth
    +chap
    +chapms
    +chapms-v2
    ipcp-accept-local
    ipcp-accept-remote
    lcp-echo-failure 30
    lcp-echo-interval 5
    deflate 0
    mppe-128
    mppe-stateless
    require-mppe
    require-mppe-stateless

<div class="note">

- System 192.168.1.3 acts as a WINS server so I have included that IP as the “ms-wins” value.

- I have pointed the remote clients at my DNS server -- it has external address 206.124.146.177.

- I am requiring 128-bit stateless compression.

</div>

Here's my /etc/ppp/chap-secrets:

    Secrets for authentication using CHAP
    # client        server    secret    IP addresses
    CPQTDM\\TEastep *         <shhhhhh> 192.168.1.7
    TEastep         *         <shhhhhh> 192.168.1.7

I am the only user who connects to the server but I may connect either with or without a domain being specified. The system I connect from is my laptop so I give it the same IP address when tunneled in at it has when I use its wireless LAN card around the house.

You will also want the following in /etc/modules.conf:

    alias ppp-compress-18 ppp_mppe
    alias ppp-compress-21 bsd_comp
    alias ppp-compress-24 ppp_deflate
    alias ppp-compress-26 ppp_deflate

## Configuring pptpd

PoPTop (pptpd) is available from <http://www.poptop.org/>.

Here is a copy of my /etc/pptpd.conf file:

    option /etc/ppp/options.poptop
    speed 115200
    localip 192.168.1.254
    remoteip 192.168.1.33-38

<div class="note">

- I specify the /etc/ppp/options.poptop file as my ppp options file (I have several).

- The local IP is the same as my internal interface's (192.168.1.254).

- I have assigned a remote IP range that overlaps my local network. This, together with “proxyarp” in my /etc/ppp/options.poptop file make the remote hosts look like they are part of the local subnetwork.

</div>

I use this file to start/stop pptpd -- I have this in /etc/init.d/pptpd:

    #!/bin/sh
    #
    # /etc/rc.d/init.d/pptpd
    #
    # chkconfig: 5 12 85
    # description: control pptp server
    #

    case "$1" in
    start)
        echo 1 > /proc/sys/net/ipv4/ip_forward
        modprobe ppp_async
        modprobe ppp_generic
        modprobe ppp_mppe
        modprobe slhc
        if /usr/local/sbin/pptpd; then
            touch /var/lock/subsys/pptpd
        fi
        ;;
    stop)
        killall pptpd
        rm -f /var/lock/subsys/pptpd
        ;;
    restart)
        killall pptpd
        if /usr/local/sbin/pptpd; then
            touch /var/lock/subsys/pptpd
        fi
        ;;
    status)
        ifconfig
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        ;;
    esac

## Configuring Shorewall

### Basic Setup

Here' a basic setup that treats your remote users as if they were part of your **loc** zone. Note that if your primary Internet connection uses ppp0, then be sure that **loc** follows **net** in /etc/shorewall/zones.

`/etc/shorewall/tunnels`:

    #TYPE           ZONE             GATEWAY           GATEWAY ZONE
    pptpserver      net              0.0.0.0/0

`/etc/shorewall/interfaces`:

    #ZONE          INTERFACE         BROADCAST        OPTIONS
    loc            ppp+

### Remote Users in a Separate Zone

If you want to place your remote users in their own zone so that you can control connections between these users and the local network, follow this example. Note that if your primary Internet connection uses ppp0 then be sure that **vpn** follows **net** in /etc/shorewall/zones as shown below.

`/etc/shorewall/tunnels`:

    #TYPE           ZONE             GATEWAY           GATEWAY ZONE
    pptpserver      net              0.0.0.0/0

`/etc/shorewall/zones`:

    #ZONE           TYPE
    net             ipv4
    loc             ipv4
    vpn             ipv4

`/etc/shorewall/interfaces`:

    #ZONE          INTERFACE         BROADCAST        OPTIONS
    net            eth0              206.124.146.255
    loc            eth2              192.168.10.255
    vpn            ppp+

Your policies and rules may now be configured for traffic to/from the **vpn** zone.

### Multiple Remote Networks

Often there will be situations where you want multiple connections from remote networks with these networks having different firewalling requirements.

Here's how you configure this in Shorewall. Note that if your primary Internet connection uses ppp0 then be sure that the **vpn{1-3}** zones follows **net** in /etc/shorewall/zones as shown below.

`/etc/shorewall/tunnels`:

    #TYPE           ZONE             GATEWAY           GATEWAY ZONE
    pptpserver      net              0.0.0.0/0

`/etc/shorewall/zones`:

    #ZONE           TYPE
    fw              firewall
    net             ipv4
    loc             ipv4
    vpn1            ipv4
    vpn2            ipv4
    vpn3            ipv4

`/etc/shorewall/interfaces`:

    #ZONE          INTERFACE         BROADCAST        OPTIONS
    net            eth0              206.124.146.255
    loc            eth2              192.168.10.255
    -              ppp+

`/etc/shorewall/hosts`:

    #ZONE          HOST(S)                   OPTIONS
    vpn1           ppp+:192.168.1.0/24
    vpn2           ppp+:192.168.2.0/24
    vpn3           ppp+:192.168.3.0/24

Your policies and rules can now be configured using separate zones (vpn1, vpn2, and vpn3) for the three remote network.

# PPTP Server Running Behind your Firewall

If you have a single external IP address, add the following to your /etc/shorewall/rules file:

`/etc/shorewall/rules`:

    #ACTION      SOURCE         DEST                  PROTO       DEST PORT(S)
    DNAT         net            loc:<server address>  tcp         1723
    DNAT         net            loc:<server address>  47

If you have multiple external IP address and you want to forward a single \<*external address*\>, add the following to your /etc/shorewall/rules file:

`/etc/shorewall/rules`:

    #ACTION      SOURCE         DEST                  PROTO       DEST PORT(S)     SOURCE          ORIGINAL
    #                                                                              PORT(S)         DEST
    DNAT         net            loc:<server address>  tcp         1723             -               <external address>
    DNAT         net            loc:<server address>  47          -                -               <external address>

You will also want to add this entry to your `/etc/shorewall/masq` file:

    #INTERFACE             SUBNET             ADDRESS               PROTO
    <external interface>   <server address>   <external address>    47

<div class="important">

Be sure that the above entry comes **before** any other entry that might match the server's address.

</div>

# PPTP Clients Running Behind your Firewall

Please see [this article](VPN.md).

# PPTP Client Running on your Firewall

The key elements of this setup are as follows:

1.  Define a zone for the remote network accessed via PPTP.

2.  Associate that zone with a ppp interface.

3.  Define rules for PPTP traffic to/from the firewall.

4.  Define rules for traffic two and from the remote zone.

Here are examples from one of my old setups:

`/etc/shorewall/zones`:

    #ZONE          TYPE
    cpq            ipv4

`/etc/shorewall/interfaces`:

    #ZONE          INTERFACE        BROADCAST          OPTIONS
    -              ppp+

/etc/shorewall/hosts:

    #ZONE          HOST(S)                             OPTIONS
    cpq            ppp+:!192.168.1.0/24

`/etc/shorewall/tunnels`:

    #TYPE          ZONE             GATEWAY            GATEWAY ZONE
    pptpclient     net              0.0.0.0/0

I use the combination of interface and hosts file to define the “cpq” zone because I also run a PPTP server on my firewall (see above). Using this technique allows me to distinguish clients of my own PPTP server from arbitrary hosts at Compaq; I assign addresses in 192.168.1.0/24 to my PPTP clients and Compaq doesn't use that RFC1918 Class C subnet.

I use this script in /etc/init.d to control the client. The reason that I disable ECN when connecting is that the Compaq tunnel servers don't do ECN yet and reject the initial TCP connection request if I enable ECN :-(

    #!/bin/sh
    #
    # /etc/rc.d/init.d/pptp
    #
    # chkconfig: 5 60 85
    # description: PPTP Link Control
    #
    NAME="Tandem"
    ADDRESS=tunnel-tandem.compaq.com
    USER='Tandem\tommy'
    ECN=0
    DEBUG=

    start_pptp() {
        echo $ECN > /proc/sys/net/ipv4/tcp_ecn
        if /usr/sbin/pptp $ADDRESS user $USER noauth $DEBUG; then
            touch /var/lock/subsys/pptp
            echo "PPTP Connection to $NAME Started"
        fi
    }

    stop_pptp() {
        if killall /usr/sbin/pptp 2> /dev/null; then
            echo "Stopped pptp"
        else
            rm -f /var/run/pptp/*
        fi

        # if killall pppd; then
        # echo "Stopped pppd"
        # fi

        rm -f /var/lock/subsys/pptp

        echo 1 > /proc/sys/net/ipv4/tcp_ecn
    }


    case "$1" in
    start)
        echo "Starting PPTP Connection to ${NAME}..."
        start_pptp
        ;;
    stop)
        echo "Stopping $NAME PPTP Connection..."
        stop_pptp
        ;;
    restart)
        echo "Restarting $NAME PPTP Connection..."
        stop_pptp
        start_pptp
        ;;
    status)
        ifconfig
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        ;;
    esac

Here's my /etc/ppp/options file:

    #
    # Identify this connection
    #
    ipparam Compaq
    #
    # Lock the port
    #
    lock
    #
    # We don't need the tunnel server to authenticate itself
    #
    noauth

    +chap
    +chapms
    +chapms-v2

    multilink
    mrru 1614
    #
    # Turn off transmission protocols we know won't be used
    #
    nobsdcomp
    nodeflate

    #
    # We want MPPE
    #
    mppe-128
    mppe-stateless

    #
    # We want a sane mtu/mru
    #
    mtu 1000
    mru 1000

    #
    # Time this thing out of it goes poof
    #
    lcp-echo-failure 10
    lcp-echo-interval 10

My /etc/ppp/ip-up.local file sets up the routes that I need to route Compaq traffic through the PPTP tunnel:

    #/bin/sh

    case $6 in
    Compaq)
        route add -net 16.0.0.0 netmask 255.0.0.0 gw $5 $1
        route add -net 130.252.0.0 netmask 255.255.0.0 gw $5 $1
        route add -net 131.124.0.0 netmask 255.255.0.0 gw $5 $1
        ...
        ;;
    esac

Finally, I run the following script every five minutes under crond to restart the tunnel if it fails:

    #!/bin/sh
    restart_pptp() {
        /sbin/service pptp stop
        sleep 10
        if /sbin/service pptp start; then
            /usr/bin/logger "PPTP Restarted"
        fi
    }

    if [ -n "`ps ax | grep /usr/sbin/pptp | grep -v grep`" ]; then
        exit 0
    fi

    echo "Attempting to restart PPTP"

    restart_pptp > /dev/null 2>&1 &

[Here's a script and corresponding ip-up.local](ftp://ftp.shorewall.net/pub/shorewall/misc/Vonau) from Jerry Vonau <jvonau@home.com> that controls two PPTP connections.

# PPTP Client running on your Firewall with PPTP Server in an ADSL Modem

Some ADSL systems in Europe (most notably in Austria and the Netherlands) feature a PPTP server builtinto an ADSL “Modem”. In this setup, an Ethernet interface is dedicated to supporting the PPTP tunnel between the firewall and the “Modem” while the actual Internet access is through PPTP (interface ppp0). If you have this type of setup, you need to modify the sample configuration that you downloaded as described in this section. **These changes are in addition to those described in the [QuickStart Guides](../reference/shorewall_quickstart_guide.md).**

Lets assume the following:

- ADSL Modem connected through eth0

- Modem IP address = 192.168.1.1

- eth0 IP address = 192.168.1.2

The changes you need to make are as follows:

1.  Add this entry to /etc/shorewall/zones:

        #ZONE          TYPE
        modem          ipv4

    That entry defines a new zone called “modem” which will contain only your ADSL modem.

2.  Add the following entry to /etc/shorewall/interfaces:

        #ZONE          INTERFACE        BROADCAST          OPTIONS
        modem          eth0             192.168.1.255      dhcp

    You will of course modify the “net” entry in /etc/shorewall/interfaces to specify “ppp0” as the interface as described in the QuickStart Guide corresponding to your setup.

3.  Add the following to /etc/shorewall/tunnels:

        #TYPE          ZONE             GATEWAY            GATEWAY ZONE
        pptpclient     modem            192.168.1.1

    That entry allows a PPTP tunnel to be established between your Shorewall system and the PPTP server in the modem.
