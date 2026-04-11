This page covers Shorewall configuration to use with [Squid](http://www.squid-cache.org) running as a Transparent Proxy or as a Manual Proxy.

<div class="caution">

**This article applies to Shorewall 4.0 and later. If you are running a version of Shorewall earlier than Shorewall 4.0.0 then please see the documentation for that release.**

</div>

<div class="caution">

If your firewall is dual-stack, there are risks to using either Transparent Proxy or TPROXY. Both break PMTU discovery for local clients and can cause slow page loading and/or inability to connect to some sites.

</div>

# Squid as a Transparent (Interception) Proxy

<div class="important">

This section gives instructions for transparent proxying of HTTP. HTTPS (normally TCP port 443) **cannot** be proxied transparently (stop and think about it for a minute; if HTTPS could be transparently proxied, then how secure would it be?).

</div>

<div class="caution">

Please observe the following general requirements:

- In all cases, Squid should be configured to run as a transparent proxy as described at <http://wiki.squid-cache.org/SquidFaq/InterceptionProxy>.

  The bottom line of that article is that if you are running **Squid 2.6 or later**, then you simply need to add the word transparent to your http_port specification:

      http_port 3128 transparent

  In **earlier Squid versions**, you need to set several options:

      http_port 3128
      httpd_accel_host virtual
      httpd_accel_port 80
      httpd_accel_with_proxy  on
      httpd_accel_uses_host_header on

- Depending on your distribution, other Squid configuration changes may be required. These changes typically consist of:

  1.  Adding an ACL that represents the clients on your local network.

      Example:

          ACL my_networks src 192.168.1.0/24 192.168.2.0/24

  2.  Allowing HTTP access to that ACL.

      Example:

          http_access allow my_networks

  See your distribution's Squid documentation and <http://www.squid-cache.org/> for details.

  It is a good idea to get Squid working as a [manual proxy](#Manual) first before you try transparent proxying.

- The following instructions mention the file /etc/shorewall/start - if you don't have that file, simply create it.

- When the Squid server is in the local zone, that zone must be defined ONLY by its interface -- no /etc/shorewall/hosts file entries. That is because the packets being routed to the Squid server still have their original destination IP addresses.

- You must have iptables installed on your Squid server.

</div>

<div class="caution">

In the instructions below, only TCP Port 80 is opened from the system running Squid to the Internet. If your users require browsing sites that use a port other than 80 (e.g., http://www.domain.tld:**8080**) then you must open those ports as well.

</div>

## Configurations

Three different configurations are covered:

Squid (transparent) Running on the Firewall

Squid (transparent) Running in the local Network

Squid (transparent) Running in a DMZ

### Squid (transparent) Running on the Firewall

You want to redirect all local www connection requests EXCEPT those to your own http server (206.124.146.177) to a Squid transparent proxy running on the firewall and listening on port 3128. Squid will of course require access to remote web servers.

In `/etc/shorewall/rules`:

    #ACTION   SOURCE     DEST     PROTO    DPORT            SPORT      ORIGDEST
    ACCEPT    $FW        net      tcp      www
    REDIRECT  loc        3128     tcp      www              -          !206.124.146.177

There may be a requirement to exclude additional destination hosts or networks from being redirected. For example, you might also want requests destined for 130.252.100.0/24 to not be routed to Squid.

If needed, you may just add the additional hosts/networks to the ORIGDEST column in your REDIRECT rule.

`/etc/shorewall/rules`:

    #ACTION   SOURCE     DEST     PROTO    DPORT            SPORT      ORIGDEST
    REDIRECT  loc        3128     tcp      www              -          !206.124.146.177,130.252.100.0/24

People frequently ask *How can I exclude certain internal systems from using the proxy? I want to allow those systems to go directly to the net*.

Suppose that you want to exclude 192.168.1.5 and 192.168.1.33 from the proxy. Your rules would then be:

    #ACTION   SOURCE     DEST     PROTO    DPORT            SPORT      ORIGDEST
    ACCEPT    $FW        net      tcp      www
    REDIRECT  loc:!192.168.1.5,192.168.1.33\
                         3128     tcp      www              -          !206.124.146.177,130.252.100.0/24
    ACCEPT    loc        net      tcp      www

The last rule may be omitted if your loc-\>net policy is ACCEPT.

In some cases (when running an LTSP server on the Shorewall system), you might want to transparently proxy web connections that originate on the firewall itself. This requires care to ensure that Squid's own web connections are not proxied.

First, determine the user id that Squid is running under:

    gateway:/etc/shorewall# ps aux | fgrep -i squid | fgrep -v fgrep
    root     10085  0.0  0.0  23864   700 ?        Ss   Apr22   0:00 /usr/sbin/squid -D -YC
    proxy    10088  0.0  0.9  40512 19192 ?        S    Apr22  10:58 (squid) -D -YC
    gateway:/etc/shorewall# 

In this case, the proxy process **(squid)** is running under the **proxy** user Id. We add these rules:

    #ACTION   SOURCE     DEST     PROTO    DPORT            SPORT      ORIGDEST          RATE       USER
    ACCEPT    $FW        net      tcp      www
    REDIRECT  $FW        3128     tcp      www              -          -                 -          !proxy

### Squid (transparent) Running in the local network

You want to redirect all local www connection requests to a Squid transparent proxy running in your local zone at 192.168.1.3 and listening on port 3128. Your local interface is eth1. There may also be a web server running on 192.168.1.3. It is assumed that web access is already enabled from the local zone to the Internet.

1.  Add this entry to your /etc/shorewall/providers file.

        #NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS
        Squid   1       202     -               eth1            192.168.1.3     loose,notrack

2.  In `/etc/shorewall/mangle` add:

        #ACTION        SOURCE              DEST        PROTO    DPORT            SPORT      ORIGDEST
        MARK(202):P    eth1:!192.168.1.3   0.0.0.0/0   tcp      80

    If you are still using a tcrules file, you should consider switching to using a mangle file (`shorewall update -t` (`shorewall update` on Shorewall 5.0 and later) will do that for you). Corresponding /etc/shorewall/tcrules entries are:

        #MARK    SOURCE              DEST        PROTO    DPORT
        202:P    eth1:!192.168.1.3   0.0.0.0/0   tcp      80

3.  In `/etc/shorewall/interfaces`:

        #ZONE   INTERFACE    OPTIONS
        loc     eth1         routeback,routefilter=0,logmartians=0        

4.  On 192.168.1.3, arrange for the following command to be executed after networking has come up

        iptables -t nat -A PREROUTING -i eth0 ! -d 192.168.1.3 -p tcp --dport 80 -j REDIRECT --to-ports 3128          

    If you are running RedHat on the server, you can simply execute the following commands after you have typed the iptables command above:

        iptables-save > /etc/sysconfig/iptables
         chkconfig --level 35 iptables on         

### Squid (transparent) Running in the DMZ

You have a single system in your DMZ with IP address 192.0.2.177. You want to run both a web server and Squid on that system.

### Simple Configuration

In `/etc/shorewall/rules`:

    #ACTION  SOURCE   DEST                 PROTO    DPORT           SPORT      ORIGDEST
    DNAT     loc      dmz:192.0.2.177:3128 tcp      80              -          !192.0.2.177

### More Complex configuration

Assume that the dmz is connected through eth2 and that your local lan interfaces through eth1

1.  Add this entry to your /etc/shorewall/providers file.

        #NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS
        Squid   1       202     -               eth2            192.0.2.177     loose,notrack

2.  In `/etc/shorewall/mangle` add:

        #ACTION        SOURCE              DEST        PROTO    DPORT
        MARK(202):P    eth1                0.0.0.0/0   tcp      80

    Corresponding /etc/shorewall/tcrules entries are:

        #MARK    SOURCE              DEST        PROTO    DPORT
        202:P    eth1                0.0.0.0/0   tcp      80

3.  In `/etc/shorewall/interfaces`:

        #ZONE   INTERFACE    OPTIONS
        loc     eth2         routefilter=0,logmartians=0        

4.  On 172.0.2.177, arrange for the following command to be executed after networking has come up

        iptables -t nat -A PREROUTING -i eth0 ! -d 192.0.2.177 -p tcp --dport 80 -j REDIRECT --to-ports 3128          

    If you are running RedHat on the server, you can simply execute the following commands after you have typed the iptables command above:

        iptables-save > /etc/sysconfig/iptables
         chkconfig --level 35 iptables on         

# Squid as a Manual Proxy

Assume that Squid is running in zone SZ and listening on port SP; all web sites that are to be accessed through Squid are in the “net” zone. Then for each zone Z that needs access to the Squid server.

`/etc/shorewall/rules`:

    #ACTION   SOURCE   DEST   PROTO   DPORT
    ACCEPT    Z        SZ     tcp     SP
    ACCEPT    SZ       net    tcp     80,443

`/etc/shorewall/rules:`

    #ACTION   SOURCE   DEST   PROTO    DPORT
    ACCEPT    loc      $FW    tcp      8080
    ACCEPT    $FW      net    tcp      80,443

# Squid3 as a Transparent Proxy with TPROXY

Shorewall 4.5.4 contains support for TPROXY. TPROXY differs from REDIRECT in that it does not modify the IP header and requires Squid 3 or later. Because the IP header stays intact, TPROXY requires policy routing to direct the packets to the proxy server running on the firewall. This approach requires TPROXY support in your kernel and iptables and Squid 3. See <http://wiki.squid-cache.org/Features/Tproxy4>.

<div class="note">

Support for the TPROXY action in shorewall-tcrules(5) and the `local` option in shorewall-providers(5) has been available since Shoreall 4.4.7. That support required additional rules to be added in the 'start' extention script to make it work reliably. Beginning with Shorewall 4.6.0, TPROXY in [shorewall-tcrules](https://shorewall.org/manpages/shorewall-tcrules.html)(5) and in [shorewall-mangle](https://shorewall.org/manpages/shorewall-mangle.html)(5) work as described here.

</div>

The following configuration works with Squid running on the firewall itself (assume that Squid is listening on port 3129 for TPROXY connections).

`/etc/shorewall/interfaces:`

    #ZONE        INTERFACE        OPTIONS
    -            lo               -

`/etc/shorewall/providers`:

    #NAME   NUMBER   MARK    DUPLICATE  INTERFACE  GATEWAY         OPTIONS               COPY
    Tproxy    1        -        -           lo        -            tproxy

<div class="note">

Notice that the MARK, DUPLICATE and GATEWAY columns are empty and that the only option is `tproxy`.

</div>

`/etc/shorewall/mangle` (assume loc interface is eth1 and net interface is eth0):

    #ACTION         SOURCE      DEST        PROTO      DPORT       SPORT
    DIVERT          eth0        0.0.0.0/0   tcp        -           80
    TPROXY(3129)    eth1        0.0.0.0/0   tcp        80

Corresponding `/etc/shorewall/tcrules` are:

    #MARK           SOURCE      DEST        PROTO      DPORT       SPORT
    DIVERT          eth0        0.0.0.0/0   tcp        -           80
    TPROXY(3129)    eth1        0.0.0.0/0   tcp        80

The DIVERT rules are used to avoid unnecessary invocation of TPROXY for request packets after the connection is established and to direct response packets back to Squid3.

<div class="note">

If you run a web server on the Shorewall system that also listens on port 80, then you need to exclude it from TPROXY. Suppose that your web server listens on 192.0.2.144; then:

    #MARK           SOURCE              DEST           PROTO      DPORT       SPORT
    DIVERT          eth0                0.0.0.0/0      tcp        -           80
    TPROXY(3129)    eth1                !192.0.2.144   tcp        80          -

</div>

/etc/shorewall/rules:

    #ACTION   SOURCE   DEST   PROTO   DPORT
    ACCEPT    loc      $FW    tcp     80
    ACCEPT    $FW      net    tcp     80

`/etc/squid3/squid.conf`:

    ...
    http_port 3129 tproxy
    ...

<div class="important">

If you use TPROXY with both IPv4 and IPv6, then both your local hosts and the gateway must have the same DNS view. If a client resolves a website URL to an IPv6 address and the server can only resolve to an IPv4 address, then Squid will attempt to connect to the IPv4 address using the local client's IPv6 address. That clearly doesn't work.

</div>
