<div class="caution">

**This article applies to Shorewall 3.0 and later. If you are running a version of Shorewall earlier than Shorewall 3.0.0 then please see the documentation for that release**

</div>

# Important Notes

<div class="note">

Shorewall distribution contains a library of user-defined macros that allow for easily allowing or blocking a particular application. `ls /usr/share/shorewall/macro.*` for the list of macros in your distribution. If you find what you need, you simply use the macro in a rule. For example, to allow DNS queries from the **dmz** zone to the **net** zone:

    #ACTION         SOURCE        DEST
    DNS(ACCEPT)     dmz           net

</div>

<div class="note">

In the rules that are shown in this document, the ACTION is shown as ACCEPT. You may need to use DNAT (see [FAQ 30](../reference/FAQ.md#faq30)) or you may want DROP or REJECT if you are trying to block the application.

Example: You want to port forward FTP from the net to your server at 192.168.1.4 in your DMZ. The FTP section below gives you:

    #ACTION        SOURCE    DEST             PROTO      DPORT
    FTP(ACCEPT)    <source>  <destination>

You would code your rule as follows:

    #ACTION        SOURCE    DESTINATION      PROTO      DPORT
    FTP(DNAT)       net       dmz:192.168.1.4  

</div>

# Auth (identd)

<div class="caution">

***It is now the 21st Century* ; don't use identd in production anymore.**

</div>

    #ACTION          SOURCE    DESTINATION      PROTO      DPORT
    Auth(ACCEPT)     <source>  <destination>

# BitTorrent

<div class="caution">

This information is valid only for Shorewall 3.2 or later.

</div>

<div class="caution">

***This rule assumes that your BitTorrent client listens on the default port(s)***

</div>

    #ACTION           SOURCE    DESTINATION      PROTO      DPORT
    BitTorrent(ACCEPT)<source>  <destination>

# DNS

    #ACTION          SOURCE    DESTINATION      PROTO      DPORT
    DNS(ACCEPT)      <source>  <destination>    

Note that if you are setting up a DNS server that supports recursive resolution, the server is the \<*destination*\> for resolution requests (from clients) and is also the \<*source*\> of recursive resolution requests (usually to other servers in the 'net' zone). So for example, if you have a public DNS server in your DMZ that supports recursive resolution for local clients then you would need:

    #ACTION     SOURCE    DESTINATION      PROTO      DPORT
    DNS(ACCEPT) all       dmz              
    DNS(ACCEPT) dmz       net              

<div class="note">

Recursive Resolution means that if the server itself can't resolve the name presented to it, the server will attempt to resolve the name with the help of other servers.

</div>

# Emule

<div class="caution">

This information is valid only for Shorewall 3.2 or later.

</div>

In contrast to how the rest of this article is organized, for emule I will give you the rules necessary to run emule on a single machine in your loc network (since that's what 99.99% of you want to do). Assume that:

1.  The internal machine running emule has IP address 192.168.1.4.

2.  You use Masquerading or SNAT for the local network.

3.  The zones are named as they are in the [two- and three-interface QuickStart guides)](../reference/shorewall_quickstart_guide.md).

4.  Your loc-\>net policy is ACCEPT

`/etc/shorewall/rules:`

    #ACTION       SOURCE   DESTINATION          PROTO         DPORT
    Edonkey(DNAT)  net      loc:192.168.1.4
    #if you wish to enable the Emule webserver, add this rule too.
    DNAT        net      loc:192.168.1.4      tcp           4711

# FTP

    #ACTION        SOURCE    DESTINATION      PROTO      DPORT
    FTP(ACCEPT)    <source>  <destination>

Look [here](FTP.md) for much more information.

# Gnutella

1.  The internal machine running a Gnutella Client has IP address 192.168.1.4.

2.  You use Masquerading or SNAT for the local network.

3.  The zones are named as they are in the [two- and three-interface QuickStart guides)](../reference/shorewall_quickstart_guide.md).

4.  Your loc-\>net policy is ACCEPT

<!-- -->

    #ACTION              SOURCE   DESTINATION      PROTO      DPORT
    Gnutella(DNAT)       net      loc:192.168.1.4

# ICQ/AIM

    #ACTION     SOURCE    DESTINATION      PROTO      DPORT
    ICQ(ACCEPT) <source>  net

# IMAP

<div class="caution">

When accessing your mail from the Internet, use **only** **IMAP over SSL.**

</div>

<div class="caution">

This information is valid only for Shorewall 3.2 or later.

</div>

    #ACTION         SOURCE    DESTINATION      PROTO      DPORT
    IMAP(ACCEPT)    <source>  <destination> # Unsecure IMAP 
    IMAPS(ACCEPT)   <source>  <destination> # IMAP over SSL.

# IPsec

    #ACTION    SOURCE         DESTINATION      PROTO      DPORT
    ACCEPT     <source>       <destination>    50     
    ACCEPT     <source>       <destination>    51
    ACCEPT     <source>       <destination>    udp        500
    ACCEPT     <destination>  <source>         50     
    ACCEPT     <destination>  <source>         51
    ACCEPT     <destination>  <source>         udp        500

Lots more information [here](IPSEC-2.6.md) and [here](VPN.md).

# LDAP

<div class="caution">

This information is valid only for Shorewall 3.2 or later.

</div>

    #ACTION          SOURCE           DESTINATION      PROTO      DPORT
    LDAP(ACCEPT)     <source>       <destination>      #Insecure LDAP
    LDAPS(ACCEPT)    <source>       <destination>   # LDAP over SSL

# My\SQL

<div class="caution">

This information is valid only for Shorewall 3.2 or later.

</div>

<div class="caution">

Allowing access from untrusted hosts to your MySQL server represents a **severe security risk**.

**DO NOT USE THIS** if you don't know how to deal with the consequences, you have been warned.

</div>

    #ACTION          SOURCE           DESTINATION      PROTO      DPORT
    MySQL(ACCEPT)     <source>       <destination>     

# NFS

    #ACTION    SOURCE                         DESTINATION      PROTO      DPORT
    ACCEPT     <z1>:<list of client IPs>      <z2>:a.b.c.d     tcp        111
    ACCEPT     <z1>:<list of client IPs>      <z2>:a.b.c.d     udp

For more NFS information, see <http://lists.shorewall.net/~kb/>.

# NTP (Network Time Protocol)

    #ACTION        SOURCE    DESTINATION      PROTO      DPORT
    NTP(ACCEPT)    <source>  <destination>

# PCAnywhere

    #ACTION        SOURCE    DESTINATION      PROTO      DPORT
    PCA(ACCEPT)    <source>  <destination>

# POP3

<div class="caution">

If Possible , **Avoid this protocol** , use **IMAP** instead.

</div>

<div class="caution">

This information is valid only for Shorewall 3.2 or later

</div>

    #ACTION         SOURCE    DESTINATION      PROTO      DPORT
    POP3(ACCEPT)    <source>  <destination>   # Secure
    POP3S(ACCEPT)   <source>  <destination>  #Unsecure Pop3

# PPTP

    #ACTION    SOURCE    DESTINATION      PROTO      DPORT
    ACCEPT     <source>  <destination>    47    
    ACCEPT     <source>  <destination>    tcp        1723

Lots more information [here](PPTP.md) and [here](VPN.md).

# rdate

    #ACTION          SOURCE    DESTINATION      PROTO      DPORT
    Rdate(ACCEPT)    <source>  <destination>

# rsync

    #ACTION          SOURCE    DESTINATION      PROTO      DPORT
    Rsync(ACCEPT)    <source>  <destination>

# Siproxd

<div class="caution">

This assumes siproxd is running **on the firewall and is using the default ports**.

</div>

    #ACTION          SOURCE    DESTINATION      PROTO      DPORT
    REDIRECT          loc           5060         udp        5060
    ACCEPT            net           fw           udp        5060
    ACCEPT            net           fw           udp        7070:7089

# SSH/SFTP

    #ACTION    SOURCE    DESTINATION      PROTO      DPORT
    SSH(ACCEPT)<source>  <destination> 

# SMB/NMB (Samba/Windows Browsing/File Sharing)

    #ACTION        SOURCE         DESTINATION      PROTO      DPORT
    SMB(ACCEPT)    <source>       <destination>
    SMB(ACCEPT)    <destination>  <source>

Also, see [this page](../legacy/samba.md).

# SMTP

<div class="caution">

This information is valid only for Shorewall 3.2 or later.

</div>

    #ACTION         SOURCE    DESTINATION      PROTO      DPORT
    SMTP(ACCEPT)     <source>  <destination>                      #Insecure SMTP
    SMTPS(ACCEPT)    <source>  <destination>                      #SMTP over SSL (TLS)

# SNMP

    #ACTION         SOURCE    DESTINATION      PROTO      DPORT
    SNMP(ACCEPT)    <source>  <destination>

# SVN

<div class="caution">

This information is valid only for Shorewall 3.2 or later.

</div>

<div class="caution">

This rule is for Subversion running in **svnserve mode only.**

</div>

    #ACTION         SOURCE    DESTINATION      PROTO      DPORT
    SVN(ACCEPT)    <source>  <destination>

# Telnet

<div class="caution">

***The telnet protocol is very insecure*, don't use it.**

</div>

    #ACTION           SOURCE    DESTINATION      PROTO      DPORT
    Telnet(ACCEPT)    <source>  <destination>

# TFTP

You must have TFTP connection tracking support in your kernel. If modularized, the modules are **ip_conntrack_tftp** (and **ip_nat_tftp** if any form of NAT is involved) These modules may be loaded using entries in `/etc/shorewall/modules`. The **ip_conntrack_tftp** module must be loaded first. Note that the `/etc/shorewall/modules` file released with recent Shorewall versions contains entries for these modules.

    #ACTION    SOURCE    DESTINATION      PROTO      DPORT
    ACCEPT     <source>  <destination>    udp        69

# Traceroute

    #ACTION          SOURCE    DESTINATION      PROTO      DPORT
    Trcrt(ACCEPT)    <source>  <destination>  #Good for 10 hops

UDP traceroute uses ports 33434 through 33434+\<max number of hops\>-1. Note that for the firewall to respond with a TTL expired ICMP reply, you will need to allow ICMP 11 outbound from the firewall. The standard Shorewall sample configurations all set this up for you automatically since those sample configurations enable all ICMP packet types originating on the firewall itself.

    #ACTION    SOURCE    DESTINATION      PROTO      DPORT
    ACCEPT     fw        net              icmp
    ACCEPT     fw        loc              icmp
    ACCEPT     fw        ...

# Usenet (NNTP)

    #ACTION         SOURCE    DESTINATION      PROTO      DPORT
    NNTP(ACCEPT)    <source>  <destination>
    NNTPS(ACCEPT)   <source>  <destination>  # secure NNTP

TCP Port 119

# VNC

<div class="caution">

This information is valid only for Shorewall 3.2 or later.

</div>

Vncviewer to Vncserver -- TCP port 5900 + \<display number\>.

the following rule handles VNC traffic for VNC displays 0 - 9.

    #ACTION    SOURCE    DESTINATION      PROTO      DPORT
    VNC(ACCEPT)    <source>  <destination>      

Vncserver to Vncviewer in listen mode -- TCP port 5500.

    #ACTION         SOURCE    DESTINATION      PROTO      DPORT
    VNCL(ACCEPT)    <source>  <destination>

# Vonage

The standard Shorewall loc-\>net ACCEPT policy is all that is required for Vonage IP phone service to work, provided that you have loaded the tftp helper modules (add the following entries to /etc/shorewall/modules if they are not there already):

# Web Access

<div class="caution">

This information is valid for Shorewall 3.2 or later.

</div>

    #ACTION        SOURCE    DESTINATION      PROTO      DPORT
    HTTP(ACCEPT)    <source>  <destination> #Insecure HTTP 
    HTTPS(ACCEPT)   <source>  <destination> #Secure   HTTP

# Webmin

    #ACTION        SOURCE    DESTINATION      PROTO      DPORT
    Webmin(ACCEPT)    <source>  <destination>  

Webmin use TCP port 10000.

# Whois

    #ACTION        SOURCE    DESTINATION      PROTO      DPORT
    Whois(ACCEPT)    <source>  <destination>  

# X/XDMCP

Assume that the Chooser and/or X Server are running at \<*chooser*\> and the Display Manager/X applications are running at \<*apps*\>.

    #ACTION    SOURCE    DESTINATION      PROTO      DPORT
    ACCEPT     <chooser> <apps>           udp        177         #XDMCP
    ACCEPT     <apps>    <chooser>        tcp        6000:6009   #X Displays 0-9

# Other Source of Port Information

Didn't find what you are looking for -- have you looked in your own /etc/services file?

Still looking? Try <http://www.networkice.com/advice/Exploits/Ports>
