<div class="caution">

**This article applies to Shorewall 4.4 and later. If you are running a version of Shorewall earlier than Shorewall 4.4.0 then please see the documentation for that release.**

</div>

# Installing Shorewall

## Where do I find Step by Step Installation and Configuration Instructions?

**Answer:** Check out the [QuickStart Guides](shorewall_quickstart_guide.md).

## (FAQ 92) There are lots of Shorewall packages; which one(s) do I install?

**Answer**: When first installing Shorewall 4.4.0 or later, you must install the **shorewall** package. If you want to configure an IPv6 firewall, you must also install **shorewall6**. Beginning with Shorewall 4.5, you must first install the **shorewall-core** package.

### (FAQ 92a) Someone once told me to install shorewall-perl; anything to that?

**Answer**: That was good advice in Shorewall 4.2 and earlier. In those releases, there were two packages that provided the basic firewalling functionality: **shorewall-shell** and **shorewall-perl**. Beginning with Shorewall 4.4.0, **shorewall-shell** is discontinued and **shorewall-perl** is renamed **shorewall**.

## (FAQ 37) I just installed Shorewall on Debian and the /etc/shorewall directory is almost empty!!!

**Answer:**

<div class="important">

Once you have installed the .deb package and before you attempt to configure Shorewall, please heed the advice of Lorenzo Martignoni, former Shorewall Debian Maintainer:

“For more information about Shorewall usage on Debian system please look at /usr/share/doc/shorewall-common/README.Debian provided by \[the\] shorewall-common Debian package.”

</div>

If you install using the .deb, you will find that your `/etc/shorewall` directory is almost empty. This is intentional. The released configuration file skeletons may be found on your system in the directory `/usr/share/doc/shorewall-common/default-config`. Simply copy the files you need from that directory to `/etc/shorewall` and modify the copies.

### (FAQ 37a) I just installed Shorewall on Debian and I can't find the sample configurations.

**Answer:** Beginning with Shorewall 4.4, the samples are in the shorewall package and are installed in `/usr/share/doc/shorewall/examples/`.

## (FAQ 14) I can't find the Shorewall 4.4 shorewall-common, shorewall-shell and shorewall-perl packages? Where are they?

**Answer**:In Shorewall 4.4, the shorewall-shell package was discontinued. The shorewall-common and shorewall-perl packages were combined to form a single shorewall package. In Shorewall 4.5, the shorewall-core package was added and all of the other packages depend on shorewall-core.

## (FAQ 1.5) After installing the latest version (\> 5.1.10.1) of Shorewall, when I change my configuration and 'shorewall reload' or 'shorewall restart', my changes aren't in the running ruleset. Why is that happening?

**Answer:** This happens when:

1.  You use INCLUDE (?INCLUDE).

2.  The included files are in a subdirectory of /etc/shorewall\[6\] or in a separate directory.

3.  You have AUTOMAKE=Yes in [shorewall\[6\].conf(5)](https://shorewall.org/manpages/shorewall.conf.html).

When AUTOMAKE=Yes, the compiler looks for files in each directory in CONFIG_PATH for files that are newer that the last-generated firewall script. If none are found, the old script is used as is. Prior to version 5.1.10.2, that search was recursive so changes in sub-directories of /etc/shorewall\[6\] were automatically searched. This had performance implications if directories on the CONFIG_PATH were deeply nested. So, beginning with version 5.1.10.2, only the directories themselves are searched. You can restore the pre-5.1.10.2 behavior by setting AUTOMAKE=recursive, or AUTOMAKE=\<integer\>, where integer specifies the search depth. If your included files are in a separate directory, then that directory must be added to CONFIG_PATH in order to allow AUTOMAKE to work correctly.

# Upgrading Shorewall

## (FAQ 66) I'm trying to upgrade to Shorewall 4.x or later; which of these packages do I need to install?

**Answer:** Please see the [upgrade issues.](../legacy/upgrade_issues.md)

## (FAQ 34) I am trying to upgrade to Shorewall 4.4 or later and I can't find the shorewall-common, shorewall-shell and shorewall-perl packages? Where are they?

**Answer**:In Shorewall 4.4, the shorewall-shell package was discontinued. The shorewall-common and shorewall-perl packages were combined to form a single shorewall package. For further information, please see the [upgrade issues.](../legacy/upgrade_issues.md).

## (FAQ 34a) I am trying to upgrade to Shorewall 4.4 and I'm getting errors when I try to start Shorewall. Where can I find information about these issues?

**Answer**: Please see the [upgrade issues](../legacy/upgrade_issues.md).

## (FAQ 34b) I am trying to upgrade to Shorewall 4.4 and I'm seeing warning messages when I try to start Shorewall. Where can I find information about these issues?

**Answer**: Please see the [upgrade issues.](../legacy/upgrade_issues.md)

## (FAQ 76) I just upgraded my system and now masquerading doesn't work? What happened?

**Answer:** This happens to people who ignore [our advice](Install.md#Upgrade_Deb) and allow the installer to replace their working `/etc/shorewall/shorewall.conf` with one that has default settings. Failure to forward traffic (such as during masqueraded net access from a local network) usually means that `/etc/shorewall/shorewall.conf` contains the default setting IP_FORWARDING=Keep; it should be IP_FORWARDING=On.

**Update**: Beginning with Shorewall 4.4.21, there is a **shorewall update** command that does a smart merge of your existing shorewall.conf and the new one.

## (FAQ 2 .6) After upgrading to the latest version (\> 5.1.10.1) of Shorewall, when I change my configuration and 'shorewall reload' or 'shorewall restart', my changes aren't in the running ruleset. Why is that happening?

**Answer:** See[ FAQ 1.5](#faq1.5).

# Port Forwarding (Port Redirection)

## (FAQ 1) I want to forward UDP port 7777 to my personal PC with IP address 192.168.1.5. I've looked everywhere and can't find how to do it.

**Answer:** The format of a port-forwarding rule *from the net* to a local system is as follows:

    #ACTION    SOURCE      DEST                                   PROTO        DPORT
    DNAT       net         loc:local-IP-address[:local-port]      protocol     port-number

So to forward UDP port 7777 to internal system 192.168.1.5, the rule is:

    #ACTION    SOURCE   DEST             PROTO    DPORT
    DNAT       net      loc:192.168.1.5  udp      7777

If you want to forward requests directed to a particular address ( *external-IP* ) on your firewall to an internal system:

    #ACTION SOURCE DEST                                   PROTO       DPORT         SPORT   ORIGDEST
    DNAT    net    loc:local-IP-address>[:local-port]     protocol    port-number   -       external-IP

If you want to forward requests from a particular Internet address ( *address* ):

    #ACTION SOURCE        DEST                                   PROTO       DPORT         SPORT   ORIGDEST
    DNAT    net:address   loc:local-IP-address[:local-port]      protocol    port-number   -

Finally, if you need to forward a range of ports, in the DEST PORT column specify the range as *low-port:high-port*.

<div class="important">

**The above does not work for forwarding from the local network. If you want to do that, see [FAQ 2](#faq2).**

</div>

### (FAQ 1a) Okay -- I followed those instructions but it doesn't work

**Answer:** That is usually the result of one of five things:

- You are trying to redirect a UDP port and there is already a conntrack table entry for the flow, created via an ACCEPT rule.

  Example:

              DNAT    loc:192.168.0.2 dmz:192.168.1.3 udp 53

  Assuming that you have installed the *conntrack* package, you can delete all such conntrack table entries using:

              conntrack -D -s 192.168.0.2 -p udp --dport 53

- You are trying to test from inside your firewall (no, that won't work -- see [(FAQ 2) I port forward www requests to www.mydomain.com (IP 130.151.100.69) to system 192.168.1.5 in my local network. External clients can browse http://www.mydomain.com but internal clients can't.](#faq2)).

- You have a more basic problem with your local system (the one that you are trying to forward to) such as an incorrect default gateway (it must be set to the IP address of your firewall's internal interface; if that isn't possible for some reason, see [FAQ 1f](#faq1f)).

- Your ISP is blocking that particular port inbound or, for TCP, your ISP is dropping the outbound SYN,ACK response.

- You are running Mandriva Linux prior to 10.0 final and have configured Internet Connection Sharing. In that case, the name of your local zone is 'masq' rather than 'loc' (change all instances of 'loc' to 'masq' in your rules). You may want to consider re-installing Shorewall in a configuration which matches the Shorewall documentation. See the [two-interface QuickStart Guide](two-interface.md) for details.

### (FAQ 1b) I'm still having problems with port forwarding

**Answer:** To further diagnose this problem:

- As root, type “ `shorewall reset` ” ("`shorewall-lite reset`", if you are running Shorewall Lite). This clears all Netfilter counters.

- Try to connect to the redirected port from an external host.

- As root type “ `shorewall show nat` ” ("`shorewall-lite show nat`", if you are running Shorewall Lite).

- Locate the appropriate DNAT rule. It will be in a chain called *\<source zone\>*\_dnat (“net_dnat” in the above examples).

- Is the packet count in the first column non-zero? If so, the connection request is reaching the firewall and is being redirected to the server. In this case, the problem is usually a missing or incorrect default gateway setting on the local system (the system you are trying to forward to -- its default gateway must be the IP address of the firewall's interface to that system unless you use the hack described in [FAQ 1f](#faq1f)).

- If the packet count is zero:

  - the connection request is not reaching your server (possibly it is being blocked by your ISP); or

  - you are trying to connect to a secondary IP address on your firewall and your rule is only redirecting the primary IP address (You need to specify the secondary IP address in the “ORIG. DEST.” column in your DNAT rule); or

  - your DNAT rule doesn't match the connection request in some other way. In that case, you may have to use a packet sniffer such as tcpdump or Wireshark to further diagnose the problem.

  - The traffic is entering your firewall on a different interface (interfaces reversed in `/etc/shorewall/interfaces`?).

- If the packet count is non-zero, check your log to see if the connection is being dropped or rejected. If it is, then you may have a zone definition problem such that the server is in a different zone than what is specified in the DEST column. At a root prompt, type "`shorewall show zones`" ("`shorewall-lite show zones`") then be sure that in the DEST column you have specified the **first** zone in the list that matches OUT=\<dev\> and DEST= \<ip\>from the REJECT/DROP log message.

- If everything seems to be correct according to these tests but the connection doesn't work, it may be that your ISP is blocking SYN,ACK responses. This technique allows your ISP to detect when you are running a server (usually in violation of your service agreement) and to stop connections to that server from being established.

### (FAQ 1c) From the Internet, I want to connect to port 1022 on my firewall and have the firewall forward the connection to port 22 on local system 192.168.1.3. How do I do that?

**Answer:**In /`etc/shorewall/rules`:

    #ACTION    SOURCE   DEST                PROTO    DPORT
    DNAT       net      loc:192.168.1.3:22  tcp      1022

### (FAQ 1d) I have a web server in my DMZ and I use port forwarding to make that server accessible from the Internet. That works fine but when my local users try to connect to the server using the Firewall's external IP address, it doesn't work.

**Answer:** See [FAQ 2b](#faq2b).

### (FAQ 1e) In order to discourage brute force attacks I would like to redirect all connections on a non-standard port (4104) to port 22 on the router/firewall. I notice that setting up a REDIRECT rule causes the firewall to open both ports 4104 and 22 to connections from the net. Is it possible to only redirect 4104 to the localhost port 22 and have connection attempts to port 22 from the net dropped?

<div class="important">

On systems with the "Extended Conntrack Match" (NEW_CONNTRACK_MATCH) capability (see the output of `shorewall show capabilities`), port 22 is opened only to connections whose original destination port is 4104 and this FAQ does not apply.

</div>

**Answer** courtesy of Ryan: Assume that the IP address of your local firewall interface is 192.168.1.1. If you configure SSHD to only listen on that address and add the following rule, then you will have access on port 4104 from the net and on port 22 from your LAN.

    #ACTION SOURCE  DEST                    PROTO   DPORT
    DNAT    net     fw:192.168.1.1:22       tcp     4104

### (FAQ 1f) Why must the server that I port forward to have it's default gateway set to my Shorewall system's IP address?

**Answer:** Let's take an example. Suppose that

- Your Shorewall firewall's external IP address is 206.124.146.176 (eth0) and its internal IP address is 192.168.1.1 (eth1).

- You have another gateway router with external IP address 130.252.100.109 and internal IP address 192.168.1.254.

- You have an FTP server behind both routers with IP address 192.168.1.4

- The FTP server's default gateway is through the second router (192.168.1.254).

- You have this rule on the Shorewall system:

      #ACTION    SOURCE        DEST               PROTO    DPORT       SPORT     ORIGDEST
      DNAT       net           loc:192.168.1.4    tcp      21          -         206.124.146.176

- Internet host 16.105.221.4 issues the command `ftp 206.124.146.176`

This results in the following sequence of events:

1.  16.105.221.4 sends a TCP SYN packet to 206.124.146.176 specifying destination port 21.

2.  The Shorewall box rewrites the destination IP address to 192.168.1.4 and forwards the packet.

3.  The FTP server receives the packet and accepts the connection, generating a SYN,ACK packet back to 16.105.221.4. Because the server's default gateway is through the second router, it sends the packet to that router.

At this point, one of two things can happen. Either the second router discards or rejects the packet; or, it rewrites the source IP address to 130.252.100.109 and forwards the packet back to 16.105.221.4. Regardless of which happens, the connection is doomed. Clearly if the packet is rejected or dropped, the connection will not be successful. But even if the packet reaches 16.105.221.4, that host will reject it since it's SOURCE IP address (130.252.100.109) doesn't match the DESTINATION IP ADDRESS (206.124.146.176) of the original SYN packet.

The best way to work around this problem is to change the default gateway on the FTP server to the Shorewall system's internal IP address (192.168.1.1). But if that isn't possible, you can work around the problem with the following ugly hack in `/etc/shorewall/masq`:

    #INTERFACE              SOURCE             ADDRESS         PROTO   PORT
    eth1:192.168.1.4        0.0.0.0/0          192.168.1.1     tcp     21

When running Shorewall 5.0.14 or later, the eqivalent `/etc/shorewall/snat` file is:

    #ACTION                 SOURCE              DEST              PROTO  PORT
    SNAT(192.168.1.1)       0.0.0.0/0           eth1:192.168.1.4  tcp    21

This rule has the undesirable side effect of making all FTP connections from the net appear to the FTP server as if they originated on the Shorewall system. But it will force the FTP server to reply back through the Shorewall system who can then rewrite the SOURCE IP address in the responses properly.

### (FAQ 1g) I would like to redirect port 80 on my public IP address (206.124.146.176) to port 993 on Internet host 66.249.93.111

**Answer:** This requires a vile hack similar to the one in [FAQ 2](#faq2). Assuming that your Internet zone is named *net* and connects on interface `eth0`:

In `/etc/shorewall/rules`:

    #ACTION    SOURCE        DEST                   PROTO    DPORT   SPORT   ORIGDEST

    ?SECTION ALL
    ?SECTION ESTABLISHED
    ?SECTION RELATED
    ?SECTION INVALID
    ?SECTION UNTRACKED
    ?SECTION NEW

    DNAT       net           net:66.249.93.111:993  tcp      80      -       206.124.146.176

In `/etc/shorewall/interfaces`, specify the **routeback** option on eth0:

    ?FORMAT 2
    #ZONE       INTERFACE       OPTIONS
    net             eth0                    routeback

`/etc/shorewall/masq`;

    #INTERFACE              SOURCE          ADDRESS         PROTO   PORT
    eth0:66.249.93.111      0.0.0.0/0       206.124.146.176 tcp     993

When running Shorewall 5.0.14 or later, the equivalent /etc/shorewall/snat file is:

    #ACTION                 SOURCE          DEST                PROTO   PORT
    SNAT(206.124.146.176)   0.0.0.0/0       eth0:66.249.93.111  tcp     993

and in `/etc/shorewall/shorewall.conf`:

    IP_FORWARDING=On

Like the hack in FAQ 2, this one results in all forwarded connections looking to the server (66.249.93.11) as if they originated on your firewall (206.124.146.176).

### (FAQ 1h) How do I set shorewall to allow ssh on port 9022 from net? SSHD is listening on port 22.

**Answer**: Use this rule.

    #ACTION         SOURCE          DEST            PROTO   DPORT
    REDIRECT        net             22              tcp     9022

Note that the above rule will also allow connections from the net on TCP port 22. If you don't want that, see [FAQ 1e](#faq1e).

### (FAQ 1j) Why doesn't this DNAT rule work?

I added this rule but I'm still seeing the log message below

    RULE:
    DNAT           scnet:172.19.41.2       dmz0:10.199.198.145             udp     2055

    LOG:
    Sep 21 12:55:37 fw001 kernel: [10357687.114928] Shorewall:scnet2fw:DROP:IN=eth2 OUT=
    MAC=00:26:33:dd:aa:05:00:24:f7:19:ce:44:08:00 SRC=172.19.41.2 DST=172.19.1.1 LEN=1492
    TOS=0x00 PREC=0x00 TTL=63 ID=23035 PROTO=UDP SPT=6376 DPT=2055 LEN=1472

**Answer**: There was already a conntrack entry for the failing connection before you added the rule. Install the **conntrack** utility program and use it to delete the entry.

    conntrack -D -s 172.19.41.2 -d 172.19.1.1 -p udp -sport 6367 -dport 2055 

## (FAQ 30) I'm confused about when to use DNAT rules and when to use ACCEPT rules.

**Answer:** It would be a good idea to review the [QuickStart Guide](shorewall_quickstart_guide.md) appropriate for your setup; the guides cover this topic in a tutorial fashion. DNAT rules should be used for connections that need to go the opposite direction from SNAT/MASQUERADE. So if you masquerade or use SNAT from your local network to the Internet then you will need to use DNAT rules to allow connections from the Internet to your local network.

<div class="note">

If you use both 1:1 NAT and SNAT/MASQUERADE, those connections that are subject to 1:1 NAT should use ACCEPT rather than DNAT. Note, however, that DNAT can be used to override 1:1 NAT so as to redirect a connection to a different internal system or port than would be the case using 1:1 NAT.

</div>

You also want to use DNAT rules when you intentionally want to rewrite the destination IP address or port number. In all other cases, you use ACCEPT unless you need to hijack connections as they go through your firewall and handle them on the firewall box itself; in that case, you use a REDIRECT rule.

<div class="note">

The preceding answer should *not* be interpreted to mean that DNAT can only be used in conjunction with SNAT. But in common configurations using private local addresses, that is the most common usage.

</div>

## (FAQ 8) I have several external IP addresses and use /etc/shorewall/nat to associate them with systems in my DMZ. When I add a DNAT rule, say for ports 80 and 443, Shorewall redirects connections on those ports for all of my addresses. How can I restrict DNAT to only a single address?

**Answer**: Specify the external address that you want to redirect in the ORIGDEST column.

Example:

    #ACTION         SOURCE          DEST                    PROTO   DPORT   SPORT   ORIGDEST
    DNAT            net             net:192.0.2.22        tcp     80,443  -       206.124.146.178

## (FAQ 38) Where can I find more information about DNAT?

**Answer:** Ian Allen has written a [Paper about DNAT and Linux](http://idallen.com/dnat.txt).

## (FAQ 48) How do I Set up a Transparent HTTP Proxy with Shorewall?

**Answer:** See [Shorewall_Squid_Usage.html](../features/Shorewall_Squid_Usage.md).

# DNS and Port Forwarding/NAT

## (FAQ 2) I port forward www requests to www.mydomain.com (IP 130.151.100.69) to system 192.168.1.5 in my local network. External clients can browse http://www.mydomain.com but internal clients can't.

**Answer:** I have two objections to this setup.

- Having an Internet-accessible server in your local network is like raising foxes in the corner of your hen house. If the server is compromised, there's nothing between that server and your other internal systems. For the cost of another NIC and a cross-over cable, you can put your server in a DMZ such that it is isolated from your local systems - assuming that the Server can be located near the Firewall, of course :-)

- The accessibility problem is best solved using Split DNS (either [use a separate DNS server](../features/SplitDNS.md) for local clients or use [Bind Version 9 “views”](shorewall_setup_guide.md#DNS) on your main name server) such that www.mydomain.com resolves to 130.141.100.69 externally and 192.168.1.5 internally. I use a separate DNS server (dnsmasq) here at shorewall.net.

So the best and most secure way to solve this problem is to move your Internet-accessible server(s) to a separate LAN segment with it's own interface to your firewall and follow [FAQ 2b](#faq2b). That way, your local systems are still safe if your server gets hacked and you don't have to run a split DNS configuration (separate server or Bind 9 views).

If physical limitations make it impractical to segregate your servers on a separate LAN, the next best solution it to use Split DNS. Before you complain "It's too hard to set up split DNS!", [**check here**](../features/SplitDNS.md).

If you really want to route traffic between two internal systems through your firewall, then proceed as described below.

<div class="warning">

All traffic redirected through use of this technique will look to the server as if it originated on the firewall rather than on the original client! So the server's access logs will be useless for determining which local hosts are accessing the server.

</div>

Assuming that your external interface is eth0 and your internal interface is eth1 and that eth1 has IP address 192.168.1.254 with subnet 192.168.1.0/24, then:

- In `/etc/shorewall/interfaces`:

      ?FORMAT 2
      #ZONE           INTERFACE               OPTIONS
      loc             eth1                    routeback

- In `/etc/shorewall/masq`:

      #INTERFACE              SOURCE          ADDRESS         PROTO   PORT
      eth1:192.168.1.5        192.168.1.0/24  192.168.1.254   tcp     www

  When running Shorewall 5.0.14 or later, the corresponding `/etc/shorewall/snat` file is:

      #ACTION                 SOURCE          DEST                PROTO   PORT
      SNAT(192.168.1.254)     192.168.1.0/24  eth1:192.168.1.5    tcp     www

  Note: The technique described here is known as hairpinning NAT and is described in section 6 of [RFC 4787](http://www.faqs.org/rfcs/rfc4787.html). In that RFC, it is required that the *external IP address* be used as the source:

      #INTERFACE              SOURCE          ADDRESS         PROTO   PORT
      eth1:192.168.1.5        192.168.1.0/24  130.151.100.69  tcp     www

  Equivalent `/etc/shorewall/snat`:

      #ACTION                 SOURCE          DEST                PROTO   PORT
      SNAT(130.151.100.69)    192.168.1.0/24  eth1:192.168.1.5    tcp     www

- In `/etc/shorewall/rules`:

      #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   ORIGDEST

      ?SECTION ALL
      ?SECTION ESTABLISHED
      ?SECTION RELATED
      ?SECTION INVALID
      ?SECTION UNTRACKED
      ?SECTION NEW

      DNAT            loc             loc:192.168.1.5 tcp     www     -       130.151.100.69

  That rule (and the second one in the previous bullet) only works of course if you have a static external IP address. If you have a dynamic IP address then make your DNAT rule:

      #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   ORIGDEST

      ?SECTION ALL
      ?SECTION ESTABLISHED
      ?SECTION RELATED
      ?SECTION INVALID
      ?SECTION UNTRACKED
      ?SECTION NEW

      DNAT            loc             loc:192.168.1.5 tcp     www     -       &eth0

  Using this technique, you will want to configure your DHCP/PPPoE/PPTP/… client to automatically reload Shorewall each time that you get a new IP address.

  <div class="note">

  If your local interface is a bridge, see [FAQ 2e](#faq2e) for additional configuration steps.

  </div>

### (FAQ 2a) I have a zone “Z” with an RFC1918 subnet and I use one-to-one NAT to assign non-RFC1918 addresses to hosts in Z. Hosts in Z cannot communicate with each other using their external (non-RFC1918 addresses) so they can't access each other using their DNS names.

<div class="note">

If the ALL INTERFACES column in /etc/shorewall/nat is empty or contains “Yes”, you will also see log messages like the following when trying to access a host in Z from another host in Z using the destination host's public address:

    Oct 4 10:26:40 netgw kernel:
              Shorewall:FORWARD:REJECT:IN=eth1 OUT=eth1 SRC=192.168.118.200
              DST=192.168.118.210 LEN=48 TOS=0x00 PREC=0x00 TTL=127 ID=1342 DF
              PROTO=TCP SPT=1494 DPT=1491 WINDOW=17472 RES=0x00 ACK SYN URGP=0

</div>

**Answer:** This is another problem that is best solved using split DNS. It allows both external and internal clients to access a NATed host using the host's DNS name.

Another good way to approach this problem is to switch from one-to-one NAT to Proxy ARP. That way, the hosts in Z have non-RFC1918 addresses and can be accessed externally and internally using the same address.

If you don't like those solutions and prefer to route all Z-\>Z traffic through your firewall then:

1.  Set the routeback option on the interface to Z.

2.  Set the ALL INTERFACES column in the nat file to “Yes”.

<!-- -->

    Zone: dmz, Interface: eth2, Subnet: 192.168.2.0/24, Address of server 192.168.2.2

In `/etc/shorewall/interfaces`:

    ?FORMAT 2
    #ZONE           INTERFACE               OPTIONS
    dmz             eth2                    routeback 

In `/etc/shorewall/masq`:

    #INTERFACE              SOURCE
    eth2:192.168.1.2        192.168.2.0/24

When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

    #ACTION        SOURCE          DEST                PROTO   PORT
    MASQUERADE     192.168.1.0/24  eth2:192.168.1.2    tcp     www

In `/etc/shorewall/nat`, be sure that you have “Yes” in the ALL INTERFACES column.

### (FAQ 2b) I have a web server in my DMZ and I use port forwarding to make that server accessible from the Internet as www.mydomain.com. That works fine but when my local users try to connect to www.mydomain.com, it doesn't work.

**Answer:** Let's assume the following:

- External IP address is 206.124.146.176 on `eth0` (www.mydomain.com).

- Server's IP address is 192.168.2.4

You can enable access to the server from your local network using the firewall's external IP address by adding this rule:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   ORIGDEST

    ?SECTION ALL
    ?SECTION ESTABLISHED
    ?SECTION RELATED
    ?SECTION INVALID
    ?SECTION UNTRACKED
    ?SECTION NEW

    DNAT            loc             dmz:192.168.2.4 tcp     80      -       206.124.146.176

If your external IP address is dynamic, then you must make your DNAT rule:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   ORIGDEST

    ?SECTION ALL
    ?SECTION ESTABLISHED
    ?SECTION RELATED
    ?SECTION INVALID
    ?SECTION UNTRACKED
    ?SECTION NEW

    DNAT            loc             dmz:192.168.2.4 tcp     80      -       &eth0

<div class="warning">

With dynamic IP addresses, you probably don't want to use [`shorewall[-lite] save` and `shorewall[-lite] restore`](starting_and_stopping_shorewall.md).

</div>

### (FAQ 2c) I tried to apply the answer to FAQ 2 to my external interface and the net zone and it didn't work. Why?

**Answer:** Did you set **IP_FORWARDING=On** in `shorewall.conf`?

### (FAQ 2d) Does Shorewall support hairpinning NAT?

**Answer:** Yes.

In the case of simple masquerade/SNAT, see [FAQ 2](#faq2).

For one-to-one (static), NAT, simply place 'Yes' in the ALL INTERFACES column of each entry in [/etc/shorewall/nat](https://shorewall.org/manpages/shorewall-nat.html).

### (FAQ 2e) I have the situation in FAQ 2 but my local interface is a bridge and the solution in FAQ 2 doesn't work

**Answer**: Assume that the bridge is br0 and that eth2 is the bridge port that connects to the LAN containing 192.168.1.5

In addition to the steps in FAQ 2 (replacing eth1 with br0), you also need to:

1.  Set the hairpin option on eth2.

        brctl hairpin br0 eth2 on

    On Debian and derivitives, you can place that command in /etc/network/interfaces as a post-up command:

        auto br0
        iface br0 inet static
                bridge_ports    eth2
                bridge_fd       0
                bridge_maxwait  0
                address         192.168.1.1
                netmask         255.255.255.0
                post-up /sbin/brctl hairpin br0 eth2 on

2.  Install ebtables if it is not already installed.

3.  Be sure that all traffic going out of eth2 has the correct MAC address.

        ebtables -t nat -A POSTROUTING -o eth2 -j snat --to-source br0-MAC-address 

    where br0-MAC-address is the MAC address of br0.

    Here's a working example of /etc/shorewall/start that executes the above command.

        if [ $(ebtables -t nat -L POSTROUTING | wc -l) -lt 4 ]; then
           ebtables -t nat -A POSTROUTING -o eth2 -j snat --to-source 0:19:21:d0:61:65
        fi

# Blacklisting

## (FAQ 63) I just blacklisted IP address 206.124.146.176 and I can still ping it. What did I do wrong?

**Answer:** Nothing.

Blacklisting an IP address blocks incoming traffic from that IP address. And if you set BLACKLISTNEWONLY=Yes in `shorewall.conf`, then only new connections **from** that address are disallowed; traffic from that address that is part of an established connection (such as ping replies) is allowed.

<div class="note">

Beginning with Shorewall 4.4.13, you can use the `blacklist` option in [`/etc/shorewall/interfaces`](https://shorewall.org/manpages/shorewall-interfaces.html) to implement blacklisting by destination IP address.

</div>

<div class="note">

Beginning with Shorewall 4.4.26, you can use [/etc/shorewall/blrules](https://shorewall.org/manpages/shorewall-blrules.html) to implement arbitrary blacklist rules.

</div>

## (FAQ 84) I put some IPs in the blacklist file in /etc/shorewall to block the ips but i'm still getting reports from PSAD from those ips saying they're port scanning. Shouldn't being on the blacklist drop all packets from those ips?

**Answer**: You probably forgot to specify the **blacklist** option for your external interface(s) in `/etc/shorewall/interfaces`.

# Netmeeting/MSN

## (FAQ 3) I want to use Netmeeting or MSN Instant Messenger with Shorewall. What do I do?

**Answer:** There is an [H.323 connection tracking/NAT module](http://www.kfki.hu/~kadlec/sw/netfilter/newnat-suite/) that helps with Netmeeting.

Look [here](../legacy/UPnP.md) for a solution for MSN IM but be aware that there are significant security risks involved with this solution. Also check the Netfilter mailing list archives at <http://www.netfilter.org>.

# Open Ports

## (FAQ 100) With Shorewall started, the output of 'iptables -L' looks like my firewall is wide open!

**Answer:** The problem here is that a bare `iptables -L` command produces totally useless output. Use `shorewall show` instead.

<div class="note">

The `shorewall show` command is a wrapper around `iptables -L -n -v`.

</div>

## (FAQ 51) How do I Open Ports in Shorewall?

**Answer:** No one who has installed Shorewall using one of the [Quick Start Guides](shorewall_quickstart_guide.md) should have to ask this question.

Regardless of which guide you used, all outbound communication is open by default. So you do not need to 'open ports' for output.

For input:

- If you installed using the Standalone Guide, then please [re-read this section](standalone.md#Open).

- If you installed using the Two-interface Guide, then please re-read these sections: [Port Forwarding (DNAT)](two-interface.md#DNAT), and [Other Connections](two-interface.md#Open)

- If you installed using the Three-interface Guide, then please re-read these sections: [Port Forwarding (DNAT)](three-interface.md#DNAT) and [Other Connections](three-interface.md#Open)

- If you installed using the [Shorewall Setup Guide](shorewall_setup_guide.md) then you had better read the guide again -- you clearly missed a lot.

Also please see the [Port Forwarding section of this FAQ](#PortForwarding).

## (FAQ 4) I just used an online port scanner to check my firewall and it shows some ports as “closed” rather than “blocked”. Why?

**Answer:** The default Shorewall setup invokes the **Drop** action prior to enforcing a DROP policy and the default policy to all zones from the Internet is DROP. The Drop action is defined in `/usr/share/shorewall/action.Drop` which in turn invokes the **Auth** macro (defined in `/usr/share/shorewall/macro.Auth`) specifying the **REJECT** action (i.e., **Auth(REJECT)**). This is necessary to prevent outgoing connection problems to services that use the “Auth” mechanism for identifying requesting users. That is the only service which the default setup rejects.

If you are seeing closed TCP ports other than 113 (auth) then either you have added rules to REJECT those ports or a router outside of your firewall is responding to connection requests on those ports.

If you would prefer to 'stealth' port 113, then:

- If you are running Shorewall 4.4.20 or earlier, copy /`usr/share/shorewall/action.Drop` to `/etc/shorewall/` and modify the invocation of Auth to **Auth(DROP)**.

- If you are running Shorewall 4.4.21 or later, in shorewall.conf, set DROP_DEFAULT="Drop(-,DROP)". See the [Action HOWTO](../concepts/Actions.md) to learn how that magic works.

### (FAQ 4a) I just ran an nmap UDP scan of my firewall and it showed 100s of ports as open!!!!

**Answer:** Take a deep breath and read the nmap manpage section about UDP scans. If nmap gets **nothing** back from your firewall then it reports the port as open. If you want to see which UDP ports are really open, temporarily change your net-\>all policy to REJECT, restart Shorewall and run the nmap UDP scan again.

### (FAQ 4b) I have a port that I can't close no matter how I change my rules.

I had a rule that allowed telnet from my local network to my firewall; I removed that rule and restarted Shorewall but my telnet session still works!!!

**Answer:** Rules only govern the establishment of new connections. Once a connection is established through the firewall it will be usable until disconnected (tcp) or until it times out (other protocols). If you stop telnet and try to establish a new session your firewall will block that attempt.

### (FAQ 4c) How do I use Shorewall with PortSentry?

[**Answer:** Here's a writeup](https://shorewall.org/pub/shorewall/contrib/PortsentryHOWTO.txt) describing a nice integration of Shorewall and PortSentry.

# Connection Problems

## Why are these packets being Dropped/Rejected? How do I decode Shorewall log messages?

Please see [FAQ 17](#faq17).

## (FAQ 5) I've installed Shorewall and now I can't ping through the firewall

**Answer:** For a complete description of Shorewall “ping” management, see [this page](../features/ping.md).

## (FAQ 15) My local systems can't see out to the net

**Answer:** Every time I read “systems can't see out to the net”, I wonder where the poster bought computers with eyes and what those computers will “see” when things are working properly :-). That aside, the most common causes of this problem are:

1.  The default gateway on each local system isn't set to the IP address of the local firewall interface. You can test this by:

    1.  At a root shell prompt, type 'shorewall clear'.

    2.  From a local system, attempt to ping the IP address of the Shorewall system's internet (external) interface. If that doesn't work, then the default gateway on the system from which you pinged is not set correctly.

    3.  Be sure to 'shorewall start' after the test.

2.  The entry for the local network in the `/etc/shorewall/masq` file is wrong or missing.

3.  The DNS settings on the local systems are wrong or the user is running a DNS server on the firewall and hasn't enabled UDP and TCP port 53 from the local net to the firewall or from the firewall to the Internet.

4.  Forwarding is not enabled (This is often the problem for Debian users). Enter this command:

        cat /proc/sys/net/ipv4/ip_forward

    If the value displayed is 0 (zero) then set **IP_FORWARDING=On** in `/etc/shorewall/shorewall.conf` and restart Shorewall.

## (FAQ 29) FTP Doesn't Work

**Answer:** See the [Shorewall and FTP page](../features/FTP.md).

## (FAQ 33) From clients behind the firewall, connections to some sites fail. Connections to the same sites from the firewall itself work fine. What's wrong?

**Answer:** Most likely, you need to set CLAMPMSS=Yes in `/etc/shorewall/shorewall.conf`.

## (FAQ 35) I have two Ethernet interfaces to my local network which I have bridged. When Shorewall is started, I'm unable to pass traffic through the bridge. I have defined the bridge interface (br0) as the local interface in `/etc/shorewall/interfaces`; the bridged Ethernet interfaces are not defined to Shorewall. How do I tell Shorewall to allow traffic through the bridge?

**Answer:** Add the `routeback` option to `br0` in `/etc/shorewall/interfaces`.

For more information on this type of configuration, see the [Shorewall Simple Bridge documentation](../features/SimpleBridge.md).

## (FAQ 64) I just upgraded my kernel to 2.6.20 (or later) and my bridge/firewall stopped working. What is wrong?

**Answer:** In kernel 2.6.20, the Netfilter physdev match feature was changed such that it is no longer capable of matching the output device of non-bridged traffic. You will see messages such as the following in your log:

    Apr 20 15:03:50 wookie kernel: [14736.560947] physdev match: using --physdev-out in the OUTPUT, FORWARD and POSTROUTING chains for
                                                                 non-bridged traffic is not supported anymore.

This kernel change, while necessary, means that Shorewall zones may no longer be defined in terms of bridge ports. See the [Shorewall-perl bridging documentation](../legacy/bridge-Shorewall-perl.md) for information about how to configure bridge/firewalls.

<div class="note">

Following the instructions in the new bridging documentation will not prevent the above message from being issued.

</div>

## (FAQ 85) Shorewall is rejecting connections from my local lan because it thinks they are coming from the 'net' zone.

I'm seeing this in my log:

    Aug 31 16:51:24 fw22 kernel: Shorewall:net2fw:DROP:IN=eth5 OUT= MAC=00:0c:29:74:9c:0c:08:00:20:b2:5f:db:08:00
                                           SRC=10.1.50.14 DST=10.1.50.7 LEN=57 TOS=0x00 PREC=0x00 TTL=255 ID=32302 DF
                                           PROTO=UDP SPT=53289 DPT=53 LEN=37

**Answer**: This occurs when the external interface and an internal interface are connected to the same switch or hub. See [this article](../legacy/FoolsFirewall.md) for details. The solution is to never connect more than one firewall interface to the same hub or switch (an obvious exception is that when you have a switch that supports VLAN tagging and the interfaces are associated with different VLANs).

# Logging

## (FAQ 91) I changed the shorewall.conf file in /etc/shorewall/ to spit out logs to /var/log/shorewall.log and it's not happening after I restart shorewall. LOGFILE=/var/log/shorewall.log \<-- that should be the correct line, right?

**Answer**: No, that is not correct. The LOGFILE setting tells Shorewall where to find the log; it does not determine where messages are written. See [the next FAQ](#faq6).

## (FAQ 6) Where are the log messages written and how do I change the destination?

**Answer:** NetFilter uses the kernel's equivalent of syslog (see “man syslog”) to log messages. It always uses the LOG_KERN (kern) facility (see “man openlog”) and you get to choose the log level (again, see “man syslog”) in your `policies` and `rules`. The destination for messages logged by syslog is controlled by `/etc/syslog.conf` (see “man syslog.conf”). When you have changed `/etc/syslog.conf`, be sure to restart syslogd (on a RedHat system, “service syslog restart”).

It is also possible to [set up Shorewall to log all of Netfilter's messages to a separate file](../features/shorewall_logging.md).

### (FAQ 6a) Are there any log parsers that work with Shorewall?

**Answer:** Here are several links that may be helpful:

              https://shorewall.org/pub/shorewall/parsefw/
              http://aaron.marasco.com/linux.html
              http://cert.uni-stuttgart.de/projects/fwlogwatch
              http://www.logwatch.org
            

I personally use [fwlogwatch](http://www.cert.uni-stuttgart.de.projects/fwlogwatch). It emails me a report each day from my various systems with each report summarizing the logged activity on the corresponding system; here's a sample:

>     fwlogwatch summary
>     Generated Tuesday March 02 08:14:37 PST 2010 by root.
>     362 (and 455 older than 86400 seconds) of 817 entries in the file "/var/log/ulog/syslogemu.log" are packet logs, 138 have unique characteristics.
>     First packet log entry: Mar 01 08:16:06, last: Mar 02 08:06:21.
>     All entries were logged by the same host: "gateway".
>     All entries have the same target: "-".
>     Only entries with a count of at least 5 are shown.
>
>     net-dmz DROP  eth2 36 packets from 61.158.162.9 to 206.124.146.177
>     net-fw DROP  eth0 21 packets from 89.163.162.13 to 76.104.233.98
>     net-fw DROP  eth0 19 packets from 61.184.101.46 to 76.104.233.98
>     net-fw DROP  eth0 12 packets from 81.157.214.103 to 76.104.233.98
>     net-fw DROP  eth0 11 packets from 174.37.159.222 to 76.104.233.98
>     net-fw DROP  eth0 10 packets from 221.195.73.86 to 76.104.233.98
>     net-dmz DROP  eth2 9 packets from 202.199.158.6 to 206.124.146.177
>     net-fw DROP  eth2 9 packets from 202.199.158.6 to 206.124.146.176
>     net-dmz DROP  eth2 9 packets from 202.199.158.6 to 206.124.146.178
>     net-fw DROP  eth0 6 packets from 221.192.199.35 to 76.104.233.98
>     net-fw DROP  eth2 5 packets from 61.158.162.9 to 206.124.146.177

Fwlogwatch contains a built-in web server that allows monitoring recent activity in summary fashion.

### (FAQ 6b) DROP messages on port 10619 are flooding the logs with their connect requests. Can I exclude these error messages for this port temporarily from logging in Shorewall?

**Answer:** Temporarily add the following rule:

    #ACTION         SOURCE          DEST            PROTO   DPORT

    ?SECTION ALL
    ?SECTION ESTABLISHED
    ?SECTION RELATED
    ?SECTION INVALID
    ?SECTION UNTRACKED
    ?SECTION NEW

    DROP            net             $FW             udp     10619

Alternatively, if you do not set BLACKLIST_LOGLEVEL you can blacklist the port. In `/etc/shorewall/blrules`:

    #ACTION         SOURCE          DEST            PROTO   DPORT

    DROP            net             $FW             udp     10619

### (FAQ 6d) Why is the MAC address in Shorewall log messages so long? I thought MAC addresses were only 6 bytes in length.

**Answer:** What is labeled as the MAC address in a Netfilter (Shorewall) log message is actually the Ethernet frame header. It contains:

- the destination MAC address (6 bytes)

- the source MAC address (6 bytes)

- the Ethernet frame type (2 bytes)

<!-- -->

    MAC=00:04:4c:dc:e2:28:00:b0:8e:cf:3c:4c:08:00

- Destination MAC address = 00:04:4c:dc:e2:28

- Source MAC address = 00:b0:8e:cf:3c:4c

- Ethernet Frame Type = 08:00 (IP Version 4)

## (FAQ 16) Shorewall is writing log messages all over my console making it unusable!

**Answer:**

Just to be clear, it is not Shorewall that is writing all over your console. Shorewall issues a single log message during each `start`, `restart`, `stop`, etc. It is rather your logging daemon that is writing messages to your console. Shorewall itself has no control over where a particular class of messages are written. See the [Shorewall logging documentation](../features/shorewall_logging.md).

The max log level to be sent to the console is available in /proc/sys/kernel/printk:

    teastep@ursa:~$ cat /proc/sys/kernel/printk
    6      6       1       7
    teastep@ursa:~$ 

The first number determines the maximum log level (syslog priority) sent to the console. Messages with priority **less than** this number are sent to the console. On the system shown in the example above, priorities 0-5 are sent to the console. Since Shorewall defaults to using 'info' (6), the Shorewall-generated Netfilter rule set will generate log messages that **will not appear on the console.**

The second number is the default log level for kernel printk() calls that do not specify a log level.

The third number specifies the minimum console log level while the fourth gives the default console log level.

If, on your system, the first number is 7 or greater, then the default Shorewall configurations will cause messages to be written to your console. The simplest solution is to add this to your `/etc/sysctl.conf` file:

    kernel.printk = 4 4 1 7

then

    sysctl -p /etc/sysctl.conf

### (FAQ 16a) cat /proc/sys/kernel/prink returns '4 4 1 7' and still I get dmesg filled up

**Answer**: While we would argue that 'dmesg filled up' is not necessarily a problem, the only way to eliminate that is to [set up Shorewall to log all of Netfilter's messages to a separate file](../features/shorewall_logging.md).

### (FAQ 16b) Why can't I see any Shorewall messages in /var/log/messages?

Some people who ask this question report that the only Shorewall messages that they see in `/var/log/messages` are 'started', 'restarted' and 'stopped' messages.

**Answer:** First of all, it is important to understand that Shorewall itself does not control where Netfilter log messages are written. The LOGFILE setting in `shorewall.conf` simply tells the `/sbin/shorewall[-lite]` program where to look for the log. Also, it is important to understand that a log level of "debug" will generally cause Netfilter messages to be written to fewer files in `/var/log` than a log level of "info". The log level does not control the number of log messages or the content of the messages.

The actual log file where Netfilter messages are written is not standardized and will vary by distribution and distribution version. But anytime you see no logging, it's time to look outside the Shorewall configuration for the cause. As an example, recent SUSE releases use syslog-ng by default and write Shorewall messages to `/var/log/firewall`.

Please see the [Shorewall logging documentation](../features/shorewall_logging.md) for further information.

### (FAQ 16c) Shorewall messages are flooding the output of 'dmesg'; how to I stop that?

**Answer**: Switch to using [ulogd](???).

### (FAQ 16d) I set LOGFILE=/var/log/shorewall but log messages are still going to /var/log/messages.

**Answer**: See the answer to [FAQ 16b](#faq16b) above.

## (FAQ 17) Why are these packets being Dropped/Rejected? How do I decode Shorewall log messages?

**Answer:** Logging of dropped/rejected packets occurs out of a number of chains (as indicated in the log message) in Shorewall:

**\<zone\>2all, \<zone\>-all, all2\<zone\>, all-\<zone\>, all2all or all-all**  
You have a `policy` that specifies a log level and this packet is being logged under that policy. If you intend to ACCEPT this traffic then you need a [rule](https://shorewall.org/manpages/shorewall-rules.html) to that effect.

Packets logged out of these chains may have a source and/or destination that is not in any defined zone (see the output of `shorewall[-lite] show zones`). Remember that zone membership involves both a firewall interface and an ip address.

**\<zone1\>2\<zone2\> or \<zone1-zone2\>**  
Either you have a [policy](https://shorewall.org/manpages/shorewall-policy.html) for *zone1* to *zone2* that specifies a log level and this packet is being logged under that policy or this packet matches a [rule](https://shorewall.org/manpages/shorewall-rules.html) that includes a log level.

**@\<zone1\>2\<zone2\> or @\<zone1\>-\<zone2\>**  
You have a policy for traffic from \<zone1\> to \<zone2\> that specifies TCP connection rate limiting (value in the LIMIT column). The logged packet exceeds that limit and was dropped. Note that these log messages themselves are severely rate-limited so that a syn-flood won't generate a secondary DOS because of excessive log message. These log messages were added in Shorewall 2.2.0 Beta 7.

**\<zone1\>2\<zone2\>~, \<zone1\>-\<zone2\>~ or ~blacklist\<nn\>**  
These are the result of entries in the [/etc/shorewall/blrules](https://shorewall.org/manpages/shorewall-blrules.html) file.

***interface*\_mac or *interface*\_rec**  
The packet is being logged under the **maclist** [interface option](https://shorewall.org/manpages/shorewall-interfaces.html).

**blacklist**  
The packet is being logged because the source IP is blacklisted in the `/etc/shorewall/blacklist` file.

**INPUT or FORWARD**  
The packet has a source IP address that isn't in any of your defined zones (“`shorewall[-lite] show zones`” and look at the printed zone definitions) or the chain is FORWARD and the destination IP isn't in any of your defined zones. If the chain is FORWARD and the IN and OUT interfaces are the same or they match the same wildcard entry in [/etc/shorewall/interfaces](https://shorewall.org/manpages/shorewall-interfaces.html), then you probably need the **routeback** option on that interface in`/etc/shorewall/interfaces`, you need the **routeback** option in the relevant entry in `/etc/shorewall/hosts or you've done something silly like define a default route out of an internal interface.`

With OPTIMIZE=1 in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html), such packets may also be logged out of a \<zone\>2all chain or the all2all chain.

**OUTPUT**  
The packet has a destination IP address that isn't in any of your defined zones(`shorewall[-lite] show zones` and look at the printed zone definitions).

With OPTIMIZE=1 in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html), such packets may also be logged out of the fw2all chain or the all2all chain.

**logflags**  
The packet is being logged because it failed the checks implemented by the **tcpflags** [interface option](https://shorewall.org/manpages/shorewall-interfaces.html).

**sfilter**  
On systems running Shorewall 4.4.20 or later, either the packet matched the `filter` [interface option](https://shorewall.org/manpages/shorewall-interfaces.html) or it is being routed out of the same interface on which it arrived and the interface does not have the `routeback` or `routefilter` [interface option](https://shorewall.org/manpages/shorewall-interfaces.html).

<!-- -->

    Jun 27 15:37:56 gateway kernel:
            Shorewall:all2all:REJECT:IN=eth2
              OUT=eth1
              SRC=192.168.2.2
              DST=192.168.1.3 LEN=67 TOS=0x00 PREC=0x00 TTL=63 ID=5805 DF PROTO=UDP
            SPT=1803 DPT=53 LEN=47

Let's look at the important parts of this message:

all2all:REJECT  
This packet was REJECTed out of the **all2all** chain -- the packet was rejected under the “all”-\>“all” REJECT policy ([all2all](#all2all) above).

IN=eth2  
the packet entered the firewall via eth2. If you see “IN=” with no interface name, the packet originated on the firewall itself.

OUT=eth1  
if accepted, the packet would be sent on eth1. If you see “OUT=” with no interface name, the packet would be processed by the firewall itself.

<div class="note">

When a DNAT rule is logged, there will never be an OUT= shown because the packet is being logged before it is routed. Also, DNAT logging will show the *original* destination IP address and destination port number. When a REDIRECT rule is logged, the message will also show the original destination IP address and port number.

</div>

SRC=192.168.2.2  
the packet was sent by 192.168.2.2

DST=192.168.1.3  
the packet is destined for 192.168.1.3

PROTO=UDP  
UDP Protocol

DPT=53  
The destination port is 53 (DNS)

In this case, 192.168.2.2 was in the “dmz” zone and 192.168.1.3 is in the “loc” zone. I was missing the rule:

    ACCEPT dmz loc udp 53

## (FAQ 21) I see these strange log entries occasionally; what are they?

    Nov 25 18:58:52 linux kernel:
          Shorewall:net2all:DROP:IN=eth1 OUT=
          MAC=00:60:1d:f0:a6:f9:00:60:1d:f6:35:50:08:00 SRC=206.124.146.179
          DST=192.0.2.3 LEN=56 TOS=0x00 PREC=0x00 TTL=110 ID=18558 PROTO=ICMP
          TYPE=3 CODE=3 [SRC=192.0.2.3 DST=172.16.1.10 LEN=128 TOS=0x00 PREC=0x00
          TTL=47 ID=0 DF PROTO=UDP SPT=53 DPT=2857 LEN=108 ]

192.0.2.3 is external on my firewall... 172.16.0.0/24 is my internal LAN

**Answer:** First of all, please note that the above is a very specific type of log message dealing with ICMP port unreachable packets (PROTO=ICMP TYPE=3 CODE=3). Do not read this answer and assume that all Shorewall log messages have something to do with ICMP (hint -- see [FAQ 17](#faq17)).

While most people associate the Internet Control Message Protocol (ICMP) with “ping”, ICMP is a key piece of IP. ICMP is used to report problems back to the sender of a packet; this is what is happening here. Unfortunately, where NAT is involved (including SNAT, DNAT and Masquerade), there are many broken implementations. That is what you are seeing with these messages. When Netfilter displays these messages, the part before the "\[" describes the ICMP packet and the part between the "\[" and "\]" describes the packet for which the ICMP is a response.

Here is my interpretation of what is happening -- to confirm this analysis, one would have to have packet sniffers placed a both ends of the connection.

Host 172.16.1.10 behind NAT gateway 206.124.146.179 sent a UDP DNS query to 192.0.2.3 and your DNS server tried to send a response (the response information is in the brackets -- note source port 53 which marks this as a DNS reply). When the response was returned to to 206.124.146.179, it rewrote the destination IP TO 172.16.1.10 and forwarded the packet to 172.16.1.10 who no longer had a connection on UDP port 2857. This causes a port unreachable (type 3, code 3) to be generated back to 192.0.2.3. As this packet is sent back through 206.124.146.179, that box correctly changes the source address in the packet to 206.124.146.179 but doesn't reset the DST IP in the original DNS response similarly. When the ICMP reaches your firewall (192.0.2.3), your firewall has no record of having sent a DNS reply to 172.16.1.10 so this ICMP doesn't appear to be related to anything that was sent. The final result is that the packet gets logged and dropped in the all2all chain.

## (FAQ 52) When I blacklist an IP address with "shorewall\[-lite\] drop www.xxx.yyy.zzz", why does my log still show REDIRECT and DNAT entries from that address?

I blacklisted the address 130.252.100.59 using `shorewall drop 130.252.100.59` but I am still seeing these log messages:

    Jan 30 15:38:34 server Shorewall:net_dnat:REDIRECT:IN=eth1 OUT= MAC=00:4f:4e:14:97:8e:00:01:5c:23:24:cc:08:00
                           SRC=130.252.100.59 DST=206.124.146.176 LEN=64 TOS=0x00 PREC=0x00 TTL=43 ID=42444 DF
                           PROTO=TCP SPT=2215 DPT=139 WINDOW=53760 RES=0x00 SYN URGP=0

**Answer:** Please refer to the [Shorewall Netfilter Documentation](../concepts/NetfilterOverview.md). Logging of REDIRECT and DNAT rules occurs in the nat table's PREROUTING chain where the original destination IP address is still available. Blacklisting occurs out of the filter table's INPUT and FORWARD chains which aren't traversed until later.

## (FAQ 81) logdrop and logreject don't log.

I love the ability to type 'shorewall logdrop ww.xx.yy.zz' and completely block a particular IP address. However, the log part doesn't happen. When I look in the logdrop chain, there is no LOG prefix.

**Answer**: You haven't set a value for BLACKLIST_LOGLEVEL in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5).

## (FAQ 36) My log is filling up with these BANDWIDTH messages!

    Dec 15 16:47:30 heath-desktop kernel: [17182740.184000] BANDWIDTH_IN:IN=eth1 OUT= MAC=ff:ff:ff:ff:ff:ff:00:01:5c:23:79:02:08:00
                                                            SRC=10.119.248.1 DST=255.255.255.255 LEN=328 TOS=0x00 PREC=0x00 TTL=64
                                                            ID=62081 PROTO=UDP SPT=67 DPT=68 LEN=308
    Dec 15 16:47:30 heath-desktop last message repeated 2 times
    Dec 15 16:47:30 heath-desktop kernel: [17182740.188000] BANDWIDTH_IN:IN=eth1 OUT= MAC=ff:ff:ff:ff:ff:ff:00:01:5c:23:79:02:08:00
                                                            SRC=10.112.70.1 DST=255.255.255.255 LEN=328 TOS=0x00 PREC=0x00 TTL=64
                                                            ID=62082 PROTO=UDP SPT=67 DPT=68 LEN=308
    Dec 15 16:47:30 heath-desktop last message repeated 2 times

**Answer**: The Webmin 'bandwidth' module adds commands to `/etc/shorewall/start` that creates rules to log every packet to/from/through the firewall. **DON'T START THE BANDWIDTH SERVICE IN WEBMIN!**

To correct this situation once it occurs, edit `/etc/shorewall/start` and insert 'return 0' prior to the BANDWIDTH rules.

# Routing

## (FAQ 32) My firewall has two connections to the Internet from two different ISPs. How do I set this up in Shorewall?

**Answer:** See [this article about Shorewall and Multiple ISPs](../features/MultiISP.md).

## (FAQ 49) When I start Shorewall, my routing table gets blown away. Why does Shorewall do that?

**Answer:** This is usually the consequence of a one-to-one nat configuration blunder:

1.  Specifying the primary IP address for an interface in the EXTERNAL column of `/etc/shorewall/nat` even though the documentation (and the comments in the file) warn you not to do that.

2.  Specifying ADD_IP_ALIASES=Yes and RETAIN_ALIASES=No in /etc/shorewall/shorewall.conf.

This combination causes Shorewall to delete the primary IP address from the network interface specified in the INTERFACE column which usually causes all routes out of that interface to be deleted. The solution is to **not specify the primary IP address of an interface in the EXTERNAL column**.

# Starting and Stopping

## (FAQ 94) After I start Shorewall, ps doesn't show any shorewall process running. What is the Shorewall daemon called?

**Answer:** Shorewall is not a daemon. It is a configuration tool that configures your kernel based on the contents of `/etc/shorewall/`. Once the `start` command completes, Shorewall has done its job and there are no Shorewall processes remaining in the system.

## (FAQ 7) When I stop Shorewall using “shorewall\[-lite\] stop”, I can't connect to anything. Why doesn't that command work?

**Answer:** The `stop` command places the firewall in a safe state; connections that are allowed are governed by the setting of ADMINISABSENTMINDED in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5) and the contents of [shorewall-stoppedrules](https://shorewall.org/manpages/shorewall-stoppedrules.html) (5). To totally open the firewall, use the `clear` command.

## (FAQ 9) Why can't Shorewall detect my interfaces properly at startup?

I just installed Shorewall and when I issue the `start` command, I see the following:

    Processing /etc/shorewall/params ...
    Processing /etc/shorewall/shorewall.conf ...
    Starting Shorewall...
    Loading Modules...
    Initializing...
    Determining Zones...
       Zones: net loc
    Validating interfaces file...
    Validating hosts file...
    Determining Hosts in Zones...
        Net Zone: eth0:0.0.0.0/0
        Local Zone: eth1:0.0.0.0/0
    Deleting user chains...
    Creating input Chains...
    ...

Why can't Shorewall detect my interfaces properly?

**Answer:** The above output is perfectly normal. The Net zone is defined as all hosts that are connected through `eth0` and the local zone is defined as all hosts connected through `eth1`. You can set the **routefilter** option on an internal interface if you wish to guard against 'Martians' (a Martian is a packet with a source IP address that is not routed out of the interface on which the packet was received). If you do that, it is a good idea to also set the **logmartians** option.

## (FAQ 22) I have some iptables commands that I want to run when Shorewall starts. Which file do I put them in?

**Answer:**You can place these commands in one of the [Shorewall Extension Scripts](shorewall_extension_scripts.md). Be sure that you look at the contents of the chain(s) that you will be modifying with your commands so that the commands will do what is intended. Many iptables commands published in HOWTOs and other instructional material use the -A command which adds the rules to the end of the chain. Most chains that Shorewall constructs end with an unconditional DROP, ACCEPT or REJECT rule and any rules that you add after that will be ignored. Check “man iptables” and look at the -I (--insert) command.

## (FAQ 43) I just installed the Shorewall RPM and Shorewall doesn't start at boot time.

**Answer:** When you install using the "rpm -U" command, Shorewall doesn't run your distribution's tool for configuring Shorewall startup. You will need to run that tool (insserv, chkconfig, run-level editor, …) to configure Shorewall to start in the the default run-levels of your firewall system.

## (FAQ 59) After I start Shorewall, there are lots of unused Netfilter modules loaded. How do I avoid that?

**Answer:** Copy `/usr/share/shorewall[-lite]/modules` to `/etc/shorewall/modules`and modify the copy to include only the modules that you need. An alternative is to set LOAD_HELPERS_ONLY=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5).

## (FAQ 68) I have a VM under an OpenVZ system. I can't get rid of the following message:

ERROR: Command "/sbin/iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT" failed.

**Answer:** See the [Shorewall OpenVZ article](../legacy/OpenVZ.md).

## (FAQ 73) When I stop Shorewall, the firewall is wide open. Isn't that a security risk?

It is important to understand that the scripts in `/etc/init.d` are generally provided by your distribution and not by the Shorewall developers. These scripts must meet the requirements of the distribution's packaging system which may conflict with the requirements of a tight firewall. So when you say "…when I stop Shorewall…" it is necessary to distinguish between the commands `/sbin/shorewall stop` and `/etc/init.d/shorewall stop`.

`/sbin/shorewall stop` places the firewall in a safe state, the details of which depend on your `/etc/shorewall/stoppedrules` file ([shorewall-stoppedrules](https://shorewall.org/manpages/shorewall-stoppedrules.html)(5)) and on the setting of ADMINISABSENTMINDED in `/etc/shorewall/shorewall.conf` ([shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5)).

`/etc/init.d/shorewall stop` may or may not do the same thing. In the case of Debian systems for example, that command actually executes `/sbin/shorewall clear` which opens the firewall completely. In other words, in the init script, `stop` reverses the effect of `start`.

Beginning with Shorewall 4.4, when the Shorewall tarballs are installed on a Debian (or derivative) system, the `/etc/init.d/shorewall` file is the same as would be installed by the .deb. The behavior of `/etc/init.d/shorewall stop` is controlled by the setting of SAFESTOP in `/etc/default/shorewall`. When set to 0 (the default), the firewall is cleared; when set to 1, the firewall is placed in a safe state.

## (FAQ 78) After restart and bootup of my Debian firewall, all traffic is blocked for hosts behind the firewall trying to connect out onto the net or through the vpn (although i can reach the internal firewall interface and obtain dumps etc). Once I issue 'shorewall clear' followed by 'shorewall start' it then works, despite the config not changing

**Answer:** Set IP_FORWARDING=On in `/etc/shorewall/shorewall.conf`.

## (FAQ 86) My distribution (Ubuntu) uses NetworkManager to manage my interfaces. I want to specify the upnpclient option for my interfaces which requires them to be up and configured when Shorewall starts but Shorewall is being started before NetworkManager.

Answer: I faced a similar problem which I solved as follows:

- Don't start Shorewall at boot time (Debian and Ubuntu users may simply set startup=0 in `/etc/default/shorewall`) or disable in systemd using `systemctl disable shorewall.service`.

- In `/etc/network/ip-up.d`, I added a `shorewall` script as follows:

      #!/bin/sh

      shorewall status > /dev/null 2>&1 || shorewall start # Start Shorewall if it isn't already running

  Be sure to secure the script for execute access.

Update:  
Beginning with Shorewall 4.4.10, there is a new [Shorewall Init Package](https://shorewall.org/manpages/shorewall-init.html) that is designed to handle this case.

## (FAQ 90) Shorewall starts fine but after several minutes, it stops. Why is it doing that?

**Answer:** Shorewall uses the presence of a chain named *shorewall* to indicate whether is started or stopped. That chain is created during execution of a successful **start**, **restart** or **restore** command and is removed during **stop** and **clear**. If **shorewall status** indicates that Shorewall is stopped, then something has deleted that chain. Look at the output of **shorewall status**; if it looks like this:

>     gateway:~# shorewall status
>     Shorewall-4.4.11 Status at gateway - Wed Jul 21 13:21:41 PDT 2010
>
>     Shorewall is stopped
>     State:Started (Tue Jul 20 16:01:49 PDT 2010)
>
>     gateway:~#

then it means that something outside of Shorewall has deleted the chain. This usually means that you were running another firewall package before you installed Shorewall and that other package has replaced Shorewall's Netfilter configuration with its own. You must remove (or at least disable) the other firewall package and restart Shorewall.

>     gateway:~# shorewall status
>     Shorewall-4.4.11 Status at gateway - Wed Jul 21 13:26:29 PDT 2010
>
>     Shorewall is stopped
>     State:Stopped (Wed Jul 21 13:26:26 PDT 2010)
>
>     gateway:~# 

then a **shorewall stop** command has been executed (if the State shown in the output is **Cleared**, then a **shorewall clear** command was executed). Most likely, you have installed and configured the *shorewall-init* package and a required interface has gone down.

## (FAQ 99) My /var/lib/shorewall-init.log shows that Shorewall is running at boot but after boot 'iptables -L' shows an empty configuration

**Answer**: This is caused by your failure to disable your distributions default iptables configuration tool when you installed Shorewall. Look for a service called 'iptables' that is being started after Shorewall and disable it.

## (FAQ 101) How can I speed up 'shorewall start' and 'shorewall restart' on my slow hardware?

**Answer**: There are several steps that you can take:

1.  If your kernel supports module autoloading (and distribution default kernels almost always do), then set LOAD_HELPERS_ONLY=Yes in shorewall.conf.

2.  Set AUTOMAKE=Yes in shorewall.conf. This will avoid the compilation phase in cases where the configuration has not changed since the last time that the configuration was compiled.

3.  Don't set optimization option 8. For example, if you currently set OPTIMIZE=31, then change that to OPTIMIZE=23. Optimization option 8 combines identical chains which can result in a smaller ruleset, but it slows down the compilation of large rulesets.

4.  Rather than `restart`, use `reload`. With the default setting of RESTART=restart, `restart` performs `stop` then `start`, while `reload` avoids the `stop` part.

5.  Use a capabilities file:

    - Run `shorewall show -f capabilties > /etc/shorewall/capabilities`

    - Rerun that command each time you install a new kernel or a new version of shorewall.

## (FAQ 103) Shorewall fails to start at boot but will start immediately after

**Answer:** This is usually associated with SELinux. [Here](https://lists.fedoraproject.org/pipermail/selinux/2010-June/012680.html) is an example.

## (FAQ 104) I see *kernel* messages in my log when I start or restart Shorewall or Shorewall6

Example:

    > Oct 1 13:04:39 deb kernel: [ 9570.619744] xt_addrtype: ipv6 does not support BROADCAST matching

**Answer:** These are harmless. Shorewall attempts to execute various commands to determine the capabiities of your system. If you system doesn't support a command, it will generally issue a kernel log message.

## (FAQ 106) Shorewall is not starting at boot on Debian with systemd

**Answer:** To enable start at boot, run `systemctl enable shorewall.service`

# Multiple ISPs

## (FAQ 57) I configured two ISPs in Shorewall but when I try to use the second one, it doesn't work.

**Answer:** The Multi-ISP Documentation strongly recommends that you use the **balance** option on all providers even if you want to manually specify which ISP to use. If you don't do that so that your main routing table only has one default route, then you must disable route filtering. Do not specify the **routefilter** option on the other interface(s) in `/etc/shorewall/interfaces` and disable any *IP Address Spoofing* protection that your distribution supplies.

## (FAQ 58) But if I specify 'balance' then won't Shorewall balance the traffic between the interfaces? I don't want that!

**Answer:** Suppose that you want all traffic to go out through ISP1 (mark 1) unless you specify otherwise. Then simply add these two rules as the first marking rules in your `/etc/shorewall/mangle` (was tcrules) file:

    #ACTION         SOURCE          DEST
    MARK(1):P       0.0.0.0/0
    MARK(1)         $FW
    other MARK rules

Now any traffic that isn't marked by one of your other MARK rules will have mark = 1 and will be sent via ISP1. That will work whether **balance** is specified or not!

# Using DNS Names

## (FAQ 79) Can I use DNS names in Shorewall configuration file entries in place of IP addresses?

**Answer**: [Yes](configuration_file_basics.md#dnsnames), but we advise strongly against it.

# Traffic Shaping

## (FAQ 67) I just configured Shorewall's builtin traffic shaping and now Shorewall fails to Start.

The error I receive is as follows:

    RTNETLINK answers: No such file or directory
    We have an error talking to the kernel
        ERROR: Command "tc filter add dev eth2 parent ffff: protocol ip prio 
                        50 u32 match ip src 0.0.0.0/0 police rate 500kbit burst 10k drop flowid 
                        :1" Failed

**Answer:** This message indicates that your kernel doesn't have 'traffic policing' support. If your kernel is modularized, you may be able to resolve the problem by loading the **act_police** kernel module. Other kernel modules that you will need include:cls_basic, cls_fw, cls_u32, sch_htb, sch_ingress, sch_sfq

## (FAQ 97) I enable Shorewall traffic shaping and now my upload rate is way below what I specified

**Answer**: This is likely due to TCP Segmentation Offload (TSO) and/or Generic Segmentation Offload (GSO) being enabled in the network adapter. To verify, install the ethtool package and use the -k command:

    root@gateway:~# ethtool -k eth1
    Offload parameters for eth1:
    rx-checksumming: on
    tx-checksumming: on
    scatter-gather: on
    tcp-segmentation-offload: on
    udp-fragmentation-offload: off
    generic-segmentation-offload: on
    generic-receive-offload: off
    large-receive-offload: off
    ntuple-filters: off
    receive-hashing: off
    root@gateway:~#

If that is the case, you can correct the problem by adjusting the \<minburst\> setting in /etc/shorewall/tcinterfaces (simple traffic shaping) or /etc/shorewall/tcdevices (complex traffic shaping). We suggest starting at 10-12kb and adjust as necessary. Example (simple traffic shaping):

    #INTERFACE      TYPE            IN_BANDWIDTH            OUT_BANDWIDTH
    eth0            External        50mbit:200kb            5.0mbit:100kb:200ms:100mbit:10kb

Alternatively, you can turn off TSO and GSO using this command in `/etc/shorewall/init`:

    ethtool -K ethN tso off gso off

## (FAQ 97a) I enable Shorewall traffic shaping and now my download rate is way below what I specified

**Answer**: This is likely due to Generic Receive Offload (GRO) being enabled in the network adapter. To verify, install the ethtool package and use the -k command:

    root@gateway:/etc/shorewall# ethtool -k eth1
    Offload parameters for eth1:
    rx-checksumming: on
    tx-checksumming: on
    scatter-gather: on
    tcp-segmentation-offload: on
    udp-fragmentation-offload: off
    generic-segmentation-offload: on
    generic-receive-offload: on
    large-receive-offload: off
    ntuple-filters: off
    receive-hashing: off
    root@gateway:/etc/shorewall# 

To work around the issue, use this command:

    ethtool -K ethN gro off

Beginning with Shorewall 4.4.25, another option is available in the form of a rate-estimated policing filter.

Example from /etc/shorewall/tcdevices:

    #INTERFACE      IN_BANDWITH             OUT_BANDWIDTH   OPTIONS
    1:COMB_IF       ~20mbit:250ms:4sec      ${UPLOAD}kbit   hfsc,linklayer=ethernet,overhead=0

To create a rate-estimated filter, precede the bandwidth with a tilde ("~"). The optional interval and decay_interval determine how often the rate is estimated and how many samples are retained for estimating. Please see <http://ace-host.stuart.id.au/russell/files/tc/doc/estimators.txt> for details.

# About Shorewall

## (FAQ 10) What Distributions does Shorewall work with?

**Answer:** Shorewall works with any GNU/Linux distribution that includes the [proper prerequisites](../concepts/shorewall_prerequisites.md).

## (FAQ 11) What Features does Shorewall have?

**Answer:** See the [Shorewall Feature List](../concepts/shorewall_features.md).

## (FAQ 12) Is there a GUI?

**Answer:** Yes! Shorewall support is available in Webmin. See <http://www.webmin.com>. But beware of the issue described in [FAQ 36](#faq36).

## (FAQ 13) Why do you call it “Shorewall”?

**Answer:** Shorewall is a concatenation of “ *Shore*line” ([the city where I live](http://www.cityofshoreline.com)) and “Fire*wall* ”. The full name of the product is actually “Shoreline Firewall” but “Shorewall” is much more commonly used.

## (FAQ 23) Why do you use such ugly fonts on your web site?

**Answer:** The Shorewall web site is almost font neutral (it doesn't explicitly specify fonts except on a few pages) so the fonts you see are largely the default fonts configured in your browser. If you don't like them then reconfigure your browser.

## (FAQ 25) How do I tell which version of Shorewall or Shorewall Lite I am running?

**Answer:** At the shell prompt, type:

    /sbin/shorewall[-lite] version -a     

### (FAQ 25a) It says 4.4.7.5; how do I know if it is Shorewall-shell or Shorewall-perl?

**Answer**: It is Shorewall-perl. Shorewall-shell is discontinued in Shorewall 4.4.

## (FAQ 31) Does Shorewall provide protection against....

IP Spoofing: Sending packets over the WAN interface using an internal LAP IP address as the source address?  
**Answer:** Yes.

Tear Drop: Sending packets that contain overlapping fragments?  
**Answer:** This is the responsibility of the IP stack, not the Netfilter-based firewall since fragment reassembly occurs before the stateful packet filter ever touches each packet.

Smurf and Fraggle: Sending packets that use the WAN or LAN broadcast address as the source address?  
**Answer:** Shorwall filters these packets under the nosmurfs interface option in [/etc/shorewall/interfaces](https://shorewall.org/manpages/shorewall-interfaces.html).

Land Attack: Sending packets that use the same address as the source and destination address?  
**Answer:** Yes, if the [routefilter interface option](https://shorewall.org/manpages/shorewall-interfaces.html) is selected.

DOS: - SYN Dos - ICMP Dos - Per-host Dos protection  
**Answer:** Yes.

## (FAQ 65) How do I accomplish failover with Shorewall?

**Answer:** [This article by Paul Gear](http://linuxman.wikispaces.com/Clustering+Shorewall) should help you get started.

# Alias IP Addresses/Virtual Interfaces

## (FAQ 18) Is there any way to use aliased ip addresses with Shorewall, and maintain separate rule sets for different IPs?

**Answer:** Yes. See [Shorewall and Aliased Interfaces](../legacy/Shorewall_and_Aliased_Interfaces.md).

## (FAQ 83) Is there no way to nest the firewall zone or create subzones? I've got a system with Linux-VServers, it's one interface (eth0) with multiple IPs

**Answer**: Beginning with Shorewall 4.4.11 Beta 2, you can [create vserver zones](../legacy/Vserver.md) that are nested within the firewall zone.

Prior to 4.4.11 Beta 2, there is no way to create sub-zones of the firewall zone. But you can use shell variables to make vservers easier to deal with.

`/etc/shorewall/params`:

    VS1=fw:192.168.2.12
    VS2=fw:192.168.2.13
    VS3=fw:192.168.2.14

`/etc/shorewall/rules`:

    #ACTION         SOURCE          DEST            PROTO   DPORT

    ?SECTION ALL
    ?SECTION ESTABLISHED
    ?SECTION RELATED
    ?SECTION INVALID
    ?SECTION UNTRACKED
    ?SECTION NEW

    ACCEPT          $VS1            net             tcp     25
    DNAT            net             $VS1            tcp     25
    etc...

# Shorewall Lite

## (FAQ 53) What is Shorewall Lite?

**Answer:** Shorewall Lite is a companion product to Shorewall and is designed to allow you to maintain all Shorewall configuration information on a single system within your network. See the [Compiled Firewall script documentation](../features/Shorewall-Lite.md) for details.

## (FAQ 54) If I want to use Shorewall Lite, do I also need to install Shorewall on the same system?

**Answer:** No. In fact, we recommend that you do **NOT** install Shorewall on systems where you wish to use Shorewall Lite. You must have Shorewall installed on at least one system within your network in order to use Shorewall Lite.

## (FAQ 55) How do I decide which product to use - Shorewall or Shorewall Lite?

**Answer:** If you plan to have only a single firewall system, then Shorewall is the logical choice. I also think that Shorewall is the appropriate choice for laptop systems that may need to have their firewall configuration changed while on the road. In the remaining cases, Shorewall Lite will work very well. At shorewall.net, the two laptop systems have the full Shorewall product installed as does my personal Linux desktop system. All other Linux systems that run a firewall use Shorewall Lite and have their configuration directories on my desktop system.

## (FAQ 60) What are the compatibility restrictions between Shorewall and Shorewall Lite

**Answer:** There are no compatibility constraints between Shorewall and Shorewall-lite.

# VOIP

## (FAQ 77) Shorewall is eating my Asterisk egress traffic!

Somehow, my firewall config is causing a one-way audio problem in Asterisk. If a person calls into the PBX, they cannot hear me speaking, but I can hear them. If I plug the Asterisk server directly into the router, bypassing the firewall, the problem goes away.

**Answer:** There are two things to try when VOIP problems are encountered. Both begin with executing two `rmmod` commands.

If your kernel version is 2.6.20 or earlier:

    rmmod ip_nat_sip
    rmmod ip_conntrack_sip

If your kernel version is 2.6.21 or later:

    rmmod nf_nat_sip
    rmmod nf_conntrack_sip

The first alternative seems to work for those running recent kernels (2.6.26 or later):

1.  Copy `/usr/share/shorewall/module`s to `/etc/shorewall` (`/usr/share/shorewall/helpers` if you have LOAD_HELPERS_ONLY in shorewall.conf).

2.  Edit the copy and change this line:

    > loadmodule nf_conntrack_sip

    to

    > loadmodule nf_conntrack_sip sip_direct_media=0

3.  `shorewall restart`

The second alternative is to not load the sip helpers:

- If you are running kernel 2.6.20 or earlier, then change the DONT_LOAD specification in your shorewall.conf to:

      DONT_LOAD=ip_nat_sip,ip_conntrack_sip

- If you are running kernel 2.6.21 or later, then change Then change the DONT_LOAD specification in your shorewall.conf to:

      DONT_LOAD=nf_nat_sip,nf_conntrack_sip

# IPv6

## (FAQ 80) Does Shorewall support IPV6?

Answer: [Shorewall IPv6 support](../features/IPv6Support.md) is currently available in Shorewall 4.2.4 and later.

### (FAQ 80a) Why does Shorewall lPv6 Support Require Kernel 2.6.24 or later?

**Answer:** Shorewall implements a stateful firewall which requires connection tracking be present in ip6tables and in the kernel. Linux kernels before 2.6.20 didn't support connection tracking for IPv6. So we could not even start to develop Shorewall IPv6 support until 2.6.20 and there were significant problems with the facility until at least kernel 2.6.23. When distributions began offering IPv6 connection tracking support, it was with kernel 2.6.25. So that is what we developed IPv6 support on and that's all that we initially tested on. Subsequently, we have tested Shorewall6 on Ubuntu Hardy with kernel 2.6.24. If you are running 2.6.20 or later, you can **try** to run Shorewall6 by hacking`/usr/share/shorewall/prog.footer6` and changing the kernel version test to check for your kernel version rather than 2.6.24 (20624). But after that, you are on your own.

    kernel=$(printf "%2d%02d%02d\n" $(echo $(uname -r) 2> /dev/null | sed 's/-.*//' | tr '.' ' ' ) | head -n1)
    if [ $kernel -lt 20624 ]; then
        error_message "ERROR: $PRODUCT requires Linux kernel 2.6.24 or later"
        status=2
    else 
     

Update: The above logic is found in `/usr/share/shorewall/prog.footer` in later Shorewall releases.

## (FAQ 40) I have an interface that gets its IPv6 configuration from radvd. When I start Shorewall6, I immediately loose my default route. Why?

**Answer**: You have configured forwarding on the interface which disables autoconfiguration of the interface. To retain autoconfiguration on the interface when Shorewall6 starts, specify **forwarding=0** in the OPTIONS column on the interface's entry in [shorewall6-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html) (5).

## (FAQ 96) I am starting to use ipv6, but on my ipv4 FW, when restarting Shorewall . it puts in ip6tables rules. How do i dissable that ?

Answer: This is a two-step process.

1.  Set DISABLE_IPV6=No in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5) and restart Shorewall.

2.  Execute these commands at a root shell prompt:

    - ip6tables -P INPUT ACCEPT

    - ip6tables -P OUTPUT ACCEPT

    - ip6tables -P FORWARD ACCEPT

You will probably want to soon install [Shorewall6](../features/IPv6Support.md) so that you have an IPv6 firewall as well as one for IPv4.

# Wifidog

## (FAQ 105) Can Shorewall work with Wifidog?

**Answer**: Yes, with a couple of restrictions:

1.  Wifidog must be started after Shorewall. If Shorewall is restarted/reloaded, then wifidog must be restarted.

2.  FORWARD_CLEAR_MARK must be set to `No` in shorewall.conf.

# Miscellaneous

## (FAQ 20) I have just set up a server. Do I have to change Shorewall to allow access to my server from the Internet?

**Answer:** Yes. Consult the [QuickStart guide](shorewall_quickstart_guide.md) that you used during your initial setup for information about how to set up rules for your server.

## (FAQ 24) How can I allow connections to, let's say, the ssh port only from specific IP Addresses on the Internet?

**Answer:** In the SOURCE column of the rule, follow “net” by a colon and a list of the host/subnet addresses as a comma-separated list.

    net:<ip1>,<ip2>,...

    ACCEPT net:192.0.2.16/28,192.0.2.44 fw tcp 22

## (FAQ 26) When I try to use any of the SYN options in nmap on or behind the firewall, I get “operation not permitted”. How can I use nmap with Shorewall?

**Answer:** Temporarily remove any **rejNotSyn**, **dropNotSyn**, **dropInvalid**, **NotSyn(...)** and **Invalid(...)** rules from `/etc/shorewall/rules` and restart Shorewall.

## (FAQ 27) I'm compiling a new kernel for my firewall. What should I look out for?

**Answer:** First take a look at the [Shorewall kernel configuration page](kernel.md). You probably also want to be sure that you have selected the “ **NAT of local connections (READ HELP)** ” on the Netfilter Configuration menu. Otherwise, DNAT rules with your firewall as the source zone won't work with your new kernel.

## (FAQ 28) How do I use Shorewall as a Bridging Firewall?

**Answer:** Shorewall Bridging Firewall support is available — [check here for details](../legacy/bridge-Shorewall-perl.md).

## (FAQ 39) How do I block connections to a particular domain name?

I tried this rule to block Google's Adsense that you'll find on everyone's site. Adsense is a Javascript that people add to their Web pages. So I entered the rule:

    #ACTION         SOURCE  DEST                                    PROTO
    REJECT          fw      net:pagead2.googlesyndication.com       all

However, this also sometimes restricts access to "google.com". Why is that? Using dig, I found these IPs for domain googlesyndication.com:

    216.239.37.99
    216.239.39.99

And this for google.com:

    216.239.37.99
    216.239.39.99
    216.239.57.99

So my guess is that you are not actually blocking the domain, but rather the IP being called. So how in the world do you block an actual domain name?

**Answer:** Packet filters like Netfilter base their decisions on the contents of the various protocol headers at the front of each packet. Stateful packet filters (of which Netfilter is an example) use a combination of header contents and state created when the packet filter processed earlier packets. Netfilter (and Shorewall's use of Netfilter) also consider the network interface(s) where each packet entered and/or where the packet will leave the firewall/router.

When you specify [a domain name in a Shorewall rule](configuration_file_basics.md#dnsnames), the iptables program resolves that name to one or more IP addresses and the actual Netfilter rules that are created are expressed in terms of those IP addresses. So the rule that you entered was equivalent to:

    #ACTION         SOURCE          DEST                    PROTO
    REJECT          $FW             net:216.239.37.99       all
    REJECT          $FW             net:216.239.39.99       all

Given that name-based multiple hosting is a common practice (another example: lists.shorewall.net and www1.shorewall.net are both hosted on the same system with a single IP address), it is not possible to filter connections to a particular name by examination of protocol headers alone. While some protocols such as [FTP](../features/FTP.md) require the firewall to examine and possibly modify packet payload, parsing the payload of individual packets doesn't always work because the application-level data stream can be split across packets in arbitrary ways. This is one of the weaknesses of the 'string match' Netfilter extension available in later Linux kernel releases. The only sure way to filter on packet content is to proxy the connections in question -- in the case of HTTP, this means running something like [Squid](../features/Shorewall_Squid_Usage.md). Proxying allows the proxy process to assemble complete application-level messages which can then be accurately parsed and decisions can be made based on the result.

## (FAQ 42) How can I tell which features my kernel and iptables support?

**Answer:** Use the `shorewall[-lite] show capabilities` command at a root prompt.

    gateway:~# shorewall show capabilities
    Shorewall has detected the following iptables/netfilter capabilities:
       NAT: Available
       Packet Mangling: Available
       Multi-port Match: Available
       Extended Multi-port Match: Available
       Connection Tracking Match: Available
       Extended Connection Tracking Match Support: Available
       Old Connection Tracking Match Syntax: Not available
       Packet Type Match: Available
       Policy Match: Available
       Physdev Match: Available
       Physdev-is-bridged Support: Available
       Packet length Match: Available
       IP range Match: Available
       Recent Match: Available
       Owner Match: Available
       Ipset Match: Available
       CONNMARK Target: Available
       Extended CONNMARK Target: Available
       Connmark Match: Available
       Extended Connmark Match: Available
       Raw Table: Available
       IPP2P Match: Available
       Old IPP2P Match Syntax: Not available
       CLASSIFY Target: Available
       Extended REJECT: Available
       Repeat match: Available
       MARK Target: Available
       Extended MARK Target: Available
       Mangle FORWARD Chain: Available
       Comments: Available
       Address Type Match: Available
       TCPMSS Match: Available
       Hashlimit Match: Available
       Old Hashlimit Match: Not available
       NFQUEUE Target: Available
       Realm Match: Available
       Helper Match: Available
       Connlimit Match: Available
       Time Match: Available
       Goto Support: Available
       LOGMARK Target: Available
       IPMARK Target: Available
       LOG Target: Available
       Persistent SNAT: Available
    gateway:~# 

## (FAQ 19) How do I open the firewall for all traffic to/from the LAN?

**Answer:** Add these two policies:

    #SOURCE         DEST            POLICY  LOGLEVEL        LIMIT   CONNLIMIT
    $FW             loc             ACCEPT
    loc             $FW             ACCEPT

You should also delete any ACCEPT rules from \$FW-\>loc and loc-\>\$FW since those rules are redundant with the above policies.

## (FAQ 88) Can I run Snort with Shorewall?

**Answer**: Yes. In *Network Intrusion Detection System (NIDS) mode*, Snort is libpcap based (like tcpdump) so it doesn't interfere with Shorewall. We have had reports that users have also been successful in using Snort in *inline* more with Shorewall, but no HOWTO exists at this time.

## (FAQ 89) How do I connect to the web server in my aDSL modem from my local LAN?

Answer: Here's what I did:

- My local network is 172.20.1.0/24, so I set the IP address in the modem to 172.20.1.2.

- The IP address of my firewall's interface to the LAN is 172.20.1.254. The logical name of the DSL interface is EXT_IF and my LAN interface is INT_IF.

  I added the following two configuration entries:

  `/etc/shorewall/masq:`

      #INTERFACE              SOURCE          ADDRESS

      ?COMMENT DSL Modem

      EXT_IF:172.20.1.2       0.0.0.0/0       172.20.1.254

  When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

      #ACTION                SOURCE          DEST                PROTO   PORT
      SNAT(172.20.1.254)     0.0.0.0/0       EXT_IF:192.168.1.2  tcp     www

  `/etc/shorewall/proxyarp`:

      #ADDRESS        INTERFACE       EXTERNAL        HAVEROUTE       PERSISTENT
      172.20.1.2  EXT_IF      INT_IF      no      yes

If you can't change the IP address of your modem and its current address isn't in your local network, then you need to change this slightly; assuming that the modem IP address is 192.168.1.1:

- Do not include an entry in `/etc/shorewall/proxyarp`.

- Add an IP address in 192.168.1.0/24 to your external interface using your configuration's network management tools. For Debian-based systems, that means adding this to the interface's stanza in `/etc/network/interfaces`:

          post-up /sbin/ip addr add 192.168.1.254/24 dev external-interface

- Your entry in `/etc/shorewall/masq` would then be:

      #INTERFACE              SOURCE          ADDRESS

      COMMENT DSL Modem

      EXT_IF:192.168.1.1      0.0.0.0/0       192.168.1.254

  When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

      #ACTION                SOURCE          DEST                PROTO   PORT
      SNAT(192.168.1.254)    0.0.0.0/0       EXT_IF:192.168.1.1  tcp     www

## (FAQ 93) I'm not able to use Shorewall to manage a bridge. I get the following error: ERROR: BRIDGING=Yes is not supported by Shorewall 4.4.13.3.

**Answer:** If you want to apply firewall rules to the traffic passing between bridge ports, see [https://shorewall.org/bridge-Shorewall-perl.html](../legacy/bridge-Shorewall-perl.md). If you simply want to allow all traffic between ports, then see [https://shorewall.org/SimpleBridge.html](../features/SimpleBridge.md).

## (FAQ 95) What is this \$FW that I see in the configuration files and documentation?

**Answer: FW** is a [shell variable](configuration_file_basics.md#Variables) that expands to the name that you gave to the firewall zone in [shorewall-zones](https://shorewall.org/manpages/shorewall-zones.html)(5). The default name for the firewall zone is **fw**:

    #ZONE           TYPE            OPTIONS

    fw              firewall

So, using the default or sample configurations, writing **\$FW** is the same as writing **fw**. If you give the firewall zone a different name, **gate** for example, then writing **\$FW** would be the same as writing **gate**.

    #ZONE           TYPE            OPTIONS

    gate            firewall

### Why was that done?

**Answer:** The firewall zone has special semantics, so having a way to refer to it in a configuration-independent way makes writing the documentation, examples, macros, etc. easier.

## (FAQ 98) How do I Unsubscribe from the Mailing List

**Answer**: There are two ways:

1.  On the web

    Go to <https://lists.sourceforge.net/lists/listinfo/shorewall-users>. At the bottom of the form is a section entitled "**Shorewall-users Subscribers**". At the bottom of that section find:

    > "To **unsubscribe** from Shorewall-users, get a password reminder, or change your subscription options **enter your subscription email address**:".

    Enter your email address in the box provided and click on the "**[Unsubscribe or edit options](???)**" button. That will take you to a second form.

    At the top of the second form is a box to **enter your password** -- enter it there then click the **Unsubscribe** button in the center of the form. You will be unsubscribed.

    If you **don't remember your password**, click on the **Remind** button at the bottom of the form and your password will be emailed to you.

2.  Via email using this link: [mailto:shorewall-users-request@lists.sourceforge.net?subject=unsubscribe](mailto:shorewall-users-request@lists.sourceforge.net?subject=unsubscribe). You will receive a confirmation email shortly; follow the instructions in that email.

## (FAQ 102) What is 'qt'? I see it in some of the older documentation.

**Answer**: 'qt' stands for 'quiet'; qt() is a shell function that accepts a command with arguments as parameters. It redirects both standard out and standard error to /dev/null. It is defined in the Shorewall-core shell library lib.common.
