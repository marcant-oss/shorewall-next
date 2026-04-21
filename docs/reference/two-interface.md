<div class="caution">

**This article applies to Shorewall 4.4 and later. If you are running a version of Shorewall earlier than Shorewall 4.4.0 then please see the documentation for that release.**

</div>

# Introduction

Setting up a Linux system as a firewall for a small network is a fairly straight-forward task if you understand the basics and follow the documentation.

This guide doesn't attempt to acquaint you with all of the features of Shorewall. It rather focuses on what is required to configure Shorewall in its most common configuration:

- Linux system used as a firewall/router for a small local network.
- **Single public IP address.** If you have more than one public IP address, this is not the guide you want -- see the [Shorewall Setup Guide](shorewall_setup_guide.md) instead.
- Internet connection through cable modem, DSL, ISDN, Frame Relay, dial-up ...

Here is a schematic of a typical installation:

<figure id="Figure1">
<img src="images/basics.png" />
<figcaption>Common two interface firewall configuration</figcaption>
</figure>

<div class="caution">

If you edit your configuration files on a Windows system, you must save them as Unix files if your editor supports that option or you must run them through `dos2unix` before trying to use them. Similarly, if you copy a configuration file from your Windows hard drive to a floppy disk, you must run `dos2unix` against the copy before using it with Shorewall.

- [Windows Version of `dos2unix`](http://www.sourceforge.net/projects/dos2unix)

- [Linux Version of `dos2unix`](http://www.megaloman.com/%7Ehany/software/hd2u/)

</div>

## System Requirements

Shorewall requires that you have the `iproute`/`iproute2` package installed (on RedHat, the package is called `iproute`). You can tell if this package is installed by the presence of an `ip` program on your firewall system. As `root`, you can use the `which` command to check for this program:

    [root@gateway root]# which ip
    /sbin/ip
    [root@gateway root]#

I recommend that you first read through the guide to familiarize yourself with what's involved then go back through it again making your configuration changes.

## Conventions

Points at which configuration changes are recommended are flagged with .

Configuration notes that are unique to Debian and it's derivatives are marked with .

# PPTP/ADSL

If you have an ADSL Modem and you use PPTP to communicate with a server in that modem, you must make the changes recommended in the PPTP/ADSL notes (PPTP documentation was not ported to shorewall-nft) in addition to those detailed below. ADSL with PPTP is most commonly found in Europe, notably in Austria.

# Shorewall Concepts

The configuration files for Shorewall are contained in the directory `/etc/shorewall` -- for simple setups, you will only need to deal with a few of these as described in this guide.

<div class="important">

After you have [installed Shorewall](Install.md), locate the two-interfaces samples:

1.  If you installed using an RPM, the samples will be in the Samples/two-interfaces/ subdirectory of the Shorewall documentation directory. If you don't know where the Shorewall documentation directory is, you can find the samples using this command:

        ~# rpm -ql shorewall | fgrep two-interfaces
        /usr/share/doc/packages/shorewall/Samples/two-interfaces
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/interfaces
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/snat
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/policy
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/rules
        /usr/share/doc/packages/shorewall/Samples/two-interfaces/zones
        ~#

    When running Shorewall 5.0.14 or later:

        ~# rpm -ql shorewall | fgrep three-interfaces
        /usr/share/doc/packages/shorewall/Samples/three-interfaces
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/interfaces
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/policy
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/rules
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/snat
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/zones
        ~#

2.  If you installed using the tarball, the samples are in the Samples/two-interfaces directory in the tarball.

3.  If you installed using a Shorewall 3.x .deb, the samples are in /usr/share/doc/shorewall/examples/two-interfaces. You must install the shorewall-doc package.

4.  If you installed using a Shorewall 4.x .deb, the samples are in **`/usr/share/doc/shorewall/examples/two-interfaces`.** You do not need the shorewall-doc package to have access to the samples.

    <div class="warning">

    **Note to Debian and Ubuntu Users**

    If you install using the .deb, you will find that your `/etc/shorewall` directory is practially empty. This is intentional. The released configuration file skeletons may be found on your system in the directory `/usr/share/doc/shorewall/default-config`. Simply copy the files you need from that directory to `/etc/shorewall` and modify the copies.

    </div>

</div>

As each file is introduced, I suggest that you look at the actual file on your system and that you look at the [man page](configuration_file_basics.md#Manpages) for that file. For example, to look at the man page for the `/etc/shorewall/zones` file, type `man shorewall-zones` at a shell prompt.

Note: Beginning with Shorewall 4.4.20.1, there are versions of the sample files that are annotated with the corresponding manpage contents. These files have names ending in '.annotated'. You might choose to look at those files instead.

Shorewall views the network where it is running as being composed of a set of zones. In the two-interface sample configuration, the following zone names are used:

    #ZONE   TYPE     OPTIONS                 IN_OPTIONS              OUT_OPTIONS
    fw      firewall
    net     ipv4
    loc     ipv4

Zones are defined in the [`/etc/shorewall/``zones`](https://shorewall.org/manpages/shorewall-zones.html) file.

Note that Shorewall recognizes the firewall system as its own zone - when the /etc/shorewall/zones file is processed, the name of the firewall zone is stored in the shell variable \$FW which may be used to refer to the firewall zone throughout the Shorewall configuration.

Rules about what traffic to allow and what traffic to deny are expressed in terms of zones.

- You express your default policy for connections from one zone to another zone in the [`/etc/shorewall/``policy`](https://shorewall.org/manpages/shorewall-policy.html) file.
- You define exceptions to those default policies in the [`/etc/shorewall/``rules`](https://shorewall.org/manpages/shorewall-rules.html) file.

For each connection request entering the firewall, the request is first checked against the `/etc/shorewall/``rules` file. If no rule in that file matches the connection request then the first policy in `/etc/shorewall/``policy` that matches the request is applied. If there is a [common action](shorewall_extension_scripts.md) defined for the policy in `/etc/shorewall/actions` or `/usr/share/shorewall/actions.std` then that action is performed before the action is applied. The purpose of the common action is two-fold:

- It silently drops or rejects harmless common traffic that would otherwise clutter up your log — Broadcasts for example.

- If ensures that traffic critical to correct operation is allowed through the firewall — ICMP *fragmentation-needed* for example.

The `/etc/shorewall/``policy` file included with the two-interface sample has the following policies:

    #SOURCE    DEST        POLICY      LOGLEVEL     LIMIT
    loc        net         ACCEPT
    net        all         DROP        info
    all        all         REJECT      info

In the two-interface sample, the line below is included but commented out. If you want your firewall system to have full access to servers on the Internet, uncomment that line.

    #SOURCE    DEST        POLICY      LOGLEVEL     LIMIT
    $FW        net         ACCEPT

The above policy will:

- Allow all connection requests from your local network to the Internet

- Drop (ignore) all connection requests from the Internet to your firewall or local network

- Optionally accept all connection requests from the firewall to the Internet (if you uncomment the additional policy)

- reject all other connection requests.

The word info in the LOG LEVEL column for the DROP and REJECT policies indicates that packets dropped or rejected under those policies should be [logged at that level](../features/shorewall_logging.md).

It is important to note that Shorewall policies (and rules) refer to **connections** and not packet flow. With the policies defined in the `/etc/shorewall/policy` file shown above, connections are allowed from the *loc* zone to the *net* zone even though connections are not allowed from the *loc* zone to the firewall itself.

Some people want to consider their firewall to be part of their local network from a security perspective. If you want to do this, add these two policies:

    #SOURCE    DEST        POLICY      LOGLEVEL     LIMIT
    loc        $FW         ACCEPT
    $FW        loc         ACCEPT

At this point, edit your `/etc/shorewall/``policy` and make any changes that you wish.

# Network Interfaces

![](images/basics.png)

The firewall has two network interfaces. Where Internet connectivity is through a cable or DSL “Modem”, the *External Interface* will be the Ethernet adapter that is connected to that “Modem” (e.g., `eth0`) unless you connect via *Point-to-Point Protocol* over Ethernet (PPPoE) or *Point-to-Point Tunneling Protocol* (PPTP) in which case the External Interface will be a `ppp` interface (e.g., `ppp0`). If you connect via a regular modem, your External Interface will also be `ppp0`. If you connect via ISDN, your external interface will be `ippp0`.

<div class="caution">

Be sure you know which interface is your external interface. Many hours have been spent floundering by users who have configured the wrong interface. If you are unsure, then as root type `ip route ls` at the command line. The device listed in the last (default) route should be your external interface.

Example:

    root@lists:~# ip route ls
    192.168.1.1 dev eth0  scope link 
    192.168.2.2 dev tun0  proto kernel  scope link  src 192.168.2.1 
    192.168.3.0/24 dev br0  proto kernel  scope link  src 192.168.3.254 
    10.13.10.0/24 dev tun1  scope link 
    192.168.2.0/24 via 192.168.2.2 dev tun0 
    192.168.1.0/24 dev br0  proto kernel  scope link  src 192.168.1.254 
    206.124.146.0/24 dev eth0  proto kernel  scope link  src 206.124.146.176 
    10.10.10.0/24 dev tun1  scope link 
    default via 206.124.146.254 dev eth0 
    root@lists:~# 

In that example, `eth0` is the external interface.

</div>

I**f your external interface is `ppp0` or `ippp0` then you will want to set `CLAMPMSS=yes` in `/etc/shorewall/``shorewall.conf`**.

Your *Internal Interface* will be an Ethernet adapter (`eth1` or `eth0`) and will be connected to a hub or switch. Your other computers will be connected to the same hub/switch (note: If you have only a single internal system, you can connect the firewall directly to the computer using a cross-over cable).

<div class="warning">

**Do not connect the internal and external interface to the same hub or switch except for testing**.You can test using this kind of configuration if you specify the **arp_filter** option or the **arp_ignore** option in `/etc/shorewall/``interfaces` for all interfaces connected to the common hub/switch. **Using such a setup with a production firewall is strongly recommended against**.

</div>

<div class="warning">

**Do not configure a default route on your internal interface.** Your firewall should have exactly one default route via your ISP's Router.

</div>

The Shorewall two-interface sample configuration assumes that the external interface is `eth0` and the internal interface is `eth1`. If your configuration is different, you will have to modify the sample `/etc/shorewall/``interfaces` file accordingly. While you are there, you may wish to review the list of options that are specified for the interfaces. Some hints:

<div class="tip">

If your external interface is `ppp0` or `ippp0` or if you have a static IP address, you can remove `dhcp` from the option list.

</div>

<div class="tip">

If your internal interface is a bridge create using the `brctl` utility then **you must add the `routeback` option to the option list.**

</div>

Prior to Shorewall 5.1.9, you will also need to modify the snat and stopped rules file, replacing eth1 with the name of your internal interface.

# IP Addresses

Before going further, we should say a few words about Internet Protocol (IP) addresses. Normally, your ISP will assign you a single Public IP address. This address may be assigned via the Dynamic Host Configuration Protocol (DHCP) or as part of establishing your connection when you dial in (standard modem) or establish your PPP connection. In rare cases, your ISP may assign you a static IP address; that means that you configure your firewall's external interface to use that address permanently. However your external address is assigned, it will be shared by all of your systems when you access the Internet. You will have to assign your own addresses in your internal network (the Internal Interface on your firewall plus your other computers). **RFC 1918** reserves several *Private* IP address ranges for this purpose:

    10.0.0.0    - 10.255.255.255
    172.16.0.0  - 172.31.255.255
    192.168.0.0 - 192.168.255.255

You will want to assign your addresses from the same sub-network (subnet). For our purposes, we can consider a subnet to consists of a range of addresses `x.y.z.0 - x.y.z.255`. Such a subnet will have a Subnet Mask of `255.255.255.0`. The address `x.y.z.0` is reserved as the *Subnet Address* and `x.y.z.255` is reserved as the *Subnet Broadcast Address*. In Shorewall, a subnet is described using [Classless InterDomain Routing (CIDR) notation](shorewall_setup_guide.md#Subnets) with consists of the subnet address followed by `/24`. The “24” refers to the number of consecutive leading “1” bits from the left of the subnet mask.

|                        |                               |
|------------------------|-------------------------------|
| **Range:**             | `10.10.10.0` - `10.10.10.255` |
| **Subnet Address:**    | `10.10.10.0`                  |
| **Broadcast Address:** | `10.10.10.255`                |
| **CIDR Notation:**     | `10.10.10.0/24`               |

It is conventional to assign the internal interface either the first usable address in the subnet (`10.10.10.1` in the above example) or the last usable address (`10.10.10.254`).

One of the purposes of subnetting is to allow all computers in the subnet to understand which other computers can be communicated with directly. To communicate with systems outside of the subnetwork, systems send packets through a gateway (router).

Your local computers (computer 1 and computer 2 in the above diagram) should be configured with their default gateway to be the IP address of the firewall's internal interface.

The foregoing short discussion barely scratches the surface regarding subnetting and routing. If you are interested in learning more about IP addressing and routing, I highly recommend “IP Fundamentals: What Everyone Needs to Know about Addressing & Routing”, Thomas A. Maufer, Prentice-Hall, 1999, ISBN 0-13-975483-0 ([link](http://www.phptr.com/browse/product.asp?product_id={58D4F6D4-54C5-48BA-8EDD-86EBD7A42AF6})).

The remainder of this guide will assume that you have configured your network as shown here:

![](images/basics1.png)

The default gateway for computer's 1 & 2 would be `10.10.10.254`.

<div class="warning">

Your ISP might assign your external interface an **RFC 1918** address. If that address is in the `10.10.10.0/24` subnet then **you will need to select a DIFFERENT RFC 1918 subnet for your local network.**

</div>

# IP Masquerading (SNAT)

The addresses reserved by RFC 1918 are sometimes referred to as non-routable because the Internet backbone routers don't forward packets which have an RFC-1918 destination address. When one of your local systems (let's assume computer 1 in the [above diagram](#Diagram)) sends a connection request to an Internet host, the firewall must perform *Network Address Translation* (NAT). The firewall rewrites the source address in the packet to be the address of the firewall's external interface; in other words, the firewall makes it appear to the destination Internet host as if the firewall itself is initiating the connection. This is necessary so that the destination host will be able to route return packets back to the firewall (remember that packets whose destination address is reserved by RFC 1918 can't be routed across the Internet so the remote host can't address its response to computer 1). When the firewall receives a return packet, it rewrites the destination address back to `10.10.10.1` and forwards the packet on to computer 1.

On Linux systems, the above process is often referred to as *IP Masquerading* but you will also see the term *Source Network Address Translation* (SNAT) used. Shorewall follows the convention used with Netfilter:

- *Masquerade* describes the case where you let your firewall system automatically detect the external interface address.

- *SNAT* refers to the case when you explicitly specify the source address that you want outbound packets from your local network to use.

In Shorewall, both *Masquerading* and *SNAT* are configured with entries in the [`/etc/shorewall/``masq`](https://shorewall.org/manpages/shorewall-masq.html) file (`/etc/shorewall/snat` when running Shorewall 5.0.14 or later). You will normally use Masquerading if your external IP is dynamic and SNAT if the IP is static.

If your external firewall interface is `eth0`, you do not need to modify the file provided with [the sample](#Concepts). Otherwise, edit `/etc/shorewall/``masq` or `/etc/shorewall/snat` and change it to match your configuration.

If your external IP is static then, if you are running Shorewall 5.0.13 or earlier, you can enter our static IP in the third column in the `/etc/shorewall/``masq` entry if you like although your firewall will work fine if you leave that column empty (Masquerade). Entering your static IP in column 3 (SNAT) makes the processing of outgoing packets a little more efficient.

When running Shorewall 5.0.14 or later, the rule in /etc/shorewall/snat must be change from a MASQUERADE rule to an SNAT rule.

    #ACTION                      SOURCE                DEST         PROTO      PORT
    SNAT(static-ip)              ...

I**f you are using the Debian package, please check your `shorewall.conf` file to ensure that the following is set correctly; if it is not, change it appropriately:**

- `IP_FORWARDING=On`

# Logging

Shorewall does not maintain a log itself but rather relies on your [system's logging configuration](../features/shorewall_logging.md). The following [commands](https://shorewall.org/manpages/shorewall.html) rely on knowing where Netfilter messages are logged:

- `shorewall show log` (Displays the last 20 netfilter log messages)

- `shorewall logwatch` (Polls the log at a settable interval

- `shorewall dump` (Produces an extensive report for inclusion in Shorewall problem reports)

It is important that these commands work properly because when you encounter connection problems when Shorewall is running, the first thing that you should do is to look at the Netfilter log; with the help of [Shorewall FAQ 17](FAQ.md#faq17), you can usually resolve the problem quickly.

The Netfilter log location is distribution-dependent:

- Debian and its derivatives log Netfilter messages to `/var/log/kern.log`.

- Recent SuSE/OpenSuSE releases come preconfigured with syslog-ng and log netfilter messages to `/var/log/firewall`.

- For other distributions, Netfilter messages are most commonly logged to `/var/log/messages`.

If you are running a distribution that logs netfilter messages to a log other than `/var/log/messages`, then modify the LOGFILE setting in `/etc/shorewall/shorewall.conf` to specify the name of your log.

<div class="important">

The LOGFILE setting does not control where the Netfilter log is maintained -- it simply tells the /sbin/`shorewall` utility where to find the log.

</div>

# Kernel Module Loading

Beginning in Shorewall 4.4.7, `/etc/shorewall/shorewall.conf` contains a LOAD_HELPERS_ONLY option which is set to `Yes` in the samples. This causes Shorewall to attempt to load the modules listed in `/usr/share/shorewall/helpers`. In addition, it sets **sip_direct_media=0** when loading the nf_conntrack_sip module. That setting is somewhat less secure than **sip_direct_media=1**, but it generally makes VOIP through the firewall work much better.

The modules in `/usr/share/shorewall/helpers` are those that are not autoloaded. If your kernel does not support module autoloading and you want Shorewall to attempt to load all netfilter modules that it might require, then set LOAD_HELPERS_ONLY=No. That will cause Shorewall to try to load the modules listed in `/usr/share/shorewall/modules`. That file does not set **sip_direct_media=0**.

If you need to modify either `/usr/share/shorewall/helpers` or `/usr/share/shorewall/modules` then copy the file to `/etc/shorewall` and modify the copy.

Modify the setting of LOAD_HELPER_ONLY as necessary.

<div class="important">

In Shorewall 5.2.3, the LOAD_HELPERS_ONLY option was removed, and the behavior is the same as if LOAD_HELPERS_ONLY=Yes was specified.

</div>

# Port Forwarding (DNAT)

One of your goals may be to run one or more servers on your local computers. Because these computers have RFC-1918 addresses, it is not possible for clients on the Internet to connect directly to them. It is rather necessary for those clients to address their connection requests to the firewall who rewrites the destination address to the address of your server and forwards the packet to that server. When your server responds, the firewall automatically performs [SNAT](#SNAT) to rewrite the source address in the response.

The above process is called *Port Forwarding* or *Destination Network Address Translation* (DNAT). You configure port forwarding using DNAT rules in the `/etc/shorewall/``rules` file.

For forwarding connections from the *net* zone to a server in the *loc* zone, the general form of a simple port forwarding rule in `/etc/shorewall/``rules` is:

    #ACTION   SOURCE    DEST                                          PROTO      DPORT
    DNAT      net       loc:<server local ip address>[:<server port>] <protocol> <port>

<div class="important">

**If you want to forward traffic from the *loc* zone to a server in the *loc* zone, see [Shorewall FAQ 2](FAQ.md#faq2).**

</div>

<div class="important">

Be sure to add your rules after the line that reads **SECTION NEW.**

</div>

<div class="important">

The server must have a static IP address. If you assign IP addresses to your local system using DHCP, you need to configure your DHCP server to always assign the same IP address to systems that are the target of a DNAT rule.

</div>

Shorewall has [macros](../concepts/Macros.md) for many popular applications. Look at the output of `shorewall show macros` to see what is available in your release. Macros simplify creating DNAT rules by supplying the protocol and port(s) as shown in the following examples.

You run a Web Server on computer 2 in [the above diagram](#Diagram) and you want to forward incoming TCP port 80 to that system:

    #ACTION   SOURCE    DEST             PROTO     DPORT
    Web(DNAT) net       loc:10.10.10.2

You run an FTP Server on [computer 1](#Diagram) so you want to forward incoming TCP port 21 to that system:

    #ACTION    SOURCE    DEST            PROTO     DPORT
    FTP(DNAT)  net       loc:10.10.10.1

For FTP, you will also need to have FTP connection tracking and NAT support in your kernel. For vendor-supplied kernels, this means that the `ip_conntrack_ftp` and `ip_nat_ftp` modules (`nf_conntrack_ftp` and `nf_nat_ftp` in later 2.6 kernels) must be loaded. Shorewall will automatically load these modules if they are available and located in the standard place under `/lib/modules/<kernel version>/kernel/net/ipv4/netfilter`. See the [Shorewall FTP documentation](../features/FTP.md) for more information.

A couple of important points to keep in mind:

- The Shorewall-provided macros assume that the service is using its standard port and will not work with a service listening on a non-standard port.

- You must test the above rule from a client outside of your local network (i.e., don't test from a browser running on computers 1 or 2 or on the firewall). If you want to be able to access your web server and/or FTP server from inside your firewall using the IP address of your external interface, see [Shorewall FAQ \#2](FAQ.md#faq2).

- Many ISPs block incoming connection requests to port 80. If you have problems connecting to your web server, try the following rule and try connecting to port 5000.

      #ACTION    SOURCE    DEST               PROTO     DPORT
      DNAT       net       loc:10.10.10.2:80  tcp       5000

At this point, modify `/etc/shorewall/``rules` to add any DNAT rules that you require.

<div class="important">

When testing DNAT rules like those shown above, you must test from a client OUTSIDE YOUR FIREWALL (in the 'net' zone). You cannot test these rules from inside the firewall!

For DNAT troubleshooting tips, [see FAQs 1a and 1b](FAQ.md#faq1a).

</div>

For information about DNAT when there are multiple external IP addresses, see the [Shorewall Aliased Interface documentation](../legacy/Shorewall_and_Aliased_Interfaces.md) and the [Shorewall Setup Guide](shorewall_setup_guide.md#dnat).

# Domain Name Server (DNS)

Normally, when you connect to your ISP, as part of getting an IP address your firewall's *Domain Name Service* (DNS) resolver will be automatically configured (e.g., the `/etc/``resolv.conf` file will be written). Alternatively, your ISP may have given you the IP address of a pair of DNS name servers for you to manually configure as your primary and secondary name servers. Regardless of how DNS gets configured on your firewall, it is your responsibility to configure the resolver in your internal systems. You can take one of two approaches:

- You can configure your internal systems to use your ISP's name servers. If your ISP gave you the addresses of their servers or if those addresses are available on their web site, you can configure your internal systems to use those addresses. If that information isn't available, look in /etc/resolv.conf on your firewall system -- the name servers are given in "nameserver" records in that file.
- <span id="cachingdns"></span> You can configure a *Caching Name Server* on your firewall. Red Hat has an RPM for a caching name server (the RPM also requires the `bind`RPM) and for Bering users, there is `dnscache.lrp`. If you take this approach, you configure your internal systems to use the firewall itself as their primary (and only) name server. You use the internal IP address of the firewall (`10.10.10.254` in the example above) for the name server address. To allow your local systems to talk to your caching name server, you must open port 53 (both UDP and TCP) from the local network to the firewall; you do that by adding the following rules in `/etc/shorewall/``rules`.
      #ACTION    SOURCE    DEST               PROTO     DPORT
      DNS(ACCEPT)loc       $FW

# Other Connections

The two-interface sample includes the following rules:

    #ACTION     SOURCE    DEST               PROTO     DPORT
    DNS(ACCEPT) $FW       net

This rule allows DNS access from your firewall and may be removed if you uncommented the line in `/etc/shorewall/``policy` allowing all connections from the firewall to the Internet.

In the rule shown above, “DNS”(ACCEPT)is an example of a *macro invocation*. Shorewall includes a number of macros (command **shorewall show macros**) and [you can add your own](../concepts/Macros.md).

You don't have to use defined macros when coding a rule in `/etc/shorewall/rules`; Shorewall will start slightly faster if you code your rules directly rather than using macros. The the rule shown above could also have been coded as follows:

    #ACTION    SOURCE    DEST               PROTO     DPORT
    ACCEPT     $FW       net                udp       53
    ACCEPT     $FW       net                tcp       53

In cases where Shorewall doesn't include a defined macro to meet your needs, you can either define the macro yourself or you can simply code the appropriate rules directly.

The sample also includes:

    #ACTION      SOURCE    DEST               PROTO     DPORT
    SSH(ACCEPT)  loc       $FW  

That rule allows you to run an SSH server on your firewall and connect to that server from your local systems.

If you wish to enable other connections from your firewall to other systems, the general format using a macro is:

    #ACTION         SOURCE    DEST               PROTO      DPORT
    <macro>(ACCEPT) $FW       <destination zone>

The general format when not using defined macros is:

    #ACTION    SOURCE    DEST               PROTO      DPORT
    ACCEPT     $FW       <destination zone> <protocol> <port>

You want to run a Web Server on your firewall system:

    #ACTION     SOURCE    DEST               PROTO     DPORT
    Web(ACCEPT) net       $FW
    Web(ACCEPT) loc       $FW       

Those two rules would of course be in addition to the rules listed above under “[You can configure a Caching Name Server on your firewall](#cachingdns)”.

If you don't know what port and protocol a particular application uses, look [here](../features/ports.md).

<div class="important">

I don't recommend enabling `telnet` to/from the Internet because it uses clear text (even for login!). If you want shell access to your firewall from the Internet, use SSH:

    #ACTION      SOURCE    DEST               PROTO     DPORT
    SSH(ACCEPT)  net       $FW

</div>

Bering users will want to add the following two rules to be compatible with Jacques's Shorewall configuration.

    #ACTION    SOURCE    DEST    PROTO     DPORT
    ACCEPT     loc       $FW     udp       53          #Allow DNS Cache to work
    ACCEPT     loc       $FW     tcp       80          #Allow Weblet to work

Now edit your `/etc/shorewall/``rules` file to add or delete other connections as required.

# Some Things to Keep in Mind

- **You cannot test your firewall from the inside**. Just because you send requests to your firewall external IP address does not mean that the request will be associated with the external interface or the “net” zone. Any traffic that you generate from the local network will be associated with your local interface and will be treated as loc-\>fw traffic.

- **IP addresses are properties of systems, not of interfaces**. It is a mistake to believe that your firewall is able to forward packets just because you can ping the IP address of all of the firewall's interfaces from the local network. The only conclusion you can draw from such pinging success is that the link between the local system and the firewall works and that you probably have the local system's default gateway set correctly.

- **All IP addresses configured on firewall interfaces are in the \$FW (fw) zone**. If 192.168.1.254 is the IP address of your internal interface then you can write “**\$FW:192.168.1.254**” in a rule but you may not write “**loc:192.168.1.254**”. Similarly, it is nonsensical to add 192.168.1.254 to the **loc** zone using an entry in `/etc/shorewall/hosts`.

- **Reply packets do NOT automatically follow the reverse path of the one taken by the original request**. All packets are routed according to the routing table of the host at each step of the way. This issue commonly comes up when people install a Shorewall firewall parallel to an existing gateway and try to use DNAT through Shorewall without changing the default gateway of the system receiving the forwarded requests. Requests come in through the Shorewall firewall where the destination IP address gets rewritten but replies go out unmodified through the old gateway.

- **Shorewall itself has no notion of inside or outside**. These concepts are embodied in how Shorewall is configured.

# Starting and Stopping Your Firewall

The [installation procedure](Install.md) configures your system to start Shorewall at system boot but startup is disabled so that your system won't try to start Shorewall before configuration is complete. Once you have completed configuration of your firewall, you must edit /etc/shorewall/shorewall.conf and set STARTUP_ENABLED=Yes.

<div class="important">

Users of the .deb package must edit `/etc/default/``shorewall` and set `startup=1`.

</div>

While you are editing `shorewall.conf`, it is a good idea to check the value of the SUBSYSLOCK option. You can find a description of this option by typing 'man shorewall.conf' at a shell prompt and searching for SUBSYSLOCK.

The firewall is started using the “`shorewall start`” command and stopped using “`shorewall stop`”. When the firewall is stopped, routing is enabled on those hosts that have an entry in `/etc/shorewall/``routestopped` (Shorewall 4.5.7 and earlier) or in`/etc/shorewall/stoppedrules`. A running firewall may be restarted using the “`shorewall reload`” command. If you want to totally remove any trace of Shorewall from your Netfilter configuration, use “`shorewall clear`”.

The two-interface sample assumes that you want to enable routing to/from `eth1` (the local network) when Shorewall is stopped. If your local network isn't connected to `eth1` or if you wish to enable access to/from other hosts, change `/etc/shorewall/``routestopped` accordingly.

<div class="warning">

If you are connected to your firewall from the Internet, do not issue a “`shorewall stop`” command unless you have either:

1.  Used ADMINISABSENTMINDED=Yes in `/etc/shorewall/shorewall.conf`; or

2.  added an entry for the IP address that you are connected from to `/etc/shorewall/``routestopped`.

Also, I don't recommend using “`shorewall reload`”; it is better to create an alternate configuration and test it using the “`shorewall try`” command.

</div>

The firewall will start after your network interfaces have been brought up. This leaves a small window between the time that the network interfaces are working and when the firewall is controlling connections through those interfaces. If this is a concern, you can close that window by installing the Shorewall Init Package (shorewall-init documentation was not ported to shorewall-nft).

# If it Doesn't Work

- Re-check each of the items flagged with a red arrow above.

- Check your [log](../features/shorewall_logging.md).

- Check the [Troubleshooting Guide](troubleshoot.md).

- Check the [FAQ](FAQ.md).

# Disabling your existing Firewall

Before starting Shorewall for the first time, it's a good idea to stop your existing firewall. On older Redhat/CentOS/Fedora:

    service iptables stop

On recent Fedora systems that run systemd, the command is:

    systemctl stop iptables.service

If you are running SuSE, use Yast or Yast2 to stop SuSEFirewall.

On other systems that use a classic SysV init system:

    /etc/init.d/iptables stop

Once you have Shorewall running to your satisfaction, you should totally disable your existing firewall. On older Redhat/CentOS/Fedora:

    chkconfig --del iptables

On Debian systems:

    update-rc.d iptables disable

On recent Fedora system running systemd:

    systemctl disable iptables.service

At this point, disable your existing firewall service.

# Additional Recommended Reading

I highly recommend that you review the [Common Configuration File Features page](configuration_file_basics.md) -- it contains helpful tips about Shorewall features than make administering your firewall easier. Also, [Operating Shorewall and Shorewall Lite](starting_and_stopping_shorewall.md) contains a lot of useful operational hints.

# Adding a Wireless Segment to your Two-Interface Firewall

Once you have the two-interface setup working, the next logical step is to add a Wireless Network. The first step involves adding an additional network card to your firewall, either a Wireless card or an Ethernet card that is connected to a Wireless Access Point.

<div class="caution">

When you add a network card, it won't necessarily be detected as the next highest Ethernet interface. For example, if you have two Ethernet cards in your system (`eth0` and `eth1`) and you add a third card that uses the same driver as one of the other two, that third card won't necessarily be detected as `eth2`; it could rather be detected as `eth0` or `eth1`! You can either live with that or you can shuffle the cards around in the slots until the new card is detected as `eth2`.

**Update**: Distributions are getting better about this. SuSE now associates a unique interface name with each MAC address. Other distributions have add-on packages to manage the relationship between MAC addresses and device names.

</div>

Your new network will look similar to what is shown in the following figure.

The first thing to note is that the computers in your wireless network will be in a different subnet from those on your wired local LAN. In the above example, we have chosen to use the network 10.10.11.0/24. Computers 3 and 4 would be configured with a default gateway IP address of 10.10.11.254.

Second, we have chosen to include the wireless network as part of the local zone. Since Shorewall allows intra-zone traffic by default, traffic may flow freely between the local wired network and the wireless network.

There are only two changes that need to be made to the Shorewall configuration:

- An entry needs to be added to `/etc/shorewall/interfaces` for the wireless network interface. If the wireless interface is `wlan0`, the entry might look like:

      #ZONE     INTERFACE       OPTIONS
      loc       wlan0           maclist

  As shown in the above entry, I recommend using the [maclist option](../features/MAC_Validation.md) for the wireless segment. By adding entries for computers 3 and 4 in `/etc/shorewall/maclist`, you help ensure that your neighbors aren't getting a free ride on your Internet connection. Start by omitting that option; when you have everything working, then add the option and configure your `/etc/shorewall/maclist` file.

- You may need to add an entry to the `/etc/shorewall/masq` file to masquerade traffic from the wireless network to the Internet. If you file looks like this:

      #INTERFACE      SOURCE      ADDRESS     PROTO   DPORT   IPSEC   MARK
      eth0            10.0.0.0/8,\
                  169.254.0.0/16,\
                  172.16.0.0/12,\
                  192.168.0.0/16

  or of you are running Shorewall 5.0.14 or later, then you do **not** need to change the contents.

  Otherwise, if your Internet interface is `eth0` and your wireless interface is `wlan0`, the entry would be:

      #INTERFACE           SOURCE             ADDRESS
      eth0                 10.10.11.0/24

One other thing to note. To get Microsoft networking working between the wireless and wired networks, you will need either a WINS server or a PDC. I personally use Samba configured as a WINS server running on my firewall. Running a WINS server on your firewall requires the rules listed in the [Shorewall/Samba documentation](../legacy/samba.md).
