<div class="caution">

**This article applies to Shorewall 4.4 and later. If you are running a version of Shorewall earlier than Shorewall 4.4.0 then please see the documentation for that release.**

</div>

# Introduction

Setting up a Linux system as a firewall for a small network with DMZ is a fairly straight-forward task if you understand the basics and follow the documentation.

This guide doesn't attempt to acquaint you with all of the features of Shorewall. It rather focuses on what is required to configure Shorewall in one of its more popular configurations:

- Linux system used as a firewall/router for a small local network.

- Single public IP address.

  <div class="note">

  If you have more than one public IP address, this is not the guide you want -- see the [Shorewall Setup Guide](shorewall_setup_guide.md) instead.

  </div>

- DMZ connected to a separate Ethernet interface. The purpose of a DMZ is to isolate those servers that are exposed to the Internet from your local systems so that if one of those servers is compromised there is still a firewall between the hacked server and your local systems.

- Connection through DSL, Cable Modem, ISDN, Frame Relay, dial-up, ...

Here is a schematic of a typical installation.

<figure id="Figure1">
<img src="images/dmz1.png" />
<figcaption>schematic of a typical installation</figcaption>
</figure>

## Requirements

Shorewall requires that you have the `iproute`/`iproute2` package installed (on RedHat, the package is called `iproute`). You can tell if this package is installed by the presence of an `ip` program on your firewall system. As `root`, you can use the `which` command to check for this program:

    [root@gateway root]# which ip
    /sbin/ip
    [root@gateway root]#

## Before you start

I recommend that you first read through the guide to familiarize yourself with what's involved then go back through it again making your configuration changes.

<div class="caution">

If you edit your configuration files on a Windows system, you must save them as Unix files if your editor supports that option or you must run them through `dos2unix` before trying to use them. Similarly, if you copy a configuration file from your Windows hard drive to a floppy disk, you must run `dos2unix` against the copy before using it with Shorewall.

- [Windows Version of dos2unix](http://www.sourceforge.net/projects/dos2unix)

- [Linux Version of dos2unix](http://www.megaloman.com/%7Ehany/software/hd2u/)

</div>

## Conventions

Points at which configuration changes are recommended are flagged with .

Configuration notes that are unique to Debian and it's derivatives are marked with .

# PPTP/ADSL

If you have an ADSL Modem and you use PPTP to communicate with a server in that modem, you must make the changes recommended in the PPTP/ADSL notes (PPTP documentation was not ported to shorewall-nft) in addition to those detailed below. ADSL with PPTP is most commonly found in Europe, notably in Austria.

# Shorewall Concepts

The configuration files for Shorewall are contained in the directory `/etc/shorewall` -- for simple setups, you will only need to deal with a few of these as described in this guide.

After you have installed Shorewall, locate the three-interface Sample configuration:

1.  If you installed using an RPM, the samples will be in the Samples/three-interfaces/ subdirectory of the Shorewall documentation directory. If you don't know where the Shorewall documentation directory is, you can find the samples using this command:

        ~# rpm -ql shorewall | fgrep three-interfaces
        /usr/share/doc/packages/shorewall/Samples/three-interfaces
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/interfaces
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/masq
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/policy
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/rules
        /usr/share/doc/packages/shorewall/Samples/three-interfaces/zones
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

2.  If you installed using the tarball, the samples are in the Samples/three-interfaces directory in the tarball.

3.  If you installed using a Shorewall 3.x .deb, the samples are in /usr/share/doc/shorewall/examples/three-interfaces. You must install the shorewall-doc package.

4.  If you installed using a Shorewall 4.x .deb, the samples are in **`/usr/share/doc/shorewall/examples/three-interfaces`**. You do not need the shorewall-doc package to have access to the samples.

    <div class="warning">

    **Note to Debian Users**

    If you install using the .deb, you will find that your `/etc/shorewall` directory is empty. This is intentional. The released configuration file skeletons may be found on your system in the directory `/usr/share/doc/shorewall/default-config`. Simply copy the files you need from that directory to `/etc/shorewall` and modify the copies.

    </div>

As each file is introduced, I suggest that you look at the actual file on your system and that you look at the [man page](configuration_file_basics.md#Manpages) for that file. For example, to look at the man page for the `/etc/shorewall/zones` file, type `man shorewall-zones` at a shell prompt.

Note: Beginning with Shorewall 4.4.20.1, there are versions of the sample files that are annotated with the corresponding manpage contents. These files have names ending in '.annotated'. You might choose to look at those files instead.

Shorewall views the network where it is running as being composed of a set of zones. In the three-interface sample configuration, the following zone names are used:

    #ZONE   TYPE   OPTIONS                 IN_OPTIONS              OUT_OPTIONS
    fw      firewall
    net     ipv4
    loc     ipv4
    dmz     ipv4

Zone names are defined in `/etc/shorewall/zones`.

Note that Shorewall recognizes the firewall system as its own zone. When the /etc/shorewall/zones file is processed, he name of the firewall zone is stored in the shell variable \$FW which may be used throughout the Shorewall configuration to refer to the firewall zone.

Rules about what traffic to allow and what traffic to deny are expressed in terms of zones.

- You express your default policy for connections from one zone to another zone in the `/etc/shorewall/policy` file.

- You define exceptions to those default policies in the `/etc/shorewall/rules` file.

For each connection request entering the firewall, the request is first checked against the `/etc/shorewall/rules` file. If no rule in that file matches the connection request then the first policy in `/etc/shorewall/policy` that matches the request is applied. If there is a [common action](shorewall_extension_scripts.md) defined for the policy in `/etc/shorewall/actions` or `/usr/share/shorewall/actions.std` then that action is performed before the action is applied. The purpose of the common action is two-fold:

- It silently drops or rejects harmless common traffic that would otherwise clutter up your log — Broadcasts for example.

- If ensures that traffic critical to correct operation is allowed through the firewall — ICMP *fragmentation-needed* for example.

The `/etc/shorewall/policy` file included with the three-interface sample has the following policies:

    #SOURCE    DEST        POLICY      LOGLEVEL    LIMIT
    loc        net         ACCEPT
    net        all         DROP        info
    all        all         REJECT      info

<div class="important">

In the three-interface sample, the line below is included but commented out. If you want your firewall system to have full access to servers on the Internet, uncomment that line.

    #SOURCE    DEST        POLICY      LOGLEVEL    LIMIT
    $FW        net         ACCEPT

</div>

The above policy will:

1.  allow all connection requests from your local network to the Internet

2.  drop (ignore) all connection requests from the Internet to your firewall or local network

3.  optionally accept all connection requests from the firewall to the Internet (if you uncomment the additional policy)

4.  reject all other connection requests.

The word info in the LOG LEVEL column for the DROP and REJECT policies indicates that packets dropped or rejected under those policies should be [logged at that level](../features/shorewall_logging.md).

Some people want to consider their firewall to be part of their local network from a security perspective. If you want to do this, add these two policies:

    #SOURCE    DEST        POLICY      LOGLEVEL    LIMIT
    loc        $FW         ACCEPT
    $FW        loc         ACCEPT

It is important to note that Shorewall policies (and rules) refer to **connections** and not packet flow. With the policies defined in the `/etc/shorewall/policy` file shown above, connections are allowed from the *loc* zone to the *net* zone even though connections are not allowed from the *loc* zone to the firewall itself.

At this point, edit your `/etc/shorewall/policy` file and make any changes that you wish.

# Network Interfaces

<figure id="Figure2">
<img src="images/dmz1.png" />
<figcaption>DMZ</figcaption>
</figure>

The firewall has three network interfaces. Where Internet connectivity is through a cable or DSL “Modem”, the External Interface will be the Ethernet adapter that is connected to that “Modem” (e.g., `eth0`) unless you connect via *Point-to-Point Protocol* over Ethernet (PPPoE) or *Point-to-Point Tunneling Protocol* (PPTP) in which case the External Interface will be a `ppp` interface (e.g., `ppp0`). If you connect via a regular modem, your External Interface will also be `ppp0`. If you connect using ISDN, you external interface will be `ippp0`.

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

I**f your external interface is `ppp0` or `ippp0` then you will want to set `CLAMPMSS=yes` in `/etc/shorewall/shorewall.conf`.**

Your Local Interface will be an Ethernet adapter (`eth0`, `eth1` or `eth2`) and will be connected to a hub or switch. Your local computers will be connected to the same switch (note: If you have only a single local system, you can connect the firewall directly to the computer using a cross-over cable).

Your DMZ Interface will also be an Ethernet adapter (`eth0`, `eth1` or `eth2`) and will be connected to a hub or switch. Your DMZ computers will be connected to the same switch (note: If you have only a single DMZ system, you can connect the firewall directly to the computer using a cross-over cable).

<div class="caution">

**Do NOT connect multiple interfaces to the same hub or switch except for testing**. You can test using this kind of configuration if you specify the **arp_filter** option or the **arp_ignore** option in `/etc/shorewall/interfaces` for all interfaces connected to the common hub/switch. **Using such a setup with a production firewall is strongly recommended against**.

</div>

<div class="caution">

**Do not configure a default route on your internal and DMZ interfaces.** Your firewall should have exactly one default route via your ISP's Router.

</div>

The Shorewall three-interface sample configuration assumes that the external interface is `eth0`, the local interface is `eth1` and the DMZ interface is `eth2`. If your configuration is different, you will have to modify the sample `/etc/shorewall/interfaces` file accordingly. While you are there, you may wish to review the list of options that are specified for the interfaces. Some hints:

<div class="tip">

If your external interface is `ppp0` or `ippp0` or if you have a static IP address, you can remove “dhcp” from the option list.

</div>

Prior to Shorewall 5.1.9, it is also required to change the snat and stoppedrules file, to replace `eth0` with the name of your external interface and `eth1` with the name of your local interface.

# IP Addresses

Before going further, we should say a few words about Internet Protocol (IP) addresses. Normally, your ISP will assign you a single Public IP address. This address may be assigned via the Dynamic Host Configuration Protocol (DHCP) or as part of establishing your connection when you dial in (standard modem) or establish your PPP connection. In rare cases, your ISP may assign you a static IP address; that means that you configure your firewall's external interface to use that address permanently. Regardless of how the address is assigned, it will be shared by all of your systems when you access the Internet. You will have to assign your own addresses for your internal network (the local and DMZ Interfaces on your firewall plus your other computers). RFC 1918 reserves several Private IP address ranges for this purpose:

    10.0.0.0    - 10.255.255.255
    172.16.0.0  - 172.31.255.255
    192.168.0.0 - 192.168.255.255

You will want to assign your local addresses from one sub-network or subnet and your DMZ addresses from another subnet. For our purposes, we can consider a subnet to consists of a range of addresses `x.y.z.0` - `x.y.z.255`. Such a subnet will have a Subnet Mask of `255.255.255.0`. The address `x.y.z.0` is reserved as the Subnet Address and `x.y.z.255` is reserved as the Subnet Broadcast Address. In Shorewall, a subnet is described using Classless InterDomain Routing (CIDR) notation with consists of the subnet address followed by `/24`. The `24` refers to the number of consecutive “1” bits from the left of the subnet mask.

|                    |
|:-------------------|
| Range:             |
| Subnet Address:    |
| Broadcast Address: |
| CIDR Notation:     |

Example sub-network

It is conventional to assign the internal interface either the first usable address in the subnet (`10.10.10.1` in the above example) or the last usable address (`10.10.10.254`).

One of the purposes of subnetting is to allow all computers in the subnet to understand which other computers can be communicated with directly. To communicate with systems outside of the subnetwork, systems send packets through a gateway (router).

Your local computers (Local Computers 1 & 2) should be configured with their default gateway set to the IP address of the firewall's internal interface and your DMZ computers (DMZ Computers 1 & 2) should be configured with their default gateway set to the IP address of the firewall's DMZ interface.

The foregoing short discussion barely scratches the surface regarding subnetting and routing. If you are interested in learning more about IP addressing and routing, I highly recommend “IP Fundamentals: What Everyone Needs to Know about Addressing & Routing”, Thomas A. Maufer, Prentice-Hall, 1999, ISBN 0-13-975483-0.

The remainder of this guide will assume that you have configured your network as shown here:

<figure id="Figure3">
<img src="images/dmz2.png" alt="The default gateway for the DMZ computers would be 10.10.11.254 and the default gateway for the Local computers would be 10.10.10.254. Your ISP might assign your external interface an RFC 1918 address. If that address is in the 10.10.10.0/24 subnet then you will need to select a DIFFERENT RFC 1918 subnet for your local network and if it is in the 10.10.11.0/24 subnet then you will need to select a different RFC 1918 subnet for your DMZ." />
<figcaption>DMZ</figcaption>
</figure>

# IP Masquerading (SNAT)

The addresses reserved by RFC 1918 are sometimes referred to as non-routable because the Internet backbone routers don't forward packets which have an RFC-1918 destination address. When one of your local systems (let's assume local computer 1) sends a connection request to an Internet host, the firewall must perform Network Address Translation (NAT). The firewall rewrites the source address in the packet to be the address of the firewall's external interface; in other words, the firewall makes it look as if the firewall itself is initiating the connection. This is necessary so that the destination host will be able to route return packets back to the firewall (remember that packets whose destination address is reserved by RFC 1918 can't be routed across the Internet). When the firewall receives a return packet, it rewrites the destination address back to 10.10.10.1 and forwards the packet on to local computer 1.

On Linux systems, the above process is often referred to as IP Masquerading and you will also see the term Source Network Address Translation (SNAT) used. Shorewall follows the convention used with Netfilter:

- *Masquerade* describes the case where you let your firewall system automatically detect the external interface address.

- *SNAT* refers to the case when you explicitly specify the source address that you want outbound packets from your local network to use.

In Shorewall, both Masquerading and SNAT are configured with entries in the `/etc/shorewall/``masq` file (`/etc/shorewall/snat` when running Shorewall 5.0.14 or later).

If your external firewall interface is `eth0` then you do not need to modify the file provided with the sample. Otherwise, edit `/etc/shorewall/``masq` or `/etc/shorewall/snat` and change it to match your configuration.

If, in spite of all advice to the contrary, you are using this guide and want to use one-to-one NAT or Proxy ARP for your DMZ, you will need to modify the SOURCE column to list just your local interface (10.10.10.0/24 in the above example).

If your external IP is static then, if you are running Shorewall 5.0.13 or earlier, you can enter our static IP in the third column in the `/etc/shorewall/``masq` entry if you like although your firewall will work fine if you leave that column empty (Masquerade). Entering your static IP in column 3 (SNAT) makes the processing of outgoing packets a little more efficient.

When running Shorewall 5.0.14 or later, the rule in /etc/shorewall/snat must be change from a MASQUERADE rule to an SNAT rule.

    #ACTION                      SOURCE                DEST         PROTO      PORT
    SNAT(static-ip)              ...

**If you are using the Debian package, please check your `shorewall.conf` file to ensure that the following is set correctly; if it is not, change it appropriately:**

- `IP_FORWARDING=On`

# Logging

Shorewall does not maintain a log itself but rather relies on your [system's logging configuration](../features/shorewall_logging.md). The following [commands](https://shorewall.org/manpages/shorewall.html) rely on knowing where Netfilter messages are logged:

- `shorewall show log` (Displays the last 20 Netfilter log messages)

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

One of your goals will be to run one or more servers on your DMZ computers. Because these computers have RFC-1918 addresses, it is not possible for clients on the Internet to connect directly to them. It is rather necessary for those clients to address their connection requests to your firewall who rewrites the destination address to the address of your server and forwards the packet to that server. When your server responds, the firewall automatically performs SNAT to rewrite the source address in the response.

The above process is called *Port Forwarding* or *Destination Network Address Translation* (DNAT). You configure port forwarding using DNAT rules in the `/etc/shorewall/``rules` file.

The general form of a simple port forwarding rule in `/etc/shorewall/``rules` is:

    #ACTION   SOURCE    DEST                                          PROTO      DPORT
    DNAT      net       dmz:<server local IP address>[:<server port>] <protocol> <port>

If you don't specify the *`<server port>`*, it is assumed to be the same as *`<port>`*.

<div class="important">

Be sure to add your rules after the line that reads **SECTION NEW.**

</div>

    #ACTION     SOURCE    DEST                PROTO      DPORT
    Web(DNAT)   net    dmz:10.10.11.2  
    Web(ACCEPT)  loc    dmz:10.10.11.2

- Entry 1 forwards port 80 from the Internet.

- Entry 2 allows connections from the local network.

Several important points to keep in mind:

- When you are connecting to your server from your local systems, you must use the server's internal IP address (`10.10.11.2`) or you must use DNAT from the loc zone as well (see below).

      #ACTION     SOURCE    DEST                PROTO      DPORT         SPORT            ORIGDEST
      Web(DNAT)   loc       dmz:10.10.11.2      -          -             -                external-ip-address

  where \<external-ip-address\> is the IP address of the firewall's external interface.

- Many ISPs block incoming connection requests to port 80. If you have problems connecting to your web server, try the following rule and try connecting to port 5000 (e.g., connect to `http://w.x.y.z:5000 where w.x.y.z` is your external IP).

      #ACTION   SOURCE    DEST                PROTO      DPORT         SPORT            ORIGDEST
      DNAT      net       dmz:10.10.11.2:80   tcp        5000

- If you want to be able to access your server from the local network using your external address, then if you have a static external IP you can replace the loc-\>dmz rule above with:

      #ACTION   SOURCE    DEST            PROTO  DPORT         SPORT    ORIGDEST
      DNAT      loc       dmz:10.10.11.2  tcp    80            -        <external IP>

  If you have a dynamic IP then you must ensure that your external interface is up before starting Shorewall and you must code the rule as follows (assume that your external interface is `eth0`):

      #ACTION   SOURCE    DEST             PROTO   DPORT         SPORT    ORIGDEST
      DNAT      loc       dmz:10.10.11.2   tcp     80            -        &eth0

  '&eth0' expands to the IP address of eth0 (see [this article](configuration_file_basics.md#AddressVariables)).

- If you want to access your server from the DMZ using your external IP address, see [FAQ 2a](FAQ.md#faq2a).

At this point, add the DNAT and ACCEPT rules for your servers.

<div class="important">

When testing DNAT rules like those shown above, you must test from a client OUTSIDE YOUR FIREWALL (in the 'net' zone). You cannot test these rules from inside the firewall!

For DNAT troubleshooting tips, [see FAQs 1a and 1b](FAQ.md#faq1a).

</div>

# Domain Name Server (DNS)

Normally, when you connect to your ISP, as part of getting an IP address your firewall's *Domain Name Service* (DNS) resolver will be automatically configured (e.g., the `/etc/resolv.conf` file will be written). Alternatively, your ISP may have given you the IP address of a pair of DNS name servers for you to manually configure as your primary and secondary name servers. It is your responsibility to configure the resolver in your internal systems. You can take one of two approaches:

- You can configure your internal systems to use your ISP's name servers. If your ISP gave you the addresses of their servers or if those addresses are available on their web site, you can configure your internal systems to use those addresses. If that information isn't available, look in `/etc/resolv.conf` on your firewall system -- the name servers are given in “nameserver” records in that file.

- You can configure a *Caching Name Server* on your firewall or in your DMZ. Red Hat has an RPM for a caching name server (which also requires the '`bind`' RPM) and for Bering users, there is `dnscache.lrp`. If you take this approach, you configure your internal systems to use the caching name server as their primary (and only) name server. You use the internal IP address of the firewall (`10.10.10.254` in the example above) for the name server address if you choose to run the name server on your firewall. To allow your local systems to talk to your caching name server, you must open port 53 (both UDP and TCP) from the local network to the server; you do that by adding the rules in `/etc/shorewall/rules`.

If you run the name server on the firewall:

    #ACTION     SOURCE    DEST                PROTO      DPORT                     
    DNS(ACCEPT) loc       $FW
    DNS(ACCEPT) dmz       $FW            

Run name server on DMZ computer 1:

    #ACTION     SOURCE    DEST                PROTO      DPORT                      
    DNS(ACCEPT) loc       dmz:10.10.11.1
    DNS(ACCEPT) $FW       dmz:10.10.11.1             

In the rules shown above, “DNS”(ACCEPT)is an example of a *defined macro*. Shorewall includes a number of defined macros and [you can add your own](../concepts/Macros.md). To see the list of macros included with your version of Shorewall, run the command `shorewall show macros`.

You don't have to use defined macros when coding a rule in `/etc/shorewall/rules`. The first example above (name server on the firewall) could also have been coded as follows:

    #ACTION   SOURCE    DEST                PROTO      DPORT                      
    ACCEPT    loc       $FW                 tcp        53
    ACCEPT    loc       $FW                 udp        53
    ACCEPT    dmz       $FW                 tcp        53
    ACCEPT    dmz       $FW                 udp        53              

In cases where Shorewall doesn't include a defined macro to meet your needs, you can either define the macro yourself or you can simply code the appropriate rules directly. [This page](../features/ports.md) can be of help if you don't know the protocol and port involved.

<div class="caution">

The Shorewall-provided macros assume that the service is using its standard port and will not work with a service listening on a non-standard port.

</div>

# Other Connections

The three-interface sample includes the following rule:

    #ACTION     SOURCE    DEST                PROTO      DPORT                      
    DNS(ACCEPT) $FW       net       

That rule allow DNS access from your firewall and may be removed if you commented out the line in `/etc/shorewall/policy` allowing all connections from the firewall to the Internet.

The sample also includes:

    #ACTION     SOURCE    DEST                PROTO      DPORT                      
    SSH(ACCEPT) loc       $FW
    SSH(ACCEPT) loc       dmz        

Those rules allow you to run an SSH server on your firewall and in each of your DMZ systems and to connect to those servers from your local systems.

If you wish to enable other connections between your systems, the general format for using a defined macro is:

    #ACTION         SOURCE        DEST                PROTO      DPORT                      
    <macro>(ACCEPT) <source zone> <destination zone>

The general format when not using a defined macro is:

    #ACTION   SOURCE        DEST                PROTO      DPORT                      
    ACCEPT    <source zone> <destination zone>  <protocol> <port> 

Using defined macros:

    #ACTION     SOURCE    DEST                PROTO      DPORT
    DNS(ACCEPT) net       $FW

Not using defined macros:

    #ACTION   SOURCE    DEST                PROTO      DPORT                      
    ACCEPT    net       $FW                 tcp        53
    ACCEPT    net       $FW                 udp        53        

Those rules would of course be in addition to the rules listed above under "If you run the name server on your firewall".

If you don't know what port and protocol a particular application uses, [look here](../features/ports.md).

<div class="important">

I don't recommend enabling telnet to/from the Internet because it uses clear text (even for login!). If you want shell access to your firewall from the Internet, use SSH:

    #ACTION     SOURCE    DEST                PROTO      DPORT                      
    SSH(ACCEPT) net       $FW

</div>

Bering users will want to add the following two rules to be compatible with Jacques's Shorewall configuration:

    #ACTION   SOURCE    DEST                PROTO      DPORT                      
    ACCEPT    loc       $FW                 udp        53
    ACCEPT    net       $FW                 tcp        80       

- Entry 1 allows the DNS Cache to be used.

- Entry 2 allows the “weblet” to work.

Now modify `/etc/shorewall/rules` to add or remove other connections as required.

# Some Things to Keep in Mind

- **You cannot test your firewall from the inside**. Just because you send requests to your firewall external IP address does not mean that the request will be associated with the external interface or the “net” zone. Any traffic that you generate from the local network will be associated with your local interface and will be treated as loc-\>fw traffic.

- **IP addresses are properties of systems, not of interfaces**. It is a mistake to believe that your firewall is able to forward packets just because you can ping the IP address of all of the firewall's interfaces from the local network. The only conclusion you can draw from such pinging success is that the link between the local system and the firewall works and that you probably have the local system's default gateway set correctly.

- **All IP addresses configured on firewall interfaces are in the \$FW (fw) zone**. If 192.168.1.254 is the IP address of your internal interface then you can write “**\$FW:192.168.1.254**” in a rule but you may not write “**loc:192.168.1.254**”. Similarly, it is nonsensical to add 192.168.1.254 to the **loc** zone using an entry in `/etc/shorewall/hosts`.

- **Reply packets do NOT automatically follow the reverse path of the one taken by the original request**. All packets are routed according to the routing table of the host at each step of the way. This issue commonly comes up when people install a Shorewall firewall parallel to an existing gateway and try to use DNAT through Shorewall without changing the default gateway of the system receiving the forwarded requests. Requests come in through the Shorewall firewall where the destination IP address gets rewritten but replies go out unmodified through the old gateway.

- **Shorewall itself has no notion of inside or outside**. These concepts are embodied in how Shorewall is configured.

# Starting and Stopping Your Firewall

The [installation procedure](Install.md) configures your system to start Shorewall at system boot but startup is disabled so that your system won't try to start Shorewall before configuration is complete. Once you have completed configuration of your firewall, you can enable Shorewall startup by editing `/etc/shorewall/shorewall.conf` and setting STARTUP_ENABLED=Yes.

<div class="important">

Users of the `.deb` package must edit `/etc/default/shorewall` and set `startup=1`.

</div>

While you are editing `shorewall.conf`, it is a good idea to check the value of the SUBSYSLOCK option. You can find a description of this option by typing 'man shorewall.conf' at a shell prompt and searching for SUBSYSLOCK

The firewall is started using the `shorewall start` command and stopped using `shorewall stop`. When the firewall is stopped, routing is enabled on those hosts that have an entry in `/etc/shorewall/stoppedrules` ([`/etc/shorewall/routestopped`](https://shorewall.org/manpages/shorewall-routestopped.html) on Shorewall 4.5.7 and earlier). A running firewall may be restarted using the `shorewall reload` command. If you want to totally remove any trace of Shorewall from your Netfilter configuration, use `shorewall clear`.

The three-interface sample assumes that you want to enable routing to/from `eth1` (your local network) and `eth2` (DMZ) when Shorewall is stopped. If these two interfaces don't connect to your local network and DMZ or if you want to enable a different set of hosts, modify `/etc/shorewall/routestopped` accordingly.

<div class="warning">

If you are connected to your firewall from the Internet, do not issue a “`shorewall stop`” command unless you have either:

1.  Used ADMINISABSENTMINDED=Yes in `/etc/shorewall/shorewall.conf`; or

2.  added an entry for the IP address that you are connected from to `/etc/shorewall/``routestopped`.

Also, I don't recommend using “`shorewall reload`”; it is better to create an alternate configuration and test it using the “`shorewall try`” command.

</div>

The firewall will start after your network interfaces have been brought up. This leaves a small window between the time that the network interface are working and when the firewall is controlling connections through those interfaces. If this is a concern, you can close that window by installing the Shorewall Init Package (shorewall-init documentation was not ported to shorewall-nft).

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

I highly recommend that you review the [Common Configuration File Features](configuration_file_basics.md) page -- it contains helpful tips about Shorewall features than make administering your firewall easier. Also, [Operating Shorewall and Shorewall Lite](starting_and_stopping_shorewall.md) contains a lot of useful operational hints.
