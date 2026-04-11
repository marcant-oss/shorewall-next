<div class="caution">

**This article applies to Shorewall 4.4 and later. If you are running a version of Shorewall earlier than Shorewall 4.4.0 then please see the documentation for that release.**

</div>

# Introduction

Setting up Shorewall on a standalone Linux system is very easy if you understand the basics and follow the documentation.

This guide doesn't attempt to acquaint you with all of the features of Shorewall. It rather focuses on what is required to configure Shorewall in one of its most common configurations:

- Linux system

- Single external IP address

- Connection through Cable Modem, DSL, ISDN, Frame Relay, dial-up... or connected to a LAN and you simply wish to protect your Linux system from other systems on that LAN.

## System Requirements

Shorewall requires that you have the `iproute`/`iproute2` package installed (on RedHat, the package is called `iproute`). You can tell if this package is installed by the presence of an `ip` program on your firewall system. As root, you can use the `which` command to check for this program:

    [root@gateway root]# which ip
    /sbin/ip
    [root@gateway root]#

## Before you start

I recommend that you read through the guide first to familiarize yourself with what's involved then go back through it again making your configuration changes.

<div class="caution">

If you edit your configuration files on a Windows system, you must save them as Unix files if your editor supports that option or you must run them through `dos2unix` before trying to use them. Similarly, if you copy a configuration file from your Windows hard drive to a floppy disk, you must run `dos2unix` against the copy before using it with Shorewall.

- [Windows Version of `dos2unix`](http://www.sourceforge.net/projects/dos2unix)

- [Linux Version of `dos2unix`](http://www.megaloman.com/%7Ehany/software/hd2u/)

</div>

## Conventions

Points at which configuration changes are recommended are flagged with .

Configuration notes that are unique to Debian and it's derivatives are marked with .

# PPTP/ADSL

If you have an ADSL Modem and you use PPTP to communicate with a server in that modem, you must make the changes recommended [here](../features/PPTP.md#PPTP_ADSL) in addition to those detailed below. ADSL with PPTP is most commonly found in Europe, notably in Austria.

# Shorewall Concepts

The configuration files for Shorewall are contained in the directory `/etc/shorewall` -- for simple setups, you only need to deal with a few of these as described in this guide. After you have [installed Shorewall](Install.md), you can find the Samples as follows:

1.  If you installed using an RPM, the samples will be in the `Samples/one-interface` subdirectory of the Shorewall documentation directory. If you don't know where the Shorewall documentation directory is, you can find the samples using this command:

        ~# rpm -ql shorewall | fgrep one-interface
        /usr/share/doc/packages/shorewall/Samples/one-interface
        /usr/share/doc/packages/shorewall/Samples/one-interface/interfaces
        /usr/share/doc/packages/shorewall/Samples/one-interface/policy
        /usr/share/doc/packages/shorewall/Samples/one-interface/rules
        /usr/share/doc/packages/shorewall/Samples/one-interface/zones
        ~#

2.  If you installed using the tarball, the samples are in the `Samples/one-interface` directory in the tarball.

3.  If you installed using a Shorewall 4.x .deb, the samples are in **`/usr/share/doc/shorewall/examples/one-interface`..** You do not need the shorewall-doc package to have access to the samples.

<div class="warning">

**Note to Debian Users**

You will find that your `/etc/shorewall` directory is empty. This is intentional. If you need configuration files other than those found in **`/usr/share/doc/shorewall/examples/one-interface`,** they may be found on your system in the directory `/usr/share/doc/shorewall/default-config`. Simply copy the files you need from that directory to `/etc/shorewall` and modify the copies.

</div>

As each file is introduced, I suggest that you look at the actual file on your system and that you look at the [man page](configuration_file_basics.md#Manpages) for that file. For example, to look at the man page for the `/etc/shorewall/zones` file, type `man shorewall-zones` at a shell prompt.

Note: Beginning with Shorewall 4.4.20.1, there are versions of the sample files that are annotated with the corresponding manpage contents. These files have names ending in '.annotated'. You might choose to look at those files instead.

Shorewall views the network where it is running as being composed of a set of *zones*. In the one-interface sample configuration, only two zones are defined:

    #ZONE   TYPE    OPTIONS                 IN                      OUT
    #                                       OPTIONS                 OPTIONS
    fw      firewall
    net     ipv4

Shorewall zones are defined in [`/etc/shorewall/zones`](https://shorewall.org/manpages/shorewall-zones.html).

Note that Shorewall recognizes the firewall system as its own zone. When the `/etc/shorewall/zones` file is processed, the name of the firewall zone (“fw” in the above example) is stored in the shell variable \$FW which may be used to refer to the firewall zone throughout the Shorewall configuration.

Rules about what traffic to allow and what traffic to deny are expressed in terms of zones.

- You express your default policy for connections from one zone to another zone in the [`/etc/shorewall/policy`](https://shorewall.org/manpages/shorewall-policy.html) file.

- You define exceptions to those default policies in the [`/etc/shorewall/rules`](https://shorewall.org/manpages/shorewall-rules.html) file.

For each connection request entering the firewall, the request is first checked against the `/etc/shorewall/rules` file. If no rule in that file matches the connection request then the first policy in `/etc/shorewall/policy` that matches the request is applied. If there is a [common action](shorewall_extension_scripts.md) defined for the policy in `/etc/shorewall/actions` or `/usr/share/shorewall/actions.std` then that action is performed before the policy is applied. The purpose of the common action is two-fold:

- It silently drops or rejects harmless common traffic that would otherwise clutter up your log — Broadcasts for example.

- If ensures that traffic critical to correct operation is allowed through the firewall — ICMP *fragmentation-needed* for example.

The `/etc/shorewall/policy` file included with the one-interface sample has the following policies:

    #SOURCE        DEST               POLICY   LOGLEVEL   LIMIT
    $FW            net                ACCEPT
    net            all                DROP     info
    all            all                REJECT   info

The above policy will:

1.  allow all connection requests from the firewall to the Internet

2.  drop (ignore) all connection requests from the Internet to your firewall

3.  reject all other connection requests (Shorewall requires this catchall policy).

The word info in the LOG LEVEL column for the last two policies indicates that packets dropped or rejected under those policies should be [logged at that level](../features/shorewall_logging.md).

At this point, edit your `/etc/shorewall/policy` and make any changes that you wish.

# External Interface

The firewall has a single network interface. Where Internet connectivity is through a cable or DSL “Modem”, the *External Interface* will be the Ethernet adapter (`eth0`) that is connected to that “Modem” <u>unless</u> you connect via *Point-to-Point Protocol over Ethernet* (PPPoE) or *Point-to-Point Tunneling Protocol* (PPTP) in which case the External Interface will be a PPP interface (e.g., `ppp0`). If you connect via a regular modem, your External Interface will also be `ppp0`. If you connect using ISDN, your external interface will be `ippp0`.

<div class="caution">

Be sure you know which interface is your external interface. Many hours have been spent floundering by users who have configured the wrong interface. If you are unsure, then as root type `ip route ls` at the command line. The device listed in the last (default) route should be your external interface.

Example:

    root@lists:~# ip route ls
    192.168.2.2 dev tun0  proto kernel  scope link  src 192.168.2.1 
    10.13.10.0/24 dev tun1  scope link 
    192.168.2.0/24 via 192.168.2.2 dev tun0 
    206.124.146.0/24 dev eth0  proto kernel  scope link  src 206.124.146.176 
    10.10.10.0/24 dev tun1  scope link 
    default via 206.124.146.254 dev eth0 
    root@lists:~# 

In that example, `eth0` is the external interface.

</div>

The Shorewall one-interface sample configuration assumes that the external interface is `eth0`. If your configuration is different, you will have to modify the sample `/etc/shorewall/interfaces` file accordingly. While you are there, you may wish to review the list of options that are specified for the interface. Some hints:

<div class="tip">

If your external interface is `ppp0` or `ippp0` or if you have a static IP address, you can remove “dhcp” from the option list.

</div>

# IP Addresses

Before going further, we should say a few words about *Internet Protocol* (IP) addresses. Normally, your *Internet Service Provider* (ISP) will assign you a single IP address. That address can be assigned statically, by the *Dynamic Host Configuration Protocol* (DHCP), through the establishment of your dial-up connection, or during establishment of your other type of PPP (PPPoA, PPPoE, etc.) connection.

**RFC-1918** reserves several *Private* IP address ranges for use in private networks:

    10.0.0.0    - 10.255.255.255
    172.16.0.0  - 172.31.255.255
    192.168.0.0 - 192.168.255.255

These addresses are sometimes referred to as *non-routable* because the Internet backbone routers will not forward a packet whose destination address is reserved by **RFC-1918**. In some cases though, ISPs are assigning these addresses then using *Network Address Translation* *-* NAT) to rewrite packet headers when forwarding to/from the Internet.

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

If you are running a distribution that logs Netfilter messages to a log other than `/var/log/messages`, then modify the LOGFILE setting in `/etc/shorewall/shorewall.conf` to specify the name of your log.

<div class="important">

The LOGFILE setting does not control where the Netfilter log is maintained -- it simply tells the /sbin/`shorewall` utility where to find the log.

</div>

# Kernel Module Loading

Beginning in Shorewall 4.4.7, `/etc/shorewall/shorewall.conf` contains a LOAD_HELPERS_ONLY option which is set to `Yes` in the samples. This causes Shorewall to attempt to load the modules listed in `/usr/share/shorewall/helpers`. In addition, it sets **sip_direct_media=0** when loading the nf_conntrack_sip module. That setting is somewhat less secure than **sip_direct_media=1**, but it generally makes VOIP through the firewall work much better.

The modules in `/usr/share/shorewall/helpers` are those that are not autoloaded. If your kernel does not support module autoloading and you want Shorewall to attempt to load all netfilter modules that it might require, then set LOAD_HELPERS_ONLY=No. That will cause Shorewall to try to load the modules listed in `/usr/share/shorewall/modules`. That file does not set **sip_direct_media=0**.

<div class="important">

In Shorewall 5.2.3, the LOAD_HELPERS_ONLY option was removed and the behavior is the same as if LOAD_HELPERS_ONLY=Yes.

</div>

If you need to modify either `/usr/share/shorewall/helpers` or `/usr/share/shorewall/modules` then copy the file to `/etc/shorewall` and modify the copy.

Modify the setting of LOAD_HELPER_ONLY as necessary.

# Enabling other Connections

Shorewall includes a collection of macros that can be used to quickly allow or deny services. You can find a list of the macros included in your version of Shorewall using the command `ls /usr/share/shorewall/macro.*`.

If you wish to enable connections from the Internet to your firewall and you find an appropriate macro in `/usr/share/shorewall/macro.*`, the general format of a rule in `/etc/shorewall/rules` is:

    #ACTION         SOURCE    DEST            PROTO       DPORT
    <macro>(ACCEPT) net       $FW

<div class="important">

Be sure to add your rules after the line that reads **?SECTION NEW**.

</div>

    #ACTION     SOURCE    DEST            PROTO       DPORT
    Web(ACCEPT) net       $FW
    IMAP(ACCEPT)net       $FW

<div class="caution">

The Shorewall-provided macros assume that the associated service is using it's standard port and will not work with services listening on a non-standard port.

</div>

You may also choose to code your rules directly without using the pre-defined macros. This will be necessary in the event that there is not a pre-defined macro that meets your requirements. In that case the general format of a rule in `/etc/shorewall/rules` is:

    #ACTION   SOURCE    DEST            PROTO       DPORT
    ACCEPT    net       $FW             <protocol>  <port>

    #ACTION   SOURCE    DEST            PROTO        DPORT
    ACCEPT    net       $FW             tcp          80
    ACCEPT    net       $FW             tcp          143

If you don't know what port and protocol a particular application uses, see [here](../features/ports.md).

<div class="important">

I don't recommend enabling telnet to/from the Internet because it uses clear text (even for login!). If you want shell access to your firewall from the Internet, use SSH:

    #ACTION     SOURCE    DESTINATION     PROTO       DPORT
    SSH(ACCEPT) net       $FW           

</div>

At this point, edit `/etc/shorewall/rules` to add other connections as desired.

# Starting and Stopping Your Firewall

The [installation procedure](Install.md) configures your system to start Shorewall at system boot but startup is disabled so that your system won't try to start Shorewall before configuration is complete. Once you have completed configuration of your firewall, you must edit /etc/shorewall/shorewall.conf and set STARTUP_ENABLED=Yes.

<div class="important">

Users of the .deb package must edit `/etc/default/shorewall` and set `startup=1.`

</div>

<div class="important">

You must enable startup by editing `/etc/shorewall/shorewall.conf` and setting `STARTUP_ENABLED=Yes.`

</div>

While you are editing `shorewall.conf`, it is a good idea to check the value of the SUBSYSLOCK option. You can find a description of this option by typing 'man shorewall.conf' at a shell prompt and searching for SUBSYSLOCK.

The firewall is started using the “`shorewall start`” command and stopped using “`shorewall stop`”. When the firewall is stopped, traffic is enabled on those hosts that have an entry in `/etc/shorewall/stoppedrules` (`/etc/shorewall/routestopped` in Shorewall 4.5.7 and earlier). A running firewall may be restarted using the “`shorewall reload`” command. If you want to totally remove any trace of Shorewall from your Netfilter configuration, use “`shorewall clear`”.

<div class="warning">

If you are connected to your firewall from the Internet, do not issue a “`shorewall stop`” command unless you have either:

1.  Used ADMINISABSENTMINDED=Yes in `/etc/shorewall/shorewall.conf` or

2.  added an entry for the IP address that you are connected from to [`/etc/shorewall/routestopped`](https://shorewall.org/manpages/shorewall-routestopped.html).

Also, I don't recommend using “`shorewall reload`”; it is better to create an *[alternate configuration](configuration_file_basics.md#Configs)* and test it using the [“`shorewall try`”](starting_and_stopping_shorewall.md) command.

</div>

The firewall will start after your network interface has been brought up. This leaves a small window between the time that the network interface is working and when the firewall is controlling connections through that interface. If this is a concern, you can close that window by installing the [Shorewall Init Package](../features/Shorewall-init.md).

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
