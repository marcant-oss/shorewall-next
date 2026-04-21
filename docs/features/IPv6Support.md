<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

# Overview

Beginning with Shorewall 4.2.4, support for firewalling IPv6 is included as part of Shorewall.

## Prerequisites

In order to use Shorewall with IPv6, your firewall must meet the following prerequisites:

1.  [Kernel 2.6.24 or later](../reference/FAQ.md#faq80a).

2.  Iptables 1.4.0 or later (1.4.1.1 is strongly recommended)

3.  If you wish to include DNS names in your IPv6 configuration files, you must have Perl 5.10 and must install the Perl Socket6 library.

## Packages

Shorewall IPv6 support introduced two new packages:

1.  Shorewall6. This package provides `/sbin/shorewall6` which is the IPv6 equivalent of `/sbin/shorewall`. `/sbin/shorewall` only handles IPv4 while `/sbin/shorewall6` handles only IPv6.. Shorewall6 depends on Shorewall. The Shorewall6 configuration is stored in `/etc/shorewall6`.

2.  Shorewall6 Lite. This package is to IPv6 what Shorewall Lite is to IPv4. The package stores its configuration in `/etc/shorewall6-lite`. As with Shorewall Lite, Shorewall6 Lite usually requires no configuration changes on the firewall system.

## IPv4/IPv6 Interaction

IP connections are either IPv4 or IPv6; there is no such thing as a mixed IPv4/6 connecton. IPv4 connections are controlled by Shorewall (or Shorewall-lite); IPv6 connections are controlled by Shorewall6 (or Shorewall6-lite). Starting and stopping the firewall for one address family has no effect on the other address family.

As a consequence, there is very little interaction between Shorewall and Shorewall6.

### DISABLE_IPV6

An obvious area where the configuration of Shorewall affects Shorewall6 is the DISABLE_IPV6 setting in `/etc/shorewall/shorewall.conf`. When configuring Shorewall6, you will want to set DISABLE_IPV6=No and restart Shorewall or Shorewall-lite.

### TC_ENABLED

Another area where their configurations overlap is in traffic shaping; the `tcdevices` and tcclasses files do exactly the same thing in both Shorewall and Shorewall6. Consequently, you will have TC_ENABLED=Internal in Shorewall or in Shorewall6 and TC_ENABLED=No in the other product. Also, you will want CLEAR_TC=No in the configuration with TC_ENABLED=No.

Regardless of which product has TC_ENABLED=Internal:

- IPv4 packet marking is controlled by /etc/shorewall/mangle (Shorewall 4.6.0 and later) or by /etc/shorewall/tcrules

- IPv6 packet marking is controlled by /etc/shorewall6/mangle (Shorewall 4.6.0 and later) or by /etc/shorewall6/tcrules

### KEEP_RT_TABLES

Multi-ISP users will need to be aware of this one. When there are entries in the providers file, Shorewall normally installs a modified `/etc/iproute2/rt_tables` during `shorewall start` and `shorewall restart` and restores a default file during `shorewall stop`. Setting KEEP_RT_TABLES=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5) stops Shorewall (Shorewall lite) from modifying `/etc/iproute2/rt_tables`.

Shorewall6 is also capable of modifying `/etc/iproute2/rt_tables` in a similar way.

Our recommendation to Multi-ISP users is to:

- Select the same names for similar providers.

- Set KEEP_RT_TABLES=No in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5) and set KEEP_RT_TABLES=Yes in [shorewall6.conf](https://shorewall.org/manpages/shorewall.conf.html)(5).

These setting allow Shorewall to control the contents of `/etc/iproute2/rt_tables`.

### 6TO4

If you are using a 6to4 tunnel for your IPv6 connectivity, you need an entry in `/etc/shorewall/tunnels`.

    #TYPE                   ZONE            GATEWAY                 GATEWAY_ZONE
    6to4                    net

# Shorewall6 Differences from Shorewall

Configuring and operating Shorewall6 is very similar to configuring Shorewall with some notable exceptions:

Default Zone Type  
The default zone type in Shorewall6 is ipv6. It is suggested that you specify **ipv6** in the TYPE column of `/etc/shorewall6/zones` and a type of **ipv4** in `/etc/shorewall/zones`; that way, if you run the wrong utility on a configuration, you will get an instant error.

Interface Options  
The following interface options are available in `/etc/shorewall6/interfaces`:

blacklist  
Same as in Shorewall

bridge  
Same as in Shorewall

dhcp  
Interface is assigned by IPv6 DHCP or the firewall hosts an IPv6 DHCP server on the interface.

maclist  
Same as in Shorewall

nosmurfs  
Checks the source IP address of packets arriving on the interface and drops packets whose SOURCE address is:

- An IPv6 multicast address

- The subnet-router anycast address for any of the global unicast addresses assigned to the interface.

- An RFC 2526 anycast address for any of the global unicast addresses assigned to the interface.

optional  
Same as in Shorewall

routeback  
Same as in Shorewall

sourceroute\[={0\|1}\]  
Same as in Shorewall

tcpflags  
Same as in Shorewall

mss=\<mss\>  
Same as in Shorewall

forward\[={0\|1}\]  
Override the setting of IP_FORWARDING in shorewall6.conf with respect to how the system behaves on this interface. If 1, behave as a router; if 0, behave as a host.

Host Options  
The following host options are available in`/etc/shorewall6/hosts`:

blacklist  
Same as in Shorewall

maclist  
Same as in Shorewall

routeback  
Same as in Shorewall

tcpflags  
Same as in Shorewall

Specifying Addresses  
Shorewall follows the usual convention of distinguishing IPv6 address by enclosing them in square brackets ("\[" and "\]").

Anywhere that an address or address list follows a colon (":"), the address or list may be enclosed in square brackets to improve readability.

Example (`/etc/shorewall6/rules`):

    #ACTION         SOURCE          DEST                    PROTO   DPORT

    ?SECTION NEW

    ACCEPT          net             $FW:[2002:ce7c:92b4::3] tcp     22

When the colon is preceeded by an interface name, *the angle brackets are required*. This is true even when the address is a MAC address in Shorewall format.

Example (`/etc/shorewall6/rules`):

    #ACTION         SOURCE                          DEST            PROTO   DPORT

    ?SECTION NEW

    ACCEPT          net:wlan0:[2002:ce7c:92b4::3]   $FW             tcp     22

Prior to Shorewall 4.5.4, angled brackets ("\<" and "\>") were used. While these are still accepted, their use is deprecated in favor of square brackets.

Example (`/etc/shorewall6/rules`):

    #ACTION         SOURCE                          DEST            PROTO   DPORT

    SECTION NEW

    ACCEPT          net:wlan0:<2002:ce7c:92b4::3>   $FW             tcp     22

Prior to Shorewall 4.5.9, network addresses were required to be enclosed in either angle brackets or square brackets (e.g. \[2001:470:b:787::/64\]). Beginning with Shorewall 4.5.9, the more common representation that places the VLSM outside the brackets is accepted and preferred (e.g., \[2001:470:b:787::\]/64).

Beginning with Shorewall 4.5.14, the rules compiler translates "\<" and "\>" to "\[" and "\]" respectively before parsing. So square brackets may appear in error messages even when angled brackets were used.

Stopped State  
When Shorewall6 or Shorewall6 Lite is in the stopped state, the following traffic is still allowed.

- Traffic with a multicast destination IP address (ff00::/8).

- Traffic with a link local source address (ff800::/8)

- Traffic with a link local destination address.

Multi-ISP  
The Linux IPv6 stack does not support balancing (multi-hop) routes. Thehe `balance` and `fallback` options in [shorewall6-providers](https://shorewall.org/manpages/shorewall-providers.html)(5) and USE_DEFAULT_RT=Yes in [shorewall6.conf](https://shorewall.org/manpages/shorewall.conf.html)(5) are supported, but at most one provider can have the `balance` option and at most one provider can have the `fallback` option.

/sbin/shorewall6 and /sbin/shorewall6-lite Commands  
Several commands supported by `/sbin/shorewall` and `/sbin/shorewall-lite` are not supported by `/sbin/shorewall6` and `/sbin/shorewall6-lite`:

- hits

- ipcalc

- iprange

Macros  
The Shorewall6 package depends on Shorewall for application macros. Only certain address-family specific macros such as macro.AllowICMPs are included in Shorewall6. As a consequence, /usr/share/shorewall/ is included in the default Shorewall6 CONFIG_PATH.

# Installing IPv6 Support

You will need at least the following packages:

- Shorewall 4.3.5 or later.

- Shorewall6 4.3.5 or later.

You may also with to install Shorewall6-lite 4.3.5 or later on your remote firewalls to allow for central IPv6 firewall administration.

# Shared Shorewall/Shorewall6 Configuration Files

Normally, the configuration files for Shorewall are kept in /etc/shorewall/ and those for Shorewall6 are kept in /etc/shorewall6/. It is possible, however, to share almost all of those files as shown in [this article](SharedConfig.md).

# More information about IPv6

I strongly suggest that you read the [Linux IPv6 HOWTO](http://tldp.org/HOWTO/Linux+IPv6-HOWTO/). The 6to4 Tunnels article (not ported to shorewall-nft) also includes instructions for setting up your first IPv6 environment; see [GenericTunnels.md](GenericTunnels.md) for current tunnel configuration.

In addition to the Linux IPv6 HOWTO, I have found the following two books to be useful:

- *IPv6 Essentials*, Silvia Hagen, 2002, O'Reilly Media, Inc, ISBN 0-596-00125-8.

  O'Reilly published a second edition of this book in 2006.

- *IPV6 Theory, Protocol, and Practice*, Second Edition, Pete Loshin, 2004, Morgan-Kaufmann Publishers, IBSN 1-55860-820-9
