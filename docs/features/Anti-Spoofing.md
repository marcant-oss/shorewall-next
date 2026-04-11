# Introduction

Spoofing is the practice of sending packets with a forged source address in an attempt to circumvent security measures. Shorewall supports a variety of measures to counter spoofing attacks.

# The *routefilter* Interface Option

This [shorewall-interfaces](???) (5) option was the first measure implemented and uses `/proc/sys/net/ipv4/conf/*/rp_filter`. Many distributions set this option by default for all ip interfaces. The option works by determining the reverse path (the route from the packets destination to its source); it that route does not go out through the interface that received the packet, then the packet is declared to be a martian and is dropped. A kernel log message is generated if the interface's `logmartians` option is set (`/proc/sys/net/ipv4/conf/*/log_martians`).

While this option is simple to configure, it has a couple of disadvantages:

- It is not supported by IPv6.

- It does not use packet marks so it doesn't work with some [Multi-ISP](MultiISP.md) configurations.

- The log messages produces are obscure and confusing.

# Hairpin Filtering

Spoofing can be used to exploit Netfilter's connection tracking to open arbitrary firewall ports. Attacks of this type establish a connection to a server that uses separate control and data connections such as an FTP server. It then sends a packet addressed to itself and from the server. Such packets are sent back out the same interface that received them (hairpin). In cases where the `routefilter` option can't be used, Shorewall 4.4.20 and later will set up hairpinning traps (see the SFILTER_DISPOSITION and SFILTER_LOG_LEVEL options in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5)).

This automatic hairpin trapping is disabled on interfaces with the `routeback` option.

# The *rpfilter* Interface Option

A new iptables/ip6tables match (rpfilter) was added in kernel 3.4.4. This match performs reverse path evaluation similar to `routefilter` but without the disadvantages:

- It is supported by both IPv4 and IPv6.

- It uses packet marks so it works with all [Multi-ISP](MultiISP.md) configurations.

- It produces standard Shorewall/Netfilter log messages controlled by the RPFILTER_LOG_LEVEL option in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5)).

- Both the disposition and auditing can be controlled using the RPFILTER_DISPOSITION option in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5)).
