# Features

- Uses Netfilter's connection tracking facilities for stateful packet filtering.

- Can be used in **a wide range of router/firewall/gateway applications** .

  - Completely customizable using configuration files.

  - No limit on the number of network interfaces.

  - Allows you to partition the network into [zones](https://shorewall.org/manpages/shorewall-zones.html) and gives you complete control over the connections permitted between each pair of zones.

  - Multiple interfaces per zone and multiple zones per interface permitted.

  - Supports nested and overlapping zones.

- Supports **centralized firewall administration**.

  - Shorewall installed on a single administrative system. May be a Windows PC running Cygwin or an Apple MacIntosh running OS X.

  - Centrally generated firewall scripts run on the firewalls under control of [Shorewall-lite](../features/Shorewall-Lite.md).

- [QuickStart Guides (HOWTOs)](../reference/shorewall_quickstart_guide.md) to help get your first firewall up and running quickly

- A **GUI** is available via Webmin 1.060 and later (<http://www.webmin.com>)

- Extensive **[documentation](../legacy/Documentation_Index.md)** is available in both Docbook XML and HTML formats.

- **Flexible address management/routing support** (and you can use all types in the same firewall):

  - [Masquerading/SNAT](https://shorewall.org/manpages/shorewall-masq.html).

  - [Port Forwarding (DNAT)](../reference/FAQ.md#faq1).

  - [One-to-one NAT](../features/NAT.md).

  - [Proxy ARP](../features/ProxyARP.md).

  - [NETMAP](../features/netmap.md).

  - [Multiple ISP support](../features/MultiISP.md) (Multiple Internet Links from the same firewall/gateway)

- [**Blacklisting**](../legacy/blacklisting_support.md) of individual IP addresses and subnetworks is supported.

- [Operational Support](../reference/starting_and_stopping_shorewall.md).

  - Commands to start, stop and clear the firewall

  - Supports status monitoring with an audible alarm when an “interesting” packet is detected.

  - Wide variety of informational commands.

- **VPN Support**.

  - [IPsec, GRE, IPIP and OpenVPN Tunnels](https://shorewall.org/manpages/shorewall-tunnels.html).

  - [PPTP](../features/PPTP.md) clients and Servers.

- Support for [**Traffic** Control/**Shaping**](../features/simple_traffic_shaping.md).

- Wide support for different **GNU/Linux Distributions**.

  - [RPM](../reference/Install.md#Install_RPM) and [Debian](http://www.debian.org) packages available.

  - Includes automated [install, upgrade and uninstall facilities](../reference/Install.md) for users who can't use or choose not to use the RPM or Debian packages.

  - Included as a standard part of [LEAF/Bering](http://leaf.sourceforge.net/devel/jnilo) (router/firewall on a floppy, CD or compact flash).

- [Media Access Control (**MAC**) Address **Verification**](../features/MAC_Validation.md).

- **[Traffic Accounting](../features/Accounting.md).**

- [**Bridge**/Firewall support](../legacy/bridge-Shorewall-perl.md)

- [**IPv6** Support](../features/IPv6Support.md)

- Works with a wide range of **Virtualization** Solutions:

  - [**KVM**](../features/KVM.md)

  - [**Xen**](../legacy/XenMyWay-Routed.md)

  - [**Linux-Vserver**](../legacy/Vserver.md)

  - [**OpenVZ**](../legacy/OpenVZ.md)

  - VirtualBox

  - [LXC](../features/LXC.md)

  - Docker (Shorewall 5.0.6 and later)
