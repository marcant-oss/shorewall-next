# Introduction

Kernel-mode Virtual Machines (<http://kvm.qumranet.com/>) is a virtualization platform that leverages the virtualization capabilities available with current microprocessors from both Intel and AMD. For an overview of KVM, please see my [2008 Linuxfest Northwest presentation](https://shorewall.org/Linuxfest-2008.pdf).

I use KVM to implement a number of virtual machines running various Linux Distributions. The following diagram shows the entire network.

My personal laptop (Ursa) hosts the virtual machines. As shown in the diagram, Ursa has routes to the Internet through both the Linksys WRT300N and through my Shorewall firewall. This allows me to test the [Shorewall Multi-ISP feature](MultiISP.md).

The Linux Bridges shown in the diagram are, of course, actually within their associated system (Firewall or Ursa) but I've pictured them separately.

# Networking Configuration

I use a network configuration where each VM has its own VNET and tap device and the tap devices are all configured as ports on a Linux Bridge. For clarity, I've only shown four of the virtual machines available on the system.

I run [dmsmasq](???) to act as a DHCP server and name server for the VMs.

The bridge is configured using the script described in my Linuxfest presentation linked above. The script may be found at <https://shorewall.org/pub/shorewall/contrib/kvm/kvm>.

With this configuration, and with only a single network interface on the laptop, this is just a simple [two-interface masquerading setup](../reference/two-interface.md) where the local network interface is `br0`. As with all bridges, `br0` must be configured with the `routeback` option in [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html)(5).

For additional information about this setup, including the Shorewall configuration, see [https://shorewall.org/MultiISP.html#Shared](MultiISP.md#Shared)
