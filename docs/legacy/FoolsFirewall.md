# Definition

Occasionally, we hear from someone who has cabled his firewall's external and internal firewall interfaces to the same unmanaged switch (or mis-configured managed switch). I call this configuration The Fool's Firewall.

When the external interface supports broadcast, this configuration has two very bad drawbacks:

1.  It is very insecure

2.  Both the up-stream router and the local systems can send incoming packets to the wrong interface.

# Security Issue

Because Fool's firewall is not physically located between the net and the local systems, the local systems are exposed to all of the systems in the same broadcast domain. Because the local systems (especially those running Windows) send broadcasts, those systems can be easily detected by using a packet sniffer. Once the systems have been spotted, it is child's play to add an IP address in Fool's internal IP network and bypass his "Firewall".

# ARP Roulette

The Linux IP stack implements the [weak host model.](http://en.wikipedia.org/wiki/Host_model) As a result, it exhibits some unexpected behavior with respect to ARP. It will respond to ARP 'who-has' requests received on *any* interface and not just on the interface owning the address. So when the upstream router sends a 'who-has' request for Fool's external IP address, the response may come from his *internal* interface (and reflect the MAC address of that interface). When that happens, packets from the net start entering the firewall's internal interface.

A similar problem can occur when a local system sends to the "Firewall" or to the Net. The packets may arrive on the firewall through the *external* interface.
