# Virtual Private Networking (VPN)

It is often the case that a system behind the firewall needs to be able to access a remote network through Virtual Private Networking (VPN). The two most common means for doing this are IPsec and PPTP. The basic setup is shown in the following diagram:

A system with an RFC 1918 address needs to access a remote network through a remote gateway. For this example, we will assume that the local system has IP address 192.168.1.12 and that the remote gateway has IP address 192.0.2.224.

If PPTP is being used and you need to have two or more local systems connected to the same remote server at the same time, then you should be sure that the PPTP helpers modules are loaded (ip_conntrack_pptp and ip_nat_pptp or nf_conntrack_pptp and nf_nat_pptp). Using the default modules file, Shorewall (Lite) will attempt to load these modules when Shorewall (Lite) is started.

If IPsec is being used, you should configure IPsec to use NAT Traversal -- Under NAT traversal the IPsec packets (protocol 50 or 51) are encapsulated in UDP packets (normally with destination port 4500). Additionally, keep-alive messages are sent frequently so that NATing gateways between the end-points will retain their connection-tracking entries. This is the way that I connect to the HP Intranet and it works flawlessly without anything in Shorewall other than my ACCEPT loc-\>net policy. NAT traversal is available as a patch for Windows 2K and is a standard feature of Windows XP -- simply select "L2TP IPsec VPN" from the "Type of VPN" pulldown.

Alternatively, if you have an IPsec gateway behind your firewall then you can try the following: only one system may connect to the remote gateway and there are firewall configuration requirements as follows:

| ACTION | SOURCE          | DEST             | PROTO | DPORT | SPORT | ORIGDEST |
|--------|-----------------|------------------|-------|-------|-------|----------|
| DNAT   | net:192.0.2.224 | loc:192.168.1.12 | 50    |       |       |          |
| DNAT   | net:192.0.2.224 | loc:192.168.1.12 | udp   | 500   |       |          |

/etc/shorewall/rules

The above may or may not work — your mileage may vary. NAT Traversal is definitely a better solution. To use NAT traversal:

| ACTION | SOURCE          | DEST             | PROTO | DPORT | SPORT | ORIGDEST |
|--------|-----------------|------------------|-------|-------|-------|----------|
| DNAT   | net:192.0.2.224 | loc:192.168.1.12 | udp   | 4500  |       |          |
| DNAT   | net:192.0.2.224 | loc:192.168.1.12 | udp   | 500   |       |          |

/etc/shorewall/rules with NAT Traversal

If you want to be able to give access to all of your local systems to the remote network, you should consider running a VPN client on your firewall. As starting points, see [The /etc/shorewall/tunnels manpage](https://shorewall.org/manpages/shorewall-tunnels.html).
