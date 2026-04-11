White lists are most often used to give special privileges to a set of hosts within an organization. Let us suppose that we have the following environment:

- A firewall with three interfaces -- one to the Internet, one to a local network and one to a DMZ.
- The local network uses SNAT to the Internet and is comprised of the Class B network `10.10.0.0/16` (Note: While this example uses an RFC 1918 local network, the technique described here in no way depends on that or on SNAT. It may be used with Proxy ARP, Subnet Routing, Static NAT, etc.).
- The network operations staff have workstations with IP addresses in the Class C network `10.10.10.0/24`.
- We want the network operations staff to have full access to all other hosts.
- We want the network operations staff to bypass the transparent HTTP proxy running on our firewall.

The basic approach will be that we will place the operations staff's class C in its own zone called ops. Here are the appropriate configuration files:

**Zone File**

    #ZONE      TYPE          OPTIONS
    fw         firewall
    net        ipv4
    ops        ipv4
    loc        ipv4
    dmz        ipv4

The `ops` zone has been added to the standard 3-zone zones file -- since `ops` is a sub-zone of `loc`, we list it *BEFORE* `loc`.

**Interfaces File**

    #ZONE      INTERFACE        BROADCAST        OPTIONS
    net        eth0             <whatever>      ...
    dmz        eth1             <whatever>      ...
    -          eth2             10.10.255.255

Because `eth2` interfaces to two zones (`ops` and `loc`), we don't specify a zone for it here.

**Hosts File**

    #ZONE      HOST(S)                OPTIONS
    ops        eth2:10.10.10.0/24
    loc        eth2:0.0.0.0/0

Here we define the `ops` and `loc` zones. When Shorewall is stopped, only the hosts in the `ops` zone will be allowed to access the firewall and the DMZ. I use `0.0.0.0/0` to define the `loc` zone rather than `10.10.0.0/16` so that the limited broadcast address (`255.255.255.255`) falls into that zone. If I used `10.10.0.0/16` then I would have to have a separate entry for that special address.

**Policy File**

    #SOURCE          DEST         POLICY         LOGLEVEL
    ops              all          ACCEPT
    all              ops          CONTINUE
    loc              net          ACCEPT
    net              all          DROP           info
    all              all          REJECT         info

Two entries for `ops` (in bold) have been added to the standard 3-zone policy file.

**Rules File**

    #ACTION   SOURCE      DEST        PROTO        DPORT     SPORT    ORIGDEST
    REDIRECT  loc!ops     3128        tcp          http

This is the rule that transparently redirects web traffic to the transparent proxy running on the firewall. The **SOURCE** column explicitly excludes the `ops` zone from the rule.

**Routestopped File**

    #INTERFACE          HOST(S)           OPTIONS
    eth1
    eth2                10.10.10.0/24
