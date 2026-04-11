<div class="warning">

2006-01-17. The ECN Netfilter target in some 2.6 Linux Kernels is broken. Symptoms are that you will be unable to establish a TCP connection to hosts defined in the /etc/shorewall/ecn file.

</div>

# Explicit Congestion Notification (ECN)

Explicit Congestion Notification (ECN) is described in RFC 3168 and is a proposed Internet standard. Unfortunately, not all sites support ECN and when a TCP connection offering ECN is sent to sites that don't support it, the result is often that the connection request is ignored.

To allow ECN to be used, Shorewall allows you to enable ECN on your Linux systems then disable it in your firewall when the destination matches a list that you create (the /etc/shorewall/ecn file).

You enable ECN by

    echo 1 > /proc/sys/net/ipv4/tcp_ecn

You must arrange for that command to be executed at system boot. Most distributions have a method for doing that -- on RedHat, you make an entry in /etc/sysctl.conf.

    net.ipv4.tcp_ecn = 1

Entries in /etc/shorewall/ecn have two columns as follows:

INTERFACE  
The name of an interface on your system

HOST(S)  
An address (host or subnet) of a system or group of systems accessed through the interface in the first column. You may include a comma-separated list of such addresses in this column.

| INTERFACE | HOST(S)      |
|-----------|--------------|
| eth0      | 192.0.2.0/24 |

/etc/shorewall/ecn

Beginning with Shorewall 5.0.6, you may also specify clearing of the ECN flags through use of the ECN action in [shorewall-mangle(8)](https://shorewall.org/manpages/shorewall-ecn.html).
