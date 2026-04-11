# Background

LXC (<http://lxc.sourceforge.net/>) is a set of user-space tools for managing the container capabilities that have been in the Linux Kernel since 2.6.27.

This short article describes how I've implemented LXC here at shorewall.net, with emphasis on the networking and firewall aspects.

# Overview of a Working Configuration

The following diagram shows the network at shorewall.net in the spring of 2011.

As shown in that diagram, the LXC containers are bridged to br0. Here are the relevant configuration entries.

`/etc/network/interfaces:`

    #
    # LXC bridge
    #
    auto br0
    iface br0 inet static
          bridge_ports none
          bridge_fd 0
          address 70.90.191.121
          broadcast 0.0.0.0
          netmask 255.255.255.255
          post-up ip route add 70.90.191.124/31 dev br0

    iface br0 inet6 static
          address 2001:470:b:227::41
          netmask 124

`/etc/lxc/mail.conf`

    lxc.network.type=veth
    lxc.network.link=br0
    lxc.network.flags=up

    lxc.network.ipv4=70.90.191.124/29
    lxc.network.ipv6=2001:470:b:227::42/124

    …

`/etc/lxc/server.conf`

    lxc.network.type=veth
    lxc.network.link=br0
    lxc.network.flags=up

    lxc.network.ipv4=70.90.191.125/29
    lxc.network.ipv6=2001:470:b:227::43/124

    …

Note that I have subnetted 2001:470:b:227::/64 with a /124 (2001:470:b:227::40/124) assigned to the bridge. To make those addresses accessible from the LOC zone, the following entries are required in /etc/shorewall6/proxyndp:

    #ADDRESS                INTERFACE       EXTERNAL        HAVEROUTE       PERSISTENT
    2001:470:b:227::41  -       eth1        Yes     Yes
    2001:470:b:227::42  -       eth1        Yes     Yes
    2001:470:b:227::43  -       eth1        Yes     Yes

The entries in the LXC .conf files are expected to configure eth0 in the LXC containers; they do, *sort of*. In both of the containers, no ipv6 default route was assigned. I corrected that by adding this entry in `/etc/sysctl.conf` in both containers:

    net.ipv6.conf.all.forwarding=0

I then added this stanza to `/etc/radvd.conf` on the host:

    interface br0{
        AdvSendAdvert on;
        MinRtrAdvInterval 300;
        MaxRtrAdvInterval 505;
        AdvDefaultLifetime 9000;

        route ::/0 {
            AdvRouteLifetime infinity;
        };
    };

Curiosly, LXC gives container mail's eth0 this somewhat odd configuration, and fails to add a default ipv4 route:

    14: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
        link/ether 4e:56:66:11:3c:6b brd ff:ff:ff:ff:ff:ff
        inet 70.90.191.124/29 brd 70.90.191.120 scope global eth0
        inet6 2001:470:b:227::42/124 scope global 
           valid_lft forever preferred_lft forever
        inet6 fe80::4c56:66ff:fe11:3c6b/64 scope link 
           valid_lft forever preferred_lft forever

So in that container's`/etc/rc.local`, I also have:

    ip route add default via 70.90.191.121

With the exception of the entries in `/etc/shorewall6/proxyndp`. the Shorewall and Shorewall6 configurations are fairly conventional three-interface setups. In both configurations, the `interfaces` file entry for br0 has the `routeback` option specified.
