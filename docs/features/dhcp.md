<div class="note">

For most operations, DHCP software interfaces to the Linux IP stack at a level below Netfilter. Hence, Netfilter (and therefore Shorewall) cannot be used effectively to police DHCP. The “dhcp” interface option described in this article allows for Netfilter to stay out of DHCP's way for those operations that can be controlled by Netfilter and prevents unwanted logging of DHCP-related traffic by Shorewall-generated Netfilter logging rules.

</div>

# If you want to Run a DHCP Server on your firewall

- Specify the “dhcp” option on each interface to be served by your server in the `/etc/shorewall/interfaces` file. This will generate rules that will allow DHCP to and from your firewall system.

- When starting “dhcpd”, you need to list those interfaces on the run line. On a RedHat system, this is done by modifying `/etc/sysconfig/dhcpd`.

- If you set 'ping-check' true in your `/etc/dhcp/dhcpd.conf` file then you will want to [accept 'ping'](ping.md) from your firewall to the zone(s) served by the firewall's DHCP server.

# If a Firewall Interface gets its IP Address via DHCP

- Specify the “dhcp” option for this interface in the [`/etc/shorewall/interfaces`](https://shorewall.org/manpages/shorewall-interfaces.html) file. This will generate rules that will allow DHCP to and from your firewall system.

- If you know that the dynamic address is always going to be in the same subnet, you can specify the subnet address in the interface's entry in the [`/etc/shorewall/interfaces`](https://shorewall.org/manpages/shorewall-interfaces.html) file.

- If you don't know the subnet address in advance, you should specify “detect” for the interface's subnet address in the [`/etc/shorewall/interfaces`](https://shorewall.org/manpages/shorewall-interfaces.html) file and start Shorewall after the interface has started.

- In the event that the subnet address might change while Shorewall is started, you need to arrange for a `shorewall reload` command to be executed when a new dynamic IP address gets assigned to the interface. Check your DHCP client's documentation.

- It is a good idea to [accept 'ping'](ping.md) on any interface that gets its IP address via DHCP. That way, if the DHCP server is configured with 'ping-check' true, you won't be blocking its 'ping' requests.

# If you wish to pass DHCP requests and responses through a bridge

- Specify the “dhcp” option for the bridge interface in the [`/etc/shorewall/interfaces`](https://shorewall.org/manpages/shorewall-interfaces.html) file. This will generate rules that will allow DHCP to and from your firewall system as well as through the bridge.

# Running dhcrelay on the firewall

- Specify the "dhcp" option (in `/etc/shorewall/interfaces`) on the interface facing the DHCP server and on the interfaces to be relayed.

- Allow UDP ports 67 and 68 ("67:68") between the client zone and the server zone:

      #ACTION        SOURCE        DEST        PROTO       DPORT
      ACCEPT         ZONEA         ZONEB       udp         67:68
      ACCEPT         ZONEB         ZONEA       udp         67:68

  Alternatively, use the DHCPfwd macro:

      #ACTION         SOURCE        DEST        PROTO       DPORT
      DHCPfwd(ACCEPT) ZONEA         ZONEB

- If the server is configured with 'ping-check' true, then you must [allow 'ping'](ping.md) from the server's zone to the zone(s) served by dhcrelay.
