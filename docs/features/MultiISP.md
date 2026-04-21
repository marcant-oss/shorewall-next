<div class="warning">

This document describes the Multi-ISP facility in **Shorewall 4.4.26 and later**. If you are running an earlier release, please see the documentation for that release.

</div>

<div class="warning">

Reading just Shorewall documentation is probably not going to give you enough background to use this material. Shorewall may make iptables easy but the Shorewall team doesn't have the resources to be able to spoon-feed Linux policy routing to you (please remember that the user's manual for a tractor doesn't teach you to grow corn either). You will likely need to refer to the following additional information:

- The LARTC HOWTO: <http://comparitech.net/lartc>

- Output of `man ip`

- Output of `ip route help` and `ip rule help`

</div>

# Multiple Internet Connection Support

Shorewall includes limited support for multiple Internet connections. Limitations of this support are as follows:

- It utilizes static routing configuration. If there is a change in the routing topopogy, Shorewall must be restarted.

- The routing changes are made and the route cache is purged when Shorewall is started **and when Shorewall is restarted** (unless you specify the "-n" option to `shorewall restart`). Ideally, restarting the packet filter should have no effect on routing.

- For most routing applications, [Quagga](http://www.quagga.net/) is a better solution although it requires that your ISPs offer routing protocol support.

## Overview

Let's assume that a firewall is connected via two separate Ethernet interfaces to two different ISPs.[^1] as in the following diagram.

- eth0 connects to ISP1. The IP address of eth0 is 206.124.146.176 and the ISP's gateway router has IP address 206.124.146.254.

- eth1 connects to ISP 2. The IP address of eth1 is 130.252.99.27 and the ISP's gateway router has IP address 130.252.99.254.

- eth2 connects to the local LAN. Its IP configuration is not relevant to this discussion.

Each of these providers is described in an entry in the file `/etc/shorewall/providers`.

Entries in `/etc/shorewall/providers` can specify that outgoing connections are to be load-balanced between the two ISPs. Entries in `/etc/shorewall/mangle` and `/etc/shorewall/rtrules` can be used to direct particular outgoing connections to one ISP or the other. Use of `/etc/shorewall/mangle` (or `/etc/shorewall/tcrules`) is not required for `/etc/shorewall/providers` to work, but in most cases, you must select a unique MARK value for each provider so Shorewall can set up the correct marking rules for you.

<div class="important">

`/etc/shorewall/mangle` superseded `/etc/shorewall/tcrules` in Shorewall 4.6.0.

</div>

When you use the **track** option in `/etc/shorewall/providers`, connections from the Internet are automatically routed back out of the correct interface and through the correct ISP gateway. This works whether the connection is handled by the firewall itself or if it is routed or port-forwarded to a system behind the firewall.

Shorewall will set up the routing and will update the `/etc/iproute2/rt_tables` to include the table names and numbers of the tables that it adds.

<div class="caution">

This feature uses [packet marking](traffic_shaping.md) to control the routing. As a consequence, there are some restrictions concerning entries in `/etc/shorewall/mangle`:

- Packet marking for traffic control purposes may not be done in the PREROUTING table for connections involving providers with 'track' specified (see below).

- You may not use the SAVE or RESTORE options unless you also set HIGH_ROUTE_MARKS=Yes (PROVIDER_OFFSET \> 0 with Shorewall 4.4.26 and later) in `/etc/shorewall/shorewall.conf`.

  <div class="note">

  In Shorewall 4.4.26, the HIGH_ROUTE_MARKS and WIDE_TC_MARKS options in `/etc/shorewall/shorewall.conf` were replaced by the PROVIDER_OFFSET and TC_BITS options. Look [here](PacketMarking.md#Values) for details.

  </div>

- You may not use connection marking unless you also set HIGH_ROUTE_MARKS=Yes (PROVIDER_OFFSET \> 0 with Shorewall 4.4.26 and later) in `/etc/shorewall/shorewall.conf`.

</div>

The `/etc/shorewall/providers` file can also be used in other routing scenarios. See the [Squid documentation](Shorewall_Squid_Usage.md) for an example.

## USE_DEFAULT_RT

The behavior and configuration of Multiple ISP support is dependent on the setting of USE_DEFAULT_RT in shorewall\[6\].conf.

When USE_DEFAULT_RT=Yes, packets are first routed through the main routing table *which does not contain a default route*. Packets which fail to be routed by an entry in the main table are then passed to shorewall-defined routing tables based on your Multi-ISP configuration. The advantage of this approach is that dynamic changes to the ip configuration, such as VPNs going up and down, do not require notificaiton of Shorewall. USE_DEFAULT_RT is now the default and use of USE_DEFAULT_RT=No is deprecated.

When USE_DEFAULT_RT=No, packets are routed via Shorewall-generated routing tables. As a consequence, the main routing table must be copied into each of those tables and must be recopied when there is a change to the main table. This can only be accomplished via a `shorewall[6] reload` or `restart` command.

## /etc/shorewall/providers File

Entries in this file have the following columns. As in all Shorewall configuration files, enter "-" in a column if you don't want to enter any value.

NAME  
The provider name. Must begin with a letter and consist of letters and digits. The provider name becomes the name of the generated routing table for this provider.

NUMBER  
A number between 1 and 252. This becomes the routing table number for the generated table for this provider.

MARK  
A mark value used in your`/etc/shorewall/mangle`file to direct packets to this provider. Shorewall will also mark connections that have seen input from this provider with this value and will restore the packet mark in the PREROUTING CHAIN. Mark values must be in the range 1-255.

Alternatively, you may set HIGH_ROUTE_MARKS=Yes (PROVIDER_OFFSET \> 0 with Shorewall 4.4.26 and later) in `/etc/shorewall/shorewall.conf`. This allows you to:

- Use connection marks for traffic shaping, provided that you assign those marks in the FORWARD chain.

- Use mark values \> 255 for provider marks in this column.

  - With HIGH_ROUTE_MARKS=Yes (PROVIDER_OFFSET=8), these mark values must be a multiple of 256 in the range 256-65280 (hex equivalent 0x100 - 0xFF00 with the low-order 8 bits being zero); or

  - Set WIDE_TC_MARKS=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5) (PROVIDER_OFFSET=16), and use mark values in the range 0x10000 - 0xFF0000 with the low-order 16 bits being zero.

This column may be omitted if you don´t use packet marking to direct connections to a particular provider.

DUPLICATE  
Gives the name or number of a routing table to duplicate. May be 'main' or the name or number of a previously declared provider. This field should be be specified as '-' when USE_DEFAULT_RT=Yes in `shorewall.conf. When USE_DEFAULT_RT=No (not recommended), this column is normally specified as main.`

INTERFACE  
The name of the interface to the provider. Where multiple providers share the same interface, you must follow the name of the interface by a colon (":") and the IP address assigned by this provider (e.g., eth0:206.124.146.176). See [below](#Shared) for additional considerations.

The interface must have been previously defined in [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html) (5). In general, that interface should not have the `proxyarp` option specified unless `loose` is given in the OPTIONS column of this entry.

GATEWAY  
The IP address of the provider's Gateway router.

You can enter **detect** here and Shorewall will attempt to automatically determine the gateway IP address.

**Hint:** **"detect"** is appropriate for use in cases where the interface named in the INTERFACE column is dynamically configured via DHCP etc. Be sure, however, that you don't have stale dhcp client state files in `/var/lib/dhcpcd`or `/var/lib/dhclient-*.lease` because Shorewall may try to use those stale files to determine the gateway address.

If Shorewall is unable to detect the gateway, it is likely because you are using a DHCP client that Shorewall doesn't natively support. You can work around that issue by using the **findgw** [extension script.](../reference/shorewall_extension_scripts.md)

For example, these examples from Mika Ilmaranta, work with RHEL7-based systems with nmcli:

    nmcli --terse --fields IP6.GATEWAY device show ${1} | cut -f2- -d':' # IPv6

    nmcli --terse --fields IP4.GATEWAY device show ${1} | cut -f2- -d':' #IPv4

This one from PGNd works on OpenSuSE running wicked:

    svc_status=$( systemctl is-active wickedd-dhcp4.service )

    if [ $svc_status == 'active' ]; then
      data="/var/lib/wicked/lease-${1}-dhcp-ipv4.xml"
      if [ -f $data ]; then
        gateway=$( xml_grep 'gateway' $data --text_only )
        echo $gateway
      fi
    fi

The GATEWAY may be omitted (enter '-') for point-to-point links.

OPTIONS  
A comma-separated list from the following:

track  
<div class="important">

Beginning with Shorwall 4.3.3, **track** defaults to the setting of the `TRACK_PROVIDERS` option in [shorewall.conf](manpages/shorewall.conf) (5). To disable this option when you have specified TRACK_PROVIDERS=Yes, you must specify **notrack** (see below).

</div>

If specified, connections FROM this interface are to be tracked so that responses may be routed back out this same interface.

You want to specify 'track' if Internet hosts will be connecting to local servers through this provider. Any time that you specify 'track', you will normally want to also specify 'balance' (see below). 'track' will also ensure that outgoing connections remain stay anchored to a single provider and don't try to switch providers when route cache entries expire.

Use of this feature requires that your kernel and iptables include CONNMARK target and connmark match support (**Warning**: Until recently, standard Debian and Ubuntu kernels lacked that support. *Both Lenny and Jaunty do have the proper support*).

<div class="important">

If you are running a version of Shorewall earlier than 4.4.3 and are using `/etc/shorewall/providers` because you have multiple Internet connections, we recommend that you specify **track** even if you don't need it. It helps maintain long-term connections in which there are significant periods with no traffic.

</div>

balance  
The providers that have **balance** specified will get outbound traffic load-balanced among them. Balancing will not be perfect, as it is route based, and routes are cached. This means that routes to often-used sites will always be over the same provider.

By default, each provider is given the same weight (1) . You can change the weight of a given provider by following **balance** with "=" and the desired weight (e.g., balance=2). The weights reflect the relative bandwidth of the providers connections and should be small numbers since the kernel actually creates additional default routes for each weight increment.

<div class="important">

If you are using `/etc/shorewall/providers` because you have multiple Internet connections, we recommend that you specify **balance** even if you don't need it. You can still use entries in `/etc/shorewall/mangle` and `/etc/shorewall/rtrules` to force all traffic to one provider or another.

<div class="note">

If you don't heed this advice then please read and follow the advice in [FAQ 57](../reference/FAQ.md#faq57) and [FAQ 58](../reference/FAQ.md#faq58).

</div>

</div>

Prior to Shorewall 5.1.1, **balance=1** is the default when USE_DEFAULT_RT=Yes and neither the `fallback`, `loose`, `load` or `tproxy` option is specified. Beginning with Shorewall 5.1.1, **balance=1** is the default when both USE_DEFAULT_RT=Yes and BALANCE_PROVIDERS=Yes and neither the `fallback`, `loose`, `load` nor `tproxy` option is specified.

loose  
Do not generate routing rules that force traffic whose source IP is an address of the INTERFACE to be routed to this provider. Useful for defining providers that are to be used only when the appropriate packet mark is applied.

Shorewall makes no attempt to consolidate the routing rules added when **loose** is not specified. So, if you have multiple IP addresses on a provider interface, you may be able to replace the rules that Shorewall generates with one or two rules in `/etc/shorewall/rtrules`. In that case, you can specify **loose** to suppress Shorewall's rule generation. See the [example](#Complete) below.

notrack  
Added in Shorewall 4.4.3. This option turns off the **track** option.

optional  
<div class="note">

This option is deprecated in favor of the `optional` [interface option](https://shorewall.org/manpages/shorewall-interfaces.html). That option performs the same function.

</div>

Shorewall will determine if this interface is up and has a configured IP address. If it is not, a warning is issued and this provider is not configured.

<div class="note">

**optional** is designed to detect interface states that will cause `shorewall start` or `shorewall restart` to fail; just because an interface is in a state that Shorewall can \[re\]start without error doesn't mean that traffic can actually be sent through the interface.

You can supply an 'isusable' [extension script](../reference/shorewall_extension_scripts.md) to extend Shorewall's interface state detection. See also the [Gateway Monitoring and Failover](#LinkMonitor) section below.

</div>

primary  
Added in Shorewall 4.6.6, **primary** is a synonym for **balance=1** and is preferred when the remaining providers specify **fallback** or **tproxy**.

src=\<source-address\>  
Specifies the source address to use when routing to this provider and none is known (the local client has bound to the 0 address). May not be specified when an \<address\> is given in the INTERFACE column. If this option is not used, Shorewall substitutes the primary IP address on the interface named in the INTERFACE column.

mtu=\<number\>  
Specifies the MTU when forwarding through this provider. If not given, the MTU of the interface named in the INTERFACE column is assumed.

fallback\[=\<weight\>\]  
Indicates that a default route through the provider should be added to the default routing table (table 253). If a \<weight\> is given, a balanced route is added with the weight of this provider equal to the specified \<weight\>. If the option is given without a \<weight\>, a separate default route is added through the provider's gateway; the route has a metric equal to the provider's NUMBER.

Prior to Shorewall 4.4.24, the option is ignored with a warning message if USE_DEFAULT_RT=Yes in `shorewall.conf`.

<div class="warning">

If you set this option on an interface, you must disable route filtering on the interface. Include 'routefilter=0,logmartions=0' in the OPTIONS column of [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html)(5).

</div>

For those of you who are confused between **track** and **balance**:

- **track** governs incoming connections (but is also useful for binding long-running connections to the same interface).

- **balance** governs outgoing connections.

COPY  
A comma-separated list of other interfaces on your firewall. Wildcards specified using an asterisk ("\*") are permitted (e.g., tun\* ). Usually used only when DUPLICATE is `main`. Only copy routes through INTERFACE and through interfaces listed here. If you only wish to copy routes through INTERFACE, enter `none` in this column.

<div class="note">

Beginning with Shorewall 4.4.15, provider routing tables can be augmeted with additional routes through use of the [/etc/shorewall/routes](#routes) file.

</div>

## What an entry in the Providers File Does

Adding another entry in the providers file simply creates an alternate routing table for you (see the [LARTC Howto](http://www.lartc.org)). The table will usually contain two routes:

1.  A host route to the specified GATEWAY through the specified INTERFACE.

2.  A default route through the GATEWAY.

Note that the first route is omitted if "-" is specified as the GATEWAY; in that case, the default route does not specify a gateway (point-to-point link).

If the DUPLICATE column is non-empty, then routes from the table named in that column are copied into the new table. By default, all routes (except default routes) are copied. The set of routes copied can be restricted using the COPY column which lists the interfaces whose routes you want copied. You will generally want to include all local interfaces in this list. You should exclude the loopback interface (lo) and any interfaces that do not have an IP configuration. You should also omit interfaces like **tun** interfaces that are created dynamically. Traffic to networks handled by those interfaces should be routed through the main table using entries in `/etc/shorewall/rtrules` (see Example 2 [below](#Examples)) or by using [USE_DEFAULT_RT=Yes](#USE_DEFAULT_RT) (recommended)

In addition:

1.  Unless **loose** is specified, an ip rule is generated for each IP address on the INTERFACE that routes traffic from that address through the associated routing table.

2.  If you specify **track**, then connections which have had at least one packet arrive on the interface listed in the INTERFACE column have their connection mark set to the value in the MARK column. In the PREROUTING chain, packets with a connection mark have their packet mark set to the value of the associated connection mark; packets marked in this way bypass any prerouting rules that you create in `/etc/shorewall/mangle`. This ensures that packets associated with connections from outside are always routed out of the correct interface.

3.  If you specify **balance**, then Shorewall will replace the 'default' route with weight 100 in the 'main' routing table with a load-balancing route among those gateways where **balance** was specified. So if you configure default routes, be sure that their weight is less than 100 or the route added by Shorewall will not be used.

That's **all** that these entries do. You still have to follow the principle stated in the [Shorewall Routing documentation](Shorewall_and_Routing.md):

1.  Routing determines where packets are to be sent.

2.  Once routing determines where the packet is to go, the firewall (Shorewall) determines if the packet is allowed to go there and controls rewriting of the SOURCE IP address (SNAT/MASQUERADE).

The bottom line is that if you want traffic to go out through a particular provider then you *must* mark that traffic with the provider's MARK value in `/etc/shorewall/mangle` and you must do that marking in the PREROUTING chain; or, you must provide the appropriate rules in `/etc/shorewall/rtrules`.

## What an entry in the Providers File Does Not Do

Shorewall itself provides no mechanism for dealing with provider links that are in the up state but not responsive. If you want transparent failover when a link is unresponsive, you must configure all provider interfaces as **optional** ([shorewall-interfaces(5)](https://shorewall.org/manpages/shorewall-interfaces.html)) then [install and configure FOOLSM](#LinkMonitor).

Shorewall-init (shorewall-init documentation was not ported to shorewall-nft) provides for handling links that go hard down and are later brought back up.

## ./etc/shorewall/masq (/etc/shorewall/snat) and Multi-ISP

If you masquerade a local network, you will need to add masquerade rules for both external interfaces. Referring to the diagram above, if each of the interfaces has only a single IP address and you have no systems with public IP addresses behind your firewall, then I suggest the following simple entries:

    #INTERFACE       SOURCE            ADDRESS
    eth0             0.0.0.0/0         206.124.146.176
    eth1             0.0.0.0/0         130.252.99.27

When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

    #ACTION                SOURCE          DEST                PROTO   PORT
    SNAT(206.124.146.176)  0.0.0.0/0       eth0
    SNAT(130252.99.27)     0.0.0.0/0       eth1

If you have a public subnet (for example 206.124.146.176/30) behind your firewall, then use exclusion:

    #INTERFACE       SOURCE               ADDRESS
    eth0             !206.124.146.176/29  206.124.146.176
    eth1             0.0.0.0/0            130.252.99.27

The equivalent `/etc/shorewall/snat` is:

    #ACTION                SOURCE              DEST                PROTO   PORT
    SNAT(206.124.146.176)  !206.124.146.176/29 eth0
    SNAT(130.252.99.27)    0.0.0.0/0           eth1

Note that exclusion is only used on the interface corresponding to internal subnetwork.

If you have multiple IP addresses on one of your interfaces, you can use a similar technique -- simplY exclude the smallest network that contains all of those addresses from being masqueraded.

<div class="warning">

Entries in `/etc/shorewall/masq` (`/etc/shorewall/snat`) have no effect on which ISP a particular connection will be sent through. That is rather the purpose of entries in `/etc/shorewall/mangle` and `/etc/shorewall/rtrules`.

</div>

## Martians

One problem that often arises with Multi-ISP configuration is 'Martians'. If you set ROUTE_FILTER=Yes in `/etc/shorewall/shorewall.conf` or if your Internet interfaces are configured with the **routefilter** option in `/etc/shorewall/interfaces` (remember that if you set that option, you should also select **logmartians**), then things may not work correctly and you will see messages like this:

    Feb  9 17:23:45 gw.ilinx kernel: martian source 206.124.146.176 from 64.86.88.116, on dev eth1 
    Feb  9 17:23:45 gw.ilinx kernel: ll header: 00:a0:24:2a:1f:72:00:13:5f:07:97:05:08:00

The above message is somewhat awkwardly phrased. The source IP in this incoming packet was 64.86.88.116 and the destination IP address was 206.124.146.176. Another gotcha is that the incoming packet has already had the destination IP address changed for DNAT or because the original outgoing connection was altered by an entry in `/etc/shorewall/masq` or `/etc/shorewall/snat` (SNAT or Masquerade). So the destination IP address (206.124.146.176) may not have been the destination IP address in the packet as it was initially received.

There a couple of common causes for these problems:

1.  You have connected both of your external interfaces to the same hub/switch. Connecting multiple firewall interfaces to a common hub or switch is always a bad idea that will result in hard-to-diagnose problems.

2.  You are specifying both the **loose** and **balance** options on your provider(s). This can cause individual connections to ping-pong back and forth between the interfaces which is almost guaranteed to cause problems.

3.  You are redirecting traffic from the firewall system out of one interface or the other using packet marking in your `/etc/shorewall/mangle` file. A better approach is to configure the application to use the appropriate local IP address (the IP address of the interface that you want the application to use). See [below](#Local).

If all else fails, remove the **routefilter** option from your external interfaces. If you do this, you may wish to add rules to log and drop packets from the Internet that have source addresses in your local networks. For example, if the local LAN in the above diagram is 192.168.1.0/24, then you would add this rule:

    #ACTION          SOURCE                     DEST
    DROP:info        net:192.168.1.0/24         all

Be sure the above rule is added before any other rules with *net* in the SOURCE column.

<div class="important">

If you set ROUTE_FILTER=Yes in `/etc/shorewall/shorewall.conf`, then setting **routefilter**=0 in [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html) (5) will not disable route filtering on a given interface. You must set ROUTE_FILTER=No in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5), then set the **routefilter** option on those interfaces on which you want route filtering.

</div>

## Legacy Example

This section describes the legacy method of configuring multiple uplinks. It is deprecated in favor of the USE_DEFAULT_RT=Yes configuration described [below](#USE_DEFAULT_RT).

The configuration in the figure at the top of this section would be specified in `/etc/shorewall/providers` as follows.

    #NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS          COPY
    ISP1    1       1       main            eth0            206.124.146.254 track,balance    eth2
    ISP2    2       2       main            eth1            130.252.99.254  track,balance    eth2

Other configuration files go something like this:

`/etc/shorewall/interfaces`:

    #ZONE    INTERFACE    BROADCAST       OPTIONS
    net      eth0         detect          …          
    net      eth1         detect          …

`/etc/shorewall/policy`:

    #SOURCE    DESTINATION    POLICY     LOGLEVEL     LIMIT
    net        net            DROP

`/etc/shorewall/masq`:

    #INTERFACE       SOURCE            ADDRESS
    eth0             0.0.0.0/0         206.124.146.176
    eth1             0.0.0.0/0         130.252.99.27

## Example using USE_DEFAULT_RT=Yes

This section shows the differences in configuring the above example with USE_DEFAULT_RT=Yes. The changes are confined to the DUPLICATE and COPY columns of the providers file.

The configuration in the figure at the top of this section would be specified in `/etc/shorewall/providers` as follows.

    #NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS          COPY
    ISP1    1       1       -               eth0            206.124.146.254 track,balance    -
    ISP2    2       2       -               eth1            130.252.99.254  track,balance    -

Other configuration files go something like this:

`/etc/shorewall/interfaces`:

    #ZONE    INTERFACE    BROADCAST       OPTIONS
    net      eth0         detect          …          
    net      eth1         detect          …

`/etc/shorewall/policy`:

    #SOURCE    DESTINATION    POLICY     LOGLEVEL     LIMIT
    net        net            DROP

`/etc/shorewall/masq`:

    #INTERFACE       SOURCE            ADDRESS
    eth0             0.0.0.0/0         206.124.146.176
    eth1             0.0.0.0/0         130.252.99.27

When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

    #ACTION                SOURCE          DEST                PROTO   PORT
    SNAT(206.124.146.176)  0.0.0.0/0       eth0
    SNAT(130.252.99.27)    0.0.0.0/0       eth1

## Routing a Particular Application Through a Specific Interface

This continues the example in the preceding section.

Now suppose that you want to route all outgoing SMTP traffic from your local network through ISP 2. If you are running Shorewall 4.6.0 or later, you would make this entry in [/etc/shorewall/mangle](https://shorewall.org/manpages/shorewall-mangle.html).

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   USER    TEST
    MARK(2):P       <local network> 0.0.0.0/0       tcp     25

Note that traffic from the firewall itself must be handled in a different rule:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   USER    TEST
    MARK(2)         $FW             0.0.0.0/0       tcp     25

If you are running a Shorewall version earlier than 4.6.0, the above rules in [/etc/shorewall/tcrules](https://shorewall.org/manpages/shorewall-tcrules.html) would be:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   USER    TEST
    2:P             <local network> 0.0.0.0/0       tcp     25

And for traffic from the firewall:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   USER    TEST
    2               $FW             0.0.0.0/0       tcp     25

## Port Forwarding

Shorewall provides considerable flexibility for port forwarding in a multi-ISP environment.

Normal port forwarding rules such as the following will forward from both providers.

`/etc/shorewall/rules`:

    #ACTION        SOURCE             DEST              PROTO     DPORT            SPORT        ORIGDEST
    DNAT           net                loc:192.168.1.3   tcp       25

Continuing the above example, to forward only connection requests from ISP 1, you can either:

1.  Qualify the SOURCE by ISP 1's interface:

        #ACTION        SOURCE             DEST              PROTO     DPORT            SPORT        ORIGDEST
        DNAT           net:eth0           loc:192.168.1.3   tcp       25

    or

2.  Specify the IP address of ISP 1 in the ORIGDEST column:

        #ACTION        SOURCE             DEST              PROTO     DPORT            SPORT        ORIGDEST
        DNAT           net                loc:192.168.1.3   tcp       25               -            206.124.146.176

## More than 2 Providers

When there are more than two providers, you need to extend the two-provider case in the expected way:

1.  For each external address, you need an entry in `/etc/shorewall/masq` to handle the case where a connection using that address as the SOURCE is sent out of the interfaces other than the one that the address is configured on.

2.  For each external interface, you need to add an entry to `/etc/shorewall/masq` (`/etc/shorewall/snat`).

If we extend the above example to add eth3 with IP address 16.105.78.4 with gateway 16.105.78.254, then:

`/etc/shorewall/providers`:

    #NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS          COPY
    ISP1    1       1       main            eth0            206.124.146.254 track,balance    eth2
    ISP2    2       2       main            eth1            130.252.99.254  track,balance    eth2
    ISP3    3       3       main            eth3            16.105.78.254   track,balance    eth2

`/etc/shorewall/masq`:

    #INTERFACE       SUBNET            ADDRESS
    eth0             0.0.0.0/0         206.124.146.176
    eth1             0.0.0.0/0         130.252.99.27
    eth3             0.0.0.0/0         16.105.78.4

When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` is:

    #ACTION                SOURCE          DEST                PROTO   PORT
    SNAT(206.124.146.176)  0.0.0.0/0       eth0
    SNAT(130.252.99.27)    0.0.0.0/0       eth1
    SNAT(16.105.78.4)      0.0.0.0/0       eth2

## /etc/shorewall/rtrules (formerly /etc/shorewall/route_rules)

The `rtrules` file allows assigning certain traffic to a particular provider just as entries in the `mangle` file. The difference between the two files is that entries in `rtrules` are independent of Netfilter.

### Routing Rules

Routing rules are maintained by the Linux kernel and can be displayed using the `ip rule ls` command. When routing a packet, the rules are processed in turn until the packet is successfully routed.

    gateway:~ # ip rule ls
    0:      from all lookup local                <=== Local (to the firewall) IP addresses
    10001:  from all fwmark 0x1 lookup Blarg     <=== This and the next rule are generated by the
    10002:  from all fwmark 0x2 lookup Comcast        'MARK' values in /etc/shorewall/providers.
    20000:  from 206.124.146.176 lookup Blarg    <=== This and the next rule are generated unless
    20256:  from 24.12.22.33 lookup Comcast           'loose' is specified; based in the output of 'ip addr ls'
    32766:  from all lookup main                 <=== This is the routing table shown by 'iproute -n'
    32767:  from all lookup default              <=== This table is usually empty
    gateway:~ #

In the above example, there are two providers: Blarg and Comcast with MARK 1 going to Blarg and mark 2 going to Comcast.

### Columns in the rtrules file

Columns in the file are:

SOURCE (Optional)  
An ip address (network or host) that matches the source IP address in a packet. May also be specified as an interface name optionally followed by ":" and an address. If the device 'lo' is specified, the packet must originate from the firewall itself.

DEST (Optional)  
An ip address (network or host) that matches the destination IP address in a packet.

If you choose to omit either SOURCE or DEST, place "-" in that column. Note that you may not omit both SOURCE and DEST.

PROVIDER  
The provider to route the traffic through. May be expressed either as the provider name or the provider number.

PRIORITY  
The rule's priority which determines the order in which the rules are processed.

1000-1999 Before Shorewall-generated 'MARK' rules

11000- 11999 After 'MARK' rules but before Shorewall-generated rules for ISP interfaces.

26000-26999 After ISP interface rules but before 'default' rule.

Rules with equal priority are applied in the order in which they appear in the file.

MARK (Optional - added in Shorewall 4.4.25)  
Mark and optional mask in the form \<mark\>\[/\<mask\>\]. For this rule to be applied to a packet, the packet's mark value must match the \<mark\> when logically anded with the \<mask\>. If a \<mask\> is not supplied, Shorewall supplies a suitable provider mask.

### Multi-ISP and VPN

For those VPN types that use routing to direct traffic to remote VPN clients (including but not limited to OpenVPN in routed mode and PPTP), the VPN software adds a host route to the **main** table for each VPN client. The best approach is to use USE_DEFAULT_RT=Yes as described [below](#USE_DEFAULT_RT). If that isn't possible, you must add a routing rule in the 1000-1999 range to specify the **main** table for traffic addressed to those clients. See[ Example 2](#Openvpn) below.

If you have an IPsec gateway on your firewall, be sure to arrange for ESP packets to be routed out of the same interface that you have configured your keying daemon to use.

### Examples

**Example 1:** You want all traffic entering the firewall on eth1 to be routed through Comcast.

    #SOURCE            DEST      PROVIDER        PRIORITY
    eth1               -         Comcast         1000

With this entry, the output of `ip rule ls` would be as follows.

    gateway:~ # ip rule ls
    0:      from all lookup local
    1000:   from all iif eth1 lookup Comcast
    10001:  from all fwmark 0x1 lookup Blarg
    10002:  from all fwmark 0x2 lookup Comcast
    20000:  from 206.124.146.176 lookup Blarg
    20256:  from 24.12.22.33 lookup Comcast
    32766:  from all lookup main
    32767:  from all lookup default
    gateway:~ #

Note that because we used a priority of 1000, the test for `eth1` is inserted before the fwmark tests.

**Example 2:** You use OpenVPN (routed setup w/tunX) in combination with multiple providers. In this case you have to set up a rule to ensure that the OpenVPN traffic is routed back through the tunX interface(s) rather than through any of the providers. 10.8.0.0/24 is the subnet chosen in your OpenVPN configuration (server 10.8.0.0 255.255.255.0).

    #SOURCE                 DEST            PROVIDER        PRIORITY
    -                       10.8.0.0/24     main            1000

## Applications running on the Firewall - making them use a particular provider

As [noted above](#Applications), separate entries in `/etc/shorewall/mangle` are required for traffic originating from the firewall.

Experience has shown that in some cases, problems occur with applications running on the firewall itself. This is especially true when you have specified **routefilter** on your external interfaces in /etc/shorewall/interfaces (see [above](#Martians)). When this happens, it is suggested that you have the application use specific local IP addresses rather than 0.

Examples:

- Squid: In `squid.conf`, set **tcp_outgoing_address** to the IP address of the interface that you want Squid to use.

- In OpenVPN, set **local** (**--local** on the command line) to the IP address that you want the server to receive connections on.

Note that some traffic originating on the firewall doesn't have a SOURCE IP address before routing. At least one Shorewall user reports that an entry in `/etc/shorewall/rtrules` with 'lo' in the SOURCE column seems to be the most reliable way to direct such traffic to a particular ISP.

Example:

    #SOURCE     DEST      PROVIDER        PRIORITY
    lo          -         shorewall       1000

## /etc/shorewall/routes File

Beginning with Shorewall 4.4.15, additional routes can be added to the provider routing tables using the /etc/shorewall/routes file.

The columns in the file are as follows.

**PROVIDER**  
The name or number of a provider defined in [shorewall-providers](https://shorewall.org/manpages/shorewall-providers.html) (5).

**DEST**  
Destination host address or network address.

**GATEWAY** (Optional)  
If specified, gives the IP address of the gateway to the DEST.

Beginning with Shorewall 4.5.14, you may specify `blackhole` in this column to create a blackhole route. When `blackhole` is specified, the DEVICE column must be empty.

Beginning with Shorewall 4.5.15, you may specify `prohibit` or `unreachable` to create a prohibit or unreachable route respectively. Again, the DEVICE column must be empty.

See the next section for additional information.

**DEVICE** (Optional)  
Specifies the device route. If neither DEVICE nor GATEWAY is given, then the INTERFACE specified for the PROVIDER in [shorewall-providers](https://shorewall.org/manpages/shorewall-providers.html) (5).

Assume the following entry in `/etc/shorewall/providers`:

    #NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS          COPY
    Comcast      1     -    xxx             eth2            ....     

The following table gives some example entries in the file and the `ip route` command which results.

    #PROVIDER     DEST             GATEWAY         DEVICE        |              Generated Command
    Comcast       172.20.1.0/24    -               eth0          | ip -4 route add 172.20.1.0/24 dev eth0 table 1
    Comcast       192.0.2.0/24   172.20.1.1                    | ip -4 route add 192.168.1.0/24 via 172.20.1.1 table 1
    Comcast       192.0.2.0/24                                 | ip -4 route add 192.0.2.0/24 dev eth2 table 1 

## Null Routing

Null routing is a type of routing which discards a given packet instead of directing it through a specific predefined route. Generally speaking, there are 3 different types of Null routing as indicated below:

1.  Unreachable routes

    When used, a request for a routing decision returns a destination with an unreachable route type, an ICMP unreachable is generated (icmp type 3) and returned to the source address.

    Example:

        ip route add unreachable 10.22.0.12
        ip route add unreachable 192.168.14.0/26
        ip route add unreachable 82.32.0.0/12

    Unreachable routes are usually indicated by a dash ("-") in the "Iface" column when "route -n" is executed:

        ~# route -n
        Kernel IP routing table
        Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
        10.22.0.12      -               255.255.255.255 !H    0      -        0 -
        192.168.14.0    -               255.255.255.192 !     0      -        0 -
        82.32.0.0       -               255.240.0.0     !     0      -        0 -

2.  Prohibit routes

    Similar to "unreachable" routes above, when a request for a routing decision returns a destination with a prohibit route type, the kernel generates an ICMP prohibited to return to the source address.

    Example:

        ip route add prohibit 10.22.0.12
        ip route add prohibit 192.168.14.0/26
        ip route add prohibit 82.32.0.0/12

    "Prohibit" type routes are also indicated by a dash in the "Iface" column as shown above.

3.  Blackhole routes

    The difference between this type of routing and the previous two listed above is that a packet matching a route with the route type blackhole is simply discarded (DROPed). No ICMP is sent and no packet is forwarded.

    Example:

        ip route add blackhole 10.22.0.12
        ip route add blackhole 192.168.14.0/26
        ip route add blackhole 82.32.0.0/12

    Blackhole routes are usually indicated with a star ("\*") in the "Iface" column:

        ~# route -n
        Kernel IP routing table
        Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
        10.22.0.12      0.0.0.0         255.255.255.255 UH    0      0        0 *
        192.168.14.0    0.0.0.0         255.255.255.192 U     0      0        0 *
        82.32.0.0       0.0.0.0         255.240.0.0     U     0      0        0 *

### Null Routing Implementation in Shorewall

As of Shorewall 4.5.14, the only type of null routing implemented in Shorewall is "blackhole" routing. This can be specified in two different ways as described below.

1.  Null Routing with NULL_ROUTE_RFC1918 shorewall.conf configuration option.

    When NULL_ROUTE_RFC1918 is set to Yes, it causes Shorewall to null-route the IPv4 address ranges reserved by RFC1918 (private networks).

    When combined with route filtering (ROUTE_FILTER=Yes or routefilter in [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html)(5)), this option ensures that packets with an RFC1918 source address are only accepted from interfaces having known routes to networks using such addresses.

    When this option is used, the blackhole routes for all RFC1918 subnets are defined for the "main" routing table only. These, however, can be copied over to different routing tables or further customised and fine-tuned to suit individual needs by using the "routes" file (see below).

    For example, by specifying NULL_ROUTE_RFC1918=Yes in shorewall.conf, Shorewall generates 3 different route statements to be executed at Shorewall startup:

        ip route replace blackhole 10.0.0.0/8
        ip route replace blackhole 172.16.0.0/12
        ip replace blackhole 192.168.0.0/16

    <div class="important">

    When NULL_ROUTE_RFC1918=Yes is used, Shorewall creates a shell script file in \${VARDIR}/undo_rfc1918_routing to undo the null routing, if needed (see below as to some instances when this may be necessary).

    </div>

2.  Null Routing Using Shorewall "routes" (added in Shorewall 4.5.14)

    By definition, entries in this file are used to define routes to be added to provider routing tables, including the default routing table (main).

    This option allows for a better control over what is defined as a null route in Shorewall and also allows for custom-defined subnets (in addition to RFC1918 type networks) to be added. Blackhole routes defined in this way need to include the word "blackhole" in the GATEWAY column and the DEVICE column must also be ommitted (see example below).

    Example of use (`/etc/shorewall/routes`):

        #PROVIDER       DEST            GATEWAY         DEVICE
        main            10.0.0.0/8      blackhole
        dmz             82.32.0.0/12    blackhole
        dmz             192.168.14.0/26 blackhole

    The above generates the following 3 statements for execution upon Shorewall startup:

        ip route add blackhole 10.0.0.0/8 table main
        ip route add blackhole 82.32.0.0/12 table dmz
        ip route add blackhole 192.168.14.0/26 table dmz

    <div class="important">

    When blackhole routes are added to a \<provider\> (including 'main'), Shorewall creates a shell script file in \${VARDIR}/undo\_\<provider\>\_routing to undo the routing, if needed (see below as to some instances when this may be necessary).

    </div>

Beginning with Shorewall 4.5.15, Shorewall also supports "unreachable" and "prohibit" routing.

1.  The NULL_ROUTE_RFC1918 option may be set to "blackhole", "prohibit" or "unreachable" in addition to "Yes" and "No".

    Shorewall will create the three route statements using the specified type type. For compatibility with earlier releases, "Yes" is equivalent to "blackhole".

    For example, if NULL_ROUTE_RFC1918=prohibit, then the following three route statements will be executed at Shorewall startup:

        ip route replace prohibit 10.0.0.0/8
        ip route replace prohibit 172.16.0.0/12
        ip replace prohibit 192.168.0.0/16

2.  The words "prohibit" and "unreachable" may be placed in the GATEWAY column of `/etc/shorewall/routes`.

    The DEVICE column must be omitted.

    Example of use (`/etc/shorewall/routes`):

        #PROVIDER       DEST            GATEWAY         DEVICE
        main            10.0.0.0/8      unreachable
        dmz             82.32.0.0/12    unreachable
        dmz             192.168.14.0/26 unreachable

    The above generates the following 3 statements for execution upon Shorewall startup:

        ip route add unreachable 10.0.0.0/8 table main
        ip route add unreachable 82.32.0.0/12 table dmz
        ip route add unreachable 192.168.14.0/26 table dmz

    <div class="important">

    When prohibit or unreachable routes are added to a \<provider\> (including 'main'), Shorewall creates a shell script file in \${VARDIR}/undo\_\<provider\>\_routing to undo the routing, if needed (see below as to some instances when this may be necessary).

    </div>

### Important Points To Remember When Using Null Routing in Shorewall

1.  In order to create "pinhole" in a particular blackhole route, at least one route needs to be defined in addition to the null route.

    Lets take the following example: We need to null-route all addresses from the 10.0.0.0/8 range, **except** 10.1.0.0/24. In such a case we need to define two routes in our "routes" file (assuming the default "main" routing table is used and also assuming that 10.1.0.0/24 is routed via the default gateway on eth0 and we need to use 'blackhole' type null routing).

    `/etc/shorewall/routes`:

        #PROVIDER       DEST            GATEWAY         DEVICE
        main            10.0.0.0/8      blackhole
        main            10.1.0.0/24     -               eth0

    The above will generate 2 statements for execution when Shorewall starts:

        ip route replace blackhole 10.0.0.0/8 table main
        ip route replace 10.1.0.0/24 table main

    The order in which the two routes above are defined in "routes" is not important, simply because, by definition, routes with lower mask value are always traversed first. In that way, packets originating from or destined to 10.1.0.0/24 will always be processed before the 10.0.0.0/8 blackhole route.

2.  Null routes, by their definition, are not attached to any network device. What this means in reality is that when the status of a particular device changes (either going up or down), that has absolutely **no** effect on the null routes defined (as already indicated, these are "static" and can only be removed by executing "ip route del" or by executing the relevant \${VARDIR}/undo\_\*\_routing shell script).

    <div class="important">

    The \${VARDIR}/undo\_\*\_routing scripts generated by Shorewall 4.5.14 and earlier cannot be executed directly from the shell without first sourcing \${SHAREDIR}/shorewall/functions. Example:

        . /usr/share/shorewall/functions
        . /var/lib/shorewall/undo_x_routing

    </div>

    This sometimes may lead to undesirable side effect: when a network interface goes down (even temporarily), then **all** routes defined or attached to that interface are simply deleted from the routing table by the kernel, while the blackhole routes are untouched.

    Lets take our example above: when eth0 goes down, then the route we defined in "routes" for our private subnet (10.1.0.0/24) will be deleted from the routing table. As soon as eth0 goes back up again, unless the route for our private 10.1.0.0/24 subnet is defined again, all packets originating from or destined to 10.1.0.0/24 will simply be dropped by the kernel!

    An indication of this type of behaviour is getting endless "martian" packets reported in the system log, like so:

        IPv4: martian source 10.1.0.7 from 10.1.0.1, on dev eth0

    There are currently two possible solutions to this particular problem:

    1.  Add all network-interface dependent routes (the ones which are deleted when that interface goes down) to your distribution's network configuration system. On Redhat and derivatives, that would be `/etc/sysconfig/network-scripts/route-X` (where "X" is the name of the interface in question). On Debian and derivatives, it is `/etc/network/interfaces`.

        That way, when the network device goes back up again, the Linux OS will add these routes "automatically". Using our example above - to add a route to 10.1.0.0/24 using the default gateway on eth0 and also using the main routing table, the following needs to be added to `/etc/sysconfig/network-scripts/route-eth0` (Redhat and derivatives):

            10.1.0.0/24 dev eth0 table main

        On Debian and derivatives (in the eth0 stanza of `/etc/network/interfaces`):

            iface eth0 ...
                   ... 
                   post-up ip route add 10.1.0.0/24 dev eth0 table main

    2.  A more elegant solution is, in addition to the "standard" shorewall package (shorewall-lite, shorewall, etc), to add shorewall-init (shorewall-init documentation was not ported to shorewall-nft) to take care of this automatically.

        With this approach, when the network interface is brought back up, the OS passes control to /sbin/ifup-local, which forms part of the shorewall-init package, and that script, in turn, executes the appropriate command to reload the network device settings in the already-compiled \${VARDIR}/firewall file.

        When shorewall-init is used, all configuration settings (routes, interface options etc) are kept in one place and do not have to be defined separately (via /etc/sysconfig/network-scripts/route-X for example), which eases maintenance efforts quite considerably.

## Looking at the routing tables

To look at the various routing tables, you must use the **ip** utility. To see the entire routing configuration (including rules), the command is `shorewall show routing`. To look at an individual provider's table use `ip route ls table provider` where \<provider\> can be either the provider name or number.

Example:

    lillycat:- #ip route ls
    144.77.167.142 dev ppp0  proto kernel  scope link  src 144.177.121.199
    71.190.227.208 dev ppp1  proto kernel  scope link  src 71.24.88.151
    192.168.7.254 dev eth1  scope link  src 192.168.7.1
    192.168.7.253 dev eth1  scope link  src 192.168.7.1
    192.168.7.0/24 dev eth1  proto kernel  scope link  src 192.168.7.1
    192.168.5.0/24 via 192.0.2.2 dev eth0
    192.0.2.0/24 dev eth0  proto kernel  scope link  src 192.0.2.223
    192.168.1.0/24 via 192.0.2.222 dev eth0
    default
            nexthop dev ppp1 weight 2
            nexthop dev ppp0 weight 1
    lillycat: #ip route ls table 1
    144.77.167.142 dev ppp0  proto kernel  scope link  src 144.177.121.199 
    192.168.5.0/24 via 192.0.2.2 dev eth0 
    192.0.2.0/24 dev eth0  proto kernel  scope link  src 192.0.2.223 
    192.168.1.0/24 via 192.0.2.222 dev eth0 
    default dev ppp0  scope link 
    lillycat: #

## USE_DEFAULT_RT

USE_DEFAULT_RT is an option in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5).

One of the drawbacks of the Multi-ISP support as described in the preceding sections is that changes to the main table made by applications are not added to the individual provider tables. This makes route rules such as described in [one of the examples above](#Openvpn) necessary.

USE_DEFAULT_RT=Yes works around that problem by passing packets through the main table first rather than last. This has a number of implications:

1.  Both the DUPLICATE and the COPY columns in the providers file must remain empty or contain "-". The individual provider routing tables generated when USE_DEFAULT_RT=Yes contain only a host route to the gateway and a default route via the gateway.

2.  The **balance** option is assumed for all interfaces that do not have the **loose** option. When you want both **balance** and **loose**, both must be specified.

3.  The default route generated by Shorewall is added to the *default* routing table (253) rather than to the main routing table (254).

4.  Packets are sent through the main routing table by a routing rule with priority 999. The priority range 1-998 may be used for inserting rules that bypass the main table.

5.  You should disable all default route management outside of Shorewall. If a default route is inadvertently added to the main table while Shorewall is started, then all policy routing will stop working except for those routing rules in the priority range 1-998.

6.  For ppp interfaces, the GATEWAY may remain unspecified ("-"). For those interfaces managed by dhcpcd or dhclient, you may specify 'detect' in the GATEWAY column; Shorewall will use the dhcp client's database to determine the gateway IP address. All other interfaces must have a GATEWAY specified explicitly.

The configuration in the figure at the top of this section would be specified in `/etc/shorewall/providers` as follows.

    #NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS          COPY
    ISP1    1       1       -               eth0            206.124.146.254 track            -
    ISP2    2       2       -               eth1            130.252.99.254  track            -  

The remainder of the example is the same.

Although 'balance' is automatically assumed when USE_DEFAULT_RT=Yes, you can easily cause all traffic to use one provider except when you explicitly direct it to use the other provider via [shorewall-rtrules](https://shorewall.org/manpages/shorewall-rtrules.html) (5) or [shorewall-mangle](https://shorewall.org/manpages/shorewall-tcrules.html) (5).

Example (send all traffic through the 'shorewall' provider unless otherwise directed).

/etc/shorewall/providers:

    #NAME    NUMBER MARK DUPLICATE INTERFACE GATEWAY       OPTIONS
    linksys       1    1    -        wlan0   172.20.1.1    track,balance=1,optional
    shorewall     2    2    -        eth0    192.168.1.254 track,balance=2,optional

/etc/shorewall/rtrules:

    #SOURCE     DEST      PROVIDER        PRIORITY
    -           -         shorewall       11999

Tuomo Soini describes the following issue when using USE_DEFAULT_RT=Yes.

He has a /27 network (let.s call it 70.90.191.0/27) from his primary ISP and his secondary ISP supplies him with a dynamic IP address on the 91.156.0.0/19 network. From the output of `shorewall show routing`:

    999:    from all lookup main 
    10000:  from all fwmark 0x100 lookup ISP1 
    10001:  from all fwmark 0x200 lookup ISP2

Note that the main routing table is consulted prior to the marks for his two provlders. When clients in the large /19 network connected to his /27 (through ISP1), the responses were routed out of the ISP2 interface because the main routing table included a route to the /19.

The solution was to add an additional entry to rtrules:

    #SOURCE             DEST           PROVIDER       PRIORITY
    70.90.191.0/27      91.156.0.0/19  ISP1           900

With this additional entry, the routing rules are as below and traffic from the /27 is returned via ISP1.

    900:    from 70.90.191.0/27 to 91.156.0.0/19 lookup ISP1 
    999:    from all lookup main 
    10000:  from all fwmark 0x100 lookup ISP1 
    10001:  from all fwmark 0x200 lookup ISP2

### DHCP with USE_DEFAULT_RT

When USE_DEFAULT_RT=Yes, you don't want your DHCP client inserting a default route into the main routing table.

#### Debian

In this Debian-specific example, eth0 is managed by dhcpcd.

`/etc/default/dhcpcd`:

    # Config file for dhcpcd. Note that you have to edit the interface
    # name below, or duplicate the configuration for different interfaces.
    # If you are editing this file just to get DNS servers set by DHCP,
    # then you should consider installing the resolvconf package instead.

    case ${INTERFACE} in
    eth0) 

    # Uncomment this to allow dhcpcd to set the DNS servers in /etc/resolv.conf
    # If you are using resolvconf then you can leave this commented out.
    #SET_DNS='yes'

    # Uncomment this to allow dhcpcd to set hostname of the host to the
    # hostname option supplied by DHCP server.
    #SET_HOSTNAME='yes'

    # Uncomment this to allow dhcpcd to set the NTP servers in /etc/ntp.conf
    #SET_NTP='yes'

    # Uncomment this to allow dhcpcd to set the YP servers in /etc/yp.conf
    #SET_YP='yes'

    # Add other options here, see man 8 dhcpcd-bin for details.
    OPTIONS=(--nogateway --nodns --nontp --script /etc/shorewall/dhcpcd.sh)
    ;;

    # Add other interfaces here
    *)
    ;;

    esac

`/etc/shorewall/start`:

    cat <<EOF > /var/lib/shorewall/eth0.info
    ETH0_GATEWAY=$SW_ETH0_GATEWAY
    ETH0_ADDRESS=$SW_ETH0_ADDRESS
    EOF

`/etc/shorewall/dhcpd.sh`:

    #!/bin/sh

    if [ $2 != down ]; then
        if [ -f /var/lib/dhcpcd/dhcpcd-eth0.info ]; then
            . /var/lib/dhcpcd/dhcpcd-eth0.info
        else
            logger -p daemon.err "/var/lib/dhcpcd/dhcpcd-eth0.info does not exist!"
            exit 1
        fi

        logger -p daemon.info "DHCP-assigned address/gateway for eth0 is $IPADDR/$GATEWAYS"

        [ -f /var/lib/shorewall/eth0.info ] && . /var/lib/shorewall/eth0.info
        
        if [ "$GATEWAYS" != "$ETH0_GATEWAY" -o "$IPADDR" != "$ETH0_ADDRESS" ]; then
            logger -p daemon.info "eth0 IP configuration changed - restarting foolsm and Shorewall"
            killall foolsm
            /sbin/shorewall restart
        fi
    fi

A couple of things to notice about `/etc/shorewall/dhcpcd.sh`:

- It is hard-coded for eth0

- It assumes the use of [FOOLSM](#lsm); If you aren't using foolsm, you can change the log message and remove the 'killall foolsm'

- It restarts Shorewall if the current IPv4 address of eth0 and the gateway through eth0 are not the same as they were when Shorewall was last started.

#### RedHat and Derivatives

On Redhat-based systems, specify DEFROUTE=No in the device's ifcfg file.

`/etc/sysconfig/networking/network-scripts/ifcfg-eth2`:

    BOOTPROTO=dhcp
    PERSISTENT_DHCLIENT=yes
    PEERDNS=no
    PEERNTP=no
    DEFROUTE=no
    DHCLIENTARGS="-nc"
    DEVICE=eth2
    ONBOOT=yes

#### SuSE and Derivatives

On these systems, set DHCLIENT_SET_DEFAULT_ROUTE=No in the device's ifcfg file.

## An alternative form of balancing

Beginning with Shorewall 4.5.0, an alternative to the `balance`=\<weight\> option in [shorewall-providers](https://shorewall.org/manpages/shorewall-providers.html) (5) is available in the form of a PROBABILITY column in [shorewall-mangle](https://shorewall.org/manpages/shorewall-mangle.html)(5) ([shorewall-tcrules](https://shorewall.org/manpages/shorewall-tcrules.html)) (5). This feature requires the Statistic Match capability in your iptables and kernel.

This method works when there are multiple links to the same ISP where both links have the same default gateway.

The key features of this method are:

1.  Providers to be balanced are given a \<load factor\> using the `load`= option in [shorewall-providers](https://shorewall.org/manpages/shorewall-providers.html) (5).

2.  A load factor is a number in the range 0 \< number \<= 1 and specifies the probability that any particular new connection will be assigned to the associated provider.

3.  When one of the interfaces is disabled or enabled, the load factors of the currently-available interfaces are adjusted so that the sum of these remaining load factors totals to the sum of all interfaces that specify `load`=.

Here's an example that sends 1/3 of the connections through provider ComcastC and the rest through ComastB.

`/etc/shorewall/shorewall.conf`:

    MARK_IN_FORWARD_CHAIN=No
    ...
    USE_DEFAULT_RT=Yes
    ...
    TC_BITS=0
    PROVIDER_BITS=2
    PROVIDER_OFFSET=16
    MASK_BITS=8
    ZONE_BITS=4

<div class="note">

PROVIDER_OFFSET=16 and ZONE_BITS=4 means that the provider mask will be 0xf0000.

</div>

`/etc/shorewall/providers`:

    #NAME    NUMBER MARK DUPLICATE  INTERFACE GATEWAY       OPTIONS
    ComcastB 1      -    -          eth1      70.90.191.126 loose,balance,load=0.66666667
    ComcastC 2      -    -          eth0      detect        loose,fallback,load=0.33333333

<div class="note">

The `loose` option is specified so that the compiler will not generate and rules based on interface IP addresses. That way we have complete control over the priority of such rules through entries in the rtrules file.

</div>

`/etc/shorewall/rtrules`:

    #SOURCE             DEST  PROVIDER  PRIORITY
    70.90.191.120/29    -     ComcastB  1000
    &eth0               -     ComcastC  1000

<div class="note">

This example assumes that eth0 has a dynamic address, so **&eth0** is used in the SOURCE column. That will cause the first IP address of eth0 to be substituted when the firewall is started/restarted.

</div>

<div class="note">

Priority = 1000 means that these rules will come before rules that select a provider based on marks.

</div>

## Gateway Monitoring and Failover

There is an option (FOOLSM) available for monitoring the status of provider links and taking action when a failure occurs. FOOLSM assumes that each provider has a unique nexthop gateway.

You specify the `optional` option in `/etc/shorewall/interfaces`:

    #ZONE    INTERFACE    BROADCAST       OPTIONS
    net      eth0         detect          optional         
    net      eth1         detect          optional

### Link Status Monitor (FOOLSM)

[Link Status Monitor](http://lsm.foobar.fi/) was written by Mika Ilmaranta \<ilmis at nullnet.fi\> and performs more sophisticated monitoring than the simple SWPING script that preceded it.

<div class="important">

If you have installed Shorewall-init, you should disable its ifup/ifdown/NetworkManager integration (set IFUPDOWN=0 in the [Shorewall-init configuration file](https://shorewall.org/manpages/shorewall-init.html)) before installing LSM.

</div>

<div class="important">

To avoid an achronym clash with *Linux Security Module*, the Link Status Monitor is now called *foolsm*.

</div>

Like many Open Source products, FOOLSM is poorly documented. It's main configuration file is normally kept in `/etc/foolsm/foolsm.conf`, but the file's name is passed as an argument to the foolsm program so you can name it anything you want.

The sample `foolsm.conf` included with the product shows some of the possibilities for configuration. One feature that is not mentioned in the sample is that an "include" directive is supported. This allows additional files to be sourced in from the main configuration file.

FOOLSM monitors the status of the links defined in its configuration file and runs a user-provided script when the status of a link changes. The script name is specified in the eventscript option in the configuration file. Key arguments to the script are as follows:

\$1  
The state of the link ('up' or 'down')

\$2  
The name of the connection as specified in the configuration file.

\$4  
The name of the network interface associated with the connection.

\$5  
The email address of the person specified to receive notifications. Specified in the warn_email option in the configuration file.

It is the responsibility of the script to perform any action needed in reaction to the connection state change. The default script supplied with FOOLSM composes an email and sends it to \$5.

I personally use FOOLSM here at shorewall.net (configuration is described [below](#Complete)). I have set things up so that:

- Shorewall \[re\]starts foolsm during processing of the `start` and `restore` commands. I don't have Shorewall restart foolsm during Shorewall `restart` because I restart Shorewall much more often than the average user is likely to do.

- Shorewall starts foolsm because I have a dynamic IP address from one of my providers (Comcast); Shorewall detects the default gateway to that provider and creates a secondary configuration file (`/etc/foolsm/shorewall.conf`) that contains the link configurations. That file is included by `/etc/foolsm/foolsm.conf`.

Below are my relevant configuration files.

<div class="warning">

These files only work with Shorewall-perl 4.4 Beta 2 and later.

</div>

`/etc/shorewall/params:`

    EXT_IF=eth0
    COM_IF=eth1

`/etc/shorewall/isusable`:

    local status=0
    #
    # Read the status file (if any) created by /etc/foolsm/script
    #
    [ -f ${VARDIR}/${1}.status ] && status=$(cat ${VARDIR}/${1}.status)

    return $status

Note that the above script overrides the normal behavior of *persistent* providers, in that it prevents the attempt to enable the provider during `start`, `restart` and `reload`.

`/etc/shorewall/lib.private`:

    ###############################################################################
    # Create /etc/foolsm/shorewall.conf
    # Remove the current interface status files
    # Start foolsm
    ###############################################################################
    start_foolsm() {
       #
       # Kill any existing foolsm process(es)
       #
       killall foolsm 2> /dev/null
       #
       # Create the Shorewall-specific part of the FOOLSM configuration. This file is
       # included by /etc/foolsm/foolsm.conf
       #
       # Avvanta has a static gateway while Comcast's is dynamic
       #
       cat <<EOF > /etc/foolsm/shorewall.conf
    connection {
        name=Avvanta
        checkip=206.124.146.254
        device=$EXT_IF
        ttl=2
    }

    connection {
        name=Comcast
        checkip=${SW_ETH0_GATEWAY:-71.231.152.1}
        device=$COM_IF
        ttl=1
    }
    EOF
       #
       # Run FOOLSM -- by default, it forks into the background
       #
       /usr/sbin/foolsm -c /etc/foolsm/foolsm.conf >> /var/log/foolsm
    }

eth0 has a dynamic IP address so I need to use the Shorewall-detected gateway address (\$SW_ETH1_GATEWAY). I supply a default value to be used in the event that detection fails.

<div class="note">

In Shorewall 4.4.7 and earlier, the variable name is ETH1_GATEWAY.

</div>

`/etc/shorewall/started`:

    ##################################################################################
    # [re]start foolsm if this is a 'start' command or if foolsm isn't running
    ##################################################################################
    if [ "$COMMAND" = start -o -z "$(ps ax | grep 'foolsm ' | grep -v 'grep ' )" ]; then
        start_foolsm
    fi

`/etc/shorewall/restored`:

    ##################################################################################
    # Start foolsm if it isn't running
    ##################################################################################
    if [ -z "$(ps ax | grep 'foolsm ' | grep -v 'grep ' )" ]; then
       start_foolsm
    fi

`/etc/foolsm/foolsm.conf`:

    #
    # Defaults for the connection entries
    #
    defaults {
      name=defaults
      checkip=127.0.0.1
      eventscript=/etc/foolsm/script
      max_packet_loss=20
      max_successive_pkts_lost=7
      min_packet_loss=5
      min_successive_pkts_rcvd=10
      interval_ms=2000
      timeout_ms=2000
      warn_email=you@yourdomain.com
      check_arp=0
      sourceip=
      ttl=0
    }

    include /etc/foolsm/shorewall.conf

`/etc/foolsm/script` (Shorewall 4.4.23 and later - note that this script must be executable by root)

    #!/bin/sh
    #
    # (C) 2009 Mika Ilmaranta <ilmis@nullnet.fi>
    # (C) 2009 Tom Eastep <teastep@shorewall.net>
    #
    # License: GPLv2
    #

    STATE=${1}
    NAME=${2}
    CHECKIP=${3}
    DEVICE=${4}
    WARN_EMAIL=${5}
    REPLIED=${6}
    WAITING=${7}
    TIMEOUT=${8}
    REPLY_LATE=${9}
    CONS_RCVD=${10}
    CONS_WAIT=${11}
    CONS_MISS=${12}
    AVG_RTT=${13}

    if [ -f /usr/share/shorewall-lite/lib.base ]; then
        VARDIR=/var/lib/shorewall-lite
        STATEDIR=/etc/shorewall-lite
        TOOL=/sbin/shorewall-lite
    else
        VARDIR=/var/lib/shorewall
        STATEDIR=/etc/shorewall
        TOOL=/sbin/shorewall
    fi

    [ -f ${STATEDIR}/vardir ] && . ${STATEDIR}/vardir

    cat <<EOM | mail -s "${NAME} ${STATE}, DEV ${DEVICE}" ${WARN_EMAIL}

    Hi,

    Connection ${NAME} is now ${STATE}.

    Following parameters were passed:
    newstate     = ${STATE}
    name         = ${NAME}
    checkip      = ${CHECKIP}
    device       = ${DEVICE}
    warn_email   = ${WARN_EMAIL}

    Packet counters:
    replied      = ${REPLIED} packets replied
    waiting      = ${WAITING} packets waiting for reply
    timeout      = ${TIMEOUT} packets that have timed out (= packet loss)
    reply_late   = ${REPLY_LATE} packets that received a reply after timeout
    cons_rcvd    = ${CONS_RCVD} consecutively received replies in sequence
    cons_wait    = ${CONS_WAIT} consecutive packets waiting for reply
    cons_miss    = ${CONS_MISS} consecutive packets that have timed out
    avg_rtt      = ${AVG_RTT} average rtt, notice that waiting and timed out packets have rtt = 0 when calculating this

    Your FOOLSM Daemon

    EOM

    if [ ${STATE} = up ]; then
    # echo 0 > ${VARDIR}/${DEVICE}.status # Uncomment this line if you are running Shorewall 4.4.x or earlier
      ${VARDIR}/firewall enable ${DEVICE}
    else
    #  echo 1 > ${VARDIR}/${DEVICE}.status # Uncomment this line if you are running Shorewall 4.4.x or earlier
       ${VARDIR}/firewall disable ${DEVICE}
    fi

    $TOOL show routing >> /var/log/foolsm

    exit 0

    #EOF

Prior to Shorewall 4.4.23, it was necessary to restart the firewall when an interface transitions between the usable and unusable states.

    #!/bin/sh
    #
    # (C) 2009 Mika Ilmaranta <ilmis@nullnet.fi>
    # (C) 2009 Tom Eastep <teastep@shorewall.net>
    #
    # License: GPLv2
    #

    STATE=${1}
    NAME=${2}
    CHECKIP=${3}
    DEVICE=${4}
    WARN_EMAIL=${5}
    REPLIED=${6}
    WAITING=${7}
    TIMEOUT=${8}
    REPLY_LATE=${9}
    CONS_RCVD=${10}
    CONS_WAIT=${11}
    CONS_MISS=${12}
    AVG_RTT=${13}

    if [ -f /usr/share/shorewall-lite/lib.base ]; then
        VARDIR=/var/lib/shorewall-lite
        STATEDIR=/etc/shorewall-lite
        TOOL=/sbin/shorewall-lite
    else
        VARDIR=/var/lib/shorewall
        STATEDIR=/etc/shorewall
        TOOL=/sbin/shorewall
    fi

    [ -f ${STATEDIR}/vardir ] && . ${STATEDIR}/vardir

    cat <<EOM | mail -s "${NAME} ${STATE}, DEV ${DEVICE}" ${WARN_EMAIL}

    Hi,

    Connection ${NAME} is now ${STATE}.

    Following parameters were passed:
    newstate     = ${STATE}
    name         = ${NAME}
    checkip      = ${CHECKIP}
    device       = ${DEVICE}
    warn_email   = ${WARN_EMAIL}

    Packet counters:
    replied      = ${REPLIED} packets replied
    waiting      = ${WAITING} packets waiting for reply
    timeout      = ${TIMEOUT} packets that have timed out (= packet loss)
    reply_late   = ${REPLY_LATE} packets that received a reply after timeout
    cons_rcvd    = ${CONS_RCVD} consecutively received replies in sequence
    cons_wait    = ${CONS_WAIT} consecutive packets waiting for reply
    cons_miss    = ${CONS_MISS} consecutive packets that have timed out
    avg_rtt      = ${AVG_RTT} average rtt, notice that waiting and timed out packets have rtt = 0 when calculating this

    Your FOOLSM Daemon

    EOM

    # Uncomment the next two lines if you are running Shorewall 4.4.x or earlier

    # [ ${STATE} = up ] && state=0 || state=1
    # echo $state > ${VARDIR}/${DEVICE}.status

    $TOOL restart -f >> /var/log/foolsm 2>&1

    $TOOL show routing >> /var/log/foolsm

    exit 0

    #EOF

## Two Providers Sharing an Interface

Shared interface support has the following characteristics:

1.  Only Ethernet (or Ethernet-like) interfaces can be used. For inbound traffic, the MAC addresses of the gateway routers are used to determine which provider a packet was received through. Note that only routed traffic can be categorized using this technique.

2.  You must specify the address on the interface that corresponds to a particular provider in the INTERFACE column by following the interface name with a colon (":") and the address.

3.  Entries in `/etc/shorewall/masq` and `/etc/shorewall/snat` must be qualified by the provider name (or number).

4.  This feature requires Realm Match support in your kernel and iptables.

5.  You must add rtrules entries for networks that are accessed through a particular provider.

6.  If you have additional IP addresses through either provider, you must add `rtrules` to direct traffic FROM each of those addresses through the appropriate provider.

7.  You must manually add MARK rules for traffic known to come from each provider.

8.  You must specify a gateway IP address in the GATEWAY column of`/etc/shorewall/providers`; **detect** is not permitted.

9.  The **optional** provider/interface option doesn't work (and is disallowed beginning with Shorewall 5.2.1). If you need failover, you will need to front-end your firewall with a configurable switch and create a separate VLAN for each of your providers, thus providing a separate network interface for each provider.

Taken together, b. and h. effectively preclude using this technique with dynamic IP addresses.

Example:

This is our home network circa fall 2008. We have two Internet providers:

1.  Comcast -- Cable modem with one dynamic IP address.

2.  Avvanta -- ADSL with 5 static IP addresses.

Because the old Compaq Presario that I use for a firewall only has three PCI slots and no onboard Ethernet, it doesn't have enough Ethernet controllers to support both providers. So I use a Linksys WRT300n pre-N router as a gateway to Comcast. Note that because the Comcast IP address is dynamic, I could not share a single firewall interface between the two providers directly.

On my personal laptop (ursa), I have 9 virtual machines running various Linux distributions. *It is the Shorewall configuration on ursa that I will describe here*.

Below is a diagram of our network:

The local wired network in my office is connected to both gateways and uses the private (RFC 1918) network 172.20.1.0/24. The Comcast gateway has local IP address 172.20.1.1 while the Avvanta gateway has local IP address 172.20.1.254. Ursa's eth0 interface has a single IP address (172.20.1.130).

This configuration uses USE_DEFAULT_RT=Yes in `shorewall.conf`(see [above](#USE_DEFAULT_RT)).

Here is the `providers` file:

    #NAME          NUMBER   MARK DUPLICATE INTERFACE            GATEWAY      OPTIONS                            COPY
    comcast        1        1    -         eth0:172.20.1.130    172.20.1.1   track,loose,balance,optional
    avvanta        2        2    -         eth0:172.20.1.130    172.20.1.254 track,optional,loose
    wireless       3        3    -         wlan0                172.20.1.1   track,optional

Several things to note:

1.  172.20.1.130 is specified as the `eth0` IP address for both providers.

2.  Both wired providers have the **loose** option. This prevents Shorewall from automatically generating routing rules based on the source IP address.

3.  Only **comcast** has the **balance** option. With USE_DEFAULT_RT=yes, that means that **comcast** will be the default provider. While **balance** is the default, with USE_DEFAULT_RT=Yes, it must be specified explicitly when **loose** is also specified.

4.  I always disable the **wireless** interface when the laptop is connected to the wired network.

5.  I use a different Shorewall configuration when I take the laptop on the road.

Here is the rtrules file:

    #SOURCE                 DEST                    PROVIDER        PRIORITY
    -                       206.124.146.176/31      avvanta         1000
    -                       206.124.146.178/31      avvanta         1000
    -                       206.124.146.180/32      avvanta         1000

Those rules direct traffic to the five static Avvanta IP addresses (only two are currently used) through the **avvanta** provider.

Here is the mangle file (MARK_IN_FORWARD_CHAIN=No in `shorewall.conf`):

    #ACTION               SOURCE          DEST            PROTO   DPORT           SPORT  USER    TEST    LENGTH  TOS     CONNBYTES       HELPER
    MARK(2)               $FW             0.0.0.0/0       tcp     21
    MARK(2)               $FW             0.0.0.0/0       tcp     -               -       -       -       -       -       -               ftp
    MARK(2)               $FW             0.0.0.0/0       tcp     119

If you are still using a tcrules file, you should consider switching to using a mangle file (`shorewall update -t` will do that for you). Here are the equivalent tcrules entries:

    #MARK           SOURCE          DEST            PROTO   DPORT           SPORT   USER    TEST    LENGTH  TOS     CONNBYTES       HELPER
    2               $FW             0.0.0.0/0       tcp     21
    2               $FW             0.0.0.0/0       tcp     -               -       -       -       -       -       -               ftp
    2               $FW             0.0.0.0/0       tcp     119

These rules:

- Use **avvanta** for FTP.

- Use **avvanta** for NTTP

The same rules converted to use the mangle file are:

    #MARK           SOURCE          DEST            PROTO   DPORT           SPORT   USER    TEST    LENGTH  TOS     CONNBYTES       HELPER
    MARK(2)         $FW             0.0.0.0/0       tcp     21
    MARK(2)         $FW             0.0.0.0/0       tcp     -               -       -       -       -       -       -               ftp
    MARK(2)         $FW             0.0.0.0/0       tcp     119

The remaining files are for a rather standard two-interface config with a bridge as the local interface.

`zones`:

    #ZONE   IPSEC   OPTIONS                 IN_OPTIONS              OUT_OPTIONS
    fw      firewall
    net     ipv4
    kvm     ipv4

`policy`:

    net             net             NONE
    fw              net             ACCEPT
    fw              kvm             ACCEPT
    kvm             all             ACCEPT
    net             all             DROP            info
    all             all             REJECT          info

interfaces:

    #ZONE    INTERFACE      OPTIONS
    #
    net     eth0            dhcp,tcpflags,routefilter,blacklist,logmartians,optional,arp_ignore
    net     wlan0           dhcp,tcpflags,routefilter,blacklist,logmartians,optional
    kvm     br0             routeback       #Virtual Machines

<div class="note">

`wlan0` is the wireless adapter in the notebook. Used when the laptop is in our home but not connected to the wired network.

</div>

masq:

    #INTERFACE              SUBNET          ADDRESS         PROTO   DPORT   IPSEC
    eth0                    192.168.0.0/24
    wlan0                   192.168.0.0/24

<div class="note">

Because the firewall has only a single external IP address, I don't need to specify the providers in the masq rules.

</div>

# A Complete Working Example

This section describes the network at shorewall.net in late 2013. The configuration is as follows:

- Two providers:

  - ComcastC -- A consumer-grade Comcast cable line with a dynamic IP address.

  - ComcastB -- A Comcast Business-class line with 5 static IP addresses.

- A local network consisting of wired and wireless client systems. A wireless-N router is used as an access point for the wireless hosts.

- A DMZ hosting a two servers (one has two public IP addresses - one for receiving email and one for sending) and a system dedicaed to running irssi (usually via IPv6)

The network is pictured in the following diagram:

## IPv4 Configuration

The Business Gateway manages a gigabit local network with address 10.0.1.1/24. So The firewall is given address 10.0.1.11/24 and the gateway is configured to route the public IP block via that address. The gateway's firewall is only enabled for the 10.0.1.0/24 network.

Because the business network is faster and more reliable, the configuration favors sending local network traffic via that uplink rather than the consumer line.

Here are the key entries in `/etc/shorewall/params`:

    LOG=NFLOG

    INT_IF=eth2
    TUN_IF=tun+
    COMB_IF=eth1
    COMC_IF=eth0

    STATISTICAL=
    PROXY=
    FALLBACK=
    PROXYDMZ=
    SQUID2=

The last five variables are used to configure the firewall differently to exercise various Shorewall features. Their use requires Shorewall 4.5.2 or later.

Here are the key entries in `/etc/shorewall/shorewall.conf`:

    ###############################################################################
    #                       F I R E W A L L   O P T I O N S
    ###############################################################################

    ...

    ACCOUNTING_TABLE=mangle

    ...

    AUTOMAKE=Yes

    BLACKLISTNEWONLY=Yes

    ...

    EXPAND_POLICIES=No

    EXPORTMODULES=Yes

    FASTACCEPT=No

    ..

    KEEP_RT_TABLES=Yes #This is necessary when both IPv4 and IPv6 Multi-ISP are used

    LEGACY_FASTSTART=Yes

    LOAD_HELPERS_ONLY=Yes

    ...

    MARK_IN_FORWARD_CHAIN=No

    MODULE_SUFFIX=ko

    MULTICAST=No

    MUTEX_TIMEOUT=60

    NULL_ROUTE_RFC1918=Yes

    OPTIMIZE=31

    OPTIMIZE_ACCOUNTING=No

    REQUIRE_INTERFACE=No

    RESTORE_DEFAULT_ROUTE=No

    RETAIN_ALIASES=No

    ROUTE_FILTER=No

    SAVE_IPSETS=

    TC_ENABLED=No

    TC_EXPERT=No

    TC_PRIOMAP="2 3 3 3 2 3 1 1 2 2 2 2 2 2 2 2"

    TRACK_PROVIDERS=Yes

    USE_DEFAULT_RT=Yes

    USE_PHYSICAL_NAMES=Yes

    ZONE2ZONE=-

    ################################################################################
    #                       P A C K E T  M A R K  L A Y O U T
    ################################################################################

    TC_BITS=8

    PROVIDER_BITS=2

    PROVIDER_OFFSET=16

    MASK_BITS=8

    ZONE_BITS=0

I use USE_DEFAULT_RT=Yes and since there are only two providers, two provider bits are all that are required.

Here is /etc/shorewall/zones:

    fw              firewall
    loc             ip           #Local Zone
    net             ip           #Internet
    smc:net         ip           #10.0.1.0/24
    vpn             ip           #OpenVPN clients
    dmz             ip           #LXC Containers

`/etc/shorewall/interfaces`:

    #ZONE  INTERFACE        OPTIONS
    loc    INT_IF           dhcp,physical=$INT_IF,ignore=1,wait=5,routefilter,nets=172.20.1.0/24,routeback
    net    COMB_IF          optional,sourceroute=0,routefilter=0,arp_ignore=1,proxyarp=0,physical=$COMB_IF,upnp,nosmurfs,tcpflags
    net    COMC_IF          optional,sourceroute=0,routefilter=0,arp_ignore=1,proxyarp=0,physical=$COMC_IF,upnp,nosmurfs,tcpflags,dhcp
    vpn    TUN_IF+          physical=tun+,ignore=1
    dmz    br0              routeback,proxyarp=1,required,wait=30

`/etc/shorewall/hosts:`

    #ZONE   HOST(S)                                 OPTIONS
    smc     COMB_IF:10.1.10.0/24
    smc     COMC_IF:10.0.0.0/24

`/etc/shorewall/providers`:

    #NAME             NUMBER   MARK    DUPLICATE  INTERFACE   GATEWAY         OPTIONS               COPY
    ?if $FALLBACK
    ComcastB          1        0x10000 -          COMB_IF     70.90.191.126 loose,fallback
    ComcastC          2        0x20000 -          COMC_IF     detect        loose,fallback
    ?elsif $STATISTICAL
    ComcastB          1        0x10000 -          COMB_IF     70.90.191.126 loose,load=0.66666667
    ComcastC          2        0x20000 -          COMC_IF     detect        loose,load=0.33333333
    ?else
    ComcastB          1        0x10000 -          COMB_IF     70.90.191.126 loose,balance=2
    ComcastC          2        0x20000 -          COMC_IF     detect        loose,balance
    ?endif
    ?if $PROXY && ! $SQUID2
    Squid             3        -       -          lo          -             tproxy 
    ?endif

Notice that in the current balance mode, as in the STATISTICAL mode, the business line is favored 2:1 over the consumer line.

Here is `/etc/shorewall/rtrules`:

    #SOURCE             DEST             PROVIDER  PRIORITY
    70.90.191.121       -                ComcastB  1000
    70.90.191.123       -                ComcastB  1000
    &COMC_IF            -                ComcastC  1000
    br0                 -                ComcastB  11000
    172.20.1.191        -                ComcastB  1000

For reference, this configuration generates these routing rules:

    root@gateway:~# ip rule ls
    0:      from all lookup local 
    1:      from all fwmark 0x80000/0x80000 lookup TProxy 
    999:    from all lookup main 
    1000:   from 70.90.191.121 lookup ComcastB 
    1000:   from 70.90.191.123 lookup ComcastB 
    1000:   from 172.20.1.191 lookup ComcastB 
    1000:   from 10.0.0.4 lookup ComcastC 
    10000:  from all fwmark 0x10000/0x30000 lookup ComcastB 
    10001:  from all fwmark 0x20000/0x30000 lookup ComcastC 
    11000:  from all iif br0 lookup ComcastB 
    32765:  from all lookup balance 
    32767:  from all lookup default 
    root@gateway:~# 

`/etc/shorewall/mangle` is not used to support Multi-ISP:

    #MARK                           SOURCE        DEST          PROTO  DPORT   SPORT
    TTL(+1):P                       INT_IF        -
    SAME:P                          INT_IF        -             tcp    80,443
    ?if $PROXY && ! $SQUID2
       DIVERT                       COMB_IF       -             tcp    -       80
       DIVERT                       COMC_IF       -             tcp    -       80
       DIVERT                       br0           172.20.1.0/24 tcp    -       80
       TPROXY(3129,172.20.1.254)    INT_IF        -             tcp    80
       ?if $PROXYDMZ
          TPROXY(3129,172.20.1.254) br0           -             tcp    80
       ?endif
    ?endif

## IPv6 Configuration

The IPv6 configuration has two separate sub-nets, both services through 6in4 tunnels from [Hurricane Electric](http://tunnelbroker.he.net). They are both configured through the Business IPv4 uplink. I originally had the sit2 tunnel configured through the consumer uplink but Comcast (Xfinity) decided to start blocking HE IPv6 tunnels on their consumer network, preferring their own 6to4 IPv6 solution.

One HE tunnel handles the servers and one tunnel handles the local network.

Here are the key entries in `/etc/shorewall6/shorewall6.conf`:

    ###############################################################################
    #                      F I R E W A L L  O P T I O N S
    ###############################################################################

    ...

    FASTACCEPT=No

    FORWARD_CLEAR_MARK=Yes

    IMPLICIT_CONTINUE=No

    IP_FORWARDING=Keep

    KEEP_RT_TABLES=Yes #Required when both IPv4 and IPv6 Multi-ISP are used

    ...

    TRACK_PROVIDERS=No

    USE_DEFAULT_RT=Yes

    ZONE2ZONE=-

    ...

    ################################################################################
    #                      P A C K E T  M A R K  L A Y O U T
    ################################################################################

    TC_BITS=8

    PROVIDER_BITS=8

    PROVIDER_OFFSET=8

    MASK_BITS=8

    ZONE_BITS=0

Here is `/etc/shorewall6/zones`:

    #ZONE   TYPE    OPTIONS
    fw      firewall
    net     ipv6
    loc     ipv6
    dmz     ipv6

`/etc/shorewall/interfaces`:

    #ZONE   INTERFACE       OPTIONS
    net     sit1            forward=1,sfilter=2001:470:b:227::40/124,optional
    net     sit2            forward=1,sfilter=2001:470:b:227::40/124,optional
    net     sit3            forward=1,sfilter=2001:470:b:227::40/124,optional
    loc     eth2            forward=1
    dmz     br0             routeback,forward=1,required

`/etc/shorewall/providers`:

    #NAME   NUMBER    MARK    DUPLICATE   INTERFACE GATEWAY                OPTIONS            COPY
    LOC     4        0x100    -           sit2      -                      track,balance,loose
    DMZ     5        0x200    -           sit1      -                      track,fallback,loose
    6to4    6        0x300    -           sit3      ::192.88.99.1          track,fallback,loose

Notice that the provider numbers are disjoint from those in the IPv4 configuration. This allows for unique provider names in `/etc/iproute2/rt_tables`:

    #
    # reserved values
    #
    255     local
    254     main
    253     default
    250     balance
    0       unspec
    #
    # local
    #
    1       ComcastB
    2       ComcastC
    3       TProxy
    4       LOC
    5       DMZ
    6       6to4

The `/etc/shorewall6/rtrules` file is straight-forward:

    #SOURCE                DEST                     PROVIDER             PRIORITY
    2001:470:B:227::1/64   ::/0                     DMZ                  11000
    2001:470:B:787::1/64   ::/0                     LOC                  11000
    2002:465a:bf79::1/64   ::/0                     6to4                 11000

This results in the following routing rules:

    root@gateway:~# ip -6 rule ls
    0:     from all lookup local 
    999:   from all lookup main 
    10003: from all fwmark 0x100/0xff00 lookup LOC 
    10004: from all fwmark 0x200/0xff00 lookup DMZ 
    10005: from all fwmark 0x300/0xff00 lookup 6to4 
    11000: from 2001:470:b:787::1/64 lookup LOC 
    11000: from 2001:470:b:227::1/64 lookup DMZ 
    11000: from 2002:465a:bf79::1/64 lookup 6to4 
    32765: from all lookup balance 
    32767: from all lookup default 
    root@gateway:~# 

[^1]: While we describe a setup using different ISPs in this article, the facility also works with two uplinks from the same ISP.
