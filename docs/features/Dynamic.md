# Overview

There is sometimes a need to be able to define a zone whose members are unknown at compile-time. For example, you may wish to require authentication of internal users before allowing them access to the internet. When a user is authenticated, the user's IP address is added to the zone of users permitted web access.

Shorewall provides basic support for defining such zones. This support is based on [ipset](http://ipset.netfilter.org/). Most current distributions have ipset, but you may need to install the [xtables-addons](http://xtables-addons.sourceforge.net/) package.

# Dynamic Zones

Prior to Shorewall 4.5.9, when multiple records for a zone appear in `/etc/shorewall/hosts`, Shorewall would create a separate ipset for each interface. This meant that an add or delete command was required for each of the interface, when the address involved was reachable via multiple interfaces.

Beginning with Shoreawll 4.5.9, it is possible to have a single ipset shared among all interfaces. This also simplifies management of dynamic zone contents for dynamic zones associated with only a single interface.

The earlier implementation described below is still available in these later releases.

## Defining a Dynamic Zone

A dynamic zone is defined by specifying the **dynamic_shared** option in the zones file and using the **dynamic** keyword in the hosts list.

`/etc/shorewall/zones`:

    #NAME        TYPE             OPTIONS
    net          ipv4
    rsyncok:loc  ipv4             dynamic_shared

`/etc/shorewall/interfaces`:

    #ZONE       INTERFACE      BROADCAST        OPTIONS
    loc         eth0           -                …
    loc         eth1           -                …

`/etc/shorewall/hosts`:

    #ZONE       HOSTS          OPTIONS
    rsyncok     eth0:dynamic
    rsyncok     eth1:dynamic

When the **dynamic_shared** option is specified, a single ipset is created; the ipset has the same name as the zone.

In the above example, **rsyncok** is a sub-zone of the single zone **loc**. Making a dynamic zone a sub-zone of multiple other zones is also supported.

## Adding a Host to a Dynamic Zone.

Adding a host to a dynamic zone is accomplished by adding the host's IP address to the appropriate ipset. Shorewall provldes a command for doing that:

> `shorewall add` \<zone address\> ...

Example:

> `shorewall add rsyncok 70.90.191.124`

## Deleting a Host from a Dynamic Zone

Deleting a host from a dynamic zone is accomplished by removing the host's IP address from the appropriate ipset. Shorewall provldes a command for doing that:

> `shorewall delete` \<zone\> \<address\> ...

Example:

> `shorewall delete rsyncok 70.19.191.124`

The command can only be used when the ipset involved is of type iphash. For other ipset types, the `ipset` command must be used directly.

## Listing the Contents of a Dynamic Zone

The shorewall show command may be used to list the current contents of a dynamic zone.

> `shorewall show dynamic` \<zone\>

Example:

>     shorewall show dynamic rsyncok
>     rsyncok:
>        70.90.191.122
>        70.90.191.124

# Dynamic Zone Contents and Shorewall stop/start/restart

When SAVE_IPSETS=Yes in shorewall.conf, the contents of a dynamic zone survive `shorewall stop/shorewall start` and `shorewall restart`. During `shorewall stop`, the contents of the ipsets are saved in the file `${VARDIR}/ipsets.save` (usually `/var/lib/shorewall/ipsets.save`). During `shorewall start`, the contents of that file are restored to the sets. During both `shorewall start` and `shorewall restart`, any new ipsets required as a result of a configuration change are added.
