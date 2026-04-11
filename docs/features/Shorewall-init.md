# Introduction

The Shorewall init scripts released from shorewall.net and by most distributions start Shorewall after networking. This allows Shorewall to detect the network configuration and taylor itself accordingly. It is possible to start Shorewall prior to networking but doing so limits the set of Shorewall features that can be used.

When Shorewall starts after networking, there is the possibility of unwanted connections being accepted between the time that an interface comes up and the time that Shorewall has finished starting up. Also, Shorewall has had no means of reacting when interfaces are brought up and down.

Beginning with Shorewall 4.4.10, a new package, Shorewall Init, is available. Shorewall Init serves two purposes:

1.  It can 'close' the firewall before the network interfaces are brought up during boot.

2.  It can change the firewall state as the result of interfaces being brought up or taken down.

These two features can be controlled independently. Shorewall Init can be used together with any combination of the other Shorewall packages. Shorewall-init works on RedHat-based, SuSE-based and Debian-based distributions.

# Closing the Firewall before the Network Interfaces are brought up

When Shorewall-init is first installed, it does nothing until you configure it.

The configuration file is `/etc/default/shorewall-init`on Debian-based systems and `/etc/sysconfig/shorewall-init` otherwise. There are two settings in the file:

PRODUCTS  
Lists the Shorewall packages that you want to integrate with Shorewall-init.

Example: PRODUCTS="shorewall shorewall6"

IFUPDOWN  
When set to 1, enables integration with NetworkManager and the ifup/ifdown scripts.

To close your firewall before networking starts:

1.  In the Shorewall-init configuration file, set PRODUCTS to the firewall products installed on your system.

2.  Be sure that your current firewall script(s) (normally in `/var/lib/<product>/firewall`) is(are) compiled with the 4.4.10 compiler.

    Shorewall and Shorewall6 users can execute these commands:

    shorewall compile
    shorewall6 compile
    Shorewall-lite and Shorewall6-lite users can execute these commands on the administrative system:

    shorewall export
    firewall-name-or-ip-address
    shorewall6 export
    firewall-name-or-ip-address

That's all that is required.

# Integration with NetworkManager and ifup/ifdown Scripts

To integrate with NetworkManager and ifup/ifdown, additional steps are required. You probably don't want to enable this feature if you run a link status monitor like FOOLSM.

1.  In the Shorewall-init configuration file, set IFUPDOWN=1.

2.  In your Shorewall interfaces file(s), set the `required` option on any interfaces that must be up in order for the firewall to start. At least one interface must have the `required` or `optional` option if you perform the next optional step.

3.  Optional) -- If you have specified at least one `required` or `optional` interface, you can then disable automatic firewall startup at boot time. On Debian systems, set startup=0 in `/etc/default/product`. On other systems, use your service startup configuration tool (chkconfig, insserv, ...) to disable startup.

    <div class="warning">

    If your system uses Upstart as it's system initialization daemon, you should not disable startup. Upstart is standard on recent Ubuntu and Fedora releases and is optional on Debian.

    </div>

The following actions occur when an interface comes up:

|                    |               |            |
|--------------------|---------------|------------|
| **FIREWALL STATE** | **INTERFACE** | **ACTION** |
| Any                | Required      | start      |
| stopped            | Optional      | start      |
| started            | Optional      | enable     |
| started            | Any           | restart    |

The following actions occur when an interface goes down:

|                    |               |            |
|--------------------|---------------|------------|
| **FIREWALL STATE** | **INTERFACE** | **ACTION** |
| Any                | Required      | stop       |
| stopped            | Optional      | start      |
| started            | Optional      | disable    |
| started            | Any           | restart    |

For optional interfaces, the `/var/lib/product/interface.state` files are maintained to reflect the state of the interface so that they may be used by the standard isusable script. Please note that the action is carried out using the current compiled script; the configuration is not recompiled.

A new option has been added to `shorewall.conf` and `shorewall6.conf`. The REQUIRE_INTERFACE option determines the outcome when an attempt to start/restart/restore/refresh the firewall is made and none of the optional interfaces are available. With REQUIRE_INTERFACE=No (the default), the operation is performed. If REQUIRE_INTERFACE=Yes, then the operation fails and the firewall is placed in the stopped state. This option is suitable for a laptop with both ethernet and wireless interfaces. If either come up, the firewall starts. If neither comes up, the firewall remains in the stopped state.

Similarly, if an optional interface goes down and there are no optional interfaces remaining in the up state, then the firewall is stopped.

On Debian-based systems, during system shutdown the firewall is opened prior to network shutdown (`/etc/init.d/shorewall stop` performs a 'clear' operation rather than a 'stop'). This is required by Debian standards. You can change this default behavior by setting SAFESTOP=1 in `/etc/default/shorewall` (`/etc/default/shorewall6`, ...).
