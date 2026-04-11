<div class="caution">

**Do not attempt to install Shorewall on a remote system. You are virtually assured to lock yourself out.**

</div>

Please read this short article first.

- [Introduction to Shorewall](Introduction.md)

Now, [install Shorewall](../reference/Install.md).

Next, read the QuickStart Guide that is appropriate for your configuration:

**If you just want to protect a system: (Requires Shorewall 4.4.12-Beta3 or later)**

- [Universal](../features/Universal.md) configuration -- requires no configuration to protect a single system.

  <div class="caution">

  This configuration places all interfaces in the net zone. If you add another interface or VPN, you will want to select a different QuickStart Guide.

  </div>

**If you have only one public IP address:**

- [Standalone](../reference/standalone.md) Linux System with a single network interface (if you are running Shorewall 4.4.12 Beta 3 or later, use the [Universal](../features/Universal.md) configuration instead).

- [Two-interface](../reference/two-interface.md) Linux System acting as a firewall/router for a small local network. For Redhat-specific install/configure information, see [this article](???) contributed by Digimer.

- [Three-interface](../reference/three-interface.md) Linux System acting as a firewall/router for a small local network and a DMZ.

**If you have more than one public IP address:**

- The [Shorewall Setup Guide](../reference/shorewall_setup_guide.md) outlines the steps necessary to set up a firewall where there are multiple public IP addresses involved or if you want to learn more about Shorewall than is explained in the single-address guides above.

The following articles are also recommended reading for newcomers.

- [Configuration File Basics](../reference/configuration_file_basics.md)

  > |                                                                            |                                                                                                |
  > |----------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
  > | [Man Pages](../reference/configuration_file_basics.md#Manpages)                        | [Using MAC Addresses in Shorewall](../reference/configuration_file_basics.md#MAC)                          |
  > | [Comments in configuration files](../reference/configuration_file_basics.md#Comments)  | [Using Shell Variables](../reference/configuration_file_basics.md#Variables)                               |
  > | [Attach Comment to Netfilter Rules](../reference/configuration_file_basics.md#COMMENT) | [Using DNS Names](../reference/configuration_file_basics.md#dnsnames)                                      |
  > | [Line Continuation](../reference/configuration_file_basics.md#Continuation)            | [Complementing an IP address or Subnet](../reference/configuration_file_basics.md#Compliment)              |
  > | [INCLUDE Directive](../reference/configuration_file_basics.md#INCLUDE)                 | [IP Address Ranges](../reference/configuration_file_basics.md#IPRanges)                                    |
  > | [Port Numbers/Service Names](../reference/configuration_file_basics.md#Ports)          | [Shorewall Configurations (making a test configuration)](../reference/configuration_file_basics.md#Levels) |
  > | [Port Ranges](../reference/configuration_file_basics.md#Ranges)                        |                                                                                                |

- [Operating Shorewall and Shorewall Lite](../reference/starting_and_stopping_shorewall.md) contains a lot of useful operational hints.

- PPPPPPPS ( or, Paul's Principles for Practical Provision of Packet Processing with Shorewall ) <http://linuxman.wikispaces.com/PPPPPPS>
