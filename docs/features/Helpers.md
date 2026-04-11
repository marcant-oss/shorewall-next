# Helpers - Introduction

There are a number of applications that create connections dynamically between a client and server. These connections use temporary TCP or UDP ports, so static configuration of firewall rules to allow those connections would require a very lax firewall configuration. To deal with these problem applications, Netfilter supports the concept of a helper. Each helper monitors traffic to/from the default primary port used by the application and opens the firewall to accept temporary connections created by the primary session.

There are helpers for the following applications; default ports monitored by each helper are listed in parentheses:

- Amanda (UDP 10080)

- FTP (TCP 21)

- H323 (UDP 1719, TCP 1720)

- IRC (TCP 6667)

- Netbios-NS (UDP 137)

- PPTP (TCP 1723)

- SANE (TCP 6566)

- SIP (UDP 5060)

- SNMP (UDP 161)

- TFTP (UDP 69)

## Helper Module Loading

In a modular kernel, each helper is typically packaged as two kernel modules. One module handles connection tracking where NAT isn't involved and the other module handles NAT. For example, the FTP helper consists of these two modules (kernels 2.6.20 and later):

- nf_conntrack_ftp

- nf_nat_ftp

Note that the naming convention is nf_conntrack\_\<application\> and nf_nat\_\<application\>; more about that below.

Prior to Shorewall 4.5.7, helper modules were not auto-loaded and must be loaded explicitly using the `modprob` or `insmod` utilities. Beginning with Shorewall 4.5.7, these modules are loaded when Shorewall is determining the capabilities of your system.

Many of the modules allow parameters to be specified when the module is loaded. Among the common parameters is the `ports` parameter that lists one or more ports that the module is to monitor. This allows running the application on a non-standard port.

## Iptables and Helpers

Iptables supports two ways of interacting with modules:

Helper Match  
This match (-m helper --helper \<name\>) allows selection of packets from connections monitored or created by the named helper.

CT Target  
This target (-j CT --helper \<name\> ...) , introduced in the 3.4 kernels, allows for explicit association of a helper with a connection.

It is important to note that the name used in iptables is not always the same as the name in the kernel module. Names used in iptables are shown in the following table:

|                         |                                      |
|-------------------------|--------------------------------------|
| Name of kernel module   | Name recognized by iptables          |
| nf_conntrack_amanda     | amanda                               |
| nf_conntrack_ftp        | ftp                                  |
| nf_conntrack_h323       | **RAS (udp 1719), Q.931 (tcp 1720)** |
| nf_conntrack_irc        | irc                                  |
| nf_conntrack_netbios_ns | **netbios-ns**                       |
| nf_conntrack_pptp       | pptp                                 |
| nf_conntrack_sane       | sane                                 |
| nf_conntrack_sip        | sip                                  |
| nf_conntrack_snmp       | snmp                                 |
| nf_conntrack_tftp       | tftp                                 |

Netfilter helpers present an opportunity for attackers to attempt to breach your firewall by IP address spoofing; See <https://home.regit.org/netfilter-en/secure-use-of-helpers/> for a description of the Netfilter facilities available to meet these attacks.

# Shorewall Support for Helpers

Shorewall includes support for helpers is several areas. These areas are covered in the sections below.

## Module Loading

Shorewall includes support for loading the helper modules as part of its support for loading kernel modules in general. There are several options in shorewall.conf (5) that deal with kernel module loading:

MODULESDIR  
This option specifies a comma-separated list of directories where Shorewall will look for kernel modules to load.

MODULE_SUFFIX  
Lists the possible suffixes for module names.

LOAD_HELPERS_ONLY  
Controls whether Shorewall should load only the helpers and leave the other modules to the auto-loader. This option dramatically reduces the time to process a `shorewall start` or `shorewall restart` command.

DONT_LOAD  
This is a comma-separated list of modules that you specifically don't want Shorewall to load.

HELPERS  
This option was added in Shorewall 4.5.7 and lists the modules to be enabled for association with connections (comma-separated). This option is fully functional only on systems running kernel 3.5 or later.

The module names allowed in this list are **amanda**, **ftp**, **h323**, **irc**, **netbios-ns**, **pptp**, **sane**, **sip**, **snmp** and **tftp**. If you don't want a particular helper module loaded, then:

- List it in the DONT_LOAD option; and

- Explicitly list those helpers that you do want in HELPERS.

AUTOHELPERS  
This option was also added in Shorewall 4.5.7. When enabled on systems that support the CT Target capability, it provides automatic association of helpers to connections in the same manner as in pre-3.5 kernels (and with the same vulnerabilities).

The helper modules to be loaded are listed in the file `/usr/share/shorewall/helpers`. If you wish to customize that file to load only a subset of the helpers or to specify module parameters, then copy the file to `/etc/shorewall/`and modify the copy. That way, your changes won't be overwritten the next time that Shorewall is updated on your system.

On systems running a a kernel earlier than 3.5, not all of the helpers can be totally disabled. The following modules can be disabled by using the parameter **ports=0** in /etc/shorewall/helpers:

- ftp

- irc

- sane

- sip

- tftp

After disabling one or more helpers using this method, you must:

- Unload the related module(s).

- Restart Shorewall (use the -c option (e.g., `shorewall restart -c`) if you have AUTOMAKE=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5))..

Note that if you choose to reboot your system to unload the modules, then if you have CT:helper entries in [shorewall-conntrack](https://shorewall.org/manpages/shorewall-conntrack.html) (5) that refer to the module(s) and you have AUTOMAKE=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5), then Shorewall will fail to start at boot time.

## Iptables

The iptables helper match is supported by Shorewall in the form of the HELPER column in [shorewall-mangle](https://shorewall.org/manpages/shorewall-mangle.html) (5) and [shorewall-tcrules](https://shorewall.org/manpages/shorewall-tcrules.html) (5).

The CT target is supported directly in [shorewall-conntrack](https://shorewall.org/manpages/shorewall-conntrack.html) (5).

In these files, Shorewall supports the same module names as iptables; see the table above.

Beginning with Shorewall 4.5.7, there is a HELPER column in [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5). In the NEW section, this column allows the explicit association of a helper with connections allowed by a given rules. The column may contain any of the helper names recognized by iptables (see the table above). In the RELATED section, the rule will only match the packet if the related connection has the named helper attached.

Also added in Shorewall 4.5.7 is the HELPER action in [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5). HELPER rules associate the helper listed in the HELPER column with connections that match the rule. A destination zone should not be specified in HELPER rules.

## Capabilities

The output of `shorewall show capabilities` has two entries for each of the helpers listed above that can be disabled by adding **ports=0** in /etc/shorewall/helpers.

    shorewall show capabilities
       Amanda Helper: Available
       FTP Helper: Not available
       FTP-0 Helper: Available
       IRC Helper: Not available
       IRC-0 Helper: Available
       Netbios_ns Helper: Available
       H323 Helper: Not available
       PPTP Helper: Available
       SANE Helper: Not available
       SANE-0 Helper: Available
       SNMP Helper: Available
       TFTP Helper: Not available
       TFTP-0 Helper: Available
       iptables -S (IPTABLES_S): Available
       Basic Filter (BASIC_FILTER): Available
       CT Target (CT_TARGET): Available
       Kernel Version (KERNELVERSION): 30404
       Capabilities Version (CAPVERSION): 40507

The above output is produced when this /etc/shorewall/helpers file is used on a system running kernel 3.4.4:

    loadmodule nf_conntrack_ftp         ports=0
    loadmodule nf_conntrack_irc         ports=0
    loadmodule nf_conntrack_netbios_ns
    loadmodule nf_conntrack_sip         ports=0
    loadmodule nf_conntrack_tftp        ports=0
    loadmodule nf_conntrack_sane        ports=0

The reason for the double capabilities is that when **ports=0** is specified, the iptables name of the helper gets '-0' added to it. So in order for the compiler to generate the correct iptables commands, it needs to know if **ports=0** was specified for each of the helprs that support it.

Notice that most of the other helpers are available, even though their modules were not loaded. That's because auto-loading occurs during capability detection on those modules whose iptables name matches the module name.

# Kernel \>= 3.5 and Shorewall \>= 4.5.7

While the AUTOHELPER option described above provides for seamless migration to kernel 3.5 and beyond, we recommend setting AUTOHELPER=No at the first opportunity after migrating. Additionally, you should:

- Use the HELPER action and the HELPER column in [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5) to attach helpers to only those connections that you need to support.

- If you run one or more servers (such as an FTP server) that interact with helpers, you should consider adding rules to the RELATED section of [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5) to limit the scope of the helper. Suppose that your Linux FTP server is in zone dmz and has address 70.90.191.123.

      #ACTION               SOURCE                         DEST                      PROTO            DPORT          SPORT
      SECTION RELATED
      ACCEPT                all                            dmz:70.90.191.123                          32768:               ; helper=ftp   # passive FTP to dmz server; /proc/sys/net/ipv4/ip_local_port_range == 32760:65535
      ACCEPT                dmz:70.90.191.123              all                       tcp              1024:          20    ; helper=ftp   # active  FTP to dmz server
      ACCEPT                loc,dmz,$FW                    net                       tcp              -              1024: ; helper=ftp   # passive FTP to net
      ACCEPT                net                            all                       tcp              1024:          20    ; helper=ftp   # active  FTP from net
      DROP:info             all                            all                                                             ; helper=ftp   # 
      SECTION NEW
      HELPER                all                            net                       tcp              21                   ; helper=ftp
      ACCEPT                all                            dmz:70.90.191.123         tcp              21                   ; helper=ftp
