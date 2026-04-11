# Products

Shorewall 5.0 consists of six packages.

1.  **Shorewall Core**. This package contains the core Shorewall shell libraries and is required to install any of the other packages. Beginning with Shorewall 5.1.0, it also includes the Command Line Interface (CLI) program common to all of the packages.

2.  **Shorewall**. This package must be installed on at least one system in your network. It contains everything needed to create an IPv4 firewall.

3.  **Shorewall6**. This package requires the Shorewall package and adds those components needed to create an IPv6 firewall.

4.  **Shorewall-lite**. Shorewall allows for central administration of multiple IPv4 firewalls through use of Shorewall lite. The full Shorewall product is installed on a central administrative system where compiled Shorewall scripts are generated. These scripts are copied to the firewall systems where they run under the control of Shorewall-lite.

5.  **Shorewall6-lite**. Shorewall allows for central administration of multiple IPv4 firewalls through use of Shorewall lite. The full Shorewall product is installed on a central administrative system where compiled Shorewall scripts are generated. These scripts are copied to the firewall systems where they run under the control of Shorewall-lite.

6.  **Shorewall-init**. An add-on to any of the above packages that allows the firewall state to be altered in reaction to interfaces coming up and going down. Where Upstart is not being used, this package can also be configured to place the firewall in a safe state prior to bringing up the network interfaces.

# Shorewall

The Shorewall package includes a large number of files which were traditionally installed in `/sbin`, `/usr/share/shorewall`, `/etc/shorewall`, `/etc/init.d` and `/var/lib/shorewall/`. These are described in the sub-sections that follow.

<div class="important">

Since Shorewall 4.5.2, each of these directories is now relocatable using the [configure scripts included with Shorewall Core](../reference/Install.md#idp8774904608). These scripts set shell variables in the shorewallrc file which is normally installed in /usr/share/shorewall/. The name of the variable is included in parentheses in the section headings below.

</div>

## /sbin (\$SBINDIR)

The `/sbin/shorewall` shell program is used to interact with Shorewall. See [shorewall](https://shorewall.org/manpages/shorewall.html)(8).

## /usr/share/shorewall (\${SHAREDIR}/shorewall)

The bulk of Shorewall is installed here.

- `action.template` - template file for creating [actions](Actions.md).

- `action.*` - standard Shorewall actions.

- `actions.std` - file listing the standard actions.

- `compiler.pl` - The configuration compiler perl program.

- `configfiles` - A directory containing configuration files to copy to create a [Shorewall-lite export directory.](../features/Shorewall-Lite.md)

- `configpath` - A file containing distribution-specific path assignments.

- `firewall` - A shell program that handles the `add` and `delete` commands (see [shorewall](https://shorewall.org/manpages/shorewall.html)(8)). It also handles the `stop` and `clear` commands when there is no current compiled firewall script on the system.

- `functions` - A symbolic link to `lib.base` that provides for compatibility with older versions of Shorewall.

- `init` - A symbolic link to the init script (usually `/etc/init.d/shorewall`).

- `lib.*` - Shell function libraries used by the other shell programs. Most of these are actually provided by Shorewall-core.

- `macro.*` - The standard Shorewall [macros](Macros.md).

- `modules.*` - File that drives the loading of Netfilter kernel modules. May be overridden by `/etc/shorewall/modules`.

- `prog.*` - Shell program fragments used as input to the compiler.

- `Shorewall` - Directory containing the Shorewall Perl modules used by the compiler.

- `shorewallrc` - A file that specifies where all of the other installed components (from all packages) are installed.

- `version` - A file containing the currently install version of Shorewall.

- `wait4ifup` - A shell program that [extension scripts](../reference/shorewall_extension_scripts.md) can use to delay until a network interface is available.

## /etc/shorewall (\${CONFDIR}/shorewall)

This is where the modifiable IPv4 configuration files are installed.

## /etc/init.d or /etc/rc.d (depends on distribution) (\$INITDIR) or /lib/systemd/system (\$SERVICEDIR)

An init script is installed here. Depending on the distribution, it is named `shorewall` or `rc.firewall`. Only installed on systems where systemd is not installed.

When systemd is installed, the Shorewall .service files are installed in the directory specified by the SERVICEDIR variable in `/usr/share/shorewall/shorewallrc`.

## /var/lib/shorewall (\${VARLIB}/shorewall)

Shorewall doesn't install any files in this directory but rather uses the directory for storing state information. This directory may be relocated using [shorewall-vardir](https://shorewall.org/manpages/shorewall-vardir.html)(5).

- `.iptables-restore-input` - The file passed as input to the iptables-restore program to initialize the firewall during the last `start` or `restart` command (see [shorewall](https://shorewall.org/manpages/shorewall.html)(8)).

- `.modules` - The contents of the modules file used during the last `start` or `restart` command (see [shorewall](https://shorewall.org/manpages/shorewall.html)(8) for command information).

- `.modulesdir` - The MODULESDIR setting ([shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5)) at the last `start` or `restart`.

- `nat` - This unfortunately-named file records the IP addresses added by ADD_SNAT_ALIASES=Yes and ADD_IP_ALIASES=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5).

- `proxyarp` - Records the arp entries added by entries in [shorewall-proxyarp](https://shorewall.org/manpages/shorewall-proxyarp.html)(5).

- `.refresh` - The shell program that performed the last successful `refresh` command.

- `.restart` - The shell program that performed the last successful `restart` command.

- `restore` - The default shell program used to execute `restore` commands.

- `.restore` - The shell program that performed the last successful `refresh, restart` or `start` command.

- `save` - File created by the `save` command and used to restore the dynamic blacklist during `start/restart`.

- `.start` - The shell program that performed the last successful `start` command.

- `state` - Records the current firewall state.

- `zones` - Records the current zone contents.

# Shorewall6

Shorewall6 installs its files in a number of directories:

## /sbin (\$SBINDIR)

Prior to Shorewall 5.1.0, the `/sbin/shorewall6` shell program is used to interact with Shorewall6. See [shorewall6](https://shorewall.org/manpages/shorewall6.html)(8). Beginning with Shorewall 5.1.0, `/sbin/shorewall6` is a symbolic link to `/sbin/shorewall`. See [shorewall](https://shorewall.org/manpages/shorewall.html)(8).

## /usr/share/shorewall6 (\${SHAREDIR}/shorewall6)

The bulk of Shorewall6 is installed here.

- `action.template` - template file for creating [actions](Actions.md).

- `action.*` - standard Shorewall actions.

- `actions.std` - file listing the standard actions.

- `configfiles` - A directory containing configuration files to copy to create a [Shorewall6-lite export directory.](../features/Shorewall-Lite.md)

- `configpath` - A file containing distribution-specific path assignments.

- `firewall` - A shell program that handles the `add` and `delete` commands (see [shorewall](https://shorewall.org/manpages/shorewall.html)(8)). It also handles the `stop` and `clear` commands when there is no current compiled firewall script on the system.

- `functions` - A symbolic link to `lib.base` that provides for compatibility with older versions of Shorewall.

- `lib.*` - Shell function libraries used by the other shell programs.

- `Macros/*` - The standard Shorewall6 [macros](Macros.md).

- `modules` - File that drives the loading of Netfilter kernel modules. May be overridden by `/etc/shorewall/modules`.

- `version` - A file containing the currently install version of Shorewall.

- `wait4ifup` - A shell program that [extension scripts](../reference/shorewall_extension_scripts.md) can use to delay until a network interface is available.

## /etc/shorewall6 (\${CONFDIR}/shorewall6)

This is where the modifiable IPv6 configuration files are installed.

## /etc/init.d or /etc/rc.d (depends on distribution) (\$INITDIR) or /lib/systemd/system (\$SERVICEDIR)

An init script is installed here. Depending on the distribution, it is named `shorewall6` or `rc.firewall`. Only installed on systems where systemd is not installed.

When systemd is installed, the Shorewall .service files are installed in the directory specified by the SERVICEDIR variable in `/usr/share/shorewall/shorewallrc`.

## /var/lib/shorewall6 (\${VARLIB}/shorewall6)

Shorewall6 doesn't install any files in this directory but rather uses the directory for storing state information. This directory may be relocated using [shorewall-vardir](https://shorewall.org/manpages/shorewall-vardir.html)(5).

- `.ip6tables-restore-input` - The file passed as input to the ip6tables-restore program to initialize the firewall during the last `start` or `restart` command (see [shorewall6](https://shorewall.org/manpages/shorewall6.html)(8)).

- `.modules` - The contents of the modules file used during the last `start` or `restart` command (see [shorewall](https://shorewall.org/manpages/shorewall6.html)(8) for command information).

- `.modulesdir` - The MODULESDIR setting ([shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5)) at the last `start` or `restart`.

- `.refresh` - The shell program that performed the last successful `refresh` command.

- `.restart` - The shell program that performed the last successful `restart` command.

- `restore` - The default shell program used to execute `restore` commands.

- `.restore` - The shell program that performed the last successful `refresh, restart` or `start` command.

- `save` - File created by the `save` command and used to restore the dynamic blacklist during `start/restart`.

- `.start` - The shell program that performed the last successful `start` command.

- `state` - Records the current firewall state.

- `zones` - Records the current zone contents.

# Shorewall-lite

The Shorewall-lite product includes files installed in `/sbin`, `/usr/share/shorewall-lite`, `/etc/shorewall-lite`, `/etc/init.d` and `/var/lib/shorewall-lite/`. These are described in the sub-sections that follow.

## /sbin (\$SBINDIR)

The `/sbin/shorewall-lite` shell program is used to interact with Shorewall lite. See [shorewall-lite](https://shorewall.org/manpages/shorewall-lite.html)(8). Beginning with Shorewall 5.1.0, `/sbin/shorewall-lite` is a symbolic link to `/sbin/shorewall`. See [shorewall](https://shorewall.org/manpages/shorewall.html)(8).

## /etc/init.d or /etc/rc.d (depends on distribution) (\$INITDIR) or /lib/systemd/system (\$SERVICEDIR)

An init script is installed here. Depending on the distribution, it is named `shorewall-lite` or `rc.firewall`. Only installed on systems where systemd is not installed.

When systemd is installed, the Shorewall .service files are installed in the directory specified by the SERVICEDIR variable in `/usr/share/shorewall/shorewallrc`.

## /etc/shorewall-lite (\${CONFDIR}/shorewall-lite)

This is where the modifiable configuration files are installed.

## /usr/share/shorewall-lite (\${SHAREDIR}/shorewall-lite)

The bulk of Shorewall-lite is installed here.

- `configpath` - A file containing distribution-specific path assignments.

- `functions` - A symbolic link to `lib.base` that provides for compatibility with older versions of Shorewall.

- `lib.base` - Shell function librarie used by the other shell programs. This is a thin wrapper around `/usr/share/shorewall/lib.base`.

- `modules`\* - Files that drive the loading of Netfilter kernel modules. May be overridden by `/etc/shorewall-lite/modules`.

- `shorecap` - A shell program used for generating capabilities files. See the [Shorewall-lite documentation](../features/Shorewall-Lite.md).

- `version` - A file containing the currently install version of Shorewall.

- `wait4ifup` - A shell program that [extension scripts](../reference/shorewall_extension_scripts.md) can use to delay until a network interface is available.

## /var/lib/shorewall-lite (\${VARLIB}/shorewall-lite)

Shorewall-lite doesn't install any files in this directory but rather uses the directory for storing state information. This directory may be relocated using [shorewall-lite-vardir](https://shorewall.org/manpages/shorewall-lite-vardir.html)(5).

- `firewall` - Compiled shell script installed by running the load or reload command on the administrative system (see [shorewall](https://shorewall.org/manpages/shorewall.html)(8)).

- `firewall.conf` - Digest of the shorewall.conf file used to compile the firewall script on the administrative system.

<!-- -->

- `.iptables-restore-input` - The file passed as input to the iptables-restore program to initialize the firewall during the last `start` or `restart` command (see [shorewall-lite](https://shorewall.org/manpages/shorewall-lite.html)(8)).

- `.modules` - The contents of the modules file used during the last `start` or `restart` command (see [shorewall-lite](https://shorewall.org/manpages/shorewall-lite.html)(8) for command information).

- `.modulesdir` - The MODULESDIR setting ([shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5)) at the last `start` or `restart.`

- `nat` - This unfortunately-named file records the IP addresses added by ADD_SNAT_ALIASES=Yes and ADD_IP_ALIASES=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5).

- `proxyarp` - Records the arp entries added by entries in [shorewall-proxyarp](https://shorewall.org/manpages/shorewall-proxyarp.html)(5).

- `.refresh` - The shell program that performed the last successful `refresh` command.

- `.restart` - The shell program that performed the last successful `restart` command.

- `restore` - The default shell program used to execute `restore` commands.

- `.restore` - The shell program that performed the last successful `refresh, restart` or `start` command.

- `save` - File created by the `save` command and used to restore the dynamic blacklist during `start/restart`.

- `.start` - The shell program that performed the last successful `start` command.

- `state` - Records the current firewall state.

- `zones` - Records the current zone contents.

# Shorewall6-lite

The Shorewall6-lite product includes files installed in `/sbin`, `/usr/share/shorewall6-lite`, `/etc/shorewall6-lite`, `/etc/init.d` and `/var/lib/shorewall6-lite/`. These are described in the sub-sections that follow.

## /sbin

The `/sbin/shorewall6-lite` shell program is use to interact with Shorewall lite. See [shorewall6-lite](https://shorewall.org/manpages/shorewall6-lite.html)(8). Beginning with Shorewall 5.1.0, `/sbin/shorewall6`-lite is a symbolic link to `/sbin/shorewall`. See [shorewall](https://shorewall.org/manpages/shorewall.html)(8).

## /etc/init.d or /etc/rc.d (depends on distribution) (\$INITDIR) or /lib/systemd/system (\$SERVICEDIR)

An init script is installed here. Depending on the distribution, it is named `shorewall`6-lite or `rc.firewall`. Only installed on systems where systemd is not installed.

When systemd is installed, the Shorewall .service files are installed in the directory specified by the SERVICEDIR variable in `/usr/share/shorewall/shorewallrc`.

## /etc/shorewall6-lite (\${CONFDIR}/shorewall6-lite)

This is where the modifiable configuration files are installed.

## /usr/share/shorewall6-lite (\${SHAREDIR}/shorewall6-lite)

The bulk of Shorewall-lite is installed here.

- `configpath` - A file containing distribution-specific path assignments.

- `functions` - A symbolic link to `lib.base` that provides for compatibility with older versions of Shorewall.

- `lib.base` - Shell function librarie used by the other shell programs. This is a thin wrapper around `/usr/share/shorewall/lib.base`.

- `modules`\* - Files that drive the loading of Netfilter kernel modules. May be overridden by `/etc/shorewall-lite/modules`.

- `shorecap` - A shell program used for generating capabilities files. See the [Shorewall-lite documentation](../features/Shorewall-Lite.md).

- `version` - A file containing the currently install version of Shorewall.

- `wait4ifup` - A shell program that [extension scripts](../reference/shorewall_extension_scripts.md) can use to delay until a network interface is available.

## /var/lib/shorewall6-lite (\${VARLIB}/shorewall6-lite)

Shorewall6-lite doesn't install any files in this directory but rather uses the directory for storing state information. This directory may be relocated using [shorewall-lite-vardir](https://shorewall.org/manpages/shorewall-lite-vardir.html)(5).

- `firewall` - Compiled shell script installed by running the load or reload command on the administrative system (see [shorewall6](https://shorewall.org/manpages/shorewall.html)(8)).

- `firewall.conf` - Digest of the shorewall.conf file used to compile the firewall script on the administrative system.

<!-- -->

- `.ip6tables-restore-input` - The file passed as input to the ip6tables-restore program to initialize the firewall during the last `start` or `restart` command (see [shorewall-lite](https://shorewall.org/manpages/shorewall-lite.html)(8)).

- `.modules` - The contents of the modules file used during the last `start` or `restart` command (see [shorewall-lite](https://shorewall.org/manpages/shorewall-lite.html)(8) for command information).

- `.modulesdir` - The MODULESDIR setting ([shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5)) at the last `start` or `restart.`

- `.refresh` - The shell program that performed the last successful `refresh` command.

- `.restart` - The shell program that performed the last successful `restart` command.

- `restore` - The default shell program used to execute `restore` commands.

- `.restore` - The shell program that performed the last successful `refresh, restart` or `start` command.

- `save` - File created by the `save` command and used to restore the dynamic blacklist during `start/restart`.

- `.start` - The shell program that performed the last successful `start` command.

- `state` - Records the current firewall state.

- `zones` - Records the current zone contents.
