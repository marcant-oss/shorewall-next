<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation appropriate for your version.**

</div>

# Overview

Shorewall has the capability to compile a Shorewall configuration and produce a runnable firewall program script. The script is a complete program which can be placed on a system with *Shorewall Lite* installed and can serve as the firewall creation script for that system.

## Shorewall Lite

Shorewall Lite is a companion product to Shorewall and is designed to allow you to maintain all Shorewall configuration information on a single system within your network.

1.  You install the full Shorewall release on one system within your network. You need not configure Shorewall there and you may totally disable startup of Shorewall in your init scripts. For ease of reference, we call this system the 'administrative system'.

    The administrative system may be a GNU/Linux system, a Windows system running [Cygwin](http://www.cygwin.com/) or an [Apple MacIntosh](http://www.apple.com/mac/) running OS X. Install from a shell prompt [using the install.sh script](../reference/Install.md).

2.  On each system where you wish to run a Shorewall-generated firewall, you install Shorewall Lite. For ease of reference, we will call these systems the 'firewall systems'.

    <div class="note">

    The firewall systems do **NOT** need to have the full Shorewall product installed but rather only the Shorewall Lite product. Shorewall and Shorewall Lite may be installed on the same system but that isn't encouraged.

    </div>

3.  On the administrative system you create a separate 'export directory' for each firewall system. You copy the contents of `/usr/share/shorewall/configfiles` into each export directory.

    <div class="note">

    Users of Debian and derivatives that install the package from their distribution will be disappointed to find that `/usr/share/shorewall/configfiles` does not exist on their systems. They will instead need to either:

    - Copy the files in /usr/share/doc/shorewall/default-config/ into each export directory.

    - Copy /etc/shorewall/shorewall.conf into each export directory and remove /etc/shorewall from the CONFIG_PATH setting in the copied files.

    or

    - Download the Shorewall tarball corresponding to their package version.

    - Untar and copy the files from the `configfiles` sub-directory in the untarred `shorewall-...` directory.

    </div>

    After copying, you may need to change two setting in the copy of shorewall.conf:

    - CONFIG_PATH=/usr/share/shorewall

    - STARTUP_LOG=/var/log/shorewall-lite-init.log

    Older versions of Shorewall included copies of shorewall.conf with these settings already modified. This practice was discontinued in Shorewall 4.4.20.1.

4.  Prior to Shorewall 4.5.8, the `/etc/shorewall/shorewall.conf` file was used to determine the VERBOSITY setting which determines how much output the compiler generates. All other settings were taken from the `shorewall.conf`file in the remote systems export directory.

    <div class="caution">

    Prior to Shorewall 4.5.8, if you want to be able to allow non-root users to manage remote firewall systems, then the files `/etc/shorewall/params` and `/etc/shorewall/shorewall.conf` must be readable by all users on the administrative system. Not all packages secure the files that way and you may have to change the file permissions yourself.

    Prior to Shorewall 4.5.14, `/etc/shorewall/params` must be readable by non-root users or each export directory must have its own params file.

    </div>

5.  On each firewall system, If you are running Debian or one of its derivatives like Ubuntu then edit `/etc/default/shorewall-lite` and set startup=1.

6.  On the administrative system, for each firewall system you do the following (this may be done by a non-root user who has root ssh access to the firewall system):

    1.  modify the files in the corresponding export directory appropriately (i.e., *just as you would if you were configuring Shorewall on the firewall system itself*). It's a good idea to include the IP address of the administrative system in the [`stoppedrules` file](https://shorewall.org/manpages/shorewall-stoppedrules.html).

        It is important to understand that with Shorewall Lite, the firewall's export directory on the administrative system acts as `/etc/shorewall` for that firewall. So when the Shorewall documentation gives instructions for placing entries in files in the firewall's `/etc/shorewall`, when using Shorewall Lite you make those changes in the firewall's export directory on the administrative system.

        The CONFIG_PATH variable is treated as follows:

        - The value of CONFIG_PATH in `/etc/shorewall/shorewall.conf` is ignored when compiling for export (the -e option in given) and when the `load` or `reload` command is being executed (see below).

        - The value of CONFIG_PATH in the `shorewall.conf` file in the export directory is used to search for configuration files during compilation of that configuration.

        - The value of CONFIG_PATH used when the script is run on the firewall system is "/etc/shorewall-lite:/usr/share/shorewall-lite".

        - Prior to Shorewall 4.5.14, the export directory should contain a `params` file, even if it is empty. Otherwise, `/sbin/shorewall` will attempt to read`/etc/shorewall/params`.

        - If the remote system has a different directory layout from the administrative system, then the export directory should contain a copy of the remote system's shorewallrc file (normally found in /usr/share/shorewall/shorewallrc).

    2.  cd <export directory>
            /sbin/shorewall remote-start firewall

        The [`remote-start`](../reference/starting_and_stopping_shorewall.md#Load) command compiles a firewall script from the configuration files in the current working directory (using `shorewall compile -e`), copies that file to the remote system via scp and starts Shorewall Lite on the remote system via ssh.

        Example (firewall's DNS name is 'gateway'):

        `/sbin/shorewall remote-start gateway`

        <div class="note">

        Although scp and ssh are used by default, you can use other utilities by setting RSH_COMMAND and RCP_COMMAND in `/etc/shorewall/shorewall.conf`.

        </div>

        The first time that you issue a `load` command, Shorewall will use ssh to run `/usr/share/shorewall-lite/shorecap` on the remote firewall to create a capabilities file in the firewall's administrative direction. It also uses scp to copy the shorewallrc file from the remote firewall system. See [below](#Shorecap).

7.  If you later need to change the firewall's configuration, change the appropriate files in the firewall's export directory then:

        cd <export directory>
        /sbin/shorewall remote-reload firewall

    The [`remote-reload`](https://shorewall.org/manpages/shorewall.html) command compiles a firewall script from the configuration files in the current working directory (using `shorewall compile -e`), copies that file to the remote system via scp and reloads Shorewall Lite on the remote system via ssh. The **remote-reload** command also supports the '-c' option.

There is a `shorewall-lite.conf` file installed as part of Shorewall Lite (`/etc/shorewall-lite/shorewall-lite.conf`). You can use that file on the firewall system to override some of the settings from the shorewall.conf file in the export directory.

Settings that you can override are:

> VERBOSITY
>
> LOGFILE
>
> LOGFORMAT
>
> IPTABLES
>
> PATH
>
> SHOREWALL_SHELL
>
> SUBSYSLOCK
>
> RESTOREFILE

You will normally never touch `/etc/shorewall-lite/shorewall-lite.conf` unless you run Debian or one of its derivatives (see [above](#Debian)).

The `/sbin/shorewall-lite` program included with Shorewall Lite supports the same set of commands as the `/sbin/shorewall` program in a full Shorewall installation with the following exceptions:

> add
>
> compile
>
> delete
>
> refresh
>
> reload
>
> try
>
> safe-start
>
> safe-restart
>
> show actions
>
> show macros

On systems with only Shorewall Lite installed, I recommend that you create a symbolic link `/sbin/shorewall` and point it at `/sbin/shorewall-lite`. That way, you can use `shorewall` as the command regardless of which product is installed.

>     ln -sf shorewall-lite /sbin/shorewall

### Module Loading

As with a normal Shorewall configuration, the shorewall.conf file can specify LOAD_HELPERS_ONLY which determines if the `modules` file (LOAD_HELPERS_ONLY=No) or `helpers` file (LOAD_HELPERS_ONLY=Yes) is used. Normally, the file on the firewall system is used. If you want to specify modules at compile time on the Administrative System, then you must place a copy of the appropriate file (`modules` or `helpers`) in the firewall's configuration directory before compilation.

In Shorewall 4.4.17, the EXPORTMODULES option was added to shorewall.conf (and shorewall6.conf). When EXPORTMODULES=Yes, any `modules` or `helpers` file found on the CONFIG_PATH on the Administrative System during compilation will be used.

In Shorewall 5.2.3, the LOAD_HELPERS_ONLY option was removed and the behavior is that which was formerly obtained by setting LOAD_HELPERS_ONLY=Yes.

### Converting a system from Shorewall to Shorewall Lite

Converting a firewall system that is currently running Shorewall to run Shorewall Lite instead is straight-forward.

1.  On the administrative system, create an export directory for the firewall system.

2.  Copy the contents of `/etc/shorewall/` from the firewall system to the export directory on the administrative system.

3.  On the firewall system:

    Be sure that the IP address of the administrative system is included in the firewall's export directory `stoppedrules` file.

        shorewall stop

    **We recommend that you uninstall Shorewall at this point.**

4.  Install Shorewall Lite on the firewall system.

    If you are running Debian or one of its derivatives like Ubuntu then edit `/etc/default/shorewall-lite` and set startup=1.

5.  On the administrative system:

    It's a good idea to include the IP address of the administrative system in the firewall system's [`stoppedrules` file](https://shorewall.org/manpages/shorewall-stoppedrules.html).

    Also, edit the `shorewall.conf` file in the firewall's export directory and change the CONFIG_PATH setting to remove `/etc/shorewall`. You can replace it with `/usr/share/shorewall/configfiles` if you like.

    Example:

    > Before editing:
    >
    >     CONFIG_PATH=/etc/shorewall:/usr/share/shorewall
    >
    > After editing:
    >
    >     CONFIG_PATH=/usr/share/shorewall/configfiles:/usr/share/shorewall

    Changing CONFIG_PATH will ensure that subsequent compilations using the export directory will not include any files from `/etc/shorewall` other than `shorewall.conf` and `params`.

    If you set variables in the params file, there are a couple of issues:

    The `params` file is not processed at run time if you set EXPORTPARAMS=No in `shorewall.conf`. For run-time setting of shell variables, use the `init` extension script. Beginning with Shorewall 4.4.17, the variables set in the `params` file are available in the firewall script when EXPORTPARAMS=No.

    If the `params` file needs to set shell variables based on the configuration of the firewall system, you can use this trick:

        EXT_IP=$(ssh root@firewall "/sbin/shorewall-lite call find_first_interface_address eth0")

    The `shorewall-lite call` command allows you to to call interactively any Shorewall function that you can call in an extension script.

    After having made the above changes to the firewall's export directory, execute the following commands.

    >     cd <export directory>
    >     /sbin/shorewall remote-start <firewall system>
    >
    > Example (firewall's DNS name is 'gateway'):
    >
    > `/sbin/shorewall remote-start gateway`

    The first time that you issue a `remote-start` command, Shorewall will use ssh to run `/usr/share/shorewall-lite/shorecap` on the remote firewall to create a capabilities file in the firewall's administrative direction. See [below](#Shorecap).

    The [`load`](../reference/starting_and_stopping_shorewall.md#Load) command compiles a firewall script from the configuration files in the current working directory (using `shorewall compile -e`), copies that file to the remote system via `scp` and starts Shorewall Lite on the remote system via `ssh`.

6.  If you later need to change the firewall's configuration, change the appropriate files in the firewall's export directory then:

        cd <export directory>
        /sbin/shorewall remote-reload firewall

    The [`reload`](../reference/starting_and_stopping_shorewall.md#Reload) command compiles a firewall script from the configuration files in the current working directory (using `shorewall compile -e`), copies that file to the remote system via `scp` and restarts Shorewall Lite on the remote system via `ssh`.

7.  If the kernel/iptables configuration on the firewall later changes and you need to create a new `capabilities` file, do the following on the firewall system:

        /usr/share/shorewall-lite/shorecap > capabilities
        scp capabilities <admin system>:<this system's config dir>

    Or simply use the -c option the next time that you use the `remote-reload` command (e.g., `shorewall remote-reload -c gateway`).

8.  Shorewall6-lite works with Shorewall6 in the same way that Shorewall-lite works with Shorewall. Beginning with Shorewall 5.0.0, running 'shorewall \<cmd\>" is the same as running "shorewall-lite \<cmd\>" when Shorewall is not installed.. To continue to use the "shorewall6" command after switching to Shoerwall6-lite, you need to add this to your .profile (or to .bashrc if root's shell is bash):

            alias shorewall6=shorewall6-lite

## Restrictions

While compiled Shorewall programs (as are used in Shorewall Lite) are useful in many cases, there are some important restrictions that you should be aware of before attempting to use them.

1.  All extension scripts used are copied into the program (with the exception of [those executed at compile-time by the compiler](../reference/shorewall_extension_scripts.md)). The ramifications of this are:

    - If you update an extension script, the compiled program will not use the updated script.

    - The `params` file is only processed at compile time if you set EXPORTPARAMS=No in `shorewall.conf`. For run-time setting of shell variables, use the `init` extension script. Although the default setting is EXPORTPARAMS=Yes for compatibility, the recommended setting is EXPORTPARAMS=No. Beginning with Shorewall 4.4.17, the variables set in the `params` file are available in the firewall script when EXPORTPARAMS=No.

      If the `params` file needs to set shell variables based on the configuration of the firewall system, you can use this trick:

          EXT_IP=$(ssh root@firewall "/sbin/shorewall-lite call find_first_interface_address eth0")

      The `shorewall-lite call` command allows you to to call interactively any Shorewall function that you can call in an extension script.

2.  You must install Shorewall Lite on the system where you want to run the script. You then install the compiled program in /usr/share/shorewall-lite/firewall and use the /sbin/shorewall-lite program included with Shorewall Lite to control the firewall just as if the full Shorewall distribution was installed.

3.  Beginning with Shorewall 4.4.9, the compiler detects bridges and sets the **bridge** and **routeback** options explicitly. That can't happen when the compilation no longer occurs on the firewall system.

# The "shorewall compile" command

A compiled script is produced using the `compile` command:

> `shorewall compile [ -e ] [ <directory name> ] [ <path name> ]`

where

> -e  
> Indicates that the program is to be "exported" to another system. When this flag is set, neither the "detectnets" interface option nor DYNAMIC_ZONES=Yes in shorewall.conf are allowed. The created program may be run on a system that has only Shorewall Lite installed
>
> When this flag is given, Shorewall does not probe the current system to determine the kernel/iptables features that it supports. It rather reads those capabilities from `/etc/shorewall/capabilities`. See below for details.
>
> Also, when `-e` is specified you should have a copy of the remote firewall's `shorewallrc` file in the the directory specified by \<\<directory name\>\>.
>
> \<directory name\>  
> specifies a directory to be searched for configuration files before those directories listed in the CONFIG_PATH variable in `shorewall.conf`.
>
> When -e \<\<directory-name\>\> is included, only the SHOREWALL_SHELL and VERBOSITY settings from `/etc/shorewall/shorewall.conf` are used and these apply only to the compiler itself. The settings used by the compiled firewall script are determined by the contents of `<directory name>/shorewall.conf`.
>
> <div class="note">
>
> Beginning with Shorewall 4.5.7.2, `/etc/shorewall/shorewall.conf` is not read if there is a `shorewall.conf` file in the specified configuration directory.
>
> </div>
>
> \<path name\>  
> specifies the name of the script to be created. If not given, \${VARDIR}/firewall is assumed (by default, \${VARDIR} is `/var/lib/shorewall/`)

The compile command can be used to stage a new compiled strict that can be activated later using

shorewall restart -f

# The /etc/shorewall/capabilities file and the shorecap program

As mentioned above, the `/etc/shorewall/capabilities` file specifies that kernel/iptables capabilities of the target system. Here is a sample file:

>     #
>     # Shorewall detected the following iptables/netfilter capabilities - Tue Jul 15 07:28:12 PDT 2008
>     #
>     NAT_ENABLED=Yes
>     MANGLE_ENABLED=Yes
>     MULTIPORT=Yes
>     XMULTIPORT=Yes
>     CONNTRACK_MATCH=Yes
>     POLICY_MATCH=Yes
>     PHYSDEV_MATCH=Yes
>     PHYSDEV_BRIDGE=Yes
>     LENGTH_MATCH=Yes
>     IPRANGE_MATCH=Yes
>     RECENT_MATCH=Yes
>     OWNER_MATCH=Yes
>     IPSET_MATCH=Yes
>     CONNMARK=Yes
>     XCONNMARK=Yes
>     CONNMARK_MATCH=Yes
>     XCONNMARK_MATCH=Yes
>     RAW_TABLE=Yes
>     IPP2P_MATCH=
>     CLASSIFY_TARGET=Yes
>     ENHANCED_REJECT=Yes
>     KLUDGEFREE=Yes
>     MARK=Yes
>     XMARK=Yes
>     MANGLE_FORWARD=Yes
>     COMMENTS=Yes
>     ADDRTYPE=Yes
>     TCPMSS_MATCH=Yes
>     HASHLIMIT_MATCH=Yes
>     NFQUEUE_TARGET=Yes
>     REALM_MATCH=Yes
>     CAPVERSION=40190

As you can see, the file contains a simple list of shell variable assignments — the variables correspond to the capabilities listed by the `shorewall show capabilities` command and they appear in the same order as the output of that command.

To aid in creating this file, Shorewall Lite includes a `shorecap` program. The program is installed in the `/usr/share/shorewall-lite/` directory and may be run as follows:

> `[ IPTABLES=<iptables binary> ] [ MODULESDIR=<kernel modules directory> ] /usr/share/shorewall-lite/shorecap > capabilities`

The IPTABLES and MODULESDIR options have their [usual Shorewall default values](https://shorewall.org/manpages/shorewall.conf.html).

The `capabilities` file may then be copied to a system with Shorewall installed and used when compiling firewall programs to run on the remote system.

The `capabilities` file may also be creating using `/sbin/shorewall-lite`:

> `shorewall-lite show -f capabilities > capabilities`

Note that unlike the `shorecap` program, the `show capabilities` command shows the kernel's current capabilities; it does not attempt to load additional kernel modules.

# Running compiled programs directly

Compiled firewall programs are complete shell programs that support the following command line forms:

> \<program\> \[ -q \] \[ -v \] \[ -n \] start
>
> \<program\> \[ -q \] \[ -v \] \[ -n \] stop
>
> \<program\> \[ -q \] \[ -v \] \[ -n \] clear
>
> \<program\> \[ -q \] \[ -v \] \[ -n \] refresh
>
> \<program\> \[ -q \] \[ -v \] \[ -n \] reset
>
> \<program\> \[ -q \] \[ -v \] \[ -n \] restart
>
> \<program\> \[ -q \] \[ -v \] \[ -n \] status
>
> \<program\> \[ -q \] \[ -v \] \[ -n \] version

The options have the same meanings as when they are passed to `/sbin/shorewall` itself. The default VERBOSITY level is the level specified in the `shorewall.conf` file used when the program was compiled.
