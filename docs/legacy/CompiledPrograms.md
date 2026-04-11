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

    - Remove /etc/shorewall (/etc/shorewal6) from the setting of CONFIG_PATH

    - STARTUP_LOG=/var/log/shorewall-lite-init.log

    Older versions of Shorewall included copies of shorewall.conf with these settings already modified. This practice was discontinued in Shorewall 4.4.20.1.

4.  The `/etc/shorewall/shorewall.conf` file is used to determine the VERBOSITY setting which determines how much output the compiler generates. All other settings are taken from the `shorewall.conf`file in the remote systems export directory.

    <div class="caution">

    If you want to be able to allow non-root users to manage remote firewall systems, then the files `/etc/shorewall/params` and `/etc/shorewall/shorewall.conf` must be readable by all users on the administrative system. Not all packages secure the files that way and you may have to change the file permissions yourself.

    </div>

5.  On each firewall system, If you are running Debian or one of its derivatives like Ubuntu then edit `/etc/default/shorewall-lite` and set startup=1.

6.  On the administrative system, for each firewall system you do the following (this may be done by a non-root user who has root ssh access to the firewall system):

    1.  modify the files in the corresponding export directory appropriately (i.e., *just as you would if you were configuring Shorewall on the firewall system itself*). It's a good idea to include the IP address of the administrative system in the [`stoppedrules` file](https://shorewall.org/manpages/shorewall-stoppedrules.html).

        It is important to understand that with Shorewall Lite, the firewall's export directory on the administrative system acts as `/etc/shorewall` for that firewall. So when the Shorewall documentation gives instructions for placing entries in files in the firewall's `/etc/shorewall`, when using Shorewall Lite you make those changes in the firewall's export directory on the administrative system.

        The CONFIG_PATH variable is treated as follows:

        - The value of CONFIG_PATH in `/etc/shorewall/shorewall.conf` is ignored when compiling for export (the -e option in given) and when the `load` or `reload` command is being executed (see below).

        - The value of CONFIG_PATH in the `shorewall.conf` file in the export directory is used to search for configuration files during compilation of that configuration.

        - The value of CONFIG_PATH used when the script is run on the firewall system is "/etc/shorewall-lite:/usr/share/shorewall-lite".

    2.  cd <export directory>
            /sbin/shorewall remote-startfirewall

        The [`remote-start`](../reference/starting_and_stopping_shorewall.md#Load) command compiles a firewall script from the configuration files in the current working directory (using `shorewall compile -e`), copies that file to the remote system via scp and starts Shorewall Lite on the remote system via ssh.

        Example (firewall's DNS name is 'gateway'):

        `/sbin/shorewall remote-start gateway`

        <div class="note">

        Although scp and ssh are used by default, you can use other utilities by setting RSH_COMMAND and RCP_COMMAND in `/etc/shorewall/shorewall.conf`.

        </div>

        The first time that you issue a `load` command, Shorewall will use ssh to run `/usr/share/shorewall-lite/shorecap` on the remote firewall to create a capabilities file in the firewall's administrative direction. See [below](#Shorecap).

7.  If you later need to change the firewall's configuration, change the appropriate files in the firewall's export directory then:

        cd <export directory>
        /sbin/shorewall remote-reload firewall

    The [`remote-reload`](https://shorewall.org/manpages/shorewall.html) command compiles a firewall script from the configuration files in the current working directory (using `shorewall compile -e`), copies that file to the remote system via scp and restarts Shorewall Lite on the remote system via ssh. The **remote-reload** command also supports the '-c' option.

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

The `/sbin/shorewall-lite` program (which is a symbolic link pointing to `/sbin/shorewall`) included with Shorewall Lite supports the same set of commands as the `/sbin/shorewall` program in a full Shorewall installation with the following exceptions:

> action
>
> actions
>
> check
>
> compile
>
> export
>
> macro
>
> macros
>
> remote-getrc
>
> remote-getcaps
>
> remote-reload
>
> remote-restart
>
> remote-start
>
> safe-reload
>
> safe-restart
>
> safe-start
>
> try
>
> update

### Module Loading

Normally, the `helpers` file on the firewall system is used. If you want to specify modules at compile time on the Administrative System, then you must place a copy of the `helpers` file in the firewall's configuration directory before compilation.

In Shorewall 4.4.17, the EXPORTMODULES option was added to shorewall.conf (and shorewall6.conf). When EXPORTMODULES=Yes, any `helpers` file found on the CONFIG_PATH on the Administrative System during compilation will be used.

### Converting a system from Shorewall to Shorewall Lite

Converting a firewall system that is currently running Shorewall to run Shorewall Lite instead is straight-forward.

1.  On the administrative system, create an export directory for the firewall system.

2.  Copy the contents of `/etc/shorewall/` from the firewall system to the export directory on the administrative system.

3.  On the firewall system:

    Be sure that the IP address of the administrative system is included in the firewall's export directory `stoppedrules` file.

        shorewall stop

    **We recommend that you uninstall Shorewall at this point.**

4.  Install Shorewall Lite on the firewall system.

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
    >     /sbin/shorewall load <firewall system>
    >
    > Example (firewall's DNS name is 'gateway'):
    >
    > `/sbin/shorewall load gateway`

    The first time that you issue a `load` command, Shorewall will use ssh to run `/usr/share/shorewall-lite/shorecap` on the remote firewall to create a capabilities file in the firewall's administrative direction. See [below](#Shorecap).

    The [`load`](../reference/starting_and_stopping_shorewall.md#Load) command compiles a firewall script from the configuration files in the current working directory (using `shorewall compile -e`), copies that file to the remote system via `scp` and starts Shorewall Lite on the remote system via `ssh`.

6.  If you later need to change the firewall's configuration, change the appropriate files in the firewall's export directory then:

        cd <export directory>
        /sbin/shorewall reload firewall

    The [`reload`](../reference/starting_and_stopping_shorewall.md#Reload) command compiles a firewall script from the configuration files in the current working directory (using `shorewall compile -e`), copies that file to the remote system via `scp` and restarts Shorewall Lite on the remote system via `ssh`.

7.  If the kernel/iptables configuration on the firewall later changes and you need to create a new `capabilities` file, do the following on the firewall system:

        /usr/share/shorewall-lite/shorecap > capabilities
        scp capabilities <admin system>:<this system's config dir>

    Or simply use the -c option the next time that you use the `reload` command (e.g., `shorewall reload -c gateway`).

## Restrictions

While compiled Shorewall programs (as are used in Shorewall Lite) are useful in many cases, there are some important restrictions that you should be aware of before attempting to use them.

1.  All extension scripts used are copied into the program (with the exception of [those executed at compile-time by the compiler](../reference/shorewall_extension_scripts.md)). The ramifications of this are:

    - If you update an extension script, the compiled program will not use the updated script.

    - The `params` file is only processed at compile time if you set EXPORTPARAMS=No in `shorewall.conf`. For run-time setting of shell variables, use the `init` extension script. Although the default setting is EXPORTPARAMS=Yes for compatibility, the recommended setting is EXPORTPARAMS=No. Beginning with Shorewall 4.4.17, the variables set in the `params` file are available in the firewall script when EXPORTPARAMS=No.

      If the `params` file needs to set shell variables based on the configuration of the firewall system, you can use this trick:

          EXT_IP=$(ssh root@firewall "/sbin/shorewall-lite call find_first_interface_address eth0")

      The `shorewall-lite call` command allows you to to call interactively any Shorewall function that you can call in an extension script.

2.  You must install Shorewall Lite on the system where you want to run the script. You then install the compiled program in /usr/share/shorewall-lite/firewall and use the /sbin/shorewall-lite program included with Shorewall Lite to control the firewall just as if the full Shorewall distribution was installed.

# The "shorewall compile" command

A compiled script is produced using the `compile` command:

> `shorewall compile [ -e ] [ <directory name> ] [ <path name> ]`

where

> -e  
> Indicates that the program is to be "exported" to another system. When this flag is set, neither the "detectnets" interface option nor DYNAMIC_ZONES=Yes in shorewall.conf are allowed. The created program may be run on a system that has only Shorewall Lite installed
>
> When this flag is given, Shorewall does not probe the current system to determine the kernel/iptables features that it supports. It rather reads those capabilities from `/etc/shorewall/capabilities`. See below for details.
>
> \<directory name\>  
> specifies a directory to be searched for configuration files before those directories listed in the CONFIG_PATH variable in `shorewall.conf`.
>
> When -e \<directory-name\> is included, only the SHOREWALL_SHELL and VERBOSITY settings from `/etc/shorewall/shorewall.conf` are used and these apply only to the compiler itself. The settings used by the compiled firewall script are determined by the contents of `<directory name>/shorewall.conf`.
>
> \<path name\>  
> specifies the name of the script to be created. If not given, \${VARDIR}/firewall is assumed (by default, \${VARDIR} is `/var/lib/shorewall/`)

# The /etc/shorewall/capabilities file and the shorecap program

As mentioned above, the `/etc/shorewall/capabilities` file specifies that kernel/iptables capabilities of the target system. Here is a sample file:

    # Shorewall 5.2.3.3 detected the following iptables/netfilter capabilities - Mon 16 Sep 2019 01:32:20 PM PDT
    #
    ACCOUNT_TARGET=
    ADDRTYPE=Yes
    AMANDA_HELPER=
    ARPTABLESJF=
    AUDIT_TARGET=Yes
    BASIC_EMATCH=Yes
    BASIC_FILTER=Yes
    CAPVERSION=50200
    CHECKSUM_TARGET=Yes
    CLASSIFY_TARGET=Yes
    COMMENTS=Yes
    CONDITION_MATCH=
    CONNLIMIT_MATCH=Yes
    CONNMARK_MATCH=Yes
    CONNMARK=Yes
    CONNTRACK_MATCH=Yes
    CPU_FANOUT=Yes
    CT_TARGET=Yes
    DSCP_MATCH=Yes
    DSCP_TARGET=Yes
    EMULTIPORT=Yes
    ENHANCED_REJECT=Yes
    EXMARK=Yes
    FLOW_FILTER=Yes
    FTP0_HELPER=
    FTP_HELPER=Yes
    FWMARK_RT_MASK=Yes
    GEOIP_MATCH=
    GOTO_TARGET=Yes
    H323_HELPER=
    HASHLIMIT_MATCH=Yes
    HEADER_MATCH=
    HELPER_MATCH=Yes
    IFACE_MATCH=
    IMQ_TARGET=
    IPMARK_TARGET=
    IPP2P_MATCH=
    IPRANGE_MATCH=Yes
    IPSET_MATCH_COUNTERS=Yes
    IPSET_MATCH_NOMATCH=Yes
    IPSET_MATCH=Yes
    IPSET_V5=Yes
    IPTABLES_S=Yes
    IRC0_HELPER=
    IRC_HELPER=Yes
    KERNELVERSION=41900
    KLUDGEFREE=Yes
    LENGTH_MATCH=Yes
    LOGMARK_TARGET=
    LOG_TARGET=Yes
    MANGLE_ENABLED=Yes
    MANGLE_FORWARD=Yes
    MARK_ANYWHERE=Yes
    MARK=Yes
    MASQUERADE_TGT=Yes
    MULTIPORT=Yes
    NAT_ENABLED=Yes
    NAT_INPUT_CHAIN=Yes
    NETBIOS_NS_HELPER=
    NETMAP_TARGET=Yes
    NEW_CONNTRACK_MATCH=Yes
    NEW_TOS_MATCH=Yes
    NFACCT_MATCH=Yes
    NFLOG_SIZE=Yes
    NFLOG_TARGET=Yes
    NFQUEUE_TARGET=Yes
    OLD_CONNTRACK_MATCH=
    OLD_HL_MATCH=
    OLD_IPP2P_MATCH=
    OLD_IPSET_MATCH=
    OWNER_MATCH=Yes
    OWNER_NAME_MATCH=Yes
    PERSISTENT_SNAT=Yes
    PHYSDEV_BRIDGE=Yes
    PHYSDEV_MATCH=Yes
    POLICY_MATCH=Yes
    PPTP_HELPER=
    RAW_TABLE=Yes
    REALM_MATCH=Yes
    REAP_OPTION=Yes
    RECENT_MATCH=Yes
    RESTORE_WAIT_OPTION=Yes
    RPFILTER_MATCH=Yes
    SANE0_HELPER=
    SANE_HELPER=
    SIP0_HELPER=
    SIP_HELPER=
    SNMP_HELPER=
    STATISTIC_MATCH=Yes
    TARPIT_TARGET=
    TCPMSS_MATCH=Yes
    TCPMSS_TARGET=Yes
    TFTP0_HELPER=
    TFTP_HELPER=
    TIME_MATCH=Yes
    TPROXY_TARGET=Yes
    UDPLITEREDIRECT=
    ULOG_TARGET=
    WAIT_OPTION=Yes
    XCONNMARK_MATCH=Yes
    XCONNMARK=Yes
    XMARK=Yes
    XMULTIPORT=Yes

As you can see, the file contains a simple list of shell variable assignments — the variables correspond to the capabilities listed by the `shorewall show capabilities` command and they appear in the same order as the output of that command.

The capabilities file can be generated automatically from the administrative system by using the `remote-getcaps` command. Should that option fail for any reason, the file can be generated manually on the remote firewall.

To aid in creating this file on the remote firewall, Shorewall Lite includes a `shorecap` program. The program is installed in the `/usr/share/shorewall-lite/` directory and may be run as follows:

> `[ IPTABLES=<iptables binary> ] [ MODULESDIR=<kernel modules directory> ] /usr/share/shorewall-lite/shorecap > capabilities`

The IPTABLES and MODULESDIR options have their [usual Shorewall default values](https://shorewall.org/manpages/shorewall.conf.html).

The `capabilities` file may then be copied to a system with Shorewall installed and used when compiling firewall programs to run on the remote system.

The `capabilities` file may also be creating using `/sbin/shorewall-lite`:

> `shorewall-lite show -f capabilities > capabilities`

Note that unlike the `shorecap` program, the `show capabilities` command shows the kernel's current capabilities; it does not attempt to load additional kernel modules.

Once generated, the file can be copied manually to the administrative system.

# Running compiled programs directly

Compiled firewall programs are complete shell programs that may be run directly. Here is the output from the program's help command (Shorewall version 5.2.4)

    <program> [ options ] <command>

    <command> is one of:
       start
       stop
       clear
       disable <interface>
       down <interface>
       enable <interface>
       reset
       reenable <interface>
       refresh
       reload
       restart
       run <command> [ <parameter> ... ]
       status
       up <interface>
       savesets <file>
       call <function> [ <parameter> ... ]
       help
       version
       info

    Options are:

       -v and -q        Standard Shorewall verbosity controls
       -n               Don't update routing configuration
       -p               Purge Conntrack Table
       -t               Timestamp progress Messages
       -c               Save/restore iptables counters
       -V <verbosity>   Set verbosity explicitly
       -R <file>        Override RESTOREFILE setting
       -T               Trace execution

The options have the same meanings as when they are passed to `/sbin/shorewall` itself. The default VERBOSITY level is the level specified in the `shorewall.conf` file used when the program was compiled.
