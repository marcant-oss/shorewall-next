# Important

It is important that you read all of the sections on this page where the version number mentioned in the section title is later than what you are currently running.

In the descriptions that follows, the term *group* refers to a particular network or subnetwork (which may be `0.0.0.0/0` or it may be a host address) accessed through a particular interface.

Examples:

eth0:0.0.0.0/0

eth2:192.168.1.0/24

eth3:192.0.2.123

You can use the `shorewall show zones` command to see the groups associated with each of your zones.

# Version \>= 5.0.0

See the [Shorewall 5 documentation](Shorewall-5.md).

# Version \>= 4.6.0

1.  Beginning with Shorewall 4.6.0, section headers are now preceded by '?' (e.g., '?SECTION ...'). If your configuration contains any bare 'SECTION' entries, the following warning is issued:

        WARNING: 'SECTION' is deprecated in favor of '?SECTION' - consider running 'shorewall update -D' ...

    As mentioned in the message, running 'shorewall\[6\] update -D' will eliminate the warning.

2.  Beginning with Shorewall 4.6.0, the 'tcrules' file has been superseded by the 'mangle' file. Existing 'tcrules' files will still be processed, with the restriction that TPROXY is no longer supported in FORMAT 1. If your 'tcrules' file has non-commentary entries, the following warning message is issued:

        WARNING: Non-empty tcrules file (...); consider running 'shorewall update -t'

    See [shorewall](https://shorewall.org/manpages/shorewall.html)(8) for limitations of 'update -t'.

3.  The default value LOAD_HELPERS_ONLY is now 'Yes'.

4.  Beginning with Shorewall 4.5.0, FORMAT-1 actions and macros are deprecated and a warning will be issued for each FORMAT-1 action or macro found.

        WARNING: FORMAT-1 actions are deprecated and support will be dropped in a future release.

        WARNING: FORMAT-1 macros are deprecated and support will be dropped in a future release.

    To eliminate these warnings, add the following line before the first rule in the action or macro:

        ?FORMAT 2

    and adjust the columns appropriately. FORMAT-1 actions have the following columns:

    TARGET
    SOURCE
    DEST
    PROTO
    DEST PORT(S)
    SOURCE PORT(S)
    RATE/LIMIT
    USER/GROUP
    MARK
    while FORMAT-2 actions have these columns:

    TARGET
    SOURCE
    DEST
    PROTO
    DEST PORT(S)
    SOURCE PORT(S)
    ORIGINAL DEST
    RATE/LIMIT
    USER/GROUP
    MARK
    CONLIMIT
    TIME
    HEADERS (Used in IPv6 only)
    CONDITION
    HELPER
    FORMAT-1 macros have the following columns:

    TARGET
    SOURCE
    DEST
    PROTO
    DEST PORT(S)
    SOURCE PORT(S)
    RATE/LIMIT
    USER/GROUP
    while FORMAT-2 macros have the following columns:

    TARGET
    SOURCE
    DEST
    PROTO
    DEST PORT(S)
    SOURCE PORT(S)
    ORIGINAL DEST
    RATE/LIMIT
    USER/GROUP
    MARK
    CONLIMIT
    TIME
    HEADERS (Used in IPv6 only)
    CONDITION
    HELPER

# Versions \>= 4.5.0

1.  Shorewall, Shorewall6, Shorewall-lite and Shorewall6-lite now depend on the new package Shorewall-core. If you use the Shorewall installers, you must install Shorewall-core prior to installing or upgrading any of the other packages.

2.  The BLACKLIST section of the rules file has been eliminated. If you have entries in that file section, you must move them to the blrules file.

3.  This version of Shorewall requires the Digest::SHA1 or the Digest:SHA Perl module.

    Debian: libdigest-sha-perl
    Fedora: perl-Digest-SHA1
    OpenSuSE: perl-Digest-SHA1

4.  The generated firewall script now maintains the /var/lib/shorewall\[6\]\[-lite\]/interface.status files used by SWPING and by LSM.

5.  Beginning with Shorewall 4.5.2, using /etc/shorewall-lite/vardir and /etc/shorewall6-lite/vardir to specify VARDIR is deprecated in favor of the VARDIR setting in shorewallrc.

    NOTE: While the name of the variable remains VARDIR, the meaning is slightly different. When set in shorewallrc, each product (shorewall-lite, and shorewall6-lite) will create a directory under the specified path name to hold state information.

    Example:

    > VARDIR=/opt/var/
    >
    > The state directory for shorewall-lite will be /opt/var/shorewall-lite/ and the directory for shorewall6-lite will be /opt/var/shorewall6-lite.

    When VARDIR is set in /etc/shorewall\[6\]/vardir, the product will save its state directly in the specified directory.

6.  Begining with Shorewall 4.5.6, the tcrules file is processed if MANGLE_ENABLED=Yes, independent of the setting of TC_ENABLED. This allows actions like TTL and TPROXY to be used without enabling traffic shaping. If you have rules in your tcrules file that you only want processed when TC_ENABLED is other than 'No', then enclose them in

    > ?IF \$TC_ENABLED
    >
    > ...
    >
    > ?ENDIF

    If they are to be processed only if TC_ENABLED=Internal, then enclose them in

    > ?IF TC_ENABLED eq 'Internal'
    >
    > ...
    >
    > ?ENDIF.

7.  Beginning with Shorewall 4.5.7, the deprecated /etc/shorewall\[6\]/blacklist files are no longer installed. Existing files are still processed by the compiler.

    Note that blacklist files may be converted to equivalent blrules files using `shorewall[6] update -b`.

8.  In Shorewall 4.5.7, the `/etc/shorewall[6]/notrack` file was renamed `/etc/shorewall[6]/conntrack`. When upgrading to a release \>= 4.5.7, the `conntrack` file will be installed along side of an existing `notrack` file.

    If the 'notrack' file is non-empty, a warning message is issued during compilation:

    > WARNING: Non-empty notrack file (...); please move its contents to the conntrack file

    This warning can be eliminated by removing the notrack file (if it has no entries), or by moving its entries to the conntrack file and removing the notrack file. Note that the conntrack file is always populated with rules

9.  In Shorewall 4.5.8, the /etc/shorewall\[6\]/routestopped files were deprecated if favor of new /etc/shorewall\[6\]/stoppedrules counterparts. The new files have much more familiar and straightforward semantics. Once a stoppedrules file is populated, the compiler will process that file and will ignore the corresponding routestopped file.

10. In Shorewall 4.5.8, a new variable (VARLIB) was added to the shorewallrc file. This variable assumes the role formerly played by VARDIR, and VARDIR now designates the configuration directory for a particular product.

    This change should be transparent to all users:

    1.  If VARDIR is set in an existing shorewallrc file and VARLIB is not, then VARLIB is set to \${VARDIR} and VARDIR is set to \${VARLIB}/\${PRODUCT}.

    2.  If VARLIB is set in a shorewallrc file and VARDIR is not, then VARDIR is set to \${VARLIB}/\${PRODUCT}.

    The Shorewall-core installer will automatically update ~/.shorewallrc and save the original in ~/.shorewallrc.bak.

11. Previously, the macro.SNMP macro opened both UDP ports 161 and 162 from SOURCE to DEST. This is against the usual practice of opening these ports in the opposite direction. Beginning with Shorewall 4.5.8, the SNMP macro opens port 161 from SOURCE to DEST as before, and a new SNMPTrap macro is added that opens port 162 (from SOURCE to DEST).

12. Beginning with Shorewall 4.5.11, ?FORMAT is preferred over FORMAT for specifying the format of records in these configuration files:

    action
    .\* files
    conntrack
    interface
    macro
    .\* files
    tcrules
    The first instance of 'FORMAT' (without the '?') will generate this warning:

    WARNING: FORMAT is deprecated in favor of ?FORMAT; consider running 'shorewall update -D'
    As the warning suggests, 'shorewall\[6\] update -D' will convert all instances of FORMAT to ?FORMAT in files on the CONFIG_PATH.

13. Also beginning with Shorewalll 4.5.11, ?COMMENT is preferred over COMMENT for specifying comments to be attached to generated Netfilter rules in the following files:

    accounting
    action
    .\* files
    blrules
    conntrack
    macro
    .\* files
    masq
    nat
    rules
    secmarks
    tcrules
    tunnels
    The first instance of 'COMMENT' (without the '?') will generate this warning:

    WARNING: COMMENT is deprecated in favor of ?COMMENT; consider running 'shorewall update -D'
    As the warning suggests, 'shorewall\[6\] update -D' will convert all instances of COMMENT to ?COMMENT in files on the CONFIG_PATH.

14. Also beginning with Shorewalll 4.5.11, ?COMMENT is preferred over COMMENT for specifying comments to be attached to generated Netfilter rules in the following files:

    accounting
    action
    .\* files
    blrules
    conntrack
    macro
    .\* files
    masq
    nat
    rules
    secmarks
    tcrules
    tunnels

15. To allow finer-grained selection of the connection-tracking states that are passed through blacklists (both dynamic and static), a BLACKLIST option was added to shorewall.conf and shorewall6.conf in Shorewall 4.5.13.

    The BLACKLISTNEWONLY option was deprecated at that point. A 'shorewall update' ( 'shorewall6 update' ) will replace the BLACKLISTNEWONLY option with the equivalent BLACKLIST option.

16. In Shorewall 4.5.14, the BLACKLIST_LOGLEVEL option was renamed BLACKLIST_LOG_LEVEL to be consistent with the other log-level option names. BLACKLIST_LOGLEVEL continues to be accepted as a synonym for BLACKLIST_LOG_LEVEL, but a 'shorewall update' or 'shorewall6 update' command will replace BLACKLIST_LOGLEVEL with BLACKLIST_LOG_LEVEL in the new .conf file.

# Versions \>= 4.4.0

1.  If you are using Shorewall-perl, there are no additional upgrade issues. If you are using Shorewall-shell or are upgrading from a Shorewall version earlier than 4.0.0 then you will need to [migrate to Shorewall-perl](Shorewall-perl.md). Shorewall-4.3.5 and later only use the perl-based compiler.

    If you have specified "SHOREWALL_COMPILER=shell" in shorewall.conf, then you must either:

    - change that specification to "SHOREWALL_COMPILER=perl"; or

    - change that specification to "SHOREWALL_COMPILER="; or

    - delete the specification altogether.

    Failure to do so will result in the following warning:

    > WARNING: SHOREWALL_COMPILER=shell ignored. Support for Shorwall-shell has been removed in this release.

2.  The `shorewall stop`, `shorewall clear`, `shorewall6 stop` and `shorewall6 clear` commands no longer read the `routestopped` file. The `routestopped` file used is the one that was present at the last `start`, `restart` or `restore` command.

    <div class="important">

    If you modify the routestopped file, you must restart Shorewall before the changes to that file will take effect.

    </div>

3.  The old macro parameter syntax (e.g., SSH/ACCEPT) is now deprecated in favor of the new syntax (e.g., SSH(ACCEPT)). The 4.3 documentation uses the new syntax exclusively, although the old syntax continues to be supported.

4.  Support for the SAME target in /etc/shorewall/masq and /etc/shorewall/rules has been removed, following the removal of the underlying support in the Linux kernel.

5.  Supplying an interface name in the SOURCE column of /etc/shorewall/masq is now deprecated. Entering the name of an interface there will result in a compile-time warning:

    WARNING: Using an interface as the masq SOURCE requires the interface to be up and configured when Shorewall starts/restarts

    To avoid this warning, replace interface names by the corresponding netwok(s) in CIDR format (e.g., 192.168.144.0/24).

6.  Previously, Shorewall has treated traffic shaping class IDs as decimal numbers (or pairs of decimal numbers). That worked fine until IPMARK was implemented. IPMARK requires Shorewall to generate class Ids in numeric sequence. In 4.3.9, that didn't work correctly because Shorewall was generating the sequence "..8,9,10,11..." when the correct sequence was "...8,9,a,b,...". Shorewall now treats class IDs as hex, like 'tc' and 'iptables' do.

    This should only be an issue if you have more than 9 interfaces defined in `/etc/shorewall/tcdevices` and if you use class IDs in `/etc/shorewall/tcrules`. You will need to renumber the class IDs for devices 10 and greater.

7.  Support for the 'norfc1918' interface and host option has been removed. If 'norfc1918' is specified for an entry in either the interfaces or the hosts file, a warning is issued and the option is ignored. Simply remove the option to avoid the warning.

    Similarly, if RFC1918_STRICT=Yes or a non-empty RFC1918_LOG_LEVEL is given in shorewall.conf, a warning will be issued and the option will be ignored.

    You may simply delete the RFC1918-related options from your shorewall.conf file if you are seeing warnings regarding them.

    Users who currently use 'norfc1918' are encouraged to consider using NULL_ROUTE_RFC1918=Yes instead.

8.  The install.sh scripts in the Shorewall and Shorewall6 packages no longer create a backup copy of the existing configuration. If you want your configuration backed up prior to upgrading, you will need to do that yourself. As part of this change, the fallback.sh scripts are no longer released.

9.  Previously, if an ipsec zone was defined as a sub-zone of an ipv4 or ipv6 zone using the special \<child\>:\<parent\>,... syntax, CONTINUE policies for the sub-zone did not work as expected. Traffic that was not matched by a sub-zone rule was not compared against the parent zone(s) rules. In 4.4.0, such traffic IS compared against the parent zone rules.

10. The name **any** is now reserved and may not be used as a zone name.

11. Perl module initialization has changed in Shorewall 4.4.1. Previously, each Shorewall Perl package would initialize its global variables for IPv4 in an INIT block. Then, if the compilation turned out to be for IPv6, Shorewall::Compiler::compiler() would reinitialize them for IPv6.

    Beginning in Shorewall 4.4.1, the modules do not initialize themselves in an INIT block. So if you use Shorewall modules outside of the Shorewall compilation environment, then you must explicitly call the module's 'initialize' function after the module has been loaded.

12. Checking for zone membership has been tighened up. Previously, a zone could contain \<interface\>:0.0.0.0/0 along with other hosts; now, if the zone has \<interface\>:0.0.0.0/0 (even with exclusions), then it may have no additional members in [/etc/shorewall/hosts](https://shorewall.org/manpages/shorewall-hosts.html).

13. ADD_IP_ALIASES=No is now the setting in the released [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) and in all of the samples. This will not affect you during upgrade unless you choose to replace your current shorewall.conf with the one from the release (not recommended).

14. The names of interface configuration variables in generated scripts have been changed to ensure uniqueness. These names now begin with SW\_. This change will only affect you if your extension scripts are using one or more of these variables.

    |                         |                             |
    |-------------------------|-----------------------------|
    | Old Variable Name       | New Variable Name           |
    | \<iface\>\_address      | SW\_\<iface\>\_ADDRESS      |
    | \<iface\>\_BCASTS       | SW\_\<iface\>\_BCASTS       |
    | \<iface\>\_ACASTS       | SW\_\<iface\>\_CASTS        |
    | \<iface\>\_GATEWAY      | SW\_\<iface\>\_NETWORKS     |
    | \<iface\>\_ADDRESSES    | SW\_`iface`\_ADDRESSES      |
    | \<iface\>\_NETWORKS     | SW\_\<iface\>\_NETWORKS     |
    | \<iface\>\_MAC          | SW\_\<iface\>\_MAC          |
    | \<provider\>\_IS_USABLE | SW\_\<provider\>\_IS_USABLE |

    were \<iface\> is a capitalized interface name (e.g., ETH0) and \<provider\> is the capitalized name of a provider.

15. If your [/etc/shorewall/params](https://shorewall.org/manpages/shorewall-params.html) (or [/etc/shorewall6/params](https://shorewall.org/manpages/shorewall-params.html)) file sends output to Standard Output, you need to be aware that the output will be redirected to Standard Error beginning with Shorewall 4.4.16.

16. Beginning with Shorewall 4.4.17, the EXPORTPARAMS option is deprecated. With EXPORTPARAMS=No, the variables set by [/etc/shorewall/params](https://shorewall.org/manpages/shorewall-params.html) ([/etc/shorewall6/params](https://shorewall.org/manpages/shorewall-params.html)) at compile time are now available in the compiled firewall script.

17. The `iprange` and `ipaddr` commands require the 'bc' utility.

18. Beginning with Shorewall 4.4.26, the WIDE_TC_MARKS and HIGH_ROUTE_MARKS options are deprecated in favor of TC_BITS, MASK_BITS, PROVIDER_BITS and PROVIDER_OFFSET. See the [Packet Marking using /etc/shorewall/tcrules](../features/PacketMarking.md#Values) article. The `shorewall update` (`shorewall6 update`) command will automatically generate the correct values for these new options depending on your settings of WIDE_TC_MARKS and HIGH_ROUTE_MARKS.

Be sure to check the latest 4.4 Release Notes linked from the [home page](https://shorewall.org/).

# Versions \>= 4.2.0

1.  Previously, when HIGH_ROUTE_MARKS=Yes, Shorewall allowed non-zero mark values \< 256 to be assigned in the OUTPUT chain. This has been changed so that only high mark values may be assigned there. Packet marking rules for traffic shaping of packets originating on the firewall must be coded in the POSTROUTING table.

2.  Previously, Shorewall did not range-check the value of the VERBOSITY option in shorewall.conf. Beginning with Shorewall 4.2: a) A VERBOSITY setting outside the range -1 through 2 is rejected. b) After the -v and -q options are applied, the resulting value is adjusted to fall within the range -1 through 2.

3.  Specifying a destination zone in a NAT-only rule now generates a warning and the destination zone is ignored. NAT-only rules are:NONAT, REDIRECT-, DNAT-

4.  The default value for LOG_MARTIANS has been changed. Previously, the defaults were: Shorewall-perl - 'Off' Shorewall-shell - 'No' The new default values are:

    Shorewall-perl  
    'On.

    Shorewall-shell  
    'Yes'

    Shorewall-perl users may:

    1.  Accept the new default -- martians will be logged from all interfaces with route filtering except those with log_martians=0 in /etc/shorewall/interfaces.

    2.  Explicitly set LOG_MARTIANS=Off to maintain compatibility with prior versions of Shorewall.

    Shorewall-shell users may:

    1.  Accept the new default -- martians will be logged from all interfaces with the route filtering enabled.

    2.  Explicitly set LOG_MARTIANS=No to maintain compatibility with prior versions of Shorewall.

5.  The value of IMPLICIT_CONTINUE in shorewall.conf (and samples) has been changed from Yes to No. If you are a Debian or Ubuntu user and you select replacement of shorewall.conf during upgrade to Shorewall 4.2, you will want to change IMPLICIT_CONTINUE back to 'Yes' if you have nested zones that rely on IMPLICIT_CONTINUE=Yes for proper operation.

6.  The 'norfc1918' option is deprecated. Use explicit rules instead. Note that there is a new 'Rfc1918' macro that acts on addresses reserved by RFC 1918.

7.  DYNAMIC_ZONES=Yes is no longer supported by Shorewall-perl. Use ipset-based zones instead.

# Versions \>= 4.0.0-Beta7

1.  Beginning with Shorewall 4.0.0, there is no single 'shorewall' package. Rather there are two compiler packages (shorewall-shell and shorewall-perl) and a set of base files (shorewall-common) required by either compiler package.

    Although the names of the packages are changing, you can upgrade without having to uninstall/reinstall.

    To repeat: **You do not need to uninstall any existing package.**

    If you attempt to upgrade using the shorewall-common RPM, you get this result:

        gateway:~ # rpm -Uvh shorewall-common-4.0.0.noarch.rpm 
        error: Failed dependencies:
        shorewall_compiler is needed by shorewall-common-4.0.0-1.noarch
        gateway:~ #

    You must either:

        rpm -Uvh shorewall-shell-4.0.0.noarch.rpm shorewall-common-4.0.0.noarch.rpm

    or

        rpm -Uvh shorewall-shell-4.0.0.noarch.rpm shorewall-perl-4.0.0.noarch.rpm shorewall-common-4.0.0.noarch.rpm

    If you don't want shorewall-shell, you must use the second command (installing both shorewall-shell and shorewall-perl) then remove shorewall-shell using this command:

        rpm -e shorewall-shell

    If you are upgrading using the tarball, you must install shorewall-shell and/or shorewall-perl before you upgrade using shorewall-common. Otherwise, the install.sh script fails with:ERROR: No Shorewall compiler is installedThe shorewall-shell and shorewall-perl packages are installed from the tarball in the expected way; untar the package, and run the install.sh script.

    Example 1: You have 'shorewall' installed and you want to continue to use the shorewall-shell compiler.

        tar -jxf shorewall-common-4.0.0.tar.bz2
        tar -jxf shorewall-shell-4.0.0.tar.bz2

        pushd shorewall-shell-4.0.0
        ./install.sh
        popd
        pushd shorewall-common-4.0.0
        ./install.sh
        shorewall check
        shorewall restart

    Example 2: You have shorewall 3.4.4 and shorewall-perl 4.0.0-Beta7 installed and you want to upgrade to 4.0. You do not need the shell-based compiler.

        tar -jxf shorewall-common-4.0.0.tar.bz2
        tar -jxf shorewall-perl-4.0.0.tar.bz2

        pushd shorewall-perl-4.0.0
        ./install.sh
        popd
        pushd /shorewall-common-4.0.0
        ./install.sh
        shorewall check
        shorewall restart

    The RPMs are set up so that if you upgrade an existing Shorewall installation as part of a distribution upgrade and you have not already installed shorewall-perl, then you will end up with Shorewall-common and Shorewall-shell installed.

2.  The ROUTE_FILTER and LOG_MARTIANS options in shorewall.conf work slightly differently in Shorewall 4.0.0. In prior releases, leaving these options empty was equivalent to setting them to 'No' which caused the corresponding flag in /proc to be reset for all interfaces. Beginning in Shorewall 4.0.0, leaving these options empty causes Shorewall to leave the flags in /proc as they are. You must set the option to 'No' in order to obtain the old behavior.

3.  The `:noah` option is now the default for ipsec tunnels. Tunnels that use AH (protocol 51) must specify `ipsec:ah` in the TYPE column.

4.  Users upgrading from Debian Etch (Shorewall 3.2.6) to Debian Lenny (Shoreall 4.0.15) report finding an issue with VOIP (Asterisk) traffic. See [Shorewall FAQ 77](../reference/FAQ.md#faq77) for details.

# Versions \>= 3.4.0-Beta1

1.  Shorewall supports the notion of "default actions". A default action defines a set of rules that are applied before a policy is enforced. Default actions accomplish two goals:

    1.  Relieve log congestion. Default actions typically include rules to silently drop or reject traffic that would otherwise be logged when the policy is enforced.

    2.  Insure correct operation. Default actions can also avoid common pitfalls like dropping connection requests on TCP port 113. If these connections are dropped (rather than rejected) then you may encounter problems connecting to Internet services that utilize the AUTH protocol of client authentication.

    In prior Shorewall versions, default actions (action.Drop and action.Reject) were defined for DROP and REJECT policies in `/usr/share/shorewall/actions.std`. These could be overridden in `/etc/shorewall/actions`.

    This approach has two drawbacks:

    1.  All DROP policies must use the same default action and all REJECT policies must use the same default action.

    2.  Now that we have [modularized action processing](https://shorewall.org/Modularization.html), we need a way to define default rules for a policy that does not involve actions.

    If you have not overridden the defaults using entries in `/etc/shorewall/actions` then you need make no changes to migrate to Shorewall version 3.4. If you have overridden either of these entries, then please read on.

    The change in version 3.4 is two-fold:

    - Four new options have been added to the `/etc/shorewall/shorewall.conf` file that allow specifying the default action for DROP, REJECT, ACCEPT and QUEUE.

      The options are DROP_DEFAULT, REJECT_DEFAULT, ACCEPT_DEFAULT and QUEUE_DEFAULT.

      DROP_DEFAULT describes the rules to be applied before a connection request is dropped by a DROP policy; REJECT_DEFAULT describes the rules to be applied if a connection request is rejected by a REJECT policy. The other two are similar for ACCEPT and QUEUE policies. The value assigned to these may be:

      1.  The name of an action.

      2.  The name of a macro.

      3.  'None' or 'none'

      The default values are:

      DROP_DEFAULT="Drop"
      REJECT_DEFAULT="Reject"
      ACCEPT_DEFAULT=none
      QUEUE_DEFAULT=none
      If USE_ACTIONS=Yes, then these values refer to action.Drop and action.Reject respectively. If USE_ACTIONS=No, then these values refer to macro.Drop and macro.Reject.

      If you set the value of either option to "None" then no default action will be used and the default action or macro (if any) must be specified in `/etc/shorewall/policy`.

    - The POLICY column in /etc/shorewall/policy has been extended.

      In `/etc/shorewall/policy`, when the POLICY is DROP, REJECT, ACCEPT or QUEUE then the policy may be followed by ":" and one of the following:

      1.  The word "None" or "none". This causes any default action defined in `/etc/shorewall/shorewall.conf` to be omitted for this policy.

      2.  The name of an action (requires that USE_ACTIONS=Yes in `shorewall.conf`). That action will be invoked before the policy is enforced.

      3.  The name of a macro. The rules in that macro will be applied before the policy is enforced. This does not require USE_ACTIONS=Yes.

    Example:

        #SOURCE         DEST            POLICY          LOGLEVEL
        loc             net             ACCEPT
        net             all             DROP:MyDrop     info
        #
        # THE FOLLOWING POLICY MUST BE LAST
        #
        all             all             REJECT:MyReject info

2.  The 'Limit' action is now a builtin. If you have 'Limit' listed in `/etc/shorewall/actions`, remove the entry. Also remove the files `/etc/shorewall/action.Limit` and/or `/etc/shorewall/Limit` if you have them.

3.  This issue only applies if you have entries in `/etc/shorewall/providers`.

    Previously, Shorewall has not attempted to undo the changes it has made to the firewall's routing as a result of entries in `/etc/shorewall/providers` and `/etc/shorewall/routes`. Beginning with this release, Shorewall will attempt to undo these changes. This change can present a migration issue in that the initial routing configuration when this version of Shorewall is installed has probably been changed by Shorewall already. Hence, when Shorewall restores the original configuration, it will be installing a configuration that the previously-installed version has already modified.

    The steps to correcting this after you have installed version 3.4 or later of Shorewall are as follows:

    1.  `shorewall[-lite] stop`

    2.  Remove the files `/var/lib/shorewall[-lite]/default_route` and `/var/lib/shorewall[-lite]/undo_routing` if they exist.

    3.  Either restart networking or reboot.

    4.  `shorewall[-lite] start`

4.  This issue only applies if you run Shorewall Lite.

    The `/etc/shorewall-lite/shorewall.conf` file has been renamed `/etc/shorewall-lite/shorewall-lite.conf`. When you upgrade, your `shorewall.conf` file will be renamed `shorewall-lite.conf`.

# Version \>= 3.2.0

1.  If you are upgrading from version 2.4 or earlier, please read the 3.0.0 upgrade considerations below.

2.  A number of macros have been split into two. The macros affected are:

    IMAP
    LDAP
    NNTP
    POP3
    SMTP
    Each of these macros now handles only traffic on the native (plaintext) port. There is a corresponding macro with S added to the end of the name for the SSL version of the same protocol. Thus each macro results in the insertion of only one port per invocation. The Web macro has not been split, but two new macros, HTTP and HTTPS have been created. The Web macro is deprecated in favour of these new macros, and may be removed from future Shorewall releases.

    These changes have been made to ensure no unexpected ports are opened due to the use of macros.

3.  In previous Shorewall releases, DNAT and REDIRECT rules supported a special syntax for exclusion of a subnet from the effect of the rule.

    Example:

    > Z2 is a subzone of Z1:
    >
    >     DNAT     Z1!Z2        loc:192.168.1.4        ...

    That feature has never worked correctly when Z2 is a dynamic zone. Furthermore, now that Shorewall supports exclusion lists, the capability is redundant since the above rule can now be written in the form:

        DNAT     Z1:!<list of exclusions>   loc:192.168.1.4   ...

    Beginning with Shorewall 3.2.0, the special exclusion syntax will no longer be supported.

4.  Important if you use the QUEUE target.

    In the /etc/shorewall/rules file and in actions, you may now specify 'tcp:syn' in the PROTO column. 'tcp:syn' is equivalent to 'tcp' but also requires that the SYN flag is set and the RST, FIN and ACK flags be off ("--syn" is added to the iptables rule).

    As part of this change, Shorewall no longer adds the "--syn" option to TCP rules that specify QUEUE as their target.

5.  Extension Scripts may require change

    In previous releases, extension scripts were executed during `[re]start` by using the Bourne Shell "." operator. In addition to executing commands during `[re]start`, these scripts had to "save" the commands to be executed during `shorewall restore`.

    This clumsiness has been eliminated in Shorewall 3.2. In Shorewall 3.2, extension scripts are copied in-line into the compiled program and are executed in-line during `start`, `restart` and `restore`. This applies to all extension scripts except those associated with a chain or action -- those extension scripts continue to be processed at compile time.

    This new approach has two implications for existing scripts.

    1.  It is no longer necessary to save the commands; so functions like 'save_command', 'run_and_save_command' and 'ensure_and_save_command' need no longer be called. The generated program will contain functions with these names:

        save_command() - does nothing
        run_and_save_command() - runs the passed command
        ensure_and_save_command() - runs the passed command and stops the firewall if the command fails.
        These functions should provide for transparent migration of scripts that use them until you can get around to eliminating their use completely.

    2.  When the extension script is copied into the compiled program, it is indented to line up with the surrounding code. If you have 'awk' installed on your system, the Shorewall compiler will correctly handle line continuation (last character on the line = "\\). If you do not have awk, it will not be possible to use line-continuation in your extension scripts. In no case is it possible to continue a quoted string over multiple lines without having additional whitespace inserted into the string.

6.  Beginning with this release, the way in which packet marking in the PREROUTING chain interacts with the 'track' option in /etc/shorewall/providers has changed in two ways:

    1.  Packets arriving on a tracked interface are now passed to the PREROUTING marking chain so that they may be marked with a mark other than the 'track' mark (the connection still retains the 'track' mark).

    2.  When HIGH_ROUTE_MARKS=Yes, you can still clear the mark on packets in the PREROUTING chain (i.e., you can specify a mark value of zero).

7.  Kernel version 2.6.16 introduces 'xtables', a new common packet filtering and connection tracking facility that supports both IPv4 and IPv6. Because a different set of kernel modules must be loaded for xtables, Shorewall now includes two 'modules' files:

    1.  `/usr/share/shorewall/modules` -- the former `/etc/shorewall/modules`

    2.  /usr/share/shorewall/xmodules -- a new file that support xtables.

    If you wish to use the new file, then simply execute this command:

    `cp -f /usr/share/shorewall/xmodules /etc/shorewall/modules`

8.  (**Versions \>= 3.2.3**) Previously, CLASSIFY tcrules were always processed out of the POSTROUTING chain. Beginning with this release, they are processed out of the POSTROUTING chain \*except\* when the SOURCE is \$FW\[:\<address\>\] in which case the rule is processed out of the OUTPUT chain.

    With correctly-coded rulesets, this change should have no effect. Users having incorrectly-coded tcrules may need to change them.

    Example:

    >     #MARK/          SOURCE  DEST    PROTO   DEST            SOURCE
    >     #CLASSIFY                               PORTS(S)        PORT(S)
    >     1:110           $FW     eth3    tcp     -               22

    While the user may have expected this rule to only affect traffic from the firewall itself, the rule was really equivalent to this one:

    >     #MARK/    SOURCE        DEST    PROTO   DEST            SOURCE
    >     #CLASSIFY                               PORTS(S)        PORT(S)
    >     1:110     0.0.0.0/0     eth3    tcp     -               22

    So after this change, the second rule will be required rather than the first if that is what was really wanted.

# Version \>= 3.0.0

1.  The "monitor" command has been eliminated.

2.  The "DISPLAY" and "COMMENTS" columns in the /etc/shorewall/zones file have been removed and have been replaced by the former columns of the /etc/shorewall/ipsec file. The latter file has been removed.

    Additionally the FW option in shorewall.conf has been deprecated and is no longer set to 'fw' by default. New users are expected to define the firewall zone in /etc/shorewall/zones.

    Adhering to the principle of least astonishment, the old `/etc/shorewall/ipsec` file will continue to be supported. A new IPSECFILE variable in /etc/shorewall/shorewall.conf determines the name of the file that Shorewall looks in for IPSEC information. If that variable is not set or is set to the empty value then IPSECFILE=ipsec is assumed. So if you simply upgrade and don't do something idiotic like replace your current shorewall.conf file with the new one, your old configuration will continue to work. A dummy 'ipsec' file is included in the release so that your package manager (e.g., rpm) won't remove your existing file.

    The shorewall.conf file included in this release sets IPSECFILE=zones so that new users are expected to use the [new zone file format](https://shorewall.org/manpages/shorewall-zones.html).

3.  The DROPINVALID option has been removed from shorewall.conf. The behavior will be as if DROPINVALID=No had been specified. If you wish to drop invalid state packets, use the dropInvalid built-in action.

4.  The 'nobogons' interface and hosts option as well as the BOGON_LOG_LEVEL option have been eliminated.

5.  Most of the standard actions have been replaced by parameterized macros (see below). So for example, the action.AllowSMTP and action.DropSMTP have been removed an a parameterized macro macro.SMTP has been added to replace them.

    In order that current users don't have to immediately update their rules and user-defined actions, Shorewall can substitute an invocation of the a new macro for an existing invocation of one of the old actions. So if your rules file calls AllowSMTP, Shorewall will replace that call with SMTP(ACCEPT). Because this substitution is expensive, it is conditional based on the setting of MAPOLDACTIONS in shorewall.conf. If this option is set to YES or if it is not set (such as if you are using your old shorewall.conf file) then Shorewall will perform the substitution. Once you have converted to use the new macros, you can set MAPOLDACTIONS=No and invocations of those actions will go much quicker during 'shorewall \[re\]start'.

6.  The STATEDIR variable in /etc/shorewall/shorewall.conf has been removed. STATEDIR is now fixed at /var/lib/shorewall. If you have previously set STATEDIR to another directory, please copy the files from that directory to /var/lib/shorewall/ before \[re\]starting Shorewall after the upgrade to this version.

7.  The "shorewall status" command now just gives the status of Shorewall (started or not-started). The previous status command has been renamed "dump". The command also shows the state relative to the state diagram at [http://shorewall.org/starting_and_stopping_shorewall.htm](https://shorewall.org/starting_and_stopping_shorewall.htm). In addition to the state, the time and date at which that state was entered is shown.

    Note that at least one "shorewall \[re\]start" must be issued after upgrading to this release before "shorewall status" will show anything but "Unknown" for the state.

8.  The "shorewall forget" command now removes the dynamic blacklist save file (/var/lib/shorewall/save).

9.  In previous versions of Shorewall, the rules generated by entries in `/etc/shorewall/tunnels` preceded those rules generated by entries in `/etc/shorewall/rules`. Beginning with this release, the rules generated by entries in the tunnels file will appear \*AFTER\* the rules generated by the rules file. This may cause you problems if you have REJECT, DENY or CONTINUE rules in your rules file that would cause the tunnel transport packets to not reach the rules that ACCEPT them. See <https://shorewall.org/VPNBasics.html> for information on the rules generated by entries in the tunnels file.

10. The NEWNOTSYN and LOGNEWNOTSYN options in shorewall.conf have been removed as have the 'newnotsyn' options in `/etc/shorewall/interfaces` and `/etc/shorewall/hosts`.

    TCP new-not-syn packets may be blocked using the 'dropNotSyn' or 'rejNotSyn' built-in actions.

    Example: Reject all new-not-syn packets from the net and log them at the 'info' level.

        #ACTION          SOURCE           DEST           PROTO
        SECTION NEW
        rejNotSyn:info   net              all            tcp

    Note that the rule is added at the front of the NEW section of the rules file.

11. A new TC_SCRIPT option replaces TC_ENABLED in shorewall.conf. If the option is not set then the internal shaper (tc4shorewall by Arne Bernin) is used. Otherwise, the script named in the variable is used.

    Users who currently use an `/etc/shorewall/tcstart` file and wish to continue to do so should set TC_SCRIPT=/etc/shorewall/tcstart in shorewall.conf.

# Version \>= 2.4.0

1.  Shorewall now enforces the restriction that mark values used in `/etc/shorewall/tcrules` are less than 256. If you are using mark values \>= 256, you must change your configuration before you upgrade.

2.  The value "ipp2p" is no longer accepted in the PROTO column of the `/etc/shorewall/rules` file. This support has never worked as intended and cannot be made to work in a consistent way. A "Howto" article on filtering P2P with Shorewall and ipp2p will be forthcoming.

3.  LEAF/Bering packages for 2.4.0 and later releases are not available from shorewall.net. See the [LEAF site](http://leaf.sourceforge.net) for those packages.
