<div class="caution">

**This article applies to Shorewall 4.4 and later. If you are running a version of Shorewall earlier than Shorewall 4.4.0 then please see the documentation appropriate for your version.**

</div>

# What are Ipsets?

Ipsets are an extension to Netfilter/iptables that are available in [xtables-addons](http://xtables-addons.sourceforge.net/) if they are not available in your current distribution. Instructions for installing xtables-addons may be found in the [Dynamic Zones article](Dynamic.md). Note that xtables-addons might not be required with the 'ipset' package provided by your distribution. See also the section [capabilities](../reference/configuration_file_basics.md#capabilities) in the [configuration file basics article](../reference/configuration_file_basics.md) and the [Shorecap program](Shorewall-Lite.md#Shorecap).

Ipset allows you to create one or more named sets of addresses then use those sets to define Netfilter/iptables rules. Possible uses of ipsets include:

1.  Blacklists. Ipsets provide an efficient way to represent large sets of addresses and you can maintain the lists without the need to restart or even refresh your Shorewall configuration.

2.  Zone definition. Using the /etc/shorewall/hosts file, you can [define a zone based on the (dynamic) contents of an ipset](Dynamic.md). Again, you can then add or delete addresses to the ipset without restarting Shorewall.

See the ipsets site (URL above) for additional information about ipsets.

# Shorewall Support for Ipsets

Support for ipsets was introduced in Shorewall version 2.3.0. In most places where a host or network address may be used, you may also use the name of an ipset prefaced by "+".

Example: "+Mirrors"

When using Shorewall, the names of ipsets are restricted as follows:

- They must begin with a letter (after the '+').

- They must be composed of letters, digits, dashes ("-") or underscores ("\_").

To generate a negative match, prefix the "+" with "!" as in "!+Mirrors".

Example 1: Blacklist all hosts in an ipset named "blacklist"

`/etc/shorewall/blrules`

    #ACTION      SOURCE           DEST     PROTO    DPORT
    DROP         net:+blacklist

Example 2: Allow SSH from all hosts in an ipset named "sshok:

`/etc/shorewall/rules`

    #ACTION      SOURCE           DEST     PROTO    DPORT
    ACCEPT       net:+sshok       $FW      tcp      22

The name of the ipset can be optionally followed by a comma-separated list of flags enclosed in square brackets (\[...\]). Each flag is either **src** or **dst** and specifies whether it is the SOURCE address or port number or the DESTINATION address or port number that should be matched. The number of flags must be appropriate for the type of ipset. If no flags are given, Shorewall assumes that the set takes a single flag and will select the flag based on the context. For example, in the blacklist file and when the ipset appears in the SOURCE column of the rules file, **src** is assumed. If the ipset appears in the DEST column of the rules file, **dst** is assumed. Note that by using **\[dst\]** in the blacklist file, you can coerce the rule into matching the destination IP address rather than the source.

Beginning with Shorewall 4.4.14, multiple source or destination matches may be specified by placing multiple set names in '+\[...\]' (e.g., +\[myset,myotherset\]). When so enclosed, the set names need not be prefixed with a plus sign. When such a list of sets is specified, matching packets must match all of the listed sets.

Shorewall can save/restore your ipset contents with certain restrictions:

1.  You must set SAVE_IPSETS=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5).

2.  You must have at least one entry in the other configuration files that uses an ipset.

3.  You can use an ipset in [shorewall-stoppedrules](https://shorewall.org/manpages/shorewall-stoppedulres.html) (5), but SAVE_IPSET={Yes\|ipv4} will not save such a set during 'stop' processing. Use Shorewall-init to save/restore your ipsets in this case (see below).

4.  The `restore` command cannot restore ipset contents saved by the `save` command unless the firewall is first stopped.

Beginning with Shorewall 4.6.4, you can save selective ipsets by setting SAVE_IPSETS to a comma-separated list of ipset names. You can also restrict the group of sets saved to ipv4 sets by setting SAVE_IPSETS=ipv4.

With Shorewall 4.6.4, the SAVE_IPSETS option may specify a list of ipsets to be saved. When such a list is specified, only those ipsets together with the ipsets supporting dynamic zones are saved. Shorewall6 support for the SAVE_IPSETS option was also added in 4.6.4. When SAVE_IPSETS=Yes in [shorewall6.conf(5)](https://shorewall.org/manpages/shorewall.conf.html), only ipv6 ipsets are saved. For Shorewall, if SAVE_IPSETS=ipv4 in [shorewall.conf(5)](https://shorewall.org/manpages/shorewall.conf.html), then only ipv4 ipsets are saved. Both features require ipset version 5 or later.

<div class="caution">

After setting SAVE_IPSETS, it is important to recompile the firewall script (e.g., 'shorewall compile', 'shorewall reload' or 'shorewall restart') before rebooting

</div>

Although Shorewall can save the definition of your ipsets and restore them when Shorewall starts, in most cases you must use the ipset utility to initially create and load your ipsets. The exception is that Shorewall will automatically create an empty iphash ipset to back each dynamic zone. It will also create the ipset required by the DYNAMIC_BLACKLIST=ipset:.. setting in [shorewall\[6\].conf(5)](https://shorewall.org/manpages/shorewall.conf.html),

# Shorewall6 and Shorewall-init Support for Ipsets

Ipset support in Shorewall6 was added in Shorewall 4.4.21.

Beginning with Shorewall 4.6.4, SAVE_IPSETS is available in [shorewall6-conf(5)](https://shorewall.org/manpages/shorewall.conf.html). When set to Yes, the ipv6 ipsets will be saved. You can also save selective ipsets by setting SAVE_IPSETS to a comma-separated list of ipset names.

Prior to Shorewall 4.6.4, SAVE_IPSETS=Yes in [shorewall.conf(5)](https://shorewall.org/manpages/shorewall.conf.html) won't work correctly because it saves both IPv4 and IPv6 ipsets. To work around this issue, Shorewall-init is capable restoring ipset contents during 'start' and saving them during 'stop'. To direct Shorewall-init to save/restore ipset contents, set the SAVE_IPSETS option in /etc/sysconfig/shorewall-init (/etc/default/shorewall-init on Debian and derivatives). The value of the option is a file name where the contents of the ipsets will be save to and restored from. Shorewall-init will create any necessary directories during the first 'save' operation.

<div class="caution">

If you set SAVE_IPSETS in /etc/sysconfig/shorewall-init (/etc/default/shorewall-init on Debian and derivatives) when shorewall-init has not been started by systemd, then when the system is going down during reboot, the ipset contents will not be saved. You can work around that as follows:

- Suppose that you have set SAVE_IPSETS=/var/lib/shorewall/init-save-ipsets.

- Before rebooting, execute this command:

      ipset save > /var/lib/shorewall/init-save-ipsets

- Be sure to enable shoewall-init (e.g., **systemctl enable shorewall-init**).

</div>

If you configure Shorewall-init to save/restore ipsets, be sure to set SAVE_IPSETS=No in shorewall.conf and shorewall6.conf.

If you configure SAVE_IPSETS in [shorewall.conf(5)](https://shorewall.org/manpages/shorewall.conf.html) and/or [shorewall6.conf(5)](https://shorewall.org/manpages/shorewall.conf.html) then do not set SAVE_IPSETS in shorewall-init.
