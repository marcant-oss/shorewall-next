<div class="caution">

**This article applies to Shorewall 4.4 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

# Introduction

Shorewall supports two different types of blacklisting; rule-based, static and dynamic. The BLACKLIST option in /etc/shorewall/shorewall.conf controls the degree of blacklist filtering.

The BLACKLIST option lists the Netfilter connection-tracking states that blacklist rules are to be applied to (states are NEW, ESTABLISHED, RELATED, INVALID, NOTRACK). The BLACKLIST option supersedes the BLACKLISTNEWONLY option:

1.  BLACKLISTNEWONLY=No -- All incoming packets are checked against the blacklist. New blacklist entries can be used to terminate existing connections.

2.  BLACKLISTNEWONLY=Yes -- The blacklists are only consulted for new connection requests. Blacklists may not be used to terminate existing connections.

<div class="important">

For automatic blacklisting based on exceeding defined threshholds, see [Events](../concepts/Events.md).

</div>

# Rule-based Blacklisting

Beginning with Shorewall 4.4.25, the preferred method of blacklisting and whitelisting is to use the blrules file ([shorewall-blrules](https://shorewall.org/manpages/shorewall-blrules.html) (5)). There you have access to the DROP, ACCEPT, REJECT and WHITELIST actions, standard and custom macros as well as standard and custom actions. See [shorewall-blrules](https://shorewall.org/manpages/shorewall-blrules.html) (5) for details.

Example:

    #ACTION         SOURCE                  DEST                    PROTO   DPORT

    WHITELIST       net:70.90.191.126       all
    DROP            net                     all                     udp     1023:1033,1434,5948,23773
    DROP            all                     net                     udp     1023:1033
    DROP            net                     all                     tcp     57,1433,1434,2401,2745,3127,3306,3410,4899,5554,5948,6101,8081,9898,23773
    DROP            net:221.192.199.48      all
    DROP            net:61.158.162.9        all
    DROP            net:81.21.54.100        all                     tcp     25
    DROP            net:84.108.168.139      all                             
    DROP            net:200.55.14.18        all

Beginning with Shorewall 4.4.26, the `update` command supports a `-b` option that causes your legacy blacklisting configuration to use the blrules file.

# Chain-based Dynamic Blacklisting

Beginning with Shorewall 4.4.7, dynamic blacklisting is enabled by setting DYNAMIC_BLACKLIST=Yes in `shorewall.conf`. Prior to that release, the feature is always enabled.

Once enabled, dynamic blacklisting doesn't use any configuration parameters but is rather controlled using /sbin/shorewall\[-lite\] commands. **Note** that **to** and **from** may only be specified when running **Shorewall 4.4.12 or later**.

- drop \[to\|from\] *\<ip address list\>* - causes packets from the listed IP addresses to be silently dropped by the firewall.

- reject \[to\|from\]*\<ip address list\>* - causes packets from the listed IP addresses to be rejected by the firewall.

- allow \[to\|from\] *\<ip address list\>* - re-enables receipt of packets from hosts previously blacklisted by a *drop* or *reject* command.

- save - save the dynamic blacklisting configuration so that it will be automatically restored the next time that the firewall is restarted.

  **Update:** Beginning with Shorewall 4.4.10, the dynamic blacklist is automatically retained over `stop/start` sequences and over `restart` and **reload**.

- show dynamic - displays the dynamic blacklisting configuration.

- logdrop \[to\|from\] *\<ip address list\>* - causes packets from the listed IP addresses to be dropped and logged by the firewall. Logging will occur at the level specified by the BLACKLIST_LOGLEVEL setting at the last \[re\]start (logging will be at the 'info' level if no BLACKLIST_LOGLEVEL was given).

- logreject \[to\|from}*\<ip address list\>* - causes packets from the listed IP addresses to be rejected and logged by the firewall. Logging will occur at the level specified by the BLACKLIST_LOGLEVEL setting at the last \[re\]start (logging will be at the 'info' level if no BLACKLIST_LOGLEVEL was given).

# Ipset-based Dynamic Blacklisting

Beginning with Shorewall 5.0.8, it is possible to use an ipset to hold blacklisted addresses. The DYNAMIC_BLACKLIST option was expanded to:

**DYNAMIC_BLACKLIST=**{**Yes**\|**No**\|\|**ipset**\[**-only**\]\[\<,option\>\[,...\]\]\[:\[\<setname\>\]\[:\<log_level\>\|:l\<og_tag\>\]\]\]}

When `ipset` or `ipset-only` is specified, the `shorewall blacklist` command is used to blacklist a single host or a network. The `allow` command is used to remove entries from the ipset. The name of the set (\<setname\>) and the level (\<log_level\>), if any, at which blacklisted traffic is to be logged may also be specified. The default set name is SW_DBL4 and the default log level is `none` (no logging). If `ipset-only` is given, then chain-based dynamic blacklisting is disabled just as if DYNAMIC_BLACKLISTING=No had been specified.

Possible \<option\>s are:

src-dst  
Normally, only packets whose source address matches an entry in the ipset are dropped. If `src-dst` is included, then packets whose destination address matches an entry in the ipset are also dropped.

`disconnect`  
The `disconnect` option was added in Shorewall 5.0.13 and requires that the conntrack utility be installed on the firewall system. When an address is blacklisted using the `blacklist` command, all connections originating from that address are disconnected. if the `src-dst` option was also specified, then all connections to that address are also disconnected.

`timeout`=\<seconds\>  
Added in Shorewall 5.0.13. Normally, Shorewall creates the dynamic blacklisting ipset with timeout 0 which means that entries are permanent. If you want entries in the set that are not accessed for a period of time to be deleted from the set, you may specify that period using this option. Note that the `blacklist` command can override the ipset's timeout setting.

<div class="important">

Once the dynamic blacklisting ipset has been created, changing this option setting requires a complete restart of the firewall; `shorewall restart` if RESTART=restart, otherwise `shorewall stop && shorewall start`

</div>

log  
Added in Shorewall 5.2.5. When specified, successful 'blacklist' and 'allow' commands will log a message to the system log.

noupdate  
Added in Shorewall 5.2.5. Normally, once an address has been blacklisted, each time that a packet is received from the packet, the ipset's entry for the address is updated to reset the timeout to the value specifyed in the `timeout` option above. Setting the `noupdate` option, inhibits this resetting of the entry's timeout. This option is ignored when the `timeout` option is not specified.

When ipset-based dynamic blacklisting is enabled, the contents of the blacklist will be preserved over `stop`/`reboot`/`start` sequences.

# BLACKLIST Policy and Action

Beginning with Shorewall 5.1.1, it is possible to specify BLACKLIST in the POLICY column of [shorewall-policy](https://shorewall.org/manpages/shorewall-policy.html)(5) when ipset-based dynamic blacklisting is being used. When a packet is disposed of via the BLACKLIST policy, the packet's sender is added to the dynamic blacklist ipset and the packet is dropped.

Also available beginning with Shorewall 5.1.1 is a BLACKLIST action for use in the rules file, macros and filter table actions. Execute the `shorewall show action BLACKLIST` command for details.

# BLACKLIST and Fail2ban

The BLACKLIST command can be used as 'blocktype' in /etc/fail2ban/action.d/shorewall.conf. Prior to Shorewall 5.2.5, this works best if there is no **timeout** specified in the DYNAMIC_BLACKLIST setting or if **timeout=0** is given.

Beginning with Shorewall 5.2.5, Shorewall includes new features that allow fail2ban to work most seamlessly with Shorewall's ipset-based dynamic blacklisting:

- When a **timeout** is specified in the DYNAMIC_BLACKLIST setting, the dynamic-blacklisting ipset is created with default timeout 0. As entries are added by BLACKLIST policies or by the **blacklist** command, the created entry is given the specified timeout value.

- The **noupdate** option has been added. Specifying this option prevents 'timeout 0' ipset entries from being changed to finite timeout entries as a result of blacklisted ip addresses continuing to send packets to the firewall.

- The **blacklist!** command has been added. specifying that command as the fail2ban 'blocktype' causes entries created by fail2ban to persist until fail2ban unbans them using the Shorewall **allow** comand.

There are a couple of additional things to note:

- The documentation in /etc/fail2ban/action.d/shorewall.conf states that you should set BLACKLIST=All. A better approach when using BLACKLIST as the 'blocktype' is to specify the **disconnect** option in the setting of DYNAMIC_BLACKLIST. With BLACKLIST=All, every packet entering the firewall from the net must be checked against the dynamic-blacklisting ipset. That is not required when you specify **disconnect**.

- The **noupdate** option allows fail2ban full control when a host is 'unbanned'. The cost of using this option is that after the specified **timeout**, the entry for an attacking host will be removed from the dynamic-blacklisting ipset, even if the host has continued the attack while blacklisted. This isn't a great concern, as the first attempt to access an unauthorized service will result in the host being re-blacklisted.
