# Background

In early 2011, Thomas Graf submitted a set of patches to the Netfilter development list that implemented an AUDIT rule target. This is from the initial submittal:

> This patch adds a new netfilter target which creates audit records for packets traversing a certain chain. It can be used to record packets which are rejected administraively as follows:
>
> -N AUDIT_DROP
>
> -A AUDIT_DROP -j AUDIT --type DROP
>
> -A AUDIT_DROP -j DROP
>
> A rule which would typically drop or reject a packet would then invoke the new chain to record packets before dropping them.
>
> -j AUDIT_DROP
>
> The module is protocol independant and works for iptables, ip6tables and ebtables.
>
> - netfilter hook
>
> - packet length
>
> - incoming/outgoing interface
>
> - MAC src/dst/proto for ethernet packets
>
> - src/dst/protocol address for IPv4/IPv6
>
> - src/dst port for TCP/UDP/UDPLITE
>
> - icmp type/code

The audited packets are sent to a daemon (auditd) that write the audit information to a log file.

In a related post by Eric Paris, the following additional information was posted:

> AUDIT exists because a very large number of gov't customers (Not just USA) have special requirements about how 'relevant' information is gathered and stored. They require centralization and standardization and require pretty formal documentation describing it's operation. The gov't certification authority has recently added a requirement that they be able to log 'illegal attempted network connections' via the approved audit facility. Thus, this patch.

The AUDIT target was included in Linux kernel 2.6.39.

# Shorewall Support

Shorewall support for the AUDIT target was added in 4.4.20.

The support involves the following:

1.  A new "AUDIT Target" capability is added and is required for auditing support. To use AUDIT support with a capabilities file, that file must be generated using this or a later release.

    Use 'shorewall show capabilities' after installing this release to see if your kernel/iptables support the AUDIT target.

2.  In /etc/shorewall/policy's POLICY column, the policy (and default action, if any) may be followed by ':audit' to cause application of the policy to be audited. Only ACCEPT, DROP and REJECT policies may be audited.

    Example:

        #SOURCE         DEST            POLICY
        net         $FW             DROP:audit

    It is allowed to also specify a log level on audited policies resulting in both auditing and logging.

3.  Three new builtin targets that may be used in the rules file, in macros and in other actions.

    - A_ACCEPT - Audits and accepts the connection request

    - A_DROP - Audits and drops the connection request

    - A_REJECT - Audits and rejects

    A log level may be supplied with these actions to provide both auditing and logging.

    Example:

        #ACTION         SOURCE          DEST            PROTO
        A_ACCEPT:info   loc             net             ...

4.  The BLACKLIST_DISPOSITION, MACLIST_DISPOSITION, SMURF_DISPOSITION and TCP_FLAGS_DISPOSITION options may be set as follows:

    |                       |                                              |
    |-----------------------|----------------------------------------------|
    | BLACKLIST_DISPOSITION | A_DROP or A_REJECT                           |
    | MACLIST_DISPOSITION   | A_DROP, A_REJECT unless MACLIST_TABLE=mangle |
    | SMURF_DISPOSITION[^1] | A_DROP                                       |
    | TCP_FLAGS_DISPOSITION | A_DROP or A_REJECT                           |

5.  An 'audit' option has been added to the /etc/shorewall/blacklist file which causes the packets matching the entryto be audited. 'audit' may not be specified together with 'accept'.

6.  The builtin actions (dropBroadcast, rejNonSyn, etc.) now support an 'audit' parameter which causes all ACCEPT, DROP and REJECTs performed by the action to be audited.

7.  There are audited versions of the standard [Default Actions](../concepts/Actions.md#Default) (A_Drop and A_Reject). These actions audit everything they do which is probably more than you want; as a consequence, you probably will want to make your own copies of these actions and modify them to only audit the packets that you are interested in.

8.  In Shorewall 4.4.21, the standard [Default Actions](../concepts/Actions.md#Default) were parameterized, accepting three parameters:

    1.  Pass 'audit' if you want all ACCEPTs, DROPs and REJECTs audited. Pass '-' otherwise.

    2.  The action to be applied to Auth requests; the default depends on the first parameter:

        |                     |             |
        |---------------------|-------------|
        | **FIRST PARAMETER** | **DEFAULT** |
        | \-                  | REJECT      |
        | audit               | A_REJECT    |

    3.  The action to be applied to SMB traffic. The default depends on the first parameter:

        |            |                     |             |
        |------------|---------------------|-------------|
        | **ACTION** | **FIRST PARAMETER** | **DEFAULT** |
        | Reject     | \-                  | REJECT      |
        | Drop       | \-                  | DROP        |
        | Reject     | audit               | A_REJECT    |
        | Drop       | audit               | A_DROP      |

    The parameters can be passed in the POLICY column of the policy file.

        #SOURCE         DEST            POLICY
        net         all         DROP:Drop(audit):audit  #Same as DROP:A_DROP:audit

        #SOURCE         DEST            POLICY
        net             all             DROP:Drop(-,DROP) #DROP rather than REJECT Auth

    The parameters can also be specified in shorewall.conf:

        DROP_DEFAULT=Drop(-,DROP) #DROP Auth rather than REJECT 

[^1]: This option was added in Shorewall 4.4.20
