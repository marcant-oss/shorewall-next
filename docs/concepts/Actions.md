<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

# What are Shorewall Actions?

Shorewall actions allow a symbolic name to be associated with a series of one or more iptables rules. The symbolic name may appear in the ACTION column of an `/etc/shorewall/rules` entry, in a [macro](Macros.md) body and within another action, in which case the traffic matching that rules file entry will be passed to the series of iptables rules named by the action.

Actions can be thought of as templates. When an action is invoked in an `/etc/shorewall/rules` entry, it may be qualified by a logging specification (log level and optionally a log tag). The presence of the log level/tag causes a modified series of rules to be generated in which each packet/rule match within the action causes a log message to be generated.

For readers familiar with iptables, actions are the way in which you can create your own filter-table chains.

There are three types of Shorewall actions:

1.  Built-in Actions. These actions are known by the Shorewall code itself. They were formerly listed in the comments at the top of the file `/usr/share/shorewall/actions.std`. They have now been replaced by Standard Actions.

2.  Standard Actions. These actions are released as part of Shorewall. They are listed in the file `/usr/share/shorewall/actions.std` and are defined in the corresponding action.\* files in `/usr/share/shorewall`. Each `action.*` file has a comment at the beginning of the file that describes what the action does. As an example, here is the definition of the AllowSMB standard action from Shorewall version 2.2.

        #
        # Shorewall 2.2 /usr/share/shorewall/action.AllowSMB
        #
        #       Allow Microsoft SMB traffic. You need to invoke this action in
        #       both directions.
        #
        ######################################################################################
        #TARGET  SOURCE         DEST            PROTO   DPORT   SPORT           RATE    USER
        ACCEPT   -              -               udp     135,445
        ACCEPT   -              -               udp     137:139
        ACCEPT   -              -               udp     1024:   137
        ACCEPT   -              -               tcp     135,139,445

    If you wish to modify one of the standard actions, do not modify the definition in `/usr/share/shorewall`. Rather, copy the file to `/etc/shorewall` (or somewhere else on your CONFIG_PATH) and modify the copy.

    You can see a list of the standard actions with a short description of each action using the `shorewall show actions` command. You can display the contents of action.\<name\>by typing s`horewall show action name`.

3.  User-defined Actions. These actions are created by end-users. They are listed in the file `/etc/shorewall/actions` and are defined in `action.*` files in `/etc/shorewall` or in another directory listed in your CONFIG_PATH (defined in `/etc/shorewall/shorewall.conf`).

# Policy Actions (Formerly Default Actions)

Shorewall allows the association of a policy action with policies. A separate policy action may be associated with ACCEPT, DROP, REJECT, QUEUE, NFQUEUE and BLACKLIST policies. Policy actions provide a way to invoke a set of common rules just before the policy is enforced. Policy actions accomplish two goals:

1.  Relieve log congestion. Default actions typically include rules to silently drop or reject traffic that would otherwise be logged when the policy is enforced.

2.  Ensure correct operation.

Shorewall supports policy actions for the ACCEPT, REJECT, DROP, QUEUE, NFQUEUE and BLACKLIST policies. These default actions are specified in the `/etc/shorewall/shorewall.conf` file using the ACCEPT_DEFAULT, REJECT_DEFAULT, DROP_DEFAULT, QUEUE_DEFAULT and NFQUEUE_DEFAULT options respectively. Policies whose default is set to a value of “none” have no default action.

In addition, the default specified in `/etc/shorewall/shorewall.conf` may be overridden by specifying a different action in the POLICY column of `/etc/shorewall/policy`.

<div class="important">

Entries in the DROP, REJECT and BLACKLIST policy actions **ARE NOT THE CAUSE OF CONNECTION PROBLEMS**. Remember — policy actions are only invoked immediately before the packet is going to be dropped or rejected anyway!!!

</div>

Prior to Shorewall 5.1.2, the Drop and Reject actions were the default policy actions for DROP and REJECT policies respectively. Those actions are parameterized; each has five parameters as follows:

|        |           |                                                                                                |                                                            |
|--------|-----------|------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| ACTION | PARAMETER | VALUE                                                                                          | DEFAULT                                                    |
| Drop   | 1         | Either '-' or 'audit'. 'audit' causes auditing by the builtin actions invoked by Drop          | \-                                                         |
| Drop   | 2         | Determines what to do with Auth requests                                                       | \-                                                         |
| Drop   | 3         | Determines what to do with SMB                                                                 | DROP or A_DROP depending on the setting of parameter 1     |
| Reject | 1         | Either '-' or 'audit'. 'audit' causes auditing by the builtin actions invoked by Drop          | \-                                                         |
| Reject | 2         | Determines what to do with Auth requests                                                       | \-                                                         |
| Reject | 3         | Determines what to do with SMB                                                                 | REJECT or A_REJECT depending on the setting of parameter 1 |
| Both   | 4         | Determines what to do with accepted critical ICMP packets.                                     | ACCEPT or A_ACCEPT depending on the setting of parameter 1 |
| Both   | 5         | Determines what to do with late-arriving DNS replies (source port 53) or UPnP (udp port 1900). | DROP or A_DROP depending on the setting of parameter 1.    |

The parameters may be specified in either shorewall.conf (e.g., DROP_DEFAULT=**Drop(-,DROP)** or in the POLICY column of [shorewall-policy](https://shorewall.org/manpages/shorewall-policy.html)(5) (e.g., DROP:**Drop(audit)**:audit).

Beginning with Shorewall 5.1.2, Drop and Reject are deprecated. In 5.1.2, a list of policy actions is accepted in both shorewall.conf and the policy file. This allows logging to be specified on some actions and not on others and eliminates the need for a large number of policy-action parameters.

Actions commonly included in policy-action lists are:

Broadcast\[(\<disposition\>)\]  
Handles broadcasts based on the \<disposition\>. The default \<disposition\> is DROP.

Multicast\[(\<disposition\>)\]  
Handles multicasts based on the \<disposition\>. The default \<disposition\> is DROP.

dropNotSyn\[:\<level\>\]  
Drops TCP packets that are not part of an existing connection but that don't have the SYN flag set or that have additional flags set. We recommend that these be logged by specifying an approproate \<level\>. This action is particularly appropriate packets received from the Internet. Recommended when the policy is BLACKLIST to avoid late-arriving FIN packets from blacklisting the remote system.

DropDNSrep\[:\<level\>\]  
Drops UDP packets with source port 53. We recommend that these be logged by specifying an approproate \<level\>. This action is recommended when the policy is BLACKLIST to avoid blacklisting uplevel DNS servers.

AllowICMPs (IPv6 only)  
Allows ICMP packets mandated by RFC 4890. In particular, this ensures that Neighbor Discovery won't be broken

The recommended settings for the 6 policy actions for IPv4 are:

            ACCEPT_DEFAULT=none
            BLACKLIST_DEFAULT="Broadcast(DROP),Multicast(DROP),dropNotSyn:$LOG_LEVEL,dropInvalid:$LOG_LEVEL,DropDNSrep:$LOG_LEVEL"
            DROP_DEFAULT="Broadcast(DROP),Multicast(DROP)"
            NFQUEUE_DEFAULT=none
            QUEUE_DEFAULT=none
            REJECT_DEFAULT="Broadcast(DROP),Multicast(DROP)"

The recommended settings for IPv6 are:

            ACCEPT_DEFAULT=none
            BLACKLIST_DEFAULT="AllowICMPs,Broadcast(DROP),Multicast(DROP),dropNotSyn:$LOG_LEVEL,dropInvalid:$LOG_LEVEL,DropDNSrep:$LOG_LEVEL"
            DROP_DEFAULT="AllowICMPs,Broadcast(DROP),Multicast(DROP)"
            NFQUEUE_DEFAULT=none
            QUEUE_DEFAULT=none
            REJECT_DEFAULT="AllowICMPs,Broadcast(DROP),Multicast(DROP)"

Note that in both cases, logging occurs based on the setting of LOG_LEVEL in shorewall\[6\].conf.

# Defining your own Actions

Before defining a new action, you should evaluate whether your goal can be best accomplished using an action or a macro. See [this article](Macros.md) for details.

To define a new action:

1.  Add a line to `/etc/shorewall/actions` that names your new action. Action names must be valid shell variable names (must begin with a letter and be composed of letters, digits and underscore characters) as well as valid Netfilter chain names. If you intend to log from the action, the name must have a maximum of 11 characters. It is recommended that the name you select for a new action begins with a capital letter; that way, the name won't conflict with a Shorewall-defined chain name.

    Normally. the rules in an action are placed in a separate chain. Beginning with Shorewall 4.5.10, the action rules can be expanded inline in a manner similar to a macro by specifying `inline` in the OPTIONS column of `/etc/shorewall/actions`.

    Beginning in Shorewall 4.5.11, the `nolog` option may be specified; see the [logging section](#Logging) below for details.

    Shorewall includes pre-defined actions for DROP and REJECT -- see above.

2.  Once you have defined your new action name (ActionName), then copy `/usr/share/shorewall/action.template` to `/etc/shorewall/action.ActionName` (for example, if your new action name is “Foo” then copy `/usr/share/shorewall/action.template` to `/etc/shorewall/action.Foo`).

3.  Now modify the new file to define the new action.

## Shorewall 5.0.0 and Later.

In Shorewall 5.0, the columns in action.template are the same as those in shorewall-rules (5). There are no restrictions regarding which targets can be used within your action.

The SOURCE and DEST columns in the action file may not include zone names; those are given when the action is invoked.

Additionally, it is possible to pass parameters to an action, when it is invoked in the rules file or in another action.

Here's a trivial example:

/etc/shorewall/action.A:

    #TARGET        SOURCE  DEST    PROTO   Dport   SPORT   ORIGDEST
    $1             -       -       tcp     80      -       1.2.3.4

/etc/shorewall/rules:

    #TARGET        SOURCE  DEST    PROTO   DPORT   SPORT   ORIGDEST

    A(REDIRECT)    net     fw

The above is equivalent to this rule:

    #TARGET        SOURCE  DEST    PROTO   DPORT   SPORT   ORIGDEST
    REDIRECT       net     -       tcp     80      -       1.2.3.4

You can 'omit' parameters by using '-'.

Example: ACTION(REDIRECT,-,info)

In the above example, \$2 would expand to nothing.

Beginning with Shorewall 4.5.13, completely omitting a arameter is equivalent to passing '-'.

Example: ACTION(REDIRECT,,info)

This example behaves the same as the one shown above.

If you refer to a parameter \$n in the body of the action, then the nth paramer must either be passed to all action invocations or it's default value must be established via a DEFAULTS line.

If you want to make '-' a parameter value, use '--' (e.g., ACTION(REDIRECT,--.info)).

Beginning with Shorewall 4.4.21, you can specify the default values of your FORMAT-2 actions:

    DEFAULTS def1,def2,...

where \<def1\> is the default value for the first parameter, \<def2\> is the default value for the second parameter and so on. You can specify an empty default using '-' (e.g. DEFAULTS DROP,-,audit).

For additional information about actions, see the [Action Variables section](../reference/configuration_file_basics.md#ActionVariables) of the Configuration Basics article.

## Mangle Actions

Beginning with Shorewall 5.0.7, actions may be used in [shorewall-mangle(5)](https://shorewall.org/manpages/shorewall-mangle.html). Because the rules and mangle files have different column layouts, actions can be defined to be used in one file or the other but not in both. To designate an action to be used in the mangle file, specify the `mangle` option in the action's entry in [shorewall-actions](https://shorewall.org/manpages/shorewall-actions.html)(5).

To create a mangle action, follow the steps in the preceding section, but use the `/usr/share/shorewall/action.mangletemplate` file.

# Actions and Logging

Specifying a log level in a rule that specifies a user-defined or Shorewall-defined action will cause each rule in the action to be logged with the specified level (and tag), unless the `nolog` option is specified in the action's entry in `/etc/shorewall/actions`.

The extent to which logging of action rules occur is governed by the following:

1.  When you invoke an action and specify a log level, only those rules in the action that have no log level will be changed to log at the level specified at the action invocation.

    Example:

    /etc/shorewall/action.foo

        #TARGET      SOURCE     DEST     PROTO    DPORT
        ACCEPT       -          -        tcp      22
        bar:info

    /etc/shorewall/rules:

        #ACTION      SOURCE     DEST     PROTO    DPORT
        foo:debug    $FW         net

    Logging in the invoke “foo” action will be as if foo had been defined as:

        #TARGET      SOURCE     DEST     PROTO    DPORT
        ACCEPT:debug -          -        tcp      22
        bar:info

2.  If you follow the log level with “!” then logging will be set at that level for all rules recursively invoked by the action.

    Example:

    /etc/shorewall/action.foo

        #TARGET      SOURCE     DEST     PROTO    DPORT
        ACCEPT       -          -        tcp      22
        bar:info

    /etc/shorewall/rules:

        #ACTION      SOURCE     DEST     PROTO    DPORT
        foo:debug!   $FW        net

    Logging in the invoke “foo” action will be as if foo had been defined as:

        #TARGET      SOURCE     DEST     PROTO    DPORT
        ACCEPT:debug -          -        tcp      22
        bar:debug

# Using Embedded Perl in an Action

There may be cases where you wish to create a chain with rules that can't be constructed using the tools defined in the `action.template`. Such rules can be constructed using [Embedded Perl.](../reference/configuration_file_basics.md#Embedded) For those who are comfortable using Perl, embedded Perl is more efficient that using complicated conditional entries. The Perl compiler is invoked only once for a BEGIN PERL...END PERL block; it is invoked most times that an expression is evaluated in an ?IF, ?ELSEIF or ?SET directive.

The Shorewall compiler provides a set of services that are available to Perl code embedded in an action file. These services are not available in in-line actions when running Shorewall 4.5.12 or earlier.

Shorewall::Config::get_action_params( \<\$howmany\> )  
This function returns an array containing the functions parameters. The scalar argument \<\$howmany\> is the number of parameters that you expect to be passed. You can ensure that at least this many parameters are passed by including a DEFAULTS line prior to the embedded Perl.

Shorewall::Config::set_action_param( \<\$ordinal\>, \<\$value\> )  
Set the value of parameter \<\$ordinal\> to \<\$value\>. Care must be take when using this function such that for a given set of parameters actually passed to the action, the same rules are created. That is because the compiler assumes that all invocations of an action with the same parameters, log level and log tag can share the same action chain.

Shorewall::Config::get_action_chain()  
This function returns a reference to the chain table entry for the current action chain.

Shorewall::Config::get_action_logging()  
Returns a two-element list containing the the log level and log tag specified when the action was invoked. Note that you must use this function rather than @loglevel and @logtag within embedded Perl, as the compiler does not expand [Shorewall Variables](../reference/configuration_file_basics.md#ShorewallVariables) within embedded Perl (or embedded shell).

Shorewall::Config::push_comment()  
Prior to Shorewall 4.5.21, this required:

    use Shorewall::Config (:DEFAULT :internal);

Returns the current rule comment to the caller and clears the comment. The returned comment may be restored by calling either pop_comment() or set_comment().

Shorewall::Config::pop_comment(\$comment) and Shorewall::Config::set_comment(\$comment).  
The set_comment() function was added in Shorewall 4.5.21. Prior to that release, accessing pop_comment() required:

    use Shorewall::Config (:DEFAULT :internal);

These functions are identical and set the current rule comment to the contents of the passed simple variable.

Shorewall::Chains::add_rule( \<\$chainre\>f, \<\$rule\> \[, \<\$expandports\> \] )  
This function adds a rule to a chain. As of Shoreall 4.5.13, it is deprecated in favor of Shorewall::Rules::perl_action_helper(). Arguments are:

\<\$chainref\>  
Normally, you get this from get_action_chain() described above.

\<\$rule\>  
The matches and target for the rule that you want added.

\<\$expandports\> (optional)  
This optional argument is for compiler-internal use only. Either omit it or pass a false value.

<div class="warning">

Do not call this function in a inline action. Use perl_action_helper() instead (see below).

</div>

Shorewall::Chains::log_rule_limit( \<\$level\>, \$\<chainref\>, \<\$chain\>, \<\$disposition\>, \<\$limit\>, \<\$tag\>, \<\$command\>, \<\$matches\> )  
This function adds a logging rule to a chain. As of Shoreall 4.5.13, it is deprecated in favor of Shorewall::Rules::perl_action_helper(). Arguments are:

\<\$level\>  
Either a syslog level or a ULOG or NFLOG target expression (e.g., "NFLOG(1,0,1)"). Specifies how you want the logging done.

\<\$chainref\>  
Normally, you get this from get_action_chain() described above.

\<\$chain\>  
The value you want substituted for the first %s formatting directive in the LOGFORMAT setting in `/etc/shorewall/shorewall.conf`.

\<\$disposition\>  
This is the value substituted for the second '%s' formatting directive in the LOGFORMAT setting in `/etc/shorewall/shorewall.conf`.

\<\$limit\>  
If you want to use the default limit set in LOGLIMIT (`/etc/shorewall/shorewall.conf`), you can specify your own '-limit' match. Otherwise, if you want to use the default, pass 0 or "". If you want the rule to be unlimited, pass '-'.

\<\$tag\>  
Log tag.

\<\$command\>  
Pass 'add' here, unless you want the rule to be inserted at the front of the chain.

\$matches  
Zero or more iptables matches that limit when logging will occur. If this parameter is other than the empty string, the last character must be a space.

Shorewall::Chains::allow::optimize( \<\$chainref\> )  
This allows the passed action chain to be optimized away (jumps to the chain are replaced by the chain's rule(s)). The \<chainref\> argument is usually obtained from get_action_chain() described above.

Shorewall::Rules::perl_action_helper( \$target, \$matches )  
This function adds a rule to the current chain. For a regular action, the chain will be an action chain; for an inline action, the chain is determined by the invoking rule.

To use this function, you must include:

use Shorewall::Rules;

Arguments are:

\$target  
The target of the rule. Legal values are anything that can appear in the TARGET column of in an action body and may include log level, tag, and parameters.

\$matches  
ip\[6\]tables matches to be included in the rule. When called in an inline action, these matches are augmented by matches generated by the invoking rule.

<div class="note">

This function has additional optional arguments which are used internally by Shorewall standard actions. Their number and behavior is likely to change in future Shorewall releases.

</div>

Shorewall::Rules::perl_action_tcp_helper( \$target, \$proto )  
This function is similar to Shorewall::Rules::perl_action_helper but is taylored for specifying options to "-p tcp".

To use this function, you must include:

use Shorewall::Rules;

Arguments are:

\$target  
The target of the rule. Legal values are anything that can appear in the TARGET column of in an action body and may include log level, tag, and parameters.

\$proto  
The '-p' part of the rule to be generated (e.g., "-p tcp --tcp-flags RST RST").

For examples of using these services, look at the standard actions in `/usr/share/shorewall/action.*`.

# Creating an Action using an Extension Script (deprecated in favor of BEGIN PERL ... END PERL)

There may be cases where you wish to create a chain with rules that can't be constructed using the tools defined in the `action.template`. In that case, you can use an [extension script](../reference/shorewall_extension_scripts.md). Beginning with Shorewall 4.5.16, such scripts require CHAIN_SCRIPTS=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5)

<div class="note">

If you actually need an action to drop broadcast packets, use the `dropBcast` standard action rather than create one like this.

</div>

If you define an action “acton” and you have an `/etc/shorewall/acton` script, the rules compiler sets lexical variables as follows:

- **\$chainref** is a reference to the chain-table entry for the chain where your rules are to be placed.

- **\$level** is the log level. If false, no logging was specified.

- **\$tag** is the log tag.

- **@params** is the list of parameter values (Shorewall 4.4.16 and later). 'Omitted' parameters contain '-'.

Example:

/etc/shorewall/actions

    DropBcasts

/etc/shorewall/action.DropBcasts

    # This file is empty

/etc/shorewall/DropBcasts

    use Shorewall::Chains;

    if ( $level ne '' ) {
        log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -m addrtype --dst-type BROADCAST ';
        log_rule_limit $level, $chainref, 'dropBcast' , 'DROP', '', $tag, 'add', ' -d 224.0.0.0/4 ';
    }

    add_rule $chainref, '-m addrtype --dst-type BROADCAST -j DROP';
    add_rule $chainref, '-d 224.0.0.0/4 -j DROP';

    1;

For a richer example, see the next section.

# Limiting Per-IP Connection Rate using the Limit Action

Shorewall supports a “Limit” built-in action. Prior to Shorewall 4.4.16, Limit is invoked with a comma-separated list in place of a logging tag. Beginning in Shorewall 4.4.16, it may also be invoked with a list of three parameters enclosed in parentheses. The list has three elements:

1.  The name of a “recent” list. You select the list name which must conform to the rules for a valid chain name. Different rules that specify the same list name will use the same set of counters.

2.  The number of connections permitted in a specified time period.

3.  The time period, expressed in seconds.

Connections that exceed the specified rate are dropped.

For example, to use a recent list name of **SSHA**, and to limit SSH connections to 3 per minute, use this entry in `/etc/shorewall/rules`:

    #ACTION                SOURCE            DEST           PROTO       DPORT
    Limit:none:SSHA,3,60   net               $FW            tcp         22

Using Shorewall 4.4.16 or later, you can also invoke the action this way:

    #ACTION                SOURCE            DEST           PROTO       DPORT
    Limit(SSHA,3,60):none  net               $FW            tcp         22

If you want dropped connections to be logged at the info level, use this rule instead:

    #ACTION                SOURCE            DEST           PROTO       DPORT
    Limit:info:SSHA,3,60   net               $FW            tcp         22

Shorewall 4.4.16 and later:

    #ACTION                SOURCE            DEST           PROTO       DPORT
    Limit(SSH,3,60):info   net               $FW            tcp         22

To summarize, you pass four pieces of information to the Limit action:

- The log level. If you don't want to log, specify “none”.

- The name of the recent list that you want to use (“SSHA” in this example).

- The maximum number of connections to accept (3 in this example).

- The number of seconds over which you are willing to accept that many connections (60 in this example).

## How Limit is Implemented

For those who are curious, the Limit action in Shorewall 4.4.16 is implemented as follows:

    use Shorewall::Chains;

    @params = split( /,/, $tag ), $tag='' unless @params;

    fatal_error 'Limit rules must include <list name>,<max connections>,<interval> as the log tag or params' unless @params == 3;

    my $list = $params[0];

    for ( @params[1,2] ) {
        fatal_error 'Max connections and interval in Limit rules must be numeric (' . $_ . ')' unless /^\d+$/
    }

    my $count = $params[1] + 1;

    add_rule $chainref, "-m recent --name $list --set";

    if ( $level ) {
        my $xchainref = new_chain 'filter' , "$chainref->{name}%";
        log_rule_limit $level, $xchainref, $params[0], 'DROP', $tag, '', 'add', '';
        add_rule $xchainref, '-j DROP';
        add_rule $chainref,  "-m recent --name $list --update --seconds $params[2] --hitcount $count -j $xchainref->{name}";
    } else {
        add_rule $chainref, "-m recent --update --name $list --seconds $params[2] --hitcount $count -j DROP";
    }

    add_rule $chainref, '-j ACCEPT';

    1; 

# Mangle Actions

Beginning with Shorewall 5.0.7, actions are supported in [shorewall-mangle(5)](https://shorewall.org/manpages/shorewall-mangle.html). Like actions used out of [shorewall-rules(5)](https://shorewall.org/manpages/shorewall-rules.html), they must be declared in [shorewall-actions(5)](https://shorewall.org/manpages/shorewall-actions.html). These mangle actions must have the `mangle` option specified on [shorewall-actions(5)](https://shorewall.org/manpages/shorewall-actions.html). Like the actions described in the preceding sections, mangle actions are defined in a files with names of the form action.\<action\>. Rules in those files have the same format as those in [shorewall-mangle(5)](https://shorewall.org/manpages/shorewall-mangle.html) with the restriction that chain designators (:P, :F, etc.) are not permitted in the ACTION column. Both regular and inline actions are supported.

Inline Example

`/etc/shorewall/actions`:

    #ACTION     OPTIONS
    Divert       inline,mangle      # TProxy Rules

`/etc/shorewall/action.Divert`:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT
    DIVERT          COMB_IF         -               tcp     -       80
    DIVERT          COMC_IF         -               tcp     -       80
    DIVERT          DMZ_IF          172.20.1.0/24   tcp     -       80

`/etc/shorewall/mangle`:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT
    Divert

More efficient way to do this:

`/etc/shorewall/actions`:

    #ACTION     OPTIONS
    Divert       inline             # TProxy Rules

`/etc/shorewall/action.Divert`:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT
    DIVERT          COMB_IF         -               
    DIVERT          COMC_IF         -               
    DIVERT          DMZ_IF          172.20.1.0/24

`/etc/shorewall/mangle`:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT
    Divert          -               -               tcp     -       80

# SNAT Actions

Beginning with Shorewall 5.0.14, actions are supported in [shorewall-snat(5](https://shorewall.org/manpages/shorewall-snat.html)); that file supercedes [shorewall-masq(5)](https://shorewall.org/manpages/shorewall-masq.html) which is still supported. The shorewall update command will convert a `masq` file into the equivalent `snat` file. Like actions used out of [shorewall-rules(5)](https://shorewall.org/manpages/shorewall-rules.html), SNAT actions must be declared in [shorewall-actions(5)](https://shorewall.org/manpages/shorewall-actions.html). These mangle actions must have the `nat` option specified on [shorewall-actions(5)](https://shorewall.org/manpages/shorewall-actions.html). Like the actions described in the preceding sections, SNAT actions are defined in a files with names of the form action.\<action\>. Rules in those files have the same format as those in [shorewall-snat(5)](https://shorewall.org/manpages/shorewall-snat.html) with two restrictions:

1.  The plus sign ("+") is not allowed in the ACTION column, so all rules in the action will either be pre-nat or post-nat depending on whether '+' was present in the action's invocation.

2.  Interface names are not allowed in the DEST column, so all rules in the action will apply to the interface specified in the action's invocation.

Both regular and inline actions are supported.

Example:

`/etc/shorewall/actions`:

    #ACTION     OPTIONS
    custEPTs    nat,inline

`/etc/shorewall/action.custEPTs`:

    #ACTION         SOURCE          DEST            PROTO   PORT
    SNAT($GW_IP)    { proto=udp port=1146 }
    SNAT($GW_IP)    { proto=tcp port=1156,7221,21000 }

`/etc/shorewall/snat`:

    ACTION          SOURCE          DEST            PROTO   PORT
    custEPTs  { source=$EPT_LIST dest=$IF_NET:$EPT_SERVERS }

More effeciently:

`/etc/shorewall/actions`:

    #ACTION     OPTIONS
    custEPTs    nat

`/etc/shorewall/action.custEPTs`:

    #ACTION         SOURCE          DEST            PROTO   PORT
    SNAT($GW_IP)    { proto=udp port=1146 }
    SNAT($GW_IP)    { proto=tcp port=1156,7221,21000 }

`/etc/shorewall/snat`:

    ACTION          SOURCE          DEST            PROTO   PORT
    custEPT  { source=$EPT_LIST dest=$IF_NET:$EPT_SERVERS }
