<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

# Overview of Shorewall Macros?

Shorewall macros allow a symbolic name to be associated with a series of one or more iptables rules. The symbolic name may appear in the ACTION column of an `/etc/shorewall/rules` file entry and in the TARGET column of an action in which case, the traffic matching that rules file entry will be passed to the series of iptables rules named by the macro.

Macros can be thought of as templates. When a macro is invoked in an `/etc/shorewall/rules` entry, it may be qualified by a logging specification (log level and optionally a log tag). The presence of the log level/tag causes a modified series of rules to be generated in which each packet/rule match within the macro causes a log message to be generated.

There are two types of Shorewall macros:

1.  Standard Macros. These macros are released as part of Shorewall. They are defined in macro.\* files in `/usr/share/shorewall`. Each `macro.*` file has a comment at the beginning of the file that describes what the macro does. As an example, here is the definition of the SMB standard macro.

        #
        # Shorewall -- /usr/share/shorewall/macro.SMB
        #
        # This macro handles Microsoft SMB traffic. You need to invoke
        # this macro in both directions.  Beware!  This rule opens a lot
        # of ports, and could possibly be used to compromise your firewall
        # if not used with care.  You should only allow SMB traffic
        # between hosts you fully trust.
        #
        ######################################################################################
        #TARGET  SOURCE  DEST    PROTO   DPORT   SPORT   ORIGDEST        RATE    USER
        PARAM    -       -       udp     135,445
        PARAM    -       -       udp     137:139
        PARAM    -       -       udp     1024:   137
        PARAM    -       -       tcp     135,139,445

    If you wish to modify one of the standard macros, do not modify the definition in `/usr/share/shorewal`l. Rather, copy the file to `/etc/shorewall` (or somewhere else on your CONFIG_PATH) and modify the copy.

2.  You can see a list of the Standard Macros in your version of Shorewall using the `shorewall show macros` command. You can see the contents of the file macro.\<name\> by typing `shorewall show macro name`.

3.  User-defined Macros. These macros are created by end-users. They are defined in macro.\* files in /etc/shorewall or in another directory listed in your CONFIG_PATH (defined in [/etc/shorewall/shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)).

Most Standard Macros are parameterized. That means that you specify what you want to do (ACCEPT, DROP, REJECT, etc.) when you invoke the macro. The SMB macro shown above is parameterized (note PARAM in the TARGET column).

When invoking a parameterized macro, you follow the name of the macro with the action that you want to substitute for PARAM enclosed in parentheses.

Example:

> /etc/shorewall/rules:
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT
>
>     SMB(ACCEPT)     loc             $FW
>
> The above is equivalent to coding the following series of rules:
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT
>
>     ACCEPT          loc             $FW             udp     135,445
>     ACCEPT          loc             $FW             udp     137:139
>     ACCEPT          loc             $FW             udp     1024:   137
>     ACCEPT          loc             $FW             tcp     135,139,445

Logging is covered in [a following section](#Logging). The other columns are treated as follows:

SOURCE and DEST  
If a value other than "-" appears in both the macro body and in the invocation of the macro, then the value in the invocation is examined and the appropriate action is taken. If the value in the invocation appears to be an address (IP or MAC) or the name of an ipset, then it is placed after the value in the macro body. Otherwise, it is placed before the value in the macro body.

Example 1:

> /etc/shorewall/macro.SMTP
>
>     #ACTION SOURCE  DEST    PROTO   DPORT
>     PARAM   -       loc     tcp     25
>
> /etc/shorewall/rules (Shorewall 4.0):
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT
>     SMTP(DNAT):info net             192.168.1.5
>
> /etc/shorewall/rules (Shorewall 4.2.0 and later):
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT
>     SMTP(DNAT):info net             192.168.1.5
>
> This would be equivalent to coding the following directly in /etc/shorewall/rules
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT
>     DNAT:info       net             loc:192.168.1.5 tcp     25

Example 2:

> /etc/shorewall/macro.SMTP
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT
>     PARAM           -               192.168.1.5     tcp     25
>
> /etc/shorewall/rules
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT
>     SMTP(DNAT):info net             loc
>
> This would be equivalent to coding the following directly in /etc/shorewall/rules
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT
>     DNAT:info       net             loc:192.168.1.5 tcp     25

You may also specify SOURCE or DEST in the SOURCE and DEST columns. This allows you to define macros that work in both directions.

Example 3:

> `/etc/shorewall/macro.SMBBI` (Note: there is already a standard macro like this released as part of Shorewall):
>
>     #ACTION SOURCE  DEST    PROTO   DPORT   SPORT   ORIGDEST        RATE    USER
>     PARAM   -       -       udp     135,445
>     PARAM   -       -       udp     137:139
>     PARAM   -       -       udp     1024:   137
>     PARAM   -       -       tcp     135,139,445
>     PARAM   DEST    SOURCE  udp     135,445
>     PARAM   DEST    SOURCE  udp     137:139
>     PARAM   DEST    SOURCE  udp     1024:   137
>     PARAM   DEST    SOURCE  tcp     135,139,445
>
> /etc/shorewall/rules:
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT
>
>     SMBBI(ACCEPT)   loc             $FW
>
> This would be equivalent to coding the following directly in /etc/shorewall/rules
>
>     #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT
>
>     ACCEPT          loc             $FW             udp     135,445
>     ACCEPT          loc             $FW             udp     137:139
>     ACCEPT          loc             $FW             udp     1024:   137
>     ACCEPT          loc             $FW             tcp     135,139,445
>
>     ACCEPT          $FW             loc             udp     135,445
>     ACCEPT          $FW             loc             udp     137:139
>     ACCEPT          $FW             loc             udp     1024:   137
>     ACCEPT          $FW             loc             tcp     135,139,445

Remaining columns  
Any value in the invocation replaces the value in the rule in the macro.

# Defining your own Macros

To define a new macro:

1.  Macro names must be valid shell variable names ((must begin with a letter and be composed of letters, digits and underscore characters) as well as valid Netfilter chain names.

2.  Copy /usr/share/shorewall/macro.template to `/etc/shorewall/macro.MacroName` (for example, if your new macro name is “Foo” then copy `/usr/share/shorewall/macro.template` to `/etc/shorewall/macro.Foo`).

3.  Now modify the new file to define the new macro.

## Shorewall 5.0.0 and Later

The columns in a macro file are the same as those in [shorewall-rules(5)](https://shorewall.org/manpages/shorewall-rules.html).

## Shorewall 4.4.16 and Later

Beginning with Shorewall 4.4.16, the columns in macro.template are the same as those in shorewall-rules (5). The first non-commentary line in the template must be

    FORMAT 2

Beginning with Shorewall 4.5.11, the preferred format is as shown below, and the above format is deprecated.

    ?FORMAT 2

There are no restrictions regarding the ACTIONs that can be performed in a macro.

Beginning with Shorewall 4.5.10, macros may also be used as [default actions](Actions.md#Default).

    DEFAULT def

where \<def\> is the default value for PARAM

## Shorewall 4.4.15 and Earlier

Before 4.4.16, columns in the macro.template file were as follows:

- ACTION - ACCEPT, DROP, REJECT, DNAT, DNAT-, REDIRECT, CONTINUE, LOG, QUEUE, PARAM or an action name. Note that a macro may not invoke another macro.

  ACCEPT - allow the connection request
  ACCEPT+ - like ACCEPT but also excludes the connection from any subsequent DNAT\[-\] or REDIRECT\[-\] rules.
  NONAT - Excludes the connection from any subsequent DNAT\[-\] or REDIRECT\[-\] rules but doesn't generate a rule to accept the traffic.
  DROP - ignore the request
  REJECT - disallow the request and return an icmp unreachable or an RST packet.
  DNAT - Forward the request to another address (and optionally another port).
  DNAT- - Advanced users only. Like DNAT but only generates the DNAT iptables rule and not the companion ACCEPT rule.
  SAME - Similar to DNAT except that the port may not be remapped and when multiple server addresses are listed, all requests from a given remote system go to the same server.
  SAME- - Advanced users only. Like SAME but only generates the SAME iptables rule and not the companion ACCEPT rule.
  REDIRECT - Redirect the request to a local port on the firewall.
  REDIRECT- - Advanced users only. Like REDIRECT but only generates the REDIRECT iptables rule and not the companion ACCEPT rule.
  CONTINUE - (For experts only). Do not process any of the following rules for this (source zone,destination zone). If The source and/or destination If the address falls into a zone defined later in /etc/shorewall/zones, this connection request will be passed to the rules defined for that (those) zone(s).
  LOG - Simply log the packet and continue.
  QUEUE - Queue the packet to a user-space application such as ftwall (http://p2pwall.sf.net).
  The ACTION may optionally be followed by ":" and a syslog log level (e.g, REJECT:info or DNAT:debug). This causes the packet to be logged at the specified level.

- SOURCE - Source hosts to which the rule applies. A comma-separated list of subnets and/or hosts. Hosts may be specified by IP or MAC address; mac addresses must begin with “~” and must use “-” as a separator.

  Alternatively, clients may be specified by interface name. For example, eth1 specifies a client that communicates with the firewall system through eth1. This may be optionally followed by another colon (“:”) and an IP/MAC/subnet address as described above (e.g. eth1:192.168.1.5).

  May also contain 'DEST' as described above.

- DEST - Location of Server. Same as above with the exception that MAC addresses are not allowed.

  Unlike in the SOURCE column, you may specify a range of up to 256 IP addresses using the syntax \<*first ip*\>-\<*last ip*\>.

  May also contain 'SOURCE' as described above.

- PROTO - Protocol - Must be “tcp”, “udp”, “icmp”, a number, or “all”.

- DEST PORT(S) - Destination Ports. A comma-separated list of Port names (from `/etc/services`), port numbers or port ranges; if the protocol is “icmp”, this column is interpreted as the destination icmp-type(s).

  A port range is expressed as \<*low port*\>:\<*high port*\>.

  This column is ignored if PROTOCOL = all but must be entered if any of the following fields are supplied. In that case, it is suggested that this field contain “-”.

  If your kernel contains multi-port match support, then only a single Netfilter rule will be generated if in this list and in the CLIENT PORT(S) list below:

  1.  There are 15 or less ports listed.

  2.  No port ranges are included.

  Otherwise, a separate rule will be generated for each port.

- SOURCE PORT(S) - Port(s) used by the client. If omitted, any source port is acceptable. Specified as a comma-separated list of port names, port numbers or port ranges.

  If you don't want to restrict client ports but need to specify an ADDRESS in the next column, then place "-" in this column.

  If your kernel contains multi-port match support, then only a single Netfilter rule will be generated if in this list and in the DEST PORT(S) list above:

  1.  There are 15 or less ports listed.

  2.  No port ranges are included.

  Otherwise, a separate rule will be generated for each port.

- ORIGDEST (Shorewall-perl 4.2.0 and later)

  To use this column, you must include 'FORMAT 2' as the first non-comment line in your macro file.

  If ACTION is DNAT\[-\] or REDIRECT\[-\] then if this column is included and is different from the IP address given in the DEST column, then connections destined for that address will be forwarded to the IP and port specified in the DEST column.

  A comma-separated list of addresses may also be used. This is most useful with the REDIRECT target where you want to redirect traffic destined for particular set of hosts. Finally, if the list of addresses begins with "!" (exclusion) then the rule will be followed only if the original destination address in the connection request does not match any of the addresses listed.

  For other actions, this column may be included and may contain one or more addresses (host or network) separated by commas. Address ranges are not allowed. When this column is supplied, rules are generated that require that the original destination address matches one of the listed addresses. This feature is most useful when you want to generate a filter rule that corresponds to a DNAT- or REDIRECT- rule. In this usage, the list of addresses should not begin with "!".

  It is also possible to specify a set of addresses then exclude part of those addresses. For example, 192.168.1.0/24!192.168.1.16/28 specifies the addresses 192.168.1.0-182.168.1.15 and 192.168.1.32-192.168.1.255. See [shorewall-exclusion](https://shorewall.org/manpages/shorewall-exclusion.html)(5).

  See [http://shorewall.org/PortKnocking.html](https://shorewall.org/PortKnocking.html) for an example of using an entry in this column with a user-defined action rule.

- RATE LIMIT - You may rate-limit the rule by placing a value in this column:

           <rate>/<interval>[:<burst>]

  where \<*rate*\> is the number of connections per \<*interval*\> (“sec” or “min”) and \<*burst*\> is the largest burst permitted. If no \<*burst*\> is given, a value of 5 is assumed. There may be no whitespace embedded in the specification.

           Example: 10/sec:20

- USER/GROUP - For output rules (those with the firewall as their source), you may control connections based on the effective UID and/or GID of the process requesting the connection. This column can contain any of the following:

  \[!\]\<
  user number
  \>\[:\]
  \[!\]\<
  user name
  \>\[:\]
  \[!\]:\<
  group number
  \>
  \[!\]:\<
  group name
  \>
  \[!\]\<
  user number
  \>:\<
  group number
  \>
  \[!\]\<
  user name
  \>:\<
  group number
  \>
  \[!\]\<
  user inumber
  \>:\<
  group name
  \>
  \[!\]\<
  user name
  \>:\<
  group name
  \>
  \[!\]+\<
  program name
  \> (Note: support for this form was removed from Netfilter in kernel version 2.6.14).

- MARK - (Added in Shorewall-4.4.2) Defines a test on the existing packet or connection mark. The rule will match only if the test returns true. Must be empty or '-' if the macro is to be used within an action.

           [!]value[/mask][:C]

  !  
  Inverts the test (not equal)

  \<value\>  
  Value of the packet or connection mark.

  \<mask\>  
  A mask to be applied to the mark before testing.

  :C  
  Designates a connection mark. If omitted, the \# packet mark's value is tested.

- CONNLIMIT - (Added in Shorewall-4.4.2) Must be empty or '-' if the macro is to be used within an action.

           [!]limit[:mask]

  May be used to limit the number of simultaneous connections from each individual host to limit connections. Requires connlimit match in your kernel and iptables. While the limit is only checked on rules specifying CONNLIMIT, the number of current connections is calculated over all current connections from the SOURCE host. By default, the \<limit\> is applied to each host but can be made to apply to networks of hosts by specifying a \<mask\>. The mask specifies the width of a VLSM mask to be applied to the source address; the number of current connections is then taken over all hosts in the subnet \<source-address\>/\<mask\>. When ! is specified, the rule matches when the number of connection exceeds the limit.

- TIME - (Added in Shorewall-4.4.2) Must be empty or '-' if the macro is to be used within an action.

           <timeelement>[&...]

  \<timeelement\> may be:

  timestart=\<hh\>:\<mm\>\[:\<ss\>\]  
  Defines the starting time of day.

  timestop=\<hh\>:\<mm\>\[:\<ss\>\]  
  Defines the ending time of day.

  utc  
  Times are expressed in Greenwich Mean Time.

  localtz  
  Times are expressed in Local Civil Time (default).

  weekdays=ddd\[,ddd\]...  
  where \<ddd\> is one of `Mon`, `Tue`, `Wed`, `Thu`, `Fri`, `Sat` or `Sun`

  monthdays=dd\[,dd\],...  
  where \<dd\> is an ordinal day of the month

  datestart=\<yyyy\>\[-\<mm\>\[-\<dd\>\[`T`\<hh\>\[:\<mm\>\[:\<ss\>\]\]\]\]\]  
  Defines the starting date and time.

  datestop=\<yyyy\>\[-\<mm\>\[-\<dd\>\[`T`\<hh\>\[:\<mm\>\[:\<ss\>\]\]\]\]\]  
  Defines the ending date and time.

Omitted column entries should be entered using a dash ("-").

Example:

`/etc/shorewall/macro.LogAndAccept`

         LOG:info
         ACCEPT

To use your macro, in `/etc/shorewall/rules` you might do something like:

    #ACTION         SOURCE          DEST            PROTO   DPORT

    LogAndAccept    loc             $FW             tcp     22

# Macros and Logging

Specifying a log level in a rule that invokes a user- or Shorewall-defined action will cause each rule in the macro to be logged with the specified level (and tag).

The extent to which logging of macro rules occur is governed by the following:

1.  When you invoke a macro and specify a log level, only those rules in the macro that have no log level will be changed to log at the level specified at the action invocation.

    Example:

    /etc/shorewall/macro.foo

        #ACTION SOURCE  DEST    PROTO   DPORT
        ACCEPT  -       -       tcp     22
        bar:info

    /etc/shorewall/rules:

        #ACTION         SOURCE          DEST            PROTO   DPORT
        foo:debug       $FW             net

    Logging in the invoked 'foo' macro will be as if foo had been defined as:

        #ACTION         SOURCE  DEST    PROTO   DPORT
        ACCEPT:debug    -       -       tcp     22
        bar:info

2.  If you follow the log level with "!" then logging will be at that level for all rules recursively invoked by the macro.

    Example:

    /etc/shorewall/macro.foo

        #ACTION SOURCE  DEST    PROTO   DPORT
        ACCEPT  -       -       tcp     22
        bar:info

    /etc/shorewall/rules:

        #ACTION         SOURCE  DEST    PROTO   DPORT
        foo:debug!      $FW     net

    Logging in the invoked 'foo' macro will be as if foo had been defined as:

        #ACTION         SOURCE  DEST    PROTO   DPORT
        ACCEPT:debug    -       -       tcp     22
        bar:debug

# How do I know if I should create an Action or a Macro?

While actions and macros perform similar functions, in any given case you will generally find that one is more appropriate than the other.

1.  Embedded Perl is [much more useful in an action](???) than it is in a macro. So if you need access to iptables features not directly supported by Shorewall then you should use an action.

2.  Macros are expanded in-line while each action (that doesn't specify the inline option) is its own chain. So if there are a lot of rules involved in your new action/macro then it is generally better to use an action than a macro. Only the packets selected when you invoke the action are directed to the corresponding chain. On the other hand, if there are only one or two rules involved in what you want to do then a macro is more efficient.

In-line actions, introduced in Shorewall 4.5.10, are very similar to macros. The advantage of in-line actions is that they may have parameters and can use the other [action variables](../reference/configuration_file_basics.md#ActionVariables).
