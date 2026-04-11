<div class="caution">

**This article applies to Shorewall 5.0 and later. If you are running a version of Shorewall earlier than Shorewall 5.0.0 then please see the documentation for that release.**

</div>

<div class="caution">

If you copy or edit your configuration files on a system running Microsoft Windows, you must run them through [dos2unix](http://www.megaloman.com/~hany/software/hd2u/) before you use them with Shorewall.

</div>

# Introduction

This article offers hints about how to accomplish common tasks with Shorewall. The [Introduction to Shorewall](../concepts/Introduction.md) is required reading for being able to use this article effectively. For information about setting up your first Shorewall-based firewall, see the [Quickstart Guides](../concepts/GettingStarted.md).

# Files

- `/etc/shorewall/shorewall.conf` - used to set global firewall parameters.

- `/etc/shorewall/params` - use this file to set shell variables that you will expand in other files. It is always processed by /bin/sh or by the shell specified through SHOREWALL_SHELL in `/etc/shorewall/shorewall.conf.`

- `/etc/shorewall/zones` - partition the firewall's view of the world into zones.

- `/etc/shorewall/policy` - establishes firewall high-level policy.

- `/etc/shorewall/initdone` - An optional Perl script that will be invoked by the Shorewall rules compiler when the compiler has finished it's initialization.

- `/etc/shorewall/interfaces` - describes the interfaces on the firewall system.

- `/etc/shorewall/hosts` - allows defining zones in terms of individual hosts and subnetworks.

- `/etc/shorewall/masq` - directs the firewall where to use many-to-one (dynamic) Network Address Translation (a.k.a. Masquerading) and Source Network Address Translation (SNAT).

- `/etc/shorewall/mangle` - supersedes `/etc/shorewall/tcrules` in Shorewall 4.6.0. Contains rules for packet marking, TTL, TPROXY, etc.

- `/etc/shorewall/rules` - defines rules that are exceptions to the overall policies established in /etc/shorewall/policy.

- `/etc/shorewall/nat` - defines one-to-one NAT rules.

- `/etc/shorewall/proxyarp` - defines use of Proxy ARP.

- `/etc/shorewall/routestopped` - defines hosts accessible when Shorewall is stopped. Superseded in Shorewall 4.6.8 by `/etc/shorewall/stoppedrules`. Not supported in Shorewall 5.0.0 and later versions.

- `/etc/shorewall/tcrules`- The file has a rather unfortunate name because it is used to define marking of packets for later use by both traffic control/shaping and policy routing. This file is superseded by `/etc/shorewall/mangle` in Shorewall 4.6.0. Not supported in Shorewall 5.0.0 and later releases.

- `/etc/shorewall/tos` - defines rules for setting the TOS field in packet headers. Superseded in Shorewall 4.5.1 by the TOS target in `/etc/shorewall/tcrules` (which file has since been superseded by `/etc/shorewall/mangle`). Not supported in Shorewall 5.0.0 and later versions.

- `/etc/shorewall/tunnels` - defines tunnels (VPN) with end-points on the firewall system.

- `/etc/shorewall/blacklist` - Deprecated in favor of `/etc/shorewall/blrules`. Lists blacklisted IP/subnet/MAC addresses. Not supported in Shorewall 5.0.0 and later releases.

- `/etc/shorewall/blrules` — Added in Shorewall 4.5.0. Define blacklisting and whitelisting.

- `/etc/shorewall/init` - commands that you wish to execute at the beginning of a “shorewall start”, "shorewall reload" or “shorewall restart”.

- `/etc/shorewall/start` - commands that you wish to execute near the completion of a “shorewall start”, "shorewall reload" or “shorewall restart”

- `/etc/shorewall/started` - commands that you wish to execute after the completion of a “shorewall start”, "shorewall reload" or “shorewall restart”

- `/etc/shorewall/stop`- commands that you wish to execute at the beginning of a “shorewall stop”.

- `/etc/shorewall/stopped` - commands that you wish to execute at the completion of a “shorewall stop”.

- `/etc/shorewall/ecn` - disable Explicit Congestion Notification (ECN - RFC 3168) to remote hosts or networks.

- `/etc/shorewall/accounting` - define IP traffic accounting rules

- `/etc/shorewall/actions` and `/usr/share/shorewall/action.template` allow user-defined actions.

- `/etc/shorewall/providers` - defines an alternate routing table.

- `/etc/shorewall/rtrules` - Defines routing rules to be used in conjunction with the routing tables defined in `/etc/shorewall/providers`.

- `/etc/shorewall/tcdevices`, `/etc/shorewall/tcclasses`, `/etc/shorewall/tcfilters` - Define complex traffic shaping.

- `/etc/shorewall/tcrules` - Mark or classify traffic for traffic shaping or multiple providers. Deprecated in Shorewall 4.6.0 in favor of `/etc/shorewall/mangle`. Not supported in Shorewall 5.0.0 and later releases.

- `/etc/shorewall/tcinterfaces` and `/etc/shorewall-tcpri` - Define simple traffic shaping.

- `/etc/shorewall/secmarks` - Added in Shorewall 4.4.13. Attach an SELinux context to selected packets.

- `/etc/shorewall/vardir` - Determines the directory where Shorewall maintains its state.

- `/usr/share/shorewall/actions.std` - Actions defined by Shorewall.

- `/usr/share/shorewall/action.*` - Details of actions defined by Shorewall.

- `/usr/share/shorewall/macro.*` - Details of macros defined by Shorewall.

- `/usr/share/shorewall/modules` — Specifies the kernel modules to be loaded during shorewall start/restart (removed in Shorewall 5.2.3).

- `/usr/share/helpers` — Added in Shorewall 4.4.7. Specifies the kernel modules to be loaded during shorewall start/restart when LOAD_HELPERS_ONLY=Yes in `shorewall.conf`.

- `/usr/share/arprules` — Added in Shorewall 4.5.12. Allows specification of arptables rules.

- `/etc/shorewall/mangle` -- Added in Shorewall 4.6.0. Supersedes`/etc/shorewall/tcrules`.

**If you need to change a file in /usr/share/shorewall/, copy it to `/etc/shorewall` and modify the copy**

# Man Pages

Man pages are provided in section 5 for each of the Shorewall configuration files. The name of the page is formed by prefixing the file name with "shorewall-".

Example — To view the manual page for `/etc/shorewall/interfaces`:

    man shorewall-interfaces

The /etc/shorewall/shorewall.conf file is an exception -- the man page for that file is 'shorewall.conf':

    man shorewall.conf

Parts of this and other articles are also available as manpages:

- shorewall-addresses(5)

- shorewall-exclusion(5)

- shorewall-files(5)

- shorewall-ipsets(5)

- shorewall-logging(5)

- shorewall-names(5)

- shorewall-nesting(5)

# Comments

You may place comments in configuration files by making the first non-whitespace character a pound sign (“\#”). You may also place comments at the end of any line, again by delimiting the comment from the rest of the line with a pound sign.

    # This is a comment
    ACCEPT  net     $FW      tcp     www     #This is an end-of-line comment

<div class="important">

If a comment ends with a backslash ("\\), the next line will also be treated as a comment. See [Line Continuation](#Continuation) below.

</div>

# Names

When you define an object in Shorewall ([Zone](https://shorewall.org/manpages/shorewall-zones.html), [Logical Interface](#Logical), [ipsets](../features/ipsets.md), [Actions](../concepts/Actions.md), etc., you give it a name. Shorewall names start with a letter and consist of letters, digits or underscores ("\_"). Except for Zone names, Shorewall does not impose a limit on name length.

When an ipset is referenced, the name must be preceded by a plus sign ("+").

The last character of an interface may also be a plus sign to indicate a wildcard name.

Physical interface names match names shown by 'ip link ls'; if the name includes an at sign ("@"), do not include that character or any character that follows. For example, "sit1@NONE" is referred to as simply 'sit1".

# Zone and Chain Names

For a pair of zones, Shorewall creates two Netfilter chains; one for connections in each direction. The names of these chains are formed by separating the names of the two zones by either "2" or "-".

Example: Traffic from zone A to zone B would go through chain A2B (think "A to B") or "A-B".

In Shorewall 4.6, the default separator is "-" but you can override that by setting ZONE_SEPARATOR="2" in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5).

<div class="note">

Prior to Shorewall 4.6, the default separator was "2".

</div>

Zones themselves have names that begin with a letter and are composed of letters, numerals, and "\_". The maximum length of a name is dependent on the setting of LOGFORMAT in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5). See [shorewall-zones](https://shorewall.org/manpages/shorewall-zones.html) (5) for details.

# Capabilities

Shorewall probes your system to determine the features that it supports. The result of this probing is a set of capabilities. This probing is normally done each time that the compiler is run but can also be done by executing the `shorewall show capabilities` command. Regardless of whether the compiler or the command does the probing, this probing may produce error messages in your system log. These log messages are to be expected and do not represent a problem; they merely indicate that capabilities that are being probed are not supported on your system.

Probing may be suppressed by using a capabilities file. A capabilities file may be generated using this command:

    shorewall show -f capabilities > /etc/shorewall/capabilities

<div class="important">

If you use a capabilities file, be sure to regenerate it after you have performed a Shorewall upgrade to ensure that all current capabilities have been recorded in your file.

</div>

# "Blank" Columns

If you don't want to supply a value in a column but want to supply a value in a following column, simply enter '-' to make the column appear empty.

Example:

    #INTERFACE         BROADCAST            OPTIONS
    br0                -                    routeback

# Line Continuation

You may continue lines in the configuration files using the usual backslash (“\\”) followed immediately by a new line character (Enter key).

    ACCEPT  net     $FW      tcp \↵
    smtp,www,pop3,imap  #Services running on the firewall

In certain cases, leading white space is ignored in continuation lines:

1.  The continued line ends with a colon (":")

2.  The continued line ends with a comma (",")

<div class="important">

What follows does NOT apply to [shorewall-params(5)](https://shorewall.org/manpages/shorewall-params.html) and [shorewall.conf(5)](https://shorewall.org/manpages/shorewall.conf.html).

</div>

Example (`/etc/shorewall/rules`):

    #ACTION     SOURCE          DEST            PROTO           DPORT
    ACCEPT      net:\
                206.124.146.177,\
                206.124.146.178,\
                206.124.146.180\
                                dmz             tcp             873

The leading white space on the first through third continuation lines is ignored so the SOURCE column effectively contains "net:206.124.146.177,206.124.147.178,206.124.146.180". Because the third continuation line does not end with a comma or colon, the leading white space in the last line is not ignored.

<div class="important">

A trailing backslash is not ignored in a comment. So the continued rule above can be commented out with a single '#' as follows:

    #ACTION     SOURCE          DEST            PROTO           DPORT
    #ACCEPT     net:\
                206.124.146.177,\
                206.124.146.178,\
                206.124.146.180\
                                dmz             tcp             873

</div>

# Alternate Specification of Column Values - Shorewall 4.4.24 and Later

Some of the configuration files now have a large number of columns. That makes it awkward to specify a value for one of the right-most columns as you must have the correct number of intervening '-' columns.

This problem is addressed by allowing column values to be specified as \<column-name\>/\<value\> pairs.

There is considerable flexibility in how you specify the pairs:

- At any point, you can enter a left curly bracket ('{') followed by one or more specifications of the following forms:

  column-name
  =
  value
  column-name
  =
  \>value
  column-name
  :
  value
  The pairs must be followed by a right curly bracket ("}").

  The value may optionally be enclosed in double quotes.

  The pairs must be separated by white space, but you can add a comma adjacent to the \<values\> for readability as in:

  { proto=\>udp, dport=1024 }

- You can also separate the pairs from columns by using a semicolon:

  ; proto:udp, dport:1024
  <div class="important">

  This form is incompatible with INLINE_MATCHES=Yes. See the INLINE_MATCHES option in [shorewall.conf(5)](https://shorewall.org/manpages/shorewall.conf.html), if you are running a version of Shorewall earlier than 5.0..

  </div>

In Shorewall 5.0.3, the sample configuration files and the man pages were updated to use the same column names in both the column headings and in the alternate specification format. The following table shows the column names for each of the table-oriented configuration files.

<div class="note">

Column names are **case-insensitive**.

</div>

|                       |                                                                                                                                                                                         |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **File**              | **Column names**                                                                                                                                                                        |
| accounting            | action,chain, source, dest, proto, dport, sport, user, mark, ipsec, headers                                                                                                             |
| conntrack             | action,source,dest,proto,dport,sport,user,switch                                                                                                                                        |
| blacklist             | networks,proto,port,options                                                                                                                                                             |
| blrules               | action,source,dest,proto,dport,sport,origdest,rate,user,mark,connlimit,time,headers,switch,helper                                                                                       |
| ecn                   | interface,hosts. Beginning with Shorewall 4.5.4, 'host' is a synonym for 'hosts'.                                                                                                       |
| hosts                 | zone,hosts,options. Beginning with Shorewall 4.5.4, 'host' is a synonym for 'hosts'.                                                                                                    |
| interfaces            | zone,interface,broadcast,options                                                                                                                                                        |
| maclist               | disposition,interface,mac,addresses                                                                                                                                                     |
| mangle                | action,source,dest,proto,dport,sport,user,test,length,tos,connbytes,helper,headers,probability,dscp,switch                                                                              |
| masq                  | interface,source,address,proto,port,ipsec,mark,user,switch                                                                                                                              |
| nat                   | external,interface,internal,allints,local                                                                                                                                               |
| netmap                | type,net1,interface,net2,net3,proto,dport,sport                                                                                                                                         |
| notrack               | source,dest,proto,dport,sport,user                                                                                                                                                      |
| policy                | source,dest,policy,loglevel,limit,connlimit                                                                                                                                             |
| providers             | table,number,mark,duplicate,interface,gateway,options,copy                                                                                                                              |
| proxyarp and proxyndp | address,interface,external,haveroute,persistent                                                                                                                                         |
| rtrules               | source,dest,provider,priority                                                                                                                                                           |
| routes                | provider,dest,gateway,device                                                                                                                                                            |
| routestopped          | interface,hosts,options,proto,dport,sport                                                                                                                                               |
| rules                 | action,source,dest,proto,dport,sport,origdest,rate,user,mark,connlimit,time,headers,switch,helper                                                                                       |
| secmarks              | secmark,chain,source,dest,proto,dport,sport,user,mark                                                                                                                                   |
| snat                  | action,source,dest,proto,port,sport,ipsec,mark,user,switch,origdest,probability (Note: 'port' may be specified as 'dport', beginning with Shorewall 5.2.6).                             |
| tcclasses             | interface,mark,rate,ceil,prio,options                                                                                                                                                   |
| tcdevices             | interface,in_bandwidth,out_bandwidth,options,redirect                                                                                                                                   |
| tcfilters             | class,source,dest,proto,dport,sport,tos,length                                                                                                                                          |
| tcinterfaces          | interface,type,in_bandwidth,out_bandwidth                                                                                                                                               |
| tcpri                 | band,proto,port,address,interface,helper                                                                                                                                                |
| tcrules               | mark,source,dest,proto,dport,sport,user,test,length,tos,connbytes,helper,headers. Beginning with Shorewall 4.5.3, 'action' is a synonym for 'mark'.                                     |
| tos                   | source,dest,proto,dport,sport,tos,mark                                                                                                                                                  |
| tunnels               | type,zone,gateway,gateway_zone. Beginning with Shorewall 4.5.3, 'gateways' is a synonym for 'gateway'. Beginning with Shorewall 4.5.4, 'gateway_zones' is a synonym for 'gateway_zone'. |
| zones                 | zone,type,options,in_options,out_options                                                                                                                                                |

Example (rules file):

    #ACTION         SOURCE            DEST            PROTO   DPORT
    DNAT            net               loc:10.0.0.1    tcp     80    ; mark="88"

Here's the same line in several equivalent formats:

    { action=>DNAT, source=>net, dest=>loc:10.0.0.1, proto=>tcp, dport=>80, mark=>88 }
    ; action:"DNAT" source:"net"  dest:"loc:10.0.0.1" proto:"tcp" dport:"80" mark:"88"
    DNAT { source=net dest=loc:10.0.0.1 proto=tcp dport=80 mark=88 }

Beginning with Shorewall 5.0.11, ip\[6\]table comments can be attached to individual rules using the `comment` keyword.

Example from the rules file:

            ACCEPT net $FW { proto=tcp, dport=22, comment="Accept \"SSH\"" }

As shown in that example, when the comment contains whitespace, it must be enclosed in double quotes and any embedded double quotes must be escaped using a backslash ("\\).

# Using Netfilter Features not Directly Supported by Shorewall

Shorewall doesn't contain built-in support for all ip\[6\]tables targets and matches. Nevertheless, you can still use the unsupported ip\[6\]tables features through several Shorewall facilities.

INLINE  
INLINE, added in Shorewall 4. is available in the mangle, snat (masq) and rules files and allows you to specify ip\[6\]table text following two semicolons to the right of the column-oriented specifications.

INLINE takes one optional parameter which, if present, must be a valid entry for the first column of the file. If the parameter is omitted, then you can specify the target of the rule in the text.

Examples from the rules file:

    #ACTION              SOURCE           DEST

    ?COMMENT Drop DNS Amplification Attack Packets
    INLINE(DROP):info    net              $FW   udp     53   ;; -m u32 --u32 "0>>22&0x3C\@8&0xffff=0x0100 && 0>>22&0x3C\@12&0xffff0000=0x00010000"
    ?COMMENT

    ?COMMENT Rule generated by the IfEvent action
    INLINE               net              $FW ;; -m recent --rcheck 10 --hitcount 5 --name SSH -s 1.2.3.4 -j MARK --or-mark 0x4000
    ?COMMENT

IPTABLES and IP6TABLES  
These are very similar to INLINE. The difference is that the parameter to IPTABLES and IP6TABLES is the ip\[6\]tables target of the Rule rather than a Shorewall-defined action or target.

Example from the mangle file:

    IPTABLES(MARK --set-mark 0x4):P eth0 1.2.3.4

Inline Matches  
In Shorewall 4.6.0 and later, setting INLINE_MATCHES=Yes in shorewall\[6\].conf allows you to include ip\[6\]tables matches following a semicolon on any rule in the mangle, masq and rules files. Note that this is incompatible with the Alternate Input form that uses a semicolon to delimit column-oriented specifications from column=value specifications. In Shorewall 5.0.0 and later, inline matches are allowed in mangle, masq and rules following two adjacent semicolons (";;"). If alternate input is present, the adjacent semicolons should follow that input. In Shorewall 5.2.2, this support was extended to the conntrack file.

<div class="caution">

INLINE_MATCHES=Yes is deprecated and is not supported in Shorewall 5.2 and beyond. Use two adjacent semicolons to introduce inline matches.

</div>

Example from the masq file that spits outgoing SNAT between two public IP addresses

    COMB_IF                         !70.90.191.120/29       70.90.191.121 ;; -m statistic --mode random --probability 0.50
    COMB_IF                         !70.90.191.120/29       70.90.191.123

If the first character of the inline matches is a plus sign ("+"), then the matches are processed before the column-oriented input in the rule. That is required when specifying additional TCP protocol parameters.

Example from action.TCPFlags:

    DROP     -      -      ;;+ -p 6 --tcp-flags ALL FIN,URG,PSH

# Addresses

In both Shorewall and Shorewall6, there are two basic types of addresses:

Host Address  
This address type refer to a single host.

In IPv4, the format is *i.j.k.l* where *i* through *l* are decimal numbers between 1 and 255.

In IPv6, the format is *a:b:c:d:e:f:g:h* where *a* through *h* consist of 1 to 4 hexidecimal digits (leading zeros may be omitted). a single series of 0 addresses may be omitted. For example 2001:227:e857:1:0:0:0:0:1 may be written 2001:227:e857:1::1.

Network Address  
A network address refers to 1 or more hosts and consists of a host address followed by a slash ("/") and a Variable Length Subnet Mask (VLSM). This is known as Classless Internet Domain Routing (CIDR) notation.

The VLSM is a decimal number. For IPv4, it is in the range 0 through 32. For IPv6, the range is 0 through 128. The number represents the number of leading bits in the address that represent the network address; the remainder of the bits are a host address and are generally given as zero.

Examples:

IPv4: 192.168.1.0/24

IPv6: 2001:227:e857:1:0:0:0:0:1/64

In the Shorewall documentation and manpages, we have tried to make it clear which type of address is accepted in each specific case.

Because Shorewall uses a colon (":") as a separator in many contexts, IPv6 addresses are best written using the standard convention in which the address itself is enclosed in square brackets:

\[2001:227:e857:1::1\]

\[2001:227:e857:1:0:0:0:0:1\]/64

For more information about addressing, see the [Setup Guide](shorewall_setup_guide.md#Addressing).

# Specifying SOURCE and DEST

Entries in Shorewall configuration files often deal with the source (SOURCE) and destination (DEST) of connections and Shorewall implements a uniform way for specifying them.

A SOURCE or DEST consists of one to three parts separated by colons (":"):

1.  ZONE — The name of a zone declared in `/etc/shorewall/zones` or `/etc/shorewall6/zones`. This part is only available in the rules file (`/etc/shorewall/rules`, `/etc/shorewall/blrules`,`/etc/shorewall6/rules` and `/etc/shorewall6/blrules`).

2.  INTERFACE — The name of an interface that matches an entry in `/etc/shorewall/interfaces` (`/etc/shorewall6/interfaces`).

3.  ADDRESS LIST — A list of one or more addresses (host or network) or address ranges, separated by commas. In an IPv6 configuration, this list must be included in square or angled brackets ("\[...\]" or "\<...\>"). The list may have [exclusion](#Exclusion).

Examples.

1.  All hosts in the **net** zone — **net**

2.  Subnet 192.168.1.0/29 in the **loc** zone — **loc:192.168.1.0/29**

3.  All hosts in the net zone connecting through `ppp0` — **net:ppp0**

4.  All hosts interfaced by `eth3` — **eth3**

5.  Subnet 10.0.1.0/24 interfacing through `eth2` — **eth2:10.0.1.0/24**

6.  Host 2002:ce7c:92b4:1:a00:27ff:feb1:46a9 in the **loc** zone — **loc:\[2002:ce7c:92b4:1:a00:27ff:feb1:46a9\]**

7.  The primary IP address of eth0 in the \$FW zone - **\$FW:&eth0** (see [Run-time Address Variables](#Rvariables) below)

8.  All hosts in Vatican City - **net:^VA** (Shorwall 4.5.4 and later - See [this article](ISO-3661.md)).

# INCLUDE Directive

Any configuration file may contain INCLUDE directives. An INCLUDE directive consists of the word INCLUDE followed by a path name and causes the contents of the named file to be logically included into the file containing the INCLUDE. Relative path names given in an INCLUDE directive are resolved using the current CONFIG_PATH setting (see [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5)).

INCLUDE's may be nested to a level of 3 -- further nested INCLUDE directives are ignored with a warning message.

Beginning with Shorewall 4.4.17, the INCLUDE directive may also appear in the following [extension scripts](shorewall_extension_scripts.md):

- clear

- findgw

- init

- isusable

- refresh

- refreshed

- restore

- restored

- start

- started

- stop

- stopped

- tcclear

When used in these scripts, the INCLUDEd files are copied into the compiled firewall script.

<div class="caution">

Prior to Shorewall 4.4.17, if you are using [Shorewall Lite](../features/Shorewall-Lite.md) , it is not advisable to use INCLUDE in the `params` file in an export directory if you set EXPORTPARAMS=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5). If you do that, you must ensure that the included file is also present on the firewall system's `/etc/shorewall-lite/` directory.

If you only need the `params` file at compile time, you can set EXPORTPARAMS=No in `shorewall.conf`. That prevents the `params` file from being copied into the compiled script. With EXPORTPARAMS=No, it is perfectly okay to use INCLUDE in the `params` file. Note that with Shorewall 4.4.17 and later:

- The variables set at compile time are available at run-time even with EXPORTPARAMS=No.

- The INCLUDE directive in the `params` file is processed at compile time and the INCLUDEd file is copied into the compiled script.

</div>

         shorewall/params.mgmt:
     
            MGMT_SERVERS=1.1.1.1,2.2.2.2,3.3.3.3
             TIME_SERVERS=4.4.4.4
             BACKUP_SERVERS=5.5.5.5
     
            ----- end params.mgmt -----
     
         shorewall/params:
     
            # Shorewall 1.3 /etc/shorewall/params
             [..]
             #######################################
      
             INCLUDE params.mgmt    
       
           # params unique to this host here
           
           ----- end params -----
     
         shorewall/rules.mgmt:
     
           ACCEPT net:$MGMT_SERVERS   $FW                  tcp    22
           ACCEPT $FW                 net:$TIME_SERVERS    udp    123
           ACCEPT $FW                 net:$BACKUP_SERVERS  tcp    22
     
          ----- end rules.mgmt -----
     
         shorewall/rules:
     
          # Shorewall version 1.3 - Rules File
           [..]
           #######################################
      
           INCLUDE rules.mgmt     
       
           # rules unique to this host here
           
     
         ----- end rules -----

You may include multiple files in one command using an [embedded shell command](#Embedded).

Example (include all of the files ending in ".rules" in a directory:):

    gateway:/etc/shorewall # ls rules.d
    ALL.rules  DNAT.rules  FW.rules  NET.rules  REDIRECT.rules  VPN.rules
    gateway:/etc/shorewall # 

/etc/shorewall/rules:

    ?SECTION NEW
    SHELL cat /etc/shorewall/rules.d/*.rules

If you are the sort to put such an entry in your rules file even though /etc/shorewall/rules.d might not exist or might be empty, then you probably want:

    ?SECTION NEW
    SHELL cat /etc/shorewall/rules.d/*.rules 2> /dev/null || true

Beginning with Shorewall 4.5.2, in files other than `/etc/shorewall/params` and `/etc/shorewall/conf`, INCLUDE may be immediately preceded with '?' to signal that the line is a compiler directive and not configuration data.

Example:

    ?INCLUDE common.rules

# ?FORMAT Directive

A number of configuration files support multiple formats. Prior to Shorewall 4.5.11, the format was specified by a line having 'FORMAT' as the first token. This requires each of the file processors to handle FORMAT separately.

In Shorewall 4.5.11, the ?FORMAT directive was created to centralize processing of FORMAT directives. The old entries, while still supported in Shorewall 4.5-4.6, are now deprecated. They are no longer supported in Shorewall 5.0 and later versions.

The ?FORMAT directive is as follows:

?FORMAT \<format\>  
Where format is an integer. In all cases, the default format is 1. The following table shows the files that have different formats and the supported formats for each.

|                          |            |
|--------------------------|------------|
| FILE                     | FORMATS    |
| action files (action.\*) | 1 and 2    |
| conntrack                | 1, 2 and 3 |
| interfaces               | 1 and 2    |
| macro files (macro.\*)   | 1 and 2    |
| tcrules                  | 1 and 2    |

# ?COMMENT Directive

A number of files allow attaching comments to generated Netfilter rules:

accounting

action

.\* files

blrules

conntrack

macro

.\* files

snat

nat

rules

secmarks

tcrules

tunnels

Prior to Shorewall 4.5.11, comments were specified by a line having COMMENT as the first token. The remainder of the line is treated as a comment to be attached to rules.

In Shorewall 4.5.11, the ?COMMENT directive was created to centralize processing of COMMENT directives. The old entries, while still supported in Shorewall 4.5 and 4.6, are now deprecated. They are no longer supported in Shorewall 5.0 and later versions.

Use of this directive requires Comment support in your kernel and iptables - see the output of `shorewall show capabilities`.

The ?COMMENT directive is as follows:

?COMMENT \[ \<comment\> \]  
If \<comment\> is present, it will appear enclosed in /\*....\*/ in the output of the `shorewall show`and `shorewall dump` commands. If no \<comment\> is present, the rules generated by following entries will not have comments attached.

Example (`/etc/shorewall/rules`):

    ?COMMENT Stop NETBIOS noise

    REJECT          loc                             net                     tcp     137,445
    REJECT          loc                             net                     udp     137:139

    ?COMMENT Stop my idiotic work laptop from sending to the net with an HP source/dest IP address

    DROP            loc:!192.168.0.0/22             net

    ?COMMENT

Here's the corresponding output from `/sbin/shorewall-lite`:

    gateway:~ # shorewall-lite show loc-net
    Shorewall Lite 4.3.3 Chains loc2net at gateway - Mon Oct 16 15:04:52 PDT 2008

    Counters reset Mon Oct 16 14:52:17 PDT 2006

    Chain loc-net (1 references)
     pkts bytes target     prot opt in     out     source               destination
        0     0 LOG        tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           tcp dpt:25 LOG flags 0 level 6 prefix `FW:loc2net:REJECT:'
        0     0 reject     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           tcp dpt:25
        0     0 LOG        udp  --  *      *       0.0.0.0/0            0.0.0.0/0           udp dpts:1025:1031 LOG flags 0 level 6 prefix `FW:loc2net:REJECT:'
        0     0 reject     udp  --  *      *       0.0.0.0/0            0.0.0.0/0           udp dpts:1025:1031
        0     0 reject     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           multiport dports 137,445 /* Stop NETBIOS noise */
        0     0 reject     udp  --  *      *       0.0.0.0/0            0.0.0.0/0           udp dpts:137:139 /* Stop NETBIOS noise */
        0     0 DROP       all  --  *      *      !192.168.0.0/22       0.0.0.0/0           /* Stop my idiotic work laptop from sending to the net with an HP source/dest IP address */
        5   316 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0
    gateway:~ #

?COMMENT lines in macro files work somewhat differently from other files. ?COMMENT lines in macros are ignored if COMMENT support is not available or if there was a COMMENT in use when the top-level macro was invoked. This allows the following:

`/usr/share/shorewall/macro.SSH`:

    #ACTION SOURCE DEST  PROTO DPORT   SPORT   RATE  USER
    ?COMMENT SSH
    PARAM   -      -     tcp   22 

`/etc/shorewall/rules`:

    ?COMMENT Allow SSH from home
    SSH(ACCEPT)    net:$MYIP      $FW
    ?COMMENT

The comment line in macro.SSH will not override the ?COMMENT line in the rules file and the generated rule will show **/\* Allow SSH from home \*/** when displayed through the Shorewall show and dump commands.

Beginning with Shorewall 5.0.11, the [alternate input format ](#Pairs)allows attaching comments to individual rules in the files listed above.

# CONFIG_PATH

The CONFIG_PATH option in shorewall.conf determines where the compiler searches for configuration files. The default setting is CONFIG_PATH=/etc/shorewall:/usr/share/shorewall which means that the compiler first looks in /etc/shorewall and if it doesn't find the file, it then looks in /usr/share/shorewall.

You can change this setting to have the compiler look in different places. For example, if you want to put your own versions of standard macros in /etc/shorewall/Macros, then you could set CONFIG_PATH=/etc/shorewall:/etc/shorewall/Macros:/usr/share/shorewall and the compiler will use your versions rather than the standard ones.

# Using Shell Variables

You may use the `/etc/shorewall/params` file to set shell variables that you can then use in the other configuration files.

It is suggested that variable names begin with an upper case letter to distinguish them from variables used internally within the Shorewall programs

The following variable names must be avoided. Those in **bold font** must be avoided in all Shorewall versions; those in regular font must be avoided in versions prior to 4.4.8.

Any option from

shorewall.conf

\(5\)

COMMAND

CONFDIR

DEBUG

ECHO_E

ECHO_N

EXPORT

FAST

FILEMODE

HOSTNAME

IPT_OPTIONS

NOROUTES

PREVIEW

PRODUCT

PROFILE

PURGE

RECOVERING

RESTOREPATH

RING_BELL

SHAREDIR

Any name beginning with SHOREWALL\_ or SW\_

STOPPING

TEST

TIMESTAMP

USE_VERBOSITY

VARDIR

VARLIB

VERBOSE

VERBOSE_OFFSET

VERSION

Example:

>         /etc/shorewall/params
>      
>             NET_IF=eth0
>             NET_OPTIONS=routefilter,routefilter
>      
>         /etc/shorewall/interfaces record:
>
>             net $NET_IF $NET_OPTIONS
>      
>         The result will be the same as if the record had been written
>      
>             net eth0 routefilter,routefilter
>      

Variables may be used anywhere in the other configuration files.

<div class="note">

If you use "\$FW" on the right side of assignments in the `/etc/shorewall/params` file, you must also set the FW variable in that file.

Example:

    /etc/shorewall/zones:

            #ZONE        TYPE          OPTIONS
            fw           firewall

    /etc/shorewall/params:

            FW=fw
            BLARG=$FW:206.124.146.176

</div>

Because the `/etc/shorewall/params` file is simply sourced into the shell, you can place arbitrary shell code in the file and it will be executed each time that the file is read. Any code included should follow these guidelines:

1.  The code should not have side effects, especially on other shorewall configuration files.

2.  The code should be safe to execute multiple times without producing different results.

3.  Should not depend on where the code is called from.

4.  Should not assume anything about the state of Shorewall.

5.  The names of any functions or variables declared should begin with an upper case letter.

6.  The `/etc/shorewall/params` file is processed by the compiler at compile-time and by the compiled script at run-time. If you have set EXPORTPARAMS=No in `shorewall.conf`, then the `params` file is only processed by the compiler; it is not run by the compiled script. Beginning with Shorewall 4.4.17, the values of the variables set at compile time are available at run time with EXPORTPRARMS=No.

7.  If you are using [Shorewall Lite](../features/Shorewall-Lite.md) and if the `params` script needs to set shell variables based on the configuration of the firewall system, you can use this trick:

        EXT_IP=$(ssh root@firewall "/sbin/shorewall-lite call find_first_interface_address eth0")

    The `shorewall-lite call` command allows you to call interactively any Shorewall function that you can call in an extension script.

    <div class="note">

    Within your configuration files, only the \$VAR and \${VAR} forms of variable expansion are supported. You may not use the more exotic forms supported by the shell (\${VAR:=val}, \${VAR:-val}, ...)

    </div>

Beginning with Shorewall 4.4.27, you may also use options in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5) (e.g., \$BLACKLIST_LOGLEVEL).

<div class="note">

When an option is set to 'No' in shorewall.conf, the corresponding shell variable will be empty.

</div>

<div class="note">

Options that were not set in shorewall.conf will expand to their default value.

</div>

Beginning with Shorewall 4.5.2, configuration files can access variables defined in the [shorewallrc file](Install.md#shorewallrc).

Beginning with Shorewall 4.5.11, variables can be altered by compiler directives.

?SET \<variable value\>  
The \<variable\> can be specified either with or without a leading '\$' to allow using both Perl and Shell variable representation. The \${...} form (e.g. \${foo}) is not allowed.

The \<value\> is a Perl-compatible expression.

<div class="note">

The Shorewall compiler performs variable expansion within the expression. So variables are expanded even when they appear in single quotes.

</div>

<div class="note">

If a variable within the expression can contain a non-numeric value, it is a good idea to enclose it in quotes. Otherwise, the Shorewall compiler has to guess whether to enclose the variable's value in quotes or not.

</div>

?RESET \<variable\>  
Removes the named \<variable\> from the compiler's variable table.

Action variables are read-only and cannot be ?SET (although you can change their values [using embedded Perl](../concepts/Actions.md#Embedded)).

Beginning with Shorewall 4.5.13, [Shorewall Variables](#ShorewallVariables) may be set. When setting a Shorewall Variable, the \<variable\> must include the leading '@' and the @{...} form is not allowed.

# Address Variables

<div class="caution">

Prior to Shorewall 5.0.14, if you use address variables that refer to an optional interface, the `enable` command will not change/insert the rules that use the variable. Therefore, to be completely safe, if you use such address variables then you must follow a successful `enable` command with a `reload` command.

Beginning with Shorewall 5.0.14, if a Shorewall-defined address variable's value has changed since the Netfilter ruleset was instantiated, then a successful `enable` command will automatically reload the ruleset.

</div>

Given that shell variables are expanded at compile time, there is no way to cause such variables to be expanded at run time. Prior to Shorewall 4.4.17, this made it difficult (to impossible) to include dynamic IP addresses in a [Shorewall-lite](../features/Shorewall-Lite.md) configuration.

Version 4.4.17 implemented Run-time address variables. In configuration files, these variables are expressed as an apersand ('&') followed by the logical name of an interface defined in shorewall-interfaces (5). Wildcard interfaces (those ending in '+') are not supported and will cause a compilation error.

Example:  
**&eth0** would represent the primary IP address of eth0.

Beginning with Shorewall 4.5.11, you can define your own address variables by using this syntax:

&{

variable

}

where \<variable\> is a valid shell variable name. The generated script will verify that the \<variable\> contains a valid host or network address, either from the environment or from it being assigned in your *init* [extension script](shorewall_extension_scripts.md), and will raise an error if it does not. In the error case, the state of the firewall will remain unchanged.

Example:

/etc/shorewall/init:

    SMC_ADDR=10.1.10.11

/etc/shorewall/rules:

    test:debug  net:&{SMC_ADDR}        fw

A second form is also available beginning with Shorewall 4.5.11

%{

variable

}

Unlike with the first form, this form does not require the variable to be set. If the variable is empty, the generated script will supply the all-zeros address (0.0.0.0 in IPv4 and :: in IPv6). In most cases, the compiler simply omits rules containing matches on the all-zeros address.

Example:

/etc/shorewall/init:

    SMC_ADDR=10.1.10.11

/etc/shorewall/rules:

    test:debug  net:%{SMC_ADDR}        fw

<div class="important">

For a particular address variable, all references must use the same prefix character ('&' or '%'). Otherwise, the following error message is raised:

ERROR: Mixed required/optional usage of address variable

variable

</div>

Run-time address variables may be used in the SOURCE and DEST column of the following configuration files:

- [shorewall-accounting](https://shorewall.org/manpages/shorewall-accounting.html) (5)

- [Action](../concepts/Actions.md) files

- [shorewall-blrules](https://shorewall.org/manpages/shorewall-blrules.html) (5)

- [Macro](../concepts/Macros.md) files

- [shorewall-mangle](https://shorewall.org/manpages/shorewall-mangle.html) (5)

- [shorewall-nat](https://shorewall.org/manpages/shorewall-nat.html)(5)

- [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5)

They may also appear in the ORIGDEST column of:

- [shorewall-accounting](https://shorewall.org/manpages/shorewall-accounting.html) (5)

- [Macro](../concepts/Macros.md) files

- [Action](../concepts/Actions.md) files

- [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5)

They may also be used as the parameter to SNAT() in [shorewall-snat](https://shorewall.org/manpages/shorewall-snat.html)(5).

For optional interfaces, if the interface is not usable at the time that the firewall starts, one of two approaches are taken, depending on the context:

- the all-zero address will be used (0.0.0.0 in IPv4 and :: in IPv6), resulting in no packets matching the rule (or all packets if used with exclusion).

- the entire rule is omitted from the ruleset.

Beginning with Shorewall 4.5.1, Run-time Gateway Variables in the form of a percent sign ('%') followed by a logical interface name are also supported. These are expanded at run-time to the gateway through the named interface. For optional interfaces, if the interface is not usable at the time that the firewall starts, the nil address will be used (0.0.0.0 in IPv4 and :: in IPv6), resulting in no packets matching the rule. Run-time gateway variables may be used in the SOURCE and DEST columns of the following configuration files:

- [shorewall-accounting](https://shorewall.org/manpages/shorewall-accounting.html) (5)

- [Action](../concepts/Actions.md) files

- [shorewall-blrules](https://shorewall.org/manpages/shorewall-blrules.html) (5)

- [Macro](../concepts/Macros.md) files

- [shorewall-mangle](https://shorewall.org/manpages/shorewall-mangle.html) (5)

- [shorewall-nat](https://shorewall.org/manpages/shorewall-nat.html)(5) (As a qualifier to the INTERFACE).

- [shorewall-routes](https://shorewall.org/manpages/shorewall-routes.html) (5)

- [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5)

Example:  
**%eth0** would represent the IP address of the gateway out of eth0.

If there is no gateway out of the named interface, rules containing the intefaces's run-time gateway variable are omitted.

# Port Variables

Beginning with Shorewall 5.1.5, Run-time Port Variables are supported. These variables have the format %{\<variable\>} and may appear any place that a port number or service name may appear. Like their address-variable counterparts above, Run-time Port Variables are most useful when Shorewall\[6\]-lite is being used.

Example using both Run-time Address and Run-time Port Variables:

/etc/shorewall/init:

         SERVER_PORT=4126
         SERVER_ADDRESS=192.0.44.12

/etc/shorewall/rules:

         ACCEPT         net            dmz:%{SERVER_ADDRESS}           tcp          %{SERVER_PORT}

Rather than assigning a numerical literal to SERVER_PORT in the `init` extension script as shown above, the variable could be assigned a dynamic value based on a database lookup.

<div class="important">

If no value is assigned to a Run-time Port Variable in the `init` extension script, then the value 255 is assumed.

</div>

<div class="caution">

Care must be exercised when using port variables in port ranges. At run-time, the generated script will verify that each port variable is either empty or contains a valid port number or service name. It does not ensure that the low port number in a range is strictly less than the high port number, when either of these is specified as a port variable.

Example: The following definitions will result in an iptables-restore failure during start/restart/reload:

/etc/shorewall/init:

          LOW_PORT=100
          HIGH_PORT=50

/etc/shorewall/rules:

          ACCEPT    net     $FW      tcp      ${LOW_PORT}:${HIGH_PORT}

</div>

# Action Variables

Action variables were introduced in Shorewall 4.4.16 and may be accessed within the body of an [action](../concepts/Actions.md).

Parameter variables  
Parameter variables expand to the value of the corresponding action parameter. *\$1* is the first parameter, *\$2* is the second parameter and so on.

Chain name  
Beginning with Shorewall 4.5.10, \$0 expands to the name of the action chain. Shorewall generates a separate chain for each unique (action,log-level,log-tag,parameters) tupple. The first such chain has the same name as the action itself. Subsequent chains are formed by prepending '%' to the action name and appending a number to insure uniqueness. For an action called 'Action', the chains would be *Action*, *%Action*, *%Action0*, *%Action1* and so on.

# Shorewall Variables

Shorewall Variables were introduced in Shorewall 4.5.11. To insure uniqueness, these variables start with the character @; the name of the variable must be enclosed in {...} when the following character is alphanumeric or is an underscore ("\_"). With the exception of @0 (or it's alias @chain), Shorewall variables may only be used within an action body.

Prior to Shorewall 4.5.13, Shorewall variables are read-only. Beginning with Shorewall 4.5.13, their values may be altered using the ?SET directive.

The Shorewall variables are:

@0 and @chain (@{0} and @{chain})  
Expands to the name of the current chain. Unlike \$0, @0 has all non-alphanumeric characters except underscore removed. Also unlike \$0, @0 may be used in SWITCH columns in configuration files.

@1, @2, ... (@{1}, @{2}, ...  
These are synonyms for the Action parameter variables \$1, \$2, etc.

@loglevel (@{loglevel})  
Expands to the log level specified when the action was invoked.

@logtag (@{logtag})  
Expands to the log tag specified when the action was invoked.

@action(@{action})  
Expands to the name of the action being compiled.

@disposition (@{disposition})  
Added in Shorewall 4.5.13. When a non-inlined action is entered, this variable is set to the empty value. When an inline action is entered, the variable's value is unchanged.

@caller (@{caller})  
Added in Shorewall 4.5.13. Within an action, expands to the name of the chain that invoked the action.

Beginning with Shorewall 4.5.13, the values of @chain and @disposition are used to generated the --log-prefix in logging rules. When either is empty, the historical value is used to generate the --log-prefix.

Within an action body, if a parameter is omitted in a DEFAULTS statement, then the value of the corresponding action and Shorewall variables is '-', while if the parameter is specified as '-' in the parameter list, the value of the action/Shorewall variable is '', if it is expanded before the DEFAULTS statement.

Additionally, when an expression is evaluated, the value 0 evaluates as false, so '?IF @n' and '?IF \$n' fail if the nth parameter is passed with value zero. To make testing of the presense of parameters more efficient and uniform, an new function has been added in Shorewall 5.0.7 for use in ?IF and ?ELSEIF:

?IF \[!\] passed(\<variable\>)

where \<variable\> is an action or Shorewall variable.

'passed(@n)' and 'passed(\$n)' evaluate to true if the nth parameter is not empty and its contents are other than '-'. If '!' is present, the result is inverted.

In this simple form, the expression is evaluated by the compiler without having to invoke the (expensive) Perl exec() function. The 'passed' function may also be used in more complex expressions, but exec() will be invoked to evaluate those expressions.

# Conditional Entries

Beginning with Shorewall 4.5.2, lines in configuration files may be conditionally included or omitted based on the setting of [Shell variables](#Variables).

The general form is:

    ?IF $variable

    <lines to be included if $variable is non-empty and non-zero>

    ?ELSE

    <lines to be omitted if $variable is non-empty and non-zero>

    ?ENDIF

The compiler predefines two special \<variable\>s that may only be used in ?IF lines:

\_\_IPV4  
True if this is an IPv4 compilation

\_\_IPV6  
True if this is an IPv6 compilation.

Unless \<variable\> is one of these pre-defined ones, it is searched for in the following places in the order listed.

- the compiler's environmental variables.

- variables set in `/etc/shorewall/params`.

- options set in `/etc/shorewall/shorewall.conf`.

- options set in the `shorewallrc` file when Shorewall Core was installed.

<div class="important">

Beginning with Shorewall 4.5.11, the compiler's environmental variables are searched last rather than first.

</div>

If the \<variable\> is still not found:

- if it begins with '\_\_', then those leading characters are stripped off.

- the variable is then searched for in the defined capabilities. The current set of capabilities may be obtained by the command `shorewall show capabilities` (the capability names are in parentheses).

If it is not found in any of those places, the \<variable\> is assumed to have a value of 0 (false) in Shorewall versions prior to 4.5.11. In 4.5.11 and later, it is assumed to have the value '' (an empty string, which also evaluates to false).

The setting in `/etc/shorewall/params` may be overridden at runtime, provided the setting in `/etc/shorewall/params` is done like this:

    [ -n "${variable:=0}" ]

or like this:

    [ -n "${variable}" ] || variable=0

Either of those will set variable to 0 if it is not set to a non-empty value in the environment. The setting can be overridden at runtime:

    variable=1 shorewall restart -c # use -c to force recompilation if AUTOMAKE=Yes in /etc/shorewall/shorewall.conf

The ?ELSE may be omitted if there are no lines to be omitted.

The test may also be inverted using '!':

    ?IF ! $variable

    <lines to be omitted if $variable is non-empty and non-zero>

    ?ELSE

    <lines to be included if $variable is non-empty and non-zero>

    ?ENDIF

Conditional entries may be nested but the number of ?IFs must match the number of ?ENDs in any give file. [INCLUDE directives](#INCLUDE) are ignored in omitted lines.

    ?IF $variable1

    <lines to be included if $variable1 is non-empty and non-zero>

       ?IF $variable2

    <lines to be included if $variable1 and $variable2 are non-empty and non-zero>

       ?ELSE

    <lines to be omitted if $variable1 is non-empty and non-zero and if $variable2 is empty or zero>

       ?ENDIF

    <lines to be included if $variable1 is non-empty and non-zero>

    ?ELSE

    <lines to be omitted if $variable is non-empty and non-zero>

    ?ENDIF

Beginning with Shorewall 4.5.6, rather than a simple variable in ?IF directives, Perl-compatible expressions are allowed (after the Shorewall compiler expands all variables, the resulting expression is then evaluated by Perl). Variables in the expressions are as described above.

Example:

    ?IF $BLACKLIST_LOGLEVEL == 6 && ! __LOG_OPTIONS

Additionally, a ?ELSIF directive is supported.

Example:

    ?IF expression-1

    <lines to be included if expression-1 evaluates to true (non-empty and non-zero)

    ?ELSIF expression1-2

    <lines to be included if expression-1 evaluates to false (zero or empty) and expression-2 evaluates to true

    ?ELSIF expression-3

    <lines to be included if expression-1 and expression-2 both evalute to false and expression-3 evalutes to true

    ?ELSE

    <lines to be included if all three expressions evaluate to false.

    ?ENDIF

Beginning in Shorewall 5.0.7, an error can be raised using the ?ERROR directive:

    ?ERROR message

Variables in the message are evaluated and the result appears in a standard Shorewall ERROR: message.

Example from the 5.0.7 action.GlusterFS:

    ?if @1 !~ /^\d+/ || ! @1 || @1 > 1024
        ?error Invalid value for Bricks (@1)
    ?elsif @2 !~ /^[01]$/
        ?error Invalid value for IB (@2)
    ?endif

The above code insures that the first action paramater is a non-zero number \<= 1024 and that the second parameter is either 0 or 1. If 2000 is passed for the first parameter, the following error message is generated:

       ERROR: Invalid value for Bricks (2000) /usr/share/shorewall/action.GlusterFS (line 15)
          from /etc/shorewall/rules (line 45)

In Shorewall 5.0.8, ?WARNING and ?INFO directives were added.

    ?WARNING message
    ?INFO message

?WARNING message produces a standard Shorewall WARNING: message, while ?INFO produces a similar message which is prefaced by INFO: rather than WARNING:. Both write the message to STDERR. The message is also written to the STARTUP_LOG, if any, provided that the command is `start`, `try`, `restart`, `reload`, `refresh`, or one of the `safe`-\* commands.

See the VERBOSE_MESSAGES option in [shorewall.conf(5)](https://shorewall.org/manpages/shorewall.conf.html) for additional information.

In Shorewall 5.1.4, the behavior of ?ERROR, ?WARNING and ?INFO was changed when they appear in an action file. Rather than reporting the action filename and line number, the generated message reports where the action was invoked. For example, the GlusterFS message above was changed to:

       ERROR: Invalid value (2000) for the GlusterFS Bricks argument /etc/shorewall/rules (line 45)

# Embedded Shell and Perl

Earlier versions of Shorewall offered [extension scripts](shorewall_extension_scripts.md) to allow users to extend Shorewall's functionality. Extension scripts were designed to work under the limitations of the Bourne Shell. With the current Perl-based compiler, Embedded scripts offer a richer and more flexible extension capability.

While inline scripts may be written in either Shell or Perl, those written in Perl have a lot more power. They may be used in all configuration files except `/etc/shorewall/params` and `/etc/shorewall/shorewall.conf`.

**Note:**In this section, '\[' and '\]' are meta-characters which indicate that what they enclose is optional and may be omitted.

Single line scripts take one of the following forms:

- \[**?**\]**PERL** \<*perl script*\>

- \[**?**\]**SHELL** \<*shell script*\>

<div class="note">

The optional leading question mark (?) is allowed in Shorewall 4.5.5 and later.

</div>

Shell scripts run in a child shell process and their output is piped back to the compiler which processes that output as if it were embedded at the point of the script.

Example: The following entries in `/etc/shorewall/rules` are equivalent:

    SHELL for z in net loc dmz; do echo "ACCEPT $z fw tcp 22"; done

    ACCEPT net fw tcp 22
    ACCEPT loc fw tcp 22
    ACCEPT dmz fw tcp 22

Perl scripts run in the context of the compiler process using Perl's eval() function. Perl scripts are implicitly prefixed by the following:

    package Shorewall::User;
    use Shorewall::Config ( qw/shorewall/ );

To produce output that will be processed by the compiler as if it were embedded in the file at the point of the script, pass that output to the Shorewall::Config::shorewall() function. The Perl equivalent of the above SHELL script would be:

    PERL for ( qw/net loc dmz/ ) { shorewall "ACCEPT $_ fw tcp 22"; }

A couple of more points should be mentioned:

1.  Compile-time extension scripts are also implicitly prefixed by "package Shorewall::User;".

2.  A **compile** extension script is supported. That script is run early in the compilation process and allows users to load additional modules and to define data and functions for use in subsequent embedded scripts and extension scripts.

3.  [Manual Chains](../concepts/ManualChains.md) may be added in the **compile** extension script..

Multi-line scripts use one of the following forms:

    [?]BEGIN SHELL
    <shell script>
    [?]END [ SHELL ]

    [?]BEGIN PERL [;]
    <perl script>
    [?]END [ PERL ] [;]

<div class="note">

The optional leading question mark (?) is allowed in Shorewall 4.5.5 and later.

</div>

# Using DNS Names

<div class="caution">

I personally recommend strongly against using DNS names in Shorewall configuration files. If you use DNS names and you are called out of bed at 2:00AM because Shorewall won't start as a result of DNS problems then don't say that you were not forewarned.

</div>

Host addresses in Shorewall configuration files may be specified as either IP addresses or DNS Names.

DNS names in iptables rules aren't nearly as useful as they first appear. When a DNS name appears in a rule, the iptables utility resolves the name to one or more IP addresses and inserts those addresses into the rule. So changes in the DNS-\>IP address relationship that occur after the firewall has started have absolutely no effect on the firewall's rule set.

For some sites, using DNS names is very risky. Here's an example:

    teastep@ursa:~$ dig pop.gmail.com

    ; <<>> DiG 9.4.2-P1 <<>> pop.gmail.com
    ;; global options:  printcmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1774
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 7, ADDITIONAL: 0

    ;; QUESTION SECTION:
    ;pop.gmail.com.               IN A

    ;; ANSWER SECTION:
    pop.gmail.com.          300   IN CNAME gmail-pop.l.google.com.
    gmail-pop.l.google.com. 300   IN A     209.85.201.109
    gmail-pop.l.google.com. 300   IN A     209.85.201.111

Note that the TTL is 300 -- 300 seconds is only 5 minutes. So five minutes later, the answer may change!

So this rule may work for five minutes then suddently stop working:

    #ACTION        SOURCE               DEST              PROTO             DPORT
    POP(ACCEPT)     loc                  net:pop.gmail.com

There are two options in [shorewall\[6\].conf(5)](https://shorewall.org/manpages/shorewall.conf.html) that affect the use of DNS names in Shorewall\[6\] config files:

- DEFER_DNS_RESOLUTION - When set to No, DNS names are resolved at compile time; when set to Yes, DNS Names are resolved at runtime.

- AUTOMAKE - When set to Yes, `start`, `restart` and `reload` only result in compilation if one of the files on the CONFIG_PATH has changed since the the last compilation.

So by setting AUTOMAKE=Yes, and DEFER_DNS_RESOLUTION=No, compilation will only take place at boot time if a change had been make to the config but no `restart` or `reload` had taken place. This is clearly spelled out in the shorewall.conf manpage. So with these settings, so long as a 'reload' or 'restart' takes place after the Shorewall configuration is changes, there should be no DNS-related problems at boot time.

<div class="important">

When DEFER_DNS_RESOLUTION=No and AUTOMAKE=Yes and a DNS change makes it necessary to recompile an existing firewall script, the `-c` option must be used with the `reload` or `restart` command to force recompilation.

</div>

If your firewall rules include DNS names then, even if DEFER_DNS_RESOLUTION=No and AUTOMAKE=Yes:

- If your `/etc/resolv.conf`is wrong then your firewall may not start.

- If your `/etc/nsswitch.conf` is wrong then your firewall may not start.

- If your Name Server(s) is(are) down then your firewall may not start.

- If your startup scripts try to start your firewall before starting your DNS server then your firewall may not start.

- Factors totally outside your control (your ISP's router is down for example), can prevent your firewall from starting.

- You must bring up your network interfaces prior to starting your firewall, or the firewall may not start.

Each DNS name must be fully qualified and include a minimum of two periods (although one may be trailing). This restriction is imposed by Shorewall to insure backward compatibility with existing configuration files.

- mail.shorewall.net

- shorewall.net. (note the trailing period).

<!-- -->

- mail (not fully qualified)

- shorewall.net (only one period)

DNS names may not be used as:

- The server address in a DNAT rule (/etc/shorewall/rules file)

- In the ADDRESS column of an entry in /etc/shorewall/masq.

- In the `/etc/shorewall/nat` file.

These restrictions are imposed by Netfilter and not by Shorewall.

# Comma-separated Lists

Comma-separated lists are allowed in a number of contexts within the configuration files. A comma separated list:

- Must not have any embedded white space.+

           Valid:   routefilter,dhcp,arpfilter
           Invalid: routefilter,     dhcp,     arpfilter

- If you use line continuation to break a comma-separated list, the comma must be the last thing on the continued line before '\\ unless the continuation line has no leading white space.

- Entries in a comma-separated list may appear in any order.

# Complementing an Address, Subnet, Protocol or Port List

Where specifying an IP address, a subnet or an interface, you can precede the item with “!” to specify the complement of the item. For example, !192.168.1.4 means “any host but 192.168.1.4”. There must be no white space following the “!”.

Similarly, in columns that specify an IP protocol, you can precede the protocol name or number by "!". For example, !tcp means "any protocol except tcp".

This also works with port lists, providing that the list contains 15 or fewer ports (where a [port range](#Ranges) counts as two ports). For example !ssh,smtp means "any port except 22 and 25".

In Shorewall 4.4.19 and later, icmp type lists are supported but complementing an icmp type list is *not* supported. You may, however, complement a single icmp (icmp6) type.

# Exclusion Lists

Where a comma-separated list of addresses is accepted, an exclusion list may also be included. An exclusion list is a comma-separated list of addresses that begins with "!".

Example:

    !192.168.1.3,192.168.1.12,192.168.1.32/27

The above list refers to "All addresses except 192.168.1.3, 192.168.1.12 and 192.168.1.32-192.168.1.63.

Exclusion lists can also be added after a network address.

Example:

    192.168.1.0/24!192.168.1.3,192.168.1.12,192.168.1.32/27

The above list refers to "All addresses in 192.168.1.0-192.168.1.255 except 192.168.1.3, 192.168.1.12 and 192.168.1.32-192.168.1.63.

# IP Address Ranges

If you kernel and iptables have *iprange* *match* *support*, you may use IP address ranges in Shorewall configuration file entries; IP address ranges have the syntax \<*low IP address*\>-\<*high IP address*\>. Example: 192.168.1.5-192.168.1.12.

To see if your kernel and iptables have the required support, use the `shorewall show capabilities` command:

    >~ shorewall show capabilities
    Shorewall has detected the following iptables/netfilter capabilities:
       ACCOUNT Target (ACCOUNT_TARGET): Not available
       Address Type Match (ADDRTYPE): Available
       Amanda Helper: Available
    ...
       IPMARK Target (IPMARK_TARGET): Not available
       IPP2P Match (IPP2P_MATCH): Not available
       IP range Match(IPRANGE_MATCH): Available <================

# Protocol Number/Names and Port Numbers/Service Names

Unless otherwise specified, when giving a protocol number you can use either an integer or a protocol name from `/etc/protocols`. Similarly, when giving a port number you can use either an integer or a service name from `/etc/services`.

<div class="note">

The rules compiler translates protocol names to protocol numbers and service names to port numbers itself.

</div>

Also, unless otherwise documented, a protocol number/name can be preceded by '!' to specify "All protocols except this one" (e.g., "!tcp").

# Port Ranges

If you need to specify a range of ports, the proper syntax is \<low port number\>:\<high port number\>. For example, if you want to forward the range of tcp ports 4000 through 4100 to local host 192.168.1.3, the entry in /etc/shorewall/rules is:

    #ACTION    SOURCE     DESTINATION     PROTO     DPORT
    DNAT       net        loc:192.168.1.3 tcp       4000:4100

If you omit the low port number, a value of zero is assumed; if you omit the high port number, a value of 65535 is assumed.

Also, unless otherwise documented, a port range can be preceded by '!' to specify "All ports except those in this range" (e.g., "!4000:4100").

Beginning with Shorewall 5.0.14, a hyphen ("-") may also be used to separate the two port numbers; when using service names, the colon must still be used.

    #ACTION    SOURCE     DESTINATION     PROTO     DPORT
    DNAT       net        loc:192.168.1.3 tcp       4000-4100

# Port Lists

In most cases where a port or port range may appear, a comma-separated list of ports or port ranges may also be entered. Shorewall requires the Netfilter **multiport** match capability if ports lists are used (see the output of "**shorewall show capabilities**").

Also, unless otherwise documented, a port list can be preceded by '!' to specify "All ports except these" (e.g., "!80,443").

Prior to Shorewall 4.4.4, port lists appearing in the [shorewall-routestopped](https://shorewall.org/manpages/shorewall-routestopped.html) (5) file may specify no more than 15 ports; port ranges appearing in a list count as two ports each.

# ICMP and ICMP6 Types and Codes

When dealing with ICMP, the DEST PORT specifies the type or type and code. You may specify the numeric type, the numeric type and code separated by a slash (e.g., 3/4) or you may use a type name.

Type names for IPv4 and their corresponding type or type/code are:

    echo-reply'                  => 0
    destination-unreachable      => 3
        network-unreachable      => 3/0
        host-unreachable         => 3/1
    protocol-unreachable         => 3/2
    port-unreachable             => 3/3
    fragmentation-needed         => 3/4
    source-route-failed          => 3/5
    network-unknown              => 3/6
    host-unknown                 => 3/7
    network-prohibited           => 3/9
    host-prohibited              => 3/10
    TOS-network-unreachable      => 3/11
    TOS-host-unreachable         => 3/12
    communication-prohibited     => 3/13
    host-precedence-violation    => 3/14
    precedence-cutoff            => 3/15
    source-quench                => 4
    redirect                     => 5
       network-redirect          => 5/0
       host-redirect             => 5/1
       TOS-network-redirect      => 5/2
       TOS-host-redirect         => 5/3
    echo-request                 => 8
    router-advertisement         => 9
    router-solicitation          => 10
    time-exceeded                => 11
       ttl-zero-during-transit   => 11/0
       ttl-zero-during-reassembly=> 11/1
    parameter-problem            => 12
       ip-header-bad             => 12/0
       required-option-missing   => 12/1
    timestamp-request            => 13
    timestamp-reply              => 14
    address-mask-request         => 17
    address-mask-reply           => 18

Type names for IPv6 and their corresponding type or type/code are:

    destination-unreachable       => 1
       no-route'                  => 1/0
       communication-prohibited   => 1/1
       address-unreachable'       => 1/3
       port-unreachable'          => 1/4
    packet-too-big                =>  2
    time-exceeded'                =>  3
    ttl-exceeded'                 =>  3
       ttl-zero-during-transit    => 3/0
       ttl-zero-during-reassembly => 3/1
    parameter-problem             =>  4
       bad-header                 => 4/0
       unknown-header-type        => 4/1
       unknown-option             => 4/2
    echo-request                  => 128
    echo-reply                    => 129
    router-solicitation           => 133
    router-advertisement          => 134
    neighbour-solicitation        => 135
    neighbour-advertisement       => 136
    redirect                      => 137

Shorewall 4.4 does not accept lists of ICMP (ICMP6) types prior to Shorewall 4.4.19.

# Using MAC Addresses

Media Access Control (MAC) addresses can be used to specify packet source in several of the configuration files. In order to control traffic to/from a host by its MAC address, the host must be on the same network as the firewall.

To use this feature, your kernel must have MAC Address Match support (CONFIG_IP_NF_MATCH_MAC) included.

MAC addresses are 48 bits wide and each Ethernet Controller has a unique MAC address.

In GNU/Linux, MAC addresses are usually written as a series of 6 hex numbers separated by colons.

         gateway:~ # ip link ls dev eth0
         4: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc htb qlen 1000
             link/ether 02:00:08:E3:FA:55 brd ff:ff:ff:ff:ff:ff
         gateway:~ #

Because Shorewall uses colons as a separator for address fields, Shorewall requires MAC addresses to be written in another way. In Shorewall, MAC addresses begin with a tilde (“~”) and consist of 6 hex numbers separated by hyphens. In Shorewall, the MAC address in the example above would be written **~02-00-08-E3-FA-55**.

<div class="note">

It is not necessary to use the special Shorewall notation in the `/etc/shorewall/maclist` file.

</div>

# Rate Limiting (Rate and Burst)

Shorewall supports rate limiting in a number of ways. When specifying a rate limit, both a rate and a burst value are given.

Example from [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5):

LOGLIMIT=10/minute:5

For each logging rule, the first time the rule is reached, the packet will be logged; in fact, since the burst is 5, the first five packets will be logged. After this, it will be 6 seconds (1 minute divided by the rate of 10) before a message will be logged from the rule, regardless of how many packets reach it. Also, every 6 seconds which passes, one of the bursts will be regained; if no packets hit the rule for 30 seconds, the burst will be fully recharged; back where we started.

Shorewall also supports per-IP rate limiting.

Another example from [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5):

LOGLIMIT="s:5/min:5"

Here, the leading "s:" indicates that logging is to be limited by source IP address ("d:" would indicate limiting by destination IP address).

"s:" is followed by the rate (5 messages per minute) and the burst (5).

The rate and limit arguments have the same meaning as in the example above.

# TIME Columns

Several of the files include a TIME colum that allows you to specify times when the rule is to be applied. Contents of this column is a list of \<timeelement\>s separated by apersands (&).

Each \<timeelement\> is one of the following:

timestart=\<hh\>:\<mm\>\[:\<ss\>\]  
Defines the starting time of day.

timestop=\<hh\>:\<mm\>\[:\<ss\>\]  
Defines the ending time of day.

contiguous  
Added in Shoreawll 5.0.12. When **timestop** is smaller than **timestart** value, match this as a single time period instead of distinct intervals. See the Examples below.

utc  
Times are expressed in Greenwich Mean Time.

localtz  
Deprecated by the Netfilter team in favor of **kerneltz**. Times are expressed in Local Civil Time (default).

kerneltz  
Added in Shorewall 4.5.2. Times are expressed in Local Kernel Time (requires iptables 1.4.12 or later).

weekdays=ddd\[,ddd\]...  
where \<ddd\> is one of `Mon`, `Tue`, `Wed`, `Thu`, `Fri`, `Sat` or `Sun`

monthdays=dd\[,dd\],...  
where \<dd\> is an ordinal day of the month

datestart=\<yyyy\>\[-\<mm\>\[-\<dd\>\[`T`\<hh\>\[:\<mm\>\[:\<ss\>\]\]\]\]\]  
Defines the starting date and time.

datestop=\<yyyy\>\[-\<mm\>\[-\<dd\>\[`T`\<hh\>\[:\<mm\>\[:\<ss\>\]\]\]\]\]  
Defines the ending date and time.

Examples:

To match on weekends, use:  
weekdays=Sat,Sun

Or, to match (once) on a national holiday block:  
datestart=2016-12-24&datestop=2016-12-27

Since the stop time is actually inclusive, you would need the following stop time to not match the first second of the new day:  
datestart=2016-12-24T17:00&datestop=2016-12-27T23:59:59

During Lunch Hour  

The fourth Friday in the month:  
weekdays=Fri&monthdays=22,23,24,25,26,27,28

Matching across days might not do what is expected. For instance,  
weekdays=Mon&timestart=23:00&timestop=01:00

Will match Monday, for one hour from midnight to 1 a.m., and then again for another hour from 23:00 onwards. If this is unwanted, e.g. if you would like 'match for two hours from Montay 23:00 onwards' you need to also specify the **contiguous** option in the example above.

# Switches

There are times when you would like to enable or disable one or more rules in the configuration without having to do a `shorewall reload` or `shorewall restart`. This may be accomplished using the SWITCH column in [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5) or [shorewall6-rules](https://shorewall.org/manpages/shorewall-rules.html) (5). Using this column requires that your kernel and iptables include Condition Match Support and you must be running Shorewall 4.4.24 or later. See the output of `shorewall show capabilities` and `shorewall version` to determine if you can use this feature.

The SWITCH column contains the name of a switch. Each switch is initially in the **off** position. You can turn on the switch named *switch1* by:

echo 1 \> /proc/net/nf_condition/switch1

You can turn it off again by:

echo 0 \> /proc/net/nf_condition/switch1

If you simply include the switch name in the SWITCH column, then the rule is enabled only when the switch is **on**. If you precede the switch name with ! (e.g., !switch1), then the rule is enabled only when the switch is **off**. Switch settings are retained over `shorewall restart`.

Shorewall requires that switch names:

- begin with a letter and be composed of letters, digits, underscore ('\_') or hyphen ('-'); and

- be 30 characters or less in length.

Multiple rules can be controlled by the same switch.

Example:

> Forward port 80 to dmz host \$BACKUP if switch 'primary_down' is on.
>
>     #ACTION     SOURCE          DEST        PROTO       DPORT        SPORT     ORIGDEST   RATE      USER      MARK    CONNLIMIT     TIME     HEADERS    SWITCH
>     DNAT        net             dmz:$BACKUP tcp         80           -         -          -         -         -       -             -        -          primary_down  

# Logical Interface Names

When dealing with a complex configuration, it is often awkward to use physical interface names in the Shorewall configuration.

- You need to remember which interface is which.

- If you move the configuration to another firewall, the interface names might not be the same.

Beginning with Shorewall 4.4.4, you can use logical interface names which are mapped to the actual interface using the `physical` option in [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html) (5).

Here is an example:

    #ZONE  INTERFACE  OPTIONS
    net    COM_IF     dhcp,blacklist,tcpflags,optional,upnp,routefilter=0,nosmurfs,logmartians=0,physical=eth0
    net    EXT_IF     dhcp,blacklist,tcpflags,optional,routefilter=0,nosmurfs,logmartians=0,proxyarp=1,physical=eth2
    loc    INT_IF     dhcp,logmartians=1,routefilter=1,tcpflags,nets=172.20.1.0/24,physical=eth1
    dmz    VPS_IF     logmartians=1,routefilter=0,routeback,physical=venet0
    loc    TUN_IF     physical=tun+

In this example, COM_IF is a logical interface name that refers to Ethernet interface `eth0`, EXT_IF is a logical interface name that refers to Ethernet interface `eth2`, and so on.

Here are a couple of more files from the same configuration:

[shorewall-masq](https://shorewall.org/manpages/shorewall-masq.html) (5):

    #INTERFACE SOURCE                    ADDRESS

    COMMENT Masquerade Local Network
    COM_IF     0.0.0.0/0
    EXT_IF     !206.124.146.0/24         206.124.146.179:persistent

[shorewall-providers](https://shorewall.org/manpages/shorewall-providers.html) (5)

    #NAME   NUMBER   MARK    DUPLICATE  INTERFACE  GATEWAY         OPTIONS               COPY
    Avvanta 1        0x10000 main       EXT_IF     206.124.146.254 loose,fallback        INT_IF,VPS_IF,TUN_IF
    Comcast 2        0x20000 main       COM_IF     detect          balance               INT_IF,VPS_IF,TUN_IF

Note in particular that Shorewall translates TUN_IF to `tun*` in the COPY column.

# Optional and Required Interfaces

Normally, Shorewall assumes that all interfaces described in [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html) (5) are going to be in an up and usable state when Shorewall starts or restarts. You can alter that assumption by specifying the **optional** option in the OPTIONS column.

When an interface is marked as optional, Shorewall will determine the interface state at `start`, `reload` and `restart` and adjust its configuration accordingly.

- The **arp_filter**, **arp_ignore**, **routefilter**, **logmartians**, **proxyarp** and **sourceroute** options are not enforced when the interface is down, thus avoiding an error message such as:

      WARNING: Cannot set Martian logging on ppp0

- If the interface is associated with a provider in [shorewall-providers](https://shorewall.org/manpages/shorewall-providers.html) (5), `start`, `reload` and `restart` will not fail if the interface is not usable.

- When DETECT_DNAT_IPADDRS=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5), DNAT rules in shorewall-rules (5) involving the interface will be omitted when the interface does not have an IP address.

- If **detect** is specified in the ADDRESS column of an entry in [shorewall-masq](https://shorewall.org/manpages/shorewall-masq.html) (5) then the firewall still starts if the optional interface in the INTERFACE column does not have an IP address.

If you don't want the firewall to start unless a given interface is usable, then specify **required** in the OPTIONS column of [shorewall-interfaces](https://shorewall.org/manpages/shorewall-interfaces.html) (5). If you have installed and configured the Shorewall-init package, then when the interface becomes available, an automatic attempt will be made to start the firewall.

# Shorewall Configurations

Shorewall allows you to have configuration directories other than `/etc/shorewall`. The shorewall `check`, `start`, `reload` and `restart` commands allow you to specify an alternate configuration directory and Shorewall will use the files in the alternate directory rather than the corresponding files in /etc/shorewall. The alternate directory need not contain a complete configuration; those files not in the alternate directory will be read from `/etc/shorewall`.

<div class="important">

Shorewall requires that the file `/etc/shorewall/shorewall.conf` to always exist. Certain global settings are always obtained from that file. If you create alternative configuration directories, do not remove /etc/shorewall/shorewall.conf.

</div>

This facility permits you to easily create a test or temporary configuration by

1.  copying the files that need modification from /etc/shorewall to a separate directory;

2.  modify those files in the separate directory; and

3.  specifying the separate directory in a `shorewall start`, `shorewall reload` or `shorewall restart` command (e.g., `shorewall restart /etc/testconfig` )

# Saved Configurations

Shorewall allows you to save the currently-running configuration in a form that permits it to be re-installed quickly. When you save the configuration using the `shorewall save` command, the running configuration is saved in a file in the `/var/lib/shorewall` directory. The default name of that file is `/var/lib/shorewall/restore` but you can specify a different name as part of the command. For example, the command `shorewall save standard` will save the running configuration in `/var/lib/shorewall/standard`. A saved configuration is re-installed using the `shorewall restore` command. Again, that command normally will restore the configuration saved in `/var/lib/shorewall/restore` but as with the `save` command, you can specify a different file name in the command. For example, `shorewall restore standard` will re-install the configuration saved in `/var/lib/shorewall/standard`. By permitting you to save different configurations under different names, Shorewall provides a means for quickly switching between these different saved configurations.

As mentioned above, the default configuration is called 'restore' but like most things in Shorewall, that default can be changed. The default name is specified using the **RESTOREFILE** option in `/etc/shorewall/shorewall.conf`.

<div class="warning">

The default saved configuration is used by Shorewall in a number of ways besides in the `restore` command; to avoid surprises, I recommend that you read the [Shorewall Operations documentation section about saved configurations](starting_and_stopping_shorewall.md#Saved) before creating one.

</div>
