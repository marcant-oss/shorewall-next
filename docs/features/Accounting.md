<div class="caution">

**This article applies to Shorewall 4.0 and later. If you are running a version of Shorewall earlier than Shorewall 4.0.0 then please see the documentation for that release**.

</div>

# Accounting Basics

Shorewall accounting rules are described in the file `/etc/shorewall/accounting`. By default, the accounting rules are placed in a chain called “accounting” and can thus be displayed using “shorewall\[-lite\] show -x accounting”. All traffic passing into, out of, or through the firewall traverses the accounting chain including traffic that will later be rejected by interface options such as “tcpflags” and “maclist”.

The columns in the accounting file are described in [shorewall-accounting](https://shorewall.org/manpages/shorewall-accounting.html) (5).

In all columns except ACTION and CHAIN, the values “-”, “any” and “all” are treated as wild-cards.

The accounting rules are evaluated in the Netfilter “filter” table. This is the same environment where the “rules” file rules are evaluated and in this environment, DNAT has already occurred in inbound packets and SNAT has not yet occurred on outbound packets.

Accounting rules are not stateful -- each rule only handles traffic in one direction. For example, if eth0 is your Internet interface, and you have a web server in your DMZ connected to eth1, then to count HTTP traffic in both directions requires two rules:

            #ACTION         CHAIN   SOURCE  DEST    PROTO   DPORT   SPORT   USER    MARK    IPSEC
            DONE            -       eth0    eth1    tcp     80
            DONE            -       eth1    eth0    tcp     -       80

Associating a counter with a chain allows for nice reporting. For example:

            #ACTION         CHAIN   SOURCE  DEST    PROTO   DPORT   SPORT   USER    MARK    IPSEC
            web:COUNT       -       eth0    eth1    tcp     80
            web:COUNT       -       eth1    eth0    tcp     -       80
            web:COUNT       -       eth0    eth1    tcp     443
            web:COUNT       -       eth1    eth0    tcp     -       443
            DONE            web

Now `shorewall show web` (or `shorewall-lite show web` for Shorewall Lite users) will give you a breakdown of your web traffic:

         [root@gateway shorewall]# shorewall show web
         Shorewall-1.4.6-20030821 Chain web at gateway.shorewall.net - Wed Aug 20 09:48:56 PDT 2003
         
         Counters reset Wed Aug 20 09:48:00 PDT 2003

         Chain web (4 references)
         pkts bytes target     prot opt in     out     source               destination
           11  1335            tcp  --  eth0   eth1    0.0.0.0/0            0.0.0.0/0          tcp dpt:80
           18  1962            tcp  --  eth1   eth0    0.0.0.0/0            0.0.0.0/0          tcp spt:80
            0     0            tcp  --  eth0   eth1    0.0.0.0/0            0.0.0.0/0          tcp dpt:443
            0     0            tcp  --  eth1   eth0    0.0.0.0/0            0.0.0.0/0          tcp spt:443
           29  3297 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0
           [root@gateway shorewall]#

Here is a slightly different example:

            #ACTION         CHAIN   SOURCE  DEST    PROTO   DPORT   SPORT   USER    MARK    IPSEC
            web             -       eth0    eth1    tcp     80
            web             -       eth1    eth0    tcp     -       80
            web             -       eth0    eth1    tcp     443
            web             -       eth1    eth0    tcp     -       443
            COUNT           web     eth0    eth1
            COUNT           web     eth1    eth0

Now `shorewall show web` (or `shorewall-lite show web` for Shorewall Lite users) simply gives you a breakdown by input and output:

         [root@gateway shorewall]# shorewall show accounting web
         Shorewall-1.4.6-20030821 Chains accounting web at gateway.shorewall.net - Wed Aug 20 10:27:21 PDT 2003

         Counters reset Wed Aug 20 10:24:33 PDT 2003

         Chain accounting (3 references)
             pkts bytes target     prot opt in     out     source               destination
             8767  727K web        tcp  --  eth0   eth1    0.0.0.0/0            0.0.0.0/0          tcp dpt:80
                0     0 web        tcp  --  eth0   eth1    0.0.0.0/0            0.0.0.0/0          tcp dpt:443

            11506   13M web        tcp  --  eth1   eth0    0.0.0.0/0            0.0.0.0/0          tcp spt:80
                0     0 web        tcp  --  eth1   eth0    0.0.0.0/0            0.0.0.0/0          tcp spt:443

         Chain web (4 references)
             pkts bytes target     prot opt in     out     source               destination
             8767  727K            all  --  eth0   eth1    0.0.0.0/0            0.0.0.0/0
            11506   13M            all  --  eth1   eth0    0.0.0.0/0            0.0.0.0/0
         [root@gateway shorewall]#

Here's how the same example would be constructed on an HTTP server with only one interface (eth0).

<div class="caution">

READ THE ABOVE CAREFULLY -- IT SAYS **SERVER**. If you want to account for web browsing, you have to reverse the rules below.

</div>

            #ACTION         CHAIN   SOURCE  DEST    PROTO   DPORT   SPORT   USER    MARK    IPSEC
            web             -       eth0    -       tcp     80
            web             -       -       eth0    tcp     -       80
            web             -       eth0    -       tcp     443
            web             -       -       eth0    tcp     -       443
            COUNT           web     eth0
            COUNT           web     -       eth0

Note that with only one interface, only the SOURCE (for input rules) or the DESTINATION (for output rules) is specified in each rule.

Here's the output:

         [root@mail shorewall]# shorewall show accounting web Shorewall-1.4.7
         Chains accounting web at mail.shorewall.net - Sun Oct 12 10:27:21 PDT 2003

         Counters reset Sat Oct 11 08:12:57 PDT 2003

         Chain accounting (3 references)
          pkts bytes target     prot opt in     out     source               destination
          8767  727K web        tcp  --  eth0   *       0.0.0.0/0            0.0.0.0/0          tcp dpt:80
         11506   13M web        tcp  --  *      eth0    0.0.0.0/0            0.0.0.0/0          tcp spt:80
             0     0 web        tcp  --  eth0   *       0.0.0.0/0            0.0.0.0/0          tcp dpt:443
             0     0 web        tcp  --  *      eth0    0.0.0.0/0            0.0.0.0/0          tcp spt:443

         Chain web (4 references)
          pkts bytes target     prot opt in     out     source               destination
          8767  727K            all  --  eth0   *       0.0.0.0/0            0.0.0.0/0
         11506   13M            all  --  *      eth0    0.0.0.0/0            0.0.0.0/0
         [root@mail shorewall]#

For an example of integrating Shorewall Accounting with MRTG, see <http://www.nightbrawler.com/code/shorewall-stats/>.

# Accounting with Bridges

The structure of the accounting rules changes slightly when there are [bridges](../legacy/bridge-Shorewall-perl.md) defined in the Shorewall configuration. Because of the restrictions imposed by Netfilter in kernel 2.6.21 and later, output accounting rules must be segregated from forwarding and input rules. To accomplish this separation, Shorewall-perl creates two accounting chains:

- **accounting** - for input and forwarded traffic.

- **accountout** - for output traffic.

If the CHAIN column contains “-”, then:

- If the SOURCE column in a rule includes the name of the firewall zone (e.g., \$FW), then the default chain to insert the rule into is **accountout** only.

- Otherwise, if the DEST in the rule is **any** or **all** or 0.0.0.0/0, then the rule is added to both **accounting** and **accountout**.

- Otherwise, the rule is added to **accounting** only.

# Sectioned Accounting Rules

Traditionally, the root of the Shorewall accounting rules has been the **accounting** chain. Having a single root chain has drawbacks:

- Many rules are traversed needlessly (they could not possibly match traffic).

- At any time, the Netfilter team could begin generating errors when loading those same rules (that has happened).

- MAC addresses may not be used in the accounting rules.

- The **accounting** chain cannot be optimized when OPTIMIZE_ACCOUNTING=Yes.

- The rules may be defined in any order so the rules compiler must post-process the ruleset to ensure that there are no loops and to alert the user to unreferenced chains.

Beginning with Shorewall 4.4.18, the accounting structure can be created with three root chains:

- **accountin**: Rules that are valid in the **INPUT** chain (may not specify an output interface).

- **accountout**: Rules that are valid in the OUTPUT chain (may not specify an input interface or a MAC address).

- **accounting**: Other rules.

The new structure is enabled by sectioning the accounting file in a manner similar to the [rules file](https://shorewall.org/manpages/shorewall-rules.html). The sections are **INPUT**, **OUTPUT** and **FORWARD** and must appear in that order (although any of them may be omitted). The first non-commentary record in the accounting file must be a section header when sectioning is used.

Beginning with Shorewall 4.4.20, the ACCOUNTING_TABLE setting was added to shorewall.conf and shorewall6.conf. That setting determines the Netfilter table (filter or mangle) where the accounting rules are added. When ACCOUNTING_TABLE=mangle is specified, the available sections are **PREROUTING**, **INPUT**, **OUTPUT**, **FORWARD** and **POSTROUTING**.

Section headers have the form:

`?SECTION` \<section-name\>

When sections are enabled:

- You must jump to a user-defined accounting chain before you can add rules to that chain.

- This eliminates loops and unreferenced chains.

- You may not specify an output interface in the **PREROUTING** and **INPUT** sections.

- In the **OUTPUT** and **POSTROUTING** sections:

  - You may not specify an input interface

  - You may not jump to a chain defined in the **INPUT** or **PREROUTING** sections that specifies an input interface

  - You may not specify a MAC address

  - You may not jump to a chain defined in the **INPUT** or **PREROUTING** section that specifies a MAC address.

- The default value of the CHAIN column is:

  - **accountin** in the **INPUT** section

  - **accounout** in the **OUTPUT** section

  - **accountfwd** in the **FORWARD** section

  - **accountpre** in the **PREROUTING** section

  - **accountpost** in the **POSTROUTING** section

- Traffic addressed to the firewall goes through the rules defined in the INPUT section.

- Traffic originating on the firewall goes through the rules defined in the OUTPUT section.

- Traffic being forwarded through the firewall goes through the rules from the FORWARD sections.

Here is a sample sectioned file that used [Per-IP Accounting](#perIP).

<div class="caution">

In this example, the dmz net corresponds to a vserver zone so lives on the firewall itself.

</div>

    #ACTION                         CHAIN   SOURCE  DEST    PROTO   DPORT   SPORT   USER    MARK    IPSEC
    ?SECTION INPUT
    ACCOUNT(fw-net,$FW_NET)     -   COM_IF
    ACCOUNT(dmz-net,$DMZ_NET)   -   COM_IF

    ?SECTION OUTPUT
    ACCOUNT(fw-net,$FW_NET)     -   -   COM_IF
    ACCOUNT(dmz-net,$DMZ_NET)       -   -   COM_IF

    ?SECTION FORWARD
    ACCOUNT(loc-net,$INT_NET)       -   COM_IF  INT_IF
    ACCOUNT(loc-net,$INT_NET)       -   INT_IF  COM_IF

# Integrating Shorewall Accounting with Collectd

Sergiusz Pawlowicz has written a nice article that shows how to integrate Shorewall Accounting with collectd to produce nice graphs of traffic activity. The article may be found at <http://collectd.org/wiki/index.php/Plugin:IPTables>.

# Per-IP Accounting

Shorewall 4.4.17 added support for per-IP accounting using the ACCOUNT target.

Per-IP accounting is configured in [shorewall-accounting](https://shorewall.org/manpages/shorewall-accounting.html) (5) (it is currently not supported in IPv6). In the ACTION column, enter:

ACCOUNT(

table

,

network

)

where

table

is the name of an accounting table (you choose the name). All rules specifying the same table will have their per-IP counters accumulated in that table.

network

is an IPv4 network in CIDR notation. The network can be as large as a /8 (class A).

One nice feature of per-IP accounting is that the counters survive `shorewall restart`. This has a downside, however. If you change the network associated with an accounting table, then you must `shorewall stop; shorewall start` to have a successful restart (counters will be cleared).

Example: Suppose your WAN interface is eth0 and your LAN interface is eth1 with network 172.20.1.0/24. To account for all traffic between the WAN and LAN interfaces:

    #ACTION                         CHAIN   SOURCE  DEST    PROTO   DPORT   SPORT   USER    MARK    IPSEC
    ACCOUNT(net-loc,172.20.1.0/24)  -       eth0    eth1
    ACCOUNT(net-loc,172.20.1.0/24)  -       eth1    eth0

This will create a **net-loc** table for counting packets and bytes for traffic between the two interfaces.

The table is dumped using the `iptaccount` utility (part of xtables-addons):

    iptaccount [-f] -l net-loc

Example:

    gateway:~# iptaccount -l net-loc

    libxt_ACCOUNT_cl userspace accounting tool v1.3

    Showing table: net-loc
    Run #0 - 3 items found
    IP: 172.20.1.105 SRC packets: 115 bytes: 131107 DST packets: 68 bytes: 20045
    IP: 172.20.1.131 SRC packets: 47 bytes: 12729 DST packets: 38 bytes: 25304
    IP: 172.20.1.145 SRC packets: 20747 bytes: 2779676 DST packets: 27050 bytes: 32286071
    Finished.
    gateway:~#

For each local IP address with non-zero counters, the packet and byte count for both incoming traffic (IP is DST) and outgoing traffic (IP is SRC) are listed. The -f option causes the table to be flushed (reset all counters to zero) after printing.

For a command synopsis:

    iptaccount --help

`/sbin/shorewall` also supports a `show ipa` command (from my own gateway just after I flushed the counters using `iptaccount -f -l`.:

    gateway:~# shorewall show ipa
    Shorewall 4.4.18-Beta1 per-IP Accounting at gateway - Thu Feb 10 13:28:37 PST 2011

    Showing table: loc-net
    IP: 172.20.1.146 SRC packets: 9 bytes: 574 DST packets: 9 bytes: 770

    Showing table: dmz-net
    IP: 70.90.191.124 SRC packets: 243 bytes: 23726 DST packets: 248 bytes: 39036
    IP: 70.90.191.125 SRC packets: 73 bytes: 10640 DST packets: 73 bytes: 4846

    Showing table: fw-net
    IP: 70.90.191.121 SRC packets: 0 bytes: 0 DST packets: 4 bytes: 243
    IP: 70.90.191.122 SRC packets: 11 bytes: 1338 DST packets: 8 bytes: 5465
    IP: 70.90.191.123 SRC packets: 42 bytes: 4604 DST packets: 44 bytes: 10662

    gateway:~# 

# Accounting using nfacct

Beginning with the 3.3 kernels, Netfilter supports a form of accounting (nfacct) that is triggered by iptables rules but that survives purging and/or reloading the Netfilter ruleset. Shorewall support for this form of accounting was added in Shorewall 4.5.7.

Use of this feature requires that the nfacct utility be installed. The nfacct utility can create, delete and display nfacct objects. These named objects consist of a packet and byte counter. Packets matching those netfilter rules that use the nfacct match cause the packet and byte count in the object named in the match to be incremented.

To use nfaccnt with Shorewall, use the NFACCT target. See [shorewall-accounting](https://shorewall.org/manpages/shorewall-accounting.html)(5) for details.

The `shorewall show nfacct` command is a thin wrapper around the `nfacct list` command.

# Preserving Counters over Restart and Reboot

Beginning with Shorewall 4.6.5, it is possible to preserve *all* ip\[6\]tables packet and byte counters over restarts and reboots through use of the `-C` option. This option is available in several commands.

save  
Causes the packet and byte counters to be saved along with the chains and rules.

restore  
Causes the packet and byte counters (if saved) to be restored along with the chains and rules.

<div class="caution">

If your iptables ruleset depends on variables that are detected at run-time, either in your params file or by Shorewall-generated code, `restore` will use the values that were detected when the ruleset was saved, which may be different from the current values.

</div>

start  
With Shorewall and Shorewall6, the -C option only has an effect if the `-f`option is also specified. If a previously-saved configuration is restored, then the packet and byte counters (if saved) will be restored along with the chains and rules.

<div class="caution">

If your iptables ruleset depends on variables that are detected at run-time, either in your params file or by Shorewall-generated code, `-C` will use the values that were detected when the ruleset was saved, which may be different from the current values.

</div>

restart  
If an existing compiled script is used (no recompilation required) and if that script generated the current running configuration, then the current netfilter configuration is reloaded as is so as to preserve the current packet and byte counters.

<div class="caution">

If your iptables ruleset depends on variables that are detected at run-time, either in your params file or by Shorewall-generated code, `-C` will use the values that were detected when the ruleset was previously started, which may be different from the current values.

</div>

If you wish to (approximately) preserve the counters over a possibly unexpected reboot, then:

- Create a cron job that periodically executes 'shorewall save `-C`'.

- Specify the`-C` and `-f` options in the STARTOPTIONS variable in either `/etc/default/shorewall` ( `/etc/default/shorewall6`, etc.) or `/etc/sysconfig/shorewall` (`/etc/sysconfig/shorewall`6, etc.), whichever is supported by your distribution. Note that not all distributions include these files so you may have to create the one(s) you need.
