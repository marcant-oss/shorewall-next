<div class="caution">

This article includes information that applies to Shorewall version 3.2.5 and later. Not all features described here will be available in earlier releases.

</div>

<div class="important">

/etc/shorewall/mangle superseded /etc/shorewall/tcrules in Shorewall 4.6.0. /etc/shorwall/tcrules is still supported but its use is deprecated.

</div>

# Packet and Connection Marks

Perhaps no aspect of Shorewall causes more confusion than packet marking. This article will attempt to clear up some of that confusion.

Each packet has a mark whose value is initially 0. Mark values are stored in the *skb* (socket buffer) structure used by the Linux kernel to track packets; the mark value is not part of the packet itself and cannot be seen with `tcpdump`, `ethereal` or any other packet sniffing program. They can be seen in an iptables/ip6tables trace -- see the `iptrace` command in [shorewall](https://shorewall.org/manpages/shorewall.html)(8).

Example (output has been folded for display ):

    [11692.096077] TRACE: mangle:tcout:return:3 IN= OUT=eth0 SRC=172.20.1.130
                                                DST=206.124.146.254 LEN=84 TOS=0x00 PREC=0x00 TTL=64
                                                ID=0 DF PROTO=ICMP TYPE=8 CODE=0 ID=7212 SEQ=3 UID=0 
                                                GID=1000 MARK=0x10082

Each active connection (even those that are not yet in ESTABLISHED state) has a mark value that is distinct from the packet marks. Connection mark values can be seen using the `shorewall show connections` command. The default connection mark value is 0.

Example (output has been folded for display ):

    shorewall show connections
    Shorewall 3.3.2 Connections at gateway - Mon Oct  2 09:08:18 PDT 2006

    tcp      6 19 TIME_WAIT src=206.124.146.176 dst=192.136.34.98 sport=58597 dport=80
             packets=23 bytes=4623 src=192.136.34.98 dst=206.124.146.176 sport=80 dport=58597
             packets=23 bytes=22532 [ASSURED] mark=256 use=1
    …

Packet marks are valid only while the packet is being processed by the firewall. Once the packet has been given to a local process or sent on to another system, the packet's mark value is no longer available. Connection mark values, on the other hand, persist for the life of the connection.

<div class="important">

Other parts of the system such as [Traffic Shaping](traffic_shaping.md) and [Policy Routing](MultiISP.md) cannot use connection marks — they can only use packet marks.

</div>

# Packet Marking "Programs"

Packet marking occurs in Netfilter's *mangle* table. See the [Netfilter Overview](../concepts/NetfilterOverview.md) article.

You can think of entries in the mangle and tcrules files like instructions in a program coded in a crude assembly language. The program gets executed for each packet.

That is another way of saying that **if you don't program, you may have difficulty making full use of Netfilter/Shorewall's Packet Marking**.

Actually, the mangle/tcrules files define several programs. Each program corresponds to one of the built-in chains in the mangle table.

- PREROUTING program — If MARK_IN_FORWARD_CHAIN=No in `shorewall.conf`, then by default entries in `/etc/shorewall/mangle` and `/etc/shorewall/tcrules` are part of the PREROUTING program. Entries specifying the ":P" suffix in the ACTION column are also part of the PREROUTING program. The PREROUTING program gets executed for each packet entering the firewall.

- FORWARD program — If MARK_IN_FORWARD_CHAIN=Yes in `shorewall.conf`, then by default entries in`/etc/shorewall/mangle` and `/etc/shorewall/tcrules` are part of the FORWARD program. Entries specifying the ":F" suffix in the ACTION column are also part of the FORWARD program. The FORWARD program gets executed for each packet forwarded by the firewall.

- OUTPUT program — Entries with \$FW in the SOURCE column are part of the OUTPUT program. The OUTPUT program is executed for each packet originating on the firewall itself.

- POSTROUTING program — Entries with a class-id in the ACTION column (and that don't specify \$FW in the SOURCE column) are part of the POSTROUTING program. These rules are executed for each packet leaving the firewall. Entries specifying the ":T" suffix in the ACTION column are also part of the POSTROUTING program (Shorewall version 3.4.0 and later).

- INPUT program — No entries in tcrules will add entries to this program. It is executed for each packet that is targeted to the firewall itself.

Note that a packet being forwarded by your firewall actually gets processed by three different programs: PREROUTING, FORWARD and POSTROUTING. Similarly, packets addressed to the firewall itself are processed by two programs (PREROUTING and INPUT) while packets originating on the firewall are likewise processed by two programs (OUTPUT and POSTROUTING).

Rules in each program are *executed* as follows:

- Rules are conditionally executed based on whether the current packet matches the contents of the SOURCE, DEST, PROTO, DPORT, SPORT, USER, TEST, LENGTH and TOS columns.

- When a rule is executed, either:

  1.  the current packet receives a new mark value; or

  2.  the connection to which the current packet belongs receives a new mark value (":C", ":CF" or ":CP" suffix in the ACTION column); or

  3.  the packet is classified for traffic shaping (class-id in the ACTION column); or

  4.  the packet mark in the current packet is moved to the connection mark for the connection that the current packet is part of ("SAVE" in the ACTION column); or

  5.  the connection mark value for the connection that the current packet is part of is moved to the current packet's mark ("RESTORE" in the ACTION column); or

  6.  jump to a subroutine (another chain in the mangle table). These jumps are generated by Shorewall; or

  7.  exit the current subroutine ("CONTINUE" in the ACTION column).

- Unless the subroutine is exited using CONTINUE, **the current packet is always passed to the next tcrule in the subroutine**.

# Mark and Mask Values

The mark value is held in a 32-bit field. Because packet marking is the Netfilter *kludge of last resort* for solving many hard technical problems, Shorewall originally reserved half of this field (16 bits) for future use. The remainder was split into two 8-bit values:

- The low-order eight bits are used for traffic shaping marks. These eight bits were also used for selecting among multiple providers when HIGH_ROUTE_MARKS=No in `shorewall.conf`. Some rules that deal with only these bits used a mask value of 0xff.

- The next 8 bits were used for selecting among multiple providers when HIGH_ROUTE_MARKS=Yes in `shorewall.conf`. These bits are manipulated using a mask value of 0xff00.

As hinted above, marking rules can specify both a mark value and a mask. The mask determines the subset of the 32 bits in the mark to be used in the operation — only those bits that are on in the mask are manipulated when the rule is executed. For entries in tcrules, Shorewall-generated rules use a mask value that depends on which program the rule is part of, what the rule does, and the setting of HIGH_ROUTE_MARKS.

For entries in mangle and tcrules, the default mask value is 0xffff except in these cases:

- RESTORE rules use a default mask value of 0xff.

- SAVE rules use a default mask value of 0xff.

- Connection marking rules use a mask value of 0xff.

When WIDE_TC_MARKS was added, the number of bits reserved for TC marks was increased to 14 when WIDE_TC_MARKS=Yes and the provider mark field (when HIGH_ROUTE_MARKS=Yes) was offset 16 bits. Also, when HIGH_ROUTE_MARKS=Yes, the mask used for setting/testing TC marks was 0xffff (16 bits).

Shorewall actually allows you to have complete control over the layout of the 32-bit mark using the following options in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5) (these options were documented in the [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(5) manpage in Shorewall 4.4.26):

TC_BITS  
The number of bits at the low end of the mark to be used for traffic shaping marking. May be zero.

PROVIDER_BITS  
The number of bits in the mark to be used for provider numbers. May be zero.

PROVIDER_OFFSET  
The offset from the right (low-order end) of the provider number field. If non-zero, must be \>= TC_BITS (Shorewall automatically adjusts PROVIDER_OFFSET's value). PROVIDER_OFFSET + PROVIDER_BITS must be \<= 32.

MASK_BITS  
Number of bits on the right of the mark to be masked when clearing the traffic shaping mark. Must be \>= TC_BITS and \<= PROVIDER_OFFSET (if PROVIDER_OFFSET \> 0)

In Shorewall 4.4.26, a new option was added:

ZONE_BITS  
Number of bits in the mark to use for automatic zone marking (see the [Shorewall Bridge/Firewall HOWTO](../legacy/bridge-Shorewall-perl.md)).

The relationship between these options is shown in this diagram.

The default values of these options are determined by the settings of other options as follows:

|                                         |                                                               |
|-----------------------------------------|---------------------------------------------------------------|
| WIDE_TC_MARKS=No, HIGH_ROUTE_MARKS=No   | TC_BITS=8, PROVIDER_BITS=8, PROVIDER_OFFSET=0, MASK_BITS=8    |
| WIDE_TC_MARKS=No, HIGH_ROUTE_MARKS=Yes  | TC_BITS=8, PROVIDER_BITS=8, PROVIDER_OFFSET=8, MASK_BITS=8    |
| WIDE_TC_MARKS=Yes, HIGH_ROUTE_MARKS=No  | TC_BITS=14, PROVIDER_BITS=8, PROVIDER_OFFSET=0, MASK_BITS=16  |
| WIDE_TC_MARKS=Yes, HIGH_ROUTE_MARKS=Yes | TC_BITS=14, PROVIDER_BITS=8, PROVIDER_OFFSET=16, MASK_BITS=16 |

Default Values

The existence of both TC_BITS and MASK_BITS is owed to the way that WIDE_TC_MARKS was originally implemented. Note that TC_BITS is 14 rather than 16 when WIDE_TC_MARKS=Yes.

Beginning with Shorewall 4.4.12, the field between MASK_BITS and PROVIDER_OFFSET can be used for any purpose you want.

Beginning with Shorewall 4.4.13, the first unused bit on the left is used by Shorewall as an exclusion mark, allowing exclusion in CONTINUE, NONAT and ACCEPT+ rules.

Beginning with Shorewall 4.4.26, WIDE_TC_MARKS and HIGH_ROUTE_MARKS are deprecated in favor of the options described above. The `shorewall update` (`shorewall6 update`) command will set the above options based on the settings of WIDE_TC_MARKS and HIGH_ROUTE_MARKS.

In Shorewall 4.5.4, a TPROXY mark was added for TPROXY support. It is a single bit wide and is to the immediate left of the exclusion mark.

The Event Mark bit was added in Shorewall 4.5.19. It is to the immediate left of the TPROXY mark, and it need not fall within the 32-bit mark unless the **reset** command is used in the **IfEvent** action.

# Shorewall-defined Chains in the Mangle Table

Shorewall creates a set of chains in the mangle table to hold rules defined in your `/etc/shorewall/mangle` (`/etc/shorewall/tcrules`) file. As mentioned above, chains are like subroutines in the packet marking programming language. By placing all of your rules in subroutines, CONTINUE (which generates a Netfilter RETURN rule) can be used to stop processing your rules while still allowing following Shorewall-generated rules to be executed.

tcpre  
PREROUTING rules.

tcfor  
FORWARD rules.

tcout  
OUTPUT rules.

tcpost  
POSTROUTING rules.

Shorewall generates jumps to these chains from the built-in chains (PREROUTING, FORWARD, etc.).

# An Example

Here's the example (slightly expanded) from the comments at the top of the `/etc/shorewall/mangle` file.

    #ACTION  SOURCE          DEST            PROTO   DPORT   SPORT   USER    TEST    LENGTH  TOS
    MARK(1)  0.0.0.0/0       0.0.0.0/0       icmp    echo-request                 #Rule 1
    MARK(1)  0.0.0.0/0       0.0.0.0/0       icmp    echo-reply                   #Rule 2
    MARK(1)  $FW             0.0.0.0/0       icmp    echo-request                 #Rule 3
    MARK(1)  $FW             0.0.0.0/0       icmp    echo-reply                   #Rule 4

    RESTORE  0.0.0.0/0       0.0.0.0/0       all     -       -       -       0    #Rule 5
    CONTINUE 0.0.0.0/0       0.0.0.0/0       all     -       -       -       !0   #Rule 6
    MARK(4)  0.0.0.0/0       0.0.0.0/0       ipp2p:all                            #Rule 7
    SAVE     0.0.0.0/0       0.0.0.0/0       all     -       -       -       !0   #Rule 8

Let's take a look at each rule:

1.  This straight-forward rule simply marks all 'ping' requests passing through the firewall with mark value 1. Note that it does not mark pings that originate on the firewall itself.

2.  Similarly, this rule marks 'ping' replies.

3.  This rule marks 'ping' requests that originate on the firewall. This rule and the next ones are part of the OUTPUT program.

4.  Similarly, this rule marks 'ping' replies from the firewall itself.

5.  Remember that even though 'ping' packets were marked in one of the first two rules, they are still passed on to rule 5 (note that packets marked by rules 3 and 4 are not processed by this rule since it is in a different program). That rule moves the connection mark to the packet mark, *if the packet mark is still zero* (note the '0' in the TEST column). Without the '0' in the TEST column, this rule would overwrite the marks assigned in the first two rules.

6.  If the packet mark is non-zero (note the '!0' in the TEST column), then exit — The remaining rules will not be executed in this case. The packet mark will be non-zero if this is a 'ping' packet, or if the connection mark restored in rule 5 was non-zero.

7.  The packet mark is still zero. This rule checks to see if this is a P2P packet and if it is, the packet mark is set to 4.

8.  If the packet mark is non-zero (meaning that it was set to 4 in rule 7), then save the value (4) in the connection. The next time that a packet from this same connection comes through this program, rule 6 will be executed and the P2P check will be avoided.

# Examining the Marking Programs on a Running System

You can see the mangle (tcrules) entries in action using the `shorewall show mangle` command.

The sample output from that command shown below has the following in `/etc/shorewall/providers`:

    #NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS         COPY
    Blarg   1       0x100   main            eth3            206.124.146.254 track,balance   br0,eth1

Here is `/etc/shorewall/mangle`:

    #ACTION                 SOURCE          DEST            PROTO   DPORT   SPORT   USER    TEST
    CLASSIFY(1:110)         192.168.0.0/22  eth3                            #Our internal nets get priority
                                                                            #over the server
    CLASSIFY(1:130)         206.124.146.177 eth3            tcp     -       873

And here is `/etc/shorewall/tcdevices` and `/etc/shorewall/tcclasses`:

    #INTERFACE      IN_BANDWITH     OUT_BANDWIDTH
    eth3            1.3mbit         384kbit

    #INTERFACE      MARK    RATE            CEIL            PRIORITY        OPTIONS
    eth3            10      full            full            1               tcp-ack,tos-minimize-delay
    eth3            20      9*full/10       9*full/10       2               default
    eth3            30      6*full/10       6*full/10       3

I've annotated the following output with comments beginning with "\<\<\<\<" and ending with "\>\>\>\>". This example uses HIGH_ROUTE_MARKS=Yes and TC_EXPERT=No in `shorewall.conf`.

    gateway:~ # shorewall show mangle
    Shorewall 3.3.2 Mangle Table at gateway - Mon Oct  2 15:07:32 PDT 2006

    Counters reset Mon Oct  2 07:49:52 PDT 2006

    <<<< The PREROUTING Program >>>>

    Chain PREROUTING (policy ACCEPT 409K packets, 122M bytes)
     pkts bytes target     prot opt in     out     source               destination

    <<<< Restore the provider mark from the connection, if any >>>>

     185K   77M CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0           CONNMARK match !0x0/0xff00 CONNMARK restore mask 0xff00

    <<<< If there is no mark in the connection and the packet came in on eth3, then jump to the routemark chain 
         This rule is generated as a result of 'track' being specified in the providers file entry for eth3 >>>>

     8804 1396K routemark  all  --  eth3   *       0.0.0.0/0            0.0.0.0/0           MARK match 0x0/0xff00

    <<<< If the packet came in on eth3, jump the the tcpre chain -- packets entering on a 'track'ed interface can have their mark set to zero there >>>>

     102K   52M tcpre      all  --  eth3   *       0.0.0.0/0            0.0.0.0/0

    <<<< Otherwise, jump to the tcpre chain if there is no current provider mark -- 
         if we would have had TC_EXPERT=Yes, this jump would have been unconditional>>>>

     215K   44M tcpre      all  --  *      *       0.0.0.0/0            0.0.0.0/0           MARK match 0x0/0xff00

    <<<< End of PREROUTING program >>>>

    <<<< INPUT Program -- Shorewall generates the single rule here which turns off the provider mark in the packet after routing
                          The rule does that by logically ANDing the mark value with 0xff which will turn off all but the low-order 8 bits >>>>

    Chain INPUT (policy ACCEPT 98238 packets, 16M bytes)
     pkts bytes target     prot opt in     out     source               destination
    98234   16M MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0           MARK and 0xff

    <<<< End of INPUT program >>>>

    <<<< FORWARD Program -- Shorewall generates the first rule here which turns off the provider mark in the packet after routing >>>>

    Chain FORWARD (policy ACCEPT 312K packets, 106M bytes)
     pkts bytes target     prot opt in     out     source               destination
     312K  106M MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0           MARK and 0xff

    <<<< Jump unconditionally to the tcfor chain >>>>

     312K  106M tcfor      all  --  *      *       0.0.0.0/0            0.0.0.0/0

    <<<< End of FORWARD program >>>>

    <<<< OUTPUT Program >>>>

    Chain OUTPUT (policy ACCEPT 1462K packets, 396M bytes)
     pkts bytes target     prot opt in     out     source               destination

    <<<< Restore the provider mark from the connection -- this rule was generated by Shorewall because of the 'track' option >>>>

     3339  615K CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0           CONNMARK match !0x0/0xff00 CONNMARK restore mask 0xff00

    <<<< If there is no provider mark, then jump to the tcout chain -- 
         if we would have had TC_EXPERT=Yes, this jump would have been unconditional >>>>

    92747   28M tcout      all  --  *      *       0.0.0.0/0            0.0.0.0/0           MARK match 0x0/0xff00

    <<<< End of FORWARD program >>>>

    <<<< POSTROUTING Program -- Unconditionally jump to the tcpost chain >>>>

    Chain POSTROUTING (policy ACCEPT 407K packets, 135M bytes)
     pkts bytes target     prot opt in     out     source               destination
     407K  135M tcpost     all  --  *      *       0.0.0.0/0            0.0.0.0/0

    <<<< End of FORWARD program >>>>

    Chain routemark (1 references)
     pkts bytes target     prot opt in     out     source               destination

    <<<< Set connection 'track' mark for packets coming in on eth3 >>>>

     8804 1396K MARK       all  --  eth3   *       0.0.0.0/0            0.0.0.0/0           MARK or 0x100

    <<<< Save any mark added above in the connection mark >>>>

     8804 1396K CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0           MARK match !0x0/0xff00 CONNMARK save mask 0xff00

    Chain tcfor (1 references)
     pkts bytes target     prot opt in     out     source               destination

    Chain tcout (1 references)
     pkts bytes target     prot opt in     out     source               destination

    Chain tcpost (1 references)
     pkts bytes target     prot opt in     out     source               destination

    <<<< The next two rules are the entries in the /etc/shorewall/mangle file >>>>

    65061   11M CLASSIFY   all  --  *      eth3    192.168.0.0/22       0.0.0.0/0           CLASSIFY set 1:110
     2224 2272K CLASSIFY   tcp  --  *      eth3    206.124.146.177      0.0.0.0/0           tcp spt:873 CLASSIFY set 1:130

    <<<< The following rules are generated by Shorewall and classify the traffic according to the marks in /etc/shorewall/classes >>>>

        0     0 CLASSIFY   all  --  *      eth3    0.0.0.0/0            0.0.0.0/0           MARK match 0xa/0xff CLASSIFY set 1:110
        0     0 CLASSIFY   all  --  *      eth3    0.0.0.0/0            0.0.0.0/0           MARK match 0x14/0xff CLASSIFY set 1:120
        0     0 CLASSIFY   all  --  *      eth3    0.0.0.0/0            0.0.0.0/0           MARK match 0x1e/0xff CLASSIFY set 1:130

    Chain tcpre (2 references)
     pkts bytes target     prot opt in     out     source               destination
    gateway:~ #
