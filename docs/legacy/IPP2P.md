<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

# Introduction

Shorewall includes support for the ipp2p match facility. This is a departure from my usual policy in that the ipp2p match facility is included in xtables-addons and is unlikely to ever be included in the kernel.org source tree. Questions about how to install xtables-addons or how to build your kernel and/or iptables should not be posted on the Shorewall mailing lists but should rather be referred to the Netfilter Mailing List.

# Scope

In the following files, the "PROTO" or "PROTOCOL" column may contain "ipp2p":

/etc/shorewall/tcrules

/etc/shorewall/mangle

/etc/shorewall/accounting

/etc/shorewall/rules

(Not Recommend. But if you insist, then you should place the rules in the ESTABLISHED section of that file).

When the PROTO or PROTOCOL column contains "ipp2p" then the DEST PORT(S) or PORT(S) column may contain a recognized ipp2p option (Shorewall-perl 4.2.5 and later accepts a comma-separated list of options); for a list of the options and their meaning, at a root prompt type:

    iptables -m ipp2p --help

You must not include the leading "--" on the option(s); Shorewall will supply those characters for you. If you do not include an option then Shorewall will assume "edk,kazaa,gnu,dc".

If 'ipp2p' is specified, Shorewall will substitute "edk,kazaa,gnu,dc".

# Example:

Example 2 in the ipp2p documentation recommends the following iptables rules:

    01# iptables -t mangle -A PREROUTING -p tcp -j CONNMARK --restore-mark
    02# iptables -t mangle -A PREROUTING -p tcp -m mark ! --mark 0 -j ACCEPT
    03# iptables -t mangle -A PREROUTING -p tcp -m ipp2p --ipp2p -j MARK --set-mark 1
    04# iptables -t mangle -A PREROUTING -p tcp -m mark --mark 1 -j CONNMARK --save-mark

    05# iptables -t mangle -A POSTROUTING -o eth0 -m mark --mark 1 -j CLASSIFY --set-class 1:12
    06# iptables -t mangle -A POSTROUTING -o eth1 -m mark --mark 1 -j CLASSIFY --set-class 2:12

Let's examine the above rules more carefully.

The individual packets of a P2P data stream do not all carry tell-tale signs that are identifiable as being a particular P2P application. So simply asking the ipp2p match code to mark each individual packet isn't enough because only those packets that carry these tell-tale signs will be marked. Fortunately, Netfilter provides a different type of mark -- the Connection Mark which is associated with the entry in the conntrack table rather that with the individual packet. You can see connection mark values with the `shorewall show connections` command:

    gateway:/etc/test# shorewall show connections
    Shorewall-2.5.6 Connections at gateway - Tue Oct  4 15:45:11 PDT 2005

    tcp      6 269712 ESTABLISHED src=192.168.3.8 dst=206.124.146.177 sport=50584 dport=993 packets=4899
             bytes=302282 src=206.124.146.177 dst=192.168.3.8 sport=993 dport=50584 packets=7760 bytes=10032928 [ASSURED] mark=0 use=1
    ...

Connection marks are persistent -- that is, once a connection mark is set it retains its value until the connection is terminated.

Netfilter provides features to:

1.  Mark individual packets with a numeric value.

2.  Save the current packet mark value in the connection mark.

3.  Restore the value in the connection mark to the current packet.

The strategy employed in the above rules is to mark the connection of each P2P session with a mark value of 1. That way, each packet that is part of the session can be marked using the 'Restore' function and can be classified accordingly.

1.  Rule 01# restores the connection mark into the current packet.

2.  Rule 02# tests that restored mark and if it is not equal to zero, the packet is ACCEPTed (no further processing).

3.  Rule 03# asks the ipp2p match module to examine the packet and if it is identifiable as part of a P2P session, mark the packet with value 1.

4.  Rule 04# saves the current packet mark in the conntrack table if the current mark value is 1 (in other words, if it was marked by rule 03#).

5.  Rule 05# classifies the packet to traffic shaping class 1:12 if it is going out of eth0 and has mark value 1.

6.  Rule 06# classifies the packet to traffic shaping class 2:12 if it is going out of eth1 and has mark value 1.

These are implemented in the /etc/shorewall/tcrules and /etc/shorewall/mangle files as follows:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   USER    TEST

    RESTORE:P       -               -               tcp
    CONTINUE:P      -               -               tcp     -       -       -       !0
    1:P             -               -               ipp2p   ipp2p
    SAVE:P          -               -               tcp     -       -       -       1
    1:12            -               eth0            -       -       -       -       1
    2:12            -               eth1            -       -       -       -       1

These rules do exactly the same thing as their counterparts described above.

One change that I recommend --do your marking in the FORWARD chain rather than in the PREROUTING chain:

    #ACTION         SOURCE          DEST            PROTO   DPORT   SPORT   USER    TEST

    RESTORE:F       -               -               tcp
    CONTINUE:F      -               -               tcp     -       -       -       !0
    1:F             -               -               ipp2p   ipp2p
    SAVE:F          -               -               tcp     -       -       -       1
    1:12            -               eth0            -       -       -       -       1
    2:12            -               eth1            -       -       -       -       1

It will work the same and will work with a [Multi-ISP setup](../features/MultiISP.md).
