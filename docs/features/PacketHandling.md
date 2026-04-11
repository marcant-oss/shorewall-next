# Introduction

This article will try to help you understand how packets pass through a firewall configured by Shorewall. You may find it useful to have a copy of the [Netfilter Overview](../concepts/NetfilterOverview.md) handy to refer to.

The discussion that follows assumes that you are running a current kernel (2.6.20 or later) with the [recommended options](../reference/kernel.md) included. Otherwise processing may be somewhat different from described below depending on the features supported by your kernel.

Where a packet is covered by steps in more than one of the following sections, processing occurs in the order in which the sections appear.

# Packets Entering the Firewall from Outside

Certain processing occurs on packets entering the firewall from the outside that don't occur for packets that originate on the firewall itself.

- The TOS field in the packet is conditionally altered based on the contents of your `/etc/shorewall/tos` file. This occurs in the **pretos** chain of the *mangle* table.

- Packets are marked based on the contents of your `/etc/shorewall/mangle` (`/etc/shorewall/tcrules`) file and the setting of MARK_IN_FORWARD_CHAIN in `/etc/shorewall/shorewall.conf`. This occurs in the **tcpre** chain of the *mangle* table.

- The destination IP address and/or port number are rewritten according to DNAT\[-\] and REDIRECT\[-\] rules in `/etc/shorewall/rules`. For new connection requests, this occurs in a chain in the *nat* table called ***zone*\_dnat** where *zone* is the zone where the request originated. For packets that are part of an already established connection, the destination rewriting takes place without any involvement of a Netfilter rule.

- If the destination was not rewritten in the previous step then it may be rewritten based on entries in /etc/shorewall/nat. For new connection requests, this occurs in a *nat* table chain called ***interface*\_in** where *interface* is the interface on which the packet entered the firewall. For packets that are part of an already established connection, the destination rewriting takes place without any involvement of a Netfilter rule.

- The packet passes through the accounting rules defined in `/etc/shorewall/accounting`.

- If FASTACCEPT=Yes in `shorewall.conf` and the packet is part of or related to an existing connection, it is accepted.

- The packet is processed according to your [Blacklisting configuration](../legacy/blacklisting_support.md) (dynamic blacklist first). If BLACKLISTNEWONLY=Yes in `/etc/shorewall/shorewall.conf` then only new connection requests are processed. Processing occurs in the dynamic and blacklst

- If the interface on which the packet entered the firewall has the *nosmurfs* option specified in `/etc/shorewall/interfaces`, then if the packet is a new connection request is checked for being a smurf in the *filter* table's **smurfs** chain.

- If:

  - the packet will be processed by the firewall itself

  - the interface on which the packet arrived has the *dhcp* option in `/etc/shorewall/interfaces`.

  - packet's protocol is UDP with destination port 67 or 68.

  then the packet is ACCEPTed in the *filter* table's ***interface*\_in** chain (for example, eth0_in). Note that if the interface is its associated zones only interface, then the ***interface*\_in** chain is optimized away and its rules are transferred to another chain.

- If the interface on which the packet entered the firewall has the *tcpflags* option specified in `/etc/shorewall/interfaces` and the packet's protocol is TCP then the TCP flags are checked by the **tcpflags** chain (*filter* table).

# All Packets

Regardless of whether the packet originated on the firewall or came from outside, certain processing steps are common.

- Packets are marked based on the contents of your `/etc/shorewall/mangle` file and the setting of MARK_IN_FORWARD_CHAIN in `/etc/shorewall/shorewall.conf`. This occurs in the **tcfor** chain of the *mangle* table.

  The remaining processing in this list occurs in the *filter* table.

- If either the host sending the packet or the host to which the packet is addressed is not in any defined zone then the all-\>all policy is applied to the packet (including logging). This can occur in the INPUT, FORWARD or OUTPUT chains.

- If the packet is part of an established connection or is part of a related connection then no further processing takes place in the filter table (**zone1*2*zone2** chain where *zone1* is the source zone and *zone2* is the destination zone).

- The packet is processed according to your `/etc/shorewall/rules` file. This happens in chains named ****zone1*2*zone2**** chain where *zone1* is the source zone and *zone2* is the destination zone. Note that in the presence of [nested or overlapping zones](https://shorewall.org/manpages/shorewall-nested.html) and CONTINUE policies, a packet may go through more than one of these chains.

- Note: If the packet gets to this step, it did not match any rule.

  If the applicable policy has a [common action](../concepts/Actions.md) then that action is applied (chain has the same name as the action).

- If the applicable policy has logging specified, the packet is logged.

- The policy is applied (the packet is accepted, dropped or rejected).

# Packets Originating on the Firewall

Packets that originate on the firewall itself undergo additional processing.

- The TOS field in the packet is conditionally altered based on the contents of your `/etc/shorewall/tos` file. This occurs in the **outtos** chain of the *mangle* table.

- Packets are marked based on the contents of your `/etc/shorewall/mangle` file. This occurs in the **tcout** chain of the *mangle* table.

# Packets Leaving the Firewall

Packets being sent to another host undergo additional processing.

<div class="note">

The source IP address only gets rewritten by the first matching rule below.

</div>

- The source IP address may be rewritten according to DNAT rules that specify SNAT. If this is a new connection request, then the rewriting occurs in a *nat* table chain called ***zone*\_snat** where *zone* is the destination zone. For packets that are part of an already established connection, the destination rewriting takes place without any involvement of a Netfilter rule.

- If FASTACCEPT=Yes in `shorewall.conf` and the packet is part of or related to an existing connection, it is accepted.

- The source IP address may be rewritten according to an entry in the `/etc/shorewall/nat` file. If this is a new connection request, then the rewriting occurs in a *nat* table chain called ***interface*\_snat** where *interface* is the interface on which the packet will be sent. For packets that are part of an already established connection, the destination rewriting takes place without any involvement of a Netfilter rule.

- The source IP address may be rewritten according to an entry in the `/etc/shorewall/masq` or `/etc/shorewall/snat` file (Shorewall 5.0.14 or later). If this is a new connection request, then the rewriting occurs in a *nat* table chain called ***interface*\_masq** where *interface* is the interface on which the packet will be sent. For packets that are part of an already established connection, the destination rewriting takes place without any involvement of a Netfilter rule.
