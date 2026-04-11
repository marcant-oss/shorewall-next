<div class="caution">

**This article applies to Shorewall 3.0 and later. If you are running a version of Shorewall earlier than Shorewall 3.0.0 then please see the documentation for that release.**

</div>

Beginning with Shorewall version 1.4.8, Shorewall can interface to ftwall. **ftwall** is part of the [p2pwall project](http://p2pwall.sourceforge.net) and is a user-space filter for applications based on the “Fast Track” peer to peer protocol. Applications using this protocol include Kazaa, KazaaLite, iMash and Grokster.

To filter traffic from your “loc” zone with ftwall, you insert the following rules in the ESTABLISHED section of /etc/shorewall/rules file after any DROP or REJECT rules whose source is the “loc” zone.

            #ACTION SOURCE     DEST       PROTO
            QUEUE   loc        net        tcp
            QUEUE   loc        net        udp
            QUEUE   loc        $FW        udp

Now simply configure ftwall as described in the ftwall documentation and restart Shorewall.

<div class="tip">

There are ftwall init scripts for use with SUSE and Debian Linux at [http://shorewall.org/pub/shorewall/contrib/ftwall](https://shorewall.org/pub/shorewall/contrib/ftwall).

</div>

Shorewall versions 2.2.0 and later also include support for the ipp2p match facility which can be use to control P2P traffic. See the [Shorewall IPP2P documentation](IPP2P.md) for details.
