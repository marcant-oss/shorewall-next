<div class="note">

The techniques described in this article were superseded in Shorewall 4.5.19 with the introduction of [Shorewall Events](../concepts/Events.md).

</div>

<div class="note">

The feature described in this article require '[Recent Match](http://snowman.net/projects/ipt_recent/)' in your iptables and kernel. See the output of `shorewall show capabilities` to see if you have that match.

</div>

# What is Port Knocking?

Port knocking is a technique whereby attempting to connect to port A enables access to port B from that same host. For the example on which this article is based, see <http://www.soloport.com/iptables.html> which should be considered to be part of this documentation.

# Implementing Port Knocking in Shorewall

In order to implement this solution, your iptables and kernel must support the 'recent match' extension (see [FAQ 42](../reference/FAQ.md#faq42)).

In this example:

1.  Attempting to connect to port 1600 enables SSH access. Access is enabled for 60 seconds.

2.  Attempting to connect to port 1601 disables SSH access (note that in the article linked above, attempting to connect to port 1599 also disables access. This is an port scan defence as explained in the article).

To implement that approach:

1.  Add an action named SSHKnock (see the [Action documentation](../concepts/Actions.md)). Leave the `action.SSHKnock` file empty.

2.  Create /etc/shorewall/SSHKnock with the following contents.

        use Shorewall::Chains;

        if ( $level ) {
            log_rule_limit( $level, 
                            $chainref, 
                            'SSHKnock',
                            'ACCEPT',
                            '',
                            $tag,
                            'add',
                            '-p tcp --dport 22   -m recent --rcheck --name SSH ' );

            log_rule_limit( $level,
                            $chainref,
                            'SSHKnock',
                            'DROP',
                            '',
                            $tag,
                            'add',
                            '-p tcp ! --dport 22 ' );
        }

        add_rule( $chainref, '-p tcp --dport 22   -m recent --rcheck --seconds 60 --name SSH          -j ACCEPT' );
        add_rule( $chainref, '-p tcp --dport 1599 -m recent                       --name SSH --remove -j DROP' );
        add_rule( $chainref, '-p tcp --dport 1600 -m recent                       --name SSH --set    -j DROP' );
        add_rule( $chainref, '-p tcp --dport 1601 -m recent                       --name SSH --remove -j DROP' );

        1;

3.  Now if you want to protect SSH access to the firewall from the Internet, add this rule in `/etc/shorewall/rules`:

        #ACTION          SOURCE            DEST           PROTO       DPORT
        SSHKnock         net               $FW            tcp         22,1599,1600,1601

    If you want to log the DROPs and ACCEPTs done by SSHKnock, you can just add a log level as in:

        #ACTION          SOURCE            DEST           PROTO       DPORT
        SSHKnock:info    net               $FW            tcp         22,1599,1600,1601

4.  Assume that you forward port 22 from external IP address 206.124.146.178 to internal system 192.168.1.5. In /etc/shorewall/rules:

        #ACTION          SOURCE            DEST            PROTO       DPORT         SPORT       ORIGDEST
        DNAT-            net               192.168.1.5     tcp         22            -           206.124.146.178
        SSHKnock         net               $FW             tcp         1599,1600,1601
        SSHKnock         net               loc:192.168.1.5 tcp         22            -           206.124.146.178

    <div class="note">

    You can use SSHKnock with DNAT on earlier releases provided that you omit the ORIGDEST entry on the second SSHKnock rule. This rule will be quite secure provided that you specify 'routefilter' on your external interface and have NULL_ROUTE_RFC1918=Yes in `shorewall.conf`.

    </div>

For another way to implement Port Knocking, see the [Manual Chain](../concepts/ManualChains.md) documentation.

# Limiting Per-IP Connection Rate

This information has been moved to the [Actions article](../concepts/Actions.md#Limit).
