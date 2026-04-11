<div class="caution">

**This article applies to Shorewall 3.0 and later. If you are running a version of Shorewall earlier than Shorewall 3.0.0 then please see the documentation for that release.**

</div>

<div class="note">

Enabling “ping” will also enable ICMP-based *traceroute*. For UDP-based traceroute, see the [port information page](ports.md).

</div>

# 'Ping' Management

In Shorewall , ICMP echo-requests are treated just like any other connection request.

In order to accept ping requests from zone z1 to zone z2 where the policy for z1 to z2 is not ACCEPT, you need a rule in `/etc/shorewall/rules` of the form:

    #ACTION      SOURCE    DEST     PROTO    DPORT
    Ping(ACCEPT) z1        z2

To permit ping from the local zone to the firewall:

    #ACTION      SOURCE    DEST     PROTO    DPORT
    Ping(ACCEPT) loc       $FW

If you would like to accept “ping” by default even when the relevant policy is DROP or REJECT, copy `/usr/share/shorewall/action.Drop` or `/usr/share shorewall/action.Reject` respectively to `/etc/shorewall` and simply add this line to the copy:

    Ping(ACCEPT)

With that rule in place, if you want to ignore “ping” from z1 to z2 then you need a rule of the form:

    #ACTION      SOURCE    DEST     PROTO    DPORT
    Ping(DROP)   z1        z2

To drop ping from the Internet, you would need this rule in `/etc/shorewall/rules`:

    #ACTION    SOURCE    DEST     PROTO    DPORT
    Ping(DROP) net       $FW

Note that the above rule may be used without changing the action files to prevent your log from being flooded by messages generated from remote pinging.
