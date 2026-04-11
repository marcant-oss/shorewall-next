# “shorewall start” and “shorewall restart” Errors

If the error is detected by the Shorewall compiler, it should be fairly obvious where the problem was found. Each error message includes the configuration file name and line number where the error was detected and often gives the particular item in error. The item is either enclosed in parentheses or is at the end following a colon (":").

Example:

    gateway:~/test # shorewall restart .
    Compiling...
       ERROR: Invalid ICMP Type (0/400) : /root/test/rules (line 19)
    gateway:~/test # 

In this case, line 19 in the rules file specified an invalid ICMP Type (0/400).

Additional information about the error can be obtained using the 'debug' keyword (Shorewall 4.4.19 and earlier) or using the (-T) option.

Example (4.4.19 and earlier):

    gateway:~/test # shorewall debug restart
    Compiling...
       ERROR: Invalid ICMP Type (0/400) : /root/test/rules (line 19) at /usr/share/shorewall/Shorewall/Config.pm line 338
            Shorewall::Config::fatal_error('Invalid ICMP Type (0/400)') called at /usr/share/shorewall/Shorewall/Chains.pm line 885
            Shorewall::Chains::validate_icmp('0/400') called at /usr/share/shorewall/Shorewall/Chains.pm line 949
            Shorewall::Chains::do_proto('icmp', '0/400', '-') called at /usr/share/shorewall/Shorewall/Rules.pm line 1055
            Shorewall::Rules::process_rule1('ACCEPT', 'loc', 'net', 'icmp', '0/400', '-', '-', '-', '-', ...) called at /usr/share/shorewall/Shorewall/Rules.pm line 1290
            Shorewall::Rules::process_rule('ACCEPT', 'loc', 'net', 'icmp', '0/400', '-', '-', '-', '-', ...) called at /usr/share/shorewall/Shorewall/Rules.pm line 1336
            Shorewall::Rules::process_rules() called at /usr/share/shorewall/Shorewall/Compiler.pm line 799
            Shorewall::Compiler::compiler('/var/lib/shorewall/.restart', '/root/test', 0, 4) called at /usr/share/shorewall/compiler.pl line 86
    gateway:~/test # 

Example (4.4.20 and later):

    gateway:~/test # shorewall restart -T
    Compiling...
       ERROR: Invalid ICMP Type (0/400) : /root/test/rules (line 19) at /usr/share/shorewall/Shorewall/Config.pm line 338
            Shorewall::Config::fatal_error('Invalid ICMP Type (0/400)') called at /usr/share/shorewall/Shorewall/Chains.pm line 885
            Shorewall::Chains::validate_icmp('0/400') called at /usr/share/shorewall/Shorewall/Chains.pm line 949
            Shorewall::Chains::do_proto('icmp', '0/400', '-') called at /usr/share/shorewall/Shorewall/Rules.pm line 1055
            Shorewall::Rules::process_rule1('ACCEPT', 'loc', 'net', 'icmp', '0/400', '-', '-', '-', '-', ...) called at /usr/share/shorewall/Shorewall/Rules.pm line 1290
            Shorewall::Rules::process_rule('ACCEPT', 'loc', 'net', 'icmp', '0/400', '-', '-', '-', '-', ...) called at /usr/share/shorewall/Shorewall/Rules.pm line 1336
            Shorewall::Rules::process_rules() called at /usr/share/shorewall/Shorewall/Compiler.pm line 799
            Shorewall::Compiler::compiler('/var/lib/shorewall/.restart', '/root/test', 0, 4) called at /usr/share/shorewall/compiler.pl line 86
    gateway:~/test # 

This information is useful to Shorewall support if you need to [file a problem report](../legacy/support.md).

The end of the compile phase is signaled by a message such as the following:

    Shorewall configuration compiled to /var/lib/shorewall/.restart

Errors occurring past that point are said to occur at run-time because they occur during the running of the compiled firewall script (/var/lib/shorewall/.restart in the case of the above message).

One common run-time failure is that the iptables-restore program encounters an error. This will produce an error such as the following:

    ...
    Restarting Shorewall....
    iptables-restore v1.3.6: No chain/target/match by that name
    Error occurred at line: 83
    Try `iptables-restore -h' or 'iptables-restore --help' for more information.
       ERROR: iptables-restore Failed. Input is in /var/lib/shorewall/.iptables-restore-input
    Restoring Shorewall...
    Shorewall restored from /var/lib/shorewall/restore
    Terminated
    gateway:~/test # 

A look at /var/lib/shorewall/restore at line 83 might show something like the following:

    -A reject -p tcp -j REJECT --reject-with tcp-reset

In this case, the user had compiled his own kernel and had forgotten to include REJECT target support (see [kernel.htm](kernel.md)).

You may also include the word **debug** as the first argument to the `/sbin/shorewall` and `/sbin/shorewall-lite` commands.

    shorewall debug restart

In most cases, **debug** is a synonym for **trace**. The exceptions are:

- **debug** is ignored by the Shorewall compiler.

- **debug** causes altered behavior of generated scripts. These scripts normally use`iptables-restore` to install the Netfilter ruleset but with **debug**, the commands normally passed to `iptables-restore` in its input file are passed individually to `iptables`. This is a diagnostic aid which allows identifying the individual command that is causing `iptables-restore` to fail; it should be used when iptables-restore fails when executing a `COMMIT` command.

<div class="warning">

The **debug** feature is strictly for problem analysis. When **debug** is used:

1.  The firewall is made 'wide open' before the rules are applied.

2.  The `stoppedrules (routestopped)` file is not consulted.

3.  The rules are applied in the canonical `iptables-restore` order. So if you need critical hosts to be always available during start/restart, you may not be able to use **debug**.

</div>

In other run-time failure cases:

- Make a note of the error message that you see.

- `shorewall debug start 2> /tmp/trace`

- Look at the `/tmp/trace` file and see if that helps you determine what the problem is. Be sure you find the place in the log where the error message you saw is generated -- you should find the message near the end of the log.

- If you still can't determine what's wrong then see the [support page](../legacy/support.md).

# Your Network Environment

Many times when people have problems with Shorewall, the problem is actually an ill-conceived network setup. Here are several popular snafus:

- Port Forwarding where client and server are in the same subnet. See [FAQ 2](FAQ.md#faq2).

- Trying to test net-\>loc DNAT rules from inside your firewall. You must test these rules from **outside** your firewall.

- Multiple interfaces connected to the same HUB or Switch. Given the way that the Linux kernel respond to ARP “who-has” requests, this type of setup **does NOT work the way that you expect it to**. You can test using this kind of configuration if you specify the **arp_filter** option or the **arp_ignore** option in `/etc/shorewall/interfaces` for all interfaces connected to the common hub/switch. **Using such a setup with a production firewall is strongly recommended against**.

# New Device Doesn't Work?

If you have just added a new device such as VOIP and it doesn't work, be sure that you have assigned it an IP address in your local network and that its default gateway has been set to the IP address of your internal interface. For many of these devices, the simplest solution is to run a DHCP server; running it on your firewall is fine — be sure to set the **dhcp** option on your internal interface in [/etc/shorewall/interfaces](https://shorewall.org/manpages/shorewall-interfaces.html).

# Connection Problems

One very important thing to remember is that not all connection problems are Shorewall configuration problems. If the connection that is giving you problems is to or from the firewall system or if it doesn't rely on NAT or Proxy ARP then you can often eliminate Shorewall using a simple test:

- `/sbin/shorewall clear`

- Try the connection. If it works then the problem is in your Shorewall configuration; if the connection still doesn't work then the problem is not with Shorewall or the way that it is configured.

- Be sure to `/sbin/shorewall start` after the test.

If you still suspect Shorewall and the appropriate policy for the connection that you are trying to make is ACCEPT, please DO NOT ADD ADDITIONAL ACCEPT RULES TRYING TO MAKE IT WORK. Such additional rules will NEVER make it work, they add clutter to your rule set and they represent a big security hole in the event that you forget to remove them later.

I also recommend against setting all of your policies to ACCEPT in an effort to make something work. That robs you of one of your best diagnostic tools - the “Shorewall” messages that Netfilter will generate when you try to connect in a way that isn't permitted by your rule set.

Check your log (“`/sbin/shorewall show log`”). If you don't see Shorewall messages, then your problem is probably NOT a Shorewall problem. If you DO see packet messages, it may be an indication that you are missing one or more rules -- see [FAQ 17](FAQ.md#faq17).

While you are troubleshooting, it is a good idea to clear LOGLIMIT in `/etc/shorewall/shorewall.conf`:

    LOGLIMIT=

This way, you will see all of the log messages being generated (be sure to restart shorewall after clearing thIs variable).

    Jun 27 15:37:56 gateway kernel: Shorewall:all2all:REJECT:IN=eth2
                                    OUT=eth1 SRC=192.168.2.2
                                    DST=192.168.1.3 LEN=67 TOS=0x00
                                    PREC=0x00 TTL=63 ID=5805 DF
                                    PROTO=UDP SPT=1803 DPT=53 LEN=47

Let's look at the important parts of this message:

- all2all:REJECT - This packet was REJECTed out of the all2all chain -- the packet was rejected under the “all”-\>“all” REJECT policy (see [FAQ 17](FAQ.md#faq17)).

- IN=eth2 - the packet entered the firewall via eth2

- OUT=eth1 - if accepted, the packet would be sent on eth1

- SRC=192.168.2.2 - the packet was sent by 192.168.2.2

- DST=192.168.1.3 - the packet is destined for 192.168.1.3

- PROTO=UDP - UDP Protocol

- DPT=53 - DNS

In this case, 192.168.2.2 was in the “dmz” zone and 192.168.1.3 is in the “loc” zone. I was missing the rule:

    #ACTION   SOURCE           DEST                  PROTO   DEST
    #                                                        PORT(S)
    ACCEPT    dmz              loc                   udp     53

# Ping Problems

Either can't ping when you think you should be able to or are able to ping when you think that you shouldn't be allowed? Shorewall's “Ping” Management is [described here](../features/ping.md). Here are a couple of tips:

- Remember that Shorewall doesn't automatically allow ICMP type 8 (“ping”) requests to be sent between zones. If you want pings to be allowed between zones, you need a rule of the form:

      #ACTION  SOURCE          DEST                  PROTO   DEST
      #                                                      PORT(S)
      Ping(ACCEPT)<source zone> <destination zone>

  The ramifications of this can be subtle. For example, if you have the following in `/etc/shorewall/nat`:

      #EXTERNAL   INTERFACE  INTERNAL
      10.1.1.2 eth0       130.252.100.18

  and you ping 130.252.100.18, unless you have allowed icmp type 8 between the zone containing the system you are pinging from and the zone containing 10.1.1.2, the ping requests will be dropped.

- Ping requests are subject to logging under your policies. So ping floods can cause an equally big flood of log messages. To eliminate these, as the last rule in your /etc/shorewall/rules file add:

      #ACTION  SOURCE          DEST                  PROTO   DEST
      #                                                      PORT(S)
      Ping(DROP)net             all

# Some Things to Keep in Mind

- **You cannot test your firewall from the inside**. Just because you send requests to your firewall external IP address does not mean that the request will be associated with the external interface or the “net” zone. Any traffic that you generate from the local network will be associated with your local interface and will be treated as loc-\>fw traffic.

- **IP addresses are properties of systems, not of interfaces**. It is a mistake to believe that your firewall is able to forward packets just because you can ping the IP address of all of the firewall's interfaces from the local network. The only conclusion you can draw from such pinging success is that the link between the local system and the firewall works and that you probably have the local system's default gateway set correctly.

- **All IP addresses configured on firewall interfaces are in the \$FW (fw) zone**. If 192.168.1.254 is the IP address of your internal interface then you can write “**\$FW:192.168.1.254**” in a rule but you may not write “**loc:192.168.1.254**”. Similarly, it is nonsensical to add 192.168.1.254 to the **loc** zone using an entry in `/etc/shorewall/hosts`.

- **Reply packets do NOT automatically follow the reverse path of the one taken by the original request**. All packets are routed according to the routing table of the host at each step of the way. This issue commonly comes up when people install a Shorewall firewall parallel to an existing gateway and try to use DNAT through Shorewall without changing the default gateway of the system receiving the forwarded requests. Requests come in through the Shorewall firewall where the destination IP address gets rewritten but replies go out unmodified through the old gateway.

- **Shorewall itself has no notion of inside or outside**. These concepts are embodied in how Shorewall is configured.

# Other Gotchas

- Seeing rejected/dropped packets logged out of the INPUT or FORWARD chains? This means that:

  1.  your zone definitions are screwed up and the host that is sending the packets or the destination host isn't in any zone (using an [`/etc/shorewall/hosts`](https://shorewall.org/manpages/shorewall-hosts.html) file are you?); or

  2.  the source and destination hosts are both connected to the same interface and you don't have a policy or rule for the source zone to or from the destination zone or you haven't set the **routeback** option for the interface in [`/etc/shorewall/interfaces`](https://shorewall.org/manpages/shorewall-interfaces.html).

  3.  You have connected two firewall interfaces (from different zones) to the same hub or switch.

- If you specify “routefilter” for an interface, that interface must be up prior to starting the firewall.

- Is your routing correct? For example, internal systems usually need to be configured with their default gateway set to the IP address of their nearest firewall interface. One often overlooked aspect of routing is that in order for two hosts to communicate, the routing between them must be set up **in both directions**. So when setting up routing between **A** and **B**, be sure to verify that the route from **B** back to **A** is defined and correct.

- Do you have your kernel properly configured? [Click here to see kernel configuration information](kernel.md).

# Still Having Problems?

See the [Shorewall Support Page](../legacy/support.md).
