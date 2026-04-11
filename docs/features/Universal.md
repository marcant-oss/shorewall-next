# Configuring Shorewall

Once you have installed the Shorewall software, you must configure it. The easiest way to do that is to use one of Shorewall's Sample Configurations. The Universal Configuration is one of those samples.

# What the Universal Configuration does

The Universal Shorewall configuration requires that you simply copy the configuration to `/etc/shorewall` and start Shorewall. This sample configuation:

- Allows all outgoing traffic.

- Blocks all incoming connections except:

  - Secure Shell

  - Ping

- Allows forwarding of traffic, provided that the system has more than one interface or is set up to route between networks on a single interface.

# How to Install it

The location of the sample configuration files is dependent on your distribution and [how you installed Shorewall](../reference/Install.md).

1.  If you installed using an RPM, the samples will be in the `Samples/Universal` subdirectory of the Shorewall documentation directory. If you don't know where the Shorewall documentation directory is, you can find the samples using this command:

        ~# rpm -ql shorewall-common | fgrep Universal
        /usr/share/doc/packages/shorewall/Samples/Universal
        /usr/share/doc/packages/shorewall/Samples/Universal/interfaces
        /usr/share/doc/packages/shorewall/Samples/Universal/policy
        /usr/share/doc/packages/shorewall/Samples/Universal/rules
        /usr/share/doc/packages/shorewall/Samples/Universal/zones
        ~#

2.  If you installed using the tarball, the samples are in the `Samples/Universal` directory in the tarball.

3.  If you installed using a Shorewall 4.x .deb, the samples are in `/usr/share/doc/shorewall-common/examples/Universal`.. You do not need the shorewall-doc package to have access to the samples.

Simple copy the files from the Universal directory to /etc/shorewall.

# How to Start the firewall

Before starting Shorewall for the first time, it's a good idea to stop your existing firewall. On Redhat/CentOS/Fedora, at a root prompt type:

> `service iptables stop`

If you are running SuSE, use Yast or Yast2 to stop SuSEFirewall.

Once you have Shorewall running to your satisfaction, you should totally disable your existing firewall. On /Redhat/CentOS/Fedora:

> `chkconfig --del iptables`

At a root prompt, type:

> `/sbin/shorewall start`

That's it. Shorewall will automatically start again when you reboot.

# Now that it is running, ...

## How do I stop the firewall?

At a root prompt, type:

> `/sbin/shorewall clear`

The system is now 'wide open'.

## How do I prevent it from responding to ping?

Edit `/etc/shorewall/rules` and remove the line that reads:

> Ping(ACCEPT) net \$FW

and at a root prompt, type:

> `/sbin/shorewall restart`

## How do I allow other kinds of incoming connections?

Shorewall includes a collection of macros that can be used to quickly allow or deny services. You can find a list of the macros included in your version of Shorewall using the command `ls /usr/share/shorewall/macro.*` or at a shell prompt type:

> `/sbin/shorewall show macros`

If you wish to enable connections from the Internet to your firewall and you find an appropriate macro in `/etc/shorewall/macro.*`, the general format of a rule in `/etc/shorewall/rules` is:

    #ACTION         SOURCE    DESTINATION     PROTO       DPORT
    <macro>(ACCEPT) net       $FW

<div class="important">

Be sure to add your rules after the line that reads **SECTION NEW.**

</div>

    #ACTION     SOURCE    DESTINATION     PROTO       DPORT
    Web(ACCEPT) net       $FW
    IMAP(ACCEPT)net       $FW

You may also choose to code your rules directly without using the pre-defined macros. This will be necessary in the event that there is not a pre-defined macro that meets your requirements. In that case the general format of a rule in `/etc/shorewall/rules` is:

    #ACTION   SOURCE    DESTINATION     PROTO       DPORT
    ACCEPT    net       $FW             <protocol>  <port>

    #ACTION   SOURCE    DESTINATION     PROTO       DPORT
    ACCEPT    net       $FW             tcp          80
    ACCEPT    net       $FW             tcp          143

If you don't know what port and protocol a particular application uses, see [here](ports.md).

## How do I make the firewall log a message when it disallows an incoming connection?

Shorewall does not maintain a log itself but rather relies on your [system's logging configuration](shorewall_logging.md). The following [commands](https://shorewall.org/manpages/shorewall.html) rely on knowing where Netfilter messages are logged:

- `shorewall show log` (Displays the last 20 Netfilter log messages)

- `shorewall logwatch` (Polls the log at a settable interval

- `shorewall dump` (Produces an extensive report for inclusion in Shorewall problem reports)

It is important that these commands work properly because when you encounter connection problems when Shorewall is running, the first thing that you should do is to look at the Netfilter log; with the help of [Shorewall FAQ 17](../reference/FAQ.md#faq17), you can usually resolve the problem quickly.

The Netfilter log location is distribution-dependent:

- Debian and its derivatives log Netfilter messages to `/var/log/kern.log`.

- Recent SuSE/OpenSuSE releases come preconfigured with syslog-ng and log netfilter messages to `/var/log/firewall`.

- For other distributions, Netfilter messages are most commonly logged to `/var/log/messages`.

Modify the LOGFILE setting in `/etc/shorewall/shorewall.conf` to specify the name of your log.

<div class="important">

The LOGFILE setting does not control where the Netfilter log is maintained -- it simply tells the /sbin/`shorewall` utility where to find the log.

</div>

Now, edit `/etc/shorewall/policy` and modify the line that reads:

> net all DROP

to

> net all DROP **info**

Then at a root prompt, type:

> `/sbin/shorewall reload`

## How do I prevent the firewall from forwarding connection requests?

Edit /etc/shorewall/interfaces, and remove the routeback option from the interface. e.g., change the line that reads:

> net all - dhcp,physical=+**,routeback**,optional

to

> net all - dhcp,physical=+,optional

Then at a root prompt, type:

> `/sbin/shorewall reload`
