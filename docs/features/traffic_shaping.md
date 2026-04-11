<div class="important">

Traffic shaping is complex and the Shorewall community is not well equipped to answer traffic shaping questions. So if you are the type of person who needs "insert tab A into slot B" instructions for everything that you do, then please don't try to implement traffic shaping using Shorewall. You will just frustrate yourself and we won't be able to help you.

</div>

<div class="warning">

Said another way, reading just Shorewall documentation is not going to give you enough background to use this material.

At a minimum, you will need to refer to at least the following additional information:

- *The LARTC HOWTO*: <http://www.lartc.org>

- T*he HTB User's Guide*: <http://luxik.cdi.cz/~devik/qos/htb/manual/userg.htm>

- *HFSC Scheduling with Linux*: <http://linux-ip.net/articles/hfsc.en/>

- Some of the documents listed at <http://www.netfilter.org/documentation/index.html#documentation-howto>. The tutorial by Oskar Andreasson is particularly good.

- The output of `man iptables`

</div>

# Introduction

Beginning with Shorewall 4.4.6, Shorewall includes two separate implementations of traffic shaping. This document describes the original implementation which is complex and difficult to configure. A much simpler version is described in [Simple Traffic Shaping/Control](simple_traffic_shaping.md) and is highly recommended unless you really need to delay certain traffic passing through your firewall.

Shorewall has builtin support for traffic shaping and control. This support does not cover all options available (and especially all algorithms that can be used to queue traffic) in the Linux kernel but it should fit most needs. If you are using your own script for traffic control and you still want to use it in the future, you will find information on how to do this, [later in this document](#owntcstart). But for this to work, you will also need to enable traffic shaping in the kernel and Shorewall as covered by the next sections.

# Linux traffic shaping and control

This section gives a brief introduction of how controlling traffic with the Linux kernel works. Although this might be enough for configuring it in the Shorewall configuration files, we strongly recommend that you take a deeper look into the [Linux Advanced Routing and Shaping HOWTO](http://lartc.org/howto/). At the time of writing this, the current version is 1.0.0.

Since kernel 2.2, Linux has extensive support for controlling traffic. You can define different algorithms that are used to queue the traffic before it leaves an interface. The standard one is called pfifo and is (as the name suggests) of the type First In First out. This means, that it does not shape anything, if you have a connection that eats up all your bandwidth, this queuing algorithm will not stop it from doing so.

For Shorewall traffic shaping we use three algorithms: HTB (Hierarchical Token Bucket), HFSC (Hierarchical Fair Service Curves) and SFQ (Stochastic Fairness Queuing). SFQ is easy to explain: it just tries to track your connections (tcp or udp streams) and balances the traffic between them. This normally works well. HTB and HFSC allow you to define a set of classes, and you can put the traffic you want into these classes. You can define minimum and maximum bandwidth settings for those classes and order them hierarchically (the less prioritized classes only get bandwidth if the more important have what they need). Additionally, HFSC allows you to specify the maximum queuing delay that a packet may experience. Shorewall builtin traffic shaping allows you to define these classes (and their bandwidth limits), and it uses SFQ inside these classes to make sure, that different data streams are handled equally. If SFQ's default notion of a 'stream' doesn't work well for you, you can change it using the **flow** option described [below](#tcclasses).

You can shape incoming traffic through use of an Intermediate Functional Block (IFB) device. [See below](#IFB). **But beware: using an IFB can result in queues building up both at your ISPs router and at your own.**

You shape and control outgoing traffic by assigning the traffic to classes. Each class is associated with exactly one network interface and has a number of attributes:

1.  PRIORITY - Used to give preference to one class over another when selecting a packet to send. The priority is a numeric value with 1 being the highest priority, 2 being the next highest, and so on.

2.  RATE - The minimum bandwidth this class should get, when the traffic load rises. Classes with a higher priority (lower PRIORITY value) are served even if there are others that have a guaranteed bandwidth but have a lower priority (higher PRIORITY value).

3.  CEIL - The maximum bandwidth the class is allowed to use when the link is idle.

4.  MARK - Netfilter has a facility for marking packets. Packet marks have a numeric value which is limited in Shorewall to the values 1-255 (1-16383 if you set WIDE_TC_MARKS=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5) ). You assign packet marks to different types of traffic using entries in the `/etc/shorewall/mangle` file (Shorewall 4.6.0 or later) or `/etc/shorewall/tcrules` (Prior to Shorewall 4.6.0).

    <div class="note">

    In Shorewall 4.4.26, WIDE_TC_MARKS was superseded by TC_BITS which specifies the width in bits of the traffic shaping mark field. The default is based on the setting of WIDE_TC_MARKS so as to provide upward compatibility. See the [Packet Marking using /etc/shorewall/mangle](PacketMarking.md#Values) article.

    </div>

One class for each interface must be designated as the default class. This is the class to which unmarked traffic (packets to which you have not assigned a mark value in `/etc/shorewall/mangle`) is assigned.

Netfilter also supports a mark value on each connection. You can assign connection mark values in `/etc/shorewall/mangle` (`/etc/shorewall/tcrules`), you can copy the current packet's mark to the connection mark (SAVE), or you can copy the connection mark value to the current packet's mark (RESTORE). For more information, see [this article](PacketMarking.md).

# Enable TC support in Shorewall

You need this support whether you use the builtin support or whether you provide your own tcstart script.

To enable the builtin traffic shaping and control in Shorewall, you have to do the following:

- Set **TC_ENABLED** to "**Internal**" in /etc/shorewall/shorewall.conf. Setting **TC_ENABLED=Yes** causes Shorewall to look for an external tcstart file (See [a later section](#tcstart) for details).

- Setting **CLEAR_TC** parameter in /etc/shorewall/shorewall.conf to **Yes** will clear the traffic shaping configuration during Shorewall \[re\]start and Shorewall stop. This is normally what you want when using the builtin support (and also if you use your own tcstart script)

- The other steps that follow depend on whether you use your own script or the builtin solution. They will be explained in the following sections.

# Using builtin traffic shaping/control

Shorewall's builtin traffic shaping feature provides a thin layer on top of the ingress qdesc, HTB and SFQ. That translation layer allows you to:

- Define HTB and/or HFSC classes using Shorewall-style column-oriented configuration files.

- Integrate the reloading of your traffic shaping configuration with the reloading of your packet-filtering and marking configuration.

- Assign traffic to HTB or HFSC classes by TOS value.

- Assign outgoing TCP ACK packets to an HTB or HFSC class.

- Assign traffic to HTB and/or HFSC classes based on packet mark value or based on packet contents.

- Throttle incoming traffic

- Use an *Intermediate functional block* (IFB) to shape incoming traffic

Those few features are really all that builtin traffic shaping/control provides; consequently, you need to understand HTB and/or HFSC and Linux traffic shaping as well as Netfilter packet marking in order to use the facility. Again, please see the links at top of this article.

For defining bandwidths (for either devices or classes) please use kbit or kbps (for Kilobytes per second) and make sure there is **NO** space between the number and the unit (it is 100kbit **not** 100 kbit). Using mbit, mbps or a raw number (which means bytes) could be used, but note that only integer numbers are supported (0.5 is **not valid**).

**To properly configure the settings for your devices you need to find out the real up- and downstream rates you have**. This is especially the case, if you are using a DSL connection or one of another type that do not have a guaranteed bandwidth. Don't trust the values your provider tells you for this; especially measuring the real download speed is important! There are several online tools that help you find out; search for "dsl speed test" on google (For Germany you can use [arcor speed check](http://www.speedcheck.arcor.de/cgi-bin/speedcheck.cgi)). Be sure to choose a test site located near you.

## /etc/shorewall/tcdevices

This file allows you to define the incoming and outgoing bandwidth for the devices you want traffic shaping to be enabled. That means, if you want to use traffic shaping for a device, you have to define it here. For additional information, see [shorewall-tcdevices](https://shorewall.org/manpages/shorewall-tcdevices.html) (5).

Columns in the file are as follows:

- INTERFACE - Name of interface. Each interface may be listed only once in this file. You may NOT specify the name of an alias (e.g., eth0:0) here; see [FAQ \#18](../reference/FAQ.md#faq18). You man NOT specify wildcards here, e.g. if you have multiple ppp interfaces, you need to put them all in here! Shorewall will determine if the device exists and will only configure the device if it does exist. If it doesn't exist or it is DOWN, the following warning is issued:

  **WARNING: Device \<device name\> is not in the UP state -- traffic-shaping configuration skipped**

  Shorewall assigns a sequential interface number to each interface (the first entry in `/etc/shorewall/tcdevices` is interface 1, the second is interface 2 and so on) You can also explicitly specify the interface number by prefixing the interface name with the number and a colon (":"). Example: 1:eth0.

  <div class="warning">

  Device numbers are expressed in hexidecimal. So the device following 9 is A, not 10.

  </div>

- IN-BANDWIDTH - The incoming Bandwidth of that interface. Please note that when you use this column, you are not traffic shaping incoming traffic, as the traffic is already received before you could do so. This Column allows you to define the maximum traffic allowed for this interface in total, if the rate is exceeded, the excess packets are dropped. You want this mainly if you have a DSL or Cable Connection to avoid queuing at your providers side. If you don't want any traffic to be dropped set this to a value faster than your interface maximum rate, or to 0 (zero).

  To determine the optimum value for this setting, we recommend that you start by setting it significantly below your measured download bandwidth (20% or so). While downloading, measure the *ping* response time from the firewall to the upstream router as you gradually increase the setting.The optimal setting is at the point beyond which the *ping* time increases sharply as you increase the setting.

  <div class="note">

  For fast lines, the actually download speed may be well below what you specify here. If you have this problem, then follow the bandwidth with a ":" and a burst size. The default burst is 10kb, but on my 50mbit line, I specify 200kb. (50mbit:200kb).

  </div>

  <div class="caution">

  Incoming IPSec traffic traverses traffic shaping twice - firs as encrypted and encapsulated ESP packets and then en clair. As a result, incoming bandwidth can be significantly less than specified if IPSEC packets form a significant part of inoming traffic.

  </div>

- OUT-BANDWIDTH - Specify the outgoing bandwidth of that interface. This is the maximum speed your connection can handle. It is also the speed you can refer as "full" if you define the tc classes. Outgoing traffic above this rate will be dropped.

- OPTIONS — A comma-separated list of options from the following list:

  **classify**  
  If specified, classification of traffic into the various classes is done by CLASSIFY entries in `/etc/shorewall/mangle` (`/etc/shorewall/tcrules`) or by entries in `/etc/shorewall/tcfilters`. No MARK value will be associated with classes on this interface.

  **hfsc**  
  Shorewall normally uses the Hierarchical Token Bucket (HTB) queuing discipline. When `hfsc` is specified, the Hierarchical Fair Service Curves (HFSC) discipline is used instead.

  **linklayer**  
  Added in Shorewall 4.5.6. Type of link (ethernet, atm, adsl). When specified, causes scheduler packet size manipulation as described in tc-stab (8). When this option is given, the following options may also be given after it:

  **mtu**=\<mtu\>  
  The device MTU; default 2048 (will be rounded up to a power of two)

  **mpu**=\<mpubytes\>  
  Minimum packet size used in calculations. Smaller packets will be rounded up to this size

  **tsize**=\<tablesize\>  
  Size table entries; default is 512

  **overhead**=\<overheadbytes\>  
  Number of overhead bytes per packet

  **connmark**  
  Added in Shorewall 5.2.7. May be specified on IFB devices to enable use of firewall marks to select the appropriate traffic shaping class.

- REDIRECTED INTERFACES — Entries are appropriate in this column only if the device in the INTERFACE column names a [Intermediate Functional Block (IFB)](#IFB). It lists the physical interfaces that will have their input shaped using classes defined on the IFB. Neither the IFB nor any of the interfaces listed in this column may have an IN-BANDWIDTH specified. You may specify zero (0) or a dash ("-:) in the IN-BANDWIDTH column.

  IFB devices automatically get the **classify** option unless the **connmark** option is specified.

Suppose you are using PPP over Ethernet (DSL) and ppp0 is the interface for this. The device has an outgoing bandwidth of 500kbit and an incoming bandwidth of 6000kbit

    #INTERFACE    IN-BANDWITH      OUT-BANDWIDTH
    ppp0           6000kbit         500kbit

## /etc/shorewall/tcclasses

This file allows you to define the actual classes that are used to split the outgoing traffic. For additional information, see [shorewall-tcclasses](https://shorewall.org/manpages/shorewall-tcclasses.html) (5).

- INTERFACE - Name of interface. Users may also specify the interface number. Must match the name (or number) of an interface with an entry in `/etc/shorewall/tcdevices`. If the interface has the **classify** option in `/etc/shorewall/tcdevices`, then the interface name or number must be followed by a colon and a class number. Examples: eth0:1, 4:9. Class numbers must be unique for a given interface. Normally, all classes defined here are sub-classes of a root class that is implicitly defined from the entry in [shorewall-tcdevices](https://shorewall.org/manpages/shorewall-tcdevices.html)(5). You can establish a class hierarchy by specifying a *parent* class (e.g., *interface*:*parent-class*:*class*) -- the number of a class that you have previously defined. The sub-class may borrow unused bandwidth from its parent.

  <div class="warning">

  Class numbers are expressed in hexidecimal. So the class following class 9 is A, not 10.

  </div>

- MARK - The mark value which is an integer in the range 1-255 (1-16383 if you set WIDE_TC_MARKS=Yes or set TC_BITS=14 in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5) ). You define these marks in the mangle or tcrules file, marking the traffic you want to go into the queuing classes defined in here. You can use the same marks for different Interfaces. You must specify "-' in this column if the device specified in the INTERFACE column has the **classify** option in `/etc/shorewall/tcdevices`.

  <div class="note">

  In Shorewall 4.5.0, WIDE_TC_MARKS was superseded by TC_BITS which specifies the width in bits of the traffic shaping mark field. The default is based on the setting of WIDE_TC_MARKS so as to provide upward compatibility.

  </div>

- RATE - The minimum bandwidth this class should get, when the traffic load rises. Please note that first the classes which equal or a lesser priority value are served even if there are others that have a guaranteed bandwidth but a lower priority. **If the sum of the RATEs for all classes assigned to an INTERFACE exceed that interfaces's OUT-BANDWIDTH, then the OUT-BANDWIDTH limit will not be honored.**

  When using HFSC, this column may contain 1, 2 or 3 pieces of information separated by colons (":"). In addition to the minimum bandwidth, leaf classes may specify realtime criteria: DMAX (maximum delay in milliseconds) and optionally UMAX (the largest packet expected in the class). See [below](#HFSC) for details.

- CEIL - The maximum bandwidth this class is allowed to use when the link is idle. Useful if you have traffic which can get full speed when more important services (e.g. interactive like ssh) are not used. You can use the value "full" in here for setting the maximum bandwidth to the defined output bandwidth of that interface.

- PRIORITY - you have to define a priority for the class. packets in a class with a higher priority (=lesser value) are handled before less prioritized ones. You can just define the mark value here also, if you are increasing the mark values with lesser priority.

- OPTIONS - A comma-separated list of options including the following:

  - default - this is the default class for that interface where all traffic should go, that is not classified otherwise.

    <div class="note">

    defining default for exactly **one** class per interface is mandatory!

    </div>

  - tos-\<tosname\> - this lets you define a filter for the given \<tosname\> which lets you define a value of the Type Of Service bits in the ip package which causes the package to go in this class. Please note, that this filter overrides all mark settings, so if you define a tos filter for a class all traffic having that mark will go in it regardless of the mark on the package. You can use the following for this option: tos-minimize-delay (16) tos-maximize-throughput (8) tos-maximize-reliability (4) tos-minimize-cost (2) tos-normal-service (0)

    <div class="note">

    Each of this options is only valid for **one** class per interface.

    </div>

  - tcp-ack - if defined causes an tc filter to be created that puts all tcp ack packets on that interface that have an size of \<=64 Bytes to go in this class. This is useful for speeding up downloads. Please note that the size of the ack packets is limited to 64 bytes as some applications (p2p for example) use to make every package an ack package which would cause them all into here. We want only packets WITHOUT payload to match, so the size limit. Bigger packets just take their normal way into the classes.

    <div class="note">

    This option is only valid for **class** per interface.

    </div>

  - occurs=*number* - Typically used with an IPMARK entry in mangle or tcrules. Causes the rule to be replicated for a total of *number* rules. Each rule has a successively class number and mark value.

    When 'occurs' is used:

    - The associated device may not have the 'classify' option.

    - The class may not be the default class.

    - The class may not have any 'tos=' options (including 'tcp-ack').

    - The class should not specify a MARK value. If one is specified, it will be ignored with a warning message.

    The 'RATE' and 'CEIL' parameters apply to each instance of the class. So the total RATE represented by an entry with 'occurs' will be the listed RATE multiplied by *number*. For additional information, see [mangle](https://shorewall.org/manpages/shorewall-mangle.html) (5) or [tcrules](https://shorewall.org/manpages/shorewall-tcrules.html) (5).

  - flow=*keys* - Shorewall attaches an SFQ queuing discipline to each leaf HTB and HFSC class. SFQ ensures that each flow gets equal access to the interface. The default definition of a flow corresponds roughly to a Netfilter connection. So if one internal system is running BitTorrent, for example, it can have lots of 'flows' and can thus take up a larger share of the bandwidth than a system having only a single active connection. The `flow` classifier (module cls_flow) works around this by letting you define what a 'flow' is. The clasifier must be used carefully or it can block off all traffic on an interface! The flow option can be specified for an HTB or HFSC leaf class (one that has no sub-classes). We recommend that you use the following:

    Shaping internet-bound traffic:
    flow=nfct-src
    Shaping traffic bound for your local net:
    flow=dst
    These will cause a 'flow' to consists of the traffic to/from each internal system.

    When more than one key is give, they must be enclosed in parenthesis and separated by commas.

    To see a list of the possible flow keys, run this command:

    > `tc filter add flow help`

    Those that begin with "nfct-" are Netfilter connection tracking fields. As shown above, we recommend flow=nfct-src; that means that we want to use the source IP address *before SNAT* as the key.

    <div class="note">

    Shorewall cannot determine ahead of time if the flow classifier is available in your kernel (especially if it was built into the kernel as opposed to being loaded as a module). Consequently, you should check ahead of time to ensure that both your kernel and 'tc' utility support the feature.

    You can test the 'tc' utility by typing (as root):

    > `tc filter add flow help`

    If flow is supported, you will see:

           Usage: ... flow ...

              [mapping mode]: map key KEY [ OPS ] ...
              [hashing mode]: hash keys KEY-LIST ...

           ...

    If 'flow' is not supported, you will see:

           Unknown filter "flow", hence option "help" is unparsable

    If your kernel supports module autoloading, just type (as root):

    > `modprobe cls_flow`

    If 'flow' is supported, no output is produced; otherwise, you will see:

           FATAL: Module cls_flow not found.

    If your kernel is not modularized or does not support module autoloading, look at your kernel configuration (either `/proc/config.gz` or the `.config` file in `/lib/modules/<kernel-version>/build/`

    If 'flow' is supported, you will see: NET_CLS_FLOW=m or NET_CLS_FLOW=y.

    For modularized kernels, Shorewall will attempt to load `/lib/modules/<kernel-version>/net/sched/cls_flow.ko` by default.

    </div>

  - pfifo - When specified for a leaf class, the pfifo queing discipline is applied to the class rather than the sfq queuing discipline.

  - limit=*number* - Added in Shorewall 4.4.3. When specified for a leaf class, specifies the maximum number of packets that may be queued within the class. The *number* must be \> 2 and less than 128. If not specified, the value 127 is assumed

  - red=(\<redoption\>,...) - Added in Shorewall 4.5.6. When specified on a leaf class, causes the class to use the red queuing discipline rather than SFQ. See tc-red (8) for additional information.

    See [shorewall-tcdevices](https://shorewall.org/manpages/shorewall-tcdevices.html) (5) for a description of the allowable \<redoptions\>.

  - fq_codel\[=(\<codeloption\>,...)\] - Added in Shorewall 4.5.12. When specified on a leaf class, causes the class to use the FQ CODEL (Fair-queuing Controlled-delay) queuing discipline rather than SFQ. See tc-fq_codel (8) for additional information.

    See [shorewall-tcclasses](https://shorewall.org/manpages/shorewall-tcclasses.html) (5) for a description of the allowable \<codloptions\>.

## /etc/shorewall/mangle and /etc/shorewall/rules

<div class="important">

Unlike rules in the [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html)(5) file, evaluation of rules in this file will continue after a match. So the final mark for each packet will be the one assigned by the LAST tcrule that matches.

Also unlike rules in the [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html)(5) file, the mangle (tcrules) file is not stateful. So every packet that goes into, out of or through your firewall is subject to entries in the mangle (tcrules) file.

Because mangle (tcrules) entries are not stateful, it is necessary to understand basic IP socket operation. Here is an edited excerpt from a post on the Shorewall Users list:

> For the purposes of this discussion, the world is separated into clients and servers. Servers provide services to clients.
>
> When a server starts, it creates a socket and *binds* the socket to an *address*. For AF_INET (IPv4) and AF_INET6 (IPv6) sockets, that address is an ordered triple consisting of an IPv4 or IPv6 address, a protocol, and possibly a port number. Port numbers are only used when the protocol is TCP, UDP, SCTP or DCCP. The protocol and port number used by a server are typically well-known so that clients will be able to connect to it or send datagrams to it. So SSH servers bind to TCP port 22, SMTP servers bind to TCP port 25, etc. We will call this port the SERVER PORT.
>
> When a client want to use the service provided by a server, it also creates a socket and, like the server's socket, the client's socket must be bound to an address. But in the case of the client, the socket is usually given an automatic address binding. For AF_INET and AF_INET6 sockets. the IP address is the IP address of the client system (loose generalization) and the port number is selected from a local port range. On Linux systems, the local port range can be seen by `cat /proc/sys/net/ipv4/ip_local_port_range`. So it is not possible in advance to determine what port the client will be using. Whatever it is, we'll call it the CLIENT PORT.
>
> Now:
>
> > Packets sent from the client to the server will have:
> >
> > > SOURCE PORT = CLIENT PORT
> > >
> > > DEST PORT = SERVER PORT
> >
> > Packets sent from the server to the client will have:
> >
> > > SOURCE PORT = SERVER PORT
> > >
> > > DEST PORT = CLIENT PORT
>
> Since the SERVER PORT is generally the only port known ahead of time, we must categorize traffic from the server to the client using the SOURCE PORT.

</div>

The fwmark classifier provides a convenient way to classify packets for traffic shaping. The `/etc/shorewall/mangle` (`/etc/shorewall/tcrules`) file is used for specifying these marks in a tabular fashion. For an in-depth look at the packet marking facility in Netfilter/Shorewall, please see [this article](PacketMarking.md).

**For marking forwarded traffic, you must either set MARK_IN_FORWARD_CHAIN=Yes shorewall.conf or by using the :F qualifier (see below).**

See shorewall-mangle(5) and shorewall-tcrules(5) for a description of the entries in these files. Note that the mangle file superseded the tcrules file in Shorewall 4.6.0.

The following examples are for the mangle file.

All packets arriving on eth1 should be marked with 1. All packets arriving on eth2 and eth3 should be marked with 2. All packets originating on the firewall itself should be marked with 3.

    #ACTION       SOURCE    DEST           PROTO     DPORT
    MARK(1)       eth1      0.0.0.0/0      all
    MARK(2)       eth2      0.0.0.0/0      all
    MARK(2)       eth3      0.0.0.0/0      all
    MARK(3)       $FW       0.0.0.0/0      all

All GRE (protocol 47) packets destined for 155.186.235.151 should be marked with 12.

    #ACTION       SOURCE    DEST            PROTO      DPORT
    MARK(12):T    0.0.0.0/0 155.182.235.151 47

All SSH request packets originating in 192.168.1.0/24 and destined for 155.186.235.151 should be marked with 22.

    #ACTION       SOURCE         DEST            PROTO      DPORT
    MARK(22):T    192.168.1.0/24 155.182.235.151 tcp        22

All SSH packets packets going out of the first device in in /etc/shorewall/tcdevices should be assigned to the class with mark value 10.

    #ACTION           SOURCE         DEST            PROTO      DPORT           SPORT
    CLASSIFY(1:110)   0.0.0.0/0      0.0.0.0/0       tcp        22
    CLASSIFY(1:110)   0.0.0.0/0      0.0.0.0/0       tcp        -               22

Mark all ICMP echo traffic with packet mark 1. Mark all peer to peer traffic with packet mark 4.

This is a little more complex than otherwise expected. Since the ipp2p module is unable to determine all packets in a connection are P2P packets, we mark the entire connection as P2P if any of the packets are determined to match. We assume packet/connection mark 0 to means unclassified. Traffic originating on the firewall is not covered by this example.

    #ACTION        SOURCE         DEST            PROTO      DPORT         SPORT    USER      TEST
    MARK(1)        0.0.0.0/0      0.0.0.0/0       icmp       echo-request
    MARK(1)        0.0.0.0/0      0.0.0.0/0       icmp       echo-reply

    RESTORE        0.0.0.0/0      0.0.0.0/0       all        -             -        -         0
    CONTINUE       0.0.0.0/0      0.0.0.0/0       all        -             -        -         !0
    MARK(4)        0.0.0.0/0      0.0.0.0/0       ipp2p:all
    SAVE           0.0.0.0/0      0.0.0.0/0       all        -             -        -         !0

The last four rules can be translated as:

> "If a packet hasn't been classified (packet mark is 0), copy the connection mark to the packet mark. If the packet mark is set, we're done. If the packet is P2P, set the packet mark to 4. If the packet mark has been set, save it to the connection mark."

Mark all forwarded VOIP connections with connection mark 1 and ensure that all VOIP packets also receive that mark (assumes that nf_conntrack_sip is loaded).

    #ACTION  SOURCE         DEST            PROTO      DPORT         SPORT    USER      TEST      CONNBYTES      TOS      HELPER
    RESTORE  0.0.0.0/0      0.0.0.0/0       all        -             -        -         0
    CONTINUE 0.0.0.0/0      0.0.0.0/0       all        -             -        -         !0
    1        0.0.0.0/0      0.0.0.0/0       all        -             -        -         -         -              -        sip
    SAVE     0.0.0.0/0      0.0.0.0/0       all        -             -        -         !0

## ppp devices

If you use ppp/pppoe/pppoa) to connect to your Internet provider and you use traffic shaping you need to restart shorewall traffic shaping. The reason for this is, that if the ppp connection gets restarted (and it usually does this at least daily), all “tc” filters/qdiscs related to that interface are deleted.

The easiest way to achieve this, is just to restart shorewall once the link is up. To achieve this add a small executable script to“/etc/ppp/ip-up.d”.

    #! /bin/sh

    /sbin/shorewall refresh

## Sharing a TC configuration between Shorewall and Shorewall6

Beginning with Shorewall 4.4.15, the traffic-shaping configuration in the tcdevices, tcclasses and tcfilters files can be shared between Shorewall and Shorewall6. Only one of the products can control the configuration but the other can configure CLASSIFY rules in its own mangle or tcrules file that refer to the shared classes.

To defined the configuration in Shorewall and shared it with Shorewall6:

- Set TC_ENABLED=Internal in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html) (5).

- Set TC_ENABLED=Shared in [shorewall6.conf](https://shorewall.org/manpages/shorewall.conf.html) (5).

- Create symbolic links from /etc/shorewall6 to /etc/shorewall/tcdevices and /etc/shorewall/tcclasses:

      ln -s ../shorewall/tcdevices /etc/shorewall6/tcdevices
      ln -s ../shorewall/tcclasses /etc/shorewall6/tcclasses

- If you need to define IPv6 tcfilter entries, do so in /etc/shorewall/tcfilters. That file now allows entries that apply to IPv6.

Shorewall6 compilations to have access to the tcdevices and tcclasses files although it will create no output. That access allows CLASSIFY rules in /etc/shorewall6/mangle to be validated against the TC configuration.

In this configuration, it is Shorewall that controls TC configuration (except for IPv6 mangle). You can reverse the settings in the files if you want to control the configuration using Shorewall6.

## Per-IP Traffic Shaping

Some network administrators feel that they have to divy up their available bandwidth by IP address rather than by prioritizing the traffic based on the type of traffic. This gets really awkward when there are a large number of local IP addresses.

This section describes the Shorewall facility for making this configuration less tedious (and a lot more efficient). Note that it requires that you [install xtables-addons](Dynamic.md#xtables-addons). So before you try this facility, we suggest that first you add the following OPTION to each external interface described in /etc/shorewall/tcdevices:

    flow=nfct-src

If you shape traffic on your internal interface(s), then add this to their entries:

    flow=dst

You may find that this simple change is all that is needed to control bandwidth hogs like Bit Torrent. If it doesn't, then proceed as described in this section.

The facility has two components:

1.  An IPMARK MARKing command in `/etc/shorewall/mangle` (`/etc/shorewall/tcrules`).

2.  An **occurs** OPTION in /etc/shorewall/tcclasses.

The facility is currently only available with IPv4.

In a sense, the IPMARK target is more like an IPCLASSIFY target in that the mark value is later interpreted as a class ID. A packet mark is 32 bits wide; so is a class ID. The *major* class occupies the high-order 16 bits and the *minor* class occupies the low-order 16 bits. So the class ID 1:4ff (remember that class IDs are always in hex) is equivalent to a mark value of 0x104ff. Remember that Shorewall uses the interface number as the *major* number where the first interface in tcdevices has *major* number 1, the second has *major* number 2, and so on.

The IPMARK target assigns a mark to each matching packet based on the either the source or destination IP address. By default, it assigns a mark value equal to the low-order 8 bits of the source address.

The syntax is as follows:

> **IPMARK**\[**(**\[{**src**\|**dst**}\]\[**,**\[*mask1*\]\[,\[*mask2*\]\[**,**\[*shift*\]\]\]\]**)**\]

Default values are:

src

mask1 = 0xFF

mask2 = 0x00

shift = 0

**src** and **dst** specify whether the mark is to be based on the source or destination address respectively. The selected address is first shifted right by *shift*, then LANDed with *mask1* and then LORed with *mask2*. The *shift* argument is intended to be used primarily with IPv6 addresses.

Example:

    IPMARK(src,0xff,0x10100)

    Source IP address is 192.0.2.3 = 0xc0a80403

            0xc0a80403 >> 0         = 0xc0a80403
            0xc0a80403 LAND 0xFF    = 0x03
            0x03       LOR  0x10100 = 0x10103

            So the mark value is 0x10103 which corresponds to class id 1:103.

It is important to realize that, while class IDs are composed of a *major* and a *minor* value, the set of *minor* values must be unique. You must keep this in mind when deciding how to map IP addresses to class IDs. For example, suppose that your internal network is 192.168.1.0/29 (host IP addresses 192.168.1.1 - 192.168.1.6). Your first notion might be to use IPMARK(src,0xFF,0x10000) so as to produce class IDs 1:1 through 1:6. But 1:1 is the class ID of the base HTB class on interface 1. So you might chose instead to use IPMARK(src,0xFF,0x10100) as shown in the example above so as to avoid minor class 1.

The **occurs** option in `/etc/shorewall/tcclasses` causes the class definition to be replicated many times.

The synax is:

> **occurs=***number*

When **occurs** is used:

1.  The associated device may not have the **classify** option.

2.  The class may not be the default class.

3.  The class may not have any **tos=** options (including **tcp-ack**).

The class should not specify a MARK value. Any MARK value given is ignored with a warning. The RATE and CEIL parameters apply to each instance of the class. So the total RATE represented by an entry with **occurs** will be the listed RATE multiplied by *number*.

Example:

`/etc/shorewall/tcdevices`:

    #INTERFACE IN_BANDWIDTH OUT_BANDWIDTH
    eth0       100mbit      100mbit

`/etc/shorewall/tcclasses`:

    #DEVICE   MARK RATE     CEIL PRIORITY    OPTIONS
    eth0:101     - 1kbit 230kbit        4    occurs=6

The above defines 6 classes with class IDs 0x101-0x106. Each class has a guaranteed rate of 1kbit/second and a ceiling of 230kbit.

`/etc/shoreall/mangle` or `/etc/shoreall/tcrules`:

    #ACTION                          SOURCE             DEST
    IPMARK(src,0xff,0x10100):F       192.168.1.0/29     eth0

This facility also alters the way in which Shorewall generates a class number when none is given. Prior to the implementation of this facility, the class number was constructed by concatinating the MARK value with the either '1' or '10'. '10' was used when there were more than 10 devices defined in `/etc/shorewall/tcdevices`.

With this facility, a new method is added; class numbers are assigned sequentially beginning with 2. The WIDE_TC_MARKS option in `shorewall.conf` selects which construction to use. WIDE_TC_MARKS=No (the default) produces pre-Shorewall 4.4 behavior. WIDE_TC_MARKS=Yes (TC_BITS \>= 14 in Shorewall 4.4.26 and later) produces the new behavior.

## Real life examples

### A Shorewall User's Experience

Chuck Kollars has provided [an excellent writeup](http://www.ckollars.org/shaping.html) about his traffic shaping experiences.

### Configuration to replace Wondershaper

You are able to fully replace the wondershaper script by using the buitin traffic control.. In this example it is assumed that your interface for your Internet connection is ppp0 (for DSL), if you use another connection type, you have to change it. You also need to change the settings in the tcdevices.wondershaper file to reflect your line speed. The relevant lines of the config files follow here. Please note that this is just a 1:1 replacement doing exactly what wondershaper should do. You are free to change it...

#### tcdevices file

    #INTERFACE      IN_BANDWITH     OUT_BANDWIDTH
    ppp0            5000kbit        500kbit

#### tcclasses file

    #INTERFACE      MARK    RATE            CEIL        PRIORITY    OPTIONS
    ppp0            1       5*full/10       full            1       tcp-ack,tos-minimize-delay
    ppp0            2       3*full/10       9*full/10       2       default
    ppp0            3       2*full/10       8*full/10       2

#### mangle file

    #ACTION         SOURCE          DEST            PROTO   DPORT    SPORT   USER
    MARK(1):F       0.0.0.0/0       0.0.0.0/0       icmp    echo-request
    MARK(1):F       0.0.0.0/0       0.0.0.0/0       icmp    echo-reply
    # mark traffic which should have a lower priority with a 3:
    # mldonkey
    MARK(3):F       0.0.0.0/0       0.0.0.0/0       udp     -        4666

Wondershaper allows you to define a set of hosts and/or ports you want to classify as low priority. To achieve this , you have to add these hosts to tcrules and set the mark to 3 (true if you use the example configuration files).

#### Setting hosts to low priority

lets assume the following settings from your old wondershaper script (don't assume these example values are really useful, they are only used for demonstrating ;-):

    # low priority OUTGOING traffic - you can leave this blank if you want
    # low priority source netmasks
    NOPRIOHOSTSRC="192.168.1.128/25 192.168.3.28"

    # low priority destination netmasks
    NOPRIOHOSTDST=60.0.0.0/24

    # low priority source ports
    NOPRIOPORTSRC="6662 6663"

    # low priority destination ports
    NOPRIOPORTDST="6662 6663"  

This would result in the following additional settings to the mangle file:

    #ACTION                SOURCE          DEST           PROTO   DPORT     SPORT   USER
    MARK(3)               192.168.1.128/25 0.0.0.0/0      all
    MARK(3)               192.168.3.28     0.0.0.0/0      all
    MARK(3)               0.0.0.0/0        60.0.0.0/24    all
    MARK(3)               0.0.0.0/0        0.0.0.0/0      udp     6662,6663
    MARK(3)               0.0.0.0/0        0.0.0.0/0      udp     -         6662,6663
    MARK(3)               0.0.0.0/0        0.0.0.0/0      tcp     6662,6663
    MARK(3)               0.0.0.0/0        0.0.0.0/0      tcp     -         6662,6663

### A simple setup

This is a simple setup for people sharing an Internet connection and using different computers for this. It just basically shapes between 2 hosts which have the ip addresses 192.168.2.23 and 192.168.2.42

#### tcdevices file

    #INTERFACE      IN_BANDWITH     OUT_BANDWIDTH
    ppp0            6000kbit        700kbit

We have 6mbit down and 700kbit upstream.

#### tcclasses file

    #INTERFACE      MARK    RATE            CEIL            PRIORITY    OPTIONS
    ppp0            1       10kbit          50kbit          1           tcp-ack,tos-minimize-delay
    ppp0            2       300kbit         full            2
    ppp0            3       300kbit         full            2
    ppp0            4       90kbit          200kbit         3           default

We add a class for tcp ack packets with highest priority, so that downloads are fast. The following 2 classes share most of the bandwidth between the 2 hosts, if the connection is idle, they may use full speed. As the hosts should be treated equally they have the same priority. The last class is for the remaining traffic.

#### mangle file

    #ACTION               SOURCE          DEST            PROTO   DPORT        SPORT     USER
    MARK(1):F             0.0.0.0/0       0.0.0.0/0       icmp    echo-request
    MARK(1):F             0.0.0.0/0       0.0.0.0/0       icmp    echo-reply
    MARK(2):F             192.168.2.23    0.0.0.0/0       all
    MARK(3):F             192.168.2.42    0.0.0.0/0       all

Corresponding tcrules file:

    #ACTION         SOURCE          DEST            PROTO   DPORT        SPORT     USER
    1:F             0.0.0.0/0       0.0.0.0/0       icmp    echo-request
    1:F             0.0.0.0/0       0.0.0.0/0       icmp    echo-reply
    2:F             192.168.2.23    0.0.0.0/0       all
    3:F             192.168.2.42    0.0.0.0/0       all

We mark icmp ping and replies so they will go into the fast interactive class and set a mark for each host.

# A Warning to Xen Users

If you are running traffic shaping in your dom0 and traffic shaping doesn't seem to be limiting outgoing traffic properly, it may be due to "checksum offloading" in your domU(s). Check the output of "shorewall show tc". Here's an excerpt from the output of that command:

    class htb 1:130 parent 1:1 leaf 130: prio 3 quantum 1500 rate 76000bit ceil 230000bit burst 1537b/8 mpu 0b overhead 0b cburst 1614b/8 mpu 0b overhead 0b level 0 
     Sent 559018700 bytes 75324 pkt (dropped 0, overlimits 0 requeues 0) 
     rate 299288bit 3pps backlog 0b 0p requeues 0 
     lended: 53963 borrowed: 21361 giants: 90174
     tokens: -26688 ctokens: -14783

There are two obvious problems in the above output:

1.  The rate (299288) is considerably larger than the ceiling (230000).

2.  There are a large number (90174) of giants reported.

This problem will be corrected by disabling "checksum offloading" in your domU(s) using the `ethtool` utility. See the [one of the Xen articles](../legacy/XenMyWay-Routed.md) for instructions.

# An HFSC Example

As mentioned at the top of this article, there is an excellent introduction to HFSC at <http://linux-ip.net/articles/hfsc.en/>. At the end of that article are 'tc' commands that implement the configuration in the article. Those tc commands correspond to the following Shorewall traffic shaping configuration.

`/etc/shorewall/tcdevices`:

    #INTERFACE    IN_BANDWITH      OUT_BANDWIDTH          OPTIONS
    eth0          -                1000kbit               hfsc

`/etc/shorewall/tcclasses`:

    #INTERFACE           MARK      RATE               CEIL     PRIORITY      OPTIONS
    1:10                 1         500kbit            full     1
    1:20                 2         500kbit            full     1
    1:10:11              3         400kbit:53ms:1500b full     2
    1:10:12              4         100kbit:30ms:1500b full     2

The following sub-section offers some notes about the article.

## Where Did all of those Magic Numbers come from?

As you read the article, numbers seem to be introduced out of thin air. I'll try to shed some light on those.

There is very clear development of these numbers:

- 12ms to transfer a 1500b packet at 1000kbits/second.

- 100kbits per second with 1500b packets, requires 8 packets per second.

- A packet from class 1:12 must be sent every 120ms.

- Total transmit delay can be no more than 132ms (120 + 12).

We then learn that the queuing latency can be reduced to 30ms if we use a two-part service curve whose first part is 400kbits/second. Where did those come from?

- The latency is calculated from the rate. If it takes 12ms to transmit a 1500 byte packet at 1000kbits/second, it takes 30ms to transmit a 1500b at 400kbits/second.

- For the slope of the first part of the service curve, in theory we can pick any number between 100 (the rate of class 1:12) and 500 (the rate of the parent class) with higher numbers providing lower latency.

The final curious number is the latency for class 1:11 - 52.5ms. It is a consequence of everything that has gone before.

To acheive 400kbits/second with 1500-byte packets, 33.33 packets per second are required. So a packet from class 1:11 must be sent every 30 ms. As the article says, "...the maximum transmission delay of this class increases from 30ms to a total of 52.5 ms.". So we are looking for an additional 22.5 ms.

Assume that both class 1:11 and 1:12 transmit for 30 ms at 400kbits/second. That is a total of 800kbits/second for 30ms. So Class 1:11 is punished for the excess. How long is the punishment? The two classes sent 24,000 bits in 30ms; they are only allowed 0.030 \* 500,000 = 15,000. So they are 9,000 bits over their quota. The amount of time required to transmit 9,000 bits at 400,000 bits/second is 22.5ms!.

# Intermediate Functional Block (IFB) Devices

The principles behind an IFB is fairly simple:

- It looks like a network interface although it is never given an IPv4 configuration.

- Because it is a network interface, queuing disciplines can be associated with an IFB.

The magic of an IFB comes in the fact that a filter may be defined on a real network interface such that each packet that arrives on that interface is queued for the IFB! In that way, the IFB provides a means for shaping input traffic.

To use an IFB, you must have IFB support in your kernel (configuration option CONFIG_IFB). Assuming that you have a modular kernel, the name of the IFB module is 'ifb' and may be loaded using the command `modprobe ifb` (if you have modprobe installed) or `insmod /path/to/module/ifb`.

By default, two IFB devices (ifb0 and ifb1) are created. You can control that using the numifbs option (e.g., `modprobe ifb numifbs=1`).

To create a single IFB when Shorewall starts, place the following two commands in `/etc/shorewall/init`:

    modprobe ifb numifbs=1
    ip link set ifb0 up

Entries in `/etc/shorewall/mangle` or `/etc/shorewall/tcrules` have no effect on shaping traffic through an IFB unless the IFB is defined in shorewall-tcclasses(5) with the **connmark** option. To allow classification of such traffic, the /etc/shorewall/tcfilters file has been added. Entries in that file create [u32 classification rules](http://b42.cz/notes/u32_classifier/).

## /etc/shorewall/tcfilters

While this file was created to allow shaping of traffic through an IFB, the file may be used for general traffic classification as well. The file is similar to [shorewall-mangle](https://shorewall.org/manpages/shorewall-mangle.html)(5) with the following key exceptions:

- The first match determines the classification, whereas in the mangle file, the last match determines the classification.

- ipsets are not supported

- DNS Names are not supported

- Address ranges and lists are not supported

- Exclusion is not supported.

- filters are applied to packets as they *appear on the wire*. So incoming packets will not have DNAT applied yet (the destination IP address will be the external address) and outgoing packets will have had SNAT applied.

The last point warrants elaboration. When looking at traffic being shaped by an IFB, there are two cases to consider:

1.  Requests — packets being sent from remote clients to local servers. These packets may undergo subsequent DNAT, either as a result of entries in `/etc/shorewall/nat` or as a result of DNAT or REDIRECT rules.

    Example: `/etc/shorewall/rules`:

        #ACTION       SOURCE           DEST            PROTO    DPORT           SPORT          ORIGDEST
        DNAT          net              dmz:192.0.2.5 tcp      80              -              206.124.146.177

    Requests redirected by this rule will have destination IP address 206.124.146.177 and destination port 80.

2.  Responses — packets being sent from remote servers to local clients. These packets may undergo subsequent DNAT as a result of entries in `/etc/shorewall/nat` or in `/etc/shorewall/masq`. The packet's destination IP address will be the external address specified in the entry.

    Example: `/etc/shorewall/masq`:

        #INTERFACE        SOURCE           ADDRESS
        eth0              192.168.1.0/24   206.124.146.179

    When running Shorewall 5.0.14 or later, the equivalent `/etc/shorewall/snat` would be:

        #ACTION                SOURCE         DEST       ...
        SNAT(206.124.146.179)  192.168.1.0/24 eth0

    HTTP response packets corresponding to requests that fall under that rule will have destination IP address 206.124.146.179 and **source** port 80.

Beginning with Shorewall 4.4.15, both IPv4 and IPv6 rules can be defined in this file. See [shorewall-tcfilters](https://shorewall.org/manpages/shorewall-tcfilters.html) (5) for details.

Columns in the file are as follow. As in all Shorewall configuration files, a hyphen ("-") may be used to indicate that no value is supplied in the column.

CLASS  
The interface name or number followed by a colon (":") and the class number.

SOURCE  
SOURCE IP address (host or network). DNS names are not allowed.

DEST  
DESTINATION IP address (host or network). DNS names are not allowed.

PROTO  
Protocol name or number.

DPORT  
Comma-separated list of destination port names or numbers. May only be specified if the protocol is TCP, UDP, SCTP or ICMP. Port ranges are supported except for ICMP.

SPORT  
Comma-separated list of source port names or numbers. May only be specified if the protocol is TCP, UDP or SCTP. Port ranges are supported.

TOS  
Specifies the value of the TOS field. The value can be any of the following:

- `tos-minimize-delay`

- `tos-maximuze-throughput`

- `tos-maximize-reliability`

- `tos-minimize-cost`

- `tos-normal-service`

- \<hex-number\>

- \<hex-number\>/\<hex-number\>

The \<hex-number\>s must be exactly two digits (e.g., 0x04).

LENGTH  
Must be a power of 2 between 32 and 8192 inclusive. Packets with a total length that is strictly less than the specified value will match the rule.

Example:

I've used this configuration on my own firewall. The IFB portion is more for test purposes rather than to serve any well-reasoned QOS strategy.

`/etc/shorewall/init`:

    qt modprobe ifb numifbs=1
    qt ip link set dev ifb0 up

`/etc/shorewall/interfaces`:

    #ZONE          INTERFACE         BROADCAST
    -              ifb0

`/etc/shorewall/tcdevices`:

    #INTERFACE      IN_BANDWITH     OUT_BANDWIDTH   OPTIONS         REDIRECT
    1:eth0          -               384kbit         classify
    2:ifb0          -               1300kbit        -               eth0

`/etc/shorewall/tcclasses`:

    #INTERFACE      MARK    RATE            CEIL            PRIORITY        OPTIONS
    1:110           -       5*full/10       full            1               tcp-ack,tos-minimize-delay
    1:120           -       2*full/10       6*full/10       2               default
    1:130           -       2*full/10       6*full/10       3
    2:110           -       5*full/10       full            1               tcp-ack,tos-minimize-delay
    2:120           -       2*full/10       6*full/10       2               default
    2:130           -       2*full/10       6*full/10       3

`/etc/shorewall/tcfilters`:

    #INTERFACE:     SOURCE          DEST            PROTO   DPORT   SPORT
    #
    #                                  OUTGOING TRAFFIC
    #
    1:130           206.124.146.178 -               tcp     -       49441,49442    #BITTORRENT on wookie
    1:110           206.124.146.178                                                #wookie
    1:110           206.124.146.179                                                #SNAT of internal systems
    1:110           206.124.146.180                                                #Work Laptop
    1:110           -               -               icmp    echo-request,echo-reply
    1:110           -               -               icmp    echo-reply
    1:130           206.124.146.177 -               tcp     -       873,25         #Bulk Traffic
    #
    #                                   INCOMING TRAFFIC
    #
    2:110           -               206.124.146.178                          #Wookie
    2:110           -               206.124.146.179                          #SNAT Responses
    2:110           -               206.124.146.180                          #Work Laptop
    2:130           -               206.124.146.177 tcp     25               #Incoming Email.

You can examine the installed filters with the `shorewall show filters` command. What follows shows the output for `eth0` with the filters shown above. **Bold font** are comments explaining the rules.

    gateway:~ # shorewall-lite show filters
    Shorewall Lite 4.1.6 Classifiers at gateway - Fri Mar 21 08:06:47 PDT 2008

    Device eth1:

    Device eth2:

    Device eth0:
    filter parent 1: protocol ip pref 10 u32 
    filter parent 1: protocol ip pref 10 u32 fh 3: ht divisor 1   <========= Start of table 3. parses TCP header

    filter parent 1: protocol ip pref 10 u32 fh 3::800 order 2048 key ht 3 bkt 0 flowid 1:130  (rule hit 102 success 0)
      match 03690000/ffff0000 at nexthdr+0 (success 0 )           <========= SOURCE PORT 873 goes to class 1:130

    filter parent 1: protocol ip pref 10 u32 fh 2: ht divisor 1   <========= Start of table 2. parses ICMP header

    filter parent 1: protocol ip pref 10 u32 fh 2::800 order 2048 key ht 2 bkt 0 flowid 1:110  (rule hit 0 success 0)
      match 08000000/ff000000 at nexthdr+0 (success 0 )           <========= ICMP Type 8 goes to class 1:110

    filter parent 1: protocol ip pref 10 u32 fh 2::801 order 2049 key ht 2 bkt 0 flowid 1:110  (rule hit 0 success 0)
      match 00000000/ff000000 at nexthdr+0 (success 0 )           <========= ICMP Type 0 goes to class 1:110

    filter parent 1: protocol ip pref 10 u32 fh 1: ht divisor 1   <========= Start of table 1. parses TCP header

    filter parent 1: protocol ip pref 10 u32 fh 1::800 order 2048 key ht 1 bkt 0 flowid 1:130  (rule hit 0 success 0)
      match c1210000/ffff0000 at nexthdr+0 (success 0 )           <========= SOURCE PORT 49441 goes to class 1:130

    filter parent 1: protocol ip pref 10 u32 fh 1::801 order 2049 key ht 1 bkt 0 flowid 1:130  (rule hit 0 success 0)
      match c1220000/ffff0000 at nexthdr+0 (success 0 )           <========= SOURCE PORT 49442 goes to class 1:130

    filter parent 1: protocol ip pref 10 u32 fh 800: ht divisor 1 <========= Start of Table 800. Packets start here!

       =============== The following 2 rules are generated by the class definition in /etc/shorewall/classes ==================

    filter parent 1: protocol ip pref 10 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:110  (rule hit 2204 success 138)
      match 00060000/00ff0000 at 8 (success 396 )                 <========= TCP    
      match 05000000/0f00ffc0 at 0 (success 250 )                 <========= Header length 20 and Packet Length < 64 
      match 00100000/00ff0000 at 32 (success 138 )                <========= ACK

    filter parent 1: protocol ip pref 10 u32 fh 800::801 order 2049 key ht 800 bkt 0 flowid 1:110  (rule hit 2066 success 0)
      match 00100000/00100000 at 0 (success 0 )                  <========= Minimize-delay goes to class 1:110

                            =============== Jump to Table 1 if the matches are met ==================
     
    filter parent 1: protocol ip pref 10 u32 fh 800::802 order 2050 key ht 800 bkt 0 link 1:  (rule hit 2066 success 0)
      match ce7c92b2/ffffffff at 12 (success 1039 )              <========= SOURCE 206.124.146.178          
      match 00060000/00ff0000 at 8 (success 0 )                  <========= PROTO TCP
        offset 0f00>>6 at 0  eat 

    filter parent 1: protocol ip pref 10 u32 fh 800::803 order 2051 key ht 800 bkt 0 flowid 1:110  (rule hit 2066 success 1039)
      match ce7c92b2/ffffffff at 12 (success 1039 )               <========= SOURCE 206.124.146.178 goes to class 1:110

    filter parent 1: protocol ip pref 10 u32 fh 800::804 order 2052 key ht 800 bkt 0 flowid 1:110  (rule hit 1027 success 132)
      match ce7c92b3/ffffffff at 12 (success 132 )                <========= SOURCE 206.124.146.179 goes to class 1:110

    filter parent 1: protocol ip pref 10 u32 fh 800::805 order 2053 key ht 800 bkt 0 flowid 1:110  (rule hit 895 success 603)
      match ce7c92b4/ffffffff at 12 (success 603 )                <========= SOURCE 206.124.146.180 goes to class 1:110

                            =============== Jump to Table 2 if the matches are met ==================

    filter parent 1: protocol ip pref 10 u32 fh 800::806 order 2054 key ht 800 bkt 0 link 2:  (rule hit 292 success 0)
      match 00010000/00ff0000 at 8 (success 0 )                   <========= PROTO ICMP 
        offset 0f00>>6 at 0  eat

                            =============== Jump to Table 3 if the matches are met ==================
     
    filter parent 1: protocol ip pref 10 u32 fh 800::807 order 2055 key ht 800 bkt 0 link 3:  (rule hit 292 success 0)
      match ce7c92b1/ffffffff at 12 (success 265 )                <========= SOURCE 206.124.146.177
      match 00060000/00ff0000 at 8 (success 102 )                 <========= PROTO TCP
        offset 0f00>>6 at 0  eat 

## IFBs and SNAT/MASQUERADE

IFB traffic shaping takes place immediately after the traffic is received by the incoming interface and before it has been passed to any Netfilter hook. This has two consequences:

- There is no opportunity to mark the packets before they are processed by the IFBs traffic shaping rules.

- The DEST IP address is still the IP address of the external interface on which the traffic arrived.

As a result, in the tcdevices file description above, a **connmark** option was added to that file in Shorewall 5.2.7. The **connmark** option allows firewall marks to be used to segregate traffic by DEST IP.

Example (based closely on one supplied by Rodrigo Araujo, who also wrote much of the code supporting the **connmark** option):

**/etc/shorewall/shorewall.conf:**

    ...
    TC_ENABLED=Internal
    ...

**/etc/shorewall/interfaces:**

    ##############################################################################
    ?FORMAT 2
    ###############################################################################
    #ZONE   INTERFACE   OPTIONS
    net     NET_IF          dhcp,tcpflags,nosmurfs,routefilter,logmartians,sourceroute=0,physical=eth0
    loc     LOC_IF          tcpflags,nosmurfs,routefilter,logmartians,physical=eth1

**/etc/shorewall/snat:**

    ?FORMAT 2
    #ACTION       SOURCE      DEST    PROTO    PORT        IPSEC    MARK   
    USER    SWITCH    ORIGDEST    PROBABILITY
    MASQUERADE    -           NET_IF

**/etc/shorewall/tcdevices:**

    #INTERFACE    IN_BANDWITH OUT_BANDWIDTH   OPTIONS     REDIRECT
    ## net upload
    10:NET_IF   -               1000mbit         htb
    ## net download
    11:ifb0         -               1000mbit         htb,connmark   NET_IF

**/etc/shorewall/tcclasses:**

    #INTERFACE    MARK    RATE        CEIL        PRIO    OPTIONS
    10:5000           111       500kbit            full       10     tcp-ack,tos-minimize-delay
    11:5000           110       500kbit            full       10     tcp-ack,tos-minimize-delay

    10:1000           100       full-50500         full       20      default
    11:1000           101       full-100500        full       20      default

    10:50             10        50mbit             50mbit     101     flow=nfct-src
    11:100            11        100mbit            100mbit    101     flow=dst

**/etc/shorewall/tcfilters:**

    #CLASS        SOURCE      DEST        PROTO   DPORT   SPORT   TOS LENGTH
    ## limit LAN upload - works
    10:50          10.100.100.0/24
    ## limit LAN download - DOESN'T WORK BECAUSE OF MASQUERADE ON eth0 !!!! (snat file)
    #11:100        -                  10.100.100.0/24

**/etc/shorewall/mangle:**

    #ACTION       SOURCE      DEST        PROTO   DPORT   SPORT   USER    TEST    LENGTH  TOS CONNBYTES   HELPER  PROBABILITY DSCP    SWITCH
    ## this only works with the aforementioned conntrack option
    ## and LAN users' download traffic will get the 11:100 class (defined in tcclasses) applied
    CONNMARK(11):F       10.100.100.0/24    - { TEST=0x0/0xff }

# Understanding the output of 'shorewall show tc'

The `shorewall show tc` (`shorewall-lite show tc`) command displays information about the current state of traffic shaping. For each device, it executes the following commands:

     echo Device $device:
     tc -s -d qdisc show dev $device
     echo
     tc -s -d class show dev $device
     echo 

So, the traffic-shaping output is generated entirely by the `tc` utility.

Here's the output of for eth0. The configuration is the one shown in the preceding section (the output was obtained almost 24 hours later than the `shorewall show filters` output shown above).

    Device eth0:

           ============== The primary queuing discipline is HTB (Hierarchical Token Bucket) ==================== 

    qdisc htb 1: r2q 10 default 120 direct_packets_stat 9 ver 3.17
     Sent 2133336743 bytes 4484781 pkt (dropped 198, overlimits 4911403 requeues 21) <=========== Note the overlimits and dropped counts
     rate 0bit 0pps backlog 0b 8p requeues 21

    ============== The ingress filter. If you specify IN-BANDWIDTH, you can see the 'dropped' count here. =========

                           In this case, the packets are being sent to the IFB for shaping
     
    qdisc ingress ffff: ---------------- 
     Sent 4069015112 bytes 4997252 pkt (dropped 0, overlimits 0 requeues 0) 
     rate 0bit 0pps backlog 0b 0p requeues 0

     ============ Each of the leaf HTB classes has an SFQ qdisc to ensure that each flow gets its turn ============
     
    qdisc sfq 110: parent 1:110 limit 128p quantum 1514b flows 128/1024 perturb 10sec 
     Sent 613372519 bytes 2870225 pkt (dropped 0, overlimits 0 requeues 6) 
     rate 0bit 0pps backlog 0b 0p requeues 6 
    qdisc sfq 120: parent 1:120 limit 128p quantum 1514b flows 128/1024 perturb 10sec 
     Sent 18434920 bytes 60961 pkt (dropped 0, overlimits 0 requeues 0) 
     rate 0bit 0pps backlog 0b 0p requeues 0 
    qdisc sfq 130: parent 1:130 limit 128p quantum 1514b flows 128/1024 perturb 10sec 
     Sent 1501528722 bytes 1553586 pkt (dropped 198, overlimits 0 requeues 15) 
     rate 0bit 0pps backlog 11706b 8p requeues 15 

                               ============= Class 1:110 -- the high-priority class ===========


                                       Note the rate and ceiling calculated from 'full'

    class htb 1:110 parent 1:1 leaf 110: prio 1 quantum 4800 rate 192000bit ceil 384000bit burst 1695b/8 mpu 0b overhead 0b cburst 1791b/8 mpu 0b overhead 0b level 0 
     Sent 613372519 bytes 2870225 pkt (dropped 0, overlimits 0 requeues 0) 
     rate 195672bit 28pps backlog 0b 0p requeues 0 <=========== Note the current rate of traffic. There is no queuing (no packet backlog) 
     lended: 2758458 borrowed: 111773 giants:
     tokens: 46263 ctokens: 35157

                                          ============== The root class ============

    class htb 1:1 root rate 384000bit ceil 384000bit burst 1791b/8 mpu 0b overhead 0b cburst 1791b/8 mpu 0b overhead 0b level 7 
     Sent 2133276316 bytes 4484785 pkt (dropped 0, overlimits 0 requeues 0) <==== Total output traffic since last 'restart'
     rate 363240bit 45pps backlog 0b 0p requeues 0 
     lended: 1081936 borrowed: 0 giants: 0
     tokens: -52226 ctokens: -52226

                          ============= Bulk Class (outgoing rsync, email and bittorrent) ============

    class htb 1:130 parent 1:1 leaf 130: prio 3 quantum 1900 rate 76000bit ceil 230000bit burst 1637b/8 mpu 0b overhead 0b cburst 1714b/8 mpu 0b overhead 0b level 0 
     Sent 1501528722 bytes 1553586 pkt (dropped 198, overlimits 0 requeues 0) 
     rate 162528bit 14pps backlog 0b 8p requeues 0 <======== Queuing is occurring (8 packet backlog). The rate is still below the ceiling.
     lended: 587134 borrowed: 966459 giants: 0               During peak activity, the rate tops out at around 231000 (just above ceiling).
     tokens: -30919 ctokens: -97657

                           ================= Default class (mostly serving web pages) ===============

    class htb 1:120 parent 1:1 leaf 120: prio 2 quantum 1900 rate 76000bit ceil 230000bit burst 1637b/8 mpu 0b overhead 0b cburst 1714b/8 mpu 0b overhead 0b level 0 
     Sent 18434920 bytes 60961 pkt (dropped 0, overlimits 0 requeues 0) 
     rate 2240bit 2pps backlog 0b 0p requeues 0 
     lended: 57257 borrowed: 3704 giants: 0
     tokens: 156045 ctokens: 54178

# Using your own tc script

## Replacing builtin tcstart file

If you prefer your own tcstart file, just install it in /etc/shorewall/tcstart.

In your tcstart script, when you want to run the “tc” utility, use the run_tc function supplied by Shorewall if you want tc errors to stop the firewall.

1.  Set TC_ENABLED=Yes and CLEAR_TC=Yes

2.  Supply an /etc/shorewall/tcstart script to configure your traffic shaping rules.

3.  Optionally supply an /etc/shorewall/tcclear script to stop traffic shaping. That is usually unnecessary.

4.  If your tcstart script uses the “fwmark” classifier, you can mark packets using entries in /etc/shorewall/mangle or /etc/shorewall/tcrules.

## Traffic control outside Shorewall

To start traffic shaping when you bring up your network interfaces, you will have to arrange for your traffic shaping configuration script to be run at that time. How you do that is distribution dependent and will not be covered here. You then should:

1.  Set TC_ENABLED=No and CLEAR_TC=No

2.  If your script uses the “fwmark” classifier, you can mark packets using entries in /etc/shorewall/mangle or /etc/shorewall/tcrules.

# Testing Tools

At least one Shorewall user has found this tool helpful: <http://e2epi.internet2.edu/network-performance-toolkit.html>
