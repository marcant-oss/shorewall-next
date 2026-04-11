<div class="caution">

This article applies to Shorewall 4.5.19 and later and supersedes [this article.](../features/PortKnocking.md)

</div>

# Overview

Shorewall events were introduced in Shorewall 4.5.19 and provide a high-level interface to the Netfilter recent match capability. An event is actually a list of (IP address, timestamp) pairs, and can be tested in a number of different ways:

- Has event E ever occurred for IP address A (is the IP address in the list)?

- Has event E occurred M or more times for IP address A?

- Has Event E occurred in the last N seconds for IP Address A (is there an entry for the address with a timestamp falling within the last N seconds)?

- Has Event E occurred M or more times in the last N seconds for IP address A (are there M or more entries for the address with timestamps falling within the last N seconds)?

The event interface is implemented as three parameterized Shorewall [Actions](Actions.md):

SetEvent  
This action initializes an event list for either the source or destination IP address in the current packets. The list will contain a single entry for the address that will have the current timestamp.

ResetEvent  
This action removes all entries for either the source or destination IP address from an event list.

IfEvent  
This action tests an event in one of the ways listed above, and performs an action based on the result.

Events are based on the Netfilter 'recent match' capability which is required for their use.

The recent-match kernel component is xt_recent which has two options that are of interest to Shorewall users:

ip_list_tot  
The number of addresses remembered per event. Default is 100.

ip_pkt_list_tot  
The number of packets (event occurrences) remembered per address. Default is 20.

These may be changed with the xt_recent module is loaded or on the kernel bootloader runline.

# Details

Because these are parameterized actions, optional parameters may be omitted. Trailing omitted parameters may be omitted entirely while embedded omitted parameters are represented by a hyphen ("-").

Each event is given a name. Event names:

- Must begin with a letter.

- May be composed of letters, digits, hyphens ('-') or underscores ('\_').

- May be at most 29 characters in length.

## SetEvent

**SetEvent**( \<event\>, \[ \<action\> \], \[ \<src-dst\> \], \[ \<disposition\> \] )

event  
Name of the event.

action  
An action to perform after the event is initialized. May be any action that may appear in the ACTION column of [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5). If no action is to be performed, use COUNT.

src-dst  
Specifies whether the source IP address (**src**) or destination IP address (**dst**) is to be added to the event. The default is **src**.

disposition  
If the \<action\> involves logging, then this parameter specifies the disposition that will appear in the log entry prefix. If no \<disposition\> is given, the log prefix is determined normally. The default is ACCEPT.

## ResetEvent

**ResetEvent**( \<event\>, \[ \<action\> \], \[ \<src-dst\> \], \[ \<disposition\> \] )

event  
Name of the event.

action  
An action to perform after the event is reset. May be any action that may appear in the ACTION column of [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5). If no action is to be performed, use COUNT. The default is ACCEPT.

src-dst  
Specifies whether the source IP address (**src**) or destination IP address (**dst**) is to be removed from the event. The default is **src**.

disposition  
If the \<action\> involves logging, then this parameter specifies the disposition that will appear in the log entry prefix. If no \<disposition\> is given, the log prefix is determined normally.

## IfEvent

**IfEvent**( \<event\>, \[ \<action\> \], \[ \<duration\> \], \[ \<hitcount\> \], \[ \<src-dst\>\], \[ \<command\>\[:\<option\>\]..., \[ \<disposition\> \] )

event  
Name of the event.

action  
An action to perform if the test succeeds. May be any action that may appear in the ACTION column of [shorewall-rules](https://shorewall.org/manpages/shorewall-rules.html) (5). The default is ACCEPT.

duration  
Number of seconds over which the event is to be tested. If not specified, the test is not constrained by time.

hitcount  
Specifies the minimum number of packets required for the test to succeed. If not specified, 1 packet is assumed.

src-dst  
Specifies whether the source IP address (**src**) or destination IP address (**dst**) is to be tested. The default is **src**.

command  
May be one of the following:

check  
Simply test if the \<duration\>/\<hitcount\> test is satisfied. If so, the \<action\> is performed.

reset  
Like **check**. If the test succeeds, the \<event\> will be reset before the \<action\> is taken. Requires the Mark in filter table capability in your kernel and iptables.

update  
Like **check**. Regardless of whether the test succeeds, an entry with the current time and for the \<src-dst\> iP address will be added to the \<event\>.

The default is **check**.

\<option\> may be one of:

reap  
Regardless of whether the test succeeds, entries for the \<src-dst\> IP address that are older than \<duration\> seconds will be deleted from the \<event\>.

ttl  
Constrains the test to require that the packet TTL match the ttl in the original packet that created the entry.

disposition  
If the \<action\> involves logging, then this parameter specifies the disposition that will appear in the log entry prefix. If no \<disposition\> is given, the log prefix is determined normally.

## 'show event' and 'show events' Commands

The CLI programs (`/sbin/shorewall`, `/sbin/shorewall-lite`, etc.) support `show event` and `show events` commands.

The `show event` command shows the contents of the events listed in the command while **show events** lists the contents of all events.

    root@gateway:~# shorewall show events
    Shorewall 4.5.19-Beta2 events at gateway - Sat Jul 13 07:17:59 PDT 2013

    SSH
       src=75.101.251.91 : 2225.808, 2225.592 
       src=218.87.16.135 : 2078.490 

    SSH_COUNTER
       src=65.182.111.112 : 5755.790 
       src=113.162.155.243 : 4678.249 

    sticky001
       src=172.20.1.146 : 5.733, 5.728, 5.623, 5.611, 5.606, 5.606, 5.589, 5.588, 5.565, 5.551, 5.543, 5.521, 5.377, 5.347, 5.347, 5.345, 5.258, 5.148, 5.048, 4.949 
       src=172.20.1.151 : 41.805, 41.800 

    sticky002
       src=172.20.1.213 : 98.122, 98.105, 98.105, 98.105, 98.088, 98.088, 98.088, 98.088, 98.058, 98.058, 80.885, 53.528, 53.526, 53.526, 53.510, 53.383, 53.194, 53.138, 53.072, 3.119 
       src=172.20.1.146 : 4.914, 4.914, 4.898, 4.897, 4.897, 4.896, 4.896, 4.896, 4.882, 4.881, 4.875, 4.875, 4.875, 4.875, 4.875, 4.875, 4.875, 4.874, 4.874, 4.874 

    root@gateway:~# 

The SSH and SSH_COUNTER events are created using the following Automatic Blacklisting example. The sticky001 and sticky002 events are created by the SAME rule action.

Each line represents one event. The list of numbers following the ':' represent the number of seconds ago that a matching packet triggered the event. The numbers are in chronological sequence, so In this event, there were 20 packets from 172.20.1.146 that arrived between 5.733 and 4.949 seconds ago:

    sticky001
       src=172.20.1.146 : 5.733, 5.728, 5.623, 5.611, 5.606, 5.606, 5.589, 5.588, 5.565, 5.551, 5.543, 5.521, 5.377, 5.347, 5.347, 5.345, 5.258, 5.148, 5.048, 4.949 

Note that there may have been earlier packets that also matched, but the system where this example was captured used the default value of the **ip_pkt_list_tot** xt_recent option (20).

The output of these commands is produced by processing the contents of `/proc/net/xt_recent/*`. You can access those files directly to see the raw data. The raw times are the uptime in milliseconds. The %CURRENTTIME entry is created by the `show event[s]` commands to obtain the current uptime.

# Examples

## Automatic Blacklisting

This example is for ssh, but it can be adapted for any application.

The name SSH has been changed to SSHLIMIT so as not to override the Shorewall macro of the same name.

`/etc/shorewall/actions`:

    #ACTION               OPTION                   DESCRIPTION
    SSHLIMIT                                       #Automatically blacklist hosts who exceed SSH connection limits
    SSH_BLACKLIST                                  #Helper for SSHLIMIT

`/etc/shorewall/action.SSH_BLACKLIST`:

    #
    # Shorewall version 4 - SSH_BLACKLIST Action
    #
    ?format 2
    ###############################################################################
    #TARGET     SOURCE  DEST    PROTO   DPORT   SPORT
    #
    # Log the Reject
    #
    LOG:warn:REJECT
    #
    # And set the SSH_COUNTER event for the SOURCE IP address
    #
    SetEvent(SSH_COUNTER,REJECT,src)

`/etc/shorewall/action.SSH`LIMIT:

    #
    # Shorewall version 4 - SSHLIMIT Action
    #
    ?format 2
    ###############################################################################
    #TARGET     SOURCE  DEST    PROTO   DPORT   SPORT
    #
    # Silently reject the client if blacklisted
    #
    IfEvent(SSH_COUNTER,REJECT,300,1)
    #
    # Blacklist if 5 attempts in the last minute
    #
    IfEvent(SSH,SSH_BLACKLIST,60,5,src,check:reap)
    #
    # Log and reject if the client has tried to connect
    # in the last two seconds
    #
    IfEvent(SSH,REJECT:warn:,2,1,-,update,Added)
    #
    # Un-blacklist the client
    #
    ResetEvent(SSH_COUNTER,LOG:warn,-,Removed)
    #
    # Set the 'SSH' EVENT and accept the connection
    #
    SetEvent(SSH,ACCEPT,src)

`etc/shorewall/rules`:

    #ACTION               SOURCE         DEST      PROTO      DPORT
    SSHLIMIT              net            $FW       tcp        22                        

<div class="caution">

The technique demonstrated in this example is not self-cleaning. The SSH_COUNTER event can become full with blackisted addresses that never attempt to connect again. When that happens and a new entry is added via SetEvent, the least recently seen address in the table is deleted.

</div>

## Generalized Automatic Blacklisting

The above two actions are generalized in the AutoBL and AutoBLL actions released in Shorewall 4.5.19. Only AutoBL is invoked directly from your rules file; AutoBL invoked AutoBLL internally.

### AutoBL

**AutoBL**( \<event\>, \[ \<Interval\> \], \[ \<hitcount\> \], \[ \<successive\> \], \[ \<blacklist-time\> \], \[ \<disposition\>\], \[ \<log_level\> \] )

event  
Name of the event. The blacklisting event itself will be \<event\>\_BL (analogous to SSH_COUNTER above).

interval  
Interval, in seconds, over which hits are to be counted. Default is 60 seconds.

hitcount  
Number of matching packets that will trigger automatic blacklisting when they arrive in \<interval\> seconds. Default is 5.

successive  
If a matching packet arrives within this many seconds of the preceding one, it should be logged according to \<log_level\> and handled according to the \<disposition\>. If successive packets are not to be considered, enter 0. Default is 2 seconds.

blacklist-time  
Time, in seconds, that the source IP address is to be blacklisted. Default is 300 (5 minutes).

disposition  
The disposition of blacklisted packets. Default is DROP.

log_level  
Log level at which packets are to be logged. Default is info.

To duplicate the SSHLIMIT entry in `/etc/shorewall/rules` shown above:

    #ACTION               SOURCE         DEST      PROTO      DPORT
    AutoBL(SSH,-,-,-,REJECT,warn)\
                          net            $FW       tcp        22                

## Port Knocking

This example shows a different implementation of the one shown in the [Port Knocking](../features/PortKnocking.md) article.

In this example:

1.  Attempting to connect to port 1600 enables SSH access. Access is enabled for 60 seconds.

2.  Attempting to connect to port 1601 disables SSH access (note that in the article linked above, attempting to connect to port 1599 also disables access. This is an port scan defence as explained in the article).

To implement that approach:

`/etc/shorewall/actions`:

    #ACTION               OPTION                   DESCRIPTION
    Knock                                          #Port Knocking

`/etc/shorewall/action.Knock`:

    #
    # Shorewall version 4 - Port-Knocking Action
    #
    ?format 2
    ###############################################################################
    #ACTION               SOURCE         DEST      PROTO      DPORT
    IfEvent(SSH,ACCEPT:info,60,1,src,reset)\
                          -              -         tcp        22
    SetEvent(SSH,ACCEPT)  -              -         tcp        1600
    ResetEvent(SSH,DROP:info)        

`etc/shorewall/rules`:

    #ACTION               SOURCE         DEST      PROTO      DPORT
    Knock                 net            $FW       tcp        22,1599-1601          

## Stateful Port Knocking (knock with a sequence of ports)

[Gerhard Wiesinger](http://www.wiesinger.com/) has contributed a Perl module that allows you to define portknocking sequences. Download [the module](pub/shorewall/contrib/PortKnocking/KnockEnhanced.pm) and copy it into your site_perl directory.

Using Gerhard's module, a port-knocking rule is defined via a '?PERL' statement. This example opens the SSH port from net-\>fw using the knock sequence 52245, 15623, 19845:

    ?BEGIN PERL
    use KnockEnhanced;
    KnockEnhanced 'net', '$FW', {name => 'SSH1', log_level => 3, proto => 'tcp', target => 'ssh', knocker => [52245,15623,19845]};
    ?END PERL

A few notes on the parameters:

- The first parameter is the rule SOURCE

- The second parameter is the rule DEST

- The third parameter is a Perl hash reference that defines the remaining parameters. Each parameter is specified via \<param\> =\> \<value\>.

  - **proto** is the protocol -- if not specified, the default is tcp

  - **seconds** is the timeout between successive events -- default is 60 seconds.

  - **original_dest** is the rule ORIGDEST

  - **target** is the port(s) that you are trying to open. May either be a single name or number, or it may be a list of names and/or numbers separated by commas and enclosed in square brackets ("\[...\]").

  - **name** is a name used as the base for event and chain names. If not supplied, the first **target** is used, in which case the first target must be a port name.

  - **log_level** specifies logging for the generated rules

  <div class="note">

  Port names and numbers may be optionally followed by a colon (":") and a protocol name or number to override the specified protocol.

  </div>

The module itself contains additional examples of its usage.
