<div class="caution">

**This article applies to Shorewall 4.0 and later. If you are running a version of Shorewall earlier than Shorewall 4.0.0 then please see the documentation for that release.**

</div>

# FTP Protocol

FTP transfers involve two TCP connections. The first **control** connection goes from the FTP client to port 21 on the FTP server. This connection is used for logon and to send commands and responses between the endpoints. Data transfers (including the output of “ls” and “dir” commands) requires a second data connection. The **data** connection is dependent on the **mode** that the client is operating in:

Passive Mode  
(often the default for web browsers) -- The client issues a PASV command. Upon receipt of this command, the server listens on a dynamically-allocated port then sends a PASV reply to the client. The PASV reply gives the IP address and port number that the server is listening on. The client then opens a second connection to that IP address and port number.

Active Mode  
(often the default for line-mode clients) -- The client listens on a dynamically-allocated port then sends a PORT command to the server. The PORT command gives the IP address and port number that the client is listening on. The server then opens a connection to that IP address and port number; the **source port** for this connection is 20 (ftp-data in /etc/services).

You can see these commands in action using your linux ftp command-line client in debugging mode. Note that my ftp client defaults to passive mode and that I can toggle between passive and active mode by issuing a “passive” command:

    [teastep@wookie Shorewall]$ ftp ftp1.shorewall.net
    Connected to lists.shorewall.net.
    220-=(<*>)=-.:. (( Welcome to PureFTPd 1.0.12 )) .:.-=(<*>)=-
    220-You are user number 1 of 50 allowed.
    220-Local time is now 10:21 and the load is 0.14. Server port: 21.
    220 You will be disconnected after 15 minutes of inactivity.
    500 Security extensions not implemented
    500 Security extensions not implemented
    KERBEROS_V4 rejected as an authentication type
    Name (ftp1.shorewall.net:teastep): ftp
    331-Welcome to ftp.shorewall.net
    331-
    331 Any password will work
    Password:
    230 Any password will work
    Remote system type is UNIX.
    Using binary mode to transfer files.
    ftp> debug
    Debugging on (debug=1).
    ftp> ls
    ---> PASV
    227 Entering Passive Mode (192,168,1,193,195,210)
    ---> LIST
    150 Accepted data connection
    drwxr-xr-x    5 0        0            4096 Nov  9  2002 archives
    drwxr-xr-x    2 0        0            4096 Feb 12  2002 etc
    drwxr-sr-x    6 0        50           4096 Feb 19 15:24 pub
    226-Options: -l
    226 3 matches total
    ftp> passive
    Passive mode off.
    ftp> ls
    ---> PORT 192,168,1,3,142,58
    200 PORT command successful
    ---> LIST
    150 Connecting to port 36410
    drwxr-xr-x    5 0        0            4096 Nov  9  2002 archives
    drwxr-xr-x    2 0        0            4096 Feb 12  2002 etc
    drwxr-sr-x    6 0        50           4096 Feb 19 15:24 pub
    226-Options: -l
    226 3 matches total
    ftp>

Things to notice:

1.  The commands that I issued are **strongly emphasized**.

2.  Commands sent by the client to the server are preceded by ---\>

3.  Command responses from the server over the control connection are numbered.

4.  FTP uses a comma as a separator between the bytes of the IP address.

5.  When sending a port number, FTP sends the MSB then the LSB and separates the two bytes by a comma. As shown in the PORT command, port 142,58 translates to 142\*256+58 = 36410.

# Linux FTP connection-tracking

Given the normal loc-\>net policy of ACCEPT, passive mode access from local clients to remote servers will always work but active mode requires the firewall to dynamically open a “hole” for the server's connection back to the client. Similarly, if you are running an FTP server in your local zone then active mode should always work but passive mode requires the firewall to dynamically open a “hole” for the client's second connection to the server. This is the role of FTP connection-tracking support in the Linux kernel.

Where any form of NAT (SNAT, DNAT, Masquerading) on your firewall is involved, the PORT commands and PASV responses may also need to be modified by the firewall. This is the job of the FTP nat support kernel function.

Including FTP connection-tracking and NAT support normally means that the modules “nf_conntrack_ftp” and “nf_nat_ftp” need to be loaded. Shorewall automatically loads these “helper” modules from /lib/modules/\<*kernel-version*\>/kernel/net/netfilter/ and you can determine if they are loaded using the “lsmod” command. The \<*kernel-version*\> may be obtained by typing

    uname -r

<div class="important">

Note: If you are running kernel 2.6.19 or earlier, then the module names are **ip_nat_ftp** and **ip_conntrack_ftp** and they are normally loaded from /lib/modules/\<*kernel-version*\>/kernel/net/ipv4/netfilter/.

</div>

<div class="important">

Because the ftp helper modules must read and modify commands being sent over the command channel, they won't work when the command channel is encrypted through use of TLS/SSL.

</div>

    [root@lists etc]# lsmod
    Module                  Size  Used by    Not tainted
    iptable_filter          3072  1 
    iptable_mangle          2816  0 
    iptable_nat             7684  0 
    iptable_raw             2048  0 
    ip_tables              12232  4 iptable_raw,iptable_mangle,iptable_nat,iptable_filter
    ipt_addrtype            1920  0 
    ipt_ah                  2048  0 
    ipt_CLUSTERIP           8708  0 
    ipt_ecn                 2304  0 
    ipt_ECN                 3072  0 
    ipt_iprange             1920  0 
    ipt_LOG                 6528  0 
    ipt_MASQUERADE          3456  0 
    ipt_NETMAP              2048  0 
    ipt_owner               2048  0 
    ipt_recent              9496  0 
    ipt_REDIRECT            2048  0 
    ipt_REJECT              4608  0 
    ipt_SAME                2432  0 
    ipt_TCPMSS              4096  0 
    ipt_tos                 1664  0 
    ipt_TOS                 2304  0 
    ipt_ttl                 1920  0 
    ipt_TTL                 2432  0 
    ipt_ULOG                8068  0 
    nf_conntrack           59864  28 ipt_MASQUERADE,ipt_CLUSTERIP,nf_nat_tftp,nf_nat_snmp_basic,nf_nat_sip,nf_nat_pptp,nf_nat_irc,nf_nat_h323,nf_nat_ftp,nf_nat_amanda,nf_conntrack_ama
    nda,nf_conntrack_tftp,nf_conntrack_sip,nf_conntrack_proto_sctp,nf_conntrack_pptp,nf_conntrack_proto_gre,nf_conntrack_netlink,nf_conntrack_netbios_ns,nf_conntrack_irc,nf_conntrack_
    h323,nf_conntrack_ftp,xt_helper,xt_state,xt_connmark,xt_conntrack,iptable_nat,nf_nat,nf_conntrack_ipv4
    nf_conntrack_amanda     5248  1 nf_nat_amanda
    nf_conntrack_ftp        9728  1 nf_nat_ftp
    nf_conntrack_h323      50396  1 nf_nat_h323
    nf_conntrack_ipv4      17932  2 iptable_nat
    nf_conntrack_irc        7064  1 nf_nat_irc
    nf_conntrack_netbios_ns     3072  0 
    nf_conntrack_netlink    26240  0 
    nf_conntrack_pptp       6912  1 nf_nat_pptp
    nf_conntrack_proto_gre     5632  1 nf_conntrack_pptp
    nf_conntrack_proto_sctp     8328  0 
    nf_conntrack_sip        9748  1 nf_nat_sip
    nf_conntrack_tftp       5780  1 nf_nat_tftp
    nf_nat                 17964  14 ipt_SAME,ipt_REDIRECT,ipt_NETMAP,ipt_MASQUERADE,nf_nat_tftp,nf_nat_sip,nf_nat_pptp,nf_nat_proto_gre,nf_nat_irc,nf_nat_h323,nf_nat_ftp,nf_nat_amand
    a,nf_conntrack_netlink,iptable_nat
    nf_nat_amanda           2432  0 
    nf_nat_ftp              3584  0 
    nf_nat_h323             7808  0 
    nf_nat_irc              2816  0 
    nf_nat_pptp             3840  0 
    nf_nat_proto_gre        3204  1 nf_nat_pptp
    nf_nat_sip              4608  0 
    nf_nat_snmp_basic      10372  0 
    nf_nat_tftp             1920  0 
    xt_CLASSIFY             1920  0 
    xt_comment              1920  0 
    xt_connmark             2432  0 
    xt_conntrack            2944  0 
    xt_dccp                 3588  0 
    xt_hashlimit           10252  0 
    xt_helper               2688  0 
    xt_length               1920  0 
    xt_limit                2688  0 
    xt_mac                  1920  0 
    xt_mark                 1920  0 
    xt_MARK                 2304  0 
    xt_multiport            3328  1 
    xt_NFLOG                2176  0 
    xt_NFQUEUE              2048  0 
    xt_physdev              2704  2 
    xt_pkttype              1920  0 
    xt_policy               3840  0 
    xt_state                2560  0 
    xt_tcpmss               2304  0 
    xt_tcpudp               3328  0 
    [root@lists etc]#

If you want Shorewall to load these modules from an alternate directory, you need to set the MODULESDIR variable in /etc/shorewall/shorewall.conf to point to that directory.

# FTP with Kernel 3.5 and Later

Because of the potential for attackers to subvert Netfilter helpers like the one for FTP, the Netfilter team are in the process of eliminating the automatic association of helpers to connections. In the 3.5 kernel, it is possible to disable this automatic association, and the team have announced that automatic association will eventually be eliminated. While it is certainly more secure to add explicit rules that create these associations, for Shorewall to require users to add those rules would present a gross inconvenience during a Shorewall upgrade. To make Shorewall and kernel upgrades as smooth as possible, several new features were added to the Shorewall 4.5.7:

- Shorewall automatically disables the kernel's automatic association of helpers to connections on kernel 3.5 and later.

- An automatic association of helpers with connections that performs the same function as in the pre-3.5 kernels has been added. This automatic association is controlled by the AUTOHELPERS shorewall.conf option which is set to 'Yes' by default.

- A HELPERS column has been added to the /etc/shorewall/rules In the NEW section: When the ACTION is ACCEPT, DNAT or REDIRECT, the specified helper is automatically associated with the connection.

- HELPERS may be specified in action files, macros and in the rules file itself. In the RELATED section: The rule will only match related connections that have the named helper attached. - The standard Macros for applications requiring a helper (FTP, IRC, etc) have been modified to automatically specify the correct helper in the HELPER column.

- HELPER is now a valid action in /etc/shorewall/rules. This action requires that a helper be present in the HELPER column and causes the specified helper to be associated with connections matching the rule. No destination zone should be specified in HELPER rules. HELPER rules allow specification of a helper for connections that are ACCEPTed by the applicable policy.

  Example (loc-\>net policy is ACCEPT) - In /etc/shorewall/rules:

      #ACTION     SOURCE       DEST
      FTP(HELPER) loc          - 

  or equivalently

      #ACTION     SOURCE       DEST    PROTO  DPORT
      HELPER      loc          -       tcp    21   { helper=ftp }

- The set of enabled helpers (either by AUTOHELPERS=Yes or by the HELPERS column) can be taylored using the new HELPERS option in shorewall.conf.

By making AUTOHELPERS=Yes the default, users can upgrade their systems to a 3.5+ kernel without disrupting the operation of their firewalls. Beyond such upgrades, we suggest setting AUTOHELPERS=No and follow one of two strategies:

- Use the HELPERS column in the rules file to enable helpers as needed (preferred); or

- Taylor the conntrack file to enable helpers on only those connections that are required.

With either of these approaches, the list if available helpers can be trimmed using the HELPERS option and rules can be added to the RELATED section of the rules file to further restrict the effect of helpers. The implementation of these new function places conditional rules in the /etc/shorewall\[6\]/conntrack file. These rules are included conditionally based in the setting of AUTOHELPERS.

Example:

    #ACTION                 SOURCE          DESTINATION     PROTO   DPORT           SPORT   USER            SWITCH
    ?if $AUTOHELPERS && __CT_TARGET
    ?if __FTP_HELPER
    CT:helper:ftp           all             -               tcp     21
    ?endif
    ...
    ?endif

\_\_FTP_HELPER evaluates to false if the HELPERS setting is non-empty and 'ftp' is not listed in that setting. For example, if you only need FTP access from your 'loc' zone, then add this rule outside of the outer-most ?if....?endif shown above.

    #ACTION                 SOURCE          DESTINATION     PROTO   DPORT           SPORT   USER            SWITCH
    ...
    CT:helper:ftp           loc             -               tcp     21

For an overview of Netfilter Helpers and Shorewall's support for dealing with them, see [https://shorewall.org/Helpers.html](Helpers.md).

See <https://home.regit.org/netfilter-en/secure-use-of-helpers/> for additional information.

# FTP on Non-standard Ports

If you are running kernel 3.5 or later and Shorewall 4.5.7 or later, then please read the preceding section. You can add appropriate entries into [shorewall-rules(5)](https://shorewall.org/manpages/shorewall-rules.html) or [shorewall-conntrack(5)](https://shorewall.org/manpages/shorewall-conntrack.html) to associate the FTP helpers with a nonstandard port.

Examples using port 12345:

`/etc/shorewall/rules:`

    #ACTION         SOURCE         DEST                 PROTO     DPORT
    DNAT            net            loc:192.168.1.2:21   tcp       12345  { helper=ftp }

That entry will accept ftp connections on port 12345 from the net and forward them to host 192.168.1..2 and port 21 in the loc zone.

`/etc/shorewall/conntrack:`

    #ACTION                 SOURCE          DESTINATION     PROTO   DPORT           SPORT   USER            SWITCH
    ...
    CT:helper:ftp           loc             -               tcp     12345

That rule automatically associates the ftp helper with TCP port 12345 from the 'loc' zone.

Otherwise, read on.

<div class="note">

If you are running **kernel 2.6.19 or earlier**, replace **nf_conntrack_ftp** with **ip_conntrack_ftp** in the following instructions. Similarly, replace **nf_nat_ftp** with **ip_nat_ftp**.

</div>

The above discussion about commands and responses makes it clear that the FTP connection-tracking and NAT helpers must scan the traffic on the control connection looking for PASV and PORT commands as well as PASV responses. If you run an FTP server on a nonstandard port or you need to access such a server, you must therefore let the helpers know by specifying the port in `/etc/shorewall/modules` entries for the helpers. You should create`/etc/shorewall/modules` by copying `/usr/share/shorewall/modules`.

<div class="caution">

You must have modularized FTP connection tracking support in order to use FTP on a non-standard port.

</div>

    loadmodule nf_conntrack_ftp ports=21,49
    loadmodule nf_nat_ftp                   # NOTE: With kernels prior to 2.6.11, you must specify the ports on this line also

<div class="note">

you MUST include port 21 in the ports list or you may have problems accessing regular FTP servers.

</div>

If there is a possibility that these modules might be loaded before Shorewall starts, then you should include the port list in /etc/modules.conf:

    options nf_conntrack_ftp ports=21,49
    options nf_nat_ftp

<div class="important">

Once you have made these changes to /etc/shorewall/modules and/or /etc/modules.conf, you must either:

1.  Unload the modules and restart shorewall:

        rmmod nf_nat_ftp; rmmod nf_conntrack_ftp; shorewall restart

2.  Reboot

</div>

# Rules

<div class="warning">

If you run an FTP server behind your firewall and your server offers a method of specifying the external IP address of your firewall, DON'T USE THAT FEATURE OF YOUR SERVER. Using that option will defeat the purpose of the ftp helper modules and can result in a server that doesn't work.

</div>

If the policy from the source zone to the destination zone is ACCEPT and you don't need DNAT (see [FAQ 30](../reference/FAQ.md#faq30)) then **you need no rule**.

Otherwise, for FTP you need exactly **one** rule:

    #ACTION      SOURCE     DESTINATION    PROTO     DPORT      SPORT       ORIGDEST
    ACCEPT or    <source>   <destination>  tcp       21         -           <external IP addr> if
    DNAT                                                                    ACTION = DNAT

You need an entry in the ORIGDEST column only if the ACTION is DNAT, you have multiple external IP addresses and you want a specific IP address to be forwarded to your server.

Note that you do **NOT** need a rule with 20 (ftp-data) in the DPORT column. If you post your rules on the mailing list and they show 20 in the DPORT column, we will know that you haven't read this article and will either ignore your post or tell you to RTFM.

Shorewall includes an FTP macro that simplifies creation of FTP rules. The macro source is in `/usr/share/shorewall/macro.FTP`. Using the macro is the preferred way to generate the rules described above. Here are a couple of examples.

Suppose that you run an FTP server on 192.168.1.5 in your local zone using the standard port (21). You need this rule:

    #ACTION      SOURCE     DESTINATION     PROTO     DPORT      SPORT       ORIGDEST
    FTP(DNAT)    net       loc:192.168.1.5

    #ACTION      SOURCE     DESTINATION     PROTO     DPORT      SPORT       ORIGDEST
    FTP(ACCEPT)  dmz        net

Note that the FTP connection tracking in the kernel cannot handle cases where a PORT command (or PASV reply) is broken across two packets or is missing the ending \<cr\>/\<lf\>. When such cases occur, you will see a console message similar to this one:

    Apr 28 23:55:09 gateway kernel: conntrack_ftp: partial PORT 715014972+1

or this one:

    21:37:40 insert-master kernel: [832161.057782] nf_ct_ftp: dropping 
    packet IN=eth4 OUT= MAC=00:0a:cd:1a:d1:95:00:22:6b:be:3c:41:08:00 
    SRC=66.199.187.46 DST=192.168.41.1 LEN=102 TOS=0x00 PREC=0x00 TTL=45 
    ID=30239 DF PROTO=TCP SPT=21 DPT=50892 SEQ=698644583 ACK=3438176321 
    WINDOW=46 RES=0x00 ACK PSH URGP=0 OPT (0101080A932DFE0231935CF7) MARK=0x1

I see this problem occasionally with the FTP server in my DMZ. My solution is to add the following rule:

    #ACTION      SOURCE     DESTINATION     PROTO     DPORT      SPORT       ORIGDEST
    ACCEPT:info  dmz        net             tcp       -          20

The above rule accepts and logs all active mode connections from my DMZ to the net.
