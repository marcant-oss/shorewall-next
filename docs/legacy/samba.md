<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

If you wish to run Samba on your firewall and access shares between the firewall and local hosts, you need the following rules:

    #ACTION   SOURCE   DEST   PROTO    DPORT          SPORT
    SMB(ACCEPT)  $FW      loc
    SMB(ACCEPT)  loc      $FW

To pass traffic SMB/Samba traffic between zones Z1 and Z2:

    #ACTION   SOURCE   DEST   PROTO    DPORT          SPORT
    SMB(ACCEPT)  Z1       Z2
    SMB(ACCEPT)  Z2       Z1

To make network browsing (“Network Neighborhood”) work properly between Z1 and Z2 **requires a Windows Domain Controller and/or a WINS server.** I have run Samba on my firewall to handle browsing between two zones connected to my firewall.

When debugging Samba/SMB problems, I recommend that you do the following:

1.  Copy `action.Drop` and `action.Reject` from `/usr/share/shorewall` to `/etc/shorewall`.

2.  Edit the copies and remove the **SMB(DROP)** and **SMB(REJECT)** lines.

3.  `shorewall restart`

The above steps will cause SMB traffic that is dropped or rejected by policy to be logged rather than handled silently.

If you are using Windows XP to test your setup,make you sure you have a properly configured client firewall .

You can just remove the copies and `shorewall restart` when you are finished debugging.
