# Shorewall 5.0.5 and Earlier

Both Docker and Shorewall assume that they 'own' the iptables configuration. This leads to problems when Shorewall is restarted or reloaded, because it drops all of the rules added by Docker. Fortunately, the extensibility features in Shorewall allow users to [create their own solution](https://blog.discourse.org/2015/11/shorewalldocker-two-great-tastes-that-taste-great-together/#) for saving the Docker-generated rules before these operations and restoring them afterwards.

# Shorewall 5.0.6 and Later

Beginning with Shorewall 5.0.6, Shorewall has native support for simple Docker configurations. This support is enabled by setting DOCKER=Yes in shorewall.conf. With this setting, the generated script saves the Docker-created ruleset before executing a `stop`, `start`, `restart` or `reload` operation and restores those rules along with the Shorewall-generated ruleset.

<div class="important">

Shorewall currently doesn't support Docker Swarm mode.

</div>

<div class="warning">

On Debian and Debian-derived systems, `systemctl restart shorewall` will lose Docker rules. You can work around this issue using a method provided by J Cliff Armstrong:

Type as root:

    systemctl edit shorewall.service

This will open the default terminal editor to a blank file in which you can paste the following:

    [Service]
    # reset ExecStop
    ExecStop=
    # set ExecStop to "stop" instead of "clear"
    ExecStop=/sbin/shorewall $OPTIONS stop

Then type `systemctl daemon-reload`to activate the changes. This change will survive future updates of the shorewall package from apt repositories. The override file itself will be saved to \`/etc/systemd/system/shorewall.service.d/\`.

</div>

This support assumes that the default Docker bridge (docker0) is being used. It is recommended that this bridge be defined to Shorewall in [shorewall-interfaces(8)](https://shorewall.org/manpages/shorewall-interfaces.html). As shown below, you can control inter-container communication using the `bridge` and `routeback` options. If docker0 is not defined to Shorewall, then Shorewall will save and restore the FORWARD chain rules involving that interface.

`/etc/shorewall/shorewall.conf`:

    DOCKER=Yes

`/etc/shorewall/zones`:

    #ZONE         TYPE        OPTIONS
    dock          ipv4        #'dock' is just an example -- call it anything you like

`/etc/shorewall/policy`:

    #SOURCE        DEST        POLICY         LEVEL
    dock           $FW         REJECT
    dock           all         ACCEPT

`/etc/shorewall/interfaces`:

    #ZONE          INTERFACE        OPTIONS
    dock           docker0          bridge   #Allow ICC (bridge implies routeback=1)

or

    #ZONE          INTERFACE        OPTIONS
    dock           docker0          bridge,routeback=0   #Disallow ICC
