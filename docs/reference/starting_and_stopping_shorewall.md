<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release**.

</div>

# /sbin/shorewall and /sbin/shorewall-lite

`/sbin/shorewall` is the program that you use to interact with Shorewall. Normally the root user's PATH includes `/sbin` and the program can be run from a shell prompt by simply typing `shorewall` followed by a command.

<div class="warning">

In some releases of KDE, the default configuration of the **konsole** program is brain dead with respect to the "Root Console". It executes the command "su" where it should execute "su -"; the latter will cause a login shell to be created which will in turn set PATH properly. You can correct this problem as follows:

1.  Click on "Settings" on the toolbar and select "Configure Konsole"

2.  Select the "Session" tab.

3.  Click on "Root Console"

4.  Change the Execute command from "su" to "su -"

5.  Click on "Save Session"

6.  Click on "Ok"

</div>

To see a list of supported commands, use the `help` command:

    shorewall help

To get further information about a particular command, use the `man` command:

    man shorewall

The program **/sbin/shorewall-lite** performs a similar role with Shorewall-lite.

For a more complete description of the files and directories involved in Shorewall and Shorewall-lite, see the [Introduction to Shorewall](../concepts/Introduction.md).

# Starting, Stopping and Clearing

As explained in the [Introduction](../concepts/Introduction.md), Shorewall is not something that runs all of the time in your system. Nevertheless, for integrating Shorewall into your initialization scripts it is useful to speak of starting Shorewall and *stopping* Shorewall.

- Shorewall is started using the `shorewall start` command. Once the start command completes successfully, Netfilter is configured as described in your Shorewall configuration files. If there is an error during `shorewall start`, then if you have a saved configuration then that configuration is restored. Otherwise, an implicit `shorewall stop` is executed.

  <div class="important">

  `shorewall start` is implemented as a compile and go; that is, the configuration is compiled and if there are no compilation errors then the resulting compiled script is executed. If there are compilation errors, the command is aborted and the state of the firewall is not altered.

  </div>

- Shorewall is stopped using the `shorewall stop` command.

  <div class="important">

  The `shorewall stop` command does not remove all Netfilter rules and open your firewall for all traffic to pass. It rather places your firewall in a safe state defined by the contents of your [/etc/shorewall/stoppedrules](https://shorewall.org/manpages/shorewall-stoppedrules.html) file and the setting of ADMINISABSENTMINDED in [/etc/shorewall/shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html).

  </div>

- If you want to remove all Netfilter rules and open your firewall for all traffic to pass, use the `shorewall clear` command.

- If you change your configuration and want to install the changes, use the `shorewall reload`command.

For additional information, see the[ Shorewall State Diagram](#State) section.

# /etc/init.d/shorewall and /etc/init.d/shorewall-lite

Because of the different requirements of distribution packaging systems, the behavior of `/etc/init.d/shorewall` and `/etc/init.d/shorewall-lite` is not consistent between distributions. As an example, when using the distribution Shorewall packages on Debian and Ubuntu systems, running `/etc/init.d/shorewall stop` will actually execute the command `/sbin/shorewall clear` rather than `/sbin/shorewall stop`! So don't expect the meaning of *start*, *stop*, *restart*, etc. to be consistent between `/sbin/shorewall` (or `/sbin/shorewall-lite`) and your init scripts unless you got your Shorewall package from shorewall.net.

**Update:**

> In Shorewall 4.4.0 and later, the tarballs from shorewall.net follow the Debian convention when installed on a Debian or Ubuntu system. Beginning with Shorewall 4.4.10, you can revert to the prior behavior by setting SAFESTOP=1 in `/etc/default/shorewall`, `/etc/default/shorewall6`, etc.

# systemd

As with SysV init described in the preceeding section, the behavior of systemctl commands differ from the Shorewall CLI commands on Debian-based systems. In versions of Shorewall before 5.2.9, to make `systemctl stop shorewall` and `systemctl restart shorewall` behave like `shorewall stop` and `shorewall restart`, use this workaround provided by J Cliff Armstrong:

Type (as root):

        systemctl edit shorewall.service

This will open the default terminal editor to a blank file in which you can paste the following:

    [Service]
    # reset ExecStop ExecStop=
    # set ExecStop to "stop" instead of "clear"
    ExecStop=/sbin/shorewall $OPTIONS stop

Then type

        systemctl daemon-reload

to activate the changes. This change will survive future updates of the shorewall package from apt repositories. The override file itself will be saved to `/etc/systemd/system/shorewall.service.d/`.

The same workaround may be applied to the other Shorewall products (excluding Shorewall Init).

From Shorewall 5.2.9 onwards, the systemd service files have been updated to execute a shell script that obeys the SAFESTOP setting to stop the firewall, and the workaround is no longer necessary.

# Tracing Command Execution and other Debugging Aids

Shorewall includes features for tracing and debugging. Commands involving the compiler can have the word **trace** inserted immediately after the command.

Example:

    shorewall trace check -r   # Shorewall versions prior to 5.2.4
    shorewall check -D         # Shorewall versions 5.2.4 and later

This produces a large amount of diagnostic output to standard out during the compilation step. If the command invokes the compiled firewall script, then that script's execution is traced to standard error. If entered on a command that invokes neither the compiler nor the compiled script, **trace** is ignored.

Commands that invoke a compiled fireawll script can have the word debug inserted immediately after the command.

Example:

    shorewall debug restart    # Shorewall versions prior to 5.2.4
    shorewall -D restart       # Shorewall versions 5.2.4 and later

**debug** (-D) causes altered behavior of scripts generated by the Shorewall compiler. These scripts normally use ip\[6\]tables-restore to install the Netfilter ruleset, but with debug, the commands normally passed to iptables-restore in its input file are passed individually to ip\[6\]tables. This is a diagnostic aid which allows identifying the individual command that is causing ip\[6\]tables-restore to fail; it should be used when ip\[6\]tables-restore fails when executing a COMMIT command.

<div class="warning">

The debug feature is strictly for problem analysis. When debug is used:

- The firewall is made 'wide open' before the rules are applied.

- The `stoppedrules` file is not consulted.

- The rules are applied in the canonical ip\[6\]tables-restore order. So if you need critical hosts to be always available during start/restart, you may not be able to use debug.

</div>

# Saving a Working Configuration for Error Recovery and Fast Startup

Once you have Shorewall working the way that you want it to, you can use `shorewall save` to save the commands necessary to recreate that configuration in a restore script.

In its simplest form, the save command is just:

    shorewall save

That command creates the default restore script, `/var/lib/shorewall/restore`. The default may be changed using the RESTOREFILE option in [/etc/shorewall/shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html). A different file name may also be specified in the `save` command:

    shorewall save <filename>

Where \<*filename*\> is a simple file name (no slashes).

Once created, the default restore script serves several useful purposes:

- If you change your configuration and there is an error when you try to restart Shorewall, the restore script will be run to restore your firewall to working order.

- Bootup is faster (although with Shorewall-perl, the difference is minimal). The -f option of the start command (e.g., `shorewall -f start`) causes Shorewall to look for the default restore script and if it exists, the script is run. When using Shorewall-shell, this is much faster than starting Shorewall using the normal mechanism of reading the configuration files and running `iptables` dozens or even hundreds of times.

  The default is to not use -f. If you wish to change the default, you must set the OPTIONS shell variable in either `/etc/default/shorewall` or `/etc/sysconfig/shorewall` (if your distribution provides neither of these files, you must create one or the other).

  **Update**: In Shorewall 4.4.20, a new LEGACY_FASTSTART option was added to [/etc/shorewall/shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html). When LEGACY_FASTSTART=No, the compiled script that did the last successful `start` or `restart` will be used.

- The `shorewall restore` command can be used at any time to quickly configure the firewall.

      shorewall restore [ <filename> ]

  If no \<*filename*\> is given, the default restore script is used. Otherwise, the script `/var/lib/shorewall/<filename>` is used.

The ability to have multiple restore scripts means that you can save different Shorewall firewall configurations and switch between them quickly using the `restore` command.

Restore scripts may be removed using the `shorewall forget` command:

    shorewall forget [ <filename> ]

If no \<*filename*\> is given, the default restore script is removed. Otherwise, `/var/lib/shorewall/<filename>` is removed (of course, you can also use the Linux `rm` command from the shell prompt to remove these files).

# Additional Configuration Directories

The CONFIG_PATH setting in `/etc/shorewall/shorewall.conf` determines where Shorewall looks for configuration files. The default setting is CONFIG_PATH=`/etc/shorewall`:`/usr/share/shorewall` which means that `/etc/shorewall` is searched first and if the file is not found then `/usr/share/shorewall` is searched. You can change the value of CONFIG_PATH to cause additional directories to be searched but CONFIG_PATH should *always* include both `/etc/shorewall` and `/usr/share/shorewall`.

When an alternate configuration directory is specified as described in the [next section](#AddDirectories), that directory is searched *before* those directories listed in CONFIG_PATH.

Example - Search `/etc/shorewall`, `/etc/shorewall/actiondir` and `/usr/share/shorewall` in that order:

    CONFIG_PATH=/etc/shorewall:/etc/shorewall/actiondir:/usr/share/shorewall

The above is the setting that I once used to allow me to place all of my user-defined 'action.' files in `/etc/shorewall/actiondir`.

# Alternate Configuration Directories

As explained [above](#AddDirectories), Shorewall normally looks for configuration files in the directories specified by the CONFIG_PATH option in `/etc/shorewall/shorewall.conf`. The `shorewall start`, `shorewall restart`, `shorewall check`, and `shorewall try`commands allow you to specify an additional directory for Shorewall to check before looking in the directories listed in CONFIG_PATH.

         shorewall {start|restart|check} <configuration-directory>
         shorewall try <configuration-directory> [ <timeout> ]

If a *\<configuration-directory*\> is specified, each time that Shorewall is going to read a file, it will first look in the *\<configuration-directory\>* . If the file is present in the *\<configuration-directory\>,* that file will be used; otherwise, the directories in the CONFIG_PATH will be searched. When changing the configuration of a production firewall, I recommend the following:

- If you haven't saved the current working configuration, do so using `shorewall save`.

- `mkdir /etc/test`

- `cd /etc/test`

- \<copy any files that you need to change from /etc/shorewall to . and change them here\>

- `shorewall check ./`

- \<correct any errors found by check and check again\>

- `shorewall restart ./`

If the `restart` fails, your configuration will be restored to its state at the last `shorewall save`.

When the new configuration works then just:

- `cp -f * /etc/shorewall`

- `cd`

- `rm -rf /etc/test`

- `shorewall save`

<div class="important">

Shorewall requires that the file `/etc/shorewall/shorewall.conf` to always exist. Certain global settings are always obtained from that file. If you create alternative configuration directories, do not remove /etc/shorewall/shorewall.conf.

</div>

# Commands

The general form of a command is:

> `shorewall [ <options> ] <command> [ <command options> ] [ <argument> ... ]`
>
> Available options are:
>
> -c \<directory\>  
> Specifies an [alternate configuration directory](#AltConfig). Use of this option is deprecated.
>
> -f  
> Specifies fast restart. See the `start` command below.
>
> -n  
> Prevents the command from changing the firewall system's routing configuration.
>
> -q  
> Reduces the verbosity level (see VERBOSITY setting in [shorewall.conf](manpages/shorewall.conf.htmlig)). May be repeated (e.g., "-qq") with each instance reducing the verbosity level by one.
>
> -v  
> Increases the verbosity level (see VERBOSITY setting in [shorewall.conf](manpages/shorewall.conf.htmlig)). May be repeated (e.g., "-vv") with each instance increasing the verbosity level by one.
>
> -x  
> Causes all iptables -L commands to display actual packet and byte counts.
>
> -t  
> All progress messages are timestamped with the date and time.
>
> In addition, the `-q` and `-v` options may be repeated to make the output less or more verbose respectively. The default level of verbosity is determined by the setting of the VERBOSITY option in `/etc/shorewall/shorewall.conf`.
>
> For Shorewall Lite, the general command form is:
>
> `shorewall-lite [ <options> ] <command> [ <command options> ] [ <argument> ... ]`
>
> where the options are the same as with Shorewall.
>
> The complete documentation for each command may be found in the [shorewall](https://shorewall.org/manpages/shorewall.html) and [shorewall-lite](https://shorewall.org/manpages/shorewall-lite.html) man pages.

# Shorewall State Diagram

The Shorewall State Diagram is depicted below.

| /sbin/shorewall Command | Resulting /var/lib/shorewall/firewall Command                                                                                                                    | Effect if the Command Succeeds                                                                                                                                                                                                                                                                |
|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| shorewall start         | firewall start                                                                                                                                                   | The system filters packets based on your current Shorewall Configuration                                                                                                                                                                                                                      |
| shorewall stop          | firewall stop                                                                                                                                                    | Only traffic allowed by ACCEPT entries in /etc/shorewall/stoppedrules is passed to/from/through the firewall. If ADMINISABSENTMINDED=Yes in /etc/shorewall/shorewall.conf then in addition, all existing connections are retained and all connection requests from the firewall are accepted. |
| shorewall reload        | firewall reload                                                                                                                                                  | Very similar to start, replacing the existing ruleset with one that reflects the current configuration file contents.                                                                                                                                                                         |
| shorewall restart       | firewall restart                                                                                                                                                 | Logically equivalent to “firewall stop;firewall start”                                                                                                                                                                                                                                        |
| shorewall add           | firewall add                                                                                                                                                     | Adds a host or subnet to a dynamic zone                                                                                                                                                                                                                                                       |
| shorewall delete        | firewall delete                                                                                                                                                  | Deletes a host or subnet from a dynamic zone                                                                                                                                                                                                                                                  |
| shorewall refresh       | firewall refresh                                                                                                                                                 | Reloads rules dealing with static blacklisting, traffic control and ECN.                                                                                                                                                                                                                      |
| shorewall reset         | firewall reset                                                                                                                                                   | Resets traffic counters                                                                                                                                                                                                                                                                       |
| shorewall clear         | firewall clear                                                                                                                                                   | Removes all Shorewall rules, chains, addresses, routes and ARP entries.                                                                                                                                                                                                                       |
| shorewall try           | firewall -c \<new configuration\> restart If unsuccessful then firewall start (standard configuration) If timeout then firewall restart (standard configuration) |                                                                                                                                                                                                                                                                                               |

The only time that a program other than `/usr/share/shorewall[-lite[/firewall` performs a state transition itself is when the `shorewall[-lite] restore` command is executed. In that case, the `/var/lib/shorewall[-lite]/restore` program sets the state to "Started".

With any command that involves compilation, there is no state transition while the compiler is running. If compilation fails, the state remains unchanged.

Also, `shorewall start`, `shorewall reload` and `shorewall restart` involve compilation followed by execution of the compiled script. So it is the compiled script that performs the state transition in these commands rather than `/usr/share/shorewall/firewall`.

The compiled script is placed in `/var/lib/shorewall` and is named either `.start`, .reload or `.restart` depending on the command.
