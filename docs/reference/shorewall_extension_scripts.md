<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

# Extension Scripts

Extension scripts are user-provided scripts that are invoked at various points during firewall start, restart, stop and clear. For each script, the Shorewall compiler creates a Bourne Shell function with the extension script as its body and calls the function at runtime.

<div class="caution">

1.  Be sure that you actually need to use an extension script to do what you want. Shorewall has a wide range of features that cover most requirements.

2.  DO NOT SIMPLY COPY RULES THAT YOU FIND ON THE NET INTO AN EXTENSION SCRIPT AND EXPECT THEM TO WORK AND TO NOT BREAK SHOREWALL. TO USE SHOREWALL EXTENSION SCRIPTS YOU MUST KNOW WHAT YOU ARE DOING WITH RESPECT TO iptables/Netfilter AND SHOREWALL.

</div>

The following scripts can be supplied:

- `lib.private` -- Intended to contain declarations of shell functions to be called by other run-time extension scripts. See [this article](../features/MultiISP.md#lsm) for an example of its use.

- `compile` -- Invoked by the rules compiler early in the compilation process. Must be written in Perl.

- `init` -- invoked early in “shorewall start” and “shorewall restart”

- `initdone` -- invoked after Shorewall has flushed all existing rules but before any rules have been added to the builtin chains.

- `start` -- invoked after the firewall has been started or restarted.

- `started` -- invoked after the firewall has been marked as 'running'.

- `stop` -- invoked as a first step when the firewall is being stopped.

- `stopped` -- invoked after the firewall has been stopped.

- `clear` -- invoked after the firewall has been cleared.

- `tcclear` -- invoked to clear traffic shaping when CLEAR_TC=Yes in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html).

- `refresh` -- called in place of `init` when the firewall is being refreshed rather than started or restarted.

- `refreshed` -- invoked after the firewall has been refreshed.

- `maclog` -- invoked while mac filtering rules are being created. It is invoked once for each interface having 'maclist' specified and it is invoked just before the logging rule is added to the current chain (the name of that chain will be in \$CHAIN).

- `isusable` -- invoked when Shorewall is trying to determine the usability of the network interface associated with an optional entry in `/etc/shorewall/providers`. \$1 is the name of the interface which will have been determined to be up and configured before the script is invoked. The return value from the script indicates whether or not the interface is usable (0 = usable, other = unusable).

  Example:

      # Ping a gateway through the passed interface
      case $1 in
          eth0)
              ping -c 4 -t 1 -I eth0 206.124.146.254 > /dev/null 2>&1
              return
              ;;
          eth1)
              ping -c 4 -t 1 -I eth1 192.168.12.254 > /dev/null 2>&1
              return
              ;;
          *)
              # No additional testing of other interfaces
              return 0
              ;;
      esac

  <div class="caution">

  We recommend that this script only be used with ADMINISABSENTMINDED=Yes.

  The firewall state when this script is invoked is indeterminate. So if you have ADMINISABSENTMINDED=No in [shorewall.conf](https://shorewall.org/manpages/shorewall.conf.html)(8) and output on an interface is not allowed by [stoppedrules](https://shorewall.org/manpages/shorewall-stoppedrules.html)(8) then the isuasable script must blow it's own holes in the firewall before probing.

  </div>

- `save` -- This script is invoked during execution of the `shorewall save` and `shorewall-lite save` commands.

- `restored` -- This script is invoked at the completion of a successful `shorewall restore` and `shorewall-lite restore`.

- findgw -- This script is invoked when Shorewall is attempting to discover the gateway through a dynamic interface. The script is most often used when the interface is managed by dhclient which has no standardized location/name for its lease database. Scripts for use with dhclient on several distributions are available at <https://shorewall.org/pub/shorewall/contrib/findgw/>

- `scfilter` -- Added in Shorewall 4.4.14. Unlike the other scripts, this script is executed by the command-line tools (`/sbin/shorewall`, `/sbin/shorewall6`, etc) and can be used to reformat the output of the `show connections` command. The connection information is piped through this script so that the script can drop information, add information or alter the format of the information. When using Shorewall Lite or Shorewall6 Lite, the script is encapsulated in a function that is copied into the generated auxillary configuration file. That function is invoked by the 'show connections' command.

  The default script is as follows and simply pipes the output through unaltered.

      #! /bin/sh
      cat -

- `postcompile` -- Added in Shorewall 4.5.8. This shell script is invoked by **/sbin/shorewall** after a script has been compiled. \$1 is the path name of the compiled script.

- `lib.cli-user` -- Added in Shorewall 5.0.2. This is actually a shell library (set of function declarations) that can be used to augment or replace functions in the standard CLI libraries.

- `enabled` -- Added in Shorewall 5.1.6. Invoked when an optional interface or provider is successfully enabled using the `enable` command.

- `disabled` -- Added in Shorewall 5.1.6. Invoked when an optional interface or provider is successfully disabled using the `disable` command.

**If your version of Shorewall doesn't have the file that you want to use from the above list, you can simply create the file yourself.** You can also supply a script with the same name as any of the filter chains in the firewall and the script will be invoked after the /etc/shorewall/rules file has been processed but before the /etc/shorewall/policy file has been processed.

The following table indicate which commands invoke the various scripts.

|             |                                                                       |
|-------------|-----------------------------------------------------------------------|
| **script**  | **Commands**                                                          |
| clear       | clear                                                                 |
| compile     | check, compile, export, load, refresh, reload, restart, restore,start |
| continue    |                                                                       |
| disable     | disable                                                               |
| enable      | enable                                                                |
| init        | load, refresh, reload, restart restore, start                         |
| initdone    | check, compile, export, refresh, restart, start                       |
| isusable    | refresh, restart, restore, start                                      |
| maclog      | check, compile, export, refresh, restart, start                       |
| postcompile | compile, export, load, refresh, reload, restart, restore, start       |
| refresh     | refresh                                                               |
| refreshed   | refresh                                                               |
| restored    | restore                                                               |
| save        | save                                                                  |
| scfilter    | show connections                                                      |
| start       | load, reload, restart, start                                          |
| started     | load, reload, restart, start                                          |
| stop        | stop, clear                                                           |
| stopped     | stop, clear                                                           |
| tcclear     | load, reload, restart, restore, start                                 |

There are a couple of special considerations for commands in extension scripts:

- When you want to run `iptables`, use the command `run_iptables` instead. `run_iptables` will run the iptables utility passing the arguments to `run_iptables` and if the command fails, the firewall will be stopped (or restored from the last `save` command, if any). `run_iptables` should not be called from the `started` or `restored` scripts.

- If you wish to generate a log message, use **log_rule_limit**. Parameters are:

  - Log Level

  - Chain to insert the rule into

  - Chain name to display in the message (this can be different from the preceding argument — see the [Port Knocking article](../features/PortKnocking.md) for an example of how to use this).

  - Disposition to report in the message (ACCEPT, DROP, etc)

  - Rate Limit (if passed as "" then \$LOGLIMIT is assumed — see the LOGLIMIT option in [/etc/shorewall/shorewall.conf](https://shorewall.org/Documentation.html#Conf))

  - Log Tag ("" if none)

  - Command (-A or -I for append or insert).

  - The remaining arguments are passed "as is" to iptables

- Many of the extension scripts get executed for both the shorewall start and shorewall restart commands. You can determine which command is being executed using the contents of \$COMMAND.

      if [ $COMMAND = start ]; then
         ...

- In addition to COMMAND, Shorewall defines three other variables that may be used for locating Shorewall files:

  - CONFDIR - The configuration directory. Will be `/etc/`. The running product is defined in the g_product variable.

  - SHAREDIR - The product shared directory. Will be `/usr/share`. The running product is defined in the g_product variable.

  - VARDIR - The product state directory. Defaults `/var/lib/shorewall`, `/var/lib/shorewall6/`, `/var/lib/shorewall-lite`, or `/var/lib/shorewall6-lite` depending on which product is running, but may be overridden by an entry in \${CONFDIR}/vardir.

- Shell variables used in extension scripts must follow the same rules as those in`/etc/shorewall/params`. See [this article](???).

## Compile-time vs Run-time Scripts

Shorewall runs some extension scripts at compile-time rather than at run-time.

The following table summarizes when the various extension scripts are run:

|                                                     |              |
|-----------------------------------------------------|--------------|
| **Compile-time**                                    | **Run-time** |
| compile                                             | clear        |
| initdone                                            | disable      |
| maclog                                              | enable       |
| Per-chain (including those associated with actions) | init         |
| postcompile                                         | isusable     |
|                                                     | start        |
|                                                     | started      |
|                                                     | stop         |
|                                                     | stopped      |
|                                                     | tcclear      |
|                                                     | refresh      |
|                                                     | refreshed    |
|                                                     | restored     |
|                                                     | scfilter     |

The contents of each run-time script is placed in a shell function, so you can declare local variables and can use the `return` command. The functions generated from the `enable` and `disable` scripts are passed three arguments:

\$1  
Physical name of the interface that was enabled or disabled.

\$2  
Logical name of the interface.

\$3  
Name of the Provider, if any, associated with the interface.

As described above, the function generated from the `isusable` script is passed a single argument that names a network interface.

With the exception of postcompile, compile-time extension scripts are executed using the Perl 'eval \`cat \<*file*\>\`' mechanism. Be sure that each script returns a 'true' value; otherwise, the compiler will assume that the script failed and will abort the compilation.

Each compile-time script is implicitly prefaced with:

    package Shorewall::User;

Most scripts will need to begin with the following line:

    use Shorewall::Chains;

For more complex scripts, you may need to 'use' other Shorewall Perl modules -- browse `/usr/share/shorewall/Shorewall/` to see what's available.

When a script is invoked, the **\$chainref** scalar variable will hold a reference to a chain table entry.**\$chainref-\>{name}** contains the name of the chain, **\$chainref-\>{table}** holds the table name

To add a rule to the chain:

    add_rule( $chainref, <the rule> [ , <break lists> ] );

Where\<*the rule*\> is a scalar argument holding the rule text. Do not include "-A \<*chain name*\>"Example:

    add_rule( $chainref, '-j ACCEPT' );

The add_rule() function accepts an optional third argument; If that argument evaluates to true and the passed rule contains a **--dports** or **--sports** list with more than 15 ports (a port range counts as two ports), the rule will be split into multiple rules where each resulting rule has 15 or fewer ports in its **--dports** and **--sports** lists.

To insert a rule into the chain:

     insert_rule( $chainref, <rulenum>, <the rule> );

The **log_rule_limit()** function works like it did in the shell compiler with three exceptions:

- You pass the chain reference rather than the name of the chain.

- The commands are 'add' and 'insert' rather than '-A' and '-I'.

- There is only a single "pass as-is to iptables" argument (so you must quote that part).

Example:

    log_rule_limit(
                   'info' ,             #Log Level
                   $chainref ,          #Chain to add the rule to
                   $chainref->{name},   #Name of the chain as it will appear in the log prefix
                   'DROP' ,             #Disposition of the packet
                   '',                  #Limit
                   '' ,                 #Log tag
                   'add',               #Command
                   '-p tcp'             #Added to the rule as-is
                   );

Note that in the 'initdone' script, there is no default chain (**\$chainref**). You can obtain a reference to a standard chain by:

    my $chainref = $chain_table{<table>}{<chain name>};

Example:

    my $chainref = $chain_table{filter}{INPUT};

You can also use the hash references **\$filter_table**, **\$mangle_table** and **\$nat_table** to access chain references in the three main tables.

Example:

    my $chainref = $filter_table->{INPUT}; #Same as above with a few less keystrokes; runs faster too

For imformation about the 'compile' extension script, see the [Manual Chains article](../concepts/ManualChains.md).
