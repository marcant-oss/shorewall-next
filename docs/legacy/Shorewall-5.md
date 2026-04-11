# Introduction

There are currently three principle groups of changes that distinguish Shorewall 5 from Shorewall 4:

1.  Cruft Removal - over the years, as new ways to accomplish various tasks are added to Shorewall, support for the old way of doing things has generally been retained but deprecated. Shorewall 5 drops support for those deprecated features.

2.  Changes to CLI commands - In order to make command names more accurately reflect what the associated commands do, a number of commands have been renamed or the function that they perform has been changed.

3.  CLI unification - Beginning with Shorewall 5.1.0, there is a single CLI program (`/sbin/shorewall`or `/usr/sbin/shorewall` depending on your distribution).

Each of these groups is described in more detail in the sections that follow.

# Cruft Removal

Removal of superseded features makes the code cleaner and easier to extend while also reducing compilation and execution time. The following subsections detail the features that are no longer supported in Shorewall 5.

## Scripts Compiled with Shorewall 4.4.7 or Earlier

Shorewall 5 cannot correctly run scripts compiled with Shorewall 4.4.7 or earlier releases. Such scripts must be recompiled with 4.4.8 or later prior to upgrading to Shorewall 5.

## Workarounds

Over the years, a number of workarounds have been added to Shorewall to work around defects in other products. In current distributions, those defects have been corrected, and in 4.6.11, a WORKAROUNDS configuration option was added to disable those workarounds. In Shorewall 5, the WORKAROUNDS setting is still available in the shorewall\[6\].conf files but:

1.  Its default setting has been changed to No.

2.  All workarounds for old distributions have been eliminated.

If there is a need to add new workarounds in the future, those workarounds will be enabled by WORKAROUNDS=Yes.

## Removal of Configuration Options

A number of configuration options have been eliminated in Shorewall 5. The following options have been eliminated and the functionality that they enabled is been removed:

- EXPORTPARAMS

- IPSECFILE

- LEGACY_FASTSTART

- CHAIN_SCRIPTS (Removed in Shorewall 5.1).

- MODULE_SUFFIX (Removed in Shorewall 5.1.7). Shorewall can now locate modules independent of their suffix (extension).

- INLINE_MATCHES (Removed in Shorewall 5.2). Inline matches are now separated from column-oriented input by two adjacent semicolons (";;").

- MAPOLDACTIONS (Removed in Shorewall 5.2).

A compilation warning is issued when any of these options are encountered in the .conf file, and the `shorewall[6] update` command will remove them from the configuration file.

These options have been eliminated because they have been superseded by newer options.

- LOGRATE and LOGBURST (superseded by LOGLIMIT)

- WIDE_TC_MARKS (superseded by TC_BITS)

- HIGH_ROUTE_MARKS (superseded by PROVIDER_OFFSET)

- BLACKLISTNEWONLY (superseded by BLACKLIST)

A fatal compilation error is emitted if any of these options are present in the .conf file, and the `shorewall[6] update` command will replace these options with equivalent setting of the options that supersede them.

## Obsolete Configuration Files

Support has been removed for the 'blacklist', 'tcrules', 'routestopped', 'notrack', 'tos' and 'masq' files.

The `update` command is available to convert the 'tcrules' and 'tos' files to the equivalent 'mangle' file, to convert the 'blacklist' file into an equivalent 'blrules' file, and to convert the 'masq' file to the equivalent 'snat' file.

As in Shorewall 4.6.12, the `update` command converts the 'routestopped' file into the equivalent 'stoppedrules' file and converts a 'notrack' file to the equivalent 'conntrack' file.

Note that in Shorewall 5.2, the update command

## Macro and Action Formats

Originally, macro and action files had formats that were different from that of the rules file,

Format-1 action files had the following columns:

- TARGET

- SOURCE

- DEST

- PROTO

- DEST PORT(S)

- SOURCE PORT(S)

- RATE

- USER/GROUP

- MARK

Format-1 macro files were similar but did not support the MARK column.

Format-2 macro and action files have these columns:

- TARGET

- SOURCE

- DEST

- PROTO

- DPORT

- SPORT

- ORIGDEST

- RATE

- USER/GROUP

- MARK

- CONNLIMIT

- TIME

- HEADERS (Only valid for IPv6)

- SWITCH

- HELPER

Notice that the first five columns of both sets are the same (although the port-valued column names have changed, the contents are the same).

In Shorewall 5, support for format-1 macros and actions has been dropped and all macros and actions will be processed as if ?FORMAT 2 were included before the first entry. Given that the vast majority of actions and macros only use the first five columns, this change will be of no concern to most users, but will cause compilation errors if columns beyold the fifth one are populated.

## COMMENT, FORMAT and SECTION Lines

COMMENT, FORMAT and SECTION Lines now require the leading question mark ("?"). In earlier releases, the question mark was optional. The `shorewall[6] update -D` command in Shorewall 4.6 will insert the question marks for you.

# CLI Command Changes

A number of commands have been renamed and/or now perform a different function.

## restart

The `restart` command now does a true restart and is equivalent to a `stop` followed by a `start`.

## load

The function performed by the Shorewall-4 `load` command is now performed by the `remote-start` command.

## reload

In Shorewall 5, the `reload` command now performs the same function as the `restart` command did in Shorewall 4. The action taken by the Shorewall-4 `reload` command is now performed by the `remote-restart` command.

For those that can't get used to the idea of using `reload` in place of `restart`, a RESTART option has been added to shorewall\[6\].conf. The option defaults to 'restart' but if set to 'reload', then the `restart` command does what it did in earlier releases.

<div class="note">

Beginning with Shorewall 5.0.1 and Shorewall 4.6.13.2, the update command will set RESTART=reload to maintain compatibility with earlier releases. Shorewall 5.0.0 created the setting LEGACY_RESTART=No which was equivalent to RESTART=restart. Under Shorewall 5.0.1 and later, update will convert LEGACY_RESTART to the equivalent RESTART setting.

</div>

## refresh

Given the availability of ipset-based blacklisting, the `refresh` command was eliminated in Shorewall 5.2.

Some users may have been using `refresh` as a lightweight form of `reload`. The most common of these uses seem to be for reloading traffic shaping after an interface has gone down and come back up. The best way to handle this situation under 5.2 is to make the interface 'optional' in your /etc/shorewall\[6\]/interfaces file, then either:

- Install Shorewall-init and enable IFUPDOWN; or

- Use the `reenable` command when the interface comes back up in place of the `refresh` command.

# CLI Unification

Prior to Shorewall 5.1, there were four separate CLI programs:

- `/sbin/shorewall`or `/usr/sbin/shorewall` depending on your distribution. Packaged with Shorewall and used to control Shorewall.

- `/sbin/shorewall6`or `/usr/sbin/shorewall6` depending on your distribution. Packaged with Shorewall6 and used to control Shorewall6.

- `/sbin/shorewall-lite`or `/usr/sbin/shorewall-lite` depending on your distribution. Packaged with Shorewall-lite and used to control Shorewall-lite.

- `/sbin/shorewall6-lite`or `/usr/sbin/shorewall6-lite` depending on your distribution. Packaged with Shorewall6-lite and used to control Shorewall6-lite.

Each of these programs had their own (largely duplicated) manpage.

Beginning with Shorewall 5.1, there is a single CLI program (`/sbin/shorewall` or `/usr/sbin/shorewall`) packaged with Shorewall-core. The Shorewall6, Shorewall-lite and Shorewall6-lite packages create a symbolic link to that program; the links are named shorewall6, shorewall-lite and shorewall6-lite respectively. These symbolic links are for backward compatibility only; all four products can be managed using the single CLI program itself. The manpages shorewall6(8), shorewall-lite(8) and shorewall6-lite(8) are skeletal and refer the reader to shorewall(8).

# Upgrading to Shorewall 5

<div class="important">

For detailed upgrade information, please consult the 'Migration Issues' section of the release notes for the version that you are upgrading to.

</div>

It is strongly recommended that you first upgrade your installation to a 4.6 release that supports the `-A` option to the `update` command; 4.6.13.2 or later is preferred.

Once you are on that release, execute the `shorewall update -A` command (and `shorewall6 update -A` if you also have Shorewall6).

Finally, add ?FORMAT 2 to each of your macro and action files and be sure that the check command does not produce errors -- if it does, you can shuffle the columns around to make them work on both Shorewall 4 and Shorewall 5.

These steps can also be taken after you upgrade, but your firewall likely won't start or work correctly until you do.

The `update` command in Shorewall 5 has many fewer options. The `-b`, `-t`, `-n`, `-D` and `-s`options have been removed -- the updates triggered by those options are now performed unconditionally. The `-i`and `-A`options have been retained - both enable checking for issues that could result if INLINE_MATCHES were to be set to Yes. The -i option was removed in Shorewall 5.2, given that the INLINE_MATCHES option was also removed.

## CHAIN_SCRIPTS Removal

Prior to the availability of ?\[BEGIN\] PERL .... ?END PERL, the only way to create Perl code to insert rules into a chain was to use a per-Chain script with the same name as the chain. The most common use of these scripts was with Actions where an action A would have an empty action.A file and then a file named A that contained Perl code. This was a hack, at best, and has been deprecated since embedded Perl has been available in action files.

In Shorewall 5.1, the compiler notices that action.A is empty and looks for a file named A on the CONFIG_PATH. If that file is found, the compiler raises a fatal error:

        ERROR: File action.A is empty and file A exists - the two must be combined as described in the Migration Considerations section of the Shorewall release notes

To resolve this issue, one of two approaches can be taken depending on what the script A does.

- If script A is simply inserting rules with ip\[6\]tables matches and/or targets that Shorewall doesn't directly support, they can probably be coded in the action.A file using the IP\[6\]TABLES action and/or inline matches. For example, the following script `DNSDDOS`

      use Shorewall::Chains;

      add_rule $chainref, q(-m string --algo bm --from 30 --to 31 --hex-string "|010000010000000000000000020001|" -j DROP);
      add_rule $chainref, q(-m string --algo bm --from 30 --to 31 --hex-string "|000000010000000000000000020001|" -j DROP);
      add_rule $chainref, q(-j ACCEPT);

      1;

  can be coded in `action.DNSDDOS` as:

      DROP    -       -       ;; -m string --algo bm --from 30 --to 31 --hex-string "|010000010000000000000000020001|"
      DROP    -       -       ;; -m string --algo bm --from 30 --to 31 --hex-string "|000000010000000000000000020001|"
      ACCEPT  -       -

- The other approach is to simply convert A into embedded Perl in action.A. Consider this `SSHKnock` script:

      use Shorewall::Chains;

      if ( $level ) {
          log_rule_limit( $level, 
                          $chainref, 
                          'SSHKnock',
                          'ACCEPT',
                          '',
                          $tag,
                          'add',
                          '-p tcp --dport 22   -m recent --rcheck --name SSH ' );
           log_rule_limit( $level,
                           $chainref,
                           'SSHKnock',
                           'DROP',
                           '',
                           $tag,
                           'add',
                           '-p tcp --dport ! 22 ' );
      }
      add_rule( $chainref, '-p tcp --dport 22   -m recent --rcheck --seconds 60 --name SSH          -j ACCEPT' );
      add_rule( $chainref, '-p tcp --dport 632 -m recent                        --name SSH --remove -j DROP' );
      add_rule( $chainref, '-p tcp --dport 633 -m recent                        --name SSH --set    -j DROP' );
      add_rule( $chainref, '-p tcp --dport 634 -m recent                        --name SSH --remove -j DROP' );
      1;

  Because this script uses the implicit \$level and \$tag variables, it must remain in Perl. This mostly involves simply moving the `SSHKnock` script into `action.SSHKnock`, but requires some additional code in `action.SSHKnock` as shown in **bold font** below:

      ?begin perl

      use Shorewall::Config;
      use Shorewall::Chains;

      my $chainref        = get_action_chain;
      my ( $level, $tag ) = get_action_logging;

      if ( $level ) {
          log_rule_limit( $level, 
                          $chainref, 
                          'SSHKnock',
                          'ACCEPT',
                          '',
                          $tag,
                          'add',
                          '-p tcp --dport 22   -m recent --rcheck --name SSH ' );

          log_rule_limit( $level,
                          $chainref,
                          'SSHKnock',
                          'DROP',
                          '',
                          $tag,
                          'add',
                          '-p tcp --dport ! 22 ' );
      }

      add_rule( $chainref, '-p tcp --dport 22   -m recent --rcheck --seconds 60 --name SSH          -j ACCEPT' );
      add_rule( $chainref, '-p tcp --dport 632 -m recent                        --name SSH --remove -j DROP' );
      add_rule( $chainref, '-p tcp --dport 633 -m recent                        --name SSH --set    -j DROP' );
      add_rule( $chainref, '-p tcp --dport 634 -m recent                        --name SSH --remove -j DROP' );
      1;

      ?end perl
