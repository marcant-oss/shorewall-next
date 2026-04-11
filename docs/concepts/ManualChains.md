# Introduction

For Perl programmers, manual chains provide an alternative to Actions with extension scripts. Manual chains are chains which you create and populate yourself using the low-level functions in Shorewall::Chains.

Manual chains work in conjunction with the compile [extension script](../reference/shorewall_extension_scripts.md) and [Embedded PERL scripts](../reference/configuration_file_basics.md#Embedded). The general idea is like this:

- In the compile extension script, you define functions that you can call later using Embedded PERL. These functions create a manual chain using Shorewall::Chains::new_manual_chain() and populate it with rules using Shorewall::Chains::add_rule(). The name passed to new_manual_chain() must not be longer than 29 characters.

- The functions also call Shorewall::Config::shorewall() to create and pass a rule to Shorewall. The TARGET in that rule is the name of the chain just created.

- The functions defined in the compile script are called by embedded PERL statements. The arguments to those calls define the contents of the manual chains and the rule(s) passed back to Shorewall for normal processing.

# Example

This example provides an alternative to the [Port Knocking](../features/PortKnocking.md) example.

In this example, a Knock.pm module is created and placed in /etc/shorewall:

    package Knock;

    use strict;
    use warnings;
    use base qw{Exporter};
    use Carp;
    use Shorewall::Chains;
    use Scalar::Util qw{reftype};
    use Shorewall::Config qw{shorewall};

    our @EXPORT = qw{Knock};

    my %recent_names;
    my %chains_created;

    sub scalar_or_array {
      my $arg = shift;
      my $name = shift;
      return () unless defined $arg;
      return ($arg) unless reftype($arg);
      return @$arg if reftype($arg) eq 'ARRAY';
      croak "Expecting argument '$name' to be scalar or array ref";
    }

    sub Knock {
      my $src = shift;
      my $dest = shift;
      my $args = shift;

      my $proto = $args->{proto} || 'tcp';
      my $seconds = $args->{seconds} || 60;
      my $original_dest = $args->{original_dest} || '-';
      my @target = scalar_or_array($args->{target}, 'target');
      my @knocker_ports = scalar_or_array($args->{knocker}, 'knocker');
      my @trap_ports = scalar_or_array($args->{trap}, 'trap');

      if (not defined $args->{name}) {
        # If you don't supply a name, then this must be the single-call
        # variant, so you have to specify all the arguments
        unless (scalar @target) {
          croak "No 'target' ports specified";
        }

        unless (scalar @knocker_ports) {
          croak "No 'knock' ports specified";
        }
      }

      # We'll need a unique name for the recent match list. Construct one
      # from the port and a serial number, if the user didn't supply one.
      my $name = $args->{name} || ($target[0] . '_' . ++$recent_names{$target[0]});
      $name = 'Knock' . $name;

      # We want one chain for all Knock rules that share a 'name' field
      my $chainref = $chains_created{$name};
      unless (defined $chainref) {
        $chainref = $chains_created{$name} = new_manual_chain($name);
      }
      
      # Logging
      if ($args->{log_level}) {
        foreach my $port (@target) {
          log_rule_limit($args->{log_level},
                         $chainref,
                         'Knock',
                         'ACCEPT',
                         '',
                         $args->{log_tag} || '',
                         'add',
                         "-p $proto --dport $port -m recent --rcheck --name $name"
                        );

          log_rule_limit($args->{log_level},
                         $chainref,
                         'Knock',
                         'DROP',
                         '',
                         $args->{log_tag} || '',
                         'add',
                         "-p $proto --dport ! $port"
                        );
        }
      }

      # Add the recent match rules to the manual chain
      foreach my $knock (@knocker_ports) {
        add_rule($chainref, "-p $proto --dport $knock -m recent --name $name --set -j DROP");
      }

      foreach my $trap (@trap_ports) {
        add_rule($chainref, "-p $proto --dport $trap -m recent --name $name --remove -j DROP");
      }

      foreach my $port (@target) {
        add_rule($chainref, "-p $proto --dport $port -m recent --rcheck --seconds $seconds --name $name -j ACCEPT");
      }

      # And add a rule to the main chain(s) to jump into the manual chain at the appropriate points
      my $all_dest_ports = join(',', @target, @knocker_ports, @trap_ports);
      shorewall "$chainref->{name} $src $dest $proto $all_dest_ports - $original_dest";

      return 1;
    }

    1;

This simplifies /etc/shorewall/compile:

    use Knock;
    1;

The rule from the Port Knocking article:

    #ACTION          SOURCE            DEST           PROTO       DPORT
    SSHKnock         net               $FW            tcp         22,1599,1600,1601

becomes:

    PERL Knock 'net', '$FW', {target => 22, knocker => 1600, trap => [1599, 1601]};

Similarly

    #ACTION          SOURCE            DEST            PROTO       DPORT         SPORT       ORIGDEST
    DNAT-            net               192.168.1.5 tcp             22            -           206.124.146.178
    SSHKnock         net               $FW             tcp         1599,1600,1601
    SSHKnock         net               loc:192.168.1.5 tcp         22            -           206.124.146.178

becomes:

    #ACTION          SOURCE            DEST            PROTO       DPORT         SPORT       ORIGDEST
    DNAT-            net               192.168.1.5 tcp             22            -           206.124.146.178

    PERL Knock 'net', '$FW', {name => 'SSH', knocker => 1600, trap => [1599, 1601]};
    PERL Knock 'net', 'loc:192.168.1.5', {name => 'SSH', target => 22, original_dest => '206.124.136.178'};
