# Introduction

This document provides an overview of Shorewall internals. It is intended to ease the task of approaching the Shorewall code base by providing a roadmap of what you will find there.

## History

Shorewall was originally written entirely in Bourne Shell. The chief advantage of this approach was that virtually any platform supports the shell, including small embedded environments. The initial release was in early 2001. This version ran iptables, ip, etc. immediately after processing the corresponding configuration entry. If an error was encountered, the firewall was stopped. For this reason, the `routestopped` file had to be very simple and foolproof.

In Shorewall 3.2.0 (July 2006), the implementation was changed to use the current compile-then-execute architecture. This was accompilished by modifying the existing code rather than writing a compiler/generator from scratch. The resulting code was fragile and hard to maintain. 3.2.0 also marked the introduction of Shorewall-lite.

By 2007, the compiler had become unmaintainable and needed to be rewritten. I made the decision to write the compiler in Perl and released it as a separate Shorewall-perl packets in Shorewall 4.0.0 (July 2007). The shell-based compiler was packaged in a Shorewall-shell package. An option (SHOREWALL_COMPILER) in shorewall.conf specified which compiler to use. The Perl-based compiler was siginificantly faster, and the compiled script also ran much faster thanks to its use of iptables-restore.

Shorewall6 was introduced in Shorewall 4.2.4 (December 2008).

Support for the old Shell-based compiler was eliminated in Shorewall 4.4.0 (July 2009).

Shorewall 4.5.0 (February 2012) marked the introduction of the current architecture and packaging.

## Architecture

The components of the Shorewall product suite fall into five broad categories:

1.  Build/Install subsystem

<!-- -->

1.  Command Line Interface (CLI)

2.  Run-time Libraries

3.  Compiler

4.  Configuration files (including actions and macros)

### Build/Install Subsystem

The Shorewall Build/Install subsystem packages the products for release and installs them on an end-user's or a packager's system. It is diagrammed in the following graphic.

The build environment components are not released and are discussed in the [Shorewall Build Article](Build.md).

The end-user/packager environment consists of the `configure` and `configure.pl` programs in Shorewall-core and an `install.sh` program in each product.

### CLI

The CLI is written entirely in Bourne Shell so as to allow it to run on small embedded systems within the -lite products. The CLI programs themselves are very small; then set global variables then call into the CLI libraries. Here's an example (/sbin/shorewall):

    PRODUCT=shorewall

    #
    # This is modified by the installer when ${SHAREDIR} != /usr/share
    #
    . /usr/share/shorewall/shorewallrc

    g_program=$PRODUCT
    g_libexec="$LIBEXECDIR"
    g_sharedir="$SHAREDIR"/shorewall
    g_sbindir="$SBINDIR"
    g_perllib="$PERLLIBDIR"
    g_confdir="$CONFDIR"/shorewall
    g_readrc=1

    . $g_sharedir/lib.cli

    shorewall_cli $@

As you can see, it sets the PRODUCT variable, loads the shorewallrc file, sets the global variables (all of which have names beginning with "g\_", loads `lib.cli`, and calls shorewall_cli passing its own arguments.

There are two CLI libraries: `lib.cli` in Shorewall Core and `lib.cli-std`in Shorewall. The `lib.cli` library is always loaded by the CLI programs; `lib-cli-std` is also loaded when the product is 'shorewall' or 'shorewall6'. `lib.cli-std` overloads some functions in `lib.cli` and also provides logic for the additional commands supported by the full products.

The CLI libraries load two additional Shell libraries from Shorewall.core: `lib.base` and `lib.common` (actually, `lib.base` loads `lib.common`). These libraries are separete from `lib.cli` for both historical and practicle reasons. `lib.base` (aka functions) can be loaded by application programs, although this was more common in the early years of Shorewall. In addition to being loaded by the CLIs, `lib.common` is also copied into the generated script by the compilers.

### Run-time Libraries

Thare are two libraries that are copied into the generated script by the compiler: `lib.common` from Shorewall-core and `lib.core` from Shorewall. The "outer block" of the generated script comes from the Shorewall file `prog.footer`.

### Compiler

With the exception of the `getparams` Shell program, the compiler is written in Perl. The compiler main program is compiler.pl from Shorewall.conf; it's run-line arguments are described in the [Shorewall Perl Article](Shorewall-perl.html%23compiler.pl). It is invoked by the *compiler* function in `lib.cli-std`.

The compiler is modularized as follows:

- `Accounting.pm` (Shorewall::Accounting). Processes the `accounting` file.

- `Chains.pm` (Shorewall::Chains). This is the module that provides an interface to iptables/Netfilter for the other modules. The optimizer is included in this module.

- `Config.pm` (Shorewall::Config). This is a multi-purpose module that supplies several related services:

  - Error and Progress message production.

  - Pre-processor. Supplies all configuration file handling including variable expansion, ?IF...?ELSE...?ENDIF processing, INCLUDE directives and embedded Shell and Perl.

  - Output script file creation with functions to write into the script. The latter functions are no-ops when the `check` command is being executed.

  - Capability Detection

  - Miscellaneous utility functions.

- `Compiler.pm` (Shorewall::Compiler). The compiler() function in this module contains the top-leve of the compiler.

- `IPAddrs.pm` (Shorewall::IPAddrs) - IP Address validation and manipulation (both IPv4 and IPv6). Also interfaces to NSS for protocol/service name resolution.

- `Misc.pm` (Shorewall::Misc) - Provides services that don't fit well into the other modules.

- `Nat.pm` (Shorewall::Nat) - Handles all nat table rules. Processes the `masq`, `nat` and `netmap` files.

- `Proc.pm` (Shorewall::Proc) - Handles manipulation of `/proc/sys/`.

- `Providers.pm` (Shorewall::Providers) - Handles policy routing; processes the `providers` file.

- `Proxyarp.pm` (Shorewall::Proxyarp) - Processes the `proxyarp` file.

- `Raw.pm` (Shorewall::Raw) - Handles the raw table; processes the `conntrack` (formerly `notrack`) file.

- `Rules.pm` (Shorewall::Rules) - Contains the logic for process the `policy` and `rules` files, including `macros` and `actions`.

- `Tc.pm` (Shorewall::Tc) - Handles traffic shaping.

- `Tunnels.pm` (Shorewall::Tunnels) - Processes the `tunnels` file.

- `Zones.pm` (Shorewall::Zones) - Processes the `zones`, `interfaces` and `hosts` files. Provides the interface to zones and interfaces to the other modules.

Because the params file can contain arbitrary shell code, it must be processed by a shell. The body of `getparams` is as follows:

    #  Parameters:
    #
    #      $1 = Path name of params file
    #      $2 = $CONFIG_PATH
    #      $3 = Address family (4 or 6)
    #
    if [ "$3" = 6 ]; then
        PRODUCT=shorewall6
    else
        PRODUCT=shorewall
    fi

    #
    # This is modified by the installer when ${SHAREDIR} != /usr/share
    #
    . /usr/share/shorewall/shorewallrc

    g_program="$PRODUCT"
    g_libexec="$LIBEXECDIR"
    g_sharedir="$SHAREDIR"/shorewall
    g_sbindir="$SBINDIR"
    g_perllib="$PERLLIBDIR"
    g_confdir="$CONFDIR/$PRODUCT"
    g_readrc=1

    . $g_sharedir/lib.cli

    CONFIG_PATH="$2"

    set -a

    . $1 >&2 # Avoid spurious output on STDOUT

    set +a

    export -p

The program establishes the environment of the Shorewall or Shoreall6 CLI program since that is the environment in which the `params` file has been traditionally processed. It then sets the -`a` option so that all newly-created variables will be exported and invokes the `params` file. Because the STDOUT file is a pipe back to the compiler, no spurious output must be sent to that file; so `getparams` redirect `params` output to STDOUT. After the script has executed, an `export -p` command is executed to send the contents of the environ array back to the compiler.

Regrettably, the various shells (and even different versions of the same shell) produce quite different output from `export -p`. The Perl function Shorewall::Config::getparams() detects which species of shell was being used and stores the variable settings into the %params hash. Variables that are also in %ENV are only stored in %params if there value in the output from the `getparams` script is different from that in %ENV.

### Configuration Files

The configuration files are all well-documented. About the only thing worth noting is that some macros and actions are duplicated in the Shorewall and Shorewall6 packages. Because the Shorewall6 default CONFIG_PATH looks in \${SHAREDIR}/shorewall6 before looking in \${SHARDIR\_/shorewall, this allows Shorewall6 to implement IPv6-specific handling where required.

## The Generated Script

The generated script is completely self-contained so as to avoid version dependencies between the Shorewall version used to create the script and the version of Shorewall-common installed on the remote firewall.

The operation of the generated script is illustrated in this diagram.

The Netfilter ruleset is sometimes dependent on the environment when the script runs. Dynamic IP addresses and gateways, for example, must be detected when the script runs. As a consequence, it is the generated script and not the compiler that creates the input for iptables-restore. While that input could be passed to iptables-restore in a pipe, it is written to `${VARDIR}/.iptables_restore-input` so that it is available for post-mortem analysis in the event that iptables-restore fails. For the other utilities (ip, tc, ipset, etc), the script runs them passing their input on the run-line.

# Compiler Internals

Because the compiler is the most complex part of the Shorewall product suite, I've chosen to document it first. Before diving into the details of the individual modules, lets take a look at a few general things.

## Modularization

While the compiler is modularized and uses encapsulation, it is not object-oriented. This is due to the fact that much of the compiler was written by manually translating the earlier Shell code.

Module data is not completely encapsulated. Heavily used tables, most notably the Chain Table (%chain_table) in Shorewall::Chains is exported for read access. Updates to module data is always encapsulated.

## Module Initialization

While currently unused and untested, the Compiler modules are designed to be able to be loaded into a parent Perl program and the compiler executed repeatedly without unloading the modules. To accomodate that usage scenario, variable data is not initialized at declaration time or in an INIT block, but is rather initialized in an initialize function. Because off of these functions have the same name ("initialize"), they are not exported but are rather called using a fully-qualified name (e.g., "Shorewall::Config::initialize").

Most of the the initialization functions accept arguements. Those most common argument is the address family (4 or 6), depending on whether an IPv4 or IPv6 firewall is being compiled. Each of the modules that are address-family dependent have their own \$family private (my) variable.

## Module Dependence

Here is the module dependency tree. To simplify the diagram, direct dependencies are not shown where there is also a transitive dependency.

## Config Module

As mentioned above, the Config module offers several related services. Each will be described in a separate sub-section.

### Pre-processor

Unlike preprocessors like ccp, the Shorewall pre-processor does it's work each time that the higher-level modules asks for the next line of input.

The major exported functions in the pre-processor are:

open_file( \$ )  
The single argument names the file to be opened and is usually a simple filename such as `shorewall.conf`. **open_file** calls **find_file** who traverses the CONFIG_PATH looking for a file with the requested name. If the file is found and has non-zero size, it is opened, module-global variables are set as follows, and the fully-qualified name of the file is returned by the function.

\$currentfile  
Handle for the file open

\$currentfilename (exported)  
The fully-qualified name of the file.

\$currentlinenumber  
Set to zero.

If the file is not found or if it has zero size, false ('') is returned.

push_open( \$ )  
Sometimes, the higher-level modules need to suspend processing of the current file and open another file. An obvious example is when the Rules module encounters a macro invocation and needs to process the corresponding macro file. The push_open function is called in these cases.

**push_open** pushes **\$currentfile**, **\$currentfilename**, **\$currentlinenumber** and **\$ifstack** onto **@includestack**, copies **@includestack** into a local array, pushes a reference to the local array onto **@openstack**, and empties **@includestack**

As its final step, **push_open** calls **open_file**.

pop_open()  
The **pop_open** function must be called after the file opened by **push_open** is processed. This is true even in the case where **push_open** returned false.

**pop_open** pops **@openstack** and restores **\$currentfile**, **\$currentfilename**, **\$currentlinenumber**, **\$ifstack** and **@includestack**.

close_file()  
**close_file** is called to close the current file. Higher-level modules should only call **close_file** to close the current file prior to end-of-file.

first_entry( \$ )  
This function is called to specify what happens when the first non-commentary and no-blank line is read from the open file. The argument may be either a scalar or a function reference. If the argument is a scalar then it is treaded as a progress message that should be issued if the VERBOSITY setting is \>= 1. If the argument is a function reference, the function (usually a closure) is called.

**first_entry** may called after a successful call to **open_file**. If it is not called, then the pre-processor takes no action when the first non-blank non-commentary line is found.

**first_entry** returns no significant value.

read_a_line( \$ )  
This function delivers the next logical input line to the caller. The single argument is defined by the following constants:

    use constant { PLAIN_READ          => 0,     # No read_a_line options
                   EMBEDDED_ENABLED    => 1,     # Look for embedded Shell and Perl
                   EXPAND_VARIABLES    => 2,     # Expand Shell variables
                   STRIP_COMMENTS      => 4,     # Remove comments
                   SUPPRESS_WHITESPACE => 8,     # Ignore blank lines
                   CHECK_GUNK          => 16,    # Look for unprintable characters
                   CONFIG_CONTINUATION => 32,    # Suppress leading whitespace if
                                                 # continued line ends in ',' or ':'
                   DO_INCLUDE          => 64,    # Look for INCLUDE <filename>
                   NORMAL_READ         => -1     # All options
                };

The actual argument may be a bit-wise OR of any of these constants.

The function does not return the logical line; that line is rather stored in the module-global variable **\$currentline** (exported). The function simply returns true if a line was read or false if end-of-file was reached. **read_a_line** automatically calls **close_file** at EOF.

split_line1  
Most of the callers of **read_a_line** want to treat each line as whitespace-separated columns. The **split_line** and **split_line1** functions return an array containing the contents of those columns.

The arguments to **split_line1** are:

- A `name` =\> \<column-number\> pair for each of the columns in the file. These are used to process lines that use the [alternate input methods](configuration_file_basics.md#Pairs) and also serve to define the number of columns in the file's records.

- A hash reference defining `keyword` =\> \<number-of-columns\> pairs. For example "{ COMMENT =\> 0, FORMAT 2 }" allows COMMENT lines of an unlimited number of space-separated tokens and it allows FORMAT lines with exactly two columns. The hash reference must be the last argument passed.

If there are fewer space-separated tokens on the line than specified in the arguments, then "-" is returned for the omitted trailing columns.

split_line  
**split_line** simply returns **split_line1( @\_, {} )**.

### Error and Progress Message Production

There are several exported functions dealing with error and warning messages:

fatal_error  
The argument(s) to this function describe the error. The generated error message is:

"ERROR: @\_" followed by the name of the file and the line number where the error occurred.

The mesage is written to the STARTUP_LOG, if any.

The function does not return but rather passes the message to **die** or to **confess**, depending on whether the "-T" option was specified.

warning_message  
The warning_message is very similar to fatal_error but avoids calling **die** or **confess**. It also prefixes the argument(s) with "WARNING: " rather than "ERROR: ".

It message is written to Standard Out and to the STARTUP_LOG, if any.

progress_message, progress_message2, progress_message3 and progress_message_nocompress  
These procedures conditionally write their argument(s) to Standard Out and to the STARTUP_LOG (if any), depending on the settings of VERBOSITY and and LOG_VERBOSITY respectively.

- **progress_message** only write messages when the verbosity is 2. This function also preserves leading whitespace while removing superflous embedded whitespace from the messages.

- **progress_message2** writes messages with the verbosity is \>= 1.

- **progress_message3** writes messages when the verbosity is \>= 0.

- **progress_message_nocompress** is like **progress_message** except that it does not preserve leading whitespace nor does it eliminate superfluous embedded whitespacve from the messages.

### Script File Handling

The functions involved in script file creation are:

create_temp_script( \$\$ )  
This function creates and opens a temporary file in the directory where the final script is to be placed; this function is not called when the `check` command is being processed. The first argument is the fully-qualified name of the output script; the second (boolean) argument determines if the compilation is for export. The function returns no meaningful value but sets module-global variables as follows:

\$script  
Handle of the open script file.

\$dir  
The directory in which the script was created.

\$tempfile  
The name of the temporary file.

\$file  
This fully-qualified name of the script file.

finalize_script( \$ )  
This function closes the temporary file and renames it to the
