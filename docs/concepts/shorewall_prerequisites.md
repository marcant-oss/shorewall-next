<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are running a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

# Shorewall Requires:

- A **Linux** kernel that supports Netfilter (No, it won't work on BSD or Solaris). I've tested with 2.4.2 - 2.6.16. Check [here](../reference/kernel.md) for kernel configuration information.

- iptables 1.2 or later (but I recommend at least version 1.3.3)

- Iproute (“ip” and "tc" utilities). The iproute package is included with most distributions but may not be installed by default. The official download site is <http://developer.osdl.org/dev/iproute2/download/>. Note that the Busybox versions of the iproute2 utilities (ip and tc) do not support all of the features required for advanced Shorewall use.

- A Bourne shell or derivative such as bash or ash. This shell must have correct support for variable expansion formats \${*variable%pattern*}, \${*variable%%pattern*}, \${*variable#pattern*} and \${*variable##pattern*}.

- Your shell must produce a sensible result when a number n (128 \<= n \<= 255) is left shifted by 24 bits. You can check this at a shell prompt by:

  - echo \$((128 \<\< 24))

  - The result must be either 2147483648 or -2147483648.

- The firewall monitoring display is greatly improved if you have awk (gawk) installed.

- On the system where the Shorewall package itself is installed, you must have Perl installed (preferably Perl 5.8.10):

  - If you want to be able to use DNS names in your Shorewall6 configuration files, then Perl 5.10 is required together with the Perl Socket6 module.

  - Perl Cwd Module

  - Perl File::Basename Module

  - Perl File::Temp Module

  - Perl Getopt::Long Module

  - Perl Carp Module

  - Perl FindBin Module

  - Perl Scalar::Util Module
