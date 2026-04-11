<div class="caution">

**This article applies to Shorewall 4.3 and later. If you are installing or upgrading to a version of Shorewall earlier than Shorewall 4.3.5 then please see the documentation for that release.**

</div>

<div class="important">

Before attempting installation, I strongly urge you to read and print a copy of the [Shorewall QuickStart](shorewall_quickstart_guide.md) Guide for the configuration that most closely matches your own. This article only tells you how to install the product on your system. The QuickStart Guides describe how to configure the product.

</div>

<div class="important">

Before upgrading, be sure to review the [Upgrade Issues](../legacy/upgrade_issues.md).

</div>

<div class="note">

Shorewall RPMs are signed. To avoid warnings such as the following

    warning: shorewall-3.2.1-1.noarch.rpm: V3 DSA signature: NOKEY, key ID 6c562ac4

download the [Shorewall GPG key](https://shorewall.org/shorewall.gpg.key) and run this command:

    rpm --import shorewall.gpg.key

</div>

# Install using RPM

To install Shorewall using the RPM:

1.  **Be sure that you have the correct RPM package!**

    The standard RPM package from shorewall.net and the mirrors is known to work with **SUSE**, **Power PPC**, **Trustix** and **TurboLinux**. There is also an RPM package provided by Simon Matter that is tailored for **RedHat/Fedora** and another package from Jack Coates that is customized for **Mandriva**. All of these are available from the [download page](https://shorewall.org/download.htm).

    If you try to install the wrong package, it probably won't work.

2.  Install the RPMs

        rpm -ivh <shorewall rpm>

    <div class="caution">

    Some users are in the habit of using the `rpm -U` command for installing packages as well as for updating them. If you use that command when installing the Shorewall RPM then you will have to manually enable Shorewall startup at boot time by running `chkconfig`, `insserv` or whatever utility you use to manipulate you init symbolic links.

    </div>

    <div class="note">

    Shorewall is dependent on the iproute package. Unfortunately, some distributions call this package iproute2 which will cause the installation of Shorewall to fail with the diagnostic:

        error: failed dependencies:iproute is needed by shorewall-3.2.x-1

    This problem should not occur if you are using the correct RPM package (see 1., above) but may be worked around by using the --nodeps option of rpm.

        rpm -ivh --nodeps <rpms>

    </div>

    Example:

        rpm -ivh shorewall-4.3.5-0base.noarch.rpm

# Install using tarball

## Versions 4.5.2 and Later

Shorewall 4.5.2 introduced a change in the philosopy used by the Shorewall installers. 4.5.2 introduced the concept of shorewallrc files. These files define the parameters to the install process. During the first installation using **Shorewall-core** 4.5.2 or later, a shorewallrc file named \${HOME}/.shorewallrc will be installed. That file will provide the default parameters for installing other Shorewall components of the same or later version.

Note that **you must install Shorewall-core before installing any other Shorewall package**.

Each of the Shorewall packages contains a set of distribution-specific shorewallrc files:

- shorewallrc.apple (OS X)

- shorewallrc.archlinux

- shorewallrc.cygwin (Cygwin running on Windows)

- shorewallrc.debian (Debian and derivatives)

- shoreallrc.default (Generic Linux)

- shorewallrc.redhat (Fedora, RHEL and derivatives)

- shorewallrc.slackware

- shorewallrc.suse (SLES and OpenSuSE)

- shorewallrc.openwrt (OpenWRT)

When installing 4.5.2 or later for the first time, a special procedure must be followed:

1.  Select the shorewallrc file that is closest to your needs.

2.  Review the settings in the file.

3.  If you want to change something then you have two choices:

    1.  Copy the file to shorewallrc and edit the copy to meet your needs; or

    2.  If the system has Bash (/bin/bash) 4.0 or later installed, you can run ./configure (see below). If you are installing 4.5.2.1 or later and your system has Perl installed, you can use the Perl version (./configure.pl).

    3.  ./install.sh

4.  If you don't need to change the file, then simply:

    ./install.sh
    shorewallrcfile-that-meets-your-needs
    Example:
    ./install.sh shorewallrc.debian

The shorewall-core install.sh script will store the shorewallrc file in ~/.shorewallrc where it will provide the defaults for future installations of all Shorewall products. Other packages/versions can be installed by simply typing

./install.sh

### Settings in a shorewallrc file

A shorewallrc file contains a number of lines of the form \<option\>=\<value.\> Because some of the installers are shared between Shorewall products, the files assume the definition of the symbol PRODUCT. \$PRODUCT will contain the name of a Shorewall product (shorewall-core, shorewall, shorewall6, shorewall-lite, shorewall6-lite or shorewall-init).

Valid values for \<option\> are:

HOST  
Selects the shorewallrc file to use for default settings. Valid values are:

apple  
OS X

archlinux  
Archlinux

cygwin  
Cygwin running under Windows

debian  
Debian and derivatives (Ubuntu, Kbuntu, etc)

default  
Generic Linux

redhat  
Fedora, RHEL and derivatives (CentOS, Foobar, etc)

slackware  
Slackware Linux

suse  
SLES and OpenSuSe

openwrt  
OpenWRT (Shorewall 5.0.2 and later)

PREFIX  
Top-level directory under which most Shorewall components are installed. All standard shorewallrc files define this as **\usr**.

SHAREDIR  
The directory where most Shorewall components are installed. In all of the standard shorewallrc file, this option has the value **\${PREFIX}/share**.

LIBEXECDIR  
Directory where internal executables are stored. In the standard shorewallrc files, the default is either **\${PREFIX}/share** or **\${PREFIX}/libexec**

PERLLIBDIR  
Directory where the Shorewall Perl modules are installed. They will be installed in this directory under the sub-directory Shorewall. Default is distribution-specific.

CONFDIR  
Directory where subsystem configuration data is stored. Default is **/etc** in all shorewallrc file.

SBINDIR  
Directory where CLI programs will be installed. Default in all shorewallrc files is /**sbin**.

MANDIR  
Directory under which manpages are to be installed. Default is distribution dependent.

INITDIR  
Directory under which SysV init scripts are installed. Default is distribution dependent.

INITSOURCE  
File in the package that is to be installed as the SysV init script for the product.

INITFILE  
The name of the SysV init script when installed under \$INITDIR. May be empty, in which case no SysV init script will be installed. This is usually the case on systems that run systemd and on systems like Cygwin or OS X where Shorewall can't act as a firewall.

AUXINITSOURCE and AUXINITFILE  
Analogs of INITSOURCE and INITFILE for distributions, like Slackware, that have a master SysV init script and multiple subordinate scripts.

SYSTEMD  
The directory under which the product's .service file is to be installed. Should only be specified on systems running systemd.

SERVICEFILE  
Added in Shorewall 4.5.20. When SYSTEMD is specified, this variable names the file to be installed as the product's .service file. If not specified, \$PRODUCT.service is assumed.

SYSCONFDIR  
The directory where package SysV init configuration files are to be installed. **/etc/default** on Debian and derivatives and **/etc/sysconfig** otherwise

SYSCONFFILE  
The file in the Shorewall package that should be installed as \${SYSCONFDIR}/\$PRODUCT

ANNOTATED  
Value is either empty or non-empty. Non-empty indicates that files in \${CONFDIR}/\${PRODUCT} should be annotated with manpage documentation.

SPARSE  
Value is either empty or non-empty. When non-empty, only \${PRODUCT}.conf will be installed in \${CONFDIR}/\${PRODUCT}

VARLIB  
Added in Shorewall 4.5.8. Directory where subsystem state data is to be stored. Default is **/var/lib**.

VARDIR  
Shorewall 4.5.7 and earlier: Directory where subsystem state data is to be stored. Default is **/var/lib**.

Shorewall 4.5.8 and later: Default is **/var/lib/\$PRODUCT**.

<div class="note">

From Shorewall 4.5.2 through 4.5.7, there were two interpretations of VARDIR. In the shorewallrc file, it referred to the directory where all Shorewall product state would be stored (default **/var/lib**). But in the code and in shorewall-vardir(5), it referred to the directory where an individual products state would be stored (e.g., **/var/lib/shorewall**).

In Shorewall 4.5.8, the variable VARLIB was added to shorewallrc. In that release, the shorewallrc files packaged with the Shorewall products were changed to include these two lines:

VARLIB=/var/lib

VARDIR defaults to '\${VARLIB}/\${PRODUCT}' if VARLIB is specified and VARDIR isn't.

The consumers of shorewallrc were changed so that if there is no VARLIB setting, then VARLIB is set to \$VARDIR and \$VARDIR is set to \${VARLIB}/\${PRODUCT}. This allows existing `shorewallrc` files to be used unchanged.

</div>

### configure Script

<div class="warning">

The configure script requires Bash 4.0 or later. Beginning with Shorewall 4.5.2.1, a Perl version (configure.pl) of the script is included for use by packagers that have to deal with systems with earlier versions of Bash. The configure.pl script works identically to the Bash version.

</div>

The configure script creates a file named `shorewallrc` in the current working directory. This file is the default input file to the i`nstall.sh` scripts. It is run as follows:

./configure

\[.pl\] \[

option

=

value

\] ...

The possible values for option are the same as those shown above in the shorewallrc file. They may be specified in either upper or lower case and may optionally be prefixed by '--'. To facilitate use with the rpm %configure script, the following options are supported:

vendor  
Alias for **host**.

sharedstatedir  
Shorewall 4.5.2 - 4.5.7 Alias for **vardir**.

Shorewall 4.5.8 and later. Alias for **varlib**.

datadir  
Alias for **sharedir**.

Note that %configure may generate option/value pairs that are incompatible with the `configure` script. The current %configure macro is:

    %configure \
      CFLAGS="${CFLAGS:-%optflags}" ; export CFLAGS ; \
      CXXFLAGS="${CXXFLAGS:-%optflags}" ; export CXXFLAGS ; \
      FFLAGS="${FFLAGS:-%optflags}" ; export FFLAGS ; \
      ./configure --host=%{_host} --build=%{_build} \\\
            --target=%{_target_platform} \\\
            --program-prefix=%{?_program_prefix} \\\
            --prefix=%{_prefix} \\\
            --exec-prefix=%{_exec_prefix} \\\
            --bindir=%{_bindir} \\\
            --sbindir=%{_sbindir} \\\
            --sysconfdir=%{_sysconfdir} \\\
            --datadir=%{_datadir} \\\
            --includedir=%{_includedir} \\\
            --libdir=%{_libdir} \\\
            --libexecdir=%{_libexecdir} \\\
            --localstatedir=%{_localstatedir} \\\
            --sharedstatedir=%{_sharedstatedir} \\\
            --mandir=%{_mandir} \\\
            --infodir=%{_infodir}

On Fedora 16, this expands to:

      CFLAGS="${CFLAGS:--O2 -g -march=i386 -mtune=i686}" ; export CFLAGS ; 
      CXXFLAGS="${CXXFLAGS:--O2 -g -march=i386 -mtune=i686}" ; export CXXFLAGS ; 
      FFLAGS="${FFLAGS:--O2 -g -march=i386 -mtune=i686}" ; export FFLAGS ; 
      ./configure --host=i686-pc-linux-gnu --build=i686-pc-linux-gnu \
            --program-prefix= \
            --prefix=/usr \
            --exec-prefix=/usr \
            --bindir=/usr/bin \
            --sbindir=/usr/sbin \
            --sysconfdir=/etc \
            --datadir=/usr/share \
            --includedir=/usr/include \
            --libdir=/usr/lib \
            --libexecdir=/usr/libexec \
            --localstatedir=/var \
            --sharedstatedir=/var/lib \
            --mandir=/usr/share/man \
            --infodir=/usr/share/info

The value of **--host** does not map to any of the valid HOST values in shorewallrc. So to use %configure on a Fedora system, you want to invoke it as follows:

    %configure --vendor=redhat

To reset the value of a setting in shorewallrc.\$host, give it a null value. For example, if you are installing on a RHEL derivative that doesn't run systemd, use this command:

    ./configure --vendor=redhat --systemd=

### Install for Packaging.

If you build your own packages, then you will want to install the Shorewall products into it's own directory tree. This is done by adding DESTDIR to the installer's environment. For example, to install a product for Debian into the /tmp/package directory:

    DESTDIR=/tmp/package ./install.sh shorewallrc.debian

When DESTDIR is specified, the installers treat \$DESTDIR as the root of the filesystem tree. In other words, the created installation is only runnable if one chroots to \$DESTDIR. Please note that the uninstall.sh scripts cannot uninstall a configuration installed with non-empty DESTDIR.

### Install into a Sandbox

When DESTDIR is used, the resulting configuration is not runnable, because all configuration pathnames are relative to \$DESTDIR. Beginning with Shorewall 4.6.4, you can create runnable configurations separate from your main configuration. Here is a sample shorewallrc file:

                    INSTALL_DIR=/usr/local/shorewall-custom
                    HOST=suse
                    PREFIX=${INSTALL_DIR}
                    SHAREDIR=${INSTALL_DIR}/share
                    LIBEXECDIR=${INSTALL_DIR}/lib
                    PERLLIBDIR=${INSTALL_DIR}/lib/perl5
                    CONFDIR=${INSTALL_DIR}/etc
                    SBINDIR=${INSTALL_DIR}/usr/sbin
                    MANDIR=${SHAREDIR}/man/
                    INITDIR=${INSTALL_DIR}/etc/init.d
                    INITSOURCE=init.suse.sh
                    INITFILE=${PRODUCT}
                    AUXINITSOURCE=
                    AUXINITFILE=
                    SYSTEMD=${INSTALL_DIR}/etc/systemd
                    SERVICEFILE=${PRODUCT}.service
                    SYSCONFFILE=sysconfig
                    SYSCONFDIR=${INSTALL_DIR}/etc/sysconfig
                    SPARSE=
                    ANNOTATED=
                    VARLIB=${INSTALL_DIR}/var/lib
                    VARDIR=${VARLIB}/${PRODUCT}
                    SANDBOX=Yes

The above shorewallrc creates a runnable configuration in /usr/local/shorewall-custom. It is triggered by adding SANDBOX to the shorewallrc file -- any non-empty value for that variable will prevent the installer from replacing the current main configuraiton.

## Versions 4.5.1 and Earlier

Beginning with Shorewall-4.5.0, the Shorewall packages depend on Shorewall-core. So the first step is to install that package:

1.  unpack the tarballs:

        tar -jxf shorewall-core-4.5.0.tar.bz2

2.  cd to the shorewall directory (the version is encoded in the directory name as in “shorewall-core-4.5.0”).

3.  Type:

        ./install.sh 

To install Shorewall using the tarball and install script:

1.  unpack the tarballs:

        tar -jxf shorewall-4.5.0.tar.bz2

2.  cd to the shorewall directory (the version is encoded in the directory name as in “shorewall-4.3.5”).

3.  Type:

        ./install.sh 

    or if you are installing Shorewall or Shorewall6 version 4.4.8 or later, you may type:

        ./install.sh -s

    The **-s** option suppresses installation of all files in `/etc/shorewall` except `shorewall.conf`. You can copy any other files you need from one of the [Samples](../concepts/GettingStarted.md) or from `/usr/share/shorewall/configfiles/`.

4.  If the install script was unable to configure Shorewall to be started automatically at boot, see [these instructions](starting_and_stopping_shorewall.md).

Beginning with shorewall 4.4.20.1, the installer also supports a `-a` (annotated) option. Beginning with that release, the standard configuration files (including samples) may be annotated with the contents of the associated manpage. The `-a` option enables that behavior. The default remains that the configuration files do not include documentation.

### Executables in /usr and Perl Modules

Distributions have different philosophies about the proper file hierarchy. Two issures are particularly contentious:

- Executable files in `/usr/share/shorewall*`. These include;

  - getparams

  - compiler.pl

  - wait4ifup

  - shorecap

  - ifupdown

- Perl Modules in `/usr/share/shorewall/Shorewall`.

To allow distributions to designate alternate locations for these files, the installers (install.sh) from 4.4.19 onward support the following environmental variables:

LIBEXEC  
Determines where in /usr getparams, compiler.pl, wait4ifup, shorecap and ifupdown are installed. Shorewall and Shorewall6 must be installed with the same value of LIBEXEC. The listed executables are installed in `/usr/${LIBEXEC}/shorewall*`. The default value of LIBEXEC is 'share'. LIBEXEC is recognized by all installers and uninstallers.

Beginning with Shorewall 4.4.20, you can specify an absolute path name for LIBEXEC, in which case the listed executables will be installed in \${LIBEXEC}/shorewall\*.

Beginning with Shorewall 4.5.1, you must specify an absolute pathname for LIBEXEC.

PERLLIB  
Determines where in `/usr`the Shorewall Perl modules are installed. Shorewall and Shorewall6 must be installed with the same value of PERLLIB. The modules are installed in `/usr/${PERLLIB}/Shorewall`. The default value of PERLLIB is 'share/shorewall'. PERLLIB is only recognized by the Shorewall and Shorewall6 installers.

Beginning with Shorewall 4.4.20, you can specify an absolute path name for PERLLIB, in which case the Shorewall Perl modules will be installed in \${PERLLIB}/Shorewall/.

Beginning with Shorewall 4.5.1, you must specify an absolute pathname for PERLLIB.

MANDIR  
Determines where the man pages are installed. Default is distribution-dependent as shown below.

### Default Install Locations

The default install locations are distribution dependent as shown in the following sections. These are the locations that are chosen by the install.sh scripts.

#### All Distributions

|                                                               |                                                              |
|---------------------------------------------------------------|--------------------------------------------------------------|
| **COMPONENT**                                                 | **LOCATION**                                                 |
| man pages                                                     | /usr/share/man/ (may ve overridden using MANDIR)             |
| Shorewall Perl Modules                                        | /usr/share/shorewall/ (may be overridden using PERLLIB)      |
| Executable helper scripts (compiler.pl, getparams, wait4ifup) | /usr/share/shorewall/ (may be overridden using LIBEXEC)      |
| ifupdown.sh (from Shorewall-init)                             | /usr/share/shorewall-init/ (may be overridden using LIBEXEC) |

#### Debian

|                                          |                                                                                                                      |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **COMPONENT**                            | **LOCATION**                                                                                                         |
| CLI programs                             | /sbin/\<product\>                                                                                                    |
| Distribution-specific configuration file | /etc/default/\<product\>                                                                                             |
| Init Scripts                             | /etc/init.d/\<product\>                                                                                              |
| ifupdown scripts from Shorewall-init     | /etc/network/if-up.d/shorewall, /etc/network/if-post-down.d/shorewall                                                |
| ppp ifupdown scripts from Shorewall-init | /etc/ppp/ip-up.d/shorewall, /etc/ppp/ip-down.d/shorewall /etc/ppp/ipv6-up.d/shorewall /etc/ppp/ipv6-down.d/shorewall |

#### Redhat and Derivatives

|                                          |                                              |
|------------------------------------------|----------------------------------------------|
| **COMPONENT**                            | **LOCATION**                                 |
| CLI programs                             | /sbin/\<product\>                            |
| Distribution-specific configuration file | /etc/sysconfig/\<product\>                   |
| Init Scripts                             | /etc/rc.d/init.d/\<product\>                 |
| ifupdown scripts from Shorewall-init     | /sbin/ifup-local, /sbin/ifdown-local         |
| ppp ifupdown scripts from Shorewall-init | /etc/ppp/ip-up.local, /etc/ppp/ip-down.local |

#### SuSE

|                                          |                                                                                                                      |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **COMPONENT**                            | **LOCATION**                                                                                                         |
| CLI programs                             | /sbin/\<product\>                                                                                                    |
| Distribution-specific configuration file | /etc/sysconfig/\<product\>                                                                                           |
| Init Scripts                             | /etc/init.d/\<product\>                                                                                              |
| ifupdown scripts from Shorewall-init     | /etc/sysconfig/network/if-up.d/shorewall, /etc/sysconfig/network/if-down.d/shorewall                                 |
| ppp ifupdown scripts from Shorewall-init | /etc/ppp/ip-up.d/shorewall, /etc/ppp/ip-down.d/shorewall /etc/ppp/ipv6-up.d/shorewall /etc/ppp/ipv6-down.d/shorewall |

#### Cygwin

|                                          |                  |
|------------------------------------------|------------------|
| **COMPONENT**                            | **LOCATION**     |
| CLI programs                             | /bin/\<product\> |
| Distribution-specific configuration file | N/A              |
| Init Scripts                             | N/A              |
| ifupdown scripts from Shorewall-init     | N/A              |
| ppp ifupdown scripts from Shorewall-init | N/A              |

#### OS X

|                                          |                   |
|------------------------------------------|-------------------|
| **COMPONENT**                            | **LOCATION**      |
| CLI programs                             | /sbin/\<product\> |
| Distribution-specific configuration file | N/A               |
| Init Scripts                             | N/A               |
| ifupdown scripts from Shorewall-init     | N/A               |
| ppp ifupdown scripts from Shorewall-init | N/A               |

# Install the .deb

<div class="important">

Once you have installed the .deb packages and before you attempt to configure Shorewall, please heed the advice of Lorenzo Martignoni, former Shorewall Debian Maintainer:

“For more information about Shorewall usage on Debian system please look at /usr/share/doc/shorewall-common/README.Debian provided by \[the\] shorewall Debian package.”

</div>

The easiest way to install Shorewall on Debian, is to use apt-get`.`

First, to ensure that you are installing the latest version of Shorewall, please modify your `/etc/apt/preferences:`

    Package: shorewall
    Pin: release o=Debian,a=testing
    Pin-Priority: 700

    Package: shorewall-doc
    Pin: release o=Debian,a=testing
    Pin-Priority: 700

***Then run:***

    # apt-get update
    # apt-get install shorewall

***Once you have completed configuring Shorewall, you can enable startup at boot time by setting startup=1 in `/etc/default/shorewall`.***

# General Notes about Upgrading Shorewall

Most problems associated with upgrades come from two causes:

- The user didn't read and follow the migration considerations in the release notes (these are also reproduced in the [Shorewall Upgrade Issues](../legacy/upgrade_issues.md)).

- The user mis-handled the `/etc/shorewall/shorewall.conf` file during upgrade. Shorewall is designed to allow the default behavior of the product to evolve over time. To make this possible, the design assumes that **you will not replace your current shorewall.conf** **file during upgrades**. It is recommended that after you first install Shorewall that you modify `/etc/shorewall/shorewall.conf` so as to prevent your package manager from overwriting it during subsequent upgrades (since the addition of STARTUP_ENABLED, such modification is assured since you must manually change the setting of that option). If you feel absolutely compelled to have the latest options in your shorewall.conf then you must proceed carefully. You should determine which new options have been added and you must reset their value (e.g. OPTION=""); otherwise, you will get different behavior from what you expect.

# Upgrade using RPM

If you already have the Shorewall RPM installed and are upgrading to a new version:

1.  **Be sure that you have the correct RPM package!**

    The standard RPM package from shorewall.net and the mirrors is known to work with SUSE, Power PPC, Trustix and TurboLinux. There is also an RPM package provided by Simon Matter that is tailored for RedHat/Fedora and another package from Jack Coates that is customized for Mandriva. If you try to upgrade using the wrong package, it probably won't work.

    <div class="important">

    Simon Matter names his '*common*' rpm '*shorewall*' rather than '*shorewall-common*'.

    </div>

2.  If you are upgrading from a 2.x or 3.x version to a 4.x version or later, please see the [upgrade issues](../legacy/upgrade_issues.md) for specific instructions.

3.  Upgrade the RPM

        rpm -Uvh <shorewall rpm file> 

    <div class="note">

    Shorewall is dependent on the iproute package. Unfortunately, some distributions call this package iproute2 which will cause the upgrade of Shorewall to fail with the diagnostic:

        error: failed dependencies:iproute is needed by shorewall-3.2.1-1

    This may be worked around by using the --nodeps option of rpm.

        rpm -Uvh --nodeps <shorewall rpm> ...

    </div>

4.  See if there are any incompatibilities between your configuration and the new Shorewall version and correct as necessary.

        shorewall check

5.  Restart the firewall.

        shorewall restart

# Upgrade using tarball

<div class="important">

If you are upgrading from a 2.x or 3.x version to a 4.x version or later, please see the [upgrade issues](../legacy/upgrade_issues.md) for specific instructions.

</div>

If you are upgrading to version 4.5.0 or later, you must first install or upgrade the Shorewall-core package:

1.  unpack the tarballs:

        tar -jxf shorewall-core-4.5.0.tar.bz2

2.  cd to the shorewall directory (the version is encoded in the directory name as in “shorewall-core-4.5.0”).

3.  Type:

        ./install.sh 

If you already have Shorewall installed and are upgrading to a new version using the tarball:

1.  unpack the tarball:

        tar -jxf shorewall-4.5.0.tar.bz2

2.  cd to the shorewall-perl directory (the version is encoded in the directory name as in “shorewall-4.5.0”).

3.  Type:

        ./install.sh

    or if you are installing Shorewall or Shorewall6 version 4.4.8 or later, you may type:

        ./install.sh -s

    The **-s** option supresses installation of all files in `/etc/shorewall` except `shorewall.conf`. You can copy any other files you need from one of the [Samples](../concepts/GettingStarted.md) or from `/usr/share/shorewall/configfiles/`.

4.  See if there are any incompatibilities between your configuration and the new Shorewall version and correct as necessary.

        shorewall check

5.  Start the firewall by typing

        shorewall start

6.  If the install script was unable to configure Shorewall to be started automatically at boot, see [these instructions](starting_and_stopping_shorewall.md).

# Upgrading the .deb

<div class="warning">

When the installer asks if you want to replace /etc/shorewall/shorewall.conf with the new version, we strongly advise you to say No. See [above](#Upgrade).

</div>

# Configuring Shorewall

You will need to edit some or all of the configuration files to match your setup. In most cases, the [Shorewall QuickStart Guides](shorewall_quickstart_guide.md) contain all of the information you need.

# Uninstall/Fallback

See “[Fallback and Uninstall](../features/fallback.md)”.
