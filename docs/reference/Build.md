<div class="note">

This information is provided primarily for Shorewall developers. Users are expected to install from pre-built tarballs or packages. In addition to the below, it is also suggested to read the [README file](https://gitlab.com/shorewall/tools/raw/master/files/shorewall-release-process.txt) located in the root directory of the tools repository.

</div>

# Git Taxonomy

The Shorewall Git tree at Gitlab serves as the master repository for Shorewall 4.4 and later versions. It is not possible to simply export a directory from Git and run the `install.sh` script in that directory. A build step is required to produce a directory that is suitable for the `install.sh` script to run in.

My local git repositories are:

## code (clone of Code)

The development branch of each product is kept here.

- Shorewall-core.

- Shorewall

- Shorewall6

- Shorewall-lite

- Shorewall6-lite

- Shorewall-init

There are also several other directories which are described in the following sub-sections.

## code/docs

The stable release XML documents. Depending on the point in the release cycle, these documents may also apply to the current development version.

## release (Clone of Release)

Added in Shorewall 4.4.22, this directory contains the files that contain release-dependent information (change.txt, releasenotes.txt, .spec files, etc). This is actually a symbolic link to ../release which has its own Git repository.

## testing (Clone of Testing)

This directory contains the regression library files.

## tools (Clone of Tools)

This is where the release and build tools are kept. There are four subordinate directories:

tools/build  
Tools for building and uploading new releases.

tools/files  
Files that are used during the release process. The license and readme files are also kept there.

tools/testing  
Tools for testing.

tools/web  
Tools for publishing web content

## web (Clone of Web)

The files from the web site that are maintained in HTML format. are kept in this directory.

# Build Tools

As described above, the build tools are kept in `tools/build.` They are described in the following sections.

## setversion

The `setversion` script updates the version number in a directory. The script is run with the current working directory being `release`.

> `setversion` \<version\>

The \<version\> may either be a minor version or a patch version.

## build45, build46, and build

These are the scripts that respectively build Shorewall 4.5, Shorewall 4.6 and Shorewall 5.\[012\] packages from Git. Build is actually a symlink to the current build script.

The scripts copy content from Git using the `git archive` command. They then use that content to build the packages. In addition to the usual Gnu utilities, the following software is required:

rpmbuild  
Required to build the RPM packages.

xsltproc (libxslt)  
Required to convert the XML documents to other formats.

Docbook XSL Stylesheets  
Required to convert the XML documents to other formats.

Perl  
Required to massage some of the config files.

xmlto  
Required to convert the XML manpages to manpages. Be sure that you have a recent version; I use 0.0.25.

You should ensure that you have the latest scripts. The scripts change periodically as we move through the release cycles.

The scripts may need to be modified to fit your particular environment. There are a number of variables that are set near the top of the file:

STYLESHEET  
Must point to the XHTML docbook.xsl stylesheet from your Docbook XSL Stylesheets installation.

LOGDIR  
Directory where you want the build log placed. Defaults to the current working directory.

RPMDIR  
Points to your RPM directory .

DIR  
Directory where you want the release to be built. Defaults to the current working directory.

GIT  
Shorewall GIT repository.

The scripts assume that there will be a separate build directory per major release. Each build directory should contain the empty file `shorewall-pkg.config`; that file is no longer used but has been retained just as a guard against initiating a build in an unintended directory. To build a release, you cd to the appropriate directory and run the build script.

The general form of the build command is:

> `build`\[\<xx\>\] \[ -\<options\> \] \<release\> \[ \<prior release\> \]

where

opt*i*ons  
are one or more of the following. If no options are given then all options are assumed

t  
build tar files

r  
build RPMs

c  
Build the shorewall-core package.

i  
Build the shorewall-init package.

l  
Build the shorewall-lite package.

6  
Build the shorewall6 package.

L  
Build the shorewall6-lite package.

h  
Build the html document package.

s  
Build the shorewall package.

x  
Build the xml document package.

*release*  
The release version to build. Must match the version in the associated Git path.

*prior release*  
The release to be used to generate patch files.

Example 1 - Build Shorewall 4.5.7 and generate patches against 4.5.6:

> `build45 4.5.7 4.5.6`

Example 2 - Build Shorewall 4.5.7.1 Shorewall-core and generate patches against 4.5.7:

> `build45 -trc 4.5.7.1 4.5.7`

## upload

This script is used to upload a release to https://shorewall.org. The command is run in the build directory for the minor release of the product.

> `upload` \[ -\<products\> \] \<release\>

where

*products*  
specifies the products to upload. If not given, all products are uploaded. This option is generally given only when uploading a patch release.

c  
Upload the shorewall-core package.

l  
Upload the shorewall-lite package.

i  
Upload the shorewall-init package.

s  
Upload the shorewall package.

6  
Upload the shorewall6 package.

L  
Upload the shorewall6-lite package.

*release*  
The version number of the release to upload.

Example 1 - Upload release 4.3.7:

> `upload 4.3.7`

Example 2 - Upload shorewall-core-4.3.7.3:

> `upload -c 4.3.7.3`

## install.sh files

Each product includes an install script (`install.sh`) that may be used to install the product on a machine or into a directory.

By default, the scripts install the corresponding product into "/'; you can direct them to install into an empty existing directory by setting an environmental variable:

- DESTDIR (release 4.4.10 and later)

- PREFIX (all releases)

There are a number of other environmental variables that you can set to cause the directory to be populated for a particular target environment:

- DEBIAN - Debian-based systems (Debian, Ubuntu, etc.)

- SUSE - SEL and OpenSuSE

- REDHAT - RHEL, CentOS, Foobar, etc.

- MAC - Apple MacIntosh (Shorewall-core, Shorewall and Shorewall6 packages only)

- CYGWIN - Cygwin under Windows (Shorewall-core, Shorewall and Shorewall6 packages only)

- OPENWRT - OpenWRT (Shorewall-core, Shorewall-lite, Shorewall6-lite and Shorewall-init only)

See the [installation article](Install.md) for additional information
