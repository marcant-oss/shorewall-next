# Falling Back to the Previous Version of Shorewall using the Fallback Script

If you install Shorewall and discover that it doesn't work for you, you can fall back to your previously installed version. To do that:

- cd to the distribution directory for the version of Shoreline Firewall that you want to fall back to.

- Type “./install.sh”

# Falling Back to the Previous Version of Shorewall using rpm

If your previous version of Shorewall was installed using RPM, you may fall back to that version by typing “rpm -Uvh --force \<old rpm\>” at a root shell prompt (Example: “rpm -Uvh --force /downloads/shorewall-3.1.1-0.noarch.rpm” would fall back to the 3.1.1-0 version of Shorewall).

# Uninstalling Shorewall

If you no longer wish to use Shorewall, you may remove it by:

- cd to the distribution directory for the version of Shorewall that you have installed.

- type “./uninstall.sh”

If you installed using an rpm, at a root shell prompt type “rpm -e shorewall”.

<div class="note">

If you specified LIBEXEC and/or PERLLIB when you installed Shorewall, you must specify the same value to the uninstall script. e.g., LIBEXEC=libexec ./uninstall.sh.

</div>
