# Overview

Laptop computers generally have several network interfaces, one of which will be used at a time.

1.  Ethernet interface ‒ Used when the computer is on the desktop at home or at work.

2.  Wireless interface ‒ Used when the laptop is being used in a cafe, train or airline terminal.

3.  Point-to-point (PPP) interface ‒ Used when neither wired nor wireless service are available.

Shorewall can be configured to treat these interfaces the same and to be able to switch between them without having to reconfigure.

# Configuration

The key to configuring Shorewall on a laptop is to define multiple optional interfaces for the 'net' zone in `/etc/shorewall/interfaces`.

    #ZONE          INTERFACE      OPTIONS
    net            eth0           optional,…
    net            wlan0          optional,…
    net            ppp0           optional,…

With this configuration, access to the 'net' zone is possible regardless of which of the interfaces is being used.
