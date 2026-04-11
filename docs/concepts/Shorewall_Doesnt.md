<div class="caution">

**This article applies to Shorewall 3.0 and later. If you are running a version of Shorewall earlier than Shorewall 3.0.0 then please see the documentation for that release**

</div>

# Shorewall Does not:

- Act as a “Personal Firewall” that allows Internet access control by application. If that's what you are looking for, try [TuxGuardian](http://tuxguardian.sourceforge.net/).

- Work with an Operating System other than Linux (version \>= 2.4.0)

- Act as a Proxy (although it can be used with a separate proxy such as Squid or Socks).

- Do content filtering:

  - HTTP - better to use [Squid](../features/Shorewall_Squid_Usage.md), [E2guardian](http://www.e2guardian.org/), or [Parental Control](http://comparitech.net/parental-control) for that.

  - Email -- Install something like [Postfix](http://www.postfix.org) on your firewall and integrate it with [SpamAssassin](http://www.spamassassin.org/) , [Amavisd-new](http://www.ijs.si/software/amavisd/) and [Clamav](http://www.clamav.net/)

- Configure/manage Network Devices (your Distribution includes tools for that).

# In Addition:

- Shorewall generally does not contain any support for Netfilter [xtables-addons](http://dev.medozas.de/files/xtables/) features -- Shorewall only supports features from released kernels except in unusual cases.
