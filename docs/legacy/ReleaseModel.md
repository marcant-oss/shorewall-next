# Shorewall Releases

1.  Releases have a three-level identification x.y.z (e.g., 4.5.0).

2.  The first two levels (*x.y*) designate the major release number (e.g., 4.5).

3.  The third level (*y*) designates the minor release Number.

4.  Installing a new minor release involves no migration issues unless you want to take advantage of an enhancement. For example, if you are running 4.5.0 and I release 4.5.1, your current configuration is 100% compatible with the new release.

5.  A major release may have migration issues. These are listed in the release notes and on the [upgrade issues page](upgrade_issues.md).

6.  Support is available through the [Mailing List](http://sourceforge.net/mail/?group_id=22587) for the most recent Major Release.

7.  After the introduction of a new major release, support is still available for the prior major release until the principle distributions have upgraded to that new release. Fixes will only be provided for the last minor release in the previous Major Release. For example, once 4.5.0 was released, the only fixes for major issues with 4.4.27 would be released for the 4.4 series.

8.  Support for the prior major release ends once the major Linux distributions have upgraded to that release.

9.  Once a minor release has been announced, work begins on the next minor release. Periodic Beta releases are made available through announcements on the Shorewall Development and Shorewall User mailing lists. Those Beta releases are numberd w.x.y-Beta1, ...Beta2, etc. Support for the Beta releases is offered through the Shorewall Development mailing list in the form of emailed patches. There is no guarantee of compatability between one Beta release and the next as features are tweaked.

10. When the next minor release is functionally complete, one or more release candidates are announced on the Shorewall Development and Shorewall User mailing lists. These release candidates are numbered w.x.y-RC1, ...-RC2, etc.

11. What does it mean for a major release to be supported? It means that that if a bug is found, we will fix the bug and include the fix in the next minor release.

12. Between minor releases, bug fixes are made available via patch releases. A patch release has a four-level identification *x.y.z.N* where x.y.z is the minor release being fixed and N = 1.2.3...

The currently-supported major release 4.5.
