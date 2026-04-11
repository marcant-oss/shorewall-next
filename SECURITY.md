# Security policy

shorewall-nft compiles and applies firewall rulesets. A bug in the
compiler can silently open production networks. We take security
reports seriously.

## Reporting a vulnerability

**Do not file security bugs in the public issue tracker.** Instead,
contact the maintainers privately:

- **Email**: security@marcant.net (PGP welcome, key on keyservers
  under the same address)
- **GitHub Security Advisory**: https://github.com/<org>/shorewall-nft/security/advisories/new
  (opens a private coordination channel)

Include in your report:

1. A description of the issue and its impact
2. Steps to reproduce, preferably a minimal config
3. Affected version(s) — output of `shorewall-nft --version`
4. Whether you've already notified anyone else
5. How you'd like to be credited (if at all) in the fix announcement

We will:

- Acknowledge your report within 72 hours
- Provide a preliminary assessment within 7 days
- Coordinate a fix and disclosure timeline with you
- Credit you in the fix announcement (unless you prefer otherwise)

## Scope

We consider the following in scope:

- **Compiler output drift**: shorewall-nft emitting a ruleset that
  allows traffic the source config intended to block, or vice versa.
  This is the highest-severity class.
- **Parser injection**: a malicious config triggering arbitrary code
  execution in the compiler (e.g. via `?IF` preprocessor escapes).
- **Plugin vulnerabilities**: the built-in plugins (ip-info, netbox)
  leaking credentials or executing untrusted data.
- **Privilege escalation** via the test tooling (`run-netns` wrapper,
  sudoers snippet) — though see the [scope note](#out-of-scope) below.

## Out of scope

- **Test tooling on production hosts**: the `run-netns` + sudoers
  installer is explicitly documented as dev/CI only. Deploying it
  to a production firewall is a configuration error by the operator,
  not a shorewall-nft bug. We will still fix issues reported here,
  but they don't follow the coordinated disclosure timeline.
- **Denial of service via pathological configs**: if you can craft a
  Shorewall config that takes 10 minutes to compile, file it as a
  normal performance bug.
- **Kernel bugs in nftables itself**: report those upstream to the
  netfilter team.
- **Issues in upstream Shorewall (the Perl tool)**: unrelated project.

## Supported versions

We backport security fixes to the most recent minor release.

| Version | Supported |
|---------|-----------|
| 0.11.x | ✓ |
| 0.10.x | ✓ (critical fixes only) |
| < 0.10 | ✗ |

## Hardening guidance for operators

If you deploy shorewall-nft in production:

1. **Run `shorewall-nft verify`** after every config change to
   compare against a known-good baseline (typically an
   `iptables-save` from your legacy Shorewall host).
2. **Enable config hash drift detection**: `shorewall-nft status`
   will warn if the loaded ruleset is older than on-disk source.
3. **Do not install the test tooling** on firewall hosts.
   `sudo tools/install-test-tooling.sh` creates a privileged group
   (`netns-test`) that is inappropriate for production.
4. **Secure plugin tokens**: `chmod 600` any
   `/etc/shorewall/plugins/*.toml` that contains API credentials,
   or use the `token_file =` indirection.
5. **Limit plugin data caching**: `/etc/shorewall/plugins/*-cache.json`
   may contain sensitive IPAM data. Root-only, don't back up to
   world-readable locations.
6. **Monitor the debug marker**: a production ruleset should never
   have `config-hash:<hex> debug` — if `shorewall-nft status` flags
   "DEBUG MODE ACTIVE", someone left a debug session running.

## Cryptographic signatures

We aim to sign release tags with GPG. Verify with:

```bash
git tag -v v0.11.0
```

The signing key fingerprint will be published in the first signed
release announcement.

## History

No CVEs have been filed against shorewall-nft to date. This section
will be updated as advisories are published.
