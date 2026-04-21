# Documentation restructure — 2026-04-20

Form and navigation unification pass. No content deleted.

## Files renamed (60)

All renames: PascalCase / snake_case -> kebab-case. Sample:

- `docs/concepts/Actions.md` -> `docs/concepts/actions.md`
- `docs/features/MultiISP.md` -> `docs/features/multi-isp.md`
- `docs/reference/FAQ.md` -> `docs/reference/faq.md`
- `docs/reference/configuration_file_basics.md` -> `docs/reference/configuration-file-basics.md`
- `docs/features/Shorewall_Squid_Usage.md` -> `docs/features/shorewall-squid-usage.md`

All 196 cross-link occurrences pointing to renamed files were updated.

## Top-matter added (83 files)

`**Audience**` / `**Scope**` top-matter block added after H1 in all docs
that lacked it, across: `docs/concepts/` (14 files), `docs/features/` (44 files),
`docs/reference/` (16 files), `docs/roadmap/` (2 files), `docs/shorewalld/index.md`,
`docs/testing/` (5 files), `docs/cli/` (1 file), `docs/roadmap/HOWTO-CLAUDE-hw-offload-addition.md`.

Two files had no H1 (`getting-started.md`, `whitelisting-under-shorewall.md`);
H1 was prepended along with top-matter.

## Admonitions normalised (311)

`<div class="caution">`, `<div class="note">`, `<div class="warning">`,
`<div class="important">` converted to `**Warning**:` / `**Note**:` in
52 files across `docs/concepts/`, `docs/features/`, and `docs/reference/`.

## Code-block language tags added (249)

Bare ` ``` ` opening fences tagged in 34 files. Tag heuristics: bash for
shell commands, python for Python, yaml for YAML, nft for nftables, text
for everything else. All remaining bare fences are closing fences (correct).

## Index pages created (7)

- `docs/concepts/index.md`
- `docs/features/index.md`
- `docs/reference/index.md`
- `docs/cli/index.md`
- `docs/roadmap/index.md`
- `docs/shorewall-nft/index.md`
- (docs/testing/index.md and docs/shorewalld/index.md already existed)

## TOC sections added (25)

Added to all docs with >= 3 H2+ headings and > 200 lines that did not
already have anchor-link TOCs, including:
`cli/commands.md`, `testing/live-firewall-test-plan.md`,
`testing/simlab.md`, `shorewall-nft/plugin-development.md`,
`roadmap/hw-offload-eswitch.md`, `concepts/marks-and-connmark.md`, etc.

## "See also" sections added (22)

Added to `docs/shorewall-nft/` (7 files), `docs/testing/` (5 files),
`docs/roadmap/` (2 files), `docs/cli/` (2 files), `docs/index.md`,
`docs/quick-start.md`, `docs/shorewalld/index.md`.

## Broken cross-links

Before restructure: 79 broken. After restructure: 79 broken (no change by restructure pass).
After broken-link fix pass (2026-04-20): **0 broken** in current docs, **0 broken** in legacy docs.

### Fix summary (broken-link fix pass)

**77 broken links re-detected** (2 were already fixed or miscounted vs 79 original).

**Legacy stub files created (14)** in `docs/legacy/`:
- `upgrade_issues.md`, `bridge-Shorewall-perl.md`, `Shorewall_and_Aliased_Interfaces.md`,
  `samba.md`, `support.md`, `Documentation_Index.md`, `blacklisting_support.md`,
  `XenMyWay-Routed.md`, `XenMyWay.md`, `Vserver.md`, `OpenVZ.md`, `UPnP.md`,
  `FoolsFirewall.md`, `IPP2P.md`

All stubs contain a redirect notice pointing to the current equivalent doc where one exists.

**Links fixed in-place (40)**: All `../legacy/` targets now resolve to the new stubs.

**Links removed/rewritten (37)**:
- `???` placeholders (10): link removed, surrounding text preserved as plain text
- `manpages/shorewall.conf.htmlig` (3): replaced with plain text `shorewall.conf(5)`
- `manpages/shorewall.conf` (1): replaced with plain text `shorewall.conf(5)`
- `Build.md`, `Shorewall-perl.html%23compiler.pl` (2): removed link, text preserved
- `pub/shorewall/contrib/...` (1): replaced with absolute `https://shorewall.org/` URL
- `../concepts/Anatomy.md` (1): repointed to `../concepts/introduction.md`
- `../features/PPTP.md` (3): removed link, text preserved (PPTP doc not ported)
- `../features/Shorewall-init.md` (3 in reference/): removed link, text preserved
- `Shorewall-init.md` (2 in features/): removed link, text preserved
- `IPSEC-2.6.md` (5): 3 removed, 1 repointed to `ipsec.md`, 1 repointed to upstream text
- `PPTP.md` (2 in features/): removed link, text preserved
- `6to4.md` (2): repointed to `ipv6-support.md#6to4`
- `../features/6to4.md` (1): repointed to `../features/ipv6-support.md#6to4`
- `images/basics.png`, `images/basics1.png` (2): removed/replaced with placeholder text

**Final broken-link count**: current=0  legacy=0

## Files intentionally left alone

- `docs/PRINCIPLES.md` — top-matter exempt per spec; has H1 and clear structure
- `docs/cleanup-2026-04-20.md` — scratch file from prior cleanup pass
- `docs/testing/security-test-plan.md` and `security-test-plan.*.{md,yaml}` — auto-generated / authored sources; not touched per spec
- `docs/reference/commands.json`, `features.json`, `test-index.json` — generated; not touched
- `docs/cli/override-json.schema.json` — schema file; not markdown
- All `CLAUDE.md` files — exempt per spec; package maintainer-owned
- `CHANGELOG.md`, `README.md`, `HOWTO-CLAUDE.md` — root-level conventions exempt

## Surprise findings

- `docs/concepts/my-network.md` (929 lines) and `docs/features/multi-isp.md`
  (1864 lines) are very long with dense legacy content. TOC was not added to
  my-network.md because it has no H2 headings (all sections use inline bold).
  Both could benefit from splitting but that would require content decisions.
- `docs/reference/shorewall_quickstart_guide.md` was already a very thin
  (33-line) doc — renamed and top-matter added, but it is essentially a pointer
  doc. Consider merging with `getting-started.md`.
- `docs/roadmap/HOWTO-CLAUDE-hw-offload-addition.md` is in German. This is
  fine for an internal AI-agent HOWTO, but worth noting for discoverability.
