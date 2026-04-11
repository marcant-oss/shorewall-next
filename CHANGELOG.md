# Changelog

All notable changes to shorewall-nft are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-04-11

First stable release.

### Added

- GPL-2.0 LICENSE, CONTRIBUTING, SECURITY, pre-commit config
- GitHub Actions CI: unit tests on Python 3.11/3.12/3.13, lint
  (ruff + shellcheck), wheel build, Debian package build, Fedora
  RPM package build, integration tests in netns
- Generic dual-stack sample fixture under `tests/fixtures/sample-fw/`
  using RFC 5737 and RFC 3849 documentation prefixes
- Network namespace route/sysctl detection tests
- Debian (`packaging/debian/`) and RPM (`packaging/rpm/`) packaging
- Shell completions (bash/zsh/fish) and a groff-checked man page
- systemd service units with legacy-shorewall conflict declarations

### Changed

- Single-binary Debian package (the `-tests` and `-doc` subpackages
  were dropped in favour of a simpler layout)
- All customer-identifying references sanitised: tests, docs, fixtures
  and examples now use RFC 5737/3849 documentation prefixes and
  generic names. Real Netbox API token removed from example config.
- CI triggers on `main` (was only `master`/`shorewall-next`)
- Relaxed `pyroute2 >= 0.7` for wider distro compatibility

### Fixed

- Comma-separated zone lists in `SOURCE` and `DEST` columns
  (`linux,vpn-voice`, `loc,dmz`) now expand correctly
- Bridge port spec `br1:bond0.115` in interfaces file: the port
  name is used as the kernel iface, not the bridge name
- Protocol column normalised to lowercase (accepts `TCP`, `UDP`)
- `~MAC` filter syntax in rules now emits `ether saddr` instead
  of `ip saddr`
- Extra named ports recognised: jetdirect (9100), iec-104, modbus,
  mms, dnp3, bacnet, opcua
- `shorewall-nft debug` restore no longer flushes the entire
  ruleset; only the `inet shorewall` table is touched
- Debug SIGTERM signal propagation through the `sudo → run-netns →
  ip netns exec` chain made robust via process-group signalling
- Test file I001/F401/F541 ruff cleanups across `tests/`

## [0.11.0] — 2026-04-11

### Added

#### Explicit config-directory override flags

All 13 commands that take a config directory (`start`, `restart`,
`reload`, `check`, `compile`, `verify`, `debug`, `migrate`, `simulate`,
`load-sets`, `generate-set-loader`, `generate-sysctl`, `generate-tc`)
now accept five new flags for full control over the configuration
source. Previously only the v4 dir could be overridden via positional
argument, and the v6 sibling was always auto-detected.

Six distinct modes are now supported:

| Mode | CLI |
|------|-----|
| Auto (default) | `shorewall-nft start` |
| Explicit merged | `shorewall-nft start -c /srv/merged` |
| Legacy dual auto-sibling | `shorewall-nft start /srv/v4` or `--config-dir4 /srv/v4` |
| Legacy dual explicit | `shorewall-nft start --config-dir4 /srv/v4 --config6-dir /srv/v6` |
| v4-only | `shorewall-nft start --config-dir4 /srv/v4 --no-auto-v6` |
| v6-only | `shorewall-nft start --config6-dir /srv/v6 --no-auto-v4` |

New flags: `-c`/`--config-dir`, `--config-dir4`, `--config6-dir`,
`--no-auto-v4`, `--no-auto-v6`.

- `load_config(..., skip_sibling_merge=True)` parser parameter to
  explicitly disable v6 sibling auto-detection.
- `_derive_v4_sibling(v6_dir)` symmetric helper for v6→v4 sibling lookup.
- 15 new resolver tests in `tests/test_cli_config_flags.py`.

#### UX improvements

- **`shorewall-nft lookup --json`** — emit pure JSON on stdout, even
  for error paths. Useful for shell scripting and machine-readable
  pipelines.

- **`shorewall-nft enrich --dry-run`** — preview plugin enrichment
  changes as a unified diff without touching disk or creating backups.

- **`shorewall-nft debug --trace NFT_MATCH`** — auto-install a
  `meta nftrace set 1` rule in the input chain for the given nft match
  expression (e.g. `--trace "ip saddr 1.2.3.4"` or
  `--trace "meta l4proto icmp"`). The filter is removed automatically
  when debug mode exits (via the ruleset flush in `_restore_and_exit`).
  Removes the boilerplate of manually inserting/removing trace rules.

- **`shorewall-nft merge-config <v4>`** (single argument) — v6 sibling
  is auto-detected by appending `6` to the v4 dir name. Errors out if
  the sibling doesn't exist. Matches the symmetry of the new start-time
  flags. Passing both directories explicitly still works.

#### Documentation

- `docs/shorewall-nft/config-dirs.md` — full reference for the 6
  config-resolution modes and all override flags, with examples and
  conflict cases.
- `docs/shorewall-nft/plugin-development.md` — complete walkthrough
  for writing custom plugins: skeleton, hooks, priority conventions,
  lifecycle, testing patterns, error handling, a full GeoIP example
  plugin, and packaging guidance.

### Tests

- 236 tests total (up from 221)
- 15 new resolver tests in `tests/test_cli_config_flags.py`


## [0.10.0] — 2026-04-11

First release cut of the `shorewall-next` branch after the plugin
system, optimizer, debug mode, merge-config, and config drift work.

### ⚠️ Backward-incompatible changes

- **`/etc/shorewall46` precedence** — when `/etc/shorewall46` exists,
  it is used as the default config directory by every `shorewall-nft`
  command, overriding `/etc/shorewall`. Pass an explicit directory
  argument to force the legacy path. Existing automation that runs
  `shorewall-nft start` without a path may silently switch source.
  This matches the "merge-config is point of truth" decision.

- **`?FAMILY` preprocessor directive** — merged `/etc/shorewall46`
  files contain a shorewall-nft-specific `?FAMILY ipv4|ipv6|any`
  directive. Feeding a merged config through stock upstream Shorewall
  will fail. Merged configs are consumable only by shorewall-nft.

### Added

#### Plugin system

- New `shorewall_nft.plugins` package with base classes, manager, and
  priority-ordered hook dispatch.
- Built-in **`ip-info`** plugin: pattern-based IPv4↔IPv6 mapping per
  `/24` subnet (fallback when no authoritative source is available).
- Built-in **`netbox`** plugin: live Netbox IPAM API + local TTL cache,
  with snapshot mode for offline/CI use. Links v4 and v6 addresses via
  shared `dns_name`. Extracts customer numbers from
  `"NNNNNN - Company Name"` tenant format.
- New CLI commands: `lookup`, `enrich`, `plugins list`.
- Plugins register their own CLI subgroups (`ip-info`, `netbox`).
- TOML-based configuration in `etc/shorewall/plugins.conf` and
  `plugins/<name>.toml`.
- Transitive variable rewriting: merge-config now detects v4/v6 params
  whose values depend on renamed variables and renames them too
  (e.g. `ALL_DC=$DC1,$DC2` becomes `ALL_DC_V6` when `DC1/DC2` are
  paired).

#### merge-config

- New default output directory `/etc/shorewall46` (no `-o` required).
- Smart `?COMMENT`-block merging: same mandant tags in v4 and v6 are
  combined inside one block with v6 rules wrapped in `?FAMILY ipv6`.
- `_merge_interfaces` handles v6-only interfaces (e.g. IPv6-only
  physical links that don't exist in the v4 config).
- `--guided` mode: interactive collision resolution for params, zones,
  policies, shorewall.conf, rule blocks — with 4 choices (keep v4,
  keep v6, merge proposal, custom input).
- `--no-plugins` flag to disable plugin enrichment for a single run.
- Plugin enrichment: `?COMMENT` blocks get customer/host annotations,
  paired params are explicitly grouped instead of silently renamed.

#### Optimizer (OPTIMIZE levels)

- **Level 3 reworked**: only ACCEPT-policy empty chains are removed;
  DROP-policy empties are kept so removing them doesn't silently open
  the firewall.
- **Level 4**: combine adjacent rules differing in one field
  (saddr/daddr/sport/dport/iifname/oifname) into a single rule with an
  anonymous set.
- **Level 8**: merge chains with identical content, replacing
  duplicates with a single `jump canonical` stub.
- ipset references (`+name`) and named sets (`@name`) are correctly
  excluded from combining.

Measured production reduction:

| Config | OPTIMIZE=0 | OPTIMIZE=8 | Reduction |
|--------|------------|------------|-----------|
| fw-large  | 18366 lines | 12806 lines | **30%** |
| fw-medium | 12075 lines |  7598 lines | **37%** |
| fw-small  |   625 lines |   546 lines | **12%** |

#### Debug mode

- New **`shorewall-nft debug`** command: compiles with debug
  annotations, saves current ruleset, loads the debug ruleset, and
  restores on `Ctrl+C`.
- Every rule in debug mode gets:
  - A **named counter** (`r_<chain>_<idx>`) queryable via
    `nft list counter inet shorewall <name>`.
  - A **source-location comment** visible in `nft monitor trace`:
    `"rules:38: OrgAdmin/ACCEPT net $FW [mandant-b] {rate=3/min}"`
    showing file, line, trimmed original rule, mandant tag, and meta
    info (rate/connlimit/time/user/mark).
- Counter declarations are injected at the top of the table.

#### Config hash drift detection

- Every emitted nft ruleset embeds a sha256 hash of its source config
  as a table comment (`comment "config-hash:<16-hex>"`).
- `shorewall-nft status` compares the loaded hash against the current
  on-disk hash and warns on drift with a clear DRIFT banner.
- `shorewall-nft debug` requires **explicit confirmation** when the
  loaded ruleset hash doesn't match on-disk — entering debug mode is a
  reload and would replace production traffic handling.
- Debug marker (`config-hash:<hex> debug`) lets `status` distinguish
  debug from production rulesets.

#### Documentation

- Full MkDocs Material documentation site under `docs/`.
- Upstream Shorewall docs converted from DocBook XML to Markdown via
  pandoc (118 files), categorized into `concepts/`, `features/`,
  `reference/`, `legacy/`.
- shorewall-nft specific docs: `plugins.md`, `optimizer.md`,
  `debug.md`, `merge-config.md`, `config-hash.md`.
- Machine-readable catalogs:
  - `docs/reference/features.json` — nft feature catalog from
    `explain.py`
  - `docs/reference/commands.json` — CLI reference from click
    introspection
- `mkdocs.yml` with Material theme and full navigation tree.

#### Explain command

- `explain-nft-features` learned a new `Performance` category with
  the full optimizer documentation.
- IPv6 extended mask examples expanded with the
  `::host_bits/::ffff:ffff:ffff:ffff` syntax.
- Complex NAT examples: netmap, symmetric bidirectional NAT,
  port-range DNAT, multi-address SNAT.

### Changed

- **149 standard Shorewall macros** are now vendored inside the package
  at `shorewall_nft/data/macros/` and shipped via the wheel
  (`package-data` in `pyproject.toml`). Previously they were loaded
  from a sibling `Shorewall/Macros/` source checkout.
- `_load_standard_macros()` prefers the bundled copy; falls back to
  `/usr/share/shorewall/Macros` on systems with upstream Shorewall
  installed.
- All shorewall-nft test/probe network namespaces now use the
  `shorewall-next-sim-*` prefix (previously `swnft-*`) for consistency
  across projects.
- Debug comments now include the **trimmed original source rule**, not
  just `file:line`.

### Fixed

- v6 rules inside merged `?COMMENT` blocks were previously appended
  *after* the closing tag, losing their tag scope. They are now
  inserted before the closing `?COMMENT`.
- Merged config `interfaces` file was copied verbatim from v4; v6-only
  interfaces (e.g. `eth4` only in `shorewall6/interfaces`) were lost.
- v6 rules that reference `$ORG_PFX` (or any variable renamed with
  the `_V6` suffix) are now automatically rewritten to
  `$ORG_PFX_V6` so they resolve to the v6 value.
- Transitive rewriting handles chains of derived variables like
  `ALL_DC=$DC1,$DC2` correctly.
- Debug mode `_restore_and_exit` flush command constructed the nft
  argument list correctly (previous bug put the binary path twice).
- Parser no longer auto-merges a sibling `shorewall6` directory when
  loading a directory whose name ends in `46` (already pre-merged).

### Removed

- Upstream Shorewall source tree (~4.6 MB): `Shorewall/`, `Shorewall6/`,
  `Shorewall6-lite/`, `Shorewall-core/`, `Shorewall-init/`,
  `Shorewall-lite/`. These Perl/shell sources were reference material
  that is no longer needed — shorewall-nft has its own Python
  implementation.
- `docs/` upstream DocBook XMLs (36 MB), replaced with their Markdown
  equivalents (2.4 MB).
- Historical `TODO.md` (all items were implemented; git history
  preserves the file).
- Broken `release/` symlink to a non-existent directory.

### Security

- Debug mode temp files are created with `prefix="shorewall-next-sim-debug-"`
  in `$TMPDIR`; the path is printed so operators can manually restore
  if the signal handler fails. No sensitive data other than the
  already-loaded ruleset is written.
- Netbox plugin API token is read plaintext from `plugins/netbox.toml`;
  operators are advised to `chmod 600` the file or use the
  `token_file = "/path/to/token"` indirection.

### Tests

- Total: **221 tests** (up from 179).
- New test files:
  - `tests/test_optimize.py` — 30 tests for the 5 optimizer passes
  - `tests/test_plugins.py` — 27 tests for the plugin base + manager +
    ip-info
  - `tests/test_netbox_plugin.py` — 16 tests for the netbox plugin
    (cache, lookups, snapshot mode, tenant parsing)
  - `tests/test_config_hash.py` — 12 tests for hash computation and
    drift markers
  - `tests/test_config_resolution.py` — 6 tests for `/etc/shorewall46`
    precedence and parser auto-merge skipping

### Known issues

- Some production configs contain zone names with a comma
  (`linux,vpn-voice`) that produced an invalid nft chain name.
  Handled by the 0.12.0 comma-expansion fix in ir.py.
- Plugin-specific CLI subcommands (`ip-info`, `netbox`) are only
  registered when the default config directory contains a
  `plugins.conf`. Passing `-c <dir>` to plugin subcommands is not yet
  supported at module load time.

## [0.9.1] — earlier

See git history for pre-0.10.0 changes. Key milestones:

- 0.9.1: `explain-nft-features` command with Shorewall config syntax
- 0.9.0: initial shorewall-next release with 100% rule coverage against
  3 production firewalls
- Triangle verifier, 3-netns packet simulator, scapy-based connstate
  tests, capability detection, netlink integration, migration tool
