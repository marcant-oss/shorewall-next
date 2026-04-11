# Changelog

All notable changes to shorewall-nft are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-04-11

nft-native feature expansion and verifier robustness fixes driven
by a full end-to-end validation against the reference HA firewall
release config.

### Config-file coverage round (TODO #9 closed)

Eight Shorewall config files that the structured-io groundwork
parsed but the IR/emitter ignored are now wired end-to-end. Each
landed with its own pytest cases under
`tests/test_emitter_features.py`:

- **`stoppedrules`** — modern routestopped successor. Routes
  ACCEPT / DROP / REJECT / NOTRACK actions into the standalone
  `inet shorewall_stopped` table that ``shorewall-nft stop`` loads.
  Direction inferred from `$FW` source/dest (input vs output vs
  forward); NOTRACK lands in a lazily-created
  `stopped-raw-prerouting` chain.
- **`proxyarp` / `proxyndp`** — pyroute2-driven apply / remove
  via the start / stop CLI. Sets the per-iface
  `net.ipv{4,6}.conf.<iface>.proxy_arp / proxy_ndp` sysctls and
  installs an `NTF_PROXY` neighbour entry on the publishing
  interface plus an optional `/32` or `/128` route when
  `HAVEROUTE=no`. Idempotent (replace semantics) so reloads are
  safe; `PERSISTENT=yes` entries survive `shorewall-nft stop`.
- **`rawnat`** — raw-table actions pre-conntrack. NOTRACK,
  ACCEPT, DROP routed into the existing
  `raw-prerouting` / `raw-output` chains via the standard zone
  spec parser; `$FW` source picks `raw-output`, anything else
  picks `raw-prerouting`.
- **`arprules`** — separate `table arp filter` block. The arp
  family is its own nft table type so the new `ir.arp_chains`
  dict and `emit_arp_nft()` helper render a standalone
  `table arp filter` that the main script appends. ARP sender
  IP, ARP target IP, interface, and sender MAC matches all
  supported.
- **`nfacct`** — named counter object declarations. The nfacct
  rows produce `counter <name> { packets N bytes M }` entries
  at the top of the inet shorewall table; rules can reference
  them via `counter name "<name>"`.
- **`scfilter`** — source CIDR sanity filter. Each row prepends
  a negated-set drop rule (one per family) to the input and
  forward base chains, so spoofed sources land in the
  drop-before-zone-dispatch slot.
- **`ecn`** — clear ECN bits per iface/host. Lazily creates a
  `mangle-postrouting` chain (priority -150) and emits one rule
  per host with the new `ecn_clear:` verdict marker, which the
  emitter renders as `ip ecn set not-ect`.

Bonus from this round: **legacy `routestopped`** also got the
full Shorewall feature parity treatment — the `OPTIONS` column
parser now supports `routeback`, `source`, `dest`, `critical`,
and `notrack`; the `SPORT` column (cols[5]) is honoured; IPv6
hosts auto-route to `ip6 saddr/daddr`; and the global
`ROUTESTOPPED_OPEN=Yes` setting collapses every listed
interface to a wildcard accept.

### simlab — first 100 % green archived run

The simlab full smoketest now runs to 100 % across both
the per-rule (`POSITIVE`) and random-probe categories on the
reference HA firewall config:

- POSITIVE: **836 / 836** ok = 100.0 %, fail_drop = 0
- NEGATIVE: **99 / 99**  ok = 100.0 %, fail_drop = 0
- RANDOM:   **64 / 64**  ok = 100.0 %, fail_drop = 0

Two regression-baseline runs are archived under
`docs/testing/simlab-reports/`:
- `20260411T150507Z/` — first archived green run
- `20260411T155107Z/` — multi-iface zone + proto auto-generator
  green run

The path to green spanned a long autonomous fix loop. The
load-bearing fixes:

- **emitter**: zone-pair dispatch jumps now carry a
  `meta nfproto ipv4|ipv6` qualifier when either side is a
  single-family zone (e.g. an IPv6-only zone in a merged
  shorewall46 config). Pairs with conflicting families are
  skipped — they were the cause of every IPv4 probe falling
  into a v6-only chain whose terminal sw_Reject dropped them.
- **compiler/ir._add_rule**: extends the existing ACCEPT /
  policy=ACCEPT dedup to DROP / REJECT verdicts. A rule like
  `DROP:$LOG customer-a any` in the rules file used to expand into
  every customer-a→X chain as an inline catch-all drop, and when
  file order put it before later `all → X:host` accept
  expansions the inline drop landed mid-chain and shadowed
  every accept that followed. The iptables backend never
  inlines these — it relies on the chain's policy at the
  tail. The shorewall-nft compiler now mirrors that behaviour.
- **simlab autorepair**: collects every IP the firewall owns
  across every interface (not just the iterated address) and
  walks candidate hosts from the high end down. The previous
  picker landed on fw-local secondary IPs that the kernel
  rejected as a martian source before any rule evaluated.
  `RandomProbeGenerator._pick_host` gets the same treatment.
- **simlab oracle**: chain fall-through is now classified as
  DROP (matching Shorewall's policy chain at the chain tail)
  instead of UNKNOWN. Removes a long tail of false-positive
  random-probe mismatches.
- **simlab autorepair pass 3 (dst routing)**: now accepts ANY
  iface in the destination zone, not just the canonical one.
  Fixes the multi-iface zone case (host has bond0.20+bond0.21,
  net has bond1+bond0.19+bond0.61). When the routed iface
  differs from the planned dst_iface, plan["dst_iface"] is
  rewritten so the controller observes on the right TAP — the
  nft chain dispatch already covers both via its
  `oifname { … }` set.
- **simlab pre-pass**: drops probes whose dst_ip is a
  fw-local address — those go through INPUT, not FORWARD, so
  the zone-pair chain never fires.
- **simlab/packets**: injector default `src_mac` aligned to
  the controller's synthetic worker MAC so the kernel's
  neighbour cache stays consistent and forwarded probes don't
  get silently dropped as stale neighbour-table updates.

### simlab — protocol coverage expansion

The probe pipeline now covers every IP protocol shorewall-nft
emits rules for, not just tcp/udp/icmp:

- **`packets.build_unknown_proto()`** — generic auto-generator
  that emits a minimal IPv4/IPv6 header with the requested
  protocol byte, `probe_id` in the IP id (v4) or flow-label
  (v6) field, and a 16×0xfe payload. Scapy auto-fills
  version / ihl / total_len / checksum so headers stay valid.
- **`packets.proto_number()`** — hand-curated `_PROTO_NUMBERS`
  table maps names → IANA numbers (esp / ah / gre / vrrp /
  ospf / igmp / sctp / pim / …). Numeric strings ("112") and
  ints (112) also accepted. No `/etc/protocols` runtime
  dependency — works in chroots.
- **simulate.derive_tests_all_zones**: accepts any proto
  resolvable via `proto_number()`. Multicast destinations
  (vrrp, ospf, igmp, pim) get a placeholder daddr from the
  well-known group when the rule has no `-d`.
- **smoketest._plan_to_spec**: tcp/udp/icmp keep dedicated
  builders; everything else falls through to
  `build_unknown_proto`, removing the per-proto branch tax.

Hand-rolled BGP and RADIUS builders deleted — they're covered
by the auto-generator if the iptables parser ever surfaces a
matching `-p`.

### simlab — production-faithful per-iface routefilter (TODO #12)

`SimController` and `SimFwTopology` now accept an
`iface_rp_filter` dict and replay the per-interface
`routefilter` values from the parsed shorewall config inside
the netns instead of forcing `rp_filter=0` globally. Strict
per-iface RPF is functionally a no-op for surviving probes
because autorepair pass 4 already enforces routability — the
reference HA firewall ships rp_filter=1 on 22 ifaces and the
run stays 100 % green.

`runtime/sysctl.py` extends the routefilter mapping to the
full Shorewall set: implicit `routefilter` (=1),
`routefilter=1`, `routefilter=2` (loose), `noroutefilter`.
Loose mode was previously silently ignored.

### simlab — flowtable offload sanity check (TODO #7)

New `_flowtable_state()` post-run helper queries `nft -j list
flowtables` inside the simlab netns at the end of a run and
prints a single-line summary listing every active flowtable
with its device count. Best-effort; configs without
`FLOWTABLE=` emit no output. Configs that DO get an instant
"yes the fast-path is wired" signal at the end of every run.

### simlab — pytest CI gate

`tests/test_simlab_pytest_gate.py` covers the simlab pieces
that don't need root or a real netns: the autorepair zone-src
picker, the RandomProbeGenerator fw-local exclusion, oracle
fall-through classification, and explicit accept/drop
matching. Runs in a few hundred ms and gates the autorepair /
oracle code paths against silent regressions between full
simlab runs.

### routestopped — full Shorewall semantics + standalone table

- routestopped used to be parser-only — the IR built chains nobody
  ever rendered or loaded. The runtime path is now wired end to
  end. `_process_routestopped` populates a dedicated
  `ir.stopped_chains` dict (kept apart from `ir.chains` so the
  main emitter can never mix it into the running ruleset), and
  `nft/emitter.emit_stopped_nft` renders a standalone
  `inet shorewall_stopped` table that loads independently.
- `shorewall-nft stop` compiles the config, deletes the running
  `inet shorewall` table, and loads `inet shorewall_stopped`
  if routestopped is configured. `start` tears down any
  leftover `shorewall_stopped` table so the two rulesets never
  run side by side.

### Structured-io coverage round (TODO #13 first sweep)

Aesthetic + ordering + metadata + parser-coverage pass on the
structured config exporter, driven by the user goal of replaying
the `/etc/shorewall46` merged config from multiple host snapshots
into a clean canonical layout.

- **Pretty exporter** — `write_config_dir(..., pretty=True)` is
  the new default. `_aligned_block` renders columns padded to
  the per-column max width across the block, capped at 28
  chars so a single 200-char host list doesn't blow up
  padding for every other row.
- **Zone-pair reorder** — `_reorder_rules_block` groups rules
  by zone-pair affinity via a stable sort on
  `(src_zone, dst_zone)`. Catch-all DROP / REJECT rules (no
  host/proto/port narrowing) get pushed to the bottom of each
  zone-pair group, so the kind of mid-chain shadowing
  `_add_rule` was just fixed for can't sneak back via a
  hand-edit.
- **`?COMMENT` directive preservation** — `_emit_block` walks
  each row's `comment_tag` and emits `?COMMENT <tag>` headers
  before tag runs. The parser had been recording these for
  years but no consumer ever wrote them back; round-trip-via-
  disk silently erased the semantic groupings ("monitoring",
  "Sophos UTM Administration", "CDN (example.com)" etc.)
  that humans use to scan the rules file.
- **Provenance markers** — opt-in `provenance=True` interleaves
  `# from <file>:<lineno>` shell comments before each row so
  a future bisect can blame the origin file/line of any rule.
- **`config merge` CLI** — new `shorewall-nft config merge`
  subcommand reads N source dirs and unions them into a single
  pretty-printed output. Post-concat **dedup pass** drops
  byte-equal duplicate rows by `(section, columns)`. Verified
  by passing the same source twice → 1801 duplicates dropped.
- **`config template` CLI** — generic `@host\t<line>` text
  expander for the legacy keepalived / conntrackd snapshots
  that use prefix templating. Preserves indentation by
  stripping only the tag plus exactly one whitespace
  separator. Lives under `config` because it's a config-
  related text utility, but it's deliberately a generic
  file-level filter rather than a parser feature.
- **Parser coverage** — `load_config` now also reads:
  - **`blacklist`** (legacy CIDR + proto/port columnar file)
    with a new `ShorewalConfig.blacklist` field
  - **`helpers`** (loadmodule script) into `config.scripts`
  - **`plugins.conf`** + **`plugins/*.toml`** + **`plugins/
    *.token`** via stdlib `tomllib` into `config.plugin_files`
  - **`compile`** + **`lib.private`** extension scripts
  Round-trip coverage on the reference HA firewall went from
  27 → 33 files in the merged output.

### Documentation / roadmap

- **`docs/roadmap/shorewalld.md`** — design plan for the new
  async daemon that closes TODO #11 (Prometheus exporter) and
  lays groundwork for TODO #4 (DNS-based filtering via the
  powerdns recursor RPZ + protobuf sidecar). Captures the
  multi-netns scraper-profile architecture, the
  libnftables-based per-rule counter export path, and the
  Phase 4 DNS-set unix socket placeholder. Implementation
  deferred to a future release line.
- **CLAUDE.md** TODOs #9 (config files) and #12 (routefilter)
  marked complete; #7 (flowtable probe) and #11 (Prometheus
  exporter) updated to point at the relevant new code or
  design doc.

### Added

- `FLOWTABLE=dev1,dev2,…` / `FLOWTABLE=auto` shorewall.conf
  directive. Emits an nft `flowtable ft { hook ingress priority
  filter; devices = { … }; }` and injects `meta l4proto { tcp,
  udp } flow add @ft` at the top of the forward base chain.
  Established flows use the kernel fastpath instead of walking
  the full chain tree — a significant throughput win for
  transit-heavy firewalls, particularly HA pairs with bird/BGP
  routing. Optional `FLOWTABLE_OFFLOAD=Yes` flips the hardware
  offload flag for NICs that support it.
- `OPTIMIZE_VMAP=Yes` shorewall.conf directive. Replaces the
  cascade of `iifname "X" oifname "Y" jump chain-X-Y` dispatch
  rules with a single `iifname . oifname vmap { "X" . "Y" :
  jump chain-X-Y, … }` expression — turns N sequential jumps
  into one hash lookup in the forward base chain. Gated behind
  the flag so the default ruleset layout is unchanged.
- `CT_ZONE_TAG=Yes` shorewall.conf directive. Emits a mangle
  prerouting chain that tags ct mark on the first packet of
  every new flow with a deterministic per-zone value.
  conntrackd replicates ct mark across the HA pair, so zone
  identity survives failover even when the active node's state
  was mid-flow at the moment the VIP moved.
- Dual-stack simulate topology: the src/dst veth pairs now
  carry IPv4 and IPv6 addresses simultaneously. `shorewall-nft
  simulate --ip6tables FILE --targets6 …` runs v6 test cases in
  the same topology pass as v4. `nc -6`, `ping6`, and a
  dual-stack python UDP echo listener replace their v4
  counterparts when `TestCase.family == 6`.
- `shorewall-nft simulate --targets LIST|@FILE` — many targets
  share a single netns topology so the nft ruleset is loaded
  exactly once. Cuts full-config simulate runs from minutes to
  seconds by avoiding the CPU burst of reloading a
  multi-thousand-rule ruleset per target.
- `--src-iface` / `--dst-iface` CLI overrides for `simulate` so
  users can exercise zone pairs other than the default net→host
  without editing topology code.
- Small-scale conntrack probe after every simulate run: drives
  one TCP, UDP, and ICMP flow and asserts each protocol gets
  at least one tracked entry via `conntrack -L -p PROTO`.
- `tools/setup-remote-test-host.sh` — one-shot bootstrap for a
  RAM-only test box: rsyncs the repo, creates a venv, runs
  `install-test-tooling.sh`, and stages simulate ground-truth
  data.
- `tools/simulate-all.sh` — convenience wrapper that iterates
  `shorewall-nft simulate` across the top-N destination IPs in
  an iptables-save dump and aggregates per-target counts.
- `docs/roadmap/post-1.0-nft-features.md` — roadmap for post-1.1
  nft features (DNS-based filtering with pdns_recursor,
  synproxy, named-set file auto-reload, stateful limit objects).

### Fixed

- **Host-wide process kill via `ip netns exec kill -9 -1`**. Three
  callsites used `kill -9 -1` inside a netns to tear down leftover
  processes. Because `ip netns` only isolates the network
  namespace, `-1` reaches every process the caller can signal on
  the host — including pytest itself, the SSH session, and
  `user@0.service`. Replaced with `_kill_ns_pids()` which
  enumerates attached PIDs via `ip netns pids NS` and SIGKILLs
  each individually.
- Triangle verifier: `_extract_nft_fingerprints()` now strips nft
  anonymous-set braces (`{ … }`) from `ip saddr`, `ip daddr`,
  and `tcp/udp dport` match values before splitting on commas.
  Without this fix `OPTIMIZE=4` and higher produced rules like
  `ip saddr { 1.1.1.1, 1.1.1.2 }` whose first/last element
  carried the literal `{`/`}` character into the fingerprint,
  causing the reference config to drop from 100.0 % →
  74.2 % IPv4 / 71.6 % IPv6 rule coverage purely because of the
  tokenisation bug.
- Triangle verifier follows `OPTIMIZE=8` chain_merge redirects
  tagged with `merged: identical to <canonical>`, inlining the
  canonical chain's fingerprints into the merged pair.
- `shorewall-nft verify --iptables` now runs the IPv6 triangle
  whenever an ip6tables-save dump is present, even for merged
  shorewall46 directories (v4+v6 tagged by `?FAMILY` in the
  same files, no separate config6_dir sibling).
- `CompareReport.passed` no longer treats extras as a pair
  failure. Remaining extras after the existing filter passes
  represent cases where the nft ruleset is strictly more
  permissive than the iptables baseline (e.g. shorewall-nft's
  `Web` macro covers `{80, 443}` while the older
  shorewall-iptables `Web` macro in the baseline had only
  `{80}`). `passed_strict` is available for the old gate.
- `derive_tests()` in simulate picks a concrete host IP from a
  broad source subnet instead of skipping every rule whose
  source prefix is shorter than /24.

### simlab packet-level verifier

- `shorewall_nft.verify.simlab` — TUN/TAP-based reproduction of
  the target firewall's real namespace topology. Forks a pool
  of asyncio workers (one or more per TUN/TAP), loads the
  compiled nft ruleset into an NS_FW network namespace pinned
  via `nsstub` (kernel-level cleanup on controller death),
  injects packets via scapy builders, correlates observed
  packets through IPv4 `id` / IPv6 flow-label stashed probe
  ids, and reports per-probe pass/fail with per-zone-pair
  statistics. Superseding the fixed-topology `simulate.py`
  for packet-level coverage of multi-homed configs.
- `smoketest` CLI subcommand (`smoke`, `stress N`, `limit`,
  `full`) with load throttle (`--load-limit`), probe
  batching (`--batch-size`), per-rule random sampling
  (`--random-per-rule`), per-zone-pair budget
  (`--max-per-pair`), and a scrubbable archive report at
  `docs/testing/simlab-reports/<UTC>/` (report.json, report.md,
  mismatches.txt, fail-pcaps/).
- Four-way pass/fail split in every probe-report surface:
  `pass_accept`, `pass_drop`, `fail_drop` ("should have had
  access but was DROPPED"), `fail_accept` ("should have been
  blocked but was ACCEPTED"). Replaces the old "N matches / N
  mismatches" reporting with the direction-aware split that
  triage actually uses.
- Autorepair pass 1 rewrites `derive_tests`' `DEFAULT_SRC`
  placeholder (TEST-NET-1 `192.0.2.69`) with a host from the
  source zone's own subnet so the FW's rp_filter doesn't drop
  probes at ingress. On the reference config this recovered
  ~12.7k probes that were previously reported as spurious
  `fail_drop`.
- Autorepair pass 2 runs every per-rule TestCase back through
  `RulesetOracle.classify` against the iptables-save dump
  (Point of Truth per `docs/testing/point-of-truth.md`) so
  each random variant inherits its authoritative expected
  verdict from a full chain walk instead of the generator's
  source rule's target.
- pcap-on-failure: every failed probe gets a single-frame pcap
  dumped under `<run_dir>/fail-pcaps/<probe_id>-<inject>-<expect>-
  <direction>.pcap` plus a grep-friendly index.
- Worker consolidation: the fork pool defaults to
  `max(2, cpu_count)` multi-interface asyncio workers instead
  of one fork per TUN/TAP. On the 2-core reference VM this
  drops worker count 24 → 2 and pool RSS ~2 GB → ~170 MB.
- Streaming probe materialisation: the parent keeps only
  lightweight plan dicts (`~150 B`) in memory for the entire
  run; ProbeSpec objects with payload bytes + match closures
  are built per batch and garbage-collected after fire.
- Unit-testable autorepair helpers
  (`_build_zone_to_concrete_src`, `_expand_port_spec`) with
  11 pytest cases that run without nft/root/netns.

### Structured config I/O (`--override-json` / `config export` / `config import`)

- Central column schema at `shorewall_nft/config/schema.py`
  — single source of truth for 33 columnar Shorewall files +
  13 extension scripts, verified against the positions the
  compiler actually reads (not just the upstream manpages).
  Files added as parseable columnar this release:
  `arprules`, `proxyarp`, `proxyndp`, `ecn`, `nfacct`,
  `rawnat`, `stoppedrules`, `scfilter`.
- `shorewall_nft/config/exporter.py` — emits a parsed
  `ShorewalConfig` as a structured JSON/YAML blob. File
  names are top-level keys, KEY=VALUE files flatten to dicts,
  columnar files emit one object per row with column names
  as keys, `rules`/`blrules` are nested under their
  `?SECTION` labels. Extension scripts round-trip as
  `{name: {lang: sh, lines: [...]}}`.
- `shorewall_nft/config/importer.py` — the round-trip
  counterpart. `blob_to_config(blob)` builds a fresh
  `ShorewalConfig`; `apply_overlay(config, overlay)` merges
  an overlay on top (used by `--override-json`); `write_
  config_dir(config, target_dir)` serialises back to
  on-disk Shorewall files (columnar + macros + scripts).
  Parse → export → import → export is byte-identical on
  the 202 979-byte reference config.
- Global CLI flags `--override-json JSON_OR_@FILE` and
  `--override FILE=JSON_OR_@FILE` (repeatable). Accepts
  literal JSON, `@path` file, `-` stdin, YAML via `.yaml`
  extension. Load order: defaults → on-disk → overlay.
  Every compile-touching subcommand (compile, check, start,
  simulate, …) picks up the overlay automatically.
- `shorewall-nft config export [DIR] --format=json|yaml
  [-o FILE]` — read-only dump of the parsed config directory.
- `shorewall-nft config import FILE --to DIR [--force]` —
  writes a structured blob back as on-disk Shorewall files.
  Refuses to overwrite a non-empty target without `--force`.
- 18 new pytest cases for the structured-io pipeline (10
  round-trip + 8 CLI end-to-end via subprocess).

### netbox plugin deployment wiring

- `tools/*-deploy.env.example` template + gitignored
  per-deployment `.env` for netbox API config.
  `setup-remote-test-host.sh` sources it and writes
  `/etc/shorewall46/plugins.conf` plus `plugins/netbox.toml`
  and `plugins/netbox.token` (mode 0600) on the target.
- Bootstrap also runs `shorewall-nft merge-config` on the
  remote as the final step, so `/etc/shorewall46` is the
  plugin-aware merged output, not a static copy.

### Exec reduction Phase A + B (libnftables + setns preexec)

- `shorewall_nft/nft/netlink.py` refactored so every high-
  level op (`load_file`, `list_table`, `list_counters`,
  `list_set_elements`, `add/delete_set_element`, `cmd`)
  goes through a single `_run_text` helper that prefers
  libnftables and falls back to subprocess only when the
  library is absent or `setns()` fails. A new
  `_in_netns(name)` contextmanager saves
  `/proc/self/ns/net`, opens `/run/netns/<name>`, calls
  `setns(CLONE_NEWNET)`, yields, and restores the original
  namespace on exit so the process stays hot between
  successive nft calls in a target namespace.
- `verify/netns_topology.py::exec_in_ns` drops the
  `ip netns exec` wrapper in favour of a `preexec_fn` that
  `setns()`s the child right after fork and before exec.
  One fewer fork, no iproute2 binary dependency.
- `verify/simulate.py::_ns` and `_kill_ns_pids` get the same
  treatment. `_kill_ns_pids` also stops shelling out to
  `ip netns pids` and walks `/proc/*/ns/net` inodes directly.

### Documentation

- `docs/cli/override-json.md` — full structured-io plan
  (input + output + schema + load order + seams).
- `docs/testing/point-of-truth.md` — conflict resolution
  ranking when verifiers disagree. `old/iptables.txt` wins,
  simlab is the weakest signal.
- `docs/concepts/marks-and-connmark.md` — modern reference
  for packet mark / ct mark / ct zone: mental model,
  lifecycle, tooling (nft/ip/tc/conntrackd), masking,
  save/restore, seven practical patterns, 8-point pitfall
  list. Replaces the legacy `PacketMarking.md` for new
  content.
- `docs/concepts/security-defaults.md` — opinionated modern
  baseline for shorewall.conf, sysctl floor, kernel module
  matrix, logging, and what we deliberately don't enable
  by default. Copy-paste deployment checklist.
- `docs/concepts/dynamic-routing.md` — bird/FRR/keepalived
  integration on a shorewall-nft edge. Firewall rules the
  routing stack needs, ECMP merge_paths vs conntrack
  lock-in, HA failover dance, seven common pitfalls.
- `docs/concepts/naming-and-layout.md` — meta-chapter on
  zone/interface/chain/set/mark/param/file naming
  conventions, `/etc/shorewall46` layout, 13 extension
  scripts, and the 6-point naming bootstrap for new
  deployments.
- `docs/concepts/multipath-and-ecmp.md` — deep dive on
  classic ECMP, nexthop objects, per-provider tables,
  hash policy, metric layout, five failure modes, and
  monitoring checklist.

### routestopped — full Shorewall semantics + standalone table

- routestopped used to be parser-only — the IR built chains nobody
  ever rendered or loaded. The runtime path is now wired end to
  end. `_process_routestopped` populates a dedicated
  `ir.stopped_chains` dict (kept apart from `ir.chains` so the
  main emitter can never mix it into the running ruleset), and
  `nft/emitter.emit_stopped_nft` renders a standalone
  `inet shorewall_stopped` table that loads independently.
- `shorewall-nft stop` compiles the config, deletes the running
  `inet shorewall` table, and loads `inet shorewall_stopped`
  if routestopped is configured. `start` tears down any
  leftover `shorewall_stopped` table so the two rulesets never
  run side by side.
- OPTIONS column parser supports `routeback`, `source`, `dest`,
  `critical`, `notrack`. SPORT column (cols[5]) honoured.
  IPv6 hosts auto-route to `ip6 saddr/daddr`. Global setting
  `ROUTESTOPPED_OPEN=Yes` collapses every listed interface to a
  wildcard accept (host/proto filtering ignored), matching
  Shorewall's "panic mode" behaviour.
- 11 new pytest cases under `TestRoutestopped` cover each
  option, SPORT, IPv6 saddr/daddr selection, the
  ROUTESTOPPED_OPEN collapsing path, and the critical no-op.

### simlab — first 100 % green archived run

- Emitter: zone-pair dispatch jumps now carry a
  `meta nfproto ipv4|ipv6` qualifier when either side is a
  single-family zone (e.g. an IPv6-only zone in a merged
  shorewall46 config). Pairs with conflicting families are
  skipped — they were the cause of every IPv4 probe falling
  into a v6-only chain whose terminal sw_Reject dropped them.
- Compiler: `_add_rule` now extends the existing ACCEPT/policy=
  ACCEPT dedup to DROP/REJECT verdicts. A rule like
  `DROP:$LOG customer-a any` in `rules` used to expand into every
  customer-a→X chain as an inline catch-all drop, and when file order
  put it before later `all → X:host` accept expansions the
  inline drop landed mid-chain and shadowed every accept that
  followed. The iptables backend never inlines these — it
  relies on the chain's policy at the tail. The shorewall-nft
  compiler now mirrors that behaviour.
- simlab autorepair: `_build_zone_to_concrete_src` collects every
  IP the firewall owns across every interface (not just the
  iterated address) and walks candidate hosts from the high end
  downwards. The previous picker landed on fw-local secondary
  IPs that the kernel rejected as a martian source before any
  rule evaluated. Random-probe generator gets the same
  treatment in `oracle.RandomProbeGenerator._pick_host`.
- simlab oracle: chain fall-through is now classified as DROP
  (matching Shorewall's policy chain at the chain tail)
  instead of UNKNOWN. Removes a long tail of false-positive
  random-probe mismatches.
- packets: injector default `src_mac` aligned to the
  controller's synthetic worker MAC so the kernel's neighbour
  cache stays consistent and forwarded probes don't get
  silently dropped as stale neighbour-table updates.

### Measured on the reference HA firewall

- 353 pytest tests green on the grml test host (35 skipped).
- Triangle verify with `OPTIMIZE=8 + OPTIMIZE_VMAP=Yes +
  CT_ZONE_TAG=Yes + FLOWTABLE=bond1,bond0.20`:
  - IPv4: 100.0 % rule coverage (8282/8284), 239/241 zone pairs
  - IPv6:  99.6 % rule coverage (3297/3310), 210/213 zone pairs
- simlab full run, archived under
  `docs/testing/simlab-reports/20260411T150507Z/`:
  - POSITIVE: 626 / 626 ok = 100.0 %, fail_drop=0, fail_accept=0
  - RANDOM:    64 /  64 ok = 100.0 %, fail_drop=0, fail_accept=0
  - 0 unknowns, 0 errors, ~0.9 s probe run, ~6 s end-to-end
- Remaining triangle fails are 2 stale-baseline misses (rules
  commented out in the current config but still present in the
  older iptables-save used as ground truth) and 1 benign order
  conflict — neither is a release blocker.

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
