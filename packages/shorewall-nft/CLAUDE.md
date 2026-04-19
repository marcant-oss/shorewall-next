# CLAUDE.md — shorewall-nft (core)

Compiler + emitter + config parser + runtime CLI.
Python package: `shorewall_nft`. Entry point: `shorewall-nft`.

**Development: use the repo-root venv at `../../.venv/` (Python 3.13).**
No per-package venv. See root `CLAUDE.md` for bootstrap.

## Key directories

- `shorewall_nft/compiler/` — config → IR (`build_ir()` in `ir.py`),
  optimisations (`optimize.py`), rule actions (`actions.py`),
  proxy ARP/NDP (`proxyarp.py`).
- `shorewall_nft/nft/` — IR → nft script emitter (`emitter.py`),
  flowtable, sets, capabilities probe, explain engine, netlink glue
  (`netlink.py`), DNS sets API (`dns_sets.py`).
- `shorewall_nft/config/` — config file parser (`parser.py`),
  importer (`importer.py`), schema consistency.
- `shorewall_nft/runtime/` — CLI commands (`cli.py`), sysctl generator,
  systemd unit generator, conntrackd fragment generator.
- `shorewall_nft/verify/` — post-compile verification:
  - `triangle.py` — static rule-coverage fingerprint vs iptables-save
  - `simulate.py` — single-pair netns packet test (deprecated; use simlab)
  - `iptables_parser.py`, `connstate.py` — shared by simlab (public API)
- `shorewall_nft/plugins/` — plugin loader + `builtin/` plugins.
- `shorewall_nft/netns/` — netns helper wrappers.
- `shorewall_nft/tools/` — `merge_config.py`, `migrate.py`.
- `tests/` — pytest; `test_emitter_features.py` covers 1.1-era knobs
  (flowtable, vmap dispatch, ct zone tag, concat-map DNAT, ct mask).

## Release-blocker invariants

Release mechanics (version bump sync, tag, CHANGELOG) live in the root
`CLAUDE.md`. Shorewall-nft-specific things that must hold at every tag:

- **`/etc/shorewall46` precedence** — when both `/etc/shorewall` and
  `/etc/shorewall46` exist, the latter wins. Backward-incompatible with
  classic Shorewall; worth a release-notes line every time.
- **`?FAMILY` directive** — shorewall-nft extension; a merged
  `/etc/shorewall46` config will crash stock upstream Shorewall.
- **Examples in sync** — `examples/plugins/` matches `plugins/builtin/*.py`.
- **`generate-systemd --netns`** honours `/etc/shorewall46` as default.
- **Wheel contents** — `python -m build` wheel must include
  `plugins/builtin/` and `data/macros/`.

Deeper open items (not release-blockers):

- host-r compiler bug: chain name `linux,vpn-voice` from zone list
  with a comma. Surfaces on the host-r corpus config.
- Debug-mode edge cases: fresh netns with no loaded ruleset during
  `debug` save → restore; SIGINT during `apply_nft`; unrelated tables
  (docker, fail2ban) in the save file.

## Packaging deps

Source of truth: `docs/reference/dependencies.md`. Tests run as root via
`tools/run-tests.sh` (unshare --mount --net — no sudoers, no
`netns-test` group, no helper binary).

## Open items (compiler/emitter)

- **routefilter / rp_filter parity** — compiler does nothing with the
  `routefilter` interface option. Shorewall maps it to
  `net.ipv4.conf.<iface>.rp_filter` (0=off, 1=strict, 2=loose) plus
  interplay with `net.ipv4.conf.all.rp_filter` (kernel uses max).
  Implement: (1) compiler reads option, emits sysctl line via
  `runtime/sysctl_gen.py`; (2) shorewall.conf `ROUTE_FILTER` global
  as default for unset interfaces.
- **3-firewall config-merge replay** — re-emit merged `/etc/shorewall46`
  with consistent column widths, zone-pair grouping, catch-all DROP at
  bottom, per-rule `?COMMENT` provenance markers. Requires `@host`
  directive support in parser first.

## Debug lessons (do not re-learn these)

- **If `nft monitor trace` shows nothing** — cause is routing / RPF /
  ARP, not firewall rules. nft trace only sees packets in the matching
  table.
- **FASTACCEPT=No** requires the emitter to put
  `ct state established,related accept` inside every zone-pair chain,
  not at the top of the base forward chain. The 1.1 emitter did this
  wrong — fix in commit `7e977f70e`.
- **CT mask emit** — cannot use `ct mark and C or iifname map {…}`.
  nft rejects `or` with a map on the right. Use per-iface rules:
  `iifname "bond1" ct mark set ct mark and INV or ZONE`.
- **Triangle verifier** skips "pure ct state" rules — a missing
  `established accept` shows up as 100 % coverage (misleading). Use
  simlab for packet-level validation of stateful paths.
- **Base chain architecture** — base chains (input/forward/output)
  must have `policy drop` and contain **only** FASTACCEPT (if enabled),
  NDP accept (input/output), and dispatch jumps. `ct state invalid
  drop` and `dropNotSyn` belong in zone-pair chains, not base chains.
  Putting ct state checks before dispatch kills IPv6 forwarding
  because conntrack may not track NDP-dependent flows correctly.
  Fixed in commit `eaff8dbad`.
- **Dispatch rule ordering** — zones without interface assignments
  (e.g. `rsr ipv6`) produce dispatch rules without `oifname`.
  These catch-all rules must be emitted **after** specific zone-pair
  rules, otherwise they swallow all IPv6 traffic into the wrong
  chain. The emitter sorts by interface specificity. Fixed in
  commit `e16d76031`.
- **Dual-stack zone merge** — when merging shorewall + shorewall6,
  zones in both configs must be promoted from `ipv4` to `ip`.
  Otherwise all dispatch rules get `meta nfproto ipv4` and IPv6
  traffic is never dispatched. Applies to both `_merge_configs()`
  in `parser.py` and `_merge_zones()` in `merge_config.py`.
  Fixed in commits `d5720c4a7` and `eaff8dbad`.
- **raw chains must not dispatch** — `raw-output` (priority -300) is
  for NOTRACK rules only. If the emitter adds zone-pair dispatch
  jumps to raw chains, NDP gets routed into chains with
  `ct state invalid drop` before the normal output chain can
  accept it. Fixed in commit `d5720c4a7`.
- **Implicit loopback accept** — classic Shorewall emits
  `-A INPUT -i lo -j ACCEPT` / `-A OUTPUT -o lo -j ACCEPT`
  unconditionally; shorewall-nft must mirror this on the running
  ruleset (not only the stopped chains). Without it, local services
  on `lo` (pdns-recursor on `127.0.0.1`, Anycast IPs on `lo`,
  firewall-originated mgmt) require an explicit `$FW $FW ACCEPT`
  policy or they hit `policy drop`. Emitted in `_create_base_chains`
  after FASTACCEPT and before NDP.
