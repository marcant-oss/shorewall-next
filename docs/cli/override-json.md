# `--override-json` — structured runtime config overlay

**Status:** planned, not yet implemented. The design seam exists in
the code (`runtime/cli.py`, `config/parser.py`, `plugins/builtin/netbox.py`)
so the feature can be wired in without further refactoring.

## Why

`shorewall-nft` reads its configuration from a directory of files
(`shorewall.conf`, `params`, `interfaces`, `rules`, `hosts`, `policy`,
`plugins.conf`, `plugins/*.toml`, …). Two real needs push for a
runtime overlay:

1. **Operators** want to flip one or two settings for a single
   `compile` / `check` / `start` invocation without rewriting files
   (`OPTIMIZE=8 just for this run`, `set NETBOX_URL to the staging
   instance`, `disable flowtable temporarily`).
2. **CI / test harnesses** want to run the compiler with **no config
   files on disk at all** — the entire config handed in as a blob.
   Today the tool requires a directory; the override mechanism
   removes that requirement.

## Shape of the JSON

The override is a **structured** object. Top-level keys are config
file names *relative to the Shorewall config directory*. The value
under each key matches the natural shape of that file:

```json
{
  "shorewall.conf": {
    "OPTIMIZE": "8",
    "FASTACCEPT": "No",
    "NETBOX_URL": "https://netbox.example.com/",
    "NETBOX_TOKEN": "…"
  },

  "params": {
    "NETMASK": "24",
    "MGMT_VLAN": "17"
  },

  "interfaces": [
    {"zone": "net",  "interface": "bond1",    "options": "tcpflags,nosmurfs"},
    {"zone": "host", "interface": "bond0.20", "options": "-"}
  ],

  "rules": [
    {"action": "ACCEPT",    "source": "net",  "dest": "fw",  "proto": "tcp", "dport": 22, "comment": "ssh from outside"},
    {"action": "DROP",      "source": "all",  "dest": "all", "proto": "icmp"}
  ],

  "hosts": [
    {"zone": "vpn", "network": "bond0.20:10.0.0.0/24"}
  ],

  "policy": [
    {"source": "net",  "dest": "all", "policy": "DROP",   "log_level": "info"}
  ],

  "plugins.conf": {
    "plugins": [
      {"name": "netbox", "enabled": true}
    ]
  },

  "plugins/netbox.toml": {
    "url":        "https://netbox.example.com/",
    "token_file": "/etc/shorewall46/plugins/netbox.token",
    "cache_ttl":  86400,
    "bulk_subnets": ["203.0.113.0/24", "2001:db8::/32"]
  }
}
```

### Per-file overlay semantics

| file class              | example files                                  | value shape                | merge rule                                     |
|-------------------------|------------------------------------------------|----------------------------|------------------------------------------------|
| KEY=VALUE               | `shorewall.conf`, `params`, `*.token`          | `{string: string}`         | dict-merge over parsed settings (JSON wins)   |
| columnar                | `interfaces`, `rules`, `hosts`, `policy`, `masq`, `conntrack`, `blrules`, `notrack` | list of row objects        | rows **appended** to the parsed list           |
| TOML plugin config      | `plugins/*.toml`                               | object matching the TOML   | dict-merge over loaded plugin config           |
| TOML plugin registry    | `plugins.conf`                                 | `{"plugins": [ … ]}`       | `plugins` list **replaces** on-disk entries    |
| raw / opaque            | anything else                                  | string                     | replaces the file content verbatim             |

The row-append rule on columnar files is the safe default: existing
rules stay, additional rows are layered on top in the original order.
When the user wants a *replacement* they can add the special key
`"_replace": true` on the list:

```json
"rules": {
  "_replace": true,
  "rows": [ { "action": "REJECT", "source": "all", "dest": "all" } ]
}
```

### Load order (lowest → highest priority)

```
built-in defaults
  → on-disk file content (if the file exists)
    → --override-json overlay
```

If the on-disk file is *absent*, the overlay still applies — it is
simply the only source. This is how `shorewall-nft` becomes usable
with no config directory at all:

```bash
shorewall-nft compile --override-json @config.json -o out.nft
```

## CLI invocation forms

Two equivalent forms, pick whichever is friendlier for a given call
site:

### 1 — One blob, every file inside

```bash
shorewall-nft compile \
  --override-json '{"shorewall.conf":{"OPTIMIZE":"8"},"rules":[…]}'

shorewall-nft compile --override-json @/tmp/cfg.json
```

`@path` reads JSON from a file; `-` reads from stdin.

### 2 — Per-file flags (one key each)

```bash
shorewall-nft compile \
  --override 'shorewall.conf={"OPTIMIZE":"8"}' \
  --override 'rules=@/tmp/extra-rules.json' \
  --override 'plugins/netbox.toml={"cache_ttl":3600}'
```

The per-file form is convenient in shell scripts (no inner-quote
gymnastics). Multiple `--override` flags accumulate and are merged
in argv order (later wins on conflict, same merge rules as above).

Both forms can be combined in a single invocation; `--override-json`
is applied first, then each `--override KEY=VALUE` on top, so ad-hoc
per-file tweaks always win over a bulk blob.

## Scope

The overlay applies to **every** command that parses a config
directory: `compile`, `check`, `start`, `restart`, `reload`, `debug`,
`simulate`, and the simlab smoketest. `merge-config` also honours
it so you can merge a v4+v6 pair while injecting extra overrides
(e.g. to exercise an experimental `OPTIMIZE` setting without
touching the checked-in config).

## No-config-directory mode

When a subcommand normally requires a positional directory, a
sentinel `-` (or simply omitting the directory when the overlay
contains enough to build a full config) selects "no on-disk
config":

```bash
# Everything from stdin, no files read.
cat my-config.json | shorewall-nft compile - --override-json -
```

The compiler refuses to proceed if the overlay is insufficient
(e.g. no zones, no interfaces) — same validation the regular path
already performs.

## Implementation seams (for the person wiring this up)

Three places already carry matching TODO comments:

- `shorewall_nft/runtime/cli.py` — add the global `--override-json`
  (and `--override`) click options, parse once, stash on
  `ctx.obj["override_json"]`, thread into every call to `_compile()`
  / `load_config()`.
- `shorewall_nft/config/parser.py::_parse_conf` — the overlay has
  to be merged after `Parser.parse()` completes, **in
  `load_config()`**, *not* inside per-file parse methods — because
  on-disk files may be missing and the per-file methods return
  early in that case.
- `shorewall_nft/plugins/manager.py::_load_config` — analogous
  overlay hook so plugin TOML files can be overridden.

Suggested new module: `shorewall_nft/config/override.py` with
`apply_overlay(parsed, overlay)` — one function per file class
(dict-merge, row-append with `_replace`, list-replace). Unit tests
per class.
