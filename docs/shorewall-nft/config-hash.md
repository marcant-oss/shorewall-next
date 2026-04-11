---
title: Config hash drift detection
description: Detect when the loaded nftables ruleset no longer matches the on-disk Shorewall config.
---

# Config hash drift detection

Every nft ruleset emitted by shorewall-nft contains a **sha256 hash**
of its source config directory, embedded as an nft table comment:

```nft
table inet shorewall {
    comment "config-hash:c5cde3358773069a"
    ...
}
```

The hash is the first 64 bits (16 hex chars) of `sha256(concat(file_names
+ file_contents))` computed over all relevant config files in the
directory: `zones`, `interfaces`, `rules`, `policy`, `params`,
`shorewall.conf`, `masq`, `conntrack`, `notrack`, `blrules`, plus
subdirectories `rules.d/` and `macros/`.

Editor backup files (`*.bak`, `*~`) are excluded.

## Drift detection

When you run `shorewall-nft status`, the loaded hash is compared with
the current on-disk config hash:

```
Shorewall-nft is running.
  Chains: 296
  Rules: ~11642
  Config hash: c5cde3358773069a (matches source)
```

If they differ, a warning is shown:

```
Shorewall-nft is running.
  Chains: 296
  Rules: ~11642
  Config hash: c5cde3358773069a (loaded)
               6acbd4dc58cfe76b (on-disk) — DRIFT!
  WARNING: loaded ruleset differs from on-disk config. Run `shorewall-nft reload` to sync.
```

## Debug mode confirmation

Entering debug mode when the loaded ruleset doesn't match on-disk
config is effectively a **reload with annotations** — it replaces the
running ruleset. To prevent accidental changes to production traffic,
debug mode requires explicit confirmation on drift:

```
── WARNING: Config drift detected ──
  Loaded ruleset hash:  c5cde3358773069a
  On-disk config hash:  7f9d50edc93fd1ea

The currently loaded ruleset was compiled from a DIFFERENT
config than the one on disk. Entering debug mode will
RELOAD the firewall with the current on-disk config, which
may change production behavior until you exit debug mode.

Do you want to proceed and reload with debug annotations? [y/N]:
```

If you answer `n` (default), debug mode aborts without touching the
ruleset. If you answer `y`, the drift is accepted and the debug
ruleset is loaded.

## Debug mode marker

When a debug ruleset is loaded, the hash comment also contains a
`debug` flag so `status` can distinguish it:

```nft
comment "config-hash:c5cde3358773069a debug"
```

`shorewall-nft status` flags this prominently:

```
  DEBUG MODE ACTIVE — this is not a production ruleset.
```

## Hash computation

The hash function is in `shorewall_nft.config.hash`:

```python
from shorewall_nft.config.hash import compute_config_hash
from pathlib import Path

h = compute_config_hash(Path("/etc/shorewall"))
# → "c5cde3358773069a"
```

Properties:

- **Deterministic**: same content → same hash, across runs and hosts
- **Order-independent within a directory**: files are sorted by name
  before hashing
- **Scoped**: only files listed in `_HASHED_FILES` and directories in
  `_HASHED_DIRS` contribute — renaming an unrelated file doesn't
  change the hash
- **Collision-safe**: 64 bits of sha256 is overwhelming for this use
  case (detecting accidental edits, not defending against adversaries)

## What counts as drift

The following changes cause a hash mismatch:

- Editing any config file (even whitespace or comments)
- Adding or removing files from `rules.d/` or `macros/`
- Renaming a file

The following **don't** trigger drift:

- Changes to `.bak` / editor-backup files
- Changes to files not in the `_HASHED_FILES` set (e.g.
  `plugins/netbox-cache.json`)
- Changes to files under ignored subdirectories

## Limitations

- **No temporal check**: the hash tells you "the config changed" but
  not "who" or "when". Use `git` or `auditd` for that.
- **Hash of plugin configs is not tracked**: changing
  `plugins/netbox.toml` doesn't invalidate the loaded hash because
  plugin configs are consumed during enrichment, not compiled into
  nft rules directly. If you want plugin-config drift to trigger a
  reload, touch a tracked file.
- **Static includes (`static.nft`) are in the hash**: changing them
  does cause a drift warning.

## Programmatic access

```python
from shorewall_nft.config.hash import (
    compute_config_hash,
    extract_hash_from_ruleset,
)

# Current on-disk hash
source_hash = compute_config_hash(Path("/etc/shorewall"))

# Parse the hash from a ruleset dump (nft list ruleset output)
import subprocess
ruleset = subprocess.run(
    ["nft", "list", "table", "inet", "shorewall"],
    capture_output=True, text=True
).stdout
loaded_hash = extract_hash_from_ruleset(ruleset)  # or None

if loaded_hash != source_hash:
    print("DRIFT — config changed since ruleset was loaded")
```
