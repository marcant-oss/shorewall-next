# DaemonConfig — typed runtime configuration

## Why

`Daemon.__init__` historically accepted ~34 loose keyword arguments.
Testing a single subsystem startup (e.g. `_start_dns_pipeline`) required
instantiating a `Daemon` with every field mocked — including unrelated
fields for VRRP, SNMP, or the control socket.

`DaemonConfig` (audit item A-2, commit `eb9d6e74c`) replaces that surface
with a single frozen dataclass.  Each `_start_*` method reads
`self._config.<field>` directly; a unit test can now construct a minimal
`DaemonConfig` with only the fields that subsystem reads.

---

## Two-stage config pipeline

```
shorewalld.conf  ──►  ConfDefaults  ──►  DaemonConfig  ──►  Daemon(config=cfg)
  (file, optional)     (Optional fields)   (concrete fields,   (runtime)
                                            frozen=True,
                                            slots=True)
```

- **`ConfDefaults`** (`config.py`): file-view dataclass with `field | None`
  types.  `None` means "not set in conf file — fall through to CLI default".
  Populated by `load_conf_defaults(path)`.

- **`DaemonConfig`** (`daemon_config.py`): fully-resolved runtime config.
  All 34 fields are concrete (no `| None`).  The CLI layer (`cli.py`) merges
  `ConfDefaults` with argparse defaults and constructs `DaemonConfig(...)`.

The split keeps file parsing and CLI parsing separate.  `DaemonConfig` is
always a complete, valid config; code never needs to check for `None` after
construction.

---

## Field surface (summary)

| Category | Fields |
|----------|--------|
| Prometheus scrape | `prom_host`, `prom_port`, `scrape_interval`, `reprobe_interval` |
| Sockets | `api_socket`, `control_socket` |
| Netns | `netns_spec` |
| DNS pipeline | `allowlist_file`, `dns_dedup_refresh_threshold`, `batch_window_sec`, `pbdns_listen`, `pbdns_proto` |
| Instances | `instances` (tuple), `iplist_configs` (tuple) |
| Peer link | `peer_link_*` fields |
| State | `state_dir` |
| VRRP / SNMP | `enable_vrrp_collector`, `vrrp_snmp_config` |

Full field list: `packages/shorewalld/shorewalld/daemon_config.py`.

---

## Quick example

```python
from shorewalld.daemon_config import DaemonConfig
from shorewalld.core import Daemon

cfg = DaemonConfig(
    scrape_interval=30,
    prom_host="0.0.0.0",
    prom_port=9748,
    # ... all 34 fields are required; use dataclasses.replace() for copies
)
daemon = Daemon(config=cfg)
```

---

## Migration note for out-of-tree callers

The kwargs-based path still works for one release cycle:

```python
# Old — still works, emits DeprecationWarning(stacklevel=2)
Daemon(prom_host="0.0.0.0", prom_port=9748, scrape_interval=30, ...)

# New — no warning
from shorewalld.daemon_config import DaemonConfig
Daemon(config=DaemonConfig(prom_host="0.0.0.0", prom_port=9748, scrape_interval=30, ...))
```

The warning fires at `stacklevel=2` so it points to the caller's
construction site, not into `core.py`.  The kwargs path will be removed in
a future major release; no hard timeline is set yet.

---

## Back-compat properties

`Daemon` exposes read-only properties (`prom_host`, `prom_port`,
`api_socket`, `netns_spec`, `scrape_interval`, `reprobe_interval`,
`allowlist_file`, `instances`, `control_socket`, `iplist_configs`) that
proxy into `self._config`.  Code that reads these attributes on a `Daemon`
instance continues to work without modification.
