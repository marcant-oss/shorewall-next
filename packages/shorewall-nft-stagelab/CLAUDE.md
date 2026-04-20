# CLAUDE.md — shorewall-nft-stagelab

Distributed bridge-lab for shorewall-nft performance and readiness testing.
Drives synthetic traffic from a high-throughput test host through a real
firewall appliance via VLAN trunk. Three endpoint modes: `probe` (scapy frames
via TAPs inside a VLAN-filtering bridge, ~1 Gbps, correctness), `native`
(physical NIC VLAN sub-interface in a netns, iperf3/nmap, 10–25 Gbps /
1 M concurrent connections), and `dpdk` (NIC bound to vfio-pci, driven by
TRex STL/ASTF, 40–100 Gbps / 10 M+ concurrent sessions).

Depends on `shorewall-nft-netkit` for TUN/TAP and netns primitives.
Complementary to `shorewall-nft-simlab` — simlab validates compiled-ruleset
correctness in a local netns; stagelab validates performance and readiness
against real hardware.

**Development: use the repo-root venv at `../../.venv/` (Python 3.13).**
No per-package venv. See root `CLAUDE.md` for bootstrap.

## Key modules

| Module | Purpose |
|--------|---------|
| `cli.py` | CLI entry points: `stagelab validate / run / inspect / review` |
| `config.py` | Pydantic schema: `Host`, `Dut`, `Endpoint`, `Scenario` (6 kinds), `MetricsSpec` (`PrometheusSourceSpec`, `SNMPSourceSpec`), `ReportSpec`, `StagelabConfig` |
| `controller.py` | asyncio orchestrator: agent-pool management, scenario dispatch, result aggregation, advisor invocation |
| `agent.py` | Subprocess agent running on each test host: netns setup, iperf3/nmap/scapy/TRex lifecycle, metrics polling |
| `ipc.py` | Async JSON-Lines transport (one JSON object per line, UTF-8). Messages: PING, SETUP\_ENDPOINT, TEARDOWN\_ENDPOINT, RUN\_SCENARIO, POLL\_METRICS, SHUTDOWN, ACK, ERROR |
| `topology_bridge.py` | probe-mode bridge + TAP setup/teardown (`ProbeBridgeSpec`, `ProbeBridgeHandle`) |
| `topology_native.py` | native-mode NIC VLAN sub-interface in netns (`NativeEndpointSpec`, `NativeEndpointHandle`) |
| `topology_dpdk.py` | DPDK NIC unbind/bind via vfio-pci, crash-recovery via `/var/lib/stagelab/dpdk-bindings.json` |
| `tuning.py` | `apply_rss`, `apply_sysctls` — applied by the agent for `tuning_sweep` grid points |
| `trafgen_iperf3.py` | iperf3 spec builder + result parser |
| `trafgen_nmap.py` | nmap spec builder + XML result parser |
| `trafgen_scapy.py` | `ProbeSpec` + `build_frame` + `send_tap` — scapy frame injection for `probe` mode |
| `trafgen_tcpkali.py` | tcpkali spec (stubbed pending T8d source-build step) |
| `trafgen_trex.py` | TRex STL (`run_trex_stl`) and ASTF (`run_trex_astf`) wrappers |
| `scenarios.py` | Per-scenario runners (`ThroughputRunner`, `ConnStormRunner`, `RuleScanRunner`, `TuningSweepRunner`, `ThroughputDpdkRunner`, `ConnStormAstfRunner`) + `build_runner` factory |
| `metrics.py` | `MetricRow` dataclass + local pollers: `poll_nft_counters`, `poll_conntrack`, `poll_ethtool`, `poll_softirq` |
| `metrics_ingest.py` | `MetricSource`, `build_source`, `scrape_all` — Prometheus and SNMP scrape loop |
| `advisor.py` | Rule-based advisor: 8 heuristics, `Recommendation` (tier A/B/C), `AdvisorInput`, `analyze()` entry point |
| `rule_order.py` | nft rule-order analyzer: groups nft counters by chain, ranks by packet count, emits tier-C hints |
| `review.py` | Consolidate tier-B/C recommendations + rule-order hints into `ReviewPayload`; render `review.md` + `review.yaml`; `open_pr` via `gh` CLI |
| `report.py` | `ScenarioResult`, `RunReport`, `write()` — creates run directory, writes `run.json`, `summary.md`, `recommendations.yaml`, `sweep-<id>.csv` |

## Boot / venv

The shared repo-root venv is at `../../.venv/` (Python 3.13). Install order
is load-bearing:

```bash
# From repo root:
source .venv/bin/activate
pip install -e 'packages/shorewall-nft-netkit[dev]' \
            -e 'packages/shorewall-nft[dev]' \
            -e 'packages/shorewalld[dev]' \
            -e 'packages/shorewall-nft-simlab[dev]' \
            -e 'packages/shorewall-nft-stagelab[dev]'
```

`shorewall-nft-netkit` must be installed before `shorewall-nft-simlab` (which
depends on it), and before this package (which uses it in `agent.py` for
`nsstub.stop_nsstub`).

## Test commands

```bash
# Unit tests (no network, no root required):
pytest packages/shorewall-nft-stagelab/tests/unit -q

# Integration tests — root required (set up endpoint topology in a netns):
# Run via tools/run-tests.sh for isolated namespace:
tools/run-tests.sh packages/shorewall-nft-stagelab/tests/ -q
# Without isolation (only when you know what you're doing):
pytest packages/shorewall-nft-stagelab/tests/ -q --run-integration
```

Integration tests are skipped automatically when `euid != 0`.

## Remote test host

**192.0.2.73** — AlmaLinux 10, virtio-net NIC. Good for correctness smoke
(`probe` mode) and `native` kernel-stack tests. Not suitable for DPDK
line-rate testing (virtio-net is not line-rate with DPDK).

Bootstrap:

```bash
# stagelab-agent (kernel tests only):
tools/setup-remote-test-host.sh root@192.0.2.73 --role stagelab-agent

# stagelab-agent-dpdk (adds DPDK + TRex):
STAGELAB_HUGEPAGES=512 tools/setup-remote-test-host.sh root@192.0.2.73 \
    --role stagelab-agent-dpdk
```

Run a minimal smoke:

```bash
ssh root@192.0.2.73 "cd /root/shorewall-nft && \
    .venv/bin/stagelab validate examples/stagelab-probe-smoke.yaml && \
    PYTHONUNBUFFERED=1 .venv/bin/stagelab run examples/stagelab-probe-smoke.yaml"
```

For long-running runs use `systemd-run` (see simlab CLAUDE.md pattern —
`--unit`, `--collect`, `StandardOutput=file:/tmp/NAME.log`).

## Architecture notes

### Controller ↔ Agent transport

The controller (`controller.py`) spawns one agent subprocess per test host.
Transport is JSON-Lines over stdio (one JSON object per newline):

- **Local agent**: `spawn_local()` — `asyncio.create_subprocess_exec`; used
  when `host.address` starts with `local:` or in integration tests.
- **Remote agent**: `spawn_ssh()` — `asyncio.create_subprocess_exec("ssh",
  user@host, "python3 -m shorewall_nft_stagelab.agent …")`; used when
  `host.address` is an SSH target.

The controller auto-dispatches based on the `address` field — no config
switch needed.

### Disjoint-NIC rule

A physical NIC on a given host can appear in either `probe`/`native`
endpoints or `dpdk` endpoints, but not both. `config.py` validates this at
load time. Violating it results in a `ValidationError` before any topology
code runs.

### DPDK reversibility contract

Before `setup_dpdk_endpoint` returns, the original kernel driver name and bind
timestamp are written to `/var/lib/stagelab/dpdk-bindings.json` under an
exclusive file lock. On `teardown_dpdk_endpoint` the NIC is re-bound to the
original driver and the entry is removed. On agent startup `recover_from_crash`
replays any entries left by a prior crash. Never skip `teardown_dpdk_endpoint`
— use `try/finally` around every `setup_dpdk_endpoint` call.

### Advisor is rule-based, not ML

All 8 heuristics in `advisor.py` are threshold comparisons. Thresholds are
module-level constants (e.g. `_CONNTRACK_FILL_FRAC = 0.80`). Tune them by
editing the constants; no model retraining. The advisor is deterministic —
same inputs, same outputs.

Tier semantics:
- **A** — testhost-only (NIC ring, IRQ affinity, TCP buffers). Auto-applied
  by `tuning_sweep`. Never touch the firewall.
- **B** — firewall-side (conntrack table, flowtable). Requires operator review.
  Goes into `stagelab review` bundle.
- **C** — compiler hint (rule ordering). Goes into `stagelab review` bundle
  for future T17b integration.

## Debug lessons (do not re-learn these)

- **Package managers differ**: bootstrap detects `apt` vs `dnf` automatically.
  Never hard-code one. `iperf3` is in EPEL on EL10 (not in AppStream).
  `bridge-utils` is not a separate package on EL (bridge commands come from
  `iproute`).

- **`spawn_local` vs `spawn_ssh` auto-dispatch**: when `host.address` starts
  with `"local:"` the controller calls `spawn_local`; otherwise `spawn_ssh`.
  Integration tests set `address: "local:"` so no SSH key is needed.

- **`run_scenarios` requires `setup_endpoints` first**: the scenario runners
  look up endpoints in the controller's internal dict. Calling `run_scenarios`
  before `setup_endpoints` raises `KeyError: 'endpoint_name'`. The `cli.py`
  `run_cmd` always calls `setup_endpoints` before `run_scenarios`. (Fixed in
  commit 0bb3d06ee.)

- **TRex is NOT pip-installable**: staged at `/opt/trex/vX.YY` by the
  bootstrap script. `trafgen_trex.py` looks for the `t-rex-64` binary under
  that path. If TRex is absent the `throughput_dpdk` / `conn_storm_astf`
  agent handlers raise `RuntimeError` with a clear message.

- **NIC binding MUST be reversible**: the `DpdkEndpointHandle` teardown writes
  the recovery entry before returning. Never let a DPDK endpoint go out of
  scope without calling `teardown_dpdk_endpoint` — use `try/finally`.
  `recover_from_crash` on agent start is a safety net, not the primary path.

- **DPDK pci_addr format**: must match `^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`
  (all lowercase). `0000:01:00.0` is valid; `0000:01:00.0` with uppercase
  letters will be rejected by `config.py` before topology code runs.

- **AlmaLinux 10 + EPEL timing**: `iperf3` and several Python packages are in
  EPEL 10. If `dnf install iperf3` fails, check that
  `dnf install -y epel-release` ran first. Bootstrap does this, but manual
  runs sometimes miss it.

- **`conn_storm` uses tcpkali**: tcpkali is not in any distro package repo at
  this time. The scenario type and config schema are wired; the agent handler
  calls `run_tcpkali` which is stubbed (T8d). If you need connection-storm
  tests today, use `conn_storm_astf` with a DPDK endpoint instead.

## Open items

- **T17b** — compiler integration: feed tier-C rule-order hints from
  `rule_order.py` back into the shorewall-nft optimizer as ordering directives.
  `rule_order.py` produces the hints; the compiler side is TODO.
- **Full HA-pair scenario** — model a second FW endpoint with VRRP failover
  + conntrackd sync. Currently only a single FW DUT is supported.
- **Hardware-offload flow-steering tests** — verify that nft flowtable
  `offload` actually moves flows to hardware. The `flowtable_stagnant` advisor
  heuristic (fires when `flowtable_*` counter == 0) is a proxy; a real offload
  verification needs conntrack counter comparison before/after ruleset load.
- **tcpkali source-build** (T8d) — add a source-build step to the bootstrap
  script so `conn_storm` kernel mode is usable.
- **CI gate** — add a minimal single-probe stagelab scenario to the CI
  integration test matrix. Currently only unit tests run in CI.
