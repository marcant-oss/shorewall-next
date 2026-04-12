# CLAUDE.md — shorewall-nft-simlab

Packet-level simulation lab for shorewall-nft firewall validation.
Python package: `shorewall_nft_simlab`. Entry point: `shorewall-nft-simlab`.
Depends on `shorewall-nft` (core) for `verify.simulate`, `verify.iptables_parser`.

## Key modules

- `smoketest.py` — CLI: `full` / `quick` / `single` runs; archives
  results under `docs/testing/simlab-reports/<UTC>/`.
- `controller.py` — asyncio controller: probe scheduling, worker pool,
  result aggregation.
- `topology.py` — netns topology builder (TUN/TAP, veth, vlan, routing).
- `worker.py` — asyncio workers: packet inject + capture + classify.
- `oracle.py` — expected-verdict oracle derived from compiled ruleset.
- `packets.py` — Scapy packet builders for all probe categories
  (TCP, UDP, ICMP, VRRP, BGP, RADIUS, DNS, ARP, NDP, …).
- `dumps.py` — parse nft/iptables dump for ground-truth data.
- `report.py` — JSON/text report generator; `_write_fail_pcaps` writes
  per-failed-probe `.pcap` files + `fail-pcaps.txt` index.
- `nsstub.py` — `spawn_nsstub()`: holds netns alive via stub process
  with `PR_SET_PDEATHSIG` (survives controller SIGKILL cleanly).
- `tundev.py` — TUN/TAP device lifecycle helpers.

## Test host

- **192.168.203.83** — grml trixie/sid live, RAM-only, passwordless
  ssh as root. Reboots wipe everything.
- Bootstrap: `tools/setup-remote-test-host.sh root@192.168.203.83`
  rsyncs the repo to `/root/shorewall-nft`, creates venv, runs
  `install-test-tooling.sh`, stages ground-truth data at
  `/root/simulate-data/`. Merged config lives at `/etc/shorewall46`.
- **Long-running tests: always use `systemd-run`**, never plain `ssh &`
  or `nohup`:

  ```bash
  systemd-run --unit=NAME --collect \
    --working-directory=/root/shorewall-nft \
    --property=StandardOutput=file:/tmp/NAME.log \
    --property=StandardError=file:/tmp/NAME.log \
    CMD
  # Status: systemctl is-active NAME
  # Stop:   systemctl stop NAME && systemctl reset-failed NAME
  ```

- **`kill -9 -1` inside `ip netns exec` reaches host processes** (no
  PID isolation) — the fix in `aa45f78ca` is load-bearing. Never issue
  `kill -9 -1` in test code; use `nsstub`'s `PR_SET_PDEATHSIG` cleanup.
- **`PrivateMounts=false`** required if wrapping the simlab controller
  in a systemd unit — otherwise the `/run/netns/<name>` bind-mount
  installed by nsstub is invisible to `ip netns exec` outside the unit.
- **Simulate coverage** on this box defaults to `net → host` IPv4.
  Full-rule coverage comes from `verify --iptables /root/simulate-data/iptables.txt`.

## run-netns tool

`sudo /usr/local/bin/run-netns` is a wrapper around `sudo ip netns`.
Installed by `tools/install-test-tooling.sh` on the test host and by
the `shorewall-nft-tests` package on distros.

```bash
sudo /usr/local/bin/run-netns add <name>
sudo /usr/local/bin/run-netns delete <name>
sudo /usr/local/bin/run-netns exec <name> <cmd>
sudo /usr/local/bin/run-netns list
```

**Monorepo note:** `install-test-tooling.sh` installiert nur run-netns + sudoers.
Die Python-Pakete müssen separat über die Sub-Package-Verzeichnisse installiert werden:
```bash
pip install -e packages/shorewall-nft[dev] \
            -e packages/shorewalld[dev] \
            -e packages/shorewall-nft-simlab[dev]
```
`pip install -e .` im Repo-Root installiert nur den leeren Monorepo-Stub.

## Running simlab

```bash
# Full run (remote, ~30 min):
ssh root@192.168.203.83 \
    "cd /root/shorewall-nft && \
     PYTHONUNBUFFERED=1 .venv/bin/python \
         -m shorewall_nft_simlab.smoketest full \
         --random 50 --max-per-pair 30 --seed 42"

# Results land under docs/testing/simlab-reports/<UTC>/ (local, not committed to git)
```

## Open items (simlab)

1. **Full simlab run → baseline** — smoketest `full` on the VM, save
   the JSON report locally under `docs/testing/simlab-reports/` (not
   committed). Start of reliable regression history once noise is cleared.
2. **simlab → pytest integration gate** — once `full` is reproducibly
   green, build a pytest wrapper that runs a minimal simlab scenario
   (single probe) in CI. Gate for future emitter changes.
3. **VRRP/BGP/RADIUS probe injection** — builders exist in `packets.py`
   but no controller-side query generates them automatically from the
   ruleset. Essential for HA validation (keepalived + bird).
4. **Flowtable offload probe** — `FLOWTABLE_FLAGS=offload` is live in
   1.1 but not simlab-validated. Needs either offload-capable mock NIC
   or software-fastpath check via conntrack counters.
5. **Full HA-pair simulation** — build a second NS_FW (simlab-peer) with
   VRRP + conntrackd sync, then run failover scenarios. Needs
   multi-FW-NS concept (currently one only).
6. **Worker ring-buffer pcaps** — `_write_fail_pcaps` currently writes
   the injected frame only. Next iteration: include the worker's
   captured-frame ring buffer (`trace_dump`) so you can see what the
   FW actually forwarded/dropped.
7. **routefilter / rp_filter in topology** — `topology.py` currently
   forces `rp_filter=0` globally. Should replay per-iface values from
   the parsed `interfaces` file instead (coordinate with core TODO).
8. **Flame graph** — `py-spy record --format flamegraph` during `full`
   scan, covering every interface carrying probe traffic. Save artifact
   locally alongside the run's JSON report (not committed to git).

## Debug lessons (do not re-learn these)

- **TUN/TAP devices** — create with a temp name in the host NS, rename
  **inside** the target namespace. Never let the canonical bond0.X name
  appear in the host NS, even briefly (collision risk).
- **`pyroute2.NetNS` forks a helper process** at first use. Any file
  descriptors the helper needs must be open in the parent **before** the
  first `ns()` call. See `topology.refresh_handles()`.
- **`netns.create(name)` leaves a bind mount at `/run/netns/<name>`**
  that survives a controller SIGKILL. Use `nsstub.spawn_nsstub()`
  instead — cleans up via `PR_SET_PDEATHSIG`.
- **systemd-run units managing named netns** must set
  `PrivateMounts=false` or the bind-mount the stub installs won't be
  visible to `ip netns exec` outside the unit.
- **Triangle verifier** skips "pure ct state" rules — rely on simlab
  for packet-level validation of stateful paths.
- **Test reports** must split false-drop vs false-accept and explain
  random-probe mismatches with the oracle reason. Don't lump them.
