---
title: Flowtable / flow offload
description: Software and hardware flow offloading via nft flowtables.
---

# Flowtable / flow offload

shorewall-nft can declare an nft flowtable so that established TCP/UDP
flows bypass the full netfilter chain walk on subsequent packets. This
reduces CPU overhead for high-throughput traffic (bulk file transfer,
streaming, etc.) and is the primary path to 10G+ line rate without
rewriting the firewall dataplane.

## How it works

1. The first packet of each TCP/UDP flow traverses the full forward chain
   and is accepted by policy as normal.
2. A `flow add @ft` rule at the top of the forward chain registers the
   five-tuple in the flowtable's hash after the flow is established in
   conntrack.
3. Subsequent packets for that flow hit the flowtable ingress hook
   (priority `filter`, before the forward chain) and are forwarded
   directly — conntrack lookup, NAT fixup, and rule evaluation are all
   skipped.

Without HW offload this is a **software flowtable** — still a
significant win (avoids chain walk + conntrack re-evaluation). With HW
offload the NIC forwards packets in hardware and the kernel sees none of
the packet processing at all.

## Configuration

All settings go in `shorewall.conf`.

| Setting | Values | Default | Description |
|---|---|---|---|
| `FLOWTABLE` | `iface[,iface…]` or `auto` or empty | (disabled) | Device list. `auto` picks every interface declared in the zones/interfaces files. |
| `FLOWTABLE_FLAGS` | `offload` or empty | (none) | Extra flowtable flags. Set to `offload` to request HW offload. |
| `FLOWTABLE_OFFLOAD` | `Yes`/`No` | `No` | Legacy alias for `FLOWTABLE_FLAGS=offload`. |
| `FLOWTABLE_PRIORITY` | keyword or integer | `filter` (0) | Ingress hook priority. Valid keywords: `raw` (−300), `mangle` (−150), `dstnat` (−100), `filter` (0), `security` (50), `srcnat` (100). |
| `FLOWTABLE_COUNTER` | `Yes`/`No` | `No` | Attach a byte/packet counter to the flowtable. |

### Minimal example (SW flowtable)

```
# shorewall.conf
FLOWTABLE=bond0,bond0.20
```

Emits:

```nft
flowtable ft {
    hook ingress priority 0;
    devices = { "bond0", "bond0.20" };
}
```

### Hardware offload example

```
# shorewall.conf
FLOWTABLE=bond0,bond0.20
FLOWTABLE_FLAGS=offload
```

Emits:

```nft
# HW offload active — enable on each device: ethtool -K <dev> hw-tc-offload on
# Kernel silently falls back to SW flowtable if the driver does not support it.
flowtable ft {
    hook ingress priority 0;
    devices = { "bond0", "bond0.20" };
    flags offload;
}
```

## Hardware offload requirements

`flags offload` instructs the kernel to push established flows into the
NIC's hardware forwarding table. This requires:

1. **Kernel module** `nft_flow_offload` loaded (or built-in). Verified
   by the capability probe at compile time; the flag is dropped with a
   warning if absent.
2. **NIC driver support** — mlx5 (Mellanox/NVIDIA ConnectX), ixgbe
   (Intel 10G), and a handful of others. Check with:
   ```
   ethtool -k <iface> | grep hw-tc-offload
   ```
3. **Enable the NIC feature:**
   ```
   ethtool -K <iface> hw-tc-offload on
   ```
   Do this for **every device** listed in `FLOWTABLE=`. If the feature
   is not enabled the kernel silently runs a SW flowtable for that
   device — no error, no dropped connections.
4. **Firmware** — some mlx5 firmware requires TC offload to be enabled
   in the device profile (`mlxconfig SET_HW_FLOW_TABLE_MODE=1` or
   similar). Consult the vendor documentation.

> **Note:** shorewall-nft's capability probe checks that the kernel
> *accepts* `flags offload` syntax but cannot verify NIC-level support —
> that can only fail at ruleset-load time if the driver rejects the
> hook registration. The emitted script includes a hint comment listing
> the devices that need `hw-tc-offload on`.

## Capability gating

When shorewall-nft is invoked with an active capability probe
(i.e. when a live kernel is available), it probes flowtable support
before emitting:

- `has_flowtable` — basic flowtable syntax accepted.
- `has_flowtable_offload` — `flags offload` accepted by kernel/nft.

If `FLOWTABLE_FLAGS=offload` is set but the probe finds
`has_flowtable_offload = False`, the flag is dropped and a warning is
written into the emitted script:

```nft
# NOTE: FLOWTABLE_FLAGS=offload dropped — kernel probe reports no flow-offload support.
```

The flowtable itself is still emitted as a software fastpath.

## Interaction with other features

- **`OPTIMIZE_VMAP=Yes`** — compatible. The vmap dispatch and the
  `flow add @ft` rule both live in the forward base chain; the flowtable
  fastpath fires at the ingress hook before the forward chain, so there
  is no ordering conflict.
- **`CT_ZONE_TAG=Yes`** — compatible. CT zone tagging happens in
  prerouting; by the time a flow is registered in the flowtable it
  already carries the correct zone mark.
- **`FASTACCEPT=No`** — compatible. The `flow add @ft` rule only
  registers flows that are already in `ct state established` — new
  connections still traverse the full zone-pair chain before being
  registered.

## Kernel module

`nft_flow_offload` must be available. It is listed under **Soft** kernel
modules in `docs/reference/kernel.md`. On Debian/Ubuntu it is typically
included in `linux-modules-extra-$(uname -r)`. On Fedora it is part of
the main `kernel` package. Load with:

```
modprobe nft_flow_offload
```

or add to `/etc/modules-load.d/shorewall-nft.conf`.
