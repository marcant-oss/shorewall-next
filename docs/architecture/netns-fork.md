# netns-fork primitive

`shorewall_nft_netkit.netns_fork` — fork+setns+pickle-IPC for netns-aware
operations.

## The problem

`libnftables.Nftables()` caches its netlink socket on first `.cmd()` call.
If the parent process calls `setns(CLONE_NEWNET)` after the socket is open,
the cached socket is **not** rebound — it still talks to the original netns.
The same applies to `pyroute2.IPRoute()` when not opened with `netns='…'`.

The only safe pattern is therefore:

    fork → child enters netns via setns() → child opens netlink objects
    → child does the work → child returns result to parent via IPC → reap

## Contract

### `run_in_netns_fork(netns, fn, *args, timeout=30.0, **kwargs)`

One-shot. Fork, setns, run `fn(*args, **kwargs)`, return result. Uses a
`os.pipe()` pair. Child pickles the return value (or exception) and writes it
to the pipe; parent reads with `select` honouring the timeout.

- `fn` must be pickleable (regular function, not a lambda or local closure).
  Check is performed in the parent before fork — a `TypeError` is raised if
  `fn` cannot be pickled.
- `PR_SET_PDEATHSIG = SIGTERM` is set in the child so that parent death
  triggers cleanup (not `SIGKILL` — see *Signal choice* below).
- Parent always reaps the child. No zombies on any code path.
- On timeout: SIGTERM → 1 s grace → SIGKILL → reap → `NetnsForkTimeout`.

### `PersistentNetnsWorker(netns, child_main)`

Long-lived child. Parent communicates over a `SOCK_SEQPACKET` socketpair.
The `child_main(ctx: ChildContext)` callable loops reading requests
(`ctx.recv()`) and sending replies (`ctx.send(data)`) until it sees EOF
(parent closed the socket) or until `worker.stop()` is called.

Wire protocol: `[uint32 BE length][payload bytes]` per message. Handles
0-byte, small, and >64 KiB payloads.

`PersistentNetnsWorker` does **not** implement auto-respawn. Callers that
need it should build their own restart policy on top (see
`shorewalld.worker_router.ParentWorker` for a full auto-respawn + backoff
example).

## How to use

```python
from shorewall_nft_netkit.netns_fork import run_in_netns_fork

def load_ruleset(script: str) -> None:
    from nftables import Nftables
    nft = Nftables()
    nft.cmd(script)

run_in_netns_fork("fw", load_ruleset, nft_script_text)
```

To replace `subprocess.run(["ip", "netns", "exec", NS, "nft", "-f", "-"],
input=script)` with the new primitive:

```python
def _apply_nft(script: str) -> None:
    from nftables import Nftables
    nft = Nftables()
    rc, out, err = nft.cmd(script)
    if rc != 0:
        raise RuntimeError(f"nft failed: {err}")

run_in_netns_fork(netns_name, _apply_nft, script_text)
```

## How NOT to use

- **Do not call from inside an asyncio event loop.** Both primitives are
  synchronous (`os.fork`, blocking `select`). Async callers must wrap with
  `loop.run_in_executor(None, run_in_netns_fork, netns, fn, ...)`.
- **Do not pass lambdas or local closures as `fn`.** They are not pickleable.
  Define the function at module scope.
- **Do not call `setns()` on the parent process directly** before calling
  libnftables — the cached socket will not rebind.

## Signal choice: SIGTERM not SIGKILL

`PR_SET_PDEATHSIG` is set to `SIGTERM` (15), not `SIGKILL` (9). `SIGKILL`
skips user-space cleanup handlers and has historically caused orphaned
bind-mount entries in `/run/netns/` when the stub process was killed before
it could `umount()` and `unlink()` its path. `SIGTERM` gives the child's
registered handler a chance to run cleanup before exit.

## Comparison with `["ip", "netns", "exec", …]`

| | `ip netns exec` | `run_in_netns_fork` |
|---|---|---|
| Fork+exec cost | Per call | Per call (fork only) |
| Requires `ip` binary | Yes | No |
| In-process libnftables | Not possible | Yes |
| Pickle IPC | No | Yes |
| Auto-reap | No | Yes |
| Timeout | No | Yes (select-based) |

For one-off operations the difference is small. For loading nft rulesets
in-process (avoiding a second `nft` binary invocation and the associated JSON
or text-parse overhead), `run_in_netns_fork` is the preferred approach.
