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

## IPC paths

Three paths exist for transferring data between parent and child:

### 1. Inline pickle pipe (≤ threshold, default 4 MiB)

The pickled payload travels through a regular `os.pipe()` pair. A
`select`-drain loop in the parent prevents pipe-buffer deadlock even for
multi-MB payloads.

### 2. Zero-copy large-payload transfer (out-of-band memfd)

When args or result pickle exceeds `large_payload_threshold` (default 4 MiB),
the oversized blob is written into an anonymous in-memory file:

```
memfd_create("nf_args", MFD_CLOEXEC | MFD_ALLOW_SEALING)
```

The child inherits the fd across `fork()` (same fd table → same kernel pages)
and `mmap()`s them read-only. **No copy occurs** — both parent and child share
the same physical RAM pages.

After writing, the parent applies write+resize seals:

```
fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW)
```

This makes the child's view immutable — no integrity digest is needed.
When the last fd-holder closes, the kernel reclaims the RAM automatically:
no `/tmp` touch, no `unlink()` call, no cleanup race.

**Why memfd beats /tmp tempfiles**

| Property | memfd | /tmp tempfile |
|----------|-------|--------------|
| Filesystem touch | None | Yes |
| Cleanup on crash | Automatic (last fd close) | Leaked until reboot |
| Digest check needed | No (sealed) | Yes (sha256) |
| Cross-netns safe | Yes (kernel memory) | Yes (bind mount) |
| Zero-copy | Yes (shared pages) | No (read syscall copies) |

**Availability**: requires Linux ≥ 3.17 and Python ≥ 3.8. Check the
module-level `MEMFD_SUPPORTED` bool at runtime. On older kernels, a
`RuntimeError` is raised when the payload exceeds the threshold.

### 3. `run_nft_in_netns_zc` — specialised nft-script path

For nft compile+apply operations, use the dedicated helper instead of a
generic `run_in_netns_fork` wrapper:

```python
from shorewall_nft_netkit.netns_fork import run_nft_in_netns_zc, NftResult

result: NftResult = run_nft_in_netns_zc("fw", nft_script_text)
# result.rc == 0, result.stdout == JSON, result.stderr == ""
```

IPC layout for `run_nft_in_netns_zc`:

| Channel | Content | Direction | When |
|---------|---------|-----------|------|
| `memfd` (sealed) | nft script bytes | parent → child | always |
| stdout pipe | JSON output (inline) | child → parent | `len(stdout) < stdout_threshold` |
| stdout output | JSON output via memfd-dup | child → parent | `len(stdout) >= stdout_threshold` (default 4 MiB) |
| stderr pipe | error text | child → parent | always |
| rc pipe | control message (see below) | child → parent | always |
| ack pipe | 1-byte parent ack | parent → child | memfd path only |

**stdout output modes**

When `len(stdout_bytes) < stdout_threshold` (default 4 MiB), the child
writes stdout to the **stdout pipe** as before. The rc pipe carries:
```
[tag=0x10 u8][rc int32 BE]   (5 bytes)
```

When `len(stdout_bytes) >= stdout_threshold`, the child routes stdout
through an **anonymous memfd**. The rc pipe carries:
```
[tag=0x11 u8][rc int32 BE][size uint32 BE][fd_number uint32 BE]   (13 bytes)
```

The child then **blocks** on the ack pipe until the parent writes a single
ack byte. This keeps the child's fd table (and therefore
`/proc/<child_pid>/fd/<fd_number>`) alive long enough for the parent to
acquire its own file descriptor via the `/proc/<pid>/fd/<n>` dup idiom:

```
parent: open("/proc/<child_pid>/fd/<fd_number>", O_RDONLY)
parent: mmap(size, ACCESS_READ) → read stdout bytes
parent: write(ack_w, b"\x01")   ← releases the child
child:  read ack → close memfd → os._exit(0)
```

**Why `/proc/<pid>/fd/<n>` instead of `SCM_RIGHTS`**

`/proc/<pid>/fd/<n>` is the simplest "cross-process fd dup" on Linux.  It
requires no extra `SOCK_DGRAM` socketpair (as `SCM_RIGHTS` would), produces
no portability concerns (we are Linux-only throughout), and is well-supported
in containers that allow `/proc`. The ack-pipe round-trip serialises the
parent's `open()` call against the child's exit — a simpler ordering
guarantee than the three-way handshake SCM_RIGHTS would need.

**`stdout_as_memoryview` option**

Pass `stdout_as_memoryview=True` to receive a `memoryview` into the parent's
mmap without an extra `bytes` allocation:

```python
with run_nft_in_netns_zc("fw", "list table inet fw",
                          stdout_threshold=0,
                          stdout_as_memoryview=True) as result:
    # result.stdout_mv is a memoryview into the mmap
    data = json.loads(result.stdout_mv)
# on exit, mmap is released
```

`NftResult` is a context manager; call `result.close()` or use `with` to
release the mmap. After `close()`, any `memoryview` derived from the mmap
becomes invalid. Callers must release (`.release()`) the `memoryview` before
calling `close()` — `mmap.close()` raises `BufferError` if an exported
pointer still exists.

The script memfd is sealed before fork — the child receives an immutable
read-only view. The stderr pipe is always drained by a dedicated thread in
the parent; the stdout pipe is drained by a thread for the inline-pipe path
(thread exits immediately with empty bytes in the memfd path).

## Contract

### `run_in_netns_fork(netns, fn, *args, timeout=30.0, **kwargs)`

One-shot. Fork, setns, run `fn(*args, **kwargs)`, return result.

- `fn` must be pickleable (regular function, not a lambda or local closure).
  Check is performed in the parent before fork — a `TypeError` is raised if
  `fn` cannot be pickled.
- `PR_SET_PDEATHSIG = SIGTERM` is set in the child so that parent death
  triggers cleanup (not `SIGKILL` — see *Signal choice* below).
- Parent always reaps the child. No zombies on any code path.
- On timeout: SIGTERM → 1 s grace → SIGKILL → reap → `NetnsForkTimeout`.
- Large args (> `large_payload_threshold`) go through the memfd path.

### `run_nft_in_netns_zc(netns, script, *, check_only=False, timeout=60.0, stdout_threshold=4MiB, stdout_as_memoryview=False)`

Specialised. Fork, setns, run `nft.cmd(script)` via libnftables, return
`NftResult(rc, stdout, stderr)`. Script transferred via sealed memfd.
stdout transferred via inline pipe (small) or child-created memfd acquired by
parent via `/proc/<pid>/fd/<n>` dup (large, `>= stdout_threshold`).

Raises `NftError` (rc != 0) unless `check_only=True`.

`NftResult` supports `close()` and context-manager usage to release any
stdout mmap. `stdout_mv` is a `memoryview` into the mmap when
`stdout_as_memoryview=True` and the memfd path was taken.

### `PersistentNetnsWorker(netns, child_main)`

Long-lived child. Parent communicates over a `SOCK_STREAM` socketpair.
The `child_main(ctx: ChildContext)` callable loops reading requests
(`ctx.recv()`) and sending replies (`ctx.send(data)`) until it sees EOF
(parent closed the socket) or until `worker.stop()` is called.

Wire protocol: `[uint32 BE length][payload bytes]` per message over
`SOCK_STREAM`. `SOCK_STREAM` has no per-message size cap; the exact-read
loop in `_recv_exact` handles arbitrarily large payloads. A 64 MB round-trip
is tested and confirmed working.

`PersistentNetnsWorker` does **not** implement auto-respawn. Callers that
need it should build their own restart policy on top (see
`shorewalld.worker_router.ParentWorker` for a full auto-respawn + backoff
example).

## How to use

```python
from shorewall_nft_netkit.netns_fork import run_in_netns_fork, run_nft_in_netns_zc

# Generic callable: any function that returns a pickleable value.
def load_ruleset(script: str) -> None:
    from nftables import Nftables
    nft = Nftables()
    nft.cmd(script)

run_in_netns_fork("fw", load_ruleset, nft_script_text)

# Specialised nft path (preferred for nft scripts — zero-copy memfd transfer):
result = run_nft_in_netns_zc("fw", nft_script_text)
if result.rc != 0:
    raise RuntimeError(f"nft failed: {result.stderr}")
```

To replace `subprocess.run(["ip", "netns", "exec", NS, "nft", "-f", "-"],
input=script)` with the specialised zero-copy path:

```python
from shorewall_nft_netkit.netns_fork import run_nft_in_netns_zc, NftError

try:
    result = run_nft_in_netns_zc(netns_name, script_text)
except NftError as e:
    raise RuntimeError(f"nft failed (rc={e.rc}): {e.stderr}")
```

## How NOT to use

- **Do not call from inside an asyncio event loop.** Both primitives are
  synchronous (`os.fork`, blocking `select`). Async callers must wrap with
  `loop.run_in_executor(None, run_in_netns_fork, netns, fn, ...)`.
- **Do not pass lambdas or local closures as `fn`.** They are not pickleable.
  Define the function at module scope.
- **Do not call `setns()` on the parent process directly** before calling
  libnftables — the cached socket will not rebind.
- **Do not use `/tmp` tempfiles for large IPC.** memfd is strictly better on
  Linux 3.17+: no filesystem quota, no cleanup race, no digest check,
  zero-copy.

## Signal choice: SIGTERM not SIGKILL

`PR_SET_PDEATHSIG` is set to `SIGTERM` (15), not `SIGKILL` (9). `SIGKILL`
skips user-space cleanup handlers and has historically caused orphaned
bind-mount entries in `/run/netns/` when the stub process was killed before
it could `umount()` and `unlink()` its path. `SIGTERM` gives the child's
registered handler a chance to run cleanup before exit.

## Kernel-version fallback

`MEMFD_SUPPORTED` (module-level bool) is `True` when `os.memfd_create` is
available. On kernels < 3.17 or Python < 3.8:

- `_memfd_write` / `_memfd_read` raise `RuntimeError` immediately with a
  message that explains the requirement and suggests keeping payloads under
  the threshold.
- `run_nft_in_netns_zc` raises `RuntimeError` before forking.
- `run_in_netns_fork` raises `RuntimeError` when the payload exceeds
  `large_payload_threshold`. Callers on such kernels must keep payloads
  under the threshold (use the persistent worker for larger data).

## Comparison with `["ip", "netns", "exec", …]`

| | `ip netns exec` | `run_in_netns_fork` | `run_nft_in_netns_zc` |
|---|---|---|---|
| Fork+exec cost | Per call | Per call (fork only) | Per call (fork only) |
| Requires `ip` binary | Yes | No | No |
| In-process libnftables | Not possible | Yes | Yes |
| Large script zero-copy | No | No | Yes (sealed memfd) |
| Large JSON output zero-copy | No | No | Yes (child memfd + `/proc` dup) |
| JSON output | No | Manual | Automatic |
| Auto-reap | No | Yes | Yes |
| Timeout | No | Yes | Yes |
| memoryview output (no extra alloc) | No | No | Yes (`stdout_as_memoryview=True`) |

For one-off nft script execution, `run_nft_in_netns_zc` is the preferred
approach. For arbitrary Python callables inside a netns, use
`run_in_netns_fork`. For hot-path dispatch (many calls per second), use
`PersistentNetnsWorker`.
