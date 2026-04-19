"""Test-only helpers for the nft worker plumbing.

Separated from :mod:`shorewalld.worker_router` so the production module
is smaller and the test-facing surface is explicit. Tests should import
``inproc_worker_pair`` from here; the old import path
(``from shorewalld.worker_router import inproc_worker_pair``) keeps
working via back-compat re-export.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Callable

from .dns_set_tracker import DnsSetTracker
from .nft_worker import worker_main_loop
from .worker_transport import WorkerTransport


def inproc_worker_pair(
    tracker: DnsSetTracker | None,
    loop: asyncio.AbstractEventLoop,
    set_name_lookup: Callable[[tuple[int, int]], str | None],
    apply_cb: Callable[[str], None] | None = None,
):
    """Wire a real SEQPACKET pair between a ParentWorker and a
    background thread running :func:`worker_main_loop`.

    Used by the router tests to exercise the full ack pipeline
    without forking. ``apply_cb`` receives the nft script each
    batch would run — default is a no-op so tests can assert on
    commands without actually touching libnftables.
    """
    # Imported locally to avoid a cycle at module import time — the
    # router imports nothing from this module in production.
    from .worker_router import ParentWorker

    parent_t, worker_t = WorkerTransport.pair()

    class _FakeNft:
        def __init__(self, cb):
            self._cb = cb

        def cmd(self, script):
            if self._cb:
                self._cb(script)

    fake_nft = _FakeNft(apply_cb)

    def run():
        worker_main_loop(worker_t, fake_nft, set_name_lookup)

    t = threading.Thread(
        target=run, name="shwd-nft-inproc", daemon=True)
    t.start()

    pw = ParentWorker(netns="inproc", tracker=tracker, loop=loop)
    pw._transport = parent_t
    pw._child_pid = None
    loop.add_reader(parent_t.fileno, pw._drain_replies)
    pw._timeout_task = loop.create_task(
        pw._ack_timeout_loop(),
        name="shorewalld.nft.ack:inproc")
    pw.metrics.spawned_total = 1
    pw.metrics.alive = 1
    pw.metrics.last_spawn_mono = time.monotonic()
    return pw, worker_t
