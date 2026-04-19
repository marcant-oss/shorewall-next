"""Set the kernel comm name (``/proc/PID/comm``) via prctl(PR_SET_NAME).

One helper, shared by the main daemon (``cli.main``) and the forked nft
worker (``nft_worker._set_proc_name``). Linux-specific; the kernel caps
the name at 15 bytes + NUL, so callers should pass an already-short
label. Fails silently — cosmetic only, never worth aborting startup for.
"""
from __future__ import annotations

import ctypes
import ctypes.util

from .logsetup import get_logger

_PR_SET_NAME = 15

log = get_logger("proctitle")


def set_proc_name(name: str) -> None:
    """Set ``/proc/self/comm`` to ``name`` (truncated to 15 bytes)."""
    name_bytes = name[:15].encode() + b"\x00"
    try:
        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        libc = ctypes.CDLL(libc_name, use_errno=True)
        libc.prctl(_PR_SET_NAME, name_bytes, 0, 0, 0)
    except OSError:
        log.debug("prctl PR_SET_NAME failed — continuing")
