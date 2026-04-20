"""Safety plumbing for DoS scenarios — rate cap, preflight warning."""

from __future__ import annotations

import os
import signal
import time

DOS_DEFAULT_RATE_CAP_PPS = 10_000_000


def rate_cap_pps() -> int:
    """Current DoS rate-cap in pps. Env override: STAGELAB_DOS_RATE_CAP_PPS."""
    v = os.environ.get("STAGELAB_DOS_RATE_CAP_PPS")
    if v is None:
        return DOS_DEFAULT_RATE_CAP_PPS
    try:
        return int(v)
    except ValueError:
        return DOS_DEFAULT_RATE_CAP_PPS


def preflight_warning(summaries: list[str], countdown_s: int = 3) -> None:
    """Print a DOS-WARNING block to stderr for the given scenario summaries,
    then sleep countdown_s seconds. SIGINT aborts early with exit code 130.

    Each element of ``summaries`` is a human-readable one-line description
    of a DoS scenario, e.g.:
        "dos_syn_flood target=10.0.13.200 rate=500000pps duration=10s"
    """
    import sys

    sys.stderr.write(
        "\n[DOS-WARNING] the following DoS-class scenarios are about to run:\n"
    )
    for s in summaries:
        sys.stderr.write(f"  \u2022 {s}\n")
    sys.stderr.write(f"\nAbort within {countdown_s} s with Ctrl-C.\n")
    sys.stderr.flush()

    aborted = False

    def _handler(signum: int, frame: object) -> None:
        nonlocal aborted
        aborted = True

    old = signal.signal(signal.SIGINT, _handler)
    try:
        for _ in range(countdown_s):
            if aborted:
                break
            time.sleep(1)
    finally:
        signal.signal(signal.SIGINT, old)
    if aborted:
        sys.stderr.write("aborted.\n")
        sys.exit(130)
