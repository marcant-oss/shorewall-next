"""Monitor and trace support for shorewall-nft.

Wraps nft monitor trace for live packet debugging.
"""

from __future__ import annotations

import subprocess
import sys


def trace_start(netns: str | None = None) -> None:
    """Start nft trace monitoring.

    Runs `nft monitor trace` and streams output to stdout.
    """
    cmd: list[str] = []
    if netns:
        cmd = ["sudo", "/usr/local/bin/run-netns", "exec", netns, "nft", "monitor", "trace"]
    else:
        cmd = ["nft", "monitor", "trace"]

    try:
        proc = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    except FileNotFoundError:
        print("ERROR: nft binary not found.", file=sys.stderr)
        sys.exit(1)
