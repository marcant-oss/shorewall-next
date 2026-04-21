"""Monitor and trace support for shorewall-nft.

Wraps nft monitor trace for live packet debugging.
"""

from __future__ import annotations

import subprocess
import sys

from shorewall_nft.nft.netlink import _in_netns


def trace_start(netns: str | None = None) -> None:
    """Start nft trace monitoring.

    Runs ``nft monitor trace`` and streams output to stdout.

    When ``netns`` is given, the main process temporarily enters the target
    network namespace via ``_in_netns()`` before spawning the ``nft`` child.
    The child inherits the netns file-descriptor and keeps running in it after
    the context manager restores the parent's original namespace.  This avoids
    a ``ip netns exec`` subprocess prefix.
    """
    try:
        with _in_netns(netns):
            proc = subprocess.Popen(  # noqa: S603
                ["nft", "monitor", "trace"],
                stdout=sys.stdout,
                stderr=sys.stderr,
            )
        # Context manager has already restored the parent netns; the child
        # continues running in the target netns independently.
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    except OSError as exc:
        if "not found" in str(exc).lower() or exc.errno == 2:
            print("ERROR: nft binary not found.", file=sys.stderr)
            sys.exit(1)
        raise
