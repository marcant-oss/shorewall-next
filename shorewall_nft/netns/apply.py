"""Apply nft scripts, optionally inside a network namespace.

Uses NftInterface for native integration when available,
falls back to subprocess.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from shorewall_nft.nft.netlink import NftError, NftInterface


def apply_nft(script: str, *, netns: str | None = None,
              check_only: bool = False) -> None:
    """Write script to a temp file and load it with nft -f.

    If netns is given, run inside that network namespace.
    If check_only is True, validate without applying.
    """
    nft = NftInterface()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False) as f:
        f.write(script)
        script_path = Path(f.name)

    try:
        nft.load_file(script_path, check_only=check_only, netns=netns)
    except NftError as e:
        raise RuntimeError(str(e)) from e
    finally:
        script_path.unlink(missing_ok=True)
