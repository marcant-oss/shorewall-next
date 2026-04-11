"""Shared unix-socket ownership / mode helper for DnstapServer + PbdnsServer.

Operators often want their DNS producer (pdns-recursor, unbound, a
sidecar) to run as a non-root user and still be able to connect to a
shorewalld-owned unix socket. The cleanest way is to give the socket
the right owner/group/mode at bind time.

``apply_socket_perms`` centralises the chmod/chown dance and the
user/group name resolution so both servers behave identically. It
swallows errors (with a warning log) rather than aborting the
server startup — a missing group name or missing ``chown``
permission should not take the whole daemon down. The operator
can still run the box as root if they need exact ownership.
"""

from __future__ import annotations

import grp
import logging
import os
import pwd
from pathlib import Path

log = logging.getLogger("shorewalld.core")


def resolve_user(owner: str | int | None) -> int | None:
    """Resolve a user name or numeric uid to an int, or ``None``."""
    if owner is None:
        return None
    if isinstance(owner, int):
        return owner
    s = str(owner).strip()
    if not s:
        return None
    if s.isdigit():
        return int(s)
    try:
        return pwd.getpwnam(s).pw_uid
    except KeyError:
        log.warning("socket owner %r: unknown user, skipping chown", owner)
        return None


def resolve_group(group: str | int | None) -> int | None:
    """Resolve a group name or numeric gid to an int, or ``None``."""
    if group is None:
        return None
    if isinstance(group, int):
        return group
    s = str(group).strip()
    if not s:
        return None
    if s.isdigit():
        return int(s)
    try:
        return grp.getgrnam(s).gr_gid
    except KeyError:
        log.warning("socket group %r: unknown group, skipping chgrp", group)
        return None


def apply_socket_perms(
    path: str | Path,
    *,
    mode: int | None,
    owner: str | int | None,
    group: str | int | None,
) -> None:
    """chmod + chown a unix socket at ``path``.

    Each argument is optional — ``None`` means "leave this axis
    alone". Errors are logged but not raised; typical failures are
    missing users / missing ``CAP_CHOWN`` when running unprivileged.
    The server stays up and keeps serving on a more-permissive
    socket, because breaking the daemon would be worse.
    """
    p = str(path)
    if mode is not None:
        try:
            os.chmod(p, mode)
        except OSError as e:
            log.warning("chmod %s to 0o%o failed: %s", p, mode, e)
    uid = resolve_user(owner)
    gid = resolve_group(group)
    if uid is not None or gid is not None:
        try:
            os.chown(p, uid if uid is not None else -1,
                     gid if gid is not None else -1)
        except OSError as e:
            log.warning(
                "chown %s to %s:%s failed: %s",
                p,
                uid if uid is not None else "-",
                gid if gid is not None else "-",
                e,
            )
