"""Tests for the shared unix-socket chmod/chown helper."""

from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

from shorewalld.sockperms import (
    apply_socket_perms,
    resolve_group,
    resolve_user,
)


def _make_socket(tmp_path: Path) -> Path:
    path = tmp_path / "test.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(path))
    s.listen(1)
    s.close()  # keep the file, drop the server
    return path


def test_resolve_user_none():
    assert resolve_user(None) is None
    assert resolve_user("") is None


def test_resolve_user_numeric_string():
    assert resolve_user("1000") == 1000


def test_resolve_user_numeric_int():
    assert resolve_user(42) == 42


def test_resolve_user_nobody_if_present():
    # nobody almost always exists; if it doesn't, skip.
    import pwd
    try:
        uid = pwd.getpwnam("nobody").pw_uid
    except KeyError:
        pytest.skip("no 'nobody' user on this host")
    assert resolve_user("nobody") == uid


def test_resolve_user_unknown_returns_none():
    assert resolve_user("does_not_exist_xyzzy") is None


def test_resolve_group_none():
    assert resolve_group(None) is None
    assert resolve_group("") is None


def test_resolve_group_numeric():
    assert resolve_group("12345") == 12345


def test_apply_mode_only(tmp_path: Path):
    path = _make_socket(tmp_path)
    apply_socket_perms(path, mode=0o600, owner=None, group=None)
    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o600


def test_apply_mode_and_gid_numeric(tmp_path: Path):
    """Chown to our own gid should always succeed."""
    path = _make_socket(tmp_path)
    my_gid = os.getgid()
    apply_socket_perms(path, mode=0o644, owner=None, group=my_gid)
    st = os.stat(path)
    assert st.st_mode & 0o777 == 0o644
    assert st.st_gid == my_gid


def test_apply_unknown_owner_is_graceful(tmp_path: Path):
    """Missing user name must not raise — the helper swallows and warns."""
    path = _make_socket(tmp_path)
    apply_socket_perms(
        path, mode=0o600, owner="nope_nonexistent", group=None)
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_apply_chown_no_perm_is_graceful(tmp_path: Path):
    """When chown fails (non-root → can't set uid=0), we log and move on."""
    if os.geteuid() == 0:
        pytest.skip("running as root — cannot test chown EPERM")
    path = _make_socket(tmp_path)
    apply_socket_perms(path, mode=0o600, owner=0, group=None)
    # mode still applied, test just asserts we didn't raise.
    assert (os.stat(path).st_mode & 0o777) == 0o600
