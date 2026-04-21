"""Shared pytest fixtures for shorewalld tests.

The ``live_dbus`` fixture provides helpers for the ``integration_dbus`` tests
that require a real system D-Bus and a running keepalived process.  All
integration_dbus tests are skipped automatically unless:

  - pytest is invoked with ``-m integration_dbus``, AND
  - the system bus socket at ``/run/dbus/system_bus_socket`` is reachable, AND
  - ``org.keepalived.Vrrp1`` is registered on that bus.

The fixture does NOT start keepalived; the CI job (or operator) is responsible
for that.  The fixture only verifies preconditions and surfaces a clean skip
message when they are not met.
"""
from __future__ import annotations

import os
import socket
import pytest


# ---------------------------------------------------------------------------
# live_dbus fixture
# ---------------------------------------------------------------------------

_SYSTEM_BUS_SOCKET = "/run/dbus/system_bus_socket"
_KA_BUS_NAME = "org.keepalived.Vrrp1"


def _bus_socket_reachable(path: str) -> bool:
    """Return True if the Unix socket at *path* is reachable."""
    if not os.path.exists(path):
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(1.0)
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()


def _keepalived_registered() -> bool:
    """Return True if org.keepalived.Vrrp1 is visible on the system bus."""
    try:
        from jeepney import DBusAddress, new_method_call
        from jeepney.io.blocking import open_dbus_connection
    except ImportError:
        return False

    try:
        conn = open_dbus_connection(
            bus="unix:path=" + _SYSTEM_BUS_SOCKET, enable_fds=False
        )
    except Exception:
        return False

    try:
        msg = new_method_call(
            DBusAddress(
                "/org/freedesktop/DBus",
                bus_name="org.freedesktop.DBus",
                interface="org.freedesktop.DBus",
            ),
            "ListNames",
        )
        reply = conn.send_and_get_reply(msg, timeout=2.0)
        names = list(reply.body[0]) if reply.body and reply.body[0] else []
        return _KA_BUS_NAME in names
    except Exception:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


@pytest.fixture(scope="session")
def live_dbus():
    """Session-scoped fixture that verifies a live D-Bus + keepalived are up.

    Skips the test if:
    - jeepney is not installed
    - the system bus socket is absent / not connectable
    - org.keepalived.Vrrp1 is not registered (keepalived not running / no --dbus)

    Returns the system bus socket path so tests can construct a real
    VrrpCollector without patching.
    """
    try:
        import jeepney  # noqa: F401
    except ImportError:
        pytest.skip("jeepney not installed — live D-Bus test skipped")

    if not _bus_socket_reachable(_SYSTEM_BUS_SOCKET):
        pytest.skip(
            f"system bus socket {_SYSTEM_BUS_SOCKET!r} not reachable"
            " — start dbus-daemon or run in a D-Bus session"
        )

    if not _keepalived_registered():
        pytest.skip(
            f"{_KA_BUS_NAME} not registered on the system bus"
            " — start keepalived with --dbus first"
        )

    return _SYSTEM_BUS_SOCKET
