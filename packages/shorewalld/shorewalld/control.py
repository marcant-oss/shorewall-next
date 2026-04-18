"""Unix-socket control server for shorewalld.

Line-oriented JSON protocol: the client sends one JSON object per line,
the server responds with one JSON object per line.

Built-in commands:

* ``{"cmd": "ping"}``
  → ``{"ok": true, "version": "1"}``

* ``{"cmd": "refresh-iplist"}``        (optional ``"name"`` key)
  → ``{"ok": true}``

* ``{"cmd": "iplist-status"}``
  → ``{"ok": true, "lists": [...]}``

* ``{"cmd": "reload-instance"}``       (optional ``"name"`` key)
  → ``{"ok": true}``

* ``{"cmd": "instance-status"}``
  → ``{"ok": true, "instances": [...]}``

* ``{"cmd": "register-instance", "config_dir": "/etc/shorewall",
  "netns": "", "name": "...", "allowlist_path": "..."}``
  (``name`` and ``allowlist_path`` optional — derived from ``config_dir``
  and ``netns`` when absent)
  → ``{"ok": true, "name": "shorewall", "qnames": 5}``

* ``{"cmd": "deregister-instance", "name": "shorewall"}``
  (``"config_dir"`` + ``"netns"`` accepted as alternatives to ``name``)
  → ``{"ok": true, "name": "shorewall"}``

Additional commands are registered by subsystems via
:meth:`ControlServer.register_handler`.

If the socket_path lives inside a netns, pass the netns name via
*netns*.  The server will call ``setns()`` before binding the socket.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

log = logging.getLogger("shorewalld.control")

_VERSION = "1"
_MAX_LINE = 65536  # bytes; guard against runaway clients


class ControlServer:
    """Asyncio Unix-socket server for operator control commands."""

    def __init__(
        self,
        socket_path: str,
        netns: str | None = None,
        socket_mode: int | None = None,
    ) -> None:
        self._socket_path = socket_path
        self._netns = netns
        self._socket_mode = socket_mode
        self._handlers: dict[str, Callable[[dict], Awaitable[dict]]] = {}
        self._server: asyncio.Server | None = None

        # Register built-in commands.
        self.register_handler("ping", self._handle_ping)

    # ── Registration ──────────────────────────────────────────────────

    def register_handler(
        self,
        command: str,
        handler: Callable[[dict], Awaitable[dict]],
    ) -> None:
        """Register a handler for *command*.

        The handler receives the full parsed request dict and must
        return a dict.  Returning ``{"ok": true, ...}`` is the
        convention for success; ``{"ok": false, "error": "..."}`` for
        failure.  Any uncaught exception from the handler results in an
        error response.
        """
        self._handlers[command] = handler

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self) -> None:
        """Bind the Unix socket and start accepting connections."""
        path = Path(self._socket_path)

        # If inside a named netns: enter it before binding.
        if self._netns:
            try:
                from shorewall_nft.nft.netlink import _in_netns
                with _in_netns(self._netns):
                    await self._bind(path)
            except ImportError:
                log.warning(
                    "control: cannot enter netns %r — _in_netns unavailable; "
                    "binding in current netns instead",
                    self._netns,
                )
                await self._bind(path)
        else:
            await self._bind(path)

    async def _bind(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Remove stale socket.
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=str(path)
        )
        # Ownership: always root:root (uid/gid 0).
        try:
            os.chown(str(path), 0, 0)
        except OSError as e:
            log.warning("control: chown root:root %s: %s", path, e)

        # Mode: explicit override or default 0660.
        mode = self._socket_mode if self._socket_mode is not None else 0o660
        try:
            os.chmod(str(path), mode)
        except OSError as e:
            log.warning("control: chmod %s: %s", path, e)

        log.info("control: listening on %s", path)

    async def shutdown(self) -> None:
        """Stop accepting connections and close the socket."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        sock = Path(self._socket_path)
        if sock.exists():
            try:
                sock.unlink()
            except OSError:
                pass
        log.info("control: server shut down")

    # ── Connection handler ─────────────────────────────────────────────

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername", "(unknown)")
        log.debug("control: client connected from %s", peer)
        try:
            while True:
                try:
                    line = await asyncio.wait_for(
                        reader.readline(), timeout=30.0
                    )
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                if len(line) > _MAX_LINE:
                    resp = {"ok": False, "error": "request too large"}
                    await _write_json(writer, resp)
                    break

                resp = await self._dispatch(line.rstrip(b"\n"))
                await _write_json(writer, resp)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            log.exception("control: unhandled error in client handler")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            log.debug("control: client %s disconnected", peer)

    async def _dispatch(self, raw: bytes) -> dict:
        """Parse *raw* JSON and route to the appropriate handler."""
        try:
            request: Any = json.loads(raw)
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"invalid JSON: {e}"}

        if not isinstance(request, dict):
            return {"ok": False, "error": "request must be a JSON object"}

        cmd = request.get("cmd")
        if not cmd:
            return {"ok": False, "error": "missing 'cmd' field"}

        handler = self._handlers.get(cmd)
        if handler is None:
            available = sorted(self._handlers)
            return {
                "ok": False,
                "error": f"unknown command {cmd!r}; available: {available}",
            }

        try:
            result = await handler(request)
        except Exception as e:
            log.exception("control: handler for %r raised", cmd)
            return {"ok": False, "error": str(e)}

        return result

    # ── Built-in handlers ──────────────────────────────────────────────

    async def _handle_ping(self, _request: dict) -> dict:
        return {"ok": True, "version": _VERSION}


async def _write_json(writer: asyncio.StreamWriter, obj: dict) -> None:
    """Serialise *obj* to JSON and write a newline-terminated line."""
    data = json.dumps(obj, separators=(",", ":"), default=str)
    writer.write(data.encode() + b"\n")
    await writer.drain()
