"""Async JSON-Lines transport between controller and remote agent.

Every message is a JSON object on one line (UTF-8, newline-terminated).
Required fields on every message: ``type``, ``id``, ``version``.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from typing import Any

__all__ = [
    # Exceptions
    "ConnectionClosedError",
    # Base
    "Message",
    # Request messages
    "PingMessage",
    "SetupEndpointMessage",
    "TeardownEndpointMessage",
    "RunScenarioMessage",
    "PollMetricsMessage",
    "ShutdownMessage",
    # Response messages
    "AckMessage",
    "ErrorMessage",
    # Transport
    "JsonLineChannel",
    # Helpers
    "decode",
    "new_id",
]

_PROTOCOL_VERSION = "1"


# ── Exceptions ────────────────────────────────────────────────────────────────


class ConnectionClosedError(Exception):
    """Raised when the remote end closes the connection cleanly (EOF)."""


# ── Base class ────────────────────────────────────────────────────────────────


class Message:
    """Abstract base for all IPC messages."""

    type: str  # discriminator — set by each subclass

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Message":
        raise NotImplementedError


# ── Request messages ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PingMessage(Message):
    id: str
    version: str = _PROTOCOL_VERSION
    type: str = "PING"

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "id": self.id, "version": self.version}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PingMessage":
        return cls(id=data["id"], version=data.get("version", _PROTOCOL_VERSION))


@dataclass(frozen=True)
class SetupEndpointMessage(Message):
    id: str
    endpoint_spec: dict  # type: ignore[type-arg]
    version: str = _PROTOCOL_VERSION
    type: str = "SETUP_ENDPOINT"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "version": self.version,
            "endpoint_spec": self.endpoint_spec,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SetupEndpointMessage":
        return cls(
            id=data["id"],
            version=data.get("version", _PROTOCOL_VERSION),
            endpoint_spec=data["endpoint_spec"],
        )


@dataclass(frozen=True)
class TeardownEndpointMessage(Message):
    id: str
    endpoint_name: str
    version: str = _PROTOCOL_VERSION
    type: str = "TEARDOWN_ENDPOINT"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "version": self.version,
            "endpoint_name": self.endpoint_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TeardownEndpointMessage":
        return cls(
            id=data["id"],
            version=data.get("version", _PROTOCOL_VERSION),
            endpoint_name=data["endpoint_name"],
        )


@dataclass(frozen=True)
class RunScenarioMessage(Message):
    id: str
    scenario_spec: dict  # type: ignore[type-arg]
    version: str = _PROTOCOL_VERSION
    type: str = "RUN_SCENARIO"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "version": self.version,
            "scenario_spec": self.scenario_spec,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunScenarioMessage":
        return cls(
            id=data["id"],
            version=data.get("version", _PROTOCOL_VERSION),
            scenario_spec=data["scenario_spec"],
        )


@dataclass(frozen=True)
class PollMetricsMessage(Message):
    id: str
    source: str
    kind: str
    version: str = _PROTOCOL_VERSION
    type: str = "POLL_METRICS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "version": self.version,
            "source": self.source,
            "kind": self.kind,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PollMetricsMessage":
        return cls(
            id=data["id"],
            version=data.get("version", _PROTOCOL_VERSION),
            source=data["source"],
            kind=data["kind"],
        )


@dataclass(frozen=True)
class ShutdownMessage(Message):
    id: str
    version: str = _PROTOCOL_VERSION
    type: str = "SHUTDOWN"

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "id": self.id, "version": self.version}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ShutdownMessage":
        return cls(id=data["id"], version=data.get("version", _PROTOCOL_VERSION))


# ── Response messages ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AckMessage(Message):
    id: str
    reply_to: str
    result: dict  # type: ignore[type-arg]
    version: str = _PROTOCOL_VERSION
    type: str = "ACK"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "version": self.version,
            "reply_to": self.reply_to,
            "result": self.result,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AckMessage":
        return cls(
            id=data["id"],
            version=data.get("version", _PROTOCOL_VERSION),
            reply_to=data["reply_to"],
            result=data.get("result", {}),
        )


@dataclass(frozen=True)
class ErrorMessage(Message):
    id: str
    reply_to: str
    error_type: str
    message: str
    version: str = _PROTOCOL_VERSION
    type: str = "ERROR"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "version": self.version,
            "reply_to": self.reply_to,
            "error_type": self.error_type,
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ErrorMessage":
        return cls(
            id=data["id"],
            version=data.get("version", _PROTOCOL_VERSION),
            reply_to=data["reply_to"],
            error_type=data["error_type"],
            message=data["message"],
        )


# ── Dispatcher ────────────────────────────────────────────────────────────────

_TYPE_MAP: dict[str, type[Message]] = {
    "PING": PingMessage,
    "SETUP_ENDPOINT": SetupEndpointMessage,
    "TEARDOWN_ENDPOINT": TeardownEndpointMessage,
    "RUN_SCENARIO": RunScenarioMessage,
    "POLL_METRICS": PollMetricsMessage,
    "SHUTDOWN": ShutdownMessage,
    "ACK": AckMessage,
    "ERROR": ErrorMessage,
}


def decode(data: dict[str, Any]) -> Message:
    """Decode a parsed JSON dict into the appropriate :class:`Message` subclass.

    Raises :exc:`ValueError` on unknown ``type`` or missing required fields.
    """
    msg_type = data.get("type")
    if not msg_type:
        raise ValueError("message missing 'type' field")
    cls = _TYPE_MAP.get(msg_type)
    if cls is None:
        raise ValueError(f"unknown message type: {msg_type!r}")
    try:
        return cls.from_dict(data)
    except KeyError as exc:
        raise ValueError(f"malformed {msg_type} message: missing field {exc}") from exc


def new_id() -> str:
    """Return a fresh UUID4 hex string suitable for use as a message ID."""
    return uuid.uuid4().hex


# ── Transport ─────────────────────────────────────────────────────────────────


class JsonLineChannel:
    """Async JSON-Lines transport over asyncio streams.

    Each message is serialised as a compact JSON object followed by a
    newline (``\\n``).  The channel does **not** own the underlying
    streams and does not close them automatically except via
    :meth:`close`.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._reader = reader
        self._writer = writer

    async def send(self, msg: Message) -> None:
        """Serialise *msg* and write it as a newline-terminated JSON line."""
        data = json.dumps(msg.to_dict(), separators=(",", ":"))
        self._writer.write(data.encode() + b"\n")
        await self._writer.drain()

    async def recv(self) -> Message:
        """Read one line from the stream and decode it as a :class:`Message`.

        Raises :exc:`ConnectionClosedError` on clean EOF.
        Raises :exc:`ValueError` on malformed JSON or unknown message type.
        """
        line = await self._reader.readline()
        if not line:
            raise ConnectionClosedError("remote end closed the connection")
        try:
            data = json.loads(line.rstrip(b"\n"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("message must be a JSON object")
        return decode(data)

    async def close(self) -> None:
        """Close the underlying writer."""
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
