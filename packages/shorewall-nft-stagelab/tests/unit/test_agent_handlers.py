"""Unit tests for agent handler stubs (no root, nsstub mocked)."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from shorewall_nft_stagelab.agent import (
    handle_ping,
    handle_setup_endpoint,
    handle_teardown_endpoint,
)
from shorewall_nft_stagelab.ipc import PingMessage, SetupEndpointMessage, TeardownEndpointMessage


def _state() -> dict:
    return {"host_name": "test-host", "stubs": {}}


def test_handle_ping_returns_empty() -> None:
    """handle_ping must return an empty dict regardless of message content."""
    msg = PingMessage(id="ping-1")
    state = _state()
    result = asyncio.run(handle_ping(msg, state))
    assert result == {}


def test_setup_and_teardown_endpoint_uses_nsstub() -> None:
    """handle_setup_endpoint / handle_teardown_endpoint wire through nsstub correctly."""
    setup_msg = SetupEndpointMessage(id="setup-1", endpoint_spec={"name": "alpha"})
    teardown_msg = TeardownEndpointMessage(id="teardown-1", endpoint_name="alpha")
    state = _state()

    with (
        patch("shorewall_nft_netkit.nsstub.spawn_nsstub", return_value=42) as mock_spawn,
        patch("shorewall_nft_netkit.nsstub.stop_nsstub") as mock_stop,
    ):
        result = asyncio.run(handle_setup_endpoint(setup_msg, state))
        assert result == {"netns": "NS_TEST_alpha", "pid": 42}
        assert state["stubs"] == {"alpha": 42}
        mock_spawn.assert_called_once_with("NS_TEST_alpha")

        result2 = asyncio.run(handle_teardown_endpoint(teardown_msg, state))
        assert result2 == {"ok": True}
        assert state["stubs"] == {}
        mock_stop.assert_called_once_with("NS_TEST_alpha", 42)
