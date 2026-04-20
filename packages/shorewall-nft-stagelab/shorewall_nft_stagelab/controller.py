"""asyncio orchestrator: agent-pool management, scenario dispatch, result aggregation."""

from __future__ import annotations

import asyncio
import logging
import sys
from asyncio.subprocess import PIPE
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .config import Host, StagelabConfig
from .ipc import (
    AckMessage,
    ConnectionClosedError,
    ErrorMessage,
    JsonLineChannel,
    PingMessage,
    RunScenarioMessage,
    ShutdownMessage,
    new_id,
)
from .report import RunReport, ScenarioResult
from .scenarios import build_runner

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AgentConnection
# ---------------------------------------------------------------------------


@dataclass
class AgentConnection:
    host_name: str
    process: asyncio.subprocess.Process
    channel: JsonLineChannel


# ---------------------------------------------------------------------------
# Transport factories
# ---------------------------------------------------------------------------


async def spawn_local(host: Host) -> asyncio.subprocess.Process:
    """Spawn the agent as a local subprocess (no SSH).

    Used in tests and when host.address starts with "local:".
    """
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "shorewall_nft_stagelab.agent",
        "--host-name",
        host.name,
        stdin=PIPE,
        stdout=PIPE,
        stderr=None,
    )


async def spawn_ssh(host: Host) -> asyncio.subprocess.Process:
    """Spawn the agent via SSH on the remote host.

    Plain SSH invocation — no ControlMaster plumbing (MVP).
    """
    return await asyncio.create_subprocess_exec(
        "ssh",
        host.address,
        f"{host.work_dir}/.venv/bin/python",
        "-m",
        "shorewall_nft_stagelab.agent",
        "--host-name",
        host.name,
        stdin=PIPE,
        stdout=PIPE,
        stderr=None,
    )


async def _auto_factory(host: Host) -> asyncio.subprocess.Process:
    """Per-host dispatch: hosts with address starting with "local:" run via
    spawn_local (no SSH); all others go through spawn_ssh.

    This is the default factory wired into StagelabController when the
    caller does not pass an explicit transport_factory.
    """
    if host.address.startswith("local:"):
        return await spawn_local(host)
    return await spawn_ssh(host)


# ---------------------------------------------------------------------------
# StagelabController
# ---------------------------------------------------------------------------


class StagelabController:
    """Orchestrates a stagelab run: spawn one agent per host, dispatch
    scenario AgentCommands, collect AgentCommand results, build RunReport.

    Transport factory: a function ``(host: Host) -> asyncio.subprocess.Process``.
    Two built-in factories:
      - ``spawn_local(host)`` — spawns ``python -m shorewall_nft_stagelab.agent
        --host-name <name>`` as a local subprocess (no SSH). Used in tests
        and when ``host.address`` starts with "local:".
      - ``spawn_ssh(host)`` — spawns ``ssh <host.address> <workdir>/.venv/bin/python
        -m shorewall_nft_stagelab.agent --host-name <name>``. Used in production.
    """

    def __init__(
        self,
        config: StagelabConfig,
        transport_factory: Callable | None = None,
        config_path: str = "<in-memory>",
    ) -> None:
        self._config = config
        self._config_path = config_path
        self._factory = transport_factory if transport_factory is not None else _auto_factory
        self._connections: dict[str, AgentConnection] = {}

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Start agents for every host. Send PING to each to confirm alive.

        Raises RuntimeError if any agent fails to ACK within 5 s.
        """
        for host in self._config.hosts:
            log.debug("spawning agent for host %r", host.name)
            proc = await self._factory(host)

            # proc.stdin is asyncio.StreamWriter; proc.stdout is asyncio.StreamReader.
            # Pass them directly to JsonLineChannel.
            assert proc.stdin is not None
            assert proc.stdout is not None

            channel = JsonLineChannel(proc.stdout, proc.stdin)
            conn = AgentConnection(
                host_name=host.name,
                process=proc,
                channel=channel,
            )
            self._connections[host.name] = conn

            # Confirm alive via PING
            ping = PingMessage(id=new_id())
            await channel.send(ping)
            try:
                response = await asyncio.wait_for(channel.recv(), timeout=5.0)
            except asyncio.TimeoutError as exc:
                raise RuntimeError(
                    f"agent for host {host.name!r} did not ACK PING within 5 s"
                ) from exc
            except ConnectionClosedError as exc:
                raise RuntimeError(
                    f"agent for host {host.name!r} closed connection before PING ACK"
                ) from exc
            if not isinstance(response, AckMessage):
                raise RuntimeError(
                    f"agent for host {host.name!r} responded to PING with "
                    f"{response!r} instead of ACK"
                )
            log.debug("agent %r alive (ping ACK received)", host.name)

    async def run_scenarios(self) -> RunReport:
        """For each scenario: build_runner().plan(cfg) -> AgentCommands.

        For each AgentCommand: send RUN_SCENARIO message to the right host
        (look up endpoint.host). Await response. Collect results into a list.
        Pass to scenario.summarize() -> ScenarioResult.
        Assemble into RunReport with UTC run_id.

        NOTE: Phase 2 will implement real agent handlers for RUN_SCENARIO.
        For MVP the agent stub raises NotImplementedError, so every command
        returns an ERROR response. The controller records these as
        ScenarioResult(ok=False) without crashing. This is expected and
        documented.
        """
        # TODO: wire metrics.py pollers for POLL_METRICS during scenarios

        # Build endpoint → host lookup table
        ep_to_host: dict[str, str] = {
            ep.name: ep.host for ep in self._config.endpoints
        }

        scenario_results: list[ScenarioResult] = []
        run_id = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        for scenario_cfg in self._config.scenarios:
            runner = build_runner(scenario_cfg)
            commands = runner.plan(self._config)
            log.debug(
                "scenario %r: %d commands", scenario_cfg.id, len(commands)
            )

            cmd_results: list[dict] = []

            for cmd in commands:
                host_name = ep_to_host.get(cmd.endpoint_name)
                if host_name is None:
                    log.warning(
                        "scenario %r command %r: endpoint %r not in config; skipping",
                        scenario_cfg.id,
                        cmd.kind,
                        cmd.endpoint_name,
                    )
                    cmd_results.append({"ok": False, "error": "endpoint not found"})
                    continue

                conn = self._connections.get(host_name)
                if conn is None:
                    log.warning(
                        "scenario %r command %r: no connection for host %r",
                        scenario_cfg.id,
                        cmd.kind,
                        host_name,
                    )
                    cmd_results.append({"ok": False, "error": "host not connected"})
                    continue

                msg = RunScenarioMessage(
                    id=new_id(),
                    scenario_spec={"kind": cmd.kind, **cmd.spec},
                )
                log.debug(
                    "sending RUN_SCENARIO to host %r: kind=%r", host_name, cmd.kind
                )
                await conn.channel.send(msg)

                try:
                    response = await asyncio.wait_for(
                        conn.channel.recv(), timeout=60.0
                    )
                except asyncio.TimeoutError:
                    log.error(
                        "host %r timed out on RUN_SCENARIO kind=%r",
                        host_name,
                        cmd.kind,
                    )
                    cmd_results.append({"ok": False, "error": "timeout"})
                    continue
                except ConnectionClosedError:
                    log.error(
                        "host %r closed connection during RUN_SCENARIO kind=%r",
                        host_name,
                        cmd.kind,
                    )
                    cmd_results.append({"ok": False, "error": "connection closed"})
                    continue

                if isinstance(response, AckMessage):
                    cmd_results.append({"ok": True, **response.result})
                elif isinstance(response, ErrorMessage):
                    # Agent stub raises NotImplementedError for RUN_SCENARIO (Phase 2).
                    # Log and record as failure — do NOT retry.
                    log.warning(
                        "host %r returned ERROR for RUN_SCENARIO kind=%r: %s",
                        host_name,
                        cmd.kind,
                        response.message,
                    )
                    cmd_results.append(
                        {"ok": False, "error": response.message}
                    )
                else:
                    log.warning(
                        "host %r unexpected response type %r for RUN_SCENARIO",
                        host_name,
                        type(response).__name__,
                    )
                    cmd_results.append({"ok": False, "error": "unexpected response"})

            scenario_result = runner.summarize(cmd_results)
            scenario_results.append(scenario_result)

        return RunReport(
            run_id=run_id,
            config_path=self._config_path,
            scenarios=scenario_results,
        )

    async def close(self) -> None:
        """Send SHUTDOWN to each agent, await ACK, terminate subprocess."""
        for host_name, conn in list(self._connections.items()):
            shutdown = ShutdownMessage(id=new_id())
            try:
                await conn.channel.send(shutdown)
                try:
                    response = await asyncio.wait_for(
                        conn.channel.recv(), timeout=5.0
                    )
                    if not isinstance(response, AckMessage):
                        log.warning(
                            "agent %r did not ACK SHUTDOWN (got %r)",
                            host_name,
                            type(response).__name__,
                        )
                except (asyncio.TimeoutError, ConnectionClosedError):
                    log.warning("agent %r did not respond to SHUTDOWN", host_name)
            except Exception:  # noqa: BLE001
                log.warning("error sending SHUTDOWN to agent %r", host_name)

            try:
                conn.process.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(conn.process.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                conn.process.kill()

        self._connections.clear()


__all__ = [
    "AgentConnection",
    "StagelabController",
    "spawn_local",
    "spawn_ssh",
]
