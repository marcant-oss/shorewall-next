"""Control-socket request handlers, separated from Daemon for testability.

Each handler is an async method receiving the decoded request dict and
returning the reply dict.  The handlers receive the subsystem references
they need via the constructor — they do NOT hold a reference to the whole
Daemon object.

Handler method names match the control-socket command names with hyphens
replaced by underscores and a ``handle_`` prefix.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable

if TYPE_CHECKING:
    from .dns_pull_resolver import PullResolver
    from .instance import InstanceManager
    from .iplist.tracker import IpListTracker

log = logging.getLogger("shorewalld.control_handlers")


class ControlHandlers:
    """Control-socket request handlers, separated from Daemon for testability.

    Each handler is an async method receiving decoded request args and
    returning the reply dict.  The handlers receive the subsystem references
    they need via the constructor — they do NOT hold a reference to the
    whole Daemon.

    The optional *nfsets_hook* callback is called after
    ``register-instance`` to wire nfsets backends; it should be
    ``Daemon._apply_nfsets_from_instances``.
    """

    def __init__(
        self,
        *,
        instance_mgr: "InstanceManager | None" = None,
        iplist_tracker: "IpListTracker | None" = None,
        pull_resolver: "PullResolver | None" = None,
        nfsets_hook: "Callable[[], Awaitable[None]] | None" = None,
    ) -> None:
        self._instance_mgr = instance_mgr
        self._iplist_tracker = iplist_tracker
        self._pull_resolver = pull_resolver
        self._nfsets_hook = nfsets_hook

    # ── iplist handlers ───────────────────────────────────────────────

    async def handle_refresh_iplist(self, req: dict) -> dict:
        """Trigger a refresh of one or all IP-list entries."""
        if self._iplist_tracker is None:
            return {"ok": False, "error": "iplist tracker not running"}
        name = req.get("name")
        if name:
            await self._iplist_tracker.refresh_one(name)
        else:
            await self._iplist_tracker.refresh_all()
        return {"ok": True}

    async def handle_iplist_status(self, req: dict) -> dict:  # noqa: ARG002
        """Return the status of all IP-list entries."""
        if self._iplist_tracker is None:
            return {"ok": False, "error": "iplist tracker not running"}
        return {"ok": True, "lists": self._iplist_tracker.status()}

    # ── instance handlers ─────────────────────────────────────────────

    async def handle_reload_instance(self, req: dict) -> dict:
        """Reload one or all instances from disk."""
        if self._instance_mgr is None:
            return {"ok": False, "error": "instance manager not running"}
        name = req.get("name")
        await self._instance_mgr.reload(name)
        return {"ok": True}

    async def handle_instance_status(self, req: dict) -> dict:  # noqa: ARG002
        """Return the status of all managed instances."""
        if self._instance_mgr is None:
            return {"ok": False, "error": "instance manager not running"}
        return {"ok": True, "instances": self._instance_mgr.status()}

    async def handle_register_instance(self, req: dict) -> dict:
        """Register (or re-register) a shorewall-nft instance.

        Required keys: ``config_dir``.
        Optional: ``netns``, ``name``, ``allowlist_path``, ``nfsets``,
        ``dns``, ``dnsr``.
        """
        if self._instance_mgr is None:
            return {"ok": False, "error": "instance manager not running"}

        from .instance import InstanceConfig

        config_dir = req.get("config_dir")
        netns = req.get("netns") or ""
        if not config_dir:
            return {"ok": False, "error": "missing 'config_dir'"}
        dir_path = Path(config_dir)
        # Client-supplied name wins (from INSTANCE_NAME / CLI);
        # otherwise derive deterministically.
        name = (req.get("name") or netns or dir_path.name).strip()
        allowlist_path = Path(
            req.get("allowlist_path")
            or (dir_path / "dnsnames.compiled")
        )
        nfsets_payload = req.get("nfsets") or None
        cfg = InstanceConfig(
            name=name,
            netns=netns,
            config_dir=dir_path,
            allowlist_path=allowlist_path,
            nfsets_payload=nfsets_payload,
        )
        dns_payload: dict[str, Any] | None = None
        if "dns" in req or "dnsr" in req:
            dns_payload = {
                k: req[k] for k in ("dns", "dnsr") if k in req
            }
        n = await self._instance_mgr.register(
            cfg,
            dns_payload=dns_payload,
            nfsets_payload=nfsets_payload,
        )
        # Wire nfsets backends (PlainListTracker etc.) after register.
        if self._nfsets_hook is not None:
            await self._nfsets_hook()
        return {"ok": True, "name": cfg.name, "qnames": n}

    async def handle_deregister_instance(self, req: dict) -> dict:
        """Deregister a shorewall-nft instance by name or config_dir."""
        if self._instance_mgr is None:
            return {"ok": False, "error": "instance manager not running"}

        name = req.get("name")
        if not name:
            config_dir = req.get("config_dir")
            netns = req.get("netns") or ""
            if config_dir:
                name = netns or Path(config_dir).name
        if not name:
            return {
                "ok": False,
                "error": "missing 'name' or 'config_dir'",
            }
        await self._instance_mgr.deregister(name)
        return {"ok": True, "name": name}

    # ── refresh-dns handler ───────────────────────────────────────────

    async def handle_refresh_dns(self, req: dict) -> dict:
        """Trigger an immediate DNS refresh for one hostname or all."""
        if self._pull_resolver is None:
            return {"ok": False, "error": "pull resolver not running"}
        hostname = req.get("hostname")
        n = await self._pull_resolver.refresh(hostname)
        return {"ok": True, "rescheduled": n}
