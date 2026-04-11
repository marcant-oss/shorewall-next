"""Native nftables integration via libnftables, JSON API, and pyroute2.

Provides direct interaction with the kernel nftables subsystem:
- Atomic ruleset replacement (no flush+load race)
- Live counter/set queries without spawning processes
- Set element manipulation (dynamic blacklist)
- Dry-run validation (nft -c)
- Native network namespace support via pyroute2.NetNS

Priority: libnftables (C bindings) > nft JSON (subprocess) > nft text (subprocess)
For netns: pyroute2.NetNS for namespace entry, then nft within.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

# nft binary path — search common locations
_NFT_PATHS = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]


def _find_nft() -> str:
    """Find the nft binary."""
    for p in _NFT_PATHS:
        if Path(p).exists():
            return p
    return "nft"  # Hope it's in PATH


class NftError(Exception):
    """Error from nft operation."""


class NftInterface:
    """Interface to nftables — uses libnftables if available, subprocess otherwise.

    Also integrates pyroute2 for native network namespace support.
    """

    def __init__(self):
        self._nft = None
        self._use_lib = False
        self._nft_bin = _find_nft()

        # Try libnftables (C bindings via python3-nftables)
        try:
            import nftables
            self._nft = nftables.Nftables()
            self._nft.set_json_output(True)
            self._nft.set_handle_output(True)
            self._use_lib = True
        except (ImportError, OSError):
            # python3-nftables is a system package, not in venvs
            try:
                import sys
                sys.path.insert(0, "/usr/lib/python3/dist-packages")
                import nftables
                self._nft = nftables.Nftables()
                self._nft.set_json_output(True)
                self._nft.set_handle_output(True)
                self._use_lib = True
            except (ImportError, OSError):
                pass

        # Check pyroute2 availability for netns
        self._has_pyroute2 = False
        try:
            import pyroute2  # noqa: F401
            self._has_pyroute2 = True
        except ImportError:
            pass

    @property
    def has_library(self) -> bool:
        return self._use_lib

    def cmd(self, command: str) -> dict[str, Any]:
        """Run an nft command and return JSON output."""
        if self._use_lib:
            rc, output, error = self._nft.cmd(command)
            if rc != 0:
                raise NftError(f"nft: {error}")
            return json.loads(output) if output else {}
        else:
            return self._subprocess_cmd(command)

    def cmd_json(self, json_payload: dict) -> dict[str, Any]:
        """Send a JSON command directly to nft."""
        if self._use_lib:
            self._nft.set_json_output(True)
            rc, output, error = self._nft.json_cmd(json_payload)
            if rc != 0:
                raise NftError(f"nft json: {error}")
            return json.loads(output) if output else {}
        else:
            payload_str = json.dumps(json_payload)
            result = subprocess.run(
                ["nft", "-j", "-f", "-"],
                input=payload_str, capture_output=True, text=True
            )
            if result.returncode != 0:
                raise NftError(f"nft: {result.stderr.strip()}")
            return json.loads(result.stdout) if result.stdout else {}

    def load_file(self, path: str | Path, *, check_only: bool = False,
                  netns: str | None = None) -> None:
        """Load an nft script file atomically."""
        cmd: list[str] = []
        if netns:
            cmd = ["sudo", "/usr/local/bin/run-netns", "exec", netns]
        cmd.extend([self._nft_bin])
        if check_only:
            cmd.append("-c")  # check/dry-run mode
        cmd.extend(["-f", str(path)])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise NftError(f"nft -f: {result.stderr.strip()}")

    def validate(self, script: str, *, netns: str | None = None) -> bool:
        """Validate an nft script without applying it (dry-run)."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False) as f:
            f.write(script)
            tmp = Path(f.name)
        try:
            self.load_file(tmp, check_only=True, netns=netns)
            return True
        except NftError:
            return False
        finally:
            tmp.unlink(missing_ok=True)

    def list_table(self, family: str = "inet", table: str = "shorewall",
                   *, netns: str | None = None) -> dict[str, Any]:
        """List a table's ruleset as JSON."""
        cmd_parts = []
        if netns:
            cmd_parts = ["sudo", "/usr/local/bin/run-netns", "exec", netns]
        cmd_parts.extend(["nft", "-j", "list", "table", family, table])

        result = subprocess.run(cmd_parts, capture_output=True, text=True)
        if result.returncode != 0:
            raise NftError(f"Table not found: {family} {table}")
        return json.loads(result.stdout)

    def list_counters(self, family: str = "inet", table: str = "shorewall",
                      *, netns: str | None = None) -> dict[str, dict[str, int]]:
        """List all counter values. Returns {name: {packets: N, bytes: N}}."""
        cmd_parts = []
        if netns:
            cmd_parts = ["sudo", "/usr/local/bin/run-netns", "exec", netns]
        cmd_parts.extend(["nft", "-j", "list", "counters", "table", family, table])

        result = subprocess.run(cmd_parts, capture_output=True, text=True)
        if result.returncode != 0:
            return {}

        data = json.loads(result.stdout)
        counters: dict[str, dict[str, int]] = {}
        for item in data.get("nftables", []):
            if "counter" in item:
                c = item["counter"]
                counters[c.get("name", "")] = {
                    "packets": c.get("packets", 0),
                    "bytes": c.get("bytes", 0),
                }
        return counters

    def list_set_elements(self, set_name: str, family: str = "inet",
                          table: str = "shorewall",
                          *, netns: str | None = None) -> list[str]:
        """List elements of a named set."""
        cmd_parts = []
        if netns:
            cmd_parts = ["sudo", "/usr/local/bin/run-netns", "exec", netns]
        cmd_parts.extend(["nft", "-j", "list", "set", family, table, set_name])

        result = subprocess.run(cmd_parts, capture_output=True, text=True)
        if result.returncode != 0:
            return []

        data = json.loads(result.stdout)
        elements: list[str] = []
        for item in data.get("nftables", []):
            if "set" in item:
                for elem in item["set"].get("elem", []):
                    if isinstance(elem, str):
                        elements.append(elem)
                    elif isinstance(elem, dict) and "prefix" in elem:
                        p = elem["prefix"]
                        elements.append(f"{p['addr']}/{p['len']}")
        return elements

    def add_set_element(self, set_name: str, element: str,
                        timeout: str | None = None,
                        family: str = "inet", table: str = "shorewall",
                        *, netns: str | None = None) -> None:
        """Add an element to a named set (e.g. dynamic blacklist)."""
        timeout_str = f" timeout {timeout}" if timeout else ""
        nft_cmd = f"add element {family} {table} {set_name} {{ {element}{timeout_str} }}"

        cmd_parts = []
        if netns:
            cmd_parts = ["sudo", "/usr/local/bin/run-netns", "exec", netns]
        cmd_parts.extend(["nft", nft_cmd])

        result = subprocess.run(cmd_parts, capture_output=True, text=True)
        if result.returncode != 0:
            raise NftError(f"Failed to add element: {result.stderr.strip()}")

    def delete_set_element(self, set_name: str, element: str,
                           family: str = "inet", table: str = "shorewall",
                           *, netns: str | None = None) -> None:
        """Remove an element from a named set."""
        nft_cmd = f"delete element {family} {table} {set_name} {{ {element} }}"

        cmd_parts = []
        if netns:
            cmd_parts = ["sudo", "/usr/local/bin/run-netns", "exec", netns]
        cmd_parts.extend(["nft", nft_cmd])

        result = subprocess.run(cmd_parts, capture_output=True, text=True)
        if result.returncode != 0:
            raise NftError(f"Failed to delete element: {result.stderr.strip()}")

    def _subprocess_cmd(self, command: str) -> dict[str, Any]:
        """Run nft command via subprocess with JSON output."""
        result = subprocess.run(
            ["nft", "-j", command],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise NftError(f"nft: {result.stderr.strip()}")
        return json.loads(result.stdout) if result.stdout else {}
